package messageflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/execution"
	"Scardice-core/core/groupstate"
	"Scardice-core/core/playerstate"
	"Scardice-core/eventstore"
)

const (
	CallbackMaxPreMarkerAttempts       = 3
	MessageWorkflowAggregateType       = "message-workflow"
	MessageWorkflowTerminatedEventType = "message-workflow.terminated"
	MaxWorkflowIDBytes                 = 255
	callbackLeaseHeartbeatFloor        = 10 * time.Millisecond
	callbackMinimumLeaseDuration       = 3 * callbackLeaseHeartbeatFloor
)

var (
	ErrCallbackUnavailable = errors.New("messageflow: callback service unavailable")
	ErrCallbackPayload     = errors.New("messageflow: invalid callback payload")
	ErrCallbackScope       = errors.New("messageflow: invalid callback scope")
	ErrCallbackWorkflow    = errors.New("messageflow: invalid callback workflow")
	ErrCallbackLease       = errors.New("messageflow: callback lease is invalid")
)

// CallbackScope is the provider-neutral owner lookup result for one message.
type CallbackScope struct {
	DiceID  string
	GroupID string
	UserID  string
}

// CallbackScopeResolver maps normalized ingress facts to durable state owners.
type CallbackScopeResolver interface {
	Resolve(ctx context.Context, endpointID string, message adapterapi.InboundMessage) (CallbackScope, error)
}

// CallbackRequest contains copied provider-neutral ingress facts and resolved
// durable owner identities. Canonical domain state is loaded by the execution
// root after callback-started.
type CallbackRequest struct {
	InboxID        string
	EndpointID     string
	Generation     uint64
	DesiredVersion uint64
	Message        adapterapi.InboundMessage
	Scope          CallbackScope
}

// WorkflowResult is returned only for a named asynchronous callback. The
// event must be the terminal event for the named message-workflow stream.
type WorkflowResult struct {
	ID              string
	ExpectedVersion uint64
	Event           eventstore.NewEvent
}

// CallbackResult is the host's durable decision. Mutations are collected
// through the execution-owned MutationCollector; only an explicit Workflow
// creates a message-workflow stream.
type CallbackCommitFence interface {
	TryLock() bool
	Unlock()
}

type CallbackResult struct {
	Workflow    *WorkflowResult
	CommitFence CallbackCommitFence
	// PublishCommitted performs a trusted, nonblocking in-memory ownership
	// handoff after durable success while CommitFence is still held. It must not
	// perform I/O, invoke user code, or reload runtime state.
	PublishCommitted func()
	AfterCommit      func()
	// Release relinquishes transaction-owned callback resources after the
	// complete UnitOfWork. CallbackService defers it after the host returns,
	// keeping the transaction valid through publication, commit notifications,
	// and releasing it on every exit.
	Release func()
}

// CallbackHost runs only after the inbox row has durably entered
// callback-started. The collector is owned by core/execution.
type CallbackHost interface {
	HandleCallback(ctx context.Context, request CallbackRequest, overlay *playerstate.LocalOverlay, collector *execution.MutationCollector) (CallbackResult, error)
}

// CallbackConfig wires the durable callback service.
type CallbackConfig struct {
	Inbox         eventstore.InboxRepository
	Store         eventstore.Store
	Resolver      CallbackScopeResolver
	Host          CallbackHost
	WorkerID      string
	LeaseDuration time.Duration
	Clock         eventstore.Clock
	Factory       eventstore.EventFactory
}

// CallbackResultSummary reports the durable terminal outcome of ProcessOne.
type CallbackResultSummary struct {
	InboxID    string
	WorkflowID string
	Attempts   int
	Status     string
}

// CallbackService claims and executes one inbox callback at a time.
type CallbackService struct {
	inbox    eventstore.InboxRepository
	store    eventstore.Store
	resolver CallbackScopeResolver
	host     CallbackHost
	workerID string
	lease    time.Duration
	clock    eventstore.Clock
	factory  eventstore.EventFactory
}

type callbackLeaseHeartbeatResult struct {
	update eventstore.InboxUpdate
	err    error
}

func (s *CallbackService) leaseOperationContext(ctx context.Context, lease eventstore.InboxUpdate) (context.Context, context.CancelFunc, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if lease.LeaseExpiresAt.IsZero() {
		operationCtx, cancel := context.WithCancel(ctx)
		return operationCtx, cancel, nil
	}
	remaining := lease.LeaseExpiresAt.Sub(s.clock.Now().UTC())
	margin := s.lease / 3
	if margin < callbackLeaseHeartbeatFloor {
		margin = callbackLeaseHeartbeatFloor
	}
	if remaining <= margin {
		return nil, nil, ErrCallbackLease
	}
	operationCtx, cancel := context.WithTimeout(ctx, remaining-margin)
	return operationCtx, cancel, nil
}

func (s *CallbackService) renewCallbackLease(ctx context.Context, current eventstore.InboxUpdate) (eventstore.InboxUpdate, error) {
	renewed, err := s.inbox.RenewInbox(ctx, eventstore.InboxRenewRequest{
		InboxID: current.InboxID, WorkerID: current.LeaseOwner,
		LeaseEpoch: current.LeaseEpoch, AttemptID: current.AttemptID,
		LeaseDuration: s.lease,
	})
	if err != nil {
		return current, err
	}
	next := renewed.Update
	if next.InboxID != current.InboxID || next.Status != eventstore.InboxStatusCallbackStarted ||
		next.LeaseOwner != current.LeaseOwner || next.LeaseEpoch != current.LeaseEpoch ||
		next.AttemptID != current.AttemptID || next.Version <= current.Version ||
		!next.LeaseExpiresAt.After(s.clock.Now().UTC()) {
		return current, ErrCallbackLease
	}
	return next, nil
}

func (s *CallbackService) keepLeaseAlive(ctx context.Context, cancel context.CancelFunc, initial eventstore.InboxUpdate, stop <-chan struct{}, done chan<- callbackLeaseHeartbeatResult) {
	interval := s.lease / 3
	if interval < callbackLeaseHeartbeatFloor {
		interval = callbackLeaseHeartbeatFloor
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	current := initial
	finish := func(err error) {
		done <- callbackLeaseHeartbeatResult{update: current, err: err}
	}
	for {
		select {
		case <-stop:
			finish(nil)
			return
		case <-ctx.Done():
			select {
			case <-stop:
				finish(nil)
			default:
				finish(ctx.Err())
			}
			return
		case <-ticker.C:
			select {
			case <-stop:
				finish(nil)
				return
			default:
			}
			if ctxErr := ctx.Err(); ctxErr != nil {
				finish(ctxErr)
				return
			}
			renewCtx, renewCancel, contextErr := s.leaseOperationContext(ctx, current)
			if contextErr != nil {
				cancel()
				finish(contextErr)
				return
			}
			next, renewErr := s.renewCallbackLease(renewCtx, current)
			renewCancel()
			if renewErr != nil {
				cancel()
				finish(renewErr)
				return
			}
			current = next
		}
	}
}

func waitCallbackCommitFence(ctx context.Context, fence CallbackCommitFence) (func(), error) {
	if fence == nil {
		return func() {}, nil
	}
	ticker := time.NewTicker(callbackLeaseHeartbeatFloor)
	defer ticker.Stop()
	for {
		if fence.TryLock() {
			if err := ctx.Err(); err != nil {
				fence.Unlock()
				return nil, err
			}
			return fence.Unlock, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func callbackIsNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

// NewCallbackService validates and constructs the durable callback service.
func NewCallbackService(config CallbackConfig) (*CallbackService, error) {
	if callbackIsNil(config.Inbox) || callbackIsNil(config.Store) || callbackIsNil(config.Resolver) || callbackIsNil(config.Host) || strings.TrimSpace(config.WorkerID) == "" {
		return nil, ErrCallbackUnavailable
	}
	if config.LeaseDuration <= 0 {
		config.LeaseDuration = time.Minute
	}
	if config.LeaseDuration < callbackMinimumLeaseDuration {
		return nil, ErrCallbackLease
	}
	if callbackIsNil(config.Clock) {
		config.Clock = eventstore.SystemClock{}
	}
	if callbackIsNil(config.Factory.Clock) {
		config.Factory.Clock = config.Clock
	}
	if callbackIsNil(config.Factory.IDs) {
		config.Factory.IDs = eventstore.UUIDGenerator{}
	}
	return &CallbackService{
		inbox: config.Inbox, store: config.Store, resolver: config.Resolver, host: config.Host,
		workerID: config.WorkerID, lease: config.LeaseDuration, clock: config.Clock, factory: config.Factory,
	}, nil
}

// ProcessOne claims the earliest unresolved lane item and either commits one
// atomic callback UnitOfWork or leaves the row failed/ambiguous. Host execution
// is never retried after callback-started.
func (s *CallbackService) ProcessOne(ctx context.Context) (summary CallbackResultSummary, err error) {
	if s == nil || s.inbox == nil || s.store == nil || s.resolver == nil || s.host == nil {
		return summary, ErrCallbackUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for attempt := 1; attempt <= CallbackMaxPreMarkerAttempts; attempt++ {
		summary.Attempts = attempt
		lease, claimErr := s.inbox.ClaimInbox(ctx, eventstore.InboxClaimRequest{WorkerID: s.workerID, LeaseDuration: s.lease})
		if claimErr != nil {
			return summary, claimErr
		}
		summary.InboxID, summary.Status = lease.Update.InboxID, lease.Update.Status
		if err := validateClaimAt(lease.Update, s.clock.Now(), s.workerID); err != nil {
			return summary, err
		}
		payload, decodeErr := s.decodeClaimed(ctx, lease.Update)
		if decodeErr != nil {
			if failureErr := s.failLease(ctx, lease.Update); failureErr != nil {
				return summary, errors.Join(decodeErr, failureErr)
			}
			summary.Status = eventstore.InboxStatusFailed
			return summary, decodeErr
		}
		scope, loadErr := s.resolveCallbackScope(ctx, lease.Update.EndpointID, payload)
		if loadErr != nil {
			if failureErr := s.failLease(ctx, lease.Update); failureErr != nil {
				return summary, errors.Join(loadErr, failureErr)
			}
			summary.Status = eventstore.InboxStatusFailed
			return summary, loadErr
		}
		startedVersion, versionErr := nextCallbackVersion(lease.Update.Version)
		if versionErr != nil {
			if failureErr := s.failLease(ctx, lease.Update); failureErr != nil {
				return summary, errors.Join(versionErr, failureErr)
			}
			summary.Status = eventstore.InboxStatusFailed
			return summary, versionErr
		}
		marker := eventstore.InboxUpdate{
			InboxID: lease.Update.InboxID, ExpectedVersion: lease.Update.Version, Version: lease.Update.Version,
			Status: eventstore.InboxStatusCallbackStarted, LeaseOwner: lease.Update.LeaseOwner,
			LeaseEpoch: lease.Update.LeaseEpoch, AttemptID: lease.Update.AttemptID,
			LeaseExpiresAt: lease.Update.LeaseExpiresAt,
		}
		if _, markerErr := s.inbox.UpdateInbox(ctx, marker); markerErr != nil {
			if isPreMarkerConflict(markerErr) && attempt < CallbackMaxPreMarkerAttempts {
				continue
			}
			if failureErr := s.failLease(ctx, lease.Update); failureErr != nil {
				return summary, errors.Join(markerErr, failureErr)
			}
			summary.Status = eventstore.InboxStatusFailed
			return summary, markerErr
		}
		lease.Update.Status = eventstore.InboxStatusCallbackStarted
		lease.Update.Version = startedVersion
		summary.Status = eventstore.InboxStatusCallbackStarted
		request := CallbackRequest{
			InboxID: lease.Update.InboxID, EndpointID: lease.Update.EndpointID,
			Generation: payload.Generation, DesiredVersion: payload.DesiredVersion,
			Message: cloneInboundMessage(payload.Message), Scope: scope,
		}
		overlay := playerstate.NewLocalOverlay()
		collector := execution.NewMutationCollector(s.factory, execution.WithReservedStreamTypes(MessageWorkflowAggregateType))
		hostCtx, cancelHost := context.WithCancel(ctx)
		stopHeartbeat := make(chan struct{})
		heartbeatDone := make(chan callbackLeaseHeartbeatResult, 1)
		go s.keepLeaseAlive(hostCtx, cancelHost, lease.Update, stopHeartbeat, heartbeatDone)
		heartbeatJoined := false
		var heartbeat callbackLeaseHeartbeatResult
		joinHeartbeat := func() callbackLeaseHeartbeatResult {
			if heartbeatJoined {
				return heartbeat
			}
			close(stopHeartbeat)
			// A real claimed lease bounds an in-flight renewal itself. Test and
			// explicitly non-durable repositories may omit the expiry, so they
			// still need cancellation to make the handoff bounded.
			if lease.Update.LeaseExpiresAt.IsZero() {
				cancelHost()
			}
			heartbeat = <-heartbeatDone
			cancelHost()
			heartbeatJoined = true
			lease.Update = heartbeat.update
			startedVersion = heartbeat.update.Version
			return heartbeat
		}
		afterCallbackFailure := func(cause error) (CallbackResultSummary, error) {
			heartbeat := joinHeartbeat()
			if heartbeat.err != nil {
				cause = heartbeat.err
			}
			return s.afterMarkerFailure(summary, cause, lease.Update, startedVersion)
		}

		callbackResult, hostErr := invokeCallbackHost(hostCtx, s.host, request, overlay, collector)
		if callbackResult.Release != nil {
			defer callbackResult.Release()
		}
		if hostErr != nil {
			return afterCallbackFailure(hostErr)
		}
		if workflowErr := validateWorkflowResult(callbackResult.Workflow); workflowErr != nil {
			return afterCallbackFailure(workflowErr)
		}
		work, buildErr := collector.UnitOfWork()
		if buildErr != nil {
			return afterCallbackFailure(buildErr)
		}
		// Derived effects belong to the inbound conversation even when a hidden
		// roll or notice is addressed elsewhere.
		if lease.Update.Subject != "" {
			for i := range work.Effects {
				work.Effects[i].Subject = lease.Update.Subject
			}
		}
		if callbackResult.Workflow != nil {
			workflow := callbackResult.Workflow
			workflowWork := eventstore.UnitOfWork{Streams: []eventstore.StreamAppend{{
				Stream:          eventstore.StreamID{AggregateType: MessageWorkflowAggregateType, AggregateID: workflow.ID},
				ExpectedVersion: workflow.ExpectedVersion,
				Events:          []eventstore.NewEvent{workflow.Event},
			}}}
			work, buildErr = execution.MergeUnitOfWork(work, workflowWork)
			if buildErr != nil {
				return afterCallbackFailure(buildErr)
			}
		}

		unlockFence, fenceErr := waitCallbackCommitFence(hostCtx, callbackResult.CommitFence)
		if fenceErr != nil {
			return afterCallbackFailure(fenceErr)
		}
		fenceHeld := true
		releaseFence := func() {
			if fenceHeld {
				unlockFence()
				fenceHeld = false
			}
		}
		defer releaseFence()
		afterHandoffFailure := func(cause error) (CallbackResultSummary, error) {
			releaseFence()
			return s.afterMarkerFailure(summary, cause, lease.Update, startedVersion)
		}

		heartbeat = joinHeartbeat()
		if heartbeat.err != nil {
			return afterHandoffFailure(heartbeat.err)
		}
		if contextErr := ctx.Err(); contextErr != nil {
			return afterHandoffFailure(contextErr)
		}

		// Finish the heartbeat-to-CAS handoff with one ordinary-duration renew.
		// No renewal can change Version after terminal.ExpectedVersion is built.
		renewCtx, renewCancel, renewContextErr := s.leaseOperationContext(ctx, lease.Update)
		if renewContextErr != nil {
			return afterHandoffFailure(renewContextErr)
		}
		renewed, renewErr := s.renewCallbackLease(renewCtx, lease.Update)
		renewCancel()
		if renewErr != nil {
			return afterHandoffFailure(renewErr)
		}
		lease.Update = renewed
		startedVersion = renewed.Version

		completedAt := s.clock.Now().UTC()
		terminalVersion, terminalErr := nextCallbackVersion(startedVersion)
		if terminalErr != nil {
			return afterHandoffFailure(terminalErr)
		}
		terminal := eventstore.InboxUpdate{
			InboxID: lease.Update.InboxID, ExpectedVersion: startedVersion, Version: terminalVersion,
			Status: eventstore.InboxStatusConfirmedConsumed, LeaseOwner: lease.Update.LeaseOwner,
			LeaseEpoch: lease.Update.LeaseEpoch, AttemptID: lease.Update.AttemptID,
			LeaseExpiresAt: lease.Update.LeaseExpiresAt, CompletedAt: completedAt,
		}
		if callbackResult.Workflow != nil {
			terminal.WorkflowID = callbackResult.Workflow.ID
		}
		work.InboxUpdates = append(work.InboxUpdates, terminal)
		if commitErr := eventstore.ValidateUnitOfWork(work); commitErr != nil {
			return afterHandoffFailure(commitErr)
		}

		// With renewal frozen, bound connection/transaction waiting to finish
		// before the freshly renewed lease can naturally expire.
		commitCtx, commitCancel, commitContextErr := s.leaseOperationContext(ctx, lease.Update)
		if commitContextErr != nil {
			return afterHandoffFailure(commitContextErr)
		}
		_, commitErr := s.store.Commit(commitCtx, work)
		commitCancel()
		if commitErr != nil {
			return afterHandoffFailure(commitErr)
		}
		if callbackResult.PublishCommitted != nil {
			callbackResult.PublishCommitted()
		}
		// The commit fence protects only the terminal linearization point.
		// Notifications may synchronously re-enter runtime loading and therefore
		// must run after the short exclusion has been released.
		releaseFence()
		if callbackResult.AfterCommit != nil {
			callbackResult.AfterCommit()
		}
		summary.InboxID, summary.Status = lease.Update.InboxID, eventstore.InboxStatusConfirmedConsumed
		if callbackResult.Workflow != nil {
			summary.WorkflowID = callbackResult.Workflow.ID
		}
		return summary, nil
	}
	return summary, eventstore.ErrConflict
}
func (s *CallbackService) decodeClaimed(_ context.Context, update eventstore.InboxUpdate) (ingressPayload, error) {
	decoded, err := decodeIngressPayload(update.Payload)
	if err != nil {
		return ingressPayload{}, err
	}
	if string(decoded.EndpointID) != update.EndpointID || !bytes.Equal(decoded.ContentDigest, update.ContentDigest) {
		return ingressPayload{}, fmt.Errorf("%w: ingress metadata mismatch", ErrCallbackPayload)
	}
	return decoded, nil
}

func decodeIngressPayload(payload []byte) (ingressPayload, error) {
	if len(payload) == 0 || len(payload) > eventstore.MaxEventPayloadBytes {
		return ingressPayload{}, fmt.Errorf("%w: payload bound", ErrCallbackPayload)
	}
	if err := validateStrictJSON(payload); err != nil {
		return ingressPayload{}, fmt.Errorf("%w: strict JSON: %w", ErrCallbackPayload, err)
	}
	var shape any
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(&shape); err != nil || shape == nil {
		return ingressPayload{}, fmt.Errorf("%w: payload object", ErrCallbackPayload)
	}
	if _, ok := shape.(map[string]any); !ok || containsNull(shape) {
		return ingressPayload{}, fmt.Errorf("%w: null or non-object payload", ErrCallbackPayload)
	}
	decoder = json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var decoded ingressPayload
	if err := decoder.Decode(&decoded); err != nil {
		return ingressPayload{}, fmt.Errorf("%w: %w", ErrCallbackPayload, err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ingressPayload{}, fmt.Errorf("%w: trailing payload", ErrCallbackPayload)
	}
	if decoded.Status != eventstore.InboxStatusPending || decoded.Generation == 0 || decoded.DesiredVersion == 0 || !decoded.EndpointID.Valid() || len(decoded.ContentDigest) == 0 || len(decoded.ContentDigest) > eventstore.MaxEventPayloadBytes {
		return ingressPayload{}, fmt.Errorf("%w: envelope fields", ErrCallbackPayload)
	}
	if err := decoded.Message.Validate(); err != nil {
		return ingressPayload{}, fmt.Errorf("%w: message", ErrCallbackPayload)
	}
	return decoded, nil
}

func containsNull(value any) bool {
	switch item := value.(type) {
	case nil:
		return true
	case []any:
		for _, child := range item {
			if containsNull(child) {
				return true
			}
		}
	case map[string]any:
		for _, child := range item {
			if containsNull(child) {
				return true
			}
		}
	}
	return false
}

func (s *CallbackService) resolveCallbackScope(ctx context.Context, endpoint string, payload ingressPayload) (CallbackScope, error) {
	scope, err := s.resolver.Resolve(ctx, endpoint, cloneInboundMessage(payload.Message))
	if err != nil {
		return CallbackScope{}, err
	}
	if err := validateCallbackScope(scope); err != nil {
		return CallbackScope{}, err
	}
	return scope, nil
}

func validateCallbackScope(scope CallbackScope) error {
	if err := groupstate.ValidateIdentity(scope.DiceID, scope.GroupID); err != nil {
		return ErrCallbackScope
	}
	if err := groupstate.ValidatePlayerIdentity(scope.DiceID, scope.GroupID, scope.UserID); err != nil {
		return ErrCallbackScope
	}
	return nil
}

func validateClaimAt(update eventstore.InboxUpdate, now time.Time, workerID string) error {
	if update.InboxID == "" || update.Status != eventstore.InboxStatusLeased || update.Version == 0 || strings.TrimSpace(update.LeaseOwner) == "" || update.LeaseOwner != workerID || update.LeaseEpoch == 0 || strings.TrimSpace(update.AttemptID) == "" {
		return ErrCallbackLease
	}
	if !update.LeaseExpiresAt.IsZero() && !update.LeaseExpiresAt.After(now.UTC()) {
		return ErrCallbackLease
	}
	return nil
}

func nextCallbackVersion(version uint64) (uint64, error) {
	if version >= ^uint64(0)>>1 {
		return 0, eventstore.ErrVersionExhausted
	}
	return version + 1, nil
}

func isPreMarkerConflict(err error) bool {
	return errors.Is(err, eventstore.ErrConflict) || errors.Is(err, eventstore.ErrParticipantConflict) || errors.Is(err, eventstore.ErrStaleLease)
}

func (s *CallbackService) failLease(ctx context.Context, lease eventstore.InboxUpdate) error {
	_, err := s.inbox.UpdateInbox(ctx, eventstore.InboxUpdate{
		InboxID: lease.InboxID, ExpectedVersion: lease.Version, Version: lease.Version,
		Status: eventstore.InboxStatusFailed, LeaseOwner: lease.LeaseOwner, LeaseEpoch: lease.LeaseEpoch,
		AttemptID: lease.AttemptID, LeaseExpiresAt: lease.LeaseExpiresAt,
	})
	return err
}

const callbackAmbiguityTimeout = 5 * time.Second

func (s *CallbackService) afterMarkerFailure(summary CallbackResultSummary, cause error, lease eventstore.InboxUpdate, version uint64) (CallbackResultSummary, error) {
	recoveryCtx, cancel := context.WithTimeout(context.Background(), callbackAmbiguityTimeout)
	defer cancel()
	if err := s.markAmbiguous(recoveryCtx, lease, version); err != nil {
		return summary, errors.Join(cause, err)
	}
	summary.Status = eventstore.InboxStatusAmbiguous
	return summary, cause
}

func (s *CallbackService) markAmbiguous(ctx context.Context, lease eventstore.InboxUpdate, version uint64) error {
	_, err := s.inbox.UpdateInbox(ctx, eventstore.InboxUpdate{
		InboxID: lease.InboxID, ExpectedVersion: version, Version: version,
		Status: eventstore.InboxStatusAmbiguous, LeaseOwner: lease.LeaseOwner, LeaseEpoch: lease.LeaseEpoch,
		AttemptID: lease.AttemptID, LeaseExpiresAt: lease.LeaseExpiresAt,
	})
	return err
}
func invokeCallbackHost(ctx context.Context, host CallbackHost, request CallbackRequest, overlay *playerstate.LocalOverlay, collector *execution.MutationCollector) (result CallbackResult, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = errors.New("messageflow: callback host panic")
		}
	}()
	return host.HandleCallback(ctx, request, overlay, collector)
}

func cloneInboundMessage(message adapterapi.InboundMessage) adapterapi.InboundMessage {
	message.Segments = append([]adapterapi.InboundSegment(nil), message.Segments...)
	if message.AdapterEvent != nil {
		event := *message.AdapterEvent
		message.AdapterEvent = &event
	}
	return message
}

func validateWorkflowResult(workflow *WorkflowResult) error {
	if workflow == nil {
		return nil
	}
	if !validWorkflowID(workflow.ID) || execution.ContainsTransientText(workflow.ID) || workflow.ExpectedVersion == ^uint64(0) {
		return ErrCallbackWorkflow
	}
	if workflow.Event.EventType != MessageWorkflowTerminatedEventType || workflow.Event.SchemaVersion == 0 || workflow.Event.Metadata.EventID == "" || workflow.Event.Metadata.CommandID == "" || workflow.Event.Metadata.CorrelationID == "" || len(workflow.Event.Payload) == 0 || len(workflow.Event.Payload) > eventstore.MaxEventPayloadBytes {
		return ErrCallbackWorkflow
	}
	if execution.ContainsTransientEvent(workflow.Event) {
		return ErrCallbackWorkflow
	}
	return nil
}

func validWorkflowID(value string) bool {
	if strings.TrimSpace(value) == "" || len(value) > MaxWorkflowIDBytes {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f || r == '/' || r == '\\' {
			return false
		}
	}
	return true
}

func validateStrictJSON(value []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.UseNumber()
	if _, err := scanJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) (bool, error) {
	token, err := decoder.Token()
	if err != nil {
		return false, err
	}
	switch value := token.(type) {
	case string:
		// Templates may reference $t variables without persisting request-local state.
		return false, nil
	case json.Delim:
		switch value {
		case '{':
			seen := make(map[string]struct{})
			overlay := false
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return false, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return false, errors.New("invalid JSON object key")
				}
				if _, duplicate := seen[key]; duplicate {
					return false, errors.New("duplicate JSON object key")
				}
				seen[key] = struct{}{}
				if strings.HasPrefix(key, "$t") {
					overlay = true
				}
				childOverlay, err := scanJSONValue(decoder)
				if err != nil {
					return false, err
				}
				overlay = overlay || childOverlay
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				if err == nil {
					err = errors.New("invalid JSON object")
				}
				return false, err
			}
			return overlay, nil
		case '[':
			overlay := false
			for decoder.More() {
				childOverlay, err := scanJSONValue(decoder)
				if err != nil {
					return false, err
				}
				overlay = overlay || childOverlay
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				if err == nil {
					err = errors.New("invalid JSON array")
				}
				return false, err
			}
			return overlay, nil
		}
		return false, errors.New("unexpected JSON delimiter")
	default:
		return false, nil
	}
}
