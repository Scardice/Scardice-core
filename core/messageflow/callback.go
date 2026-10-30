package messageflow

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	"Scardice-core/adapterapi"
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

// CallbackGroupLoader loads an immutable copy of the group-record read model.
type CallbackGroupLoader interface {
	Load(ctx context.Context, diceID, groupID string) (groupstate.State, error)
}

// CallbackPlayerLoader loads the player and group-user attribute read models.
type CallbackPlayerLoader interface {
	LoadPlayer(ctx context.Context, diceID, groupID, userID string) (playerstate.PlayerState, error)
	LoadGroupUserAttrs(ctx context.Context, diceID, groupID, userID string) (playerstate.GroupUserAttrsState, error)
}

// CallbackScopeResolver maps normalized ingress facts to durable state owners.
type CallbackScopeResolver interface {
	Resolve(ctx context.Context, endpointID string, message adapterapi.InboundMessage) (CallbackScope, error)
}

// CallbackRequest contains only copied provider-neutral facts and read models.
// It deliberately contains no encrypted ingress bytes, SDK pointers, or runtime
// compatibility objects.
type CallbackRequest struct {
	InboxID        string
	EndpointID     string
	Generation     uint64
	DesiredVersion uint64
	Message        adapterapi.InboundMessage
	Scope          CallbackScope
	Group          groupstate.CompatibilityView
	Player         playerstate.PlayerCompatibilityView
	Attrs          playerstate.GroupUserAttrsCompatibilityView
}

// WorkflowResult is returned only for a named asynchronous callback. The
// event must be the terminal event for the named message-workflow stream.
type WorkflowResult struct {
	ID              string
	ExpectedVersion uint64
	Event           eventstore.NewEvent
}

// CallbackResult is the compatibility host's durable decision. Mutations are
// collected through the supplied MutationCollector; only an explicit Workflow
// creates a message-workflow stream.
type CallbackCommitFence interface {
	TryLock() bool
	Unlock()
}

type CallbackResult struct {
	Workflow    *WorkflowResult
	CommitFence CallbackCommitFence
	AfterCommit func()
	// Release relinquishes host-owned serialization after the complete callback
	// UnitOfWork. CallbackService defers it after the host returns, keeping the
	// fence held through commit and AfterCommit and releasing it on every exit.
	Release func()
}

// CompatibilityHost is the one mutable legacy seam. The service calls it only
// after the inbox row has durably entered callback-started.
type CompatibilityHost interface {
	HandleCallback(ctx context.Context, request CallbackRequest, overlay *playerstate.LocalOverlay, collector *MutationCollector) (CallbackResult, error)
}

// CallbackAdmission serializes hosts whose compatibility state is shared across
// endpoint lanes. Admission precedes claiming, so waiting never consumes a lease.
type CallbackAdmission interface {
	BeginCallback(context.Context) (context.Context, func(), error)
}

// BoundPayloadDecryptor authenticates callback payloads with the inbox
// identity and endpoint as AEAD associated data.
type BoundPayloadDecryptor interface {
	DecryptBound(ctx context.Context, domain, identity, owner string, version uint64, ciphertext, nonce []byte, keyID string) ([]byte, error)
}

// CallbackConfig wires the narrow durable callback service.
type CallbackConfig struct {
	Inbox      eventstore.InboxRepository
	Store      eventstore.Store
	Codec      eventstore.PayloadCodec
	BoundCodec BoundPayloadDecryptor
	Resolver   CallbackScopeResolver
	Group      CallbackGroupLoader
	Player     CallbackPlayerLoader
	Host       CompatibilityHost
	WorkerID   string

	// AllowUnboundCodec is only for explicitly non-A6 codecs. Production
	// callback services must provide BoundCodec or a Codec implementing it.
	AllowUnboundCodec bool
	LeaseDuration     time.Duration
	Clock             eventstore.Clock
	Factory           eventstore.EventFactory
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
	inbox        eventstore.InboxRepository
	store        eventstore.Store
	codec        eventstore.PayloadCodec
	boundCodec   BoundPayloadDecryptor
	resolver     CallbackScopeResolver
	group        CallbackGroupLoader
	player       CallbackPlayerLoader
	host         CompatibilityHost
	workerID     string
	allowUnbound bool
	lease        time.Duration
	clock        eventstore.Clock
	factory      eventstore.EventFactory
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
	boundCodec := config.BoundCodec
	if callbackIsNil(boundCodec) {
		boundCodec = nil
	}
	if boundCodec == nil && !callbackIsNil(config.Codec) {
		boundCodec, _ = config.Codec.(BoundPayloadDecryptor)
		if callbackIsNil(boundCodec) {
			boundCodec = nil
		}
	}
	if callbackIsNil(config.Inbox) || callbackIsNil(config.Store) || callbackIsNil(config.Resolver) || callbackIsNil(config.Group) || callbackIsNil(config.Player) || callbackIsNil(config.Host) || strings.TrimSpace(config.WorkerID) == "" {
		return nil, ErrCallbackUnavailable
	}
	if boundCodec == nil && (!config.AllowUnboundCodec || callbackIsNil(config.Codec)) {
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
		inbox: config.Inbox, store: config.Store, codec: config.Codec, boundCodec: boundCodec,
		resolver: config.Resolver, group: config.Group, player: config.Player, host: config.Host,
		workerID: config.WorkerID, allowUnbound: config.AllowUnboundCodec, lease: config.LeaseDuration,
		clock: config.Clock, factory: config.Factory,
	}, nil
}

// ProcessOne claims the earliest unresolved lane item and either commits one
// atomic callback UnitOfWork or leaves the row failed/ambiguous. Host execution
// is never retried after callback-started.
func (s *CallbackService) ProcessOne(ctx context.Context) (summary CallbackResultSummary, err error) {
	if s == nil || s.inbox == nil || s.store == nil || (s.codec == nil && s.boundCodec == nil) || s.resolver == nil || s.group == nil || s.player == nil || s.host == nil {
		return summary, ErrCallbackUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if admission, ok := s.host.(CallbackAdmission); ok {
		var release func()
		ctx, release, err = admission.BeginCallback(ctx)
		if err != nil {
			return summary, err
		}
		defer release()
	}
	for attempt := 1; attempt <= CallbackMaxPreMarkerAttempts; attempt++ {
		summary.Attempts = attempt
		lease, claimErr := s.inbox.ClaimInbox(ctx, eventstore.InboxClaimRequest{WorkerID: s.workerID, LeaseDuration: s.lease, QuarantinePayloadErrors: true, TerminalizeExpired: true, RecoverExpiredCallbackStarted: true})
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
		scope, group, player, attrs, loadErr := s.loadCallbackState(ctx, lease.Update.EndpointID, payload)
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
			Group: group.CompatibilityView(), Player: player.CompatibilityView(), Attrs: attrs.CompatibilityView(),
		}
		overlay := playerstate.NewLocalOverlay()
		collector := NewMutationCollector(s.factory)
		collector.subjectKey = append([]byte(nil), lease.Update.SubjectKey...)
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
		work, buildErr := collector.unitOfWork()
		if buildErr != nil {
			return afterCallbackFailure(buildErr)
		}
		if callbackResult.Workflow != nil {
			if err := collector.addWorkflow(*callbackResult.Workflow); err != nil {
				return afterCallbackFailure(err)
			}
			work, buildErr = collector.unitOfWork()
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

		if !lease.Update.PayloadExpiresAt.IsZero() && !lease.Update.PayloadExpiresAt.After(s.clock.Now().UTC()) {
			return afterHandoffFailure(eventstore.ErrPayloadExpired)
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
func (s *CallbackService) decodeClaimed(ctx context.Context, update eventstore.InboxUpdate) (ingressPayload, error) {
	var plaintext []byte
	var err error
	version := update.PayloadVersion
	if version == 0 {
		version = 1
	}
	if s.boundCodec != nil {
		plaintext, err = s.boundCodec.DecryptBound(ctx, "inbox/v1", update.InboxID, update.EndpointID, version, append([]byte(nil), update.PayloadCiphertext...), append([]byte(nil), update.PayloadNonce...), update.PayloadEncryptionKeyID)
	} else if s.allowUnbound && s.codec != nil {
		plaintext, err = s.codec.Decrypt(ctx, append([]byte(nil), update.PayloadCiphertext...), append([]byte(nil), update.PayloadNonce...), update.PayloadEncryptionKeyID)
	} else {
		return ingressPayload{}, ErrCallbackUnavailable
	}
	if err != nil {
		return ingressPayload{}, err
	}
	decoded, err := decodeIngressPayload(plaintext)
	if err != nil {
		return ingressPayload{}, err
	}
	digestKeyID := update.ContentDigestKeyID
	if digestKeyID == "" {
		digestKeyID = update.DigestKeyID
	}
	if subtle.ConstantTimeCompare([]byte(decoded.EndpointID), []byte(update.EndpointID)) != 1 ||
		subtle.ConstantTimeCompare(decoded.ContentDigest, update.ContentDigest) != 1 ||
		subtle.ConstantTimeCompare([]byte(decoded.ContentDigestKeyID), []byte(digestKeyID)) != 1 {
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

func (s *CallbackService) loadCallbackState(ctx context.Context, endpoint string, payload ingressPayload) (CallbackScope, groupstate.State, playerstate.PlayerState, playerstate.GroupUserAttrsState, error) {
	scope, scopeErr := s.resolver.Resolve(ctx, endpoint, cloneInboundMessage(payload.Message))
	if scopeErr != nil {
		return CallbackScope{}, groupstate.State{}, playerstate.PlayerState{}, playerstate.GroupUserAttrsState{}, scopeErr
	}
	if err := validateCallbackScope(scope); err != nil {
		return CallbackScope{}, groupstate.State{}, playerstate.PlayerState{}, playerstate.GroupUserAttrsState{}, err
	}
	group, scopeErr := s.group.Load(ctx, scope.DiceID, scope.GroupID)
	if scopeErr != nil {
		return CallbackScope{}, groupstate.State{}, playerstate.PlayerState{}, playerstate.GroupUserAttrsState{}, scopeErr
	}
	player, scopeErr := s.player.LoadPlayer(ctx, scope.DiceID, scope.GroupID, scope.UserID)
	if scopeErr != nil {
		return CallbackScope{}, groupstate.State{}, playerstate.PlayerState{}, playerstate.GroupUserAttrsState{}, scopeErr
	}
	attrs, scopeErr := s.player.LoadGroupUserAttrs(ctx, scope.DiceID, scope.GroupID, scope.UserID)
	if scopeErr != nil {
		return CallbackScope{}, groupstate.State{}, playerstate.PlayerState{}, playerstate.GroupUserAttrsState{}, scopeErr
	}
	if group.Version > 0 && (group.DiceID != scope.DiceID || group.GroupID != scope.GroupID) {
		return CallbackScope{}, groupstate.State{}, playerstate.PlayerState{}, playerstate.GroupUserAttrsState{}, ErrCallbackScope
	}
	if player.Version > 0 && (player.DiceID != scope.DiceID || player.GroupID != scope.GroupID || player.UserID != scope.UserID) {
		return CallbackScope{}, groupstate.State{}, playerstate.PlayerState{}, playerstate.GroupUserAttrsState{}, ErrCallbackScope
	}
	if attrs.Version > 0 && (attrs.DiceID != scope.DiceID || attrs.GroupID != scope.GroupID || attrs.UserID != scope.UserID) {
		return CallbackScope{}, groupstate.State{}, playerstate.PlayerState{}, playerstate.GroupUserAttrsState{}, ErrCallbackScope
	}
	return scope, group.Clone(), player.Clone(), attrs.Clone(), nil
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
	if update.InboxID == "" || update.Status != eventstore.InboxStatusLeased || update.Version == 0 || strings.TrimSpace(update.LeaseOwner) == "" || update.LeaseOwner != workerID || update.LeaseEpoch == 0 || strings.TrimSpace(update.AttemptID) == "" || len(update.PayloadCiphertext) == 0 || len(update.PayloadNonce) == 0 || strings.TrimSpace(update.PayloadEncryptionKeyID) == "" {
		return ErrCallbackLease
	}
	if !update.LeaseExpiresAt.IsZero() && !update.LeaseExpiresAt.After(now.UTC()) {
		return ErrCallbackLease
	}
	if !update.PayloadExpiresAt.IsZero() && !update.PayloadExpiresAt.After(now.UTC()) {
		return eventstore.ErrPayloadExpired
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
func invokeCallbackHost(ctx context.Context, host CompatibilityHost, request CallbackRequest, overlay *playerstate.LocalOverlay, collector *MutationCollector) (result CallbackResult, err error) {
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
	if !validWorkflowID(workflow.ID) || containsOverlayText(workflow.ID) || workflow.ExpectedVersion == ^uint64(0) {
		return ErrCallbackWorkflow
	}
	if workflow.Event.EventType != MessageWorkflowTerminatedEventType || containsOverlayText(workflow.Event.EventType) || workflow.Event.SchemaVersion == 0 || workflow.Event.Metadata.EventID == "" || workflow.Event.Metadata.CommandID == "" || workflow.Event.Metadata.CorrelationID == "" || len(workflow.Event.Payload) == 0 || len(workflow.Event.Payload) > eventstore.MaxEventPayloadBytes {
		return ErrCallbackWorkflow
	}
	if containsOverlayEventPayload(workflow.Event.Payload) || containsOverlayMetadata(workflow.Event.Metadata) {
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

func containsOverlayEventPayload(value []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.UseNumber()
	decoded, err := scanJSONValue(decoder)
	if err != nil {
		return true
	}
	if _, err := decoder.Token(); err != io.EOF {
		return true
	}
	return decoded
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

func containsOverlayMetadata(metadata eventstore.Metadata) bool {
	return containsOverlayText(metadata.EventID) ||
		containsOverlayText(metadata.CommandID) ||
		containsOverlayText(metadata.CorrelationID) ||
		containsOverlayText(metadata.CausationID) ||
		containsOverlayText(metadata.PrincipalID) ||
		containsOverlayText(metadata.Producer)
}

func containsOverlayText(value string) bool {
	return strings.Contains(value, "$t")
}
func containsOverlayStream(stream eventstore.StreamID) bool {
	return containsOverlayText(stream.AggregateType) || containsOverlayText(stream.AggregateID)
}

func containsOverlayEvent(event eventstore.NewEvent) bool {
	return containsOverlayText(event.EventType) || containsOverlayMetadata(event.Metadata) || containsOverlayEventPayload(event.Payload)
}

func containsOverlayPlugin(update eventstore.PluginKVUpdate) bool {
	return containsOverlayText(update.ExtensionID) || containsOverlayText(update.EncryptionKeyID)
}

func containsOverlayEffect(effect eventstore.NewEffect) bool {
	return containsOverlayText(effect.EffectID) ||
		containsOverlayText(effect.EndpointID) ||
		containsOverlayText(effect.EffectType) ||
		containsOverlayText(effect.RiskClass) ||
		containsOverlayText(effect.Status) ||
		containsOverlayText(effect.AttemptID) ||
		containsOverlayText(effect.LeaseOwner) ||
		containsOverlayText(effect.DigestKeyID) ||
		containsOverlayText(effect.PayloadEncryptionKeyID) ||
		containsOverlayText(effect.ContentDigestKeyID) ||
		containsOverlayText(effect.ProviderMessageID) ||
		containsOverlayText(effect.ResultCode) ||
		containsOverlayText(effect.ErrorCode) ||
		containsOverlayText(effect.Resolution) ||
		containsOverlayText(effect.PrincipalID) ||
		containsOverlayText(effect.Reason)
}

// MutationCollector is the sole callback mutation output. It owns copied
// event/effect/KV bytes and rejects duplicate participants before commit.
type MutationCollector struct {
	factory    eventstore.EventFactory
	streams    map[eventstore.StreamID]eventstore.StreamAppend
	plugins    map[string]eventstore.PluginKVUpdate
	secrets    map[string]eventstore.SecretUpdate
	effects    []eventstore.NewEffect
	effectIDs  map[string]struct{}
	operations map[string]eventstore.OperationUpdate
	logUpdates []eventstore.LogUpdate
	subjectKey []byte
	workflow   *eventstore.StreamAppend
}

func NewMutationCollector(factory eventstore.EventFactory) *MutationCollector {
	if callbackIsNil(factory.Clock) {
		factory.Clock = eventstore.SystemClock{}
	}
	if callbackIsNil(factory.IDs) {
		factory.IDs = eventstore.UUIDGenerator{}
	}
	return &MutationCollector{factory: factory, streams: map[eventstore.StreamID]eventstore.StreamAppend{}, plugins: map[string]eventstore.PluginKVUpdate{}, secrets: map[string]eventstore.SecretUpdate{}, effectIDs: map[string]struct{}{}, operations: map[string]eventstore.OperationUpdate{}}
}

// AddStream adds already-decided events to one non-workflow stream.

func (c *MutationCollector) AddStream(stream eventstore.StreamID, expectedVersion uint64, events []eventstore.NewEvent) error {
	if c == nil || stream.AggregateType == "" || stream.AggregateID == "" || len(events) == 0 || stream.AggregateType == MessageWorkflowAggregateType || containsOverlayStream(stream) {
		return ErrCallbackWorkflow
	}
	if c.streams == nil {
		c.streams = make(map[eventstore.StreamID]eventstore.StreamAppend)
	}
	if _, exists := c.streams[stream]; exists {
		return eventstore.ErrDuplicateStream
	}
	if len(c.streams) >= eventstore.MaxUnitOfWorkStreams {
		return &eventstore.OversizeError{Bound: "unit of work streams", Limit: eventstore.MaxUnitOfWorkStreams, Actual: len(c.streams) + 1}
	}
	eventCount := len(events)
	for _, item := range c.streams {
		eventCount += len(item.Events)
	}
	if eventCount > eventstore.MaxUnitOfWorkEvents {
		return &eventstore.OversizeError{Bound: "unit of work events", Limit: eventstore.MaxUnitOfWorkEvents, Actual: eventCount}
	}
	copied := make([]eventstore.NewEvent, len(events))
	for i, event := range events {
		var reason string
		switch {
		case event.EventType == "":
			reason = "missing event type"
		case event.SchemaVersion == 0:
			reason = "missing schema version"
		case len(event.Payload) > eventstore.MaxEventPayloadBytes:
			reason = "payload exceeds event bound"
		case event.Metadata.EventID == "" || event.Metadata.CommandID == "" || event.Metadata.CorrelationID == "":
			reason = "missing event, command or correlation ID"
		case containsOverlayEvent(event):
			reason = "request-local identity/key or malformed JSON"
		}
		if reason != "" {
			return fmt.Errorf("%w: aggregate=%s event[%d]=%s: %s", eventstore.ErrInvalidEvent, stream.AggregateType, i, event.EventType, reason)
		}
		copied[i] = cloneNewEvent(event)
	}
	c.streams[stream] = eventstore.StreamAppend{Stream: stream, ExpectedVersion: expectedVersion, Events: copied}
	return nil
}

// AddGroupEvents serializes typed Group facts with the injected event factory.
func (c *MutationCollector) AddGroupEvents(stream eventstore.StreamID, expectedVersion uint64, metadata eventstore.Metadata, events []groupstate.TypedEvent) error {
	if c == nil {
		return ErrCallbackUnavailable
	}
	encoded := make([]eventstore.NewEvent, 0, len(events))
	for index, event := range events {
		itemMetadata := metadata
		if index > 0 {
			itemMetadata.EventID = ""
		}
		item, err := groupstate.NewEventWithFactory(c.factory, event, itemMetadata)
		if err != nil {
			return err
		}
		encoded = append(encoded, item)
	}
	return c.AddStream(stream, expectedVersion, encoded)
}

func (c *MutationCollector) AddPlayerEvents(stream eventstore.StreamID, expectedVersion uint64, metadata eventstore.Metadata, events []playerstate.PlayerEvent) error {
	if c == nil {
		return ErrCallbackUnavailable
	}
	encoded := make([]eventstore.NewEvent, 0, len(events))
	for index, event := range events {
		itemMetadata := metadata
		if index > 0 {
			itemMetadata.EventID = ""
		}
		item, err := playerstate.NewEventWithFactory(c.factory, event, itemMetadata)
		if err != nil {
			return err
		}
		encoded = append(encoded, item)
	}
	return c.AddStream(stream, expectedVersion, encoded)
}

// AddModerationEvents serializes typed moderation facts.
func (c *MutationCollector) AddModerationEvents(stream eventstore.StreamID, expectedVersion uint64, metadata eventstore.Metadata, events []playerstate.ModerationEvent) error {
	if c == nil {
		return ErrCallbackUnavailable
	}
	encoded := make([]eventstore.NewEvent, 0, len(events))
	for index, event := range events {
		itemMetadata := metadata
		if index > 0 {
			itemMetadata.EventID = ""
		}
		item, err := playerstate.NewEventWithFactory(c.factory, event, itemMetadata)
		if err != nil {
			return err
		}
		encoded = append(encoded, item)
	}
	return c.AddStream(stream, expectedVersion, encoded)
}

// AddGroupUserAttrsEvents serializes typed group-user attribute facts.
func (c *MutationCollector) AddGroupUserAttrsEvents(stream eventstore.StreamID, expectedVersion uint64, metadata eventstore.Metadata, events []playerstate.GroupUserAttrsEvent) error {
	if c == nil {
		return ErrCallbackUnavailable
	}
	encoded := make([]eventstore.NewEvent, 0, len(events))
	for index, event := range events {
		itemMetadata := metadata
		if index > 0 {
			itemMetadata.EventID = ""
		}
		item, err := playerstate.NewEventWithFactory(c.factory, event, itemMetadata)
		if err != nil {
			return err
		}
		encoded = append(encoded, item)
	}
	return c.AddStream(stream, expectedVersion, encoded)
}

// AddPluginKV adds an already encrypted plugin state update. Plaintext key or
// value APIs are intentionally absent.
func (c *MutationCollector) AddPluginKV(update eventstore.PluginKVUpdate) error {
	return c.AddPluginKVBatch([]eventstore.PluginKVUpdate{update})
}

// AddPluginKVBatch validates every update before mutating the collector, so a
// failed batch cannot leave a partially staged unit of work.
func (c *MutationCollector) AddPluginKVBatch(updates []eventstore.PluginKVUpdate) error {
	if c == nil || len(updates) == 0 {
		return eventstore.ErrInvalidMetadata
	}
	copied := make([]eventstore.PluginKVUpdate, len(updates))
	seen := make(map[string]struct{}, len(updates))
	for i, update := range updates {
		if strings.TrimSpace(update.ExtensionID) == "" || len(update.KeyHMAC) == 0 || update.ValueSize < 0 || update.ValueSize > eventstore.MaxPluginValueBytes || containsOverlayPlugin(update) {
			return eventstore.ErrInvalidMetadata
		}
		if !update.Deleted && (len(update.KeyCiphertext) == 0 || len(update.KeyNonce) == 0 || len(update.ValueCiphertext) == 0 || len(update.ValueNonce) == 0 || strings.TrimSpace(update.EncryptionKeyID) == "") {
			return eventstore.ErrInvalidMetadata
		}
		key := pluginKey(update)
		if _, exists := c.plugins[key]; exists {
			return eventstore.ErrDuplicateParticipant
		}
		if _, exists := seen[key]; exists {
			return eventstore.ErrDuplicateParticipant
		}
		seen[key] = struct{}{}
		copied[i] = clonePlugin(update)
	}
	if c.plugins == nil {
		c.plugins = make(map[string]eventstore.PluginKVUpdate, len(copied))
	}
	for i := range copied {
		c.plugins[pluginKey(copied[i])] = copied[i]
	}
	return nil
}

func (c *MutationCollector) AddSecretUpdate(update eventstore.SecretUpdate) error {
	if c == nil || strings.TrimSpace(update.SecretRef) == "" || strings.TrimSpace(update.EndpointID) == "" || strings.TrimSpace(update.AdapterID) == "" || update.SecretVersion == 0 || len(update.Ciphertext) == 0 || len(update.Nonce) == 0 || strings.TrimSpace(update.EncryptionKeyID) == "" {
		return eventstore.ErrInvalidMetadata
	}
	if c.secrets == nil {
		c.secrets = make(map[string]eventstore.SecretUpdate)
	}
	if _, exists := c.secrets[update.SecretRef]; exists {
		return eventstore.ErrDuplicateParticipant
	}
	update.Ciphertext = append([]byte(nil), update.Ciphertext...)
	update.Nonce = append([]byte(nil), update.Nonce...)
	c.secrets[update.SecretRef] = update
	return nil
}

func (c *MutationCollector) AddEffect(effect eventstore.NewEffect) error {
	if c == nil || strings.TrimSpace(effect.EffectID) == "" || strings.TrimSpace(effect.EndpointID) == "" || len(effect.LaneHMAC) == 0 || strings.TrimSpace(effect.EffectType) == "" || !validRisk(effect.RiskClass) || effect.Status != eventstore.OutboxStatusPending || len(effect.PayloadCiphertext) == 0 || len(effect.PayloadNonce) == 0 || strings.TrimSpace(effect.PayloadEncryptionKeyID) == "" || containsOverlayEffect(effect) {
		return eventstore.ErrInvalidMetadata
	}
	if effect.ExpectedVersion != 0 || effect.PrincipalID != "" {
		return eventstore.ErrInvalidMetadata
	}
	if _, exists := c.effectIDs[effect.EffectID]; exists {
		return eventstore.ErrDuplicateParticipant
	}
	if len(c.subjectKey) > 0 && len(effect.SubjectKey) > 0 && !bytes.Equal(effect.SubjectKey, c.subjectKey) {
		return eventstore.ErrInvalidMetadata
	}
	effect.LaneHMAC = append([]byte(nil), effect.LaneHMAC...)
	if len(c.subjectKey) > 0 {
		effect.SubjectKey = append([]byte(nil), c.subjectKey...)
	} else {
		effect.SubjectKey = append([]byte(nil), effect.SubjectKey...)
	}
	effect.PayloadCiphertext = append([]byte(nil), effect.PayloadCiphertext...)
	effect.PayloadNonce = append([]byte(nil), effect.PayloadNonce...)
	effect.ContentDigest = append([]byte(nil), effect.ContentDigest...)
	if c.effectIDs == nil {
		c.effectIDs = make(map[string]struct{})
	}
	c.effectIDs[effect.EffectID] = struct{}{}
	c.effects = append(c.effects, effect)
	return nil
}

func (c *MutationCollector) AddLogUpdate(update eventstore.LogUpdate) error {
	if c == nil {
		return ErrCallbackUnavailable
	}
	if len(c.logUpdates) >= eventstore.MaxUnitOfWorkEvents {
		return &eventstore.OversizeError{Bound: "unit of work log updates", Limit: eventstore.MaxUnitOfWorkEvents, Actual: len(c.logUpdates) + 1}
	}
	update.Entry = cloneStoryLogEntry(update.Entry)
	update.Intent.Entry = cloneStoryLogEntry(update.Intent.Entry)
	c.logUpdates = append(c.logUpdates, update)
	return nil
}

func cloneStoryLogEntry(entry eventstore.StoryLogEntry) eventstore.StoryLogEntry {
	entry.CommandInfo = append(entry.CommandInfo[:0:0], entry.CommandInfo...)
	if entry.Seq != nil {
		value := *entry.Seq
		entry.Seq = &value
	}
	if entry.Removed != nil {
		value := *entry.Removed
		entry.Removed = &value
	}
	if entry.ParentID != nil {
		value := *entry.ParentID
		entry.ParentID = &value
	}
	return entry
}
func (c *MutationCollector) HasStoryLogStateUpdate(diceID, groupID string) bool {
	if c == nil {
		return false
	}
	for _, update := range c.logUpdates {
		if update.IsStoryLogStateUpdate() && update.DiceID == diceID && update.GroupID == groupID {
			return true
		}
	}
	return false
}

// AddPreparedOutbound imports exactly one validated outbound stream, operation,
// and effect produced by OutboundService.Prepare.
//
// The outputs of a callback belong to the subject of the message it handles,
// wherever they are addressed: a purge of that subject must reach everything
// derived from it, and the store fences them on that subject. Prepare keys an
// effect to its target conversation, which differs for a reply sent elsewhere
// (a hidden roll to the sender's private chat, a notice to another group), so
// the effect and its stream events are rebound to the callback's subject here.
func (c *MutationCollector) AddPreparedOutbound(prepared PreparedOutbound) error {
	work := prepared.Work
	if c == nil || prepared.Result.Deduplicated || len(work.Streams) != 1 || len(work.Operations) != 1 || len(work.Effects) != 1 {
		return eventstore.ErrInvalidMetadata
	}
	stream, operation, effect := work.Streams[0], work.Operations[0], work.Effects[0]
	if stream.Stream.AggregateType != "outbound-effect" || stream.Stream.AggregateID != effect.EffectID || operation.ResourceID != effect.EffectID || operation.OperationID == "" || operation.IdempotencyScope != "outbound" || operation.IdempotencyKey == "" {
		return eventstore.ErrInvalidMetadata
	}
	if _, exists := c.operations[operation.OperationID]; exists {
		return eventstore.ErrDuplicateParticipant
	}
	if len(c.subjectKey) > 0 {
		events := slices.Clone(stream.Events)
		for i := range events {
			events[i].Metadata.SubjectKey = slices.Clone(c.subjectKey)
		}
		stream.Events = events
		effect.SubjectKey = nil
	}
	if err := c.AddStream(stream.Stream, stream.ExpectedVersion, stream.Events); err != nil {
		return err
	}
	if err := c.AddEffect(effect); err != nil {
		delete(c.streams, stream.Stream)
		return err
	}
	c.operations[operation.OperationID] = operation
	return nil
}

// HasPreparedOutboundOperation reports whether this callback collector owns a
// staged outbound operation. It exposes only membership, not mutable work.
func (c *MutationCollector) HasPreparedOutboundOperation(operationID string) bool {
	if c == nil || operationID == "" {
		return false
	}
	operation, ok := c.operations[operationID]
	return ok && operation.Kind == "outbound-effect" && operation.IdempotencyScope == "outbound"
}

func (c *MutationCollector) AddPreparedOutboundWithLog(prepared PreparedOutbound, update eventstore.LogUpdate) error {
	if c == nil {
		return ErrCallbackUnavailable
	}
	logUpdateCount := len(c.logUpdates)
	if err := c.AddLogUpdate(update); err != nil {
		return err
	}
	if err := c.AddPreparedOutbound(prepared); err != nil {
		c.logUpdates = c.logUpdates[:logUpdateCount]
		return err
	}
	return nil
}

func (c *MutationCollector) addWorkflow(workflow WorkflowResult) error {
	if err := validateWorkflowResult(&workflow); err != nil {
		return err
	}
	stream := eventstore.StreamID{AggregateType: MessageWorkflowAggregateType, AggregateID: workflow.ID}
	if _, exists := c.streams[stream]; exists || c.workflow != nil {
		return eventstore.ErrDuplicateStream
	}
	c.workflow = &eventstore.StreamAppend{Stream: stream, ExpectedVersion: workflow.ExpectedVersion, Events: []eventstore.NewEvent{cloneNewEvent(workflow.Event)}}
	return nil
}

func (c *MutationCollector) unitOfWork() (eventstore.UnitOfWork, error) {
	if c == nil {
		return eventstore.UnitOfWork{}, ErrCallbackUnavailable
	}
	streams := make([]eventstore.StreamAppend, 0, len(c.streams)+1)
	for _, item := range c.streams {
		streams = append(streams, cloneStreamAppend(item))
	}
	if c.workflow != nil {
		streams = append(streams, cloneStreamAppend(*c.workflow))
	}
	sort.Slice(streams, func(i, j int) bool {
		if streams[i].Stream.AggregateType != streams[j].Stream.AggregateType {
			return streams[i].Stream.AggregateType < streams[j].Stream.AggregateType
		}
		return streams[i].Stream.AggregateID < streams[j].Stream.AggregateID
	})

	plugins := make([]eventstore.PluginKVUpdate, 0, len(c.plugins))
	for _, update := range c.plugins {
		plugins = append(plugins, clonePlugin(update))
	}
	sort.Slice(plugins, func(i, j int) bool {
		if plugins[i].ExtensionID != plugins[j].ExtensionID {
			return plugins[i].ExtensionID < plugins[j].ExtensionID
		}
		return bytes.Compare(plugins[i].KeyHMAC, plugins[j].KeyHMAC) < 0
	})
	secrets := make([]eventstore.SecretUpdate, 0, len(c.secrets))
	for _, update := range c.secrets {
		update.Ciphertext = append([]byte(nil), update.Ciphertext...)
		update.Nonce = append([]byte(nil), update.Nonce...)
		secrets = append(secrets, update)
	}
	sort.Slice(secrets, func(i, j int) bool { return secrets[i].SecretRef < secrets[j].SecretRef })
	effects := make([]eventstore.NewEffect, 0, len(c.effects))
	for _, effect := range c.effects {
		effects = append(effects, cloneEffect(effect))
	}
	operations := make([]eventstore.OperationUpdate, 0, len(c.operations))
	for _, operation := range c.operations {
		operations = append(operations, operation)
	}
	sort.Slice(operations, func(i, j int) bool { return operations[i].OperationID < operations[j].OperationID })
	logUpdates := make([]eventstore.LogUpdate, len(c.logUpdates))
	for i, update := range c.logUpdates {
		update.Entry = cloneStoryLogEntry(update.Entry)
		update.Intent.Entry = cloneStoryLogEntry(update.Intent.Entry)
		logUpdates[i] = update
	}
	return eventstore.UnitOfWork{Streams: streams, Operations: operations, SecretUpdates: secrets, PluginKVUpdates: plugins, Effects: effects, LogUpdates: logUpdates}, nil
}

// UnitOfWork returns an owned snapshot suitable for an explicit commit.
func (c *MutationCollector) UnitOfWork() (eventstore.UnitOfWork, error) {
	return c.unitOfWork()
}

func pluginKey(update eventstore.PluginKVUpdate) string {
	return update.ExtensionID + "\x00" + string(update.KeyHMAC)
}
func validRisk(value string) bool {
	return value == eventstore.RiskPreDispatchRetryable || value == eventstore.RiskProviderIdempotent || value == eventstore.RiskNonIdempotentAfterDispatch
}
func cloneNewEvent(event eventstore.NewEvent) eventstore.NewEvent {
	event.Payload = append([]byte(nil), event.Payload...)
	event.Metadata.SubjectKey = append([]byte(nil), event.Metadata.SubjectKey...)
	return event
}
func cloneStreamAppend(item eventstore.StreamAppend) eventstore.StreamAppend {
	item.Events = append([]eventstore.NewEvent(nil), item.Events...)
	for i := range item.Events {
		item.Events[i] = cloneNewEvent(item.Events[i])
	}
	return item
}
func clonePlugin(item eventstore.PluginKVUpdate) eventstore.PluginKVUpdate {
	item.KeyHMAC = append([]byte(nil), item.KeyHMAC...)
	item.KeyCiphertext = append([]byte(nil), item.KeyCiphertext...)
	item.KeyNonce = append([]byte(nil), item.KeyNonce...)
	item.ValueCiphertext = append([]byte(nil), item.ValueCiphertext...)
	item.ValueNonce = append([]byte(nil), item.ValueNonce...)
	return item
}
func cloneEffect(item eventstore.NewEffect) eventstore.NewEffect {
	item.LaneHMAC = append([]byte(nil), item.LaneHMAC...)
	item.SubjectKey = append([]byte(nil), item.SubjectKey...)
	item.PayloadCiphertext = append([]byte(nil), item.PayloadCiphertext...)
	item.PayloadNonce = append([]byte(nil), item.PayloadNonce...)
	item.ContentDigest = append([]byte(nil), item.ContentDigest...)
	return item
}
