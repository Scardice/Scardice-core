package endpoint

import (
	"context"
	"crypto/hmac"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/eventstore"
	"Scardice-core/logger"
)

var (
	ErrDispatcherDependencies = errors.New("endpoint dispatcher: dependencies required")
	ErrDispatcherRetry        = errors.New("endpoint dispatcher: retry requires provider idempotency")
	// errDispatchDeadlineExceededAfterDispatch marks a re-claimed effect whose
	// deadline has passed but which had already reached the provider on an
	// earlier attempt. The provider outcome is unknown, so it must be settled as
	// ambiguous rather than a deterministic terminal failure.
	errDispatchDeadlineExceededAfterDispatch = errors.New("endpoint dispatcher: deadline exceeded after dispatch")
)

func effectTypeForKind(kind adapterapi.EffectKind) string {
	switch kind {
	case adapterapi.EffectKindMessage:
		return "message"
	case adapterapi.EffectKindAction:
		return "action"
	default:
		return ""
	}
}

type DispatcherStore interface {
	eventstore.Store
	eventstore.OutboxRepository
	eventstore.OperationRepository
}

type effectWire struct {
	Effect    adapterapi.OutboundEffect `json:"effect"`
	RawTarget string                    `json:"rawTarget,omitempty"`
}
type DispatcherDecryptor interface {
	DecryptBound(ctx context.Context, domain, identity, owner string, version uint64, ciphertext, nonce []byte, keyID string) ([]byte, error)
}
type DispatcherClock interface{ Now() time.Time }
type dispatcherClock struct{}

func (dispatcherClock) Now() time.Time { return time.Now().UTC() }

// EffectSuccessNotifier observes a committed terminal success. Implementations
// must treat the callback as best-effort and must not perform provider I/O.
type EffectSuccessNotifier interface {
	NotifyOutboundEffectSucceeded(ctx context.Context, effect adapterapi.OutboundEffect, result adapterapi.EffectResult)
}

// EffectResultNotifier observes any committed terminal outcome. It allows
// consumers that retain in-memory acceptance state to clean it on failures.
type EffectResultNotifier interface {
	NotifyOutboundEffectResult(ctx context.Context, effect adapterapi.OutboundEffect, result adapterapi.EffectResult)
}

func uniformJitter(upperBound time.Duration) time.Duration {
	if upperBound <= 0 {
		return 0
	}
	n, err := crand.Int(crand.Reader, big.NewInt(int64(upperBound)))
	if err != nil {
		return 0
	}
	return time.Duration(n.Int64())
}

type EffectDispatcher struct {
	store           DispatcherStore
	decrypt         DispatcherDecryptor
	executor        EffectExecutor
	ids             eventstore.IDGenerator
	clock           DispatcherClock
	workerID        string
	lease           time.Duration
	executeTimeout  time.Duration
	random          func(time.Duration) time.Duration
	successNotifier EffectSuccessNotifier
	resultNotifier  EffectResultNotifier
}
type DispatcherOption func(*EffectDispatcher)

func WithDispatcherRandom(random func(time.Duration) time.Duration) DispatcherOption {
	return func(d *EffectDispatcher) {
		if random != nil {
			d.random = func(upperBound time.Duration) time.Duration {
				if upperBound <= 0 {
					return 0
				}
				value := random(upperBound)
				if value < 0 {
					return 0
				}
				if value >= upperBound {
					return upperBound - 1
				}
				return value
			}
		}
	}
}
func WithDispatcherClock(clock DispatcherClock) DispatcherOption {
	return func(d *EffectDispatcher) {
		if clock != nil {
			d.clock = clock
		}
	}
}
func WithDispatcherIDGenerator(ids eventstore.IDGenerator) DispatcherOption {
	return func(d *EffectDispatcher) {
		if ids != nil {
			d.ids = ids
		}
	}
}
func WithDispatcherTimeout(timeout time.Duration) DispatcherOption {
	return func(d *EffectDispatcher) {
		if timeout > 0 {
			d.executeTimeout = timeout
		}
	}
}
func WithEffectResultNotifier(notifier EffectResultNotifier) DispatcherOption {
	return func(d *EffectDispatcher) {
		d.resultNotifier = notifier
	}
}
func WithEffectSuccessNotifier(notifier EffectSuccessNotifier) DispatcherOption {
	return func(d *EffectDispatcher) {
		d.successNotifier = notifier
	}
}

func NewEffectDispatcher(store DispatcherStore, decrypt DispatcherDecryptor, executor EffectExecutor, workerID string, options ...DispatcherOption) (*EffectDispatcher, error) {
	if store == nil || decrypt == nil || executor == nil || workerID == "" {
		return nil, ErrDispatcherDependencies
	}
	if _, ok := store.(eventstore.OutboxQuarantineRepository); !ok {
		return nil, ErrDispatcherDependencies
	}
	d := &EffectDispatcher{store: store, decrypt: decrypt, executor: executor, workerID: workerID, lease: time.Minute, executeTimeout: 30 * time.Second, clock: dispatcherClock{}, ids: eventstore.UUIDGenerator{}, random: uniformJitter}
	for _, option := range options {
		if option != nil {
			option(d)
		}
	}
	return d, nil
}

func (d *EffectDispatcher) DispatchOnce(ctx context.Context) (result adapterapi.EffectResult, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	claimed, err := d.store.ClaimOutbox(ctx, eventstore.OutboxClaimRequest{WorkerID: d.workerID, LeaseDuration: d.lease})
	if err != nil {
		return adapterapi.EffectResult{}, err
	}
	leaseEffect := claimed.Effect
	leaseSettled := false
	dispatched := false
	var wire effectWire
	defer func() {
		if !leaseSettled {
			if quarantineErr := d.quarantineClaim(context.Background(), leaseEffect); quarantineErr != nil {
				if err == nil {
					err = quarantineErr
				} else {
					err = fmt.Errorf("%w: dispatcher quarantine failed", err)
				}
			} else if d.resultNotifier != nil {
				quarantineEffect := adapterapi.OutboundEffect{ID: adapterapi.EffectID(leaseEffect.EffectID), EndpointID: adapterapi.EndpointID(leaseEffect.EndpointID)}
				quarantineResult := adapterapi.TerminalResult("dispatcher-quarantine", "")
				if dispatched {
					quarantineResult = adapterapi.AmbiguousResult("dispatcher-quarantine", "")
				}
				go d.notifyResult(context.WithoutCancel(ctx), quarantineEffect, quarantineResult)
			}
		}
	}()
	payloadVersion := claimed.Effect.PayloadVersion
	if payloadVersion == 0 {
		payloadVersion = 1
	}
	plain, err := d.decrypt.DecryptBound(ctx, "outbox/v1", claimed.Effect.EffectID, claimed.Effect.EndpointID, payloadVersion, claimed.Effect.PayloadCiphertext, claimed.Effect.PayloadNonce, claimed.Effect.PayloadEncryptionKeyID)
	if err != nil {
		return adapterapi.EffectResult{}, err
	}
	defer func() {
		for i := range plain {
			plain[i] = 0
		}
	}()
	wire = effectWire{}
	if err := json.Unmarshal(plain, &wire); err != nil {
		return adapterapi.EffectResult{}, fmt.Errorf("endpoint dispatcher: decode effect: %w", err)
	}
	if wire.Effect.Payload.Target.Kind == adapterapi.TargetRaw && wire.RawTarget != "" {
		wire.Effect.Payload.Target.Raw = wire.RawTarget
	}
	if err := wire.Effect.Validate(); err != nil {
		return adapterapi.EffectResult{}, err
	}
	if string(wire.Effect.ID) != claimed.Effect.EffectID || string(wire.Effect.EndpointID) != claimed.Effect.EndpointID {
		return adapterapi.EffectResult{}, errors.New("endpoint dispatcher: effect identity mismatch")
	}
	if !wire.Effect.Deadline.Equal(claimed.Effect.DeadlineAt) {
		return adapterapi.EffectResult{}, errors.New("endpoint dispatcher: effect deadline mismatch")
	}
	if claimed.Effect.EffectType != "" && claimed.Effect.EffectType != effectTypeForKind(wire.Effect.Kind) {
		return adapterapi.EffectResult{}, errors.New("endpoint dispatcher: effect type mismatch")
	}
	expectedRisk := map[adapterapi.EffectRetryClass]string{adapterapi.EffectRetryInvalid: "", adapterapi.EffectRetryPreDispatch: eventstore.RiskPreDispatchRetryable, adapterapi.EffectRetryProviderIdempotent: eventstore.RiskProviderIdempotent, adapterapi.EffectRetryNonIdempotent: eventstore.RiskNonIdempotentAfterDispatch}[wire.Effect.RetryClass]
	if expectedRisk != "" && claimed.Effect.RiskClass != expectedRisk {
		return adapterapi.EffectResult{}, errors.New("endpoint dispatcher: effect risk mismatch")
	}
	if wire.Effect.Lane.MAC != "" && len(claimed.Effect.LaneHMAC) > 0 {
		mac, decodeErr := hex.DecodeString(wire.Effect.Lane.MAC)
		if decodeErr != nil || !hmac.Equal(mac, claimed.Effect.LaneHMAC) {
			return adapterapi.EffectResult{}, errors.New("endpoint dispatcher: effect lane mismatch")
		}
	}
	eventStream := eventstore.StreamID{AggregateType: "outbound-effect", AggregateID: claimed.Effect.EffectID}
	previous, err := d.store.Load(ctx, eventStream, 1)
	if err != nil {
		return adapterapi.EffectResult{}, err
	}
	if len(previous) == 0 || previous[0].Metadata.EventID == "" || previous[0].Metadata.CommandID == "" || previous[0].Metadata.CorrelationID == "" {
		return adapterapi.EffectResult{}, errors.New("endpoint dispatcher: missing effect stream metadata")
	}
	if previous[0].EventType != "OutboundEffectRequestedV1" || previous[0].SchemaVersion != 1 {
		return adapterapi.EffectResult{}, errors.New("endpoint dispatcher: invalid source event")
	}
	var source struct {
		EffectID    string `json:"effectId"`
		OperationID string `json:"operationId"`
		EndpointID  string `json:"endpointId"`
	}
	if json.Unmarshal(previous[0].Payload, &source) != nil || source.EffectID != claimed.Effect.EffectID || source.OperationID != string(wire.Effect.OperationID) || source.EndpointID != claimed.Effect.EndpointID {
		return adapterapi.EffectResult{}, errors.New("endpoint dispatcher: source event mismatch")
	}
	expectedVersion := uint64(len(previous))
	causation, correlation, principal := previous[0].Metadata.EventID, previous[0].Metadata.CorrelationID, previous[0].Metadata.PrincipalID
	marked := claimed
	var execErr error
	var terminalErr error
	now := d.clock.Now().UTC()
	switch {
	case !claimed.Effect.DeadlineAt.IsZero() && !claimed.Effect.DeadlineAt.After(now) && claimed.Effect.DispatchedAt.IsZero():
		// Never reached the provider, so the intent is deterministically unfulfilled.
		result = adapterapi.TerminalResult("effect-deadline-exceeded", "")
	case !claimed.Effect.DeadlineAt.IsZero() && !claimed.Effect.DeadlineAt.After(now):
		// An earlier attempt already reached the provider (re-claimable only for a
		// provider-idempotent risk class). The outcome is uncertain, so fall through
		// to the ambiguous failure classification instead of a hard terminal failure.
		execErr = errDispatchDeadlineExceededAfterDispatch
	default:
		marked, err = d.store.MarkOutboxDispatched(ctx, eventstore.OutboxDispatchRequest{EffectID: claimed.Effect.EffectID, WorkerID: claimed.Effect.LeaseOwner, LeaseEpoch: claimed.Effect.LeaseEpoch, AttemptID: claimed.Effect.AttemptID})
		if err != nil {
			return adapterapi.EffectResult{}, err
		}
		leaseEffect = marked.Effect
		dispatched = true
		timeout := d.executeTimeout
		if !marked.Effect.DeadlineAt.IsZero() {
			remaining := marked.Effect.DeadlineAt.Sub(d.clock.Now().UTC())
			if remaining < timeout {
				timeout = remaining
			}
		}
		if !marked.Effect.LeaseExpiresAt.IsZero() {
			leaseRemaining := marked.Effect.LeaseExpiresAt.Sub(d.clock.Now().UTC()) - time.Second
			if leaseRemaining < timeout {
				timeout = leaseRemaining
			}
		}
		generation := uint64(0)
		if inspector, ok := d.executor.(interface {
			InspectWorker(endpointID adapterapi.EndpointID) (WorkerInspection, bool)
		}); ok {
			inspection, found := inspector.InspectWorker(adapterapi.EndpointID(marked.Effect.EndpointID))
			if !found || inspection.Generation == 0 || inspection.Exited || inspection.Ambiguous {
				execErr = ErrSupervisorAmbiguous
			} else {
				generation = inspection.Generation
			}
		}
		if execErr == nil {
			if timeout <= 0 {
				execErr = context.DeadlineExceeded
			} else {
				runCtx, cancel := context.WithTimeout(ctx, timeout)
				result, execErr = d.executor.ExecutePinned(runCtx, adapterapi.EndpointID(marked.Effect.EndpointID), generation, wire.Effect)
				cancel()
			}
		}
	}
	artifactResult := result.Artifact
	if artifactResult != nil {
		defer func() {
			for i := range artifactResult.Bytes {
				artifactResult.Bytes[i] = 0
			}
			artifactResult.Bytes = nil
		}()
	}
	if execErr != nil {
		preExec := errors.Is(execErr, ErrSupervisorAmbiguous) || errors.Is(execErr, ErrSupervisorClosed)
		retryCount := nextRetryCount(marked.Effect.RetryCount)
		status, delay := dispatcherFailureStatus(d.random, marked.Effect.RiskClass, retryCount, marked.Effect.DeadlineAt, d.clock.Now().UTC(), preExec)
		if status == eventstore.OutboxStatusPending {
			var commitErr error
			if preExec {
				_, commitErr = d.store.RequeuePreDispatch(ctx, eventstore.OutboxPreDispatchRequeueRequest{EffectID: marked.Effect.EffectID, WorkerID: marked.Effect.LeaseOwner, LeaseEpoch: marked.Effect.LeaseEpoch, AttemptID: marked.Effect.AttemptID, RetryCount: retryCount, NextAttemptAt: d.clock.Now().UTC().Add(delay)})
			} else {
				_, commitErr = d.store.Commit(ctx, eventstore.UnitOfWork{Effects: []eventstore.NewEffect{{EffectID: marked.Effect.EffectID, ExpectedVersion: marked.Effect.Version, Version: marked.Effect.Version + 1, Status: status, LeaseOwner: marked.Effect.LeaseOwner, LeaseEpoch: marked.Effect.LeaseEpoch, AttemptID: marked.Effect.AttemptID, RetryCount: retryCount, NextAttemptAt: d.clock.Now().UTC().Add(delay)}}})
			}
			if commitErr != nil {
				return adapterapi.EffectResult{}, fmt.Errorf("%w: persist dispatch failure: %w", execErr, commitErr)
			}
			leaseSettled = true
			return adapterapi.EffectResult{}, execErr
		}
		result = adapterapi.AmbiguousResult("dispatch-ambiguous", "")
	}
	if validationErr := result.Validate(); validationErr != nil {
		terminalErr = validationErr
		result = adapterapi.AmbiguousResult("invalid-effect-result", "")
	}
	status, err := dispatcherStatus(marked.Effect.RiskClass, result.Outcome)
	if err != nil {
		return result, err
	}
	if result.Outcome == adapterapi.EffectRetryable && status == eventstore.OutboxStatusPending {
		retryCount := nextRetryCount(marked.Effect.RetryCount)
		if retryCount > dispatcherRetryMax(marked.Effect.RiskClass) || (!marked.Effect.DeadlineAt.IsZero() && !marked.Effect.DeadlineAt.After(d.clock.Now().UTC())) {
			status = eventstore.OutboxStatusAmbiguous
		} else {
			base := 500 * time.Millisecond
			if marked.Effect.RiskClass == eventstore.RiskPreDispatchRetryable {
				base = 250 * time.Millisecond
			}
			delay := base << minUint32(retryCount-1, 7)
			if delay > 30*time.Second {
				delay = 30 * time.Second
			}
			next := d.clock.Now().UTC().Add(d.random(delay))
			update := eventstore.NewEffect{EffectID: marked.Effect.EffectID, ExpectedVersion: marked.Effect.Version, Version: marked.Effect.Version + 1, Status: eventstore.OutboxStatusPending, LeaseOwner: marked.Effect.LeaseOwner, LeaseEpoch: marked.Effect.LeaseEpoch, AttemptID: marked.Effect.AttemptID, NextAttemptAt: next, RetryCount: retryCount}
			if _, err := d.store.Commit(ctx, eventstore.UnitOfWork{Effects: []eventstore.NewEffect{update}}); err != nil {
				return result, err
			}
			leaseSettled = true
			return result, nil
		}
	}
	operation, err := d.store.GetOperation(ctx, string(wire.Effect.OperationID))
	if err != nil {
		return result, err
	}
	update := eventstore.NewEffect{EffectID: marked.Effect.EffectID, ExpectedVersion: marked.Effect.Version, Version: marked.Effect.Version + 1, Status: status, LeaseOwner: marked.Effect.LeaseOwner, LeaseEpoch: marked.Effect.LeaseEpoch, AttemptID: marked.Effect.AttemptID, ProviderMessageID: result.ProviderID, ResultCode: result.Code}
	work := eventstore.UnitOfWork{Operations: []eventstore.OperationUpdate{{OperationID: operation.OperationID, ExpectedVersion: operation.Version, Version: operation.Version + 1, Status: dispatcherOperationStatusForEffect(status), ResultCode: result.Code, ArtifactID: operation.ArtifactID}}, Effects: []eventstore.NewEffect{update}}
	if result.Artifact != nil {
		bytes := result.Artifact.Bytes
		if len(bytes) > 0 || result.Artifact.ID != "" {
			artifactID := string(result.Artifact.ID)
			if artifactID == "" && d.ids != nil {
				artifactID, err = d.ids.NewID()
				if err != nil {
					return result, err
				}
			}
			if artifactID == "" {
				return result, errors.New("endpoint dispatcher: artifact id required")
			}
			work.ArtifactUpdates = []eventstore.ArtifactUpdate{{ArtifactID: artifactID, OperationID: operation.OperationID, MediaType: result.Artifact.ContentType, SafeFilename: result.Artifact.Filename, Size: int64(len(bytes)), Plaintext: bytes, PlaintextSet: true}}
			work.Operations[0].ArtifactID = artifactID
			result.Artifact.ID = adapterapi.ArtifactID(artifactID)
		}
	}
	eventID, err := d.ids.NewID()
	if err != nil {
		return result, err
	}
	commandID, err := d.ids.NewID()
	if err != nil {
		return result, err
	}
	eventPayload, err := json.Marshal(struct {
		EffectID            string `json:"effectId"`
		OperationID         string `json:"operationId"`
		EndpointID          string `json:"endpointId"`
		Status              string `json:"status"`
		ResultCode          string `json:"resultCode,omitempty"`
		ResultMessage       string `json:"resultMessage,omitempty"`
		ErrorCode           string `json:"errorCode,omitempty"`
		ProviderID          string `json:"providerId,omitempty"`
		ArtifactID          string `json:"artifactId,omitempty"`
		ArtifactContentType string `json:"artifactContentType,omitempty"`
		ArtifactFilename    string `json:"artifactFilename,omitempty"`
		ArtifactSize        int64  `json:"artifactSize,omitempty"`
	}{
		EffectID:      marked.Effect.EffectID,
		OperationID:   operation.OperationID,
		EndpointID:    marked.Effect.EndpointID,
		Status:        status,
		ResultCode:    result.Code,
		ResultMessage: result.Message,
		ProviderID:    result.ProviderID,
		ArtifactID:    work.Operations[0].ArtifactID,
		ArtifactContentType: func() string {
			if result.Artifact != nil {
				return result.Artifact.ContentType
			}
			return ""
		}(),
		ArtifactFilename: func() string {
			if result.Artifact != nil {
				return result.Artifact.Filename
			}
			return ""
		}(),
		ArtifactSize: func() int64 {
			if result.Artifact != nil {
				return int64(len(result.Artifact.Bytes))
			}
			return 0
		}(),
	})
	if err != nil {
		return result, err
	}
	work.Streams = []eventstore.StreamAppend{{Stream: eventStream, ExpectedVersion: expectedVersion, Events: []eventstore.NewEvent{{EventType: dispatcherEventTypeForStatus(status), SchemaVersion: 1, Payload: eventPayload, Metadata: eventstore.Metadata{EventID: eventID, CommandID: commandID, CorrelationID: correlation, CausationID: causation, PrincipalID: principal, Producer: "endpoint-dispatcher", OccurredAtUnixNanoUTC: d.clock.Now().UTC().UnixNano(), OccurredAtUnixNanoSet: true}}}}}
	if _, err := d.store.Commit(ctx, work); err != nil {
		return result, err
	}
	leaseSettled = true
	if status == eventstore.OutboxStatusFailed || status == eventstore.OutboxStatusAmbiguous {
		logger.QueueFailures().Warnw(
			"outbound effect isolated",
			"queue", "outbox",
			"item_id", marked.Effect.EffectID,
			"endpoint_id", marked.Effect.EndpointID,
			"operation_id", operation.OperationID,
			"status", status,
			"reason", "provider-terminal-outcome",
			"outcome", result.Outcome,
			"result_code", result.Code,
			"result_message", result.Message,
			"version", marked.Effect.Version+1,
		)
	}
	if d.resultNotifier != nil {
		go d.notifyResult(context.WithoutCancel(ctx), wire.Effect, result)
	}
	if terminalErr == nil && result.Outcome == adapterapi.EffectSucceeded && d.successNotifier != nil {
		go d.notifySuccess(context.WithoutCancel(ctx), wire.Effect, result)
	}
	return result, terminalErr
}

func (d *EffectDispatcher) notifyResult(ctx context.Context, effect adapterapi.OutboundEffect, result adapterapi.EffectResult) {
	defer func() {
		_ = recover()
	}()
	d.resultNotifier.NotifyOutboundEffectResult(ctx, effect, result)
}

func (d *EffectDispatcher) notifySuccess(ctx context.Context, effect adapterapi.OutboundEffect, result adapterapi.EffectResult) {
	defer func() {
		_ = recover()
	}()
	d.successNotifier.NotifyOutboundEffectSucceeded(ctx, effect, result)
}

func (d *EffectDispatcher) quarantineClaim(ctx context.Context, effect eventstore.NewEffect) error {
	if effect.EffectID == "" || effect.LeaseOwner == "" || effect.LeaseEpoch == 0 || effect.Version == 0 || effect.AttemptID == "" {
		return eventstore.ErrStaleLease
	}
	req := eventstore.OutboxQuarantineRequest{
		EffectID:        effect.EffectID,
		ExpectedVersion: effect.Version,
		WorkerID:        effect.LeaseOwner,
		LeaseEpoch:      effect.LeaseEpoch,
		AttemptID:       effect.AttemptID,
		ErrorCode:       "dispatcher-quarantine",
		Reason:          "dispatcher-quarantine",
	}
	quarantine, ok := d.store.(eventstore.OutboxQuarantineRepository)
	if !ok {
		return ErrDispatcherDependencies
	}
	_, err := quarantine.QuarantineOutbox(ctx, req)
	return err
}

func dispatcherStatus(risk string, outcome adapterapi.EffectOutcome) (string, error) {
	switch outcome {
	case adapterapi.EffectSucceeded:
		return eventstore.OutboxStatusSucceeded, nil
	case adapterapi.EffectTerminal, adapterapi.EffectUnsupported:
		return eventstore.OutboxStatusFailed, nil
	case adapterapi.EffectAmbiguous:
		return eventstore.OutboxStatusAmbiguous, nil
	case adapterapi.EffectRetryable:
		if risk == eventstore.RiskProviderIdempotent || risk == eventstore.RiskPreDispatchRetryable {
			return eventstore.OutboxStatusPending, nil
		}
		return eventstore.OutboxStatusAmbiguous, nil
	default:
		return "", adapterapi.ErrInvalidContract
	}
}
func dispatcherEventTypeForStatus(status string) string {
	switch status {
	case eventstore.OutboxStatusSucceeded:
		return "OutboundEffectSucceededV1"
	case eventstore.OutboxStatusAmbiguous:
		return "OutboundEffectAmbiguousV1"
	default:
		return "OutboundEffectFailedV1"
	}
}
func dispatcherFailureStatus(random func(time.Duration) time.Duration, risk string, retry uint32, deadline, now time.Time, preExec bool) (string, time.Duration) {
	retryLimit := dispatcherRetryMax(risk)
	base := 500 * time.Millisecond
	if preExec {
		retryLimit = 8
		base = 250 * time.Millisecond
	}
	if retry > retryLimit || (!deadline.IsZero() && !deadline.After(now)) {
		return eventstore.OutboxStatusAmbiguous, 0
	}
	if !preExec && risk != eventstore.RiskProviderIdempotent && risk != eventstore.RiskPreDispatchRetryable {
		return eventstore.OutboxStatusAmbiguous, 0
	}
	delay := base << minUint32(retry-1, 7)
	if delay > 30*time.Second {
		delay = 30 * time.Second
	}
	return eventstore.OutboxStatusPending, random(delay)
}
func nextRetryCount(current uint32) uint32 {
	if current == ^uint32(0) {
		return current
	}
	return current + 1
}
func minUint32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}
func dispatcherRetryMax(risk string) uint32 {
	if risk == eventstore.RiskPreDispatchRetryable {
		return 8
	}
	return 5
}
func dispatcherOperationStatusForEffect(status string) string {
	if status == eventstore.OutboxStatusAmbiguous {
		return "ambiguous"
	}
	if status == eventstore.OutboxStatusSucceeded {
		return "succeeded"
	}
	return "failed"
}
