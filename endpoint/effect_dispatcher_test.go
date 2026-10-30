package endpoint

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/eventstore"
)

type dispatcherTestStore struct {
	claimed     eventstore.OutboxLease
	marked      eventstore.OutboxLease
	work        eventstore.UnitOfWork
	calls       []string
	resolved    bool
	resolve     eventstore.OutboxResolutionRequest
	quarantined bool
	quarantine  eventstore.OutboxQuarantineRequest
	commitErr   error
}

func (s *dispatcherTestStore) ClaimOutbox(_ context.Context, _ eventstore.OutboxClaimRequest) (eventstore.OutboxLease, error) {
	s.calls = append(s.calls, "claim")
	return s.claimed, nil
}
func (s *dispatcherTestStore) MarkOutboxDispatched(_ context.Context, r eventstore.OutboxDispatchRequest) (eventstore.OutboxLease, error) {
	s.calls = append(s.calls, "mark")
	s.marked.Effect.AttemptID = "fresh-attempt"
	s.marked.Effect.LeaseOwner = r.WorkerID
	s.marked.Effect.LeaseEpoch = r.LeaseEpoch
	s.marked.Effect.Version = s.claimed.Effect.Version + 1
	s.marked.Effect.Status = eventstore.OutboxStatusDispatched
	s.marked.Effect.DeadlineAt = time.Now().Add(24 * time.Hour)
	s.marked.Effect.RiskClass = s.claimed.Effect.RiskClass
	return s.marked, nil
}
func (s *dispatcherTestStore) Commit(_ context.Context, w eventstore.UnitOfWork) (eventstore.CommitResult, error) {
	s.calls = append(s.calls, "commit")
	s.work = w
	if s.commitErr != nil {
		return eventstore.CommitResult{}, s.commitErr
	}
	return eventstore.CommitResult{}, nil
}
func (s *dispatcherTestStore) Load(context.Context, eventstore.StreamID, uint64) ([]eventstore.Envelope, error) {
	payload, _ := json.Marshal(struct {
		EffectID    string `json:"effectId"`
		OperationID string `json:"operationId"`
		EndpointID  string `json:"endpointId"`
	}{"effect-1", "op-1", "endpoint-1"})
	return []eventstore.Envelope{{EventType: "OutboundEffectRequestedV1", SchemaVersion: 1, Payload: payload, Metadata: eventstore.Metadata{EventID: "source-event", CommandID: "source-command", CorrelationID: "source-correlation"}}}, nil
}
func (s *dispatcherTestStore) GetOperation(context.Context, string) (eventstore.OperationView, error) {
	return eventstore.OperationView{OperationID: "op-1", Version: 2}, nil
}
func (*dispatcherTestStore) Close() error { return nil }
func (*dispatcherTestStore) AcceptOutbox(context.Context, eventstore.NewEffect) (eventstore.CommitResult, error) {
	return eventstore.CommitResult{}, nil
}
func (*dispatcherTestStore) UpdateOutbox(context.Context, eventstore.NewEffect) (eventstore.CommitResult, error) {
	return eventstore.CommitResult{}, nil
}
func (*dispatcherTestStore) RenewOutbox(context.Context, eventstore.OutboxRenewRequest) (eventstore.OutboxLease, error) {
	return eventstore.OutboxLease{}, nil
}
func (*dispatcherTestStore) CompleteOutbox(context.Context, eventstore.OutboxCompletionRequest) (eventstore.CommitResult, error) {
	return eventstore.CommitResult{}, nil
}
func (s *dispatcherTestStore) RequeuePreDispatch(_ context.Context, _ eventstore.OutboxPreDispatchRequeueRequest) (eventstore.CommitResult, error) {
	s.calls = append(s.calls, "requeue")
	return eventstore.CommitResult{}, nil
}
func (s *dispatcherTestStore) ResolveOutbox(_ context.Context, r eventstore.OutboxResolutionRequest) (eventstore.CommitResult, error) {
	s.resolved = true
	s.resolve = r
	return eventstore.CommitResult{}, nil
}
func (s *dispatcherTestStore) QuarantineOutbox(_ context.Context, r eventstore.OutboxQuarantineRequest) (eventstore.CommitResult, error) {
	s.quarantined = true
	s.quarantine = r
	s.calls = append(s.calls, "quarantine")
	return eventstore.CommitResult{EffectIDs: []string{r.EffectID}, Version: r.ExpectedVersion + 1}, nil
}

type dispatcherTestDecrypt struct{ plain []byte }

func (d dispatcherTestDecrypt) DecryptBound(context.Context, string, string, string, uint64, []byte, []byte, string) ([]byte, error) {
	return d.plain, nil
}

type dispatcherTestExecutor struct{}

func (dispatcherTestExecutor) ExecutePinned(context.Context, adapterapi.EndpointID, uint64, adapterapi.OutboundEffect) (adapterapi.EffectResult, error) {
	return adapterapi.EffectResult{Outcome: adapterapi.EffectSucceeded}, nil
}

type dispatcherTestNotifier struct{ received chan adapterapi.EffectResult }

func (n dispatcherTestNotifier) NotifyOutboundEffectSucceeded(_ context.Context, _ adapterapi.OutboundEffect, result adapterapi.EffectResult) {
	n.received <- result
}

type dispatcherTestIDs struct{ n int }
type dispatcherTestClock struct{}

func (dispatcherTestClock) Now() time.Time          { return time.Unix(0, 0).UTC() }
func (i *dispatcherTestIDs) NewID() (string, error) { i.n++; return "id-" + string(rune('0'+i.n)), nil }
func TestEffectDispatcherUsesFreshAttemptAndAtomicTerminalWork(t *testing.T) {
	target := adapterapi.EffectTarget{Kind: adapterapi.TargetPerson, Conversation: "person-1"}
	lane, err := adapterapi.NewLaneMetadata("endpoint-1", target, []byte("root"), 1)
	if err != nil {
		t.Fatal(err)
	}
	effect := adapterapi.OutboundEffect{Version: adapterapi.EffectVersionOne, ID: "effect-1", EndpointID: "endpoint-1", OperationID: "op-1", CorrelationID: "correlation-1", CausationID: "cause-1", Lane: lane, Deadline: time.Now().Add(24 * time.Hour), Risk: adapterapi.EffectRiskNormal, RetryClass: adapterapi.EffectRetryNonIdempotent, RequiredCapabilities: adapterapi.CapabilityOutbound, RequiredAction: adapterapi.ActionKindSendMessage, Kind: adapterapi.EffectKindMessage, Payload: adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadPersonText, Target: target, Text: "hello"}}
	plain, _ := json.Marshal(effectWire{Effect: effect})
	store := &dispatcherTestStore{claimed: eventstore.OutboxLease{Effect: eventstore.NewEffect{EffectID: "effect-1", Version: 1, EndpointID: "endpoint-1", LeaseOwner: "worker", LeaseEpoch: 2, AttemptID: "old-attempt", PayloadCiphertext: []byte("cipher"), PayloadNonce: []byte("nonce"), PayloadEncryptionKeyID: "key", DeadlineAt: effect.Deadline, RiskClass: eventstore.RiskNonIdempotentAfterDispatch}}, marked: eventstore.OutboxLease{Effect: eventstore.NewEffect{EffectID: "effect-1", Version: 2, EndpointID: "endpoint-1", PayloadCiphertext: []byte("cipher"), PayloadNonce: []byte("nonce"), PayloadEncryptionKeyID: "key", RiskClass: eventstore.RiskNonIdempotentAfterDispatch}}}
	ids := &dispatcherTestIDs{}
	notifier := dispatcherTestNotifier{received: make(chan adapterapi.EffectResult, 1)}
	d, err := NewEffectDispatcher(store, dispatcherTestDecrypt{plain}, dispatcherTestExecutor{}, "worker", WithDispatcherClock(dispatcherTestClock{}), WithDispatcherIDGenerator(ids), WithEffectSuccessNotifier(notifier))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.DispatchOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-notifier.received:
		if result.Outcome != adapterapi.EffectSucceeded {
			t.Fatalf("notifier result = %#v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("success notifier was not called after commit")
	}

	if store.marked.Effect.AttemptID != "fresh-attempt" {
		t.Fatal("attempt")
	}
	if len(store.work.Effects) != 1 || store.work.Effects[0].AttemptID != "fresh-attempt" {
		t.Fatal("work")
	}
}
func TestEffectDispatcherQuarantinesDecodeFailure(t *testing.T) {
	store := &dispatcherTestStore{claimed: eventstore.OutboxLease{Effect: eventstore.NewEffect{
		EffectID: "effect-1", Version: 3, EndpointID: "endpoint-1", LeaseOwner: "worker", LeaseEpoch: 4, AttemptID: "attempt-1", PrincipalID: "principal-1",
	}}}
	d, err := NewEffectDispatcher(store, dispatcherTestDecrypt{plain: []byte("{")}, dispatcherTestExecutor{}, "worker")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.DispatchOnce(context.Background()); err == nil {
		t.Fatal("malformed effect unexpectedly dispatched")
	}
	if !store.quarantined {
		t.Fatal("decode failure did not durably quarantine claimed effect")
	}
	if store.quarantine.EffectID != "effect-1" || store.quarantine.ExpectedVersion != 3 || store.quarantine.WorkerID != "worker" || store.quarantine.LeaseEpoch != 4 || store.quarantine.AttemptID != "attempt-1" {
		t.Fatalf("quarantine request = %#v", store.quarantine)
	}
	if store.resolved {
		t.Fatal("dispatcher used operator resolution instead of quarantine")
	}
}

type dispatcherQuarantineNotifier struct {
	received chan adapterapi.EffectResult
	effects  chan adapterapi.OutboundEffect
}

func (n dispatcherQuarantineNotifier) NotifyOutboundEffectResult(_ context.Context, effect adapterapi.OutboundEffect, result adapterapi.EffectResult) {
	n.effects <- effect
	n.received <- result
}

func TestEffectDispatcherNotifiesCommittedQuarantine(t *testing.T) {
	store := &dispatcherTestStore{claimed: eventstore.OutboxLease{Effect: eventstore.NewEffect{
		EffectID: "effect-1", Version: 3, EndpointID: "endpoint-1", LeaseOwner: "worker", LeaseEpoch: 4, AttemptID: "attempt-1",
	}}}
	notifier := dispatcherQuarantineNotifier{received: make(chan adapterapi.EffectResult, 1), effects: make(chan adapterapi.OutboundEffect, 1)}
	d, err := NewEffectDispatcher(store, dispatcherTestDecrypt{plain: []byte("{")}, dispatcherTestExecutor{}, "worker", WithEffectResultNotifier(notifier))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.DispatchOnce(context.Background()); err == nil {
		t.Fatal("malformed effect unexpectedly dispatched")
	}
	select {
	case effect := <-notifier.effects:
		if string(effect.ID) != "effect-1" {
			t.Fatalf("quarantine notification effect = %#v", effect)
		}
	case <-time.After(time.Second):
		t.Fatal("committed quarantine did not notify result observer")
	}
	select {
	case result := <-notifier.received:
		if result.Outcome != adapterapi.EffectTerminal || result.Code != "dispatcher-quarantine" {
			t.Fatalf("quarantine notification result = %#v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("committed quarantine result missing")
	}
}

type dispatcherInvalidResultExecutor struct{}

func (dispatcherInvalidResultExecutor) ExecutePinned(context.Context, adapterapi.EndpointID, uint64, adapterapi.OutboundEffect) (adapterapi.EffectResult, error) {
	return adapterapi.EffectResult{}, nil
}

func TestEffectDispatcherNotifiesNormalizedInvalidResult(t *testing.T) {
	target := adapterapi.EffectTarget{Kind: adapterapi.TargetPerson, Conversation: "person-1"}
	lane, err := adapterapi.NewLaneMetadata("endpoint-1", target, []byte("root"), 1)
	if err != nil {
		t.Fatal(err)
	}
	effect := adapterapi.OutboundEffect{Version: adapterapi.EffectVersionOne, ID: "effect-1", EndpointID: "endpoint-1", OperationID: "op-1", CorrelationID: "corr-1", CausationID: "cause-1", Lane: lane, Deadline: time.Now().Add(time.Hour), Risk: adapterapi.EffectRiskNormal, RetryClass: adapterapi.EffectRetryNonIdempotent, RequiredCapabilities: adapterapi.CapabilityOutbound, RequiredAction: adapterapi.ActionKindSendMessage, Kind: adapterapi.EffectKindMessage, Payload: adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadPersonText, Target: target, Text: "hello"}}
	plain, _ := json.Marshal(effectWire{Effect: effect})
	store := &dispatcherTestStore{claimed: eventstore.OutboxLease{Effect: eventstore.NewEffect{EffectID: "effect-1", Version: 1, EndpointID: "endpoint-1", LeaseOwner: "worker", LeaseEpoch: 1, AttemptID: "attempt-1", PayloadCiphertext: []byte("cipher"), PayloadNonce: []byte("nonce"), PayloadEncryptionKeyID: "key", DeadlineAt: effect.Deadline, RiskClass: eventstore.RiskNonIdempotentAfterDispatch}}, marked: eventstore.OutboxLease{Effect: eventstore.NewEffect{EffectID: "effect-1", Version: 2, EndpointID: "endpoint-1", PayloadCiphertext: []byte("cipher"), PayloadNonce: []byte("nonce"), PayloadEncryptionKeyID: "key", RiskClass: eventstore.RiskNonIdempotentAfterDispatch}}}
	notifier := dispatcherQuarantineNotifier{received: make(chan adapterapi.EffectResult, 1), effects: make(chan adapterapi.OutboundEffect, 1)}
	d, err := NewEffectDispatcher(store, dispatcherTestDecrypt{plain}, dispatcherInvalidResultExecutor{}, "worker", WithDispatcherIDGenerator(&dispatcherTestIDs{}), WithEffectResultNotifier(notifier))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.DispatchOnce(context.Background()); err == nil {
		t.Fatal("invalid provider result unexpectedly accepted")
	}
	select {
	case result := <-notifier.received:
		if result.Outcome != adapterapi.EffectAmbiguous || result.Code != "invalid-effect-result" {
			t.Fatalf("normalized invalid result notification = %#v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("committed invalid result did not notify result observer")
	}
}

func TestEffectDispatcherQuarantinesPostDispatchPersistenceFailureAsAmbiguous(t *testing.T) {
	target := adapterapi.EffectTarget{Kind: adapterapi.TargetPerson, Conversation: "person-1"}
	lane, err := adapterapi.NewLaneMetadata("endpoint-1", target, []byte("root"), 1)
	if err != nil {
		t.Fatal(err)
	}
	effect := adapterapi.OutboundEffect{Version: adapterapi.EffectVersionOne, ID: "effect-1", EndpointID: "endpoint-1", OperationID: "op-1", CorrelationID: "corr-1", CausationID: "cause-1", Lane: lane, Deadline: time.Now().Add(time.Hour), Risk: adapterapi.EffectRiskNormal, RetryClass: adapterapi.EffectRetryNonIdempotent, RequiredCapabilities: adapterapi.CapabilityOutbound, RequiredAction: adapterapi.ActionKindSendMessage, Kind: adapterapi.EffectKindMessage, Payload: adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadPersonText, Target: target, Text: "hello"}}
	plain, _ := json.Marshal(effectWire{Effect: effect})
	store := &dispatcherTestStore{
		claimed:   eventstore.OutboxLease{Effect: eventstore.NewEffect{EffectID: "effect-1", Version: 1, EndpointID: "endpoint-1", LeaseOwner: "worker", LeaseEpoch: 1, AttemptID: "attempt-1", PayloadCiphertext: []byte("cipher"), PayloadNonce: []byte("nonce"), PayloadEncryptionKeyID: "key", DeadlineAt: effect.Deadline, RiskClass: eventstore.RiskNonIdempotentAfterDispatch}},
		marked:    eventstore.OutboxLease{Effect: eventstore.NewEffect{EffectID: "effect-1", Version: 2, EndpointID: "endpoint-1", PayloadCiphertext: []byte("cipher"), PayloadNonce: []byte("nonce"), PayloadEncryptionKeyID: "key", RiskClass: eventstore.RiskNonIdempotentAfterDispatch}},
		commitErr: errors.New("terminal persistence failed"),
	}
	notifier := dispatcherQuarantineNotifier{received: make(chan adapterapi.EffectResult, 1), effects: make(chan adapterapi.OutboundEffect, 1)}
	d, err := NewEffectDispatcher(store, dispatcherTestDecrypt{plain}, dispatcherTestExecutor{}, "worker", WithDispatcherIDGenerator(&dispatcherTestIDs{}), WithEffectResultNotifier(notifier))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.DispatchOnce(context.Background()); err == nil {
		t.Fatal("terminal persistence failure unexpectedly succeeded")
	}
	if !store.quarantined || store.quarantine.ExpectedVersion != 2 {
		t.Fatalf("post-dispatch quarantine = %#v", store.quarantine)
	}
	select {
	case result := <-notifier.received:
		if result.Outcome != adapterapi.EffectAmbiguous {
			t.Fatalf("post-dispatch quarantine notification = %#v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("post-dispatch quarantine result missing")
	}
}

type dispatcherGenerationExecutor struct {
	generation uint64
	seen       uint64
}

func (e *dispatcherGenerationExecutor) InspectWorker(adapterapi.EndpointID) (WorkerInspection, bool) {
	return WorkerInspection{Generation: e.generation}, true
}
func (e *dispatcherGenerationExecutor) ExecutePinned(_ context.Context, _ adapterapi.EndpointID, generation uint64, _ adapterapi.OutboundEffect) (adapterapi.EffectResult, error) {
	e.seen = generation
	return adapterapi.EffectResult{Outcome: adapterapi.EffectSucceeded}, nil
}

func TestEffectDispatcherSnapshotsWorkerGeneration(t *testing.T) {
	target := adapterapi.EffectTarget{Kind: adapterapi.TargetPerson, Conversation: "person-1"}
	lane, err := adapterapi.NewLaneMetadata("endpoint-1", target, []byte("root"), 1)
	if err != nil {
		t.Fatal(err)
	}
	effect := adapterapi.OutboundEffect{Version: adapterapi.EffectVersionOne, ID: "effect-1", EndpointID: "endpoint-1", OperationID: "op-1", CorrelationID: "corr-1", CausationID: "cause-1", Lane: lane, Deadline: time.Now().Add(time.Hour), Risk: adapterapi.EffectRiskNormal, RetryClass: adapterapi.EffectRetryNonIdempotent, RequiredCapabilities: adapterapi.CapabilityOutbound, RequiredAction: adapterapi.ActionKindSendMessage, Kind: adapterapi.EffectKindMessage, Payload: adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadPersonText, Target: target, Text: "hello"}}
	plain, _ := json.Marshal(effectWire{Effect: effect})
	store := &dispatcherTestStore{claimed: eventstore.OutboxLease{Effect: eventstore.NewEffect{EffectID: "effect-1", Version: 1, EndpointID: "endpoint-1", LeaseOwner: "worker", LeaseEpoch: 1, AttemptID: "attempt-1", PayloadCiphertext: []byte("cipher"), PayloadNonce: []byte("nonce"), PayloadEncryptionKeyID: "key", DeadlineAt: effect.Deadline, RiskClass: eventstore.RiskNonIdempotentAfterDispatch}}, marked: eventstore.OutboxLease{Effect: eventstore.NewEffect{EffectID: "effect-1", Version: 2, EndpointID: "endpoint-1", PayloadCiphertext: []byte("cipher"), PayloadNonce: []byte("nonce"), PayloadEncryptionKeyID: "key", RiskClass: eventstore.RiskNonIdempotentAfterDispatch}}}
	executor := &dispatcherGenerationExecutor{generation: 7}
	d, err := NewEffectDispatcher(store, dispatcherTestDecrypt{plain}, executor, "worker", WithDispatcherIDGenerator(&dispatcherTestIDs{}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.DispatchOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if executor.seen != executor.generation {
		t.Fatalf("executor generation = %d, want snapshot %d", executor.seen, executor.generation)
	}
}

type dispatcherUnavailableExecutor struct {
	executed bool
}

func (*dispatcherUnavailableExecutor) InspectWorker(adapterapi.EndpointID) (WorkerInspection, bool) {
	return WorkerInspection{}, false
}
func (e *dispatcherUnavailableExecutor) ExecutePinned(context.Context, adapterapi.EndpointID, uint64, adapterapi.OutboundEffect) (adapterapi.EffectResult, error) {
	e.executed = true
	return adapterapi.EffectResult{Outcome: adapterapi.EffectSucceeded}, nil
}

func TestEffectDispatcherRejectsMissingWorkerBeforeProviderExecution(t *testing.T) {
	target := adapterapi.EffectTarget{Kind: adapterapi.TargetPerson, Conversation: "person-1"}
	lane, err := adapterapi.NewLaneMetadata("endpoint-1", target, []byte("root"), 1)
	if err != nil {
		t.Fatal(err)
	}
	effect := adapterapi.OutboundEffect{Version: adapterapi.EffectVersionOne, ID: "effect-1", EndpointID: "endpoint-1", OperationID: "op-1", CorrelationID: "corr-1", CausationID: "cause-1", Lane: lane, Deadline: time.Now().Add(time.Hour), Risk: adapterapi.EffectRiskNormal, RetryClass: adapterapi.EffectRetryNonIdempotent, RequiredCapabilities: adapterapi.CapabilityOutbound, RequiredAction: adapterapi.ActionKindSendMessage, Kind: adapterapi.EffectKindMessage, Payload: adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadPersonText, Target: target, Text: "hello"}}
	plain, _ := json.Marshal(effectWire{Effect: effect})
	store := &dispatcherTestStore{claimed: eventstore.OutboxLease{Effect: eventstore.NewEffect{EffectID: "effect-1", Version: 1, EndpointID: "endpoint-1", LeaseOwner: "worker", LeaseEpoch: 1, AttemptID: "attempt-1", PayloadCiphertext: []byte("cipher"), PayloadNonce: []byte("nonce"), PayloadEncryptionKeyID: "key", DeadlineAt: effect.Deadline, RiskClass: eventstore.RiskNonIdempotentAfterDispatch}}, marked: eventstore.OutboxLease{Effect: eventstore.NewEffect{EffectID: "effect-1", Version: 2, EndpointID: "endpoint-1", PayloadCiphertext: []byte("cipher"), PayloadNonce: []byte("nonce"), PayloadEncryptionKeyID: "key", RiskClass: eventstore.RiskNonIdempotentAfterDispatch}}}
	executor := &dispatcherUnavailableExecutor{}
	d, err := NewEffectDispatcher(store, dispatcherTestDecrypt{plain}, executor, "worker", WithDispatcherRandom(func(time.Duration) time.Duration { return 0 }))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.DispatchOnce(context.Background()); !errors.Is(err, ErrSupervisorAmbiguous) {
		t.Fatalf("missing worker error = %v", err)
	}
	if executor.executed {
		t.Fatal("provider execution started for missing worker")
	}
	if store.quarantined {
		t.Fatal("missing worker was terminally quarantined instead of retried")
	}
	foundRequeue := false
	for _, call := range store.calls {
		if call == "requeue" {
			foundRequeue = true
		}
	}
	if !foundRequeue {
		t.Fatalf("missing worker calls = %v", store.calls)
	}
}

type dispatcherRecordingExecutor struct {
	executed bool
}

func (e *dispatcherRecordingExecutor) ExecutePinned(context.Context, adapterapi.EndpointID, uint64, adapterapi.OutboundEffect) (adapterapi.EffectResult, error) {
	e.executed = true
	return adapterapi.EffectResult{Outcome: adapterapi.EffectSucceeded}, nil
}

func TestEffectDispatcherExpiresBeforeDispatchMarker(t *testing.T) {
	target := adapterapi.EffectTarget{Kind: adapterapi.TargetPerson, Conversation: "person-1"}
	lane, err := adapterapi.NewLaneMetadata("endpoint-1", target, []byte("root"), 1)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Unix(-1, 0).UTC()
	effect := adapterapi.OutboundEffect{Version: adapterapi.EffectVersionOne, ID: "effect-1", EndpointID: "endpoint-1", OperationID: "op-1", CorrelationID: "corr-1", CausationID: "cause-1", Lane: lane, Deadline: deadline, Risk: adapterapi.EffectRiskNormal, RetryClass: adapterapi.EffectRetryNonIdempotent, RequiredCapabilities: adapterapi.CapabilityOutbound, RequiredAction: adapterapi.ActionKindSendMessage, Kind: adapterapi.EffectKindMessage, Payload: adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadPersonText, Target: target, Text: "hello"}}
	plain, _ := json.Marshal(effectWire{Effect: effect})
	store := &dispatcherTestStore{claimed: eventstore.OutboxLease{Effect: eventstore.NewEffect{EffectID: "effect-1", Version: 1, EndpointID: "endpoint-1", LeaseOwner: "worker", LeaseEpoch: 1, AttemptID: "attempt-1", PayloadCiphertext: []byte("cipher"), PayloadNonce: []byte("nonce"), PayloadEncryptionKeyID: "key", DeadlineAt: deadline, RiskClass: eventstore.RiskNonIdempotentAfterDispatch}}}
	executor := &dispatcherRecordingExecutor{}
	d, err := NewEffectDispatcher(store, dispatcherTestDecrypt{plain}, executor, "worker", WithDispatcherClock(dispatcherTestClock{}), WithDispatcherIDGenerator(&dispatcherTestIDs{}))
	if err != nil {
		t.Fatal(err)
	}
	result, err := d.DispatchOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != adapterapi.EffectTerminal || result.Code != "effect-deadline-exceeded" {
		t.Fatalf("result = %#v", result)
	}
	if executor.executed {
		t.Fatal("expired effect reached provider execution")
	}
	if len(store.calls) < 2 || store.calls[0] != "claim" || store.calls[1] != "commit" {
		t.Fatalf("store calls = %v, want claim then commit without mark", store.calls)
	}
	if len(store.work.Effects) != 1 || store.work.Effects[0].Status != eventstore.OutboxStatusFailed || store.work.Effects[0].ExpectedVersion != 1 {
		t.Fatalf("terminal work = %#v", store.work)
	}
}

func TestEffectDispatcherExpiresAfterDispatchMarkerRecordsAmbiguous(t *testing.T) {
	target := adapterapi.EffectTarget{Kind: adapterapi.TargetPerson, Conversation: "person-1"}
	lane, err := adapterapi.NewLaneMetadata("endpoint-1", target, []byte("root"), 1)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Unix(-1, 0).UTC()
	dispatchedAt := time.Unix(-10, 0).UTC()
	effect := adapterapi.OutboundEffect{
		Version: adapterapi.EffectVersionOne, ID: "effect-1", EndpointID: "endpoint-1", OperationID: "op-1",
		CorrelationID: "corr-1", CausationID: "cause-1", Lane: lane, Deadline: deadline, Risk: adapterapi.EffectRiskNormal,
		RetryClass: adapterapi.EffectRetryProviderIdempotent, RequiredCapabilities: adapterapi.CapabilityOutbound | adapterapi.CapabilityActions,
		RequiredAction: adapterapi.ActionKindRecallMessage, Kind: adapterapi.EffectKindAction,
		Payload: adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadRecall, Target: target, MessageID: "message-1"},
	}
	plain, _ := json.Marshal(effectWire{Effect: effect})
	store := &dispatcherTestStore{claimed: eventstore.OutboxLease{Effect: eventstore.NewEffect{EffectID: "effect-1", Version: 2, EndpointID: "endpoint-1", LeaseOwner: "worker", LeaseEpoch: 2, AttemptID: "attempt-2", PayloadCiphertext: []byte("cipher"), PayloadNonce: []byte("nonce"), PayloadEncryptionKeyID: "key", DeadlineAt: deadline, DispatchedAt: dispatchedAt, RiskClass: eventstore.RiskProviderIdempotent}}}
	executor := &dispatcherRecordingExecutor{}
	d, err := NewEffectDispatcher(store, dispatcherTestDecrypt{plain}, executor, "worker", WithDispatcherClock(dispatcherTestClock{}), WithDispatcherIDGenerator(&dispatcherTestIDs{}))
	if err != nil {
		t.Fatal(err)
	}
	result, err := d.DispatchOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != adapterapi.EffectAmbiguous {
		t.Fatalf("result = %#v, want ambiguous outcome", result)
	}
	if executor.executed {
		t.Fatal("re-claimed expired effect reached provider execution again")
	}
	for _, call := range store.calls {
		if call == "mark" {
			t.Fatalf("store calls = %v, want no dispatch marker", store.calls)
		}
	}
	if len(store.calls) < 2 || store.calls[0] != "claim" || store.calls[1] != "commit" {
		t.Fatalf("store calls = %v, want claim then commit", store.calls)
	}
	if len(store.work.Effects) != 1 || store.work.Effects[0].Status != eventstore.OutboxStatusAmbiguous || store.work.Effects[0].ExpectedVersion != 2 {
		t.Fatalf("terminal work = %#v, want ambiguous status", store.work)
	}
}

type invalidArtifactRuntime struct{ artifact *adapterapi.ArtifactResult }

func (invalidArtifactRuntime) Run(context.Context, adapterapi.CorePort) error { return nil }
func (invalidArtifactRuntime) Stop(context.Context) error                     { return nil }
func (invalidArtifactRuntime) Capabilities() adapterapi.CapabilitySet {
	return adapterapi.CapabilityOutbound
}
func (r invalidArtifactRuntime) Execute(context.Context, adapterapi.OutboundEffect) adapterapi.EffectResult {
	return adapterapi.EffectResult{Outcome: adapterapi.EffectSucceeded, Artifact: r.artifact}
}
func (invalidArtifactRuntime) Diagnostics(context.Context) adapterapi.DiagnosticReport {
	return adapterapi.DiagnosticReport{}
}
func TestSafeExecuteScrubsInvalidArtifact(t *testing.T) {
	a := &adapterapi.ArtifactResult{Bytes: []byte("secret")}
	_, err := safeExecute(invalidArtifactRuntime{a}, context.Background(), adapterapi.OutboundEffect{})
	if err == nil || len(a.Bytes) != 0 {
		t.Fatal("invalid artifact was not scrubbed")
	}
}
func TestDispatcherRetryCountSaturates(t *testing.T) {
	if got := nextRetryCount(^uint32(0)); got != ^uint32(0) {
		t.Fatalf("retry count overflowed: %d", got)
	}
}
func TestDispatcherPreExecUsesPhaseBudget(t *testing.T) {
	status, delay := dispatcherFailureStatus(func(d time.Duration) time.Duration { return d }, "non-idempotent-after-dispatch", 1, time.Time{}, time.Now(), true)
	if status != eventstore.OutboxStatusPending || delay != 250*time.Millisecond {
		t.Fatalf("pre-dispatch phase policy: %s %v", status, delay)
	}
}
