package endpoint

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"
	"Scardice-core/adapterapi"
	"Scardice-core/eventstore"
)

// task6FaultPoint is deliberately test-only. Production dispatcher code has no
// fault switch; the fake durable store/provider use these callbacks to model a
// process crash at a named boundary.
type task6FaultPoint string

const (
	task6FaultAtMarker         task6FaultPoint = "at-dispatched-marker"
	task6FaultLease            task6FaultPoint = "lease-acquisition"
	task6FaultBeforeMarker     task6FaultPoint = "before-dispatched-marker"
	task6FaultProviderAccept   task6FaultPoint = "provider-acceptance"
	task6FaultResponseLoss     task6FaultPoint = "provider-response-loss"
	task6FaultTerminalPersist  task6FaultPoint = "terminal-persistence"
	task6FaultNotifySchedule   task6FaultPoint = "result-notification-scheduling"
)

type task6Faults struct {
	mu    sync.Mutex
	err   map[task6FaultPoint]error
	calls map[task6FaultPoint]int
}

func (f *task6Faults) hit(point task6FaultPoint) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[point]++
	return f.err[point]
}

func (f *task6Faults) count(point task6FaultPoint) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[point]
}

type task6Clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *task6Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}
func (c *task6Clock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

type task6IDs struct {
	mu sync.Mutex
	n  int
}

func (g *task6IDs) NewID() (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.n++
	return "task6-id-" + strconv.Itoa(g.n), nil
}

type task6Decrypt struct{ plain map[string][]byte }

func (d task6Decrypt) DecryptBound(_ context.Context, _ string, effectID, _ string, _ uint64, _ []byte, _ []byte, _ string) ([]byte, error) {
	plain, ok := d.plain[effectID]
	if !ok {
		return nil, eventstore.ErrNotFound
	}
	return append([]byte(nil), plain...), nil
}

type task6Notifier struct {
	faults *task6Faults
	result chan adapterapi.EffectResult
	success chan adapterapi.EffectResult
}

func (n *task6Notifier) notificationAllowed() bool {
	if n == nil {
		return false
	}
	if n.faults == nil {
		return true
	}
	return n.faults.hit(task6FaultNotifySchedule) == nil
}

func (n *task6Notifier) NotifyOutboundEffectResult(_ context.Context, _ adapterapi.OutboundEffect, result adapterapi.EffectResult) {
	if !n.notificationAllowed() {
		return
	}
	n.result <- result
}
func (n *task6Notifier) NotifyOutboundEffectSucceeded(_ context.Context, _ adapterapi.OutboundEffect, result adapterapi.EffectResult) {
	if !n.notificationAllowed() {
		return
	}
	n.success <- result
}

type task6Provider struct {
	mu             sync.Mutex
	faults         *task6Faults
	responseLoss   bool
	retryFirst     bool
	invocations    int
	acceptances    int
	results        int
	keys           []string
	acceptedByKey  map[string]string
}

func (p *task6Provider) ExecutePinned(_ context.Context, _ adapterapi.EndpointID, _ uint64, effect adapterapi.OutboundEffect) (adapterapi.EffectResult, error) {
	p.mu.Lock()
	p.invocations++
	p.keys = append(p.keys, string(effect.ID))
	p.mu.Unlock()
	if err := p.faults.hit(task6FaultProviderAccept); err != nil {
		return adapterapi.EffectResult{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.retryFirst && p.invocations == 1 {
		return adapterapi.RetryableResult("provider-temporary", "retry"), nil
	}
	key := string(effect.ID)
	if providerID, ok := p.acceptedByKey[key]; ok {
		p.results++
		return adapterapi.SucceededResult(providerID), nil
	}
	p.acceptances++
	providerID := "provider-result-1"
	p.acceptedByKey[key] = providerID
	if p.responseLoss {
		_ = p.faults.hit(task6FaultResponseLoss)
		return adapterapi.EffectResult{}, errors.New("provider response lost after acceptance")
	}
	p.results++
	return adapterapi.SucceededResult(providerID), nil
}

func (p *task6Provider) snapshot() (invocations, acceptances, results int, keys []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.invocations, p.acceptances, p.results, append([]string(nil), p.keys...)
}

type task6DurableStore struct {
	mu       sync.Mutex
	clock    *task6Clock
	ids      *task6IDs
	faults   *task6Faults
	effects  map[string]eventstore.NewEffect
	plain    map[string][]byte
	streams  map[eventstore.StreamID][]eventstore.Envelope
	ops      map[string]eventstore.OperationView
	nextLane map[string]uint64
	closed   bool
}

func newTask6Store(clock *task6Clock, ids *task6IDs, faults *task6Faults) *task6DurableStore {
	return &task6DurableStore{clock: clock, ids: ids, faults: faults, effects: map[string]eventstore.NewEffect{}, plain: map[string][]byte{}, streams: map[eventstore.StreamID][]eventstore.Envelope{}, ops: map[string]eventstore.OperationView{}, nextLane: map[string]uint64{}}
}

func (s *task6DurableStore) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}

func (s *task6DurableStore) AcceptOutbox(_ context.Context, effect eventstore.NewEffect) (eventstore.CommitResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.effects[effect.EffectID]; ok {
		return eventstore.CommitResult{EffectIDs: []string{existing.EffectID}, OrderingSequence: existing.OrderingSequence, Version: existing.Version, Deduplicated: true, Idempotent: true}, nil
	}
	if effect.Status == "" {
		effect.Status = eventstore.OutboxStatusPending
	}
	if effect.OrderingSequence == 0 {
		s.nextLane[string(effect.LaneHMAC)]++
		effect.OrderingSequence = s.nextLane[string(effect.LaneHMAC)]
	}
	if effect.Version == 0 {
		effect.Version = 1
	}
	if effect.PayloadVersion == 0 {
		effect.PayloadVersion = 1
	}
	effect.PayloadCiphertext = append([]byte(nil), effect.PayloadCiphertext...)
	effect.PayloadNonce = append([]byte(nil), effect.PayloadNonce...)
	s.effects[effect.EffectID] = effect
	return eventstore.CommitResult{EffectIDs: []string{effect.EffectID}, OrderingSequence: effect.OrderingSequence, Version: effect.Version}, nil
}

func (s *task6DurableStore) ClaimOutbox(_ context.Context, req eventstore.OutboxClaimRequest) (eventstore.OutboxLease, error) {
	if err := s.faults.hit(task6FaultLease); err != nil {
		return eventstore.OutboxLease{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock.Now()
	ids := make([]string, 0, len(s.effects))
	for id := range s.effects {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return s.effects[ids[i]].OrderingSequence < s.effects[ids[j]].OrderingSequence })
	for _, id := range ids {
		row := s.effects[id]
		if s.laneBlocked(row) {
			continue
		}
		if row.Status == eventstore.OutboxStatusDispatched && row.RiskClass != eventstore.RiskProviderIdempotent && !row.LeaseExpiresAt.After(now) {
			row.Status = eventstore.OutboxStatusAmbiguous
			row.Version++
			row.CompletedAt, row.LeaseExpiresAt = now, time.Time{}
			row.PayloadCiphertext, row.PayloadNonce = nil, nil
			s.effects[id] = row
			s.opsForEffectLocked(row, eventstore.OutboxStatusAmbiguous, "expired-after-dispatch")
			continue
		}
		eligible := row.Status == eventstore.OutboxStatusPending && (row.NextAttemptAt.IsZero() || !row.NextAttemptAt.After(now))
		if row.Status == eventstore.OutboxStatusLeased && !row.LeaseExpiresAt.After(now) {
			eligible = true
		}
		if row.Status == eventstore.OutboxStatusDispatched && row.RiskClass == eventstore.RiskProviderIdempotent && !row.LeaseExpiresAt.After(now) {
			eligible = true
		}
		if !eligible {
			continue
		}
		row.Status = eventstore.OutboxStatusLeased
		row.Version++
		row.LeaseOwner = req.WorkerID
		row.LeaseEpoch++
		row.AttemptID = "lease-" + strconv.FormatUint(row.LeaseEpoch, 10)
		row.LeaseExpiresAt = now.Add(req.LeaseDuration)
		if row.RetryCount > 0 || row.DispatchedAt.IsZero() == false {
			row.RetryCount++
		}
		s.effects[id] = row
		return eventstore.OutboxLease{Effect: cloneTask6Effect(row)}, nil
	}
	return eventstore.OutboxLease{}, eventstore.ErrNotFound
}

func (s *task6DurableStore) laneBlocked(candidate eventstore.NewEffect) bool {
	for _, row := range s.effects {
		if string(row.LaneHMAC) != string(candidate.LaneHMAC) || row.OrderingSequence >= candidate.OrderingSequence {
			continue
		}
		switch row.Status {
		case eventstore.OutboxStatusPending, eventstore.OutboxStatusLeased, eventstore.OutboxStatusDispatched, eventstore.OutboxStatusAmbiguous:
			return true
		}
	}
	return false
}

func (s *task6DurableStore) MarkOutboxDispatched(_ context.Context, req eventstore.OutboxDispatchRequest) (eventstore.OutboxLease, error) {
	if err := s.faults.hit(task6FaultBeforeMarker); err != nil {
		return eventstore.OutboxLease{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.effects[req.EffectID]
	if !ok || row.Status != eventstore.OutboxStatusLeased || row.LeaseOwner != req.WorkerID || row.LeaseEpoch != req.LeaseEpoch || row.AttemptID != req.AttemptID {
		return eventstore.OutboxLease{}, eventstore.ErrStaleLease
	}
	row.Status = eventstore.OutboxStatusDispatched
	row.Version++
	row.DispatchedAt = s.clock.Now()
	row.AttemptID, _ = s.ids.NewID()
	s.effects[row.EffectID] = row
	if err := s.faults.hit(task6FaultAtMarker); err != nil {
		return eventstore.OutboxLease{}, err
	}
	return eventstore.OutboxLease{Effect: cloneTask6Effect(row)}, nil
}

func (s *task6DurableStore) RequeuePreDispatch(_ context.Context, req eventstore.OutboxPreDispatchRequeueRequest) (eventstore.CommitResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.effects[req.EffectID]
	if !ok || row.LeaseOwner != req.WorkerID || row.LeaseEpoch != req.LeaseEpoch || row.AttemptID != req.AttemptID {
		return eventstore.CommitResult{}, eventstore.ErrStaleLease
	}
	row.Status, row.Version, row.RetryCount, row.NextAttemptAt = eventstore.OutboxStatusPending, row.Version+1, req.RetryCount, req.NextAttemptAt
	row.LeaseOwner, row.LeaseEpoch, row.AttemptID, row.LeaseExpiresAt = "", 0, "", time.Time{}
	s.effects[row.EffectID] = row
	return eventstore.CommitResult{EffectIDs: []string{row.EffectID}, Version: row.Version}, nil
}

func (s *task6DurableStore) RenewOutbox(context.Context, eventstore.OutboxRenewRequest) (eventstore.OutboxLease, error) {
	return eventstore.OutboxLease{}, eventstore.ErrStaleLease
}
func (s *task6DurableStore) UpdateOutbox(context.Context, eventstore.NewEffect) (eventstore.CommitResult, error) {
	return eventstore.CommitResult{}, eventstore.ErrInvalidTransition
}
func (s *task6DurableStore) ResolveOutbox(context.Context, eventstore.OutboxResolutionRequest) (eventstore.CommitResult, error) {
	return eventstore.CommitResult{}, eventstore.ErrInvalidTransition
}

func (s *task6DurableStore) CompleteOutbox(_ context.Context, req eventstore.OutboxCompletionRequest) (eventstore.CommitResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.effects[req.EffectID]
	if !ok {
		return eventstore.CommitResult{}, eventstore.ErrNotFound
	}
	if row.Status == req.Status && row.ResultCode == req.ResultCode && row.ProviderMessageID == req.ProviderMessageID && !row.CompletedAt.IsZero() {
		if row.LeaseOwner != req.WorkerID || row.LeaseEpoch != req.LeaseEpoch || row.AttemptID != req.AttemptID {
			return eventstore.CommitResult{}, eventstore.ErrStaleLease
		}
		return eventstore.CommitResult{EffectIDs: []string{row.EffectID}, Version: row.Version, Idempotent: true}, nil
	}
	return eventstore.CommitResult{}, eventstore.ErrInvalidTransition
}

func (s *task6DurableStore) QuarantineOutbox(_ context.Context, req eventstore.OutboxQuarantineRequest) (eventstore.CommitResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.effects[req.EffectID]
	if !ok || row.Version != req.ExpectedVersion || row.LeaseOwner != req.WorkerID || row.LeaseEpoch != req.LeaseEpoch || row.AttemptID != req.AttemptID {
		return eventstore.CommitResult{}, eventstore.ErrStaleLease
	}
	status := eventstore.OutboxStatusFailed
	if !row.DispatchedAt.IsZero() {
		status = eventstore.OutboxStatusAmbiguous
	}
	row.Status, row.Version = status, row.Version+1
	row.CompletedAt, row.LeaseExpiresAt = s.clock.Now(), time.Time{}
	row.PayloadCiphertext, row.PayloadNonce = nil, nil
	row.ErrorCode = req.ErrorCode
	row.LeaseOwner = req.WorkerID
	s.effects[row.EffectID] = row
	s.opsForEffectLocked(row, status, req.ErrorCode)
	s.appendTerminalLocked(row, status, req.ErrorCode, "")
	return eventstore.CommitResult{EffectIDs: []string{row.EffectID}, Version: row.Version}, nil
}

func (s *task6DurableStore) Commit(_ context.Context, work eventstore.UnitOfWork) (eventstore.CommitResult, error) {
	terminal := ""
	for _, update := range work.Effects {
		if update.Status == eventstore.OutboxStatusSucceeded || update.Status == eventstore.OutboxStatusFailed || update.Status == eventstore.OutboxStatusAmbiguous {
			terminal = update.Status
		}
	}
	if terminal != "" {
		if err := s.faults.hit(task6FaultTerminalPersist); err != nil {
			return eventstore.CommitResult{}, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(work.Effects) == 0 {
		return eventstore.CommitResult{}, eventstore.ErrEmptyUnitOfWork
	}
	for _, update := range work.Effects {
		row, ok := s.effects[update.EffectID]
		if !ok {
			return eventstore.CommitResult{}, eventstore.ErrNotFound
		}
		if row.Status == update.Status && !row.CompletedAt.IsZero() && terminal != "" {
			return eventstore.CommitResult{EffectIDs: []string{row.EffectID}, Version: row.Version, Idempotent: true}, nil
		}
		if row.Version != update.ExpectedVersion || row.LeaseOwner != update.LeaseOwner || row.LeaseEpoch != update.LeaseEpoch || row.AttemptID != update.AttemptID {
			return eventstore.CommitResult{}, eventstore.ErrStaleLease
		}
		row.Status, row.Version = update.Status, row.Version+1
		row.ResultCode, row.ProviderMessageID = update.ResultCode, update.ProviderMessageID
		if update.RetryCount != 0 {
			row.RetryCount = update.RetryCount
		}
		if !update.NextAttemptAt.IsZero() {
			row.NextAttemptAt = update.NextAttemptAt
		}
		if terminal != "" {
			row.CompletedAt, row.LeaseExpiresAt = s.clock.Now(), time.Time{}
			row.PayloadCiphertext, row.PayloadNonce = nil, nil
		}
		if update.Status == eventstore.OutboxStatusPending {
			row.LeaseOwner, row.LeaseEpoch, row.AttemptID, row.LeaseExpiresAt = "", 0, "", time.Time{}
		}
		s.effects[row.EffectID] = row
		if len(work.Operations) > 0 {
			s.opsForEffectLocked(row, work.Operations[0].Status, update.ResultCode)
		}
		if len(work.Streams) > 0 {
			for _, append := range work.Streams {
				s.appendStreamLocked(append.Stream, append.ExpectedVersion, append.Events)
			}
		}
		return eventstore.CommitResult{EffectIDs: []string{row.EffectID}, Version: row.Version}, nil
	}
	return eventstore.CommitResult{}, nil
}

func (s *task6DurableStore) appendTerminalLocked(row eventstore.NewEffect, status, code, providerID string) {
	stream := eventstore.StreamID{AggregateType: "outbound-effect", AggregateID: row.EffectID}
	eventID, _ := s.ids.NewID()
	payload, _ := json.Marshal(map[string]string{"effectId": row.EffectID, "operationId": s.operationIDLocked(row.EffectID), "status": status, "resultCode": code, "providerId": providerID})
	s.appendStreamLocked(stream, uint64(len(s.streams[stream])), []eventstore.NewEvent{{EventType: dispatcherEventTypeForStatus(status), SchemaVersion: 1, Payload: payload, Metadata: eventstore.Metadata{EventID: eventID, CommandID: eventID + "-command", CorrelationID: "task6-correlation", OccurredAt: s.clock.Now()}}})
}
func (s *task6DurableStore) appendStreamLocked(stream eventstore.StreamID, expected uint64, events []eventstore.NewEvent) {
	persisted := s.streams[stream]
	if uint64(len(persisted)) != expected {
		return
	}
	for _, event := range events {
		version := uint64(len(persisted) + 1)
		persisted = append(persisted, eventstore.Envelope{Stream: stream, StreamVersion: version, GlobalPosition: version, EventID: event.Metadata.EventID, EventType: event.EventType, SchemaVersion: event.SchemaVersion, Payload: append([]byte(nil), event.Payload...), Metadata: event.Metadata})
	}
	s.streams[stream] = persisted
}
func (s *task6DurableStore) opsForEffectLocked(row eventstore.NewEffect, status, code string) {
	for id, op := range s.ops {
		if id == s.operationIDLocked(row.EffectID) {
			op.Status, op.Version, op.ResultCode = status, op.Version+1, code
			s.ops[id] = op
		}
	}
}
func (s *task6DurableStore) operationIDLocked(effectID string) string {
	for id, op := range s.ops {
		if op.ResourceID == effectID {
			return id
		}
	}
	return ""
}

func (s *task6DurableStore) Load(_ context.Context, stream eventstore.StreamID, _ uint64) ([]eventstore.Envelope, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]eventstore.Envelope(nil), s.streams[stream]...), nil
}
func (s *task6DurableStore) GetOperation(_ context.Context, operationID string) (eventstore.OperationView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	op, ok := s.ops[operationID]
	if !ok {
		return eventstore.OperationView{}, eventstore.ErrNotFound
	}
	return op, nil
}

func cloneTask6Effect(effect eventstore.NewEffect) eventstore.NewEffect {
	effect.PayloadCiphertext = append([]byte(nil), effect.PayloadCiphertext...)
	effect.PayloadNonce = append([]byte(nil), effect.PayloadNonce...)
	return effect
}

func (s *task6DurableStore) seed(t *testing.T, effect adapterapi.OutboundEffect) {
	t.Helper()
	plain, err := json.Marshal(effectWire{Effect: effect})
	if err != nil {
		t.Fatal(err)
	}
	laneHMAC, err := hex.DecodeString(effect.Lane.MAC)
	if err != nil {
		t.Fatal(err)
	}
	newEffect := eventstore.NewEffect{EffectID: string(effect.ID), EndpointID: string(effect.EndpointID), LaneHMAC: laneHMAC, EffectType: effectTypeForKind(effect.Kind), RiskClass: map[adapterapi.EffectRetryClass]string{adapterapi.EffectRetryNonIdempotent: eventstore.RiskNonIdempotentAfterDispatch, adapterapi.EffectRetryProviderIdempotent: eventstore.RiskProviderIdempotent}[effect.RetryClass], DeadlineAt: effect.Deadline, PayloadCiphertext: []byte("ciphertext-task6"), PayloadNonce: []byte("nonce-task6"), PayloadEncryptionKeyID: "key-task6"}
	if _, err := s.AcceptOutbox(context.Background(), newEffect); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.plain[string(effect.ID)] = plain
	stream := eventstore.StreamID{AggregateType: "outbound-effect", AggregateID: string(effect.ID)}
	s.streams[stream] = []eventstore.Envelope{{Stream: stream, StreamVersion: 1, GlobalPosition: 1, EventID: "source-event-" + string(effect.ID), EventType: "OutboundEffectRequestedV1", SchemaVersion: 1, Payload: mustJSON(map[string]string{"effectId": string(effect.ID), "operationId": string(effect.OperationID), "endpointId": string(effect.EndpointID)}), Metadata: eventstore.Metadata{EventID: "source-event-" + string(effect.ID), CommandID: "source-command-" + string(effect.ID), CorrelationID: string(effect.CorrelationID), OccurredAt: time.Unix(1000, 0).UTC()}}}
	s.ops[string(effect.OperationID)] = eventstore.OperationView{OperationID: string(effect.OperationID), Version: 1, Status: "pending", ResourceID: string(effect.ID)}
	s.mu.Unlock()
}

func mustJSON(value any) []byte { encoded, _ := json.Marshal(value); return encoded }

func (s *task6DurableStore) row(id string) eventstore.NewEffect {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneTask6Effect(s.effects[id])
}
func (s *task6DurableStore) events(id string) []eventstore.Envelope {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]eventstore.Envelope(nil), s.streams[eventstore.StreamID{AggregateType: "outbound-effect", AggregateID: id}]...)
}

func task6Effect(t *testing.T, id, operation string, retry adapterapi.EffectRetryClass) adapterapi.OutboundEffect {
	target := adapterapi.EffectTarget{Kind: adapterapi.TargetPerson, Conversation: "person-task6"}
	lane, err := adapterapi.NewLaneMetadata("endpoint-task6", target, []byte("task6-index-root"), 1)
	if err != nil {
		t.Fatal(err)
	}
	effect := adapterapi.OutboundEffect{Version: adapterapi.EffectVersionOne, ID: adapterapi.EffectID(id), EndpointID: "endpoint-task6", OperationID: adapterapi.OperationID(operation), CorrelationID: "correlation-task6", CausationID: "causation-task6", Lane: lane, Deadline: time.Unix(5000, 0).UTC(), Risk: adapterapi.EffectRiskNormal, RetryClass: retry, RequiredCapabilities: adapterapi.CapabilityOutbound, RequiredAction: adapterapi.ActionKindSendMessage, Kind: adapterapi.EffectKindMessage, Payload: adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadPersonText, Target: target, Text: "do not retain this plaintext"}}
	if retry == adapterapi.EffectRetryProviderIdempotent {
		effect.Kind = adapterapi.EffectKindAction
		effect.RequiredCapabilities = adapterapi.CapabilityOutbound | adapterapi.CapabilityActions
		effect.RequiredAction = adapterapi.ActionKindGroupInfoRefresh
		effect.Payload = adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadGroupInfoRefresh, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "group-task6"}}
		effect.Lane, err = adapterapi.NewLaneMetadata("endpoint-task6", effect.Payload.Target, []byte("task6-index-root"), 1)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := effect.Validate(); err != nil {
		t.Fatal(err)
	}
	return effect
}

func newTask6Dispatcher(t *testing.T, store *task6DurableStore, clock *task6Clock, ids *task6IDs, provider *task6Provider, notifier *task6Notifier) *EffectDispatcher {
	t.Helper()
	dispatcher, err := NewEffectDispatcher(store, task6Decrypt{plain: store.plain}, provider, "task6-worker", WithDispatcherClock(clock), WithDispatcherIDGenerator(ids), WithDispatcherRandom(func(time.Duration) time.Duration { return 0 }), WithEffectResultNotifier(notifier), WithEffectSuccessNotifier(notifier))
	if err != nil {
		t.Fatal(err)
	}
	return dispatcher
}

func waitTask6(t *testing.T, ch <-chan adapterapi.EffectResult, want adapterapi.EffectOutcome) adapterapi.EffectResult {
	t.Helper()
	select {
	case result := <-ch:
		if result.Outcome != want {
			t.Fatalf("notification outcome = %v, want %v", result.Outcome, want)
		}
		return result
	case <-time.After(time.Second):
		t.Fatal("notification was not scheduled")
		return adapterapi.EffectResult{}
	}
}

func assertTask6Durable(t *testing.T, store *task6DurableStore, effectID, operationID, status string, eventType string) {
	t.Helper()
	row := store.row(effectID)
	if row.Status != status || !row.CompletedAt.Equal(store.clock.Now()) {
		t.Fatalf("durable effect = %#v, want status %q at %v", row, status, store.clock.Now())
	}
	if len(row.PayloadCiphertext) != 0 || len(row.PayloadNonce) != 0 || bytes.Contains(row.PayloadCiphertext, []byte("do not retain")) {
		t.Fatalf("durable effect retained plaintext/ciphertext: %#v", row)
	}
	op, err := store.GetOperation(context.Background(), operationID)
	if err != nil || op.Status != status {
		t.Fatalf("durable operation = %#v err=%v, want status %q", op, err, status)
	}
	events := store.events(effectID)
	if len(events) != 2 || events[1].EventType != eventType {
		t.Fatalf("durable stream events = %#v, want one %s terminal event", events, eventType)
	}
	if bytes.Contains(events[1].Payload, []byte("do not retain")) {
		t.Fatalf("terminal event retained plaintext: %s", events[1].Payload)
	}
}

func TestTask6DispatcherAppendBeforeLeaseDispatchesOnce(t *testing.T) {
	clock := &task6Clock{now: time.Unix(1000, 0).UTC()}
	ids, faults := &task6IDs{}, &task6Faults{err: map[task6FaultPoint]error{}, calls: map[task6FaultPoint]int{}}
	store := newTask6Store(clock, ids, faults)
	effect := task6Effect(t, "task6-append-effect", "task6-append-operation", adapterapi.EffectRetryNonIdempotent)
	store.seed(t, effect)
	provider := &task6Provider{faults: faults, acceptedByKey: map[string]string{}}
	notifier := &task6Notifier{faults: faults, result: make(chan adapterapi.EffectResult, 2), success: make(chan adapterapi.EffectResult, 2)}
	d := newTask6Dispatcher(t, store, clock, ids, provider, notifier)
	if _, err := d.DispatchOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertTask6Durable(t, store, string(effect.ID), string(effect.OperationID), eventstore.OutboxStatusSucceeded, "OutboundEffectSucceededV1")
	waitTask6(t, notifier.result, adapterapi.EffectSucceeded)
	waitTask6(t, notifier.success, adapterapi.EffectSucceeded)
	invocations, acceptances, results, _ := provider.snapshot()
	if invocations != 1 || acceptances != 1 || results != 1 {
		t.Fatalf("provider counts invocation=%d acceptance=%d results=%d, want 1/1/1", invocations, acceptances, results)
	}
	if faults.count(task6FaultLease) != 1 || faults.count(task6FaultNotifySchedule) != 2 {
		t.Fatalf("fault boundary counts lease=%d notify=%d", faults.count(task6FaultLease), faults.count(task6FaultNotifySchedule))
	}
}

func TestDispatcherRecoveryLeasedBeforeDispatch(t *testing.T) {
	clock := &task6Clock{now: time.Unix(1000, 0).UTC()}
	ids, faults := &task6IDs{}, &task6Faults{err: map[task6FaultPoint]error{}, calls: map[task6FaultPoint]int{}}
	store := newTask6Store(clock, ids, faults)
	effect := task6Effect(t, "task6-leased-effect", "task6-leased-operation", adapterapi.EffectRetryNonIdempotent)
	store.seed(t, effect)
	claimed, err := store.ClaimOutbox(context.Background(), eventstore.OutboxClaimRequest{WorkerID: "crashed-worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if claimed.Effect.Status != eventstore.OutboxStatusLeased {
		t.Fatalf("pre-crash row = %#v", claimed.Effect)
	}
	clock.advance(2 * time.Minute)
	provider := &task6Provider{faults: faults, acceptedByKey: map[string]string{}}
	notifier := &task6Notifier{faults: faults, result: make(chan adapterapi.EffectResult, 1), success: make(chan adapterapi.EffectResult, 1)}
	d := newTask6Dispatcher(t, store, clock, ids, provider, notifier)
	if _, err := d.DispatchOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertTask6Durable(t, store, string(effect.ID), string(effect.OperationID), eventstore.OutboxStatusSucceeded, "OutboundEffectSucceededV1")
	invocations, acceptances, _, _ := provider.snapshot()
	if invocations != 1 || acceptances != 1 {
		t.Fatalf("recovery provider counts invocation=%d acceptance=%d, want 1/1", invocations, acceptances)
	}
}

func TestDispatcherCrashNonIdempotentResponseLossBlocksLane(t *testing.T) {
	clock := &task6Clock{now: time.Unix(1000, 0).UTC()}
	ids, faults := &task6IDs{}, &task6Faults{err: map[task6FaultPoint]error{task6FaultResponseLoss: errors.New("lost")}, calls: map[task6FaultPoint]int{}}
	store := newTask6Store(clock, ids, faults)
	effect := task6Effect(t, "task6-loss-effect", "task6-loss-operation", adapterapi.EffectRetryNonIdempotent)
	successor := task6Effect(t, "task6-loss-successor", "task6-loss-successor-operation", adapterapi.EffectRetryNonIdempotent)
	store.seed(t, effect)
	store.seed(t, successor)
	provider := &task6Provider{faults: faults, responseLoss: true, acceptedByKey: map[string]string{}}
	notifier := &task6Notifier{faults: faults, result: make(chan adapterapi.EffectResult, 2), success: make(chan adapterapi.EffectResult, 1)}
	d := newTask6Dispatcher(t, store, clock, ids, provider, notifier)
	if _, err := d.DispatchOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertTask6Durable(t, store, string(effect.ID), string(effect.OperationID), eventstore.OutboxStatusAmbiguous, "OutboundEffectAmbiguousV1")
	if _, err := store.ClaimOutbox(context.Background(), eventstore.OutboxClaimRequest{WorkerID: "restart-worker", LeaseDuration: time.Minute}); !errors.Is(err, eventstore.ErrNotFound) {
		t.Fatalf("blocked lane claim err=%v, want not found", err)
	}
	invocations, acceptances, results, _ := provider.snapshot()
	if invocations != 1 || acceptances != 1 || results != 0 {
		t.Fatalf("lost-response provider counts invocation=%d acceptance=%d results=%d, want 1/1/0", invocations, acceptances, results)
	}
	waitTask6(t, notifier.result, adapterapi.EffectAmbiguous)
	select {
	case <-notifier.success:
		t.Fatal("ambiguous completion scheduled success notification")
	case <-time.After(30 * time.Millisecond):
	}
	if faults.count(task6FaultResponseLoss) != 1 {
		t.Fatalf("response-loss fault count=%d, want one provider boundary hit", faults.count(task6FaultResponseLoss))
	}
}

func TestDispatcherIdempotencyUsesEffectIDAcrossRetry(t *testing.T) {
	clock := &task6Clock{now: time.Unix(1000, 0).UTC()}
	ids, faults := &task6IDs{}, &task6Faults{err: map[task6FaultPoint]error{}, calls: map[task6FaultPoint]int{}}
	store := newTask6Store(clock, ids, faults)
	effect := task6Effect(t, "task6-idempotent-effect", "task6-idempotent-operation", adapterapi.EffectRetryProviderIdempotent)
	store.seed(t, effect)
	provider := &task6Provider{faults: faults, retryFirst: true, acceptedByKey: map[string]string{}}
	notifier := &task6Notifier{faults: faults, result: make(chan adapterapi.EffectResult, 1), success: make(chan adapterapi.EffectResult, 1)}
	first := newTask6Dispatcher(t, store, clock, ids, provider, notifier)
	firstResult, err := first.DispatchOnce(context.Background())
	if err != nil || firstResult.Outcome != adapterapi.EffectRetryable {
		t.Fatalf("first idempotent result=%#v err=%v", firstResult, err)
	}
	if row := store.row(string(effect.ID)); row.Status != eventstore.OutboxStatusPending || len(store.events(string(effect.ID))) != 1 {
		t.Fatalf("retry checkpoint row=%#v events=%#v", row, store.events(string(effect.ID)))
	}
	clock.advance(time.Second)
	second := newTask6Dispatcher(t, store, clock, ids, provider, notifier)
	if _, err := second.DispatchOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertTask6Durable(t, store, string(effect.ID), string(effect.OperationID), eventstore.OutboxStatusSucceeded, "OutboundEffectSucceededV1")
	invocations, acceptances, results, keys := provider.snapshot()
	if invocations != 2 || acceptances != 1 || results != 1 {
		t.Fatalf("idempotent provider counts invocation=%d acceptance=%d results=%d, want 2/1/1", invocations, acceptances, results)
	}
	if len(keys) != 2 || keys[0] != string(effect.ID) || keys[1] != string(effect.ID) {
		t.Fatalf("provider idempotency keys=%v, want repeated effect ID", keys)
	}
	waitTask6(t, notifier.result, adapterapi.EffectSucceeded)
	waitTask6(t, notifier.success, adapterapi.EffectSucceeded)
}

func TestTask6DispatcherCompletionReplayHasOneTerminalEventAndNotifications(t *testing.T) {
	clock := &task6Clock{now: time.Unix(1000, 0).UTC()}
	ids, faults := &task6IDs{}, &task6Faults{err: map[task6FaultPoint]error{}, calls: map[task6FaultPoint]int{}}
	store := newTask6Store(clock, ids, faults)
	effect := task6Effect(t, "task6-replay-effect", "task6-replay-operation", adapterapi.EffectRetryNonIdempotent)
	store.seed(t, effect)
	provider := &task6Provider{faults: faults, acceptedByKey: map[string]string{}}
	notifier := &task6Notifier{faults: faults, result: make(chan adapterapi.EffectResult, 2), success: make(chan adapterapi.EffectResult, 2)}
	d := newTask6Dispatcher(t, store, clock, ids, provider, notifier)
	if _, err := d.DispatchOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitTask6(t, notifier.result, adapterapi.EffectSucceeded)
	waitTask6(t, notifier.success, adapterapi.EffectSucceeded)
	row := store.row(string(effect.ID))
	before := len(store.events(string(effect.ID)))
	if _, err := store.CompleteOutbox(context.Background(), eventstore.OutboxCompletionRequest{EffectID: row.EffectID, WorkerID: row.LeaseOwner, LeaseEpoch: row.LeaseEpoch, AttemptID: row.AttemptID, Status: eventstore.OutboxStatusSucceeded, ResultCode: row.ResultCode, ProviderMessageID: row.ProviderMessageID}); err != nil {
		t.Fatal(err)
	}
	if got := len(store.events(string(effect.ID))); got != before {
		t.Fatalf("completion replay appended terminal event: before=%d after=%d", before, got)
	}
	select {
	case <-notifier.result:
		t.Fatal("completion replay scheduled duplicate all-outcome notification")
	case <-time.After(30 * time.Millisecond):
	}
	select {
	case <-notifier.success:
		t.Fatal("completion replay scheduled duplicate success notification")
	case <-time.After(30 * time.Millisecond):
	}
	if faults.count(task6FaultNotifySchedule) != 2 {
		t.Fatalf("notification scheduling count=%d, want two committed terminal schedules", faults.count(task6FaultNotifySchedule))
	}
}

func TestTask6DispatcherFaultLeaseAcquisitionDoesNotChangeDurableState(t *testing.T) {
	clock := &task6Clock{now: time.Unix(1000, 0).UTC()}
	ids, faults := &task6IDs{}, &task6Faults{err: map[task6FaultPoint]error{task6FaultLease: errors.New("lease fault")}, calls: map[task6FaultPoint]int{}}
	store := newTask6Store(clock, ids, faults)
	effect := task6Effect(t, "task6-lease-fault-effect", "task6-lease-fault-operation", adapterapi.EffectRetryNonIdempotent)
	store.seed(t, effect)
	provider := &task6Provider{faults: faults, acceptedByKey: map[string]string{}}
	d := newTask6Dispatcher(t, store, clock, ids, provider, nil)
	if _, err := d.DispatchOnce(context.Background()); err == nil {
		t.Fatal("lease fault unexpectedly dispatched")
	}
	row := store.row(string(effect.ID))
	if row.Status != eventstore.OutboxStatusPending || row.Version != 1 || len(store.events(string(effect.ID))) != 1 {
		t.Fatalf("lease fault durable state = %#v events=%d", row, len(store.events(string(effect.ID))))
	}
	invocations, acceptances, _, _ := provider.snapshot()
	if invocations != 0 || acceptances != 0 || faults.count(task6FaultLease) != 1 {
		t.Fatalf("lease fault counts invocation=%d acceptance=%d fault=%d", invocations, acceptances, faults.count(task6FaultLease))
	}
}

func TestDispatcherCrashBeforeDispatchedMarkerQuarantinesWithoutProviderExecution(t *testing.T) {
	clock := &task6Clock{now: time.Unix(1000, 0).UTC()}
	ids, faults := &task6IDs{}, &task6Faults{err: map[task6FaultPoint]error{task6FaultBeforeMarker: errors.New("marker fault")}, calls: map[task6FaultPoint]int{}}
	store := newTask6Store(clock, ids, faults)
	effect := task6Effect(t, "task6-marker-fault-effect", "task6-marker-fault-operation", adapterapi.EffectRetryNonIdempotent)
	store.seed(t, effect)
	provider := &task6Provider{faults: faults, acceptedByKey: map[string]string{}}
	d := newTask6Dispatcher(t, store, clock, ids, provider, nil)
	if _, err := d.DispatchOnce(context.Background()); err == nil {
		t.Fatal("marker fault unexpectedly dispatched")
	}
	assertTask6Durable(t, store, string(effect.ID), string(effect.OperationID), eventstore.OutboxStatusFailed, "OutboundEffectFailedV1")
	invocations, acceptances, _, _ := provider.snapshot()
	if invocations != 0 || acceptances != 0 || faults.count(task6FaultBeforeMarker) != 1 {
		t.Fatalf("marker fault counts invocation=%d acceptance=%d fault=%d", invocations, acceptances, faults.count(task6FaultBeforeMarker))
	}
}

func TestDispatcherCrashAtDispatchedMarkerLeavesRecoveryBoundary(t *testing.T) {
	clock := &task6Clock{now: time.Unix(1000, 0).UTC()}
	ids, faults := &task6IDs{}, &task6Faults{err: map[task6FaultPoint]error{task6FaultAtMarker: errors.New("marker commit response lost")}, calls: map[task6FaultPoint]int{}}
	store := newTask6Store(clock, ids, faults)
	effect := task6Effect(t, "task6-at-marker-effect", "task6-at-marker-operation", adapterapi.EffectRetryNonIdempotent)
	successor := task6Effect(t, "task6-at-marker-successor", "task6-at-marker-successor-operation", adapterapi.EffectRetryNonIdempotent)
	store.seed(t, effect)
	store.seed(t, successor)
	provider := &task6Provider{faults: faults, acceptedByKey: map[string]string{}}
	d := newTask6Dispatcher(t, store, clock, ids, provider, nil)
	if _, err := d.DispatchOnce(context.Background()); err == nil {
		t.Fatal("marker response loss unexpectedly dispatched")
	}
	row := store.row(string(effect.ID))
	if row.Status != eventstore.OutboxStatusDispatched || row.DispatchedAt.IsZero() || len(store.events(string(effect.ID))) != 1 {
		t.Fatalf("at-marker durable boundary = %#v events=%d", row, len(store.events(string(effect.ID))))
	}
	invocations, acceptances, _, _ := provider.snapshot()
	if invocations != 0 || acceptances != 0 || faults.count(task6FaultAtMarker) != 1 {
		t.Fatalf("at-marker counts invocation=%d acceptance=%d fault=%d", invocations, acceptances, faults.count(task6FaultAtMarker))
	}
	clock.advance(2 * time.Minute)
	if _, err := store.ClaimOutbox(context.Background(), eventstore.OutboxClaimRequest{WorkerID: "restart-worker", LeaseDuration: time.Minute}); !errors.Is(err, eventstore.ErrNotFound) {
		t.Fatalf("expired non-idempotent marker claim err=%v, want not found", err)
	}
	row = store.row(string(effect.ID))
	if row.Status != eventstore.OutboxStatusAmbiguous || row.CompletedAt.IsZero() || len(row.PayloadCiphertext) != 0 || len(row.PayloadNonce) != 0 {
		t.Fatalf("expired marker row = %#v, want ambiguous scrubbed row", row)
	}
	if _, err := store.ClaimOutbox(context.Background(), eventstore.OutboxClaimRequest{WorkerID: "second-restart-worker", LeaseDuration: time.Minute}); !errors.Is(err, eventstore.ErrNotFound) {
		t.Fatalf("successor lane claim err=%v, want blocked by ambiguous predecessor", err)
	}
}

func TestDispatcherProviderAcceptanceFaultIsAmbiguousAfterDispatchMarker(t *testing.T) {
	clock := &task6Clock{now: time.Unix(1000, 0).UTC()}
	ids, faults := &task6IDs{}, &task6Faults{err: map[task6FaultPoint]error{task6FaultProviderAccept: errors.New("acceptance fault")}, calls: map[task6FaultPoint]int{}}
	store := newTask6Store(clock, ids, faults)
	effect := task6Effect(t, "task6-acceptance-fault-effect", "task6-acceptance-fault-operation", adapterapi.EffectRetryNonIdempotent)
	store.seed(t, effect)
	provider := &task6Provider{faults: faults, acceptedByKey: map[string]string{}}
	d := newTask6Dispatcher(t, store, clock, ids, provider, nil)
	if _, err := d.DispatchOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertTask6Durable(t, store, string(effect.ID), string(effect.OperationID), eventstore.OutboxStatusAmbiguous, "OutboundEffectAmbiguousV1")
	invocations, acceptances, results, _ := provider.snapshot()
	if invocations != 1 || acceptances != 0 || results != 0 || faults.count(task6FaultProviderAccept) != 1 {
		t.Fatalf("acceptance fault counts invocation=%d acceptance=%d results=%d fault=%d", invocations, acceptances, results, faults.count(task6FaultProviderAccept))
	}
}

func TestDispatcherCrashTerminalPersistenceAfterProviderAcceptanceIsAmbiguous(t *testing.T) {
	clock := &task6Clock{now: time.Unix(1000, 0).UTC()}
	ids, faults := &task6IDs{}, &task6Faults{err: map[task6FaultPoint]error{task6FaultTerminalPersist: errors.New("terminal persistence fault")}, calls: map[task6FaultPoint]int{}}
	store := newTask6Store(clock, ids, faults)
	effect := task6Effect(t, "task6-terminal-fault-effect", "task6-terminal-fault-operation", adapterapi.EffectRetryNonIdempotent)
	store.seed(t, effect)
	provider := &task6Provider{faults: faults, acceptedByKey: map[string]string{}}
	d := newTask6Dispatcher(t, store, clock, ids, provider, nil)
	if _, err := d.DispatchOnce(context.Background()); err == nil {
		t.Fatal("terminal persistence fault unexpectedly succeeded")
	}
	assertTask6Durable(t, store, string(effect.ID), string(effect.OperationID), eventstore.OutboxStatusAmbiguous, "OutboundEffectAmbiguousV1")
	invocations, acceptances, results, _ := provider.snapshot()
	if invocations != 1 || acceptances != 1 || results != 1 || faults.count(task6FaultTerminalPersist) != 1 {
		t.Fatalf("terminal fault counts invocation=%d acceptance=%d results=%d fault=%d", invocations, acceptances, results, faults.count(task6FaultTerminalPersist))
	}
}

func TestTask6DispatcherNotificationSchedulingFaultIsBestEffort(t *testing.T) {
	clock := &task6Clock{now: time.Unix(1000, 0).UTC()}
	ids, faults := &task6IDs{}, &task6Faults{err: map[task6FaultPoint]error{task6FaultNotifySchedule: errors.New("notification scheduling fault")}, calls: map[task6FaultPoint]int{}}
	store := newTask6Store(clock, ids, faults)
	effect := task6Effect(t, "task6-notify-fault-effect", "task6-notify-fault-operation", adapterapi.EffectRetryNonIdempotent)
	store.seed(t, effect)
	provider := &task6Provider{faults: faults, acceptedByKey: map[string]string{}}
	notifier := &task6Notifier{faults: faults, result: make(chan adapterapi.EffectResult, 1), success: make(chan adapterapi.EffectResult, 1)}
	d := newTask6Dispatcher(t, store, clock, ids, provider, notifier)
	if _, err := d.DispatchOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertTask6Durable(t, store, string(effect.ID), string(effect.OperationID), eventstore.OutboxStatusSucceeded, "OutboundEffectSucceededV1")
	select {
	case <-notifier.result:
		t.Fatal("notification scheduling fault still delivered all-outcome callback")
	case <-time.After(30 * time.Millisecond):
	}
	select {
	case <-notifier.success:
		t.Fatal("notification scheduling fault still delivered success callback")
	case <-time.After(30 * time.Millisecond):
	}
	if got := faults.count(task6FaultNotifySchedule); got != 2 {
		t.Fatalf("notification scheduling fault count=%d, want two attempted callbacks", got)
	}
}

var _ DispatcherStore = (*task6DurableStore)(nil)
var _ EffectExecutor = (*task6Provider)(nil)
var _ DispatcherDecryptor = task6Decrypt{}
var _ EffectResultNotifier = (*task6Notifier)(nil)
var _ EffectSuccessNotifier = (*task6Notifier)(nil)

func (s *task6DurableStore) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fmt.Sprintf("effects=%d streams=%d", len(s.effects), len(s.streams))
}
