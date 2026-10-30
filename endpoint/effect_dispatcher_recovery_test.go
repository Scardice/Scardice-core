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

// dispatcherFaultPoint is deliberately test-only. Production dispatcher code has no
// fault switch; the fake durable store/provider use these callbacks to model a
// process crash at a named boundary.
type dispatcherFaultPoint string

const (
	dispatcherFaultAtMarker        dispatcherFaultPoint = "at-dispatched-marker"
	dispatcherFaultLease           dispatcherFaultPoint = "lease-acquisition"
	dispatcherFaultBeforeMarker    dispatcherFaultPoint = "before-dispatched-marker"
	dispatcherFaultProviderAccept  dispatcherFaultPoint = "provider-acceptance"
	dispatcherFaultResponseLoss    dispatcherFaultPoint = "provider-response-loss"
	dispatcherFaultTerminalPersist dispatcherFaultPoint = "terminal-persistence"
	dispatcherFaultNotifySchedule  dispatcherFaultPoint = "result-notification-scheduling"
)

type dispatcherFaults struct {
	mu    sync.Mutex
	err   map[dispatcherFaultPoint]error
	calls map[dispatcherFaultPoint]int
}

func (f *dispatcherFaults) hit(point dispatcherFaultPoint) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[point]++
	return f.err[point]
}

func (f *dispatcherFaults) count(point dispatcherFaultPoint) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[point]
}

func dispatcherFaultErrors(point dispatcherFaultPoint, err error) map[dispatcherFaultPoint]error {
	faults := make(map[dispatcherFaultPoint]error, 1)
	faults[point] = err
	return faults
}

type dispatcherRecoveryClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *dispatcherRecoveryClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}
func (c *dispatcherRecoveryClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

type dispatcherRecoveryIDs struct {
	mu sync.Mutex
	n  int
}

func (g *dispatcherRecoveryIDs) NewID() (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.n++
	return "dispatcher-recovery-id-" + strconv.Itoa(g.n), nil
}

type dispatcherRecoveryDecryptor struct{ plain map[string][]byte }

func (d dispatcherRecoveryDecryptor) DecryptBound(_ context.Context, _ string, effectID, _ string, _ uint64, _ []byte, _ []byte, _ string) ([]byte, error) {
	plain, ok := d.plain[effectID]
	if !ok {
		return nil, eventstore.ErrNotFound
	}
	return append([]byte(nil), plain...), nil
}

type dispatcherRecoveryNotifier struct {
	faults  *dispatcherFaults
	result  chan adapterapi.EffectResult
	success chan adapterapi.EffectResult
}

func (n *dispatcherRecoveryNotifier) notificationAllowed() bool {
	if n == nil {
		return false
	}
	if n.faults == nil {
		return true
	}
	return n.faults.hit(dispatcherFaultNotifySchedule) == nil
}

func (n *dispatcherRecoveryNotifier) NotifyOutboundEffectResult(_ context.Context, _ adapterapi.OutboundEffect, result adapterapi.EffectResult) {
	if !n.notificationAllowed() {
		return
	}
	n.result <- result
}
func (n *dispatcherRecoveryNotifier) NotifyOutboundEffectSucceeded(_ context.Context, _ adapterapi.OutboundEffect, result adapterapi.EffectResult) {
	if !n.notificationAllowed() {
		return
	}
	n.success <- result
}

type dispatcherRecoveryProvider struct {
	mu            sync.Mutex
	faults        *dispatcherFaults
	responseLoss  bool
	retryFirst    bool
	invocations   int
	acceptances   int
	results       int
	keys          []string
	acceptedByKey map[string]string
}

func (p *dispatcherRecoveryProvider) ExecutePinned(_ context.Context, _ adapterapi.EndpointID, _ uint64, effect adapterapi.OutboundEffect) (adapterapi.EffectResult, error) {
	p.mu.Lock()
	p.invocations++
	p.keys = append(p.keys, string(effect.ID))
	p.mu.Unlock()
	if err := p.faults.hit(dispatcherFaultProviderAccept); err != nil {
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
		_ = p.faults.hit(dispatcherFaultResponseLoss)
		return adapterapi.EffectResult{}, errors.New("provider response lost after acceptance")
	}
	p.results++
	return adapterapi.SucceededResult(providerID), nil
}

func (p *dispatcherRecoveryProvider) snapshot() (invocations, acceptances, results int, keys []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.invocations, p.acceptances, p.results, append([]string(nil), p.keys...)
}

type dispatcherRecoveryStore struct {
	mu       sync.Mutex
	clock    *dispatcherRecoveryClock
	ids      *dispatcherRecoveryIDs
	faults   *dispatcherFaults
	effects  map[string]eventstore.NewEffect
	plain    map[string][]byte
	streams  map[eventstore.StreamID][]eventstore.Envelope
	ops      map[string]eventstore.OperationView
	nextLane map[string]uint64
	closed   bool
}

func newDispatcherRecoveryStore(clock *dispatcherRecoveryClock, ids *dispatcherRecoveryIDs, faults *dispatcherFaults) *dispatcherRecoveryStore {
	return &dispatcherRecoveryStore{clock: clock, ids: ids, faults: faults, effects: map[string]eventstore.NewEffect{}, plain: map[string][]byte{}, streams: map[eventstore.StreamID][]eventstore.Envelope{}, ops: map[string]eventstore.OperationView{}, nextLane: map[string]uint64{}}
}

func (s *dispatcherRecoveryStore) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}

func (s *dispatcherRecoveryStore) AcceptOutbox(_ context.Context, effect eventstore.NewEffect) (eventstore.CommitResult, error) {
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

func (s *dispatcherRecoveryStore) ClaimOutbox(_ context.Context, req eventstore.OutboxClaimRequest) (eventstore.OutboxLease, error) {
	if err := s.faults.hit(dispatcherFaultLease); err != nil {
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
		return eventstore.OutboxLease{Effect: cloneDispatcherRecoveryEffect(row)}, nil
	}
	return eventstore.OutboxLease{}, eventstore.ErrNotFound
}

func (s *dispatcherRecoveryStore) laneBlocked(candidate eventstore.NewEffect) bool {
	for _, row := range s.effects {
		if string(row.LaneHMAC) != string(candidate.LaneHMAC) || row.OrderingSequence >= candidate.OrderingSequence {
			continue
		}
		switch row.Status {
		case eventstore.OutboxStatusPending, eventstore.OutboxStatusLeased, eventstore.OutboxStatusDispatched:
			return true
		}
	}
	return false
}

func (s *dispatcherRecoveryStore) MarkOutboxDispatched(_ context.Context, req eventstore.OutboxDispatchRequest) (eventstore.OutboxLease, error) {
	if err := s.faults.hit(dispatcherFaultBeforeMarker); err != nil {
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
	if err := s.faults.hit(dispatcherFaultAtMarker); err != nil {
		return eventstore.OutboxLease{}, err
	}
	return eventstore.OutboxLease{Effect: cloneDispatcherRecoveryEffect(row)}, nil
}

func (s *dispatcherRecoveryStore) RequeuePreDispatch(_ context.Context, req eventstore.OutboxPreDispatchRequeueRequest) (eventstore.CommitResult, error) {
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

func (s *dispatcherRecoveryStore) RenewOutbox(context.Context, eventstore.OutboxRenewRequest) (eventstore.OutboxLease, error) {
	return eventstore.OutboxLease{}, eventstore.ErrStaleLease
}
func (s *dispatcherRecoveryStore) UpdateOutbox(context.Context, eventstore.NewEffect) (eventstore.CommitResult, error) {
	return eventstore.CommitResult{}, eventstore.ErrInvalidTransition
}
func (s *dispatcherRecoveryStore) ResolveOutbox(context.Context, eventstore.OutboxResolutionRequest) (eventstore.CommitResult, error) {
	return eventstore.CommitResult{}, eventstore.ErrInvalidTransition
}

func (s *dispatcherRecoveryStore) CompleteOutbox(_ context.Context, req eventstore.OutboxCompletionRequest) (eventstore.CommitResult, error) {
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

func (s *dispatcherRecoveryStore) QuarantineOutbox(_ context.Context, req eventstore.OutboxQuarantineRequest) (eventstore.CommitResult, error) {
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

func (s *dispatcherRecoveryStore) Commit(_ context.Context, work eventstore.UnitOfWork) (eventstore.CommitResult, error) {
	terminal := ""
	for _, update := range work.Effects {
		if update.Status == eventstore.OutboxStatusSucceeded || update.Status == eventstore.OutboxStatusFailed || update.Status == eventstore.OutboxStatusAmbiguous {
			terminal = update.Status
		}
	}
	if terminal != "" {
		if err := s.faults.hit(dispatcherFaultTerminalPersist); err != nil {
			return eventstore.CommitResult{}, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(work.Effects) == 0 {
		return eventstore.CommitResult{}, eventstore.ErrEmptyUnitOfWork
	}
	update := work.Effects[0]
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
		for _, streamAppend := range work.Streams {
			s.appendStreamLocked(streamAppend.Stream, streamAppend.ExpectedVersion, streamAppend.Events)
		}
	}
	return eventstore.CommitResult{EffectIDs: []string{row.EffectID}, Version: row.Version}, nil
}

func (s *dispatcherRecoveryStore) appendTerminalLocked(row eventstore.NewEffect, status, code, providerID string) {
	stream := eventstore.StreamID{AggregateType: "outbound-effect", AggregateID: row.EffectID}
	eventID, _ := s.ids.NewID()
	payload, _ := json.Marshal(map[string]string{"effectId": row.EffectID, "operationId": s.operationIDLocked(row.EffectID), "status": status, "resultCode": code, "providerId": providerID})
	s.appendStreamLocked(stream, uint64(len(s.streams[stream])), []eventstore.NewEvent{{EventType: dispatcherEventTypeForStatus(status), SchemaVersion: 1, Payload: payload, Metadata: eventstore.Metadata{EventID: eventID, CommandID: eventID + "-command", CorrelationID: "dispatcher-recovery-correlation", OccurredAt: s.clock.Now()}}})
}
func (s *dispatcherRecoveryStore) appendStreamLocked(stream eventstore.StreamID, expected uint64, events []eventstore.NewEvent) {
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
func (s *dispatcherRecoveryStore) opsForEffectLocked(row eventstore.NewEffect, status, code string) {
	for id, op := range s.ops {
		if id == s.operationIDLocked(row.EffectID) {
			op.Status, op.Version, op.ResultCode = status, op.Version+1, code
			s.ops[id] = op
		}
	}
}
func (s *dispatcherRecoveryStore) operationIDLocked(effectID string) string {
	for id, op := range s.ops {
		if op.ResourceID == effectID {
			return id
		}
	}
	return ""
}

func (s *dispatcherRecoveryStore) Load(_ context.Context, stream eventstore.StreamID, _ uint64) ([]eventstore.Envelope, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]eventstore.Envelope(nil), s.streams[stream]...), nil
}
func (s *dispatcherRecoveryStore) GetOperation(_ context.Context, operationID string) (eventstore.OperationView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	op, ok := s.ops[operationID]
	if !ok {
		return eventstore.OperationView{}, eventstore.ErrNotFound
	}
	return op, nil
}

func cloneDispatcherRecoveryEffect(effect eventstore.NewEffect) eventstore.NewEffect {
	effect.PayloadCiphertext = append([]byte(nil), effect.PayloadCiphertext...)
	effect.PayloadNonce = append([]byte(nil), effect.PayloadNonce...)
	return effect
}

func dispatcherRecoveryRiskClass(retryClass adapterapi.EffectRetryClass) string {
	switch retryClass {
	case adapterapi.EffectRetryInvalid:
		return ""
	case adapterapi.EffectRetryPreDispatch:
		return eventstore.RiskPreDispatchRetryable
	case adapterapi.EffectRetryProviderIdempotent:
		return eventstore.RiskProviderIdempotent
	case adapterapi.EffectRetryNonIdempotent:
		return eventstore.RiskNonIdempotentAfterDispatch
	}
	return ""
}

func (s *dispatcherRecoveryStore) seed(t *testing.T, effect adapterapi.OutboundEffect) {
	t.Helper()
	plain, err := json.Marshal(effectWire{Effect: effect})
	if err != nil {
		t.Fatal(err)
	}
	laneHMAC, err := hex.DecodeString(effect.Lane.MAC)
	if err != nil {
		t.Fatal(err)
	}
	newEffect := eventstore.NewEffect{EffectID: string(effect.ID), EndpointID: string(effect.EndpointID), LaneHMAC: laneHMAC, EffectType: effectTypeForKind(effect.Kind), RiskClass: dispatcherRecoveryRiskClass(effect.RetryClass), DeadlineAt: effect.Deadline, PayloadCiphertext: []byte("ciphertext-recovery"), PayloadNonce: []byte("nonce-recovery"), PayloadEncryptionKeyID: "key-recovery"}
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

func (s *dispatcherRecoveryStore) row(id string) eventstore.NewEffect {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneDispatcherRecoveryEffect(s.effects[id])
}
func (s *dispatcherRecoveryStore) events(id string) []eventstore.Envelope {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]eventstore.Envelope(nil), s.streams[eventstore.StreamID{AggregateType: "outbound-effect", AggregateID: id}]...)
}

func dispatcherRecoveryEffect(t *testing.T, id, operation string, retry adapterapi.EffectRetryClass) adapterapi.OutboundEffect {
	target := adapterapi.EffectTarget{Kind: adapterapi.TargetPerson, Conversation: "person-dispatcher-recovery"}
	lane, err := adapterapi.NewLaneMetadata("endpoint-dispatcher-recovery", target, []byte("dispatcher-index-root"), 1)
	if err != nil {
		t.Fatal(err)
	}
	effect := adapterapi.OutboundEffect{Version: adapterapi.EffectVersionOne, ID: adapterapi.EffectID(id), EndpointID: "endpoint-dispatcher-recovery", OperationID: adapterapi.OperationID(operation), CorrelationID: "correlation-dispatcher-recovery", CausationID: "causation-dispatcher-recovery", Lane: lane, Deadline: time.Unix(5000, 0).UTC(), Risk: adapterapi.EffectRiskNormal, RetryClass: retry, RequiredCapabilities: adapterapi.CapabilityOutbound, RequiredAction: adapterapi.ActionKindSendMessage, Kind: adapterapi.EffectKindMessage, Payload: adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadPersonText, Target: target, Text: "do not retain this plaintext"}}
	if retry == adapterapi.EffectRetryProviderIdempotent {
		effect.Kind = adapterapi.EffectKindAction
		effect.RequiredCapabilities = adapterapi.CapabilityOutbound | adapterapi.CapabilityActions
		effect.RequiredAction = adapterapi.ActionKindGroupInfoRefresh
		effect.Payload = adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadGroupInfoRefresh, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "group-dispatcher-recovery"}}
		effect.Lane, err = adapterapi.NewLaneMetadata("endpoint-dispatcher-recovery", effect.Payload.Target, []byte("dispatcher-index-root"), 1)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := effect.Validate(); err != nil {
		t.Fatal(err)
	}
	return effect
}

func newRecoveryDispatcher(t *testing.T, store *dispatcherRecoveryStore, clock *dispatcherRecoveryClock, ids *dispatcherRecoveryIDs, provider *dispatcherRecoveryProvider, notifier *dispatcherRecoveryNotifier) *EffectDispatcher {
	t.Helper()
	dispatcher, err := NewEffectDispatcher(store, dispatcherRecoveryDecryptor{plain: store.plain}, provider, "dispatcher-recovery-worker", WithDispatcherClock(clock), WithDispatcherIDGenerator(ids), WithDispatcherRandom(func(time.Duration) time.Duration { return 0 }), WithEffectResultNotifier(notifier), WithEffectSuccessNotifier(notifier))
	if err != nil {
		t.Fatal(err)
	}
	return dispatcher
}

func waitDispatcherResult(t *testing.T, ch <-chan adapterapi.EffectResult, want adapterapi.EffectOutcome) adapterapi.EffectResult {
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

func assertDispatcherDurableState(t *testing.T, store *dispatcherRecoveryStore, effectID, operationID, status string, eventType string) {
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

func TestDispatcherAppendBeforeLeaseDispatchesOnce(t *testing.T) {
	clock := &dispatcherRecoveryClock{now: time.Unix(1000, 0).UTC()}
	ids, faults := &dispatcherRecoveryIDs{}, &dispatcherFaults{err: make(map[dispatcherFaultPoint]error), calls: make(map[dispatcherFaultPoint]int)}
	store := newDispatcherRecoveryStore(clock, ids, faults)
	effect := dispatcherRecoveryEffect(t, "append-effect", "append-operation", adapterapi.EffectRetryNonIdempotent)
	store.seed(t, effect)
	provider := &dispatcherRecoveryProvider{faults: faults, acceptedByKey: map[string]string{}}
	notifier := &dispatcherRecoveryNotifier{faults: faults, result: make(chan adapterapi.EffectResult, 2), success: make(chan adapterapi.EffectResult, 2)}
	d := newRecoveryDispatcher(t, store, clock, ids, provider, notifier)
	if _, err := d.DispatchOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertDispatcherDurableState(t, store, string(effect.ID), string(effect.OperationID), eventstore.OutboxStatusSucceeded, "OutboundEffectSucceededV1")
	waitDispatcherResult(t, notifier.result, adapterapi.EffectSucceeded)
	waitDispatcherResult(t, notifier.success, adapterapi.EffectSucceeded)
	invocations, acceptances, results, _ := provider.snapshot()
	if invocations != 1 || acceptances != 1 || results != 1 {
		t.Fatalf("provider counts invocation=%d acceptance=%d results=%d, want 1/1/1", invocations, acceptances, results)
	}
	if faults.count(dispatcherFaultLease) != 1 || faults.count(dispatcherFaultNotifySchedule) != 2 {
		t.Fatalf("fault boundary counts lease=%d notify=%d", faults.count(dispatcherFaultLease), faults.count(dispatcherFaultNotifySchedule))
	}
}

func TestDispatcherRecoveryLeasedBeforeDispatch(t *testing.T) {
	clock := &dispatcherRecoveryClock{now: time.Unix(1000, 0).UTC()}
	ids, faults := &dispatcherRecoveryIDs{}, &dispatcherFaults{err: make(map[dispatcherFaultPoint]error), calls: make(map[dispatcherFaultPoint]int)}
	store := newDispatcherRecoveryStore(clock, ids, faults)
	effect := dispatcherRecoveryEffect(t, "leased-effect", "leased-operation", adapterapi.EffectRetryNonIdempotent)
	store.seed(t, effect)
	claimed, err := store.ClaimOutbox(context.Background(), eventstore.OutboxClaimRequest{WorkerID: "crashed-worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if claimed.Effect.Status != eventstore.OutboxStatusLeased {
		t.Fatalf("pre-crash row = %#v", claimed.Effect)
	}
	clock.advance(2 * time.Minute)
	provider := &dispatcherRecoveryProvider{faults: faults, acceptedByKey: map[string]string{}}
	notifier := &dispatcherRecoveryNotifier{faults: faults, result: make(chan adapterapi.EffectResult, 1), success: make(chan adapterapi.EffectResult, 1)}
	d := newRecoveryDispatcher(t, store, clock, ids, provider, notifier)
	if _, err := d.DispatchOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertDispatcherDurableState(t, store, string(effect.ID), string(effect.OperationID), eventstore.OutboxStatusSucceeded, "OutboundEffectSucceededV1")
	invocations, acceptances, _, _ := provider.snapshot()
	if invocations != 1 || acceptances != 1 {
		t.Fatalf("recovery provider counts invocation=%d acceptance=%d, want 1/1", invocations, acceptances)
	}
}

func TestDispatcherCrashNonIdempotentResponseLossIsolatesFailureAndAdvancesLane(t *testing.T) {
	clock := &dispatcherRecoveryClock{now: time.Unix(1000, 0).UTC()}
	ids, faults := &dispatcherRecoveryIDs{}, &dispatcherFaults{err: dispatcherFaultErrors(dispatcherFaultResponseLoss, errors.New("lost")), calls: make(map[dispatcherFaultPoint]int)}
	store := newDispatcherRecoveryStore(clock, ids, faults)
	effect := dispatcherRecoveryEffect(t, "response-loss-effect", "response-loss-operation", adapterapi.EffectRetryNonIdempotent)
	successor := dispatcherRecoveryEffect(t, "response-loss-successor", "response-loss-successor-operation", adapterapi.EffectRetryNonIdempotent)
	store.seed(t, effect)
	store.seed(t, successor)
	provider := &dispatcherRecoveryProvider{faults: faults, responseLoss: true, acceptedByKey: map[string]string{}}
	notifier := &dispatcherRecoveryNotifier{faults: faults, result: make(chan adapterapi.EffectResult, 2), success: make(chan adapterapi.EffectResult, 1)}
	d := newRecoveryDispatcher(t, store, clock, ids, provider, notifier)
	if _, err := d.DispatchOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertDispatcherDurableState(t, store, string(effect.ID), string(effect.OperationID), eventstore.OutboxStatusAmbiguous, "OutboundEffectAmbiguousV1")
	next, claimErr := store.ClaimOutbox(context.Background(), eventstore.OutboxClaimRequest{WorkerID: "restart-worker", LeaseDuration: time.Minute})
	if claimErr != nil || next.Effect.EffectID != string(successor.ID) {
		t.Fatalf("successor after isolated response loss = %#v, %v", next, claimErr)
	}
	invocations, acceptances, results, _ := provider.snapshot()
	if invocations != 1 || acceptances != 1 || results != 0 {
		t.Fatalf("lost-response provider counts invocation=%d acceptance=%d results=%d, want 1/1/0", invocations, acceptances, results)
	}
	waitDispatcherResult(t, notifier.result, adapterapi.EffectAmbiguous)
	select {
	case <-notifier.success:
		t.Fatal("ambiguous completion scheduled success notification")
	case <-time.After(30 * time.Millisecond):
	}
	if faults.count(dispatcherFaultResponseLoss) != 1 {
		t.Fatalf("response-loss fault count=%d, want one provider boundary hit", faults.count(dispatcherFaultResponseLoss))
	}
}

func TestDispatcherIdempotencyUsesEffectIDAcrossRetry(t *testing.T) {
	clock := &dispatcherRecoveryClock{now: time.Unix(1000, 0).UTC()}
	ids, faults := &dispatcherRecoveryIDs{}, &dispatcherFaults{err: make(map[dispatcherFaultPoint]error), calls: make(map[dispatcherFaultPoint]int)}
	store := newDispatcherRecoveryStore(clock, ids, faults)
	effect := dispatcherRecoveryEffect(t, "idempotent-effect", "idempotent-operation", adapterapi.EffectRetryProviderIdempotent)
	store.seed(t, effect)
	provider := &dispatcherRecoveryProvider{faults: faults, retryFirst: true, acceptedByKey: map[string]string{}}
	notifier := &dispatcherRecoveryNotifier{faults: faults, result: make(chan adapterapi.EffectResult, 1), success: make(chan adapterapi.EffectResult, 1)}
	first := newRecoveryDispatcher(t, store, clock, ids, provider, notifier)
	firstResult, err := first.DispatchOnce(context.Background())
	if err != nil || firstResult.Outcome != adapterapi.EffectRetryable {
		t.Fatalf("first idempotent result=%#v err=%v", firstResult, err)
	}
	if row := store.row(string(effect.ID)); row.Status != eventstore.OutboxStatusPending || len(store.events(string(effect.ID))) != 1 {
		t.Fatalf("retry checkpoint row=%#v events=%#v", row, store.events(string(effect.ID)))
	}
	clock.advance(time.Second)
	second := newRecoveryDispatcher(t, store, clock, ids, provider, notifier)
	if _, err := second.DispatchOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertDispatcherDurableState(t, store, string(effect.ID), string(effect.OperationID), eventstore.OutboxStatusSucceeded, "OutboundEffectSucceededV1")
	invocations, acceptances, results, keys := provider.snapshot()
	if invocations != 2 || acceptances != 1 || results != 1 {
		t.Fatalf("idempotent provider counts invocation=%d acceptance=%d results=%d, want 2/1/1", invocations, acceptances, results)
	}
	if len(keys) != 2 || keys[0] != string(effect.ID) || keys[1] != string(effect.ID) {
		t.Fatalf("provider idempotency keys=%v, want repeated effect ID", keys)
	}
	waitDispatcherResult(t, notifier.result, adapterapi.EffectSucceeded)
	waitDispatcherResult(t, notifier.success, adapterapi.EffectSucceeded)
}

func TestDispatcherCompletionReplayHasOneTerminalEventAndNotifications(t *testing.T) {
	clock := &dispatcherRecoveryClock{now: time.Unix(1000, 0).UTC()}
	ids, faults := &dispatcherRecoveryIDs{}, &dispatcherFaults{err: make(map[dispatcherFaultPoint]error), calls: make(map[dispatcherFaultPoint]int)}
	store := newDispatcherRecoveryStore(clock, ids, faults)
	effect := dispatcherRecoveryEffect(t, "replay-effect", "replay-operation", adapterapi.EffectRetryNonIdempotent)
	store.seed(t, effect)
	provider := &dispatcherRecoveryProvider{faults: faults, acceptedByKey: map[string]string{}}
	notifier := &dispatcherRecoveryNotifier{faults: faults, result: make(chan adapterapi.EffectResult, 2), success: make(chan adapterapi.EffectResult, 2)}
	d := newRecoveryDispatcher(t, store, clock, ids, provider, notifier)
	if _, err := d.DispatchOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitDispatcherResult(t, notifier.result, adapterapi.EffectSucceeded)
	waitDispatcherResult(t, notifier.success, adapterapi.EffectSucceeded)
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
	if faults.count(dispatcherFaultNotifySchedule) != 2 {
		t.Fatalf("notification scheduling count=%d, want two committed terminal schedules", faults.count(dispatcherFaultNotifySchedule))
	}
}

func TestDispatcherLeaseAcquisitionFaultDoesNotChangeDurableState(t *testing.T) {
	clock := &dispatcherRecoveryClock{now: time.Unix(1000, 0).UTC()}
	ids, faults := &dispatcherRecoveryIDs{}, &dispatcherFaults{err: dispatcherFaultErrors(dispatcherFaultLease, errors.New("lease fault")), calls: make(map[dispatcherFaultPoint]int)}
	store := newDispatcherRecoveryStore(clock, ids, faults)
	effect := dispatcherRecoveryEffect(t, "lease-fault-effect", "lease-fault-operation", adapterapi.EffectRetryNonIdempotent)
	store.seed(t, effect)
	provider := &dispatcherRecoveryProvider{faults: faults, acceptedByKey: map[string]string{}}
	d := newRecoveryDispatcher(t, store, clock, ids, provider, nil)
	if _, err := d.DispatchOnce(context.Background()); err == nil {
		t.Fatal("lease fault unexpectedly dispatched")
	}
	row := store.row(string(effect.ID))
	if row.Status != eventstore.OutboxStatusPending || row.Version != 1 || len(store.events(string(effect.ID))) != 1 {
		t.Fatalf("lease fault durable state = %#v events=%d", row, len(store.events(string(effect.ID))))
	}
	invocations, acceptances, _, _ := provider.snapshot()
	if invocations != 0 || acceptances != 0 || faults.count(dispatcherFaultLease) != 1 {
		t.Fatalf("lease fault counts invocation=%d acceptance=%d fault=%d", invocations, acceptances, faults.count(dispatcherFaultLease))
	}
}

func TestDispatcherCrashBeforeDispatchedMarkerQuarantinesWithoutProviderExecution(t *testing.T) {
	clock := &dispatcherRecoveryClock{now: time.Unix(1000, 0).UTC()}
	ids, faults := &dispatcherRecoveryIDs{}, &dispatcherFaults{err: dispatcherFaultErrors(dispatcherFaultBeforeMarker, errors.New("marker fault")), calls: make(map[dispatcherFaultPoint]int)}
	store := newDispatcherRecoveryStore(clock, ids, faults)
	effect := dispatcherRecoveryEffect(t, "marker-fault-effect", "marker-fault-operation", adapterapi.EffectRetryNonIdempotent)
	store.seed(t, effect)
	provider := &dispatcherRecoveryProvider{faults: faults, acceptedByKey: map[string]string{}}
	d := newRecoveryDispatcher(t, store, clock, ids, provider, nil)
	if _, err := d.DispatchOnce(context.Background()); err == nil {
		t.Fatal("marker fault unexpectedly dispatched")
	}
	assertDispatcherDurableState(t, store, string(effect.ID), string(effect.OperationID), eventstore.OutboxStatusFailed, "OutboundEffectFailedV1")
	invocations, acceptances, _, _ := provider.snapshot()
	if invocations != 0 || acceptances != 0 || faults.count(dispatcherFaultBeforeMarker) != 1 {
		t.Fatalf("marker fault counts invocation=%d acceptance=%d fault=%d", invocations, acceptances, faults.count(dispatcherFaultBeforeMarker))
	}
}

func TestDispatcherCrashAtDispatchedMarkerLeavesRecoveryBoundary(t *testing.T) {
	clock := &dispatcherRecoveryClock{now: time.Unix(1000, 0).UTC()}
	ids, faults := &dispatcherRecoveryIDs{}, &dispatcherFaults{err: dispatcherFaultErrors(dispatcherFaultAtMarker, errors.New("marker commit response lost")), calls: make(map[dispatcherFaultPoint]int)}
	store := newDispatcherRecoveryStore(clock, ids, faults)
	effect := dispatcherRecoveryEffect(t, "at-marker-effect", "at-marker-operation", adapterapi.EffectRetryNonIdempotent)
	successor := dispatcherRecoveryEffect(t, "at-marker-successor", "at-marker-successor-operation", adapterapi.EffectRetryNonIdempotent)
	store.seed(t, effect)
	store.seed(t, successor)
	provider := &dispatcherRecoveryProvider{faults: faults, acceptedByKey: map[string]string{}}
	d := newRecoveryDispatcher(t, store, clock, ids, provider, nil)
	if _, err := d.DispatchOnce(context.Background()); err == nil {
		t.Fatal("marker response loss unexpectedly dispatched")
	}
	row := store.row(string(effect.ID))
	if row.Status != eventstore.OutboxStatusDispatched || row.DispatchedAt.IsZero() || len(store.events(string(effect.ID))) != 1 {
		t.Fatalf("at-marker durable boundary = %#v events=%d", row, len(store.events(string(effect.ID))))
	}
	invocations, acceptances, _, _ := provider.snapshot()
	if invocations != 0 || acceptances != 0 || faults.count(dispatcherFaultAtMarker) != 1 {
		t.Fatalf("at-marker counts invocation=%d acceptance=%d fault=%d", invocations, acceptances, faults.count(dispatcherFaultAtMarker))
	}
	clock.advance(2 * time.Minute)
	next, claimErr := store.ClaimOutbox(context.Background(), eventstore.OutboxClaimRequest{WorkerID: "restart-worker", LeaseDuration: time.Minute})
	if claimErr != nil || next.Effect.EffectID != string(successor.ID) {
		t.Fatalf("successor after isolated expired marker = %#v, %v", next, claimErr)
	}
	row = store.row(string(effect.ID))
	if row.Status != eventstore.OutboxStatusAmbiguous || row.CompletedAt.IsZero() || len(row.PayloadCiphertext) != 0 || len(row.PayloadNonce) != 0 {
		t.Fatalf("expired marker row = %#v, want ambiguous scrubbed row", row)
	}
	if _, err := store.ClaimOutbox(context.Background(), eventstore.OutboxClaimRequest{WorkerID: "second-restart-worker", LeaseDuration: time.Minute}); !errors.Is(err, eventstore.ErrNotFound) {
		t.Fatalf("ambiguous effect was replayed or successor bypassed its active lease: %v", err)
	}
}

func TestDispatcherProviderAcceptanceFaultIsAmbiguousAfterDispatchMarker(t *testing.T) {
	clock := &dispatcherRecoveryClock{now: time.Unix(1000, 0).UTC()}
	ids, faults := &dispatcherRecoveryIDs{}, &dispatcherFaults{err: dispatcherFaultErrors(dispatcherFaultProviderAccept, errors.New("acceptance fault")), calls: make(map[dispatcherFaultPoint]int)}
	store := newDispatcherRecoveryStore(clock, ids, faults)
	effect := dispatcherRecoveryEffect(t, "acceptance-fault-effect", "acceptance-fault-operation", adapterapi.EffectRetryNonIdempotent)
	store.seed(t, effect)
	provider := &dispatcherRecoveryProvider{faults: faults, acceptedByKey: map[string]string{}}
	d := newRecoveryDispatcher(t, store, clock, ids, provider, nil)
	if _, err := d.DispatchOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertDispatcherDurableState(t, store, string(effect.ID), string(effect.OperationID), eventstore.OutboxStatusAmbiguous, "OutboundEffectAmbiguousV1")
	invocations, acceptances, results, _ := provider.snapshot()
	if invocations != 1 || acceptances != 0 || results != 0 || faults.count(dispatcherFaultProviderAccept) != 1 {
		t.Fatalf("acceptance fault counts invocation=%d acceptance=%d results=%d fault=%d", invocations, acceptances, results, faults.count(dispatcherFaultProviderAccept))
	}
}

func TestDispatcherCrashTerminalPersistenceAfterProviderAcceptanceIsAmbiguous(t *testing.T) {
	clock := &dispatcherRecoveryClock{now: time.Unix(1000, 0).UTC()}
	ids, faults := &dispatcherRecoveryIDs{}, &dispatcherFaults{err: dispatcherFaultErrors(dispatcherFaultTerminalPersist, errors.New("terminal persistence fault")), calls: make(map[dispatcherFaultPoint]int)}
	store := newDispatcherRecoveryStore(clock, ids, faults)
	effect := dispatcherRecoveryEffect(t, "terminal-fault-effect", "terminal-fault-operation", adapterapi.EffectRetryNonIdempotent)
	store.seed(t, effect)
	provider := &dispatcherRecoveryProvider{faults: faults, acceptedByKey: map[string]string{}}
	d := newRecoveryDispatcher(t, store, clock, ids, provider, nil)
	if _, err := d.DispatchOnce(context.Background()); err == nil {
		t.Fatal("terminal persistence fault unexpectedly succeeded")
	}
	assertDispatcherDurableState(t, store, string(effect.ID), string(effect.OperationID), eventstore.OutboxStatusAmbiguous, "OutboundEffectAmbiguousV1")
	invocations, acceptances, results, _ := provider.snapshot()
	if invocations != 1 || acceptances != 1 || results != 1 || faults.count(dispatcherFaultTerminalPersist) != 1 {
		t.Fatalf("terminal fault counts invocation=%d acceptance=%d results=%d fault=%d", invocations, acceptances, results, faults.count(dispatcherFaultTerminalPersist))
	}
}

func TestDispatcherNotificationSchedulingFaultIsBestEffort(t *testing.T) {
	clock := &dispatcherRecoveryClock{now: time.Unix(1000, 0).UTC()}
	ids, faults := &dispatcherRecoveryIDs{}, &dispatcherFaults{err: dispatcherFaultErrors(dispatcherFaultNotifySchedule, errors.New("notification scheduling fault")), calls: make(map[dispatcherFaultPoint]int)}
	store := newDispatcherRecoveryStore(clock, ids, faults)
	effect := dispatcherRecoveryEffect(t, "notification-fault-effect", "notification-fault-operation", adapterapi.EffectRetryNonIdempotent)
	store.seed(t, effect)
	provider := &dispatcherRecoveryProvider{faults: faults, acceptedByKey: map[string]string{}}
	notifier := &dispatcherRecoveryNotifier{faults: faults, result: make(chan adapterapi.EffectResult, 1), success: make(chan adapterapi.EffectResult, 1)}
	d := newRecoveryDispatcher(t, store, clock, ids, provider, notifier)
	if _, err := d.DispatchOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertDispatcherDurableState(t, store, string(effect.ID), string(effect.OperationID), eventstore.OutboxStatusSucceeded, "OutboundEffectSucceededV1")
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
	if got := faults.count(dispatcherFaultNotifySchedule); got != 2 {
		t.Fatalf("notification scheduling fault count=%d, want two attempted callbacks", got)
	}
}

var _ DispatcherStore = (*dispatcherRecoveryStore)(nil)
var _ EffectExecutor = (*dispatcherRecoveryProvider)(nil)
var _ DispatcherDecryptor = dispatcherRecoveryDecryptor{}
var _ EffectResultNotifier = (*dispatcherRecoveryNotifier)(nil)
var _ EffectSuccessNotifier = (*dispatcherRecoveryNotifier)(nil)

func (s *dispatcherRecoveryStore) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fmt.Sprintf("effects=%d streams=%d", len(s.effects), len(s.streams))
}
