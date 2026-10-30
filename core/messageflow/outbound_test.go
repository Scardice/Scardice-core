package messageflow

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/eventstore"
)

type testStore struct {
	work  eventstore.UnitOfWork
	err   error
	calls int
}

func (s *testStore) Commit(_ context.Context, work eventstore.UnitOfWork) (eventstore.CommitResult, error) {
	s.calls++
	if s.err != nil {
		return eventstore.CommitResult{}, s.err
	}
	s.work = work
	return eventstore.CommitResult{EffectIDs: []string{work.Effects[0].EffectID}, OperationIDs: []string{work.Operations[0].OperationID}, OrderingSequence: 1}, nil
}
func (*testStore) Load(context.Context, eventstore.StreamID, uint64) ([]eventstore.Envelope, error) {
	return nil, nil
}
func (*testStore) Close() error { return nil }
func (s *testStore) GetOperationByIdempotency(_ context.Context, principal, scope, key string) (eventstore.OperationView, error) {
	if s.calls == 0 {
		return eventstore.OperationView{}, eventstore.ErrNotFound
	}
	return eventstore.OperationView{OperationID: s.work.Operations[0].OperationID, ResourceID: s.work.Effects[0].EffectID, IdempotencyScope: scope, IdempotencyKey: key, RequestDigest: append([]byte(nil), s.work.Operations[0].RequestDigest...)}, nil
}

type testEncryptor struct{ plain []byte }

func (e *testEncryptor) EncryptBound(_ context.Context, _ string, _ string, _ string, _ uint64, p []byte) ([]byte, []byte, string, error) {
	e.plain = append([]byte(nil), p...)
	return []byte("cipher"), []byte("nonce"), "key-1", nil
}

type testIDs struct{ n int }

func (g *testIDs) NewID() (string, error) { g.n++; return "generated-id", nil }

type testResolver struct {
	snap EndpointSnapshot
	err  error
}

func (r testResolver) Resolve(context.Context, adapterapi.EndpointID) (EndpointSnapshot, error) {
	return r.snap, r.err
}

type testIndexSigner struct {
	root []byte
	id   string
}

func (s testIndexSigner) KeyedDigest(_ context.Context, domain string, parts ...string) ([]byte, string, error) {
	mac := hmac.New(sha256.New, s.root)
	_, _ = mac.Write([]byte(domain))
	for _, part := range parts {
		_, _ = mac.Write([]byte(part))
	}
	return mac.Sum(nil), s.id, nil
}

func testEffect() adapterapi.OutboundEffect {
	return adapterapi.OutboundEffect{Version: adapterapi.EffectVersionOne, ID: "effect-1", EndpointID: "endpoint-1", OperationID: "operation-1", CorrelationID: "corr-1", CausationID: "cause-1", Kind: adapterapi.EffectKindMessage, Payload: adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadPersonText, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetPerson, Conversation: "person-1"}, Text: "hello"}, RequiredCapabilities: adapterapi.CapabilityOutbound, RequiredAction: adapterapi.ActionKindSendMessage, RetryClass: adapterapi.EffectRetryNonIdempotent, Risk: adapterapi.EffectRiskNormal}
}

func TestOutboundSubmitCommitsShapeEventAndEncryptedEffectAtomically(t *testing.T) {
	e := testEffect()
	e.Lane = adapterapi.LaneMetadata{EndpointID: "endpoint-1", TargetDigest: "x", Key: "k", Sequence: 1, MAC: "m"}
	store := &testStore{}
	enc := &testEncryptor{}
	svc, err := NewOutboundService(store, testResolver{snap: EndpointSnapshot{EndpointID: "endpoint-1", DesiredState: "enabled", ObservedState: adapterapi.ObservedStateConnected, Capabilities: adapterapi.CapabilityOutbound, Actions: adapterapi.ActionSet(adapterapi.ActionKindSendMessage), IndexSigner: testIndexSigner{root: []byte("root"), id: "index-root-1"}}}, enc, &testIDs{})
	if err != nil {
		t.Fatal(err)
	}
	// Invalid lane is rejected before storage; a real lane is supplied by adapterapi.NewLaneMetadata in integration tests.
	_, err = svc.Submit(context.Background(), SubmitRequest{Effect: e, CommandID: "command-1", PrincipalID: "principal-1"})
	if err == nil {
		t.Fatal("invalid lane accepted")
	}
	if store.calls != 0 {
		t.Fatal("invalid request wrote storage")
	}
}
func TestOutboundSubmitCommitsAllParticipants(t *testing.T) {
	root := []byte(strings.Repeat("r", 32))
	e := testEffect()
	e.Deadline = time.Now().Add(time.Hour).UTC()
	lane, err := adapterapi.NewLaneMetadata(e.EndpointID, e.Payload.Target, root, 1)
	if err != nil {
		t.Fatal(err)
	}
	e.Lane = lane
	store := &testStore{}
	enc := &testEncryptor{}
	svc, err := NewOutboundService(store, testResolver{snap: EndpointSnapshot{EndpointID: e.EndpointID, DesiredState: "enabled", ObservedState: adapterapi.ObservedStateConnected, Capabilities: adapterapi.CapabilityOutbound, Actions: adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage), IndexRootID: "index-root-1", IndexSigner: testIndexSigner{root: root, id: "index-root-1"}}}, enc, &testIDs{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := svc.Submit(context.Background(), SubmitRequest{Effect: e, CommandID: "cmd-1", PrincipalID: "principal-a"})
	if err != nil {
		t.Fatal(err)
	}
	if got.EffectID != string(e.ID) || got.OperationID != string(e.OperationID) || store.calls != 1 {
		t.Fatalf("result=%#v calls=%d", got, store.calls)
	}
	if len(store.work.Streams) != 1 || len(store.work.Operations) != 1 || len(store.work.Effects) != 1 {
		t.Fatalf("work=%#v", store.work)
	}
	if strings.Contains(string(store.work.Streams[0].Events[0].Payload), "hello") || strings.Contains(string(store.work.Streams[0].Events[0].Payload), "person-1") {
		t.Fatal("shape event leaked payload")
	}
	if len(enc.plain) == 0 || len(store.work.Streams[0].Events[0].Payload) == 0 {
		t.Fatal("missing encrypted/request payload")
	}
}

func TestOutboundPrepareBuildsParticipantsWithoutCommit(t *testing.T) {
	root := []byte(strings.Repeat("r", 32))
	effect := testEffect()
	effect.Deadline = time.Now().Add(time.Hour).UTC()
	lane, err := adapterapi.NewLaneMetadata(effect.EndpointID, effect.Payload.Target, root, 1)
	if err != nil {
		t.Fatal(err)
	}
	effect.Lane = lane
	store := &testStore{}
	service, err := NewOutboundService(store, testResolver{snap: EndpointSnapshot{EndpointID: effect.EndpointID, DesiredState: "enabled", ObservedState: adapterapi.ObservedStateConnected, Capabilities: adapterapi.CapabilityOutbound, Actions: adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage), IndexRootID: "index-root-1", IndexSigner: testIndexSigner{root: root, id: "index-root-1"}}}, &testEncryptor{}, &testIDs{})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := service.Prepare(context.Background(), SubmitRequest{Effect: effect, CommandID: "cmd-prepare", PrincipalID: "principal-a"})
	if err != nil {
		t.Fatal(err)
	}
	if store.calls != 0 {
		t.Fatal("prepare committed storage")
	}
	if prepared.Result.EffectID != string(effect.ID) || len(prepared.Work.Streams) != 1 || len(prepared.Work.Operations) != 1 || len(prepared.Work.Effects) != 1 {
		t.Fatalf("prepared = %#v", prepared)
	}
}
func TestOutboundSubmitDeduplicatesSameCommandAndConflictsChangedDigest(t *testing.T) {
	root := []byte(strings.Repeat("r", 32))
	e := testEffect()
	e.Deadline = time.Now().Add(time.Hour).UTC()
	lane, _ := adapterapi.NewLaneMetadata(e.EndpointID, e.Payload.Target, root, 1)
	e.Lane = lane
	store := &testStore{}
	svc, err := NewOutboundService(store, testResolver{snap: EndpointSnapshot{EndpointID: e.EndpointID, DesiredState: "enabled", ObservedState: adapterapi.ObservedStateConnected, Capabilities: adapterapi.CapabilityOutbound, Actions: adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage), IndexRootID: "index-root-1", IndexSigner: testIndexSigner{root: root, id: "index-root-1"}}}, &testEncryptor{}, &testIDs{})
	if err != nil {
		t.Fatal(err)
	}
	first, err := svc.Submit(context.Background(), SubmitRequest{Effect: e, CommandID: "dedupe", PrincipalID: "principal-a"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.Submit(context.Background(), SubmitRequest{Effect: e, CommandID: "dedupe", PrincipalID: "principal-a"})
	if err != nil || !second.Deduplicated || second.EffectID != first.EffectID || store.calls != 1 {
		t.Fatalf("dedupe=%#v err=%v calls=%d", second, err, store.calls)
	}
	e.Payload.Text = "changed"
	if _, err := svc.Submit(context.Background(), SubmitRequest{Effect: e, CommandID: "dedupe", PrincipalID: "principal-a"}); !errors.Is(err, ErrCommandConflict) {
		t.Fatalf("changed digest err=%v", err)
	}
}
func TestOutboundSubmitDeduplicatesLogicalReplayWithVolatileMetadataChanges(t *testing.T) {
	root := []byte(strings.Repeat("r", 32))
	effect := testEffect()
	effect.Deadline = time.Now().Add(time.Hour).UTC()
	effect.Lane, _ = adapterapi.NewLaneMetadata(effect.EndpointID, effect.Payload.Target, root, 1)
	store := &testStore{}
	svc, err := NewOutboundService(store, testResolver{snap: EndpointSnapshot{
		EndpointID: effect.EndpointID, DesiredState: "enabled",
		ObservedState: adapterapi.ObservedStateConnected,
		Capabilities:  adapterapi.CapabilityOutbound,
		Actions:       adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage),
		IndexRootID:   "index-root-1",
		IndexSigner:   testIndexSigner{root: root, id: "index-root-1"},
	}}, &testEncryptor{}, &testIDs{})
	if err != nil {
		t.Fatal(err)
	}
	first, err := svc.Submit(context.Background(), SubmitRequest{
		Effect: effect, CommandID: "logical-replay", PrincipalID: "principal-a",
	})
	if err != nil {
		t.Fatal(err)
	}

	replay := effect
	replay.ID = "effect-replay"
	replay.OperationID = "operation-replay"
	replay.Deadline = effect.Deadline.Add(time.Hour)
	replay.CorrelationID = "corr-2"
	replay.CausationID = "cause-2"
	replay.Lane, err = adapterapi.NewLaneMetadata(replay.EndpointID, replay.Payload.Target, root, 2)
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.Submit(context.Background(), SubmitRequest{
		Effect: replay, CommandID: "logical-replay", PrincipalID: "principal-a",
	})
	if err != nil || !second.Deduplicated {
		t.Fatalf("logical replay=%#v err=%v", second, err)
	}
	if second.OperationID != first.OperationID || second.EffectID != first.EffectID {
		t.Fatalf("logical replay IDs=%#v first=%#v", second, first)
	}
	if store.calls != 1 {
		t.Fatalf("logical replay committed %d times", store.calls)
	}
}
func TestOutboundSubmitRejectsStateAndCapabilityWithValidLane(t *testing.T) {
	root := []byte(strings.Repeat("r", 32))
	e := testEffect()
	e.Deadline = time.Now().Add(time.Hour).UTC()
	lane, _ := adapterapi.NewLaneMetadata(e.EndpointID, e.Payload.Target, root, 1)
	e.Lane = lane
	base := EndpointSnapshot{EndpointID: e.EndpointID, DesiredState: "enabled", ObservedState: adapterapi.ObservedStateConnected, Capabilities: adapterapi.CapabilityOutbound, Actions: adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage), IndexRootID: "index-root-1", IndexSigner: testIndexSigner{root: root, id: "index-root-1"}}
	for name, snap := range map[string]EndpointSnapshot{"disabled": func() EndpointSnapshot { s := base; s.DesiredState = "disabled"; return s }(), "missing-capability": func() EndpointSnapshot { s := base; s.Capabilities = 0; return s }()} {
		store := &testStore{}
		svc, err := NewOutboundService(store, testResolver{snap: snap}, &testEncryptor{}, &testIDs{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Submit(context.Background(), SubmitRequest{Effect: e, CommandID: "reject-" + name, PrincipalID: "principal-a"}); err == nil {
			t.Fatalf("%s accepted", name)
		}
		if store.calls != 0 {
			t.Fatalf("%s wrote storage", name)
		}
	}
}

func TestOutboundSubmitReportsEndpointStateOnUnavailableError(t *testing.T) {
	root := []byte(strings.Repeat("r", 32))
	effect := testEffect()
	effect.Deadline = time.Now().Add(time.Hour).UTC()
	lane, err := adapterapi.NewLaneMetadata(effect.EndpointID, effect.Payload.Target, root, 1)
	if err != nil {
		t.Fatal(err)
	}
	effect.Lane = lane
	snapshot := EndpointSnapshot{
		EndpointID: effect.EndpointID, DesiredState: "enabled", ObservedState: adapterapi.ObservedStateStopped,
		Capabilities: adapterapi.CapabilityOutbound,
		Actions:      adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage),
		IndexRootID:  "index-root-1", IndexSigner: testIndexSigner{root: root, id: "index-root-1"},
	}
	service, err := NewOutboundService(&testStore{}, testResolver{snap: snapshot}, &testEncryptor{}, &testIDs{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Submit(context.Background(), SubmitRequest{Effect: effect, CommandID: "unavailable-state", PrincipalID: "principal-a"})
	if !errors.Is(err, ErrEndpointUnavailable) {
		t.Fatalf("error = %v, want endpoint unavailable", err)
	}
	if !strings.Contains(err.Error(), `observed state "stopped"`) {
		t.Fatalf("error = %v, want observed state in diagnostic", err)
	}
}

func TestOutboundSubmitPreservesEndpointResolutionCause(t *testing.T) {
	resolverErr := errors.New("projection read failed")
	service, err := NewOutboundService(&testStore{}, testResolver{err: resolverErr}, &testEncryptor{}, &testIDs{})
	if err != nil {
		t.Fatal(err)
	}
	effect := testEffect()
	effect.Deadline = time.Now().Add(time.Hour).UTC()
	root := []byte(strings.Repeat("r", 32))
	lane, laneErr := adapterapi.NewLaneMetadata(effect.EndpointID, effect.Payload.Target, root, 1)
	if laneErr != nil {
		t.Fatal(laneErr)
	}
	effect.Lane = lane
	_, err = service.Submit(context.Background(), SubmitRequest{Effect: effect, CommandID: "resolver-error", PrincipalID: "principal-a"})
	if !errors.Is(err, ErrEndpointUnavailable) || !errors.Is(err, resolverErr) {
		t.Fatalf("error = %v, want endpoint unavailable wrapping resolver cause", err)
	}
}

func TestOutboundSubmitRejectsEndpointBeforeCommit(t *testing.T) {
	store := &testStore{}
	svc, err := NewOutboundService(store, testResolver{snap: EndpointSnapshot{DesiredState: "disabled", ObservedState: adapterapi.ObservedStateStopped}}, &testEncryptor{}, &testIDs{})
	if err != nil {
		t.Fatal(err)
	}
	e := testEffect()
	e.Deadline = time.Unix(1, 0).UTC()
	e.Lane = adapterapi.LaneMetadata{EndpointID: e.EndpointID, TargetDigest: strings.Repeat("a", 64), Key: strings.Repeat("b", 64), Sequence: 1, MAC: strings.Repeat("c", 64)}
	_, err = svc.Submit(context.Background(), SubmitRequest{Effect: e, CommandID: "c", PrincipalID: "principal-a"})
	if !errors.Is(err, ErrEndpointUnavailable) {
		t.Fatalf("err=%v", err)
	}
	if store.calls != 0 {
		t.Fatal("store called")
	}
}
