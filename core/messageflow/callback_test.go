package messageflow

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"Scardice-core/adapterapi"
	"Scardice-core/core/groupstate"
	"Scardice-core/core/playerstate"

	"Scardice-core/eventstore"
)

func TestCallbackProcessOneClaimsAndMarksBeforeHost(t *testing.T) {
	inbox := newCallbackTestInbox()
	store := &callbackTestStore{}
	host := &callbackTestHost{inbox: inbox}
	service := newCallbackTestService(t, inbox, store, host, callbackTestCodec{})
	if _, err := service.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !host.called || !host.markerObserved {
		t.Fatalf("host called=%v marker=%v", host.called, host.markerObserved)
	}
	if len(store.commits) != 1 || store.commits[0].InboxUpdates[0].Status != eventstore.InboxStatusConfirmedConsumed {
		t.Fatalf("commits=%#v", store.commits)
	}
}

func TestCallbackLoadsBeforeMarkerAndHost(t *testing.T) {
	inbox := newCallbackTestInbox()
	store := &callbackTestStore{}
	host := &callbackTestHost{inbox: inbox}
	service := newCallbackTestService(t, inbox, store, host, callbackTestCodec{}, callbackTestGroupLoader{err: errors.New("load group")})
	if _, err := service.ProcessOne(context.Background()); err == nil {
		t.Fatal("load failure unexpectedly succeeded")
	}
	if host.called {
		t.Fatal("host called before load completed")
	}
	if len(inbox.updates) != 1 || inbox.updates[0].Status != eventstore.InboxStatusFailed {
		t.Fatalf("updates=%#v", inbox.updates)
	}
	if len(store.commits) != 0 {
		t.Fatal("load failure committed callback mutations")
	}
}

func TestCallbackMalformedPayloadNoHost(t *testing.T) {
	inbox := newCallbackTestInbox()
	store := &callbackTestStore{}
	host := &callbackTestHost{inbox: inbox}
	service := newCallbackTestService(t, inbox, store, host, callbackTestCodec{payload: []byte(`{"status":"pending","unknown":1}`)})
	if _, err := service.ProcessOne(context.Background()); !errors.Is(err, ErrCallbackPayload) {
		t.Fatalf("malformed err=%v", err)
	}
	if host.called || len(store.commits) != 0 {
		t.Fatal("malformed payload reached host or commit")
	}
	if len(inbox.updates) != 1 || inbox.updates[0].Status != eventstore.InboxStatusFailed {
		t.Fatalf("updates=%#v", inbox.updates)
	}
}

func TestCallbackPreMarkerConflictRetriesAtMostThree(t *testing.T) {
	inbox := newCallbackTestInbox()
	inbox.markerConflicts = CallbackMaxPreMarkerAttempts
	host := &callbackTestHost{inbox: inbox}
	store := &callbackTestStore{}
	service := newCallbackTestService(t, inbox, store, host, callbackTestCodec{})
	if _, err := service.ProcessOne(context.Background()); !errors.Is(err, eventstore.ErrConflict) {
		t.Fatalf("conflict err=%v", err)
	}
	if inbox.claims != CallbackMaxPreMarkerAttempts || host.called {
		t.Fatalf("claims=%d host=%v", inbox.claims, host.called)
	}
}

func TestCallbackHostPanicBecomesAmbiguousAndNeverReruns(t *testing.T) {
	inbox := newCallbackTestInbox()
	host := &callbackTestHost{inbox: inbox, panic: true}
	service := newCallbackTestService(t, inbox, &callbackTestStore{}, host, callbackTestCodec{})
	if _, err := service.ProcessOne(context.Background()); err == nil {
		t.Fatal("panic unexpectedly succeeded")
	}
	if len(inbox.updates) != 2 || inbox.updates[0].Status != eventstore.InboxStatusCallbackStarted || inbox.updates[1].Status != eventstore.InboxStatusAmbiguous {
		t.Fatalf("updates=%#v", inbox.updates)
	}
	if _, err := service.ProcessOne(context.Background()); !errors.Is(err, eventstore.ErrNotFound) {
		t.Fatalf("ambiguous rerun err=%v", err)
	}
	if host.calls != 1 {
		t.Fatalf("host calls=%d", host.calls)
	}
}

func TestCallbackAtomicMultiStreamPluginEffectAndWorkflow(t *testing.T) {
	inbox := newCallbackTestInbox()
	store := &callbackTestStore{}
	host := &callbackTestHost{inbox: inbox, fn: func(_ context.Context, _ CallbackRequest, overlay *playerstate.LocalOverlay, collector *MutationCollector) (CallbackResult, error) {
		overlay.Set("$t临时", "local")
		if err := collector.AddStream(eventstore.StreamID{AggregateType: "player", AggregateID: "player-1"}, 2, []eventstore.NewEvent{callbackEvent("player.changed", `{"name":"new"}`)}); err != nil {
			return CallbackResult{}, err
		}
		if err := collector.AddPluginKV(eventstore.PluginKVUpdate{ExtensionID: "plugin", KeyHMAC: []byte("hmac"), KeyCiphertext: []byte("encrypted-key"), KeyNonce: []byte("nonce"), ValueCiphertext: []byte("encrypted-value"), ValueNonce: []byte("nonce"), EncryptionKeyID: "key", ValueSize: 2}); err != nil {
			return CallbackResult{}, err
		}
		if err := collector.AddEffect(eventstore.NewEffect{EffectID: "effect-1", EndpointID: "endpoint", LaneHMAC: []byte("lane"), EffectType: "send", RiskClass: eventstore.RiskPreDispatchRetryable, Status: eventstore.OutboxStatusPending, PayloadCiphertext: []byte("encrypted-effect"), PayloadNonce: []byte("nonce"), PayloadEncryptionKeyID: "key"}); err != nil {
			return CallbackResult{}, err
		}
		return CallbackResult{Workflow: &WorkflowResult{ID: "workflow-1", Event: callbackEvent(MessageWorkflowTerminatedEventType, `{"done":true}`)}}, nil
	}}
	service := newCallbackTestService(t, inbox, store, host, callbackTestCodec{})
	result, err := service.ProcessOne(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.WorkflowID != "workflow-1" || len(store.commits) != 1 {
		t.Fatalf("result=%#v commits=%d", result, len(store.commits))
	}
	work := store.commits[0]
	if len(work.Streams) != 2 || len(work.PluginKVUpdates) != 1 || len(work.Effects) != 1 || len(work.InboxUpdates) != 1 {
		t.Fatalf("work=%#v", work)
	}
	if work.InboxUpdates[0].WorkflowID != "workflow-1" || work.InboxUpdates[0].Status != eventstore.InboxStatusConfirmedConsumed {
		t.Fatalf("terminal=%#v", work.InboxUpdates[0])
	}
}

func TestCallbackOrdinaryCallbackHasNoWorkflow(t *testing.T) {
	inbox := newCallbackTestInbox()
	store := &callbackTestStore{}
	service := newCallbackTestService(t, inbox, store, &callbackTestHost{inbox: inbox}, callbackTestCodec{})
	if _, err := service.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	work := store.commits[0]
	if len(work.Streams) != 0 || work.InboxUpdates[0].WorkflowID != "" {
		t.Fatalf("ordinary workflow mutation=%#v", work)
	}
}

func TestCallbackInvalidWorkflowIsAmbiguous(t *testing.T) {
	inbox := newCallbackTestInbox()
	host := &callbackTestHost{inbox: inbox, fn: func(context.Context, CallbackRequest, *playerstate.LocalOverlay, *MutationCollector) (CallbackResult, error) {
		return CallbackResult{Workflow: &WorkflowResult{ID: "bad/id", Event: callbackEvent(MessageWorkflowTerminatedEventType, `{}`)}}, nil
	}}
	service := newCallbackTestService(t, inbox, &callbackTestStore{}, host, callbackTestCodec{})
	if _, err := service.ProcessOne(context.Background()); !errors.Is(err, ErrCallbackWorkflow) {
		t.Fatalf("workflow err=%v", err)
	}
	if inbox.updates[len(inbox.updates)-1].Status != eventstore.InboxStatusAmbiguous {
		t.Fatalf("updates=%#v", inbox.updates)
	}
}

func TestCallbackCollectorRejectsOverlayAndDuplicateStreams(t *testing.T) {
	collector := NewMutationCollector(eventstore.EventFactory{})
	stream := eventstore.StreamID{AggregateType: "group", AggregateID: "group-1"}
	if err := collector.AddStream(stream, 0, []eventstore.NewEvent{callbackEvent("group.changed", `{"value":"$t"}`)}); !errors.Is(err, eventstore.ErrInvalidEvent) {
		t.Fatalf("overlay event err=%v", err)
	}
	if err := collector.AddStream(stream, 0, []eventstore.NewEvent{callbackEvent("group.changed", `{}`)}); err != nil {
		t.Fatal(err)
	}
	if err := collector.AddStream(stream, 0, []eventstore.NewEvent{callbackEvent("group.changed", `{}`)}); !errors.Is(err, eventstore.ErrDuplicateStream) {
		t.Fatalf("duplicate stream err=%v", err)
	}
	if err := collector.AddStream(eventstore.StreamID{AggregateType: MessageWorkflowAggregateType, AggregateID: "workflow"}, 0, []eventstore.NewEvent{callbackEvent(MessageWorkflowTerminatedEventType, `{}`)}); err == nil {
		t.Fatal("ordinary collector accepted workflow stream")
	}
}

func callbackEvent(eventType, payload string) eventstore.NewEvent {
	return eventstore.NewEvent{EventType: eventType, SchemaVersion: 1, Payload: []byte(payload), Metadata: eventstore.Metadata{EventID: eventType + "-event", CommandID: eventType + "-command", CorrelationID: eventType + "-correlation", OccurredAtUnixNanoUTC: 1, OccurredAtUnixNanoSet: true}}
}

func newCallbackTestInbox() *callbackTestInbox {
	return &callbackTestInbox{lease: eventstore.InboxLease{Update: eventstore.InboxUpdate{InboxID: "inbox-1", EndpointID: "endpoint", Status: eventstore.InboxStatusLeased, Version: 1, LeaseOwner: "worker", LeaseEpoch: 1, AttemptID: "attempt-1", PayloadCiphertext: []byte("payload"), PayloadNonce: []byte("nonce"), PayloadEncryptionKeyID: "key"}}}
}
func newCallbackTestService(t *testing.T, inbox *callbackTestInbox, store *callbackTestStore, host *callbackTestHost, codec callbackTestCodec, options ...any) *CallbackService {
	t.Helper()
	config := CallbackConfig{Inbox: inbox, Store: store, Codec: codec, Resolver: callbackTestResolver{}, Group: callbackTestGroupLoader{}, Player: callbackTestPlayerLoader{}, Host: host, WorkerID: "worker"}
	for _, option := range options {
		switch value := option.(type) {
		case callbackTestGroupLoader:
			config.Group = value
		case callbackTestPlayerLoader:
			config.Player = value
		}
	}
	service, err := NewCallbackService(config)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

type callbackTestInbox struct {
	lease           eventstore.InboxLease
	updates         []eventstore.InboxUpdate
	claims          int
	markerConflicts int
}

func (f *callbackTestInbox) AcceptInbox(context.Context, eventstore.InboxUpdate) (eventstore.CommitResult, error) {
	return eventstore.CommitResult{}, nil
}
func (f *callbackTestInbox) ClaimInbox(context.Context, eventstore.InboxClaimRequest) (eventstore.InboxLease, error) {
	f.claims++
	if f.lease.Update.Status != eventstore.InboxStatusLeased {
		return eventstore.InboxLease{}, eventstore.ErrNotFound
	}
	return f.lease, nil
}
func (f *callbackTestInbox) UpdateInbox(_ context.Context, update eventstore.InboxUpdate) (eventstore.CommitResult, error) {
	if update.Status == eventstore.InboxStatusCallbackStarted && f.markerConflicts > 0 {
		f.markerConflicts--
		return eventstore.CommitResult{}, eventstore.ErrConflict
	}
	f.updates = append(f.updates, update)
	f.lease.Update.Status = update.Status
	f.lease.Update.Version++
	return eventstore.CommitResult{Version: f.lease.Update.Version}, nil
}
func (f *callbackTestInbox) ResolveInbox(context.Context, eventstore.InboxResolutionRequest) (eventstore.CommitResult, error) {
	return eventstore.CommitResult{}, nil
}

type callbackTestStore struct {
	commits   []eventstore.UnitOfWork
	commitErr error
}

func (f *callbackTestStore) Commit(_ context.Context, work eventstore.UnitOfWork) (eventstore.CommitResult, error) {
	if f.commitErr != nil {
		return eventstore.CommitResult{}, f.commitErr
	}
	f.commits = append(f.commits, work)
	return eventstore.CommitResult{}, nil
}
func (*callbackTestStore) Load(context.Context, eventstore.StreamID, uint64) ([]eventstore.Envelope, error) {
	return nil, nil
}
func (*callbackTestStore) Close() error { return nil }

type callbackTestCodec struct {
	payload []byte
	err     error
}

func (callbackTestCodec) Encrypt(context.Context, []byte) ([]byte, []byte, string, error) {
	return nil, nil, "", nil
}
func (c callbackTestCodec) Decrypt(context.Context, []byte, []byte, string) ([]byte, error) {
	if c.err != nil {
		return nil, c.err
	}
	if len(c.payload) != 0 {
		return c.payload, nil
	}
	return []byte(`{"endpointId":"endpoint","generation":1,"desiredVersion":1,"message":{"kind":1,"sender":"user","conversation":"group","platform":"test"},"contentDigest":"AQ==","contentDigestKeyId":"digest","status":"pending"}`), nil
}

type callbackTestResolver struct{}

func (callbackTestResolver) Resolve(context.Context, string, adapterapi.InboundMessage) (CallbackScope, error) {
	return CallbackScope{DiceID: "dice", GroupID: "group", UserID: "user"}, nil
}

type callbackTestGroupLoader struct{ err error }

func (f callbackTestGroupLoader) Load(context.Context, string, string) (groupstate.State, error) {
	return groupstate.State{}, f.err
}

type callbackTestPlayerLoader struct{ err error }

func (f callbackTestPlayerLoader) LoadPlayer(context.Context, string, string, string) (playerstate.PlayerState, error) {
	return playerstate.PlayerState{}, f.err
}
func (f callbackTestPlayerLoader) LoadGroupUserAttrs(context.Context, string, string, string) (playerstate.GroupUserAttrsState, error) {
	return playerstate.GroupUserAttrsState{}, f.err
}

type callbackTestHost struct {
	inbox          *callbackTestInbox
	called         bool
	markerObserved bool
	panic          bool
	calls          int
	fn             func(context.Context, CallbackRequest, *playerstate.LocalOverlay, *MutationCollector) (CallbackResult, error)
}

func (h *callbackTestHost) HandleCallback(ctx context.Context, request CallbackRequest, overlay *playerstate.LocalOverlay, collector *MutationCollector) (CallbackResult, error) {
	h.called = true
	h.calls++
	if h.inbox != nil {
		for _, update := range h.inbox.updates {
			if update.Status == eventstore.InboxStatusCallbackStarted {
				h.markerObserved = true
			}
		}
	}
	if h.panic {
		panic("host panic")
	}
	if h.fn != nil {
		return h.fn(ctx, request, overlay, collector)
	}
	return CallbackResult{}, nil
}
func TestCallbackCommitFailureBecomesAmbiguousWithoutHostRetry(t *testing.T) {
	inbox := newCallbackTestInbox()
	store := &callbackTestStore{commitErr: eventstore.ErrParticipantFailure}
	host := &callbackTestHost{inbox: inbox}
	service := newCallbackTestService(t, inbox, store, host, callbackTestCodec{})
	if _, err := service.ProcessOne(context.Background()); !errors.Is(err, eventstore.ErrParticipantFailure) {
		t.Fatalf("commit err=%v", err)
	}
	if host.calls != 1 || len(inbox.updates) != 2 || inbox.updates[1].Status != eventstore.InboxStatusAmbiguous {
		t.Fatalf("host calls=%d updates=%#v", host.calls, inbox.updates)
	}
}
func TestCallbackSQLiteMarkerAndTerminalCommit(t *testing.T) {
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "callback.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithPayloadCodec(callbackTestCodec{}))
	inbox := eventstore.InboxUpdate{InboxID: "sqlite-inbox", EndpointID: "endpoint", ProviderEventKey: "provider", LaneHMAC: []byte("lane"), Status: eventstore.InboxStatusPending, PayloadCiphertext: []byte("payload"), PayloadNonce: []byte("nonce"), PayloadEncryptionKeyID: "key", ContentDigest: []byte("digest"), ContentDigestKeyID: "digest-key"}
	if _, err := store.AcceptInbox(ctx, inbox); err != nil {
		t.Fatal(err)
	}
	host := &callbackTestHost{}
	service, err := NewCallbackService(CallbackConfig{
		Inbox: store, Store: store, Codec: callbackTestCodec{}, Resolver: callbackTestResolver{},
		Group: groupstate.NewRepository(store), Player: playerstate.NewRepository(store), Host: host, WorkerID: "worker",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ProcessOne(ctx); err != nil {
		t.Fatal(err)
	}
	if host.calls != 1 {
		t.Fatalf("host calls=%d", host.calls)
	}
	if _, err := store.ClaimInbox(ctx, eventstore.InboxClaimRequest{WorkerID: "second-worker"}); !errors.Is(err, eventstore.ErrNotFound) {
		t.Fatalf("terminal inbox was claimable: %v", err)
	}
}
