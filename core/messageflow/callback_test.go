package messageflow

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

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

func TestCallbackPayloadMetadataMismatchNoHost(t *testing.T) {
	tests := []struct {
		name    string
		payload string
	}{
		{
			name:    "endpoint",
			payload: `{"endpointId":"other-endpoint","generation":1,"desiredVersion":1,"message":{"kind":1,"sender":"user","conversation":"group","platform":"test"},"contentDigest":"AQ==","contentDigestKeyId":"digest","status":"pending"}`,
		},
		{
			name:    "digest",
			payload: `{"endpointId":"endpoint","generation":1,"desiredVersion":1,"message":{"kind":1,"sender":"user","conversation":"group","platform":"test"},"contentDigest":"Ag==","contentDigestKeyId":"digest","status":"pending"}`,
		},
		{
			name:    "digest key",
			payload: `{"endpointId":"endpoint","generation":1,"desiredVersion":1,"message":{"kind":1,"sender":"user","conversation":"group","platform":"test"},"contentDigest":"AQ==","contentDigestKeyId":"other-digest","status":"pending"}`,
		},
		{
			name:    "duplicate envelope field",
			payload: `{"endpointId":"endpoint","generation":1,"desiredVersion":1,"message":{"kind":1,"sender":"user","conversation":"group","platform":"test"},"contentDigest":"AQ==","contentDigestKeyId":"digest","status":"pending","status":"pending"}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inbox := newCallbackTestInbox()
			host := &callbackTestHost{inbox: inbox}
			service := newCallbackTestService(t, inbox, &callbackTestStore{}, host, callbackTestCodec{payload: []byte(test.payload)})
			if _, err := service.ProcessOne(context.Background()); !errors.Is(err, ErrCallbackPayload) {
				t.Fatalf("metadata mismatch err=%v", err)
			}
			if host.called {
				t.Fatal("metadata mismatch reached host")
			}
		})
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
	if err := collector.AddStream(eventstore.StreamID{AggregateType: "group", AggregateID: "escaped"}, 0, []eventstore.NewEvent{callbackEvent("group.changed", `{"nested":["\u0024t"]}`)}); !errors.Is(err, eventstore.ErrInvalidEvent) {
		t.Fatalf("escaped overlay event err=%v", err)
	}
	if err := NewMutationCollector(eventstore.EventFactory{}).AddStream(eventstore.StreamID{AggregateType: "group", AggregateID: "duplicate-key"}, 0, []eventstore.NewEvent{callbackEvent("group.changed", `{"value":"$t","value":"ok"}`)}); !errors.Is(err, eventstore.ErrInvalidEvent) {
		t.Fatalf("duplicate-key event err=%v", err)
	}
	if err := NewMutationCollector(eventstore.EventFactory{}).AddStream(eventstore.StreamID{AggregateType: "group", AggregateID: "trailing-value"}, 0, []eventstore.NewEvent{callbackEvent("group.changed", `{"value":"ok"} {"value":"later"}`)}); !errors.Is(err, eventstore.ErrInvalidEvent) {
		t.Fatalf("trailing event err=%v", err)
	}
	for _, field := range []string{"EventID", "CommandID", "CorrelationID", "CausationID", "PrincipalID", "Producer"} {
		event := callbackEvent("group.metadata", `{}`)
		switch field {
		case "EventID":
			event.Metadata.EventID = "$t-event"
		case "CommandID":
			event.Metadata.CommandID = "$t-command"
		case "CorrelationID":
			event.Metadata.CorrelationID = "$t-correlation"
		case "CausationID":
			event.Metadata.CausationID = "$t-causation"
		case "PrincipalID":
			event.Metadata.PrincipalID = "$t-principal"
		case "Producer":
			event.Metadata.Producer = "$t-producer"
		}
		if err := NewMutationCollector(eventstore.EventFactory{}).AddStream(eventstore.StreamID{AggregateType: "group", AggregateID: "metadata-" + field}, 0, []eventstore.NewEvent{event}); !errors.Is(err, eventstore.ErrInvalidEvent) {
			t.Fatalf("overlay metadata %s err=%v", field, err)
		}
	}
	opaqueCollector := NewMutationCollector(eventstore.EventFactory{})
	if err := opaqueCollector.AddPluginKV(eventstore.PluginKVUpdate{
		ExtensionID: "plugin", KeyHMAC: []byte("key"), KeyCiphertext: []byte("$t-ciphertext"),
		KeyNonce: []byte("nonce"), ValueCiphertext: []byte("$t-ciphertext"), ValueNonce: []byte("nonce"),
		EncryptionKeyID: "key", ValueSize: 2,
	}); err != nil {
		t.Fatalf("opaque ciphertext rejected: %v", err)
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
	return &callbackTestInbox{lease: eventstore.InboxLease{Update: eventstore.InboxUpdate{InboxID: "inbox-1", EndpointID: "endpoint", Status: eventstore.InboxStatusLeased, Version: 1, LeaseOwner: "worker", LeaseEpoch: 1, AttemptID: "attempt-1", PayloadCiphertext: []byte("payload"), PayloadNonce: []byte("nonce"), PayloadEncryptionKeyID: "key", ContentDigest: []byte{1}, ContentDigestKeyID: "digest"}}}
}
func newCallbackTestService(t *testing.T, inbox *callbackTestInbox, store *callbackTestStore, host *callbackTestHost, codec callbackTestCodec, options ...any) *CallbackService {
	t.Helper()
	config := CallbackConfig{Inbox: inbox, Store: store, Codec: codec, AllowUnboundCodec: true, Resolver: callbackTestResolver{}, Group: callbackTestGroupLoader{}, Player: callbackTestPlayerLoader{}, Host: host, WorkerID: "worker"}
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

type callbackTestBoundCodec struct {
	callbackTestCodec
	calls    *int
	domain   *string
	identity *string
	owner    *string
	version  *uint64
}

func (c callbackTestBoundCodec) DecryptBound(ctx context.Context, domain, identity, owner string, version uint64, ciphertext, nonce []byte, keyID string) ([]byte, error) {
	if c.calls != nil {
		*c.calls = *c.calls + 1
	}
	if c.domain != nil {
		*c.domain = domain
	}
	if c.identity != nil {
		*c.identity = identity
	}
	if c.owner != nil {
		*c.owner = owner
	}
	if c.version != nil {
		*c.version = version
	}
	return c.callbackTestCodec.Decrypt(ctx, ciphertext, nonce, keyID)
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
	inbox := eventstore.InboxUpdate{InboxID: "sqlite-inbox", EndpointID: "endpoint", ProviderEventKey: "provider", LaneHMAC: []byte("lane"), Status: eventstore.InboxStatusPending, PayloadCiphertext: []byte("payload"), PayloadNonce: []byte("nonce"), PayloadEncryptionKeyID: "key", ContentDigest: []byte{1}, ContentDigestKeyID: "digest"}
	if _, err := store.AcceptInbox(ctx, inbox); err != nil {
		t.Fatal(err)
	}
	host := &callbackTestHost{}
	boundCalls := 0
	boundDomain, boundIdentity, boundOwner := "", "", ""
	var boundVersion uint64
	service, err := NewCallbackService(CallbackConfig{
		Inbox: store, Store: store, Codec: callbackTestBoundCodec{calls: &boundCalls, domain: &boundDomain, identity: &boundIdentity, owner: &boundOwner, version: &boundVersion},
		Resolver: callbackTestResolver{}, Group: groupstate.NewRepository(store), Player: playerstate.NewRepository(store), Host: host, WorkerID: "worker",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ProcessOne(ctx); err != nil {
		t.Fatal(err)
	}
	if host.calls != 1 || boundCalls != 1 || boundDomain != "inbox/v1" || boundIdentity != inbox.InboxID || boundOwner != inbox.EndpointID || boundVersion != 1 {
		t.Fatalf("host calls=%d bound calls=%d domain=%q identity=%q owner=%q version=%d", host.calls, boundCalls, boundDomain, boundIdentity, boundOwner, boundVersion)
	}
	if _, err := store.ClaimInbox(ctx, eventstore.InboxClaimRequest{WorkerID: "second-worker"}); !errors.Is(err, eventstore.ErrNotFound) {
		t.Fatalf("terminal inbox was claimable: %v", err)
	}
}

type callbackFixedClock struct {
	now time.Time
}

func (c *callbackFixedClock) Now() time.Time { return c.now }

func TestCallbackSQLiteExpiredLeaseStillMarksAmbiguous(t *testing.T) {
	ctx := context.Background()
	clock := &callbackFixedClock{now: time.Unix(100, 0).UTC()}
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "callback-expired.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithClock(clock), eventstore.WithPayloadCodec(callbackTestCodec{}))
	inbox := eventstore.InboxUpdate{
		InboxID: "sqlite-expired-inbox", EndpointID: "endpoint", ProviderEventKey: "expired-provider",
		LaneHMAC: []byte("expired-lane"), Status: eventstore.InboxStatusPending,
		PayloadCiphertext: []byte("payload"), PayloadNonce: []byte("nonce"), PayloadEncryptionKeyID: "key",
		ContentDigest: []byte{1}, ContentDigestKeyID: "digest",
	}
	if _, err := store.AcceptInbox(ctx, inbox); err != nil {
		t.Fatal(err)
	}
	host := &callbackTestHost{fn: func(context.Context, CallbackRequest, *playerstate.LocalOverlay, *MutationCollector) (CallbackResult, error) {
		clock.now = clock.now.Add(2 * time.Minute)
		return CallbackResult{}, errors.New("callback failed after lease expiry")
	}}
	service, err := NewCallbackService(CallbackConfig{
		Inbox: store, Store: store, Codec: callbackTestCodec{}, AllowUnboundCodec: true, Resolver: callbackTestResolver{},
		Group: groupstate.NewRepository(store), Player: playerstate.NewRepository(store), Host: host, WorkerID: "worker",
		LeaseDuration: time.Minute, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ProcessOne(ctx); err == nil {
		t.Fatal("expired callback unexpectedly succeeded")
	}
	var row eventstoreInboxRowForTest
	if err := db.GORM().Table("inbox_messages").Where("inbox_id = ?", inbox.InboxID).Scan(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != eventstore.InboxStatusAmbiguous || len(row.PayloadCiphertext) != 0 || host.calls != 1 {
		t.Fatalf("expired callback row=%#v host calls=%d", row, host.calls)
	}
	if _, err := service.ProcessOne(ctx); !errors.Is(err, eventstore.ErrNotFound) {
		t.Fatalf("ambiguous callback rerun err=%v", err)
	}
	if host.calls != 1 {
		t.Fatalf("ambiguous callback host calls=%d", host.calls)
	}
}

func TestCallbackSQLiteRecoversExpiredStartedAndClaimsSuccessor(t *testing.T) {
	ctx := context.Background()
	clock := &callbackFixedClock{now: time.Unix(100, 0).UTC()}
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "callback-recovery.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithClock(clock), eventstore.WithPayloadCodec(callbackTestCodec{}))
	first := eventstore.InboxUpdate{
		InboxID: "sqlite-started-inbox", EndpointID: "endpoint", ProviderEventKey: "started-provider",
		LaneHMAC: []byte("started-lane"), Status: eventstore.InboxStatusPending,
		PayloadCiphertext: []byte("payload"), PayloadNonce: []byte("nonce"), PayloadEncryptionKeyID: "key",
		ContentDigest: []byte{1}, ContentDigestKeyID: "digest",
	}
	if _, err := store.AcceptInbox(ctx, first); err != nil {
		t.Fatal(err)
	}
	lease, err := store.ClaimInbox(ctx, eventstore.InboxClaimRequest{WorkerID: "crashed-worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateInbox(ctx, eventstore.InboxUpdate{
		InboxID: first.InboxID, ExpectedVersion: lease.Update.Version, Version: lease.Update.Version,
		Status: eventstore.InboxStatusCallbackStarted, LeaseOwner: lease.Update.LeaseOwner,
		LeaseEpoch: lease.Update.LeaseEpoch, AttemptID: lease.Update.AttemptID, LeaseExpiresAt: lease.Update.LeaseExpiresAt,
	}); err != nil {
		t.Fatal(err)
	}
	second := first
	second.InboxID = "sqlite-successor-inbox"
	second.ProviderEventKey = "successor-provider"
	second.LaneHMAC = []byte("successor-lane")
	if _, err := store.AcceptInbox(ctx, second); err != nil {
		t.Fatal(err)
	}
	clock.now = clock.now.Add(2 * time.Minute)
	host := &callbackTestHost{}
	service, err := NewCallbackService(CallbackConfig{
		Inbox: store, Store: store, Codec: callbackTestCodec{}, AllowUnboundCodec: true,
		Resolver: callbackTestResolver{}, Group: groupstate.NewRepository(store), Player: playerstate.NewRepository(store),
		Host: host, WorkerID: "recovery-worker", LeaseDuration: time.Minute, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ProcessOne(ctx); err != nil {
		t.Fatal(err)
	}
	var firstRow, secondRow eventstoreInboxRowForTest
	if err := db.GORM().Table("inbox_messages").Where("inbox_id = ?", first.InboxID).Scan(&firstRow).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Table("inbox_messages").Where("inbox_id = ?", second.InboxID).Scan(&secondRow).Error; err != nil {
		t.Fatal(err)
	}
	if firstRow.Status != eventstore.InboxStatusAmbiguous || len(firstRow.PayloadCiphertext) != 0 {
		t.Fatalf("expired callback-started row=%#v", firstRow)
	}
	if secondRow.Status != eventstore.InboxStatusConfirmedConsumed || host.calls != 1 {
		t.Fatalf("successor row=%#v host calls=%d", secondRow, host.calls)
	}
}
func TestCallbackSQLiteAmbiguityUsesIndependentContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db, err := eventstore.OpenDatabase(context.Background(), eventstore.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "callback-canceled.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithPayloadCodec(callbackTestCodec{}))
	inbox := eventstore.InboxUpdate{
		InboxID: "sqlite-canceled-inbox", EndpointID: "endpoint", ProviderEventKey: "canceled-provider",
		LaneHMAC: []byte("canceled-lane"), Status: eventstore.InboxStatusPending,
		PayloadCiphertext: []byte("payload"), PayloadNonce: []byte("nonce"), PayloadEncryptionKeyID: "key",
		ContentDigest: []byte{1}, ContentDigestKeyID: "digest",
	}
	if _, err := store.AcceptInbox(context.Background(), inbox); err != nil {
		t.Fatal(err)
	}
	host := &callbackTestHost{fn: func(context.Context, CallbackRequest, *playerstate.LocalOverlay, *MutationCollector) (CallbackResult, error) {
		cancel()
		return CallbackResult{}, errors.New("callback failed after context cancellation")
	}}
	service, err := NewCallbackService(CallbackConfig{
		Inbox: store, Store: store, Codec: callbackTestCodec{}, AllowUnboundCodec: true,
		Resolver: callbackTestResolver{}, Group: groupstate.NewRepository(store), Player: playerstate.NewRepository(store),
		Host: host, WorkerID: "worker",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ProcessOne(ctx); err == nil {
		t.Fatal("canceled callback unexpectedly succeeded")
	}
	var row eventstoreInboxRowForTest
	if err := db.GORM().Table("inbox_messages").Where("inbox_id = ?", inbox.InboxID).Scan(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != eventstore.InboxStatusAmbiguous || len(row.PayloadCiphertext) != 0 || host.calls != 1 {
		t.Fatalf("canceled callback row=%#v host calls=%d", row, host.calls)
	}
}
func TestCallbackSQLiteCommitCancellationUsesIndependentContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db, err := eventstore.OpenDatabase(context.Background(), eventstore.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "callback-commit-canceled.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithPayloadCodec(callbackTestCodec{}))
	inbox := eventstore.InboxUpdate{
		InboxID: "sqlite-commit-canceled-inbox", EndpointID: "endpoint", ProviderEventKey: "commit-canceled-provider",
		LaneHMAC: []byte("commit-canceled-lane"), Status: eventstore.InboxStatusPending,
		PayloadCiphertext: []byte("payload"), PayloadNonce: []byte("nonce"), PayloadEncryptionKeyID: "key",
		ContentDigest: []byte{1}, ContentDigestKeyID: "digest",
	}
	if _, err := store.AcceptInbox(context.Background(), inbox); err != nil {
		t.Fatal(err)
	}
	host := &callbackTestHost{fn: func(context.Context, CallbackRequest, *playerstate.LocalOverlay, *MutationCollector) (CallbackResult, error) {
		cancel()
		return CallbackResult{}, nil
	}}
	service, err := NewCallbackService(CallbackConfig{
		Inbox: store, Store: store, Codec: callbackTestCodec{}, AllowUnboundCodec: true,
		Resolver: callbackTestResolver{}, Group: groupstate.NewRepository(store), Player: playerstate.NewRepository(store),
		Host: host, WorkerID: "worker",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ProcessOne(ctx); err == nil {
		t.Fatal("commit cancellation unexpectedly succeeded")
	}
	var row eventstoreInboxRowForTest
	if err := db.GORM().Table("inbox_messages").Where("inbox_id = ?", inbox.InboxID).Scan(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != eventstore.InboxStatusAmbiguous || len(row.PayloadCiphertext) != 0 || host.calls != 1 {
		t.Fatalf("commit-canceled callback row=%#v host calls=%d", row, host.calls)
	}
}

type eventstoreInboxRowForTest struct {
	Status            string
	PayloadCiphertext []byte
}
