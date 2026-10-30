package messageflow

import (
	"context"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/groupstate"
	"Scardice-core/core/playerstate"
	"Scardice-core/eventstore"
)

type integrationKeySource struct {
	indexID string
	index   []byte
	rootID  string
	root    []byte
}

func (s integrationKeySource) IndexRootID(context.Context) (string, error) { return s.indexID, nil }
func (s integrationKeySource) IndexRootMaterial(context.Context) ([]byte, error) {
	return append([]byte(nil), s.index...), nil
}
func (s integrationKeySource) CurrentEncryptionRoot(context.Context) (eventstore.EncryptionRoot, error) {
	return eventstore.EncryptionRoot{ID: s.rootID, Material: append([]byte(nil), s.root...)}, nil
}
func (s integrationKeySource) EncryptionRoot(_ context.Context, id string) ([]byte, error) {
	if id != s.rootID {
		return nil, eventstore.ErrKeyUnavailable
	}
	return append([]byte(nil), s.root...), nil
}

func defaultIntegrationKeySource() integrationKeySource {
	return integrationKeySource{
		indexID: "index-v1",
		index:   []byte("01234567890123456789012345678901"),
		rootID:  "root-v1",
		root:    []byte("abcdefghijklmnopqrstuvwxyz123456"),
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
	renewals        int
	renewed         chan struct{}
	renewErr        error
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
func (f *callbackTestInbox) RenewInbox(_ context.Context, request eventstore.InboxRenewRequest) (eventstore.InboxLease, error) {
	f.renewals++
	if f.renewErr != nil {
		return eventstore.InboxLease{}, f.renewErr
	}
	f.lease.Update.Version++
	f.lease.Update.LeaseExpiresAt = time.Now().UTC().Add(request.LeaseDuration)
	if f.renewed != nil {
		select {
		case f.renewed <- struct{}{}:
		default:
		}
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
	onCommit  func()
}

func (f *callbackTestStore) Commit(_ context.Context, work eventstore.UnitOfWork) (eventstore.CommitResult, error) {
	if f.onCommit != nil {
		f.onCommit()
	}
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

type callbackTestFence struct {
	locked      bool
	lockCalls   int
	unlockCalls int
}

func (f *callbackTestFence) TryLock() bool {
	if f.locked {
		return false
	}
	f.locked = true
	f.lockCalls++
	return true
}

func (f *callbackTestFence) Unlock() {
	f.locked = false
	f.unlockCalls++
}

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
	return []byte(`{"endpointId":"endpoint","generation":1,"desiredVersion":1,"message":{"kind":1,"conversationKind":2,"sender":"user","conversation":"group","platform":"test"},"contentDigest":"AQ==","contentDigestKeyId":"digest","status":"pending"}`), nil
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
		*c.calls++
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
	return c.Decrypt(ctx, ciphertext, nonce, keyID)
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

type callbackFixedClock struct {
	now time.Time
}

func (c *callbackFixedClock) Now() time.Time { return c.now }

type eventstoreInboxRowForTest struct {
	Status            string
	PayloadCiphertext []byte
}
