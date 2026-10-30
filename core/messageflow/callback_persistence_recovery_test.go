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
	"Scardice-core/endpoint"
	"Scardice-core/eventstore"
)

func TestCallbackSQLiteMarkerAndTerminalCommit(t *testing.T) {
	ctx := context.Background()
	db, acceptErr := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "callback.db")})
	if acceptErr != nil {
		t.Fatal(acceptErr)
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
	service, acceptErr := NewCallbackService(CallbackConfig{
		Inbox: store, Store: store, Codec: callbackTestBoundCodec{calls: &boundCalls, domain: &boundDomain, identity: &boundIdentity, owner: &boundOwner, version: &boundVersion},
		Resolver: callbackTestResolver{}, Group: groupstate.NewRepository(store), Player: playerstate.NewRepository(store), Host: host, WorkerID: "worker",
	})
	if acceptErr != nil {
		t.Fatal(acceptErr)
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

func TestCallbackSQLiteA6ProcessOneSuccessScrubsPayloadAndRetainsKeyMetadata(t *testing.T) {
	ctx := context.Background()
	const sourceID = "index-v1"
	source := defaultIntegrationKeySource()
	db, databaseErr := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "callback-a6.db")})
	if databaseErr != nil {
		t.Fatal(databaseErr)
	}
	defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithKeySource(source))
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "db-1", IndexRootID: sourceID,
		EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32),
		TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	inbound, databaseErr := NewInboundService(store, store)
	if databaseErr != nil {
		t.Fatal(databaseErr)
	}
	receipt, databaseErr := inbound.HandleInbound(ctx, endpoint.FencedInbound{
		EndpointID: "endpoint", Generation: 1, DesiredVersion: 1,
		Message: adapterapi.InboundMessage{
			ProviderEventID: "provider-a6", MessageID: "message-a6", Platform: "test",
			Sender: "sender-a6", Conversation: "group-a6", ConversationKind: adapterapi.ConversationKindGroup, Target: "group-a6",
			Kind: adapterapi.InboundKindMessage, Text: "hello-a6",
		},
	})
	if databaseErr != nil {
		t.Fatal(databaseErr)
	}
	if receipt.Outcome != adapterapi.IngressAccepted || receipt.InboxID == "" {
		t.Fatalf("ingress receipt=%#v", receipt)
	}
	host := &callbackTestHost{}
	service, databaseErr := NewCallbackService(CallbackConfig{
		Inbox: store, Store: store, BoundCodec: store, Resolver: callbackTestResolver{},
		Group: groupstate.NewRepository(store), Player: playerstate.NewRepository(store), Host: host, WorkerID: "worker-a6",
	})
	if databaseErr != nil {
		t.Fatal(databaseErr)
	}
	summary, databaseErr := service.ProcessOne(ctx)
	if databaseErr != nil {
		t.Fatal(databaseErr)
	}
	if summary.InboxID != receipt.InboxID || summary.Status != eventstore.InboxStatusConfirmedConsumed || host.calls != 1 {
		t.Fatalf("summary=%#v host calls=%d", summary, host.calls)
	}
	var row struct {
		Status             string
		PayloadCiphertext  []byte
		PayloadNonce       []byte
		EncryptionKeyID    string
		ContentDigestKeyID string
		PayloadVersion     uint64
	}
	if err := db.GORM().Table("inbox_messages").Where("inbox_id = ?", receipt.InboxID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != eventstore.InboxStatusConfirmedConsumed || len(row.PayloadCiphertext) != 0 || len(row.PayloadNonce) != 0 {
		t.Fatalf("terminal A6 payload was not scrubbed: %#v", row)
	}
	if row.EncryptionKeyID != "root-v1" || row.ContentDigestKeyID != sourceID || row.PayloadVersion != 1 {
		t.Fatalf("terminal A6 key metadata=%#v", row)
	}
	if _, err := store.ClaimInbox(ctx, eventstore.InboxClaimRequest{WorkerID: "second-worker"}); !errors.Is(err, eventstore.ErrNotFound) {
		t.Fatalf("terminal A6 inbox was claimable: %v", err)
	}
}
func TestCallbackBoundDecryptUsesPersistedPayloadVersion(t *testing.T) {
	inbox := newCallbackTestInbox()
	inbox.lease.Update.PayloadVersion = 7
	boundVersion := uint64(0)
	codec := callbackTestBoundCodec{version: &boundVersion}
	service, err := NewCallbackService(CallbackConfig{
		Inbox: inbox, Store: &callbackTestStore{}, Codec: codec, Resolver: callbackTestResolver{},
		Group: callbackTestGroupLoader{}, Player: callbackTestPlayerLoader{}, Host: &callbackTestHost{}, WorkerID: "worker",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	if boundVersion != 7 {
		t.Fatalf("bound decrypt version=%d", boundVersion)
	}
}

func TestCallbackSQLiteExpiredLeaseStillMarksAmbiguous(t *testing.T) {
	ctx := context.Background()
	clock := &callbackFixedClock{now: time.Unix(100, 0).UTC()}
	db, acceptErr := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "callback-expired.db")})
	if acceptErr != nil {
		t.Fatal(acceptErr)
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
	service, acceptErr := NewCallbackService(CallbackConfig{
		Inbox: store, Store: store, Codec: callbackTestCodec{}, AllowUnboundCodec: true, Resolver: callbackTestResolver{},
		Group: groupstate.NewRepository(store), Player: playerstate.NewRepository(store), Host: host, WorkerID: "worker",
		LeaseDuration: time.Minute, Clock: clock,
	})
	if acceptErr != nil {
		t.Fatal(acceptErr)
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

func TestCallbackSQLiteCommitExpiryIsolatesStartedAndAdvancesLane(t *testing.T) {
	var successorID string
	ctx := context.Background()
	clock := &callbackFixedClock{now: time.Now().UTC()}
	source := defaultIntegrationKeySource()
	db, databaseErr := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "callback-commit-expired.db")})
	if databaseErr != nil {
		t.Fatal(databaseErr)
	}
	defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithClock(clock), eventstore.WithKeySource(source))
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "db-1", IndexRootID: "index-v1",
		EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32),
		TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	inbound, databaseErr := NewInboundService(store, store, WithIngressClock(clock))
	if databaseErr != nil {
		t.Fatal(databaseErr)
	}
	firstReceipt, databaseErr := inbound.HandleInbound(ctx, endpoint.FencedInbound{
		EndpointID: "endpoint", Generation: 1, DesiredVersion: 1,
		Message: adapterapi.InboundMessage{
			ProviderEventID: "commit-expired-provider", MessageID: "commit-expired-message",
			Platform: "test", Sender: "sender", Conversation: "group", ConversationKind: adapterapi.ConversationKindGroup, Target: "group",
			Kind: adapterapi.InboundKindMessage, Text: "first",
		},
	})
	if databaseErr != nil {
		t.Fatal(databaseErr)
	}
	if firstReceipt.Outcome != adapterapi.IngressAccepted || firstReceipt.InboxID == "" {
		t.Fatalf("first ingress receipt=%#v", firstReceipt)
	}
	host := &callbackTestHost{}
	host.fn = func(hostCtx context.Context, _ CallbackRequest, _ *playerstate.LocalOverlay, _ *MutationCollector) (CallbackResult, error) {
		if host.calls == 1 {
			clock.now = clock.now.Add(IngressPayloadTTL + time.Minute)
			successorReceipt, ingressErr := inbound.HandleInbound(hostCtx, endpoint.FencedInbound{
				EndpointID: "endpoint", Generation: 1, DesiredVersion: 1,
				Message: adapterapi.InboundMessage{
					ProviderEventID: "commit-expired-successor", MessageID: "commit-expired-successor-message",
					Platform: "test", Sender: "sender", Conversation: "group", ConversationKind: adapterapi.ConversationKindGroup, Target: "group",
					Kind: adapterapi.InboundKindMessage, Text: "successor",
				},
			})
			if ingressErr != nil {
				return CallbackResult{}, ingressErr
			}
			successorID = successorReceipt.InboxID
			if successorID == "" {
				return CallbackResult{}, errors.New("successor inbox ID missing")
			}
		}
		return CallbackResult{}, nil
	}
	service, databaseErr := NewCallbackService(CallbackConfig{
		Inbox: store, Store: store, BoundCodec: store, Resolver: callbackTestResolver{},
		Group: groupstate.NewRepository(store), Player: playerstate.NewRepository(store),
		Host: host, WorkerID: "worker", LeaseDuration: time.Minute, Clock: clock,
	})
	if databaseErr != nil {
		t.Fatal(databaseErr)
	}
	_, processErr := service.ProcessOne(ctx)
	var firstRow eventstoreInboxRowForTest
	if err := db.GORM().Table("inbox_messages").Where("inbox_id = ?", firstReceipt.InboxID).Scan(&firstRow).Error; err != nil {
		t.Fatal(err)
	}
	if !errors.Is(processErr, eventstore.ErrPayloadExpired) {
		t.Fatalf("expired commit err=%v", processErr)
	}
	if errors.Is(processErr, eventstore.ErrStaleLease) {
		t.Fatalf("expired commit returned stale marker error: %v", processErr)
	}
	if firstRow.Status != eventstore.InboxStatusAmbiguous || len(firstRow.PayloadCiphertext) != 0 {
		t.Fatalf("expired callback-started row=%#v", firstRow)
	}
	var successorRow eventstoreInboxRowForTest
	if err := db.GORM().Table("inbox_messages").Where("inbox_id = ?", successorID).Scan(&successorRow).Error; err != nil {
		t.Fatal(err)
	}
	if successorRow.Status != eventstore.InboxStatusPending {
		t.Fatalf("successor row=%#v", successorRow)
	}
	next, err := service.ProcessOne(ctx)
	if err != nil || next.InboxID != successorID || next.Status != eventstore.InboxStatusConfirmedConsumed {
		t.Fatalf("successor after isolated callback = %#v, %v", next, err)
	}
	if _, err := service.ProcessOne(ctx); !errors.Is(err, eventstore.ErrNotFound) {
		t.Fatalf("isolated callback was retried: %v", err)
	}
	if host.calls != 2 {
		t.Fatalf("host calls=%d, want first attempt and successor only", host.calls)
	}
}
func TestCallbackSQLiteRecoversExpiredStartedAndClaimsSuccessor(t *testing.T) {
	ctx := context.Background()
	clock := &callbackFixedClock{now: time.Unix(100, 0).UTC()}
	db, acceptErr := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "callback-recovery.db")})
	if acceptErr != nil {
		t.Fatal(acceptErr)
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
	lease, acceptErr := store.ClaimInbox(ctx, eventstore.InboxClaimRequest{WorkerID: "crashed-worker", LeaseDuration: time.Minute})
	if acceptErr != nil {
		t.Fatal(acceptErr)
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
	service, acceptErr := NewCallbackService(CallbackConfig{
		Inbox: store, Store: store, Codec: callbackTestCodec{}, AllowUnboundCodec: true,
		Resolver: callbackTestResolver{}, Group: groupstate.NewRepository(store), Player: playerstate.NewRepository(store),
		Host: host, WorkerID: "recovery-worker", LeaseDuration: time.Minute, Clock: clock,
	})
	if acceptErr != nil {
		t.Fatal(acceptErr)
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
	db, acceptErr := eventstore.OpenDatabase(context.Background(), eventstore.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "callback-canceled.db")})
	if acceptErr != nil {
		t.Fatal(acceptErr)
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
	service, acceptErr := NewCallbackService(CallbackConfig{
		Inbox: store, Store: store, Codec: callbackTestCodec{}, AllowUnboundCodec: true,
		Resolver: callbackTestResolver{}, Group: groupstate.NewRepository(store), Player: playerstate.NewRepository(store),
		Host: host, WorkerID: "worker",
	})
	if acceptErr != nil {
		t.Fatal(acceptErr)
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
	db, acceptErr := eventstore.OpenDatabase(context.Background(), eventstore.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "callback-commit-canceled.db")})
	if acceptErr != nil {
		t.Fatal(acceptErr)
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
	service, acceptErr := NewCallbackService(CallbackConfig{
		Inbox: store, Store: store, Codec: callbackTestCodec{}, AllowUnboundCodec: true,
		Resolver: callbackTestResolver{}, Group: groupstate.NewRepository(store), Player: playerstate.NewRepository(store),
		Host: host, WorkerID: "worker",
	})
	if acceptErr != nil {
		t.Fatal(acceptErr)
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
