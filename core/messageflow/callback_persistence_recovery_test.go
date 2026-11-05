package messageflow

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"Scardice-core/core/execution"
	"Scardice-core/core/playerstate"
	"Scardice-core/eventstore"
)

func TestCallbackSQLiteMarkerAndTerminalCommit(t *testing.T) {
	ctx := context.Background()
	db, acceptErr := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "callback.db")})
	if acceptErr != nil {
		t.Fatal(acceptErr)
	}
	defer db.Close()
	store := eventstore.NewStore(db)
	inbox := eventstore.InboxUpdate{InboxID: "sqlite-inbox", EndpointID: "endpoint", ProviderEventKey: "provider", Lane: "lane", Status: eventstore.InboxStatusPending, Payload: []byte(`{"endpointId":"endpoint","generation":1,"desiredVersion":1,"message":{"kind":1,"conversationKind":2,"sender":"user","conversation":"group","platform":"test"},"contentDigest":"AQ==","status":"pending"}`), ContentDigest: []byte{1}}
	if _, err := store.AcceptInbox(ctx, inbox); err != nil {
		t.Fatal(err)
	}
	host := &callbackTestHost{}
	service, acceptErr := NewCallbackService(CallbackConfig{Inbox: store, Store: store, Resolver: callbackTestResolver{}, Host: host, WorkerID: "worker"})
	if acceptErr != nil {
		t.Fatal(acceptErr)
	}
	if _, err := service.ProcessOne(ctx); err != nil {
		t.Fatal(err)
	}
	if host.calls != 1 {
		t.Fatalf("host calls=%d", host.calls)
	}
	var terminal struct {
		Payload []byte
		Status  string
	}
	if err := db.GORM().Table("inbox_messages").Select("payload, status").Where("inbox_id = ?", inbox.InboxID).Take(&terminal).Error; err != nil {
		t.Fatal(err)
	}
	if terminal.Status != eventstore.InboxStatusConfirmedConsumed || len(terminal.Payload) == 0 {
		t.Fatalf("terminal callback payload missing: status=%q payload=%d bytes", terminal.Status, len(terminal.Payload))
	}
	if _, err := store.ClaimInbox(ctx, eventstore.InboxClaimRequest{WorkerID: "second-worker"}); !errors.Is(err, eventstore.ErrNotFound) {
		t.Fatalf("terminal inbox was claimable: %v", err)
	}
}
func TestCallbackSQLiteExpiredLeaseStillMarksAmbiguous(t *testing.T) {
	ctx := context.Background()
	clock := &callbackFixedClock{now: time.Unix(100, 0).UTC()}
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "callback-expired.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithClock(clock))
	inbox := callbackPendingTestInbox("sqlite-expired-inbox", "expired-provider", "expired-lane")
	if _, err := store.AcceptInbox(ctx, inbox); err != nil {
		t.Fatal(err)
	}
	host := &callbackTestHost{fn: func(context.Context, CallbackRequest, *playerstate.LocalOverlay, *execution.MutationCollector) (CallbackResult, error) {
		clock.now = clock.now.Add(2 * time.Minute)
		return CallbackResult{}, errors.New("callback failed after lease expiry")
	}}
	service, err := NewCallbackService(CallbackConfig{Inbox: store, Store: store, Resolver: callbackTestResolver{}, Host: host, WorkerID: "worker", LeaseDuration: time.Minute, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	if summary, err := service.ProcessOne(ctx); err == nil || summary.Status != eventstore.InboxStatusAmbiguous {
		t.Fatalf("expired callback summary=%+v err=%v", summary, err)
	}
	var row eventstoreInboxRowForTest
	if err := db.GORM().Table("inbox_messages").Where("inbox_id = ?", inbox.InboxID).Scan(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != eventstore.InboxStatusAmbiguous || string(row.Payload) == "" || host.calls != 1 {
		t.Fatalf("ambiguous callback row=%#v host calls=%d", row, host.calls)
	}
	if _, err := service.ProcessOne(ctx); !errors.Is(err, eventstore.ErrNotFound) {
		t.Fatalf("ambiguous callback rerun err=%v", err)
	}
	if host.calls != 1 {
		t.Fatalf("ambiguous callback host calls=%d", host.calls)
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
	store := eventstore.NewStore(db)
	inbox := callbackPendingTestInbox("sqlite-canceled-inbox", "canceled-provider", "canceled-lane")
	if _, err := store.AcceptInbox(context.Background(), inbox); err != nil {
		t.Fatal(err)
	}
	host := &callbackTestHost{fn: func(context.Context, CallbackRequest, *playerstate.LocalOverlay, *execution.MutationCollector) (CallbackResult, error) {
		cancel()
		return CallbackResult{}, errors.New("callback failed after context cancellation")
	}}
	service, err := NewCallbackService(CallbackConfig{Inbox: store, Store: store, Resolver: callbackTestResolver{}, Host: host, WorkerID: "worker"})
	if err != nil {
		t.Fatal(err)
	}
	if summary, err := service.ProcessOne(ctx); err == nil || summary.Status != eventstore.InboxStatusAmbiguous {
		t.Fatalf("canceled callback summary=%+v err=%v", summary, err)
	}
	var row eventstoreInboxRowForTest
	if err := db.GORM().Table("inbox_messages").Where("inbox_id = ?", inbox.InboxID).Scan(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != eventstore.InboxStatusAmbiguous || string(row.Payload) == "" || host.calls != 1 {
		t.Fatalf("canceled callback row=%#v host calls=%d", row, host.calls)
	}
	if _, err := service.ProcessOne(context.Background()); !errors.Is(err, eventstore.ErrNotFound) || host.calls != 1 {
		t.Fatalf("canceled callback reran: err=%v host calls=%d", err, host.calls)
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
	store := eventstore.NewStore(db)
	inbox := callbackPendingTestInbox("sqlite-commit-canceled-inbox", "commit-canceled-provider", "commit-canceled-lane")
	if _, err := store.AcceptInbox(context.Background(), inbox); err != nil {
		t.Fatal(err)
	}
	host := &callbackTestHost{fn: func(context.Context, CallbackRequest, *playerstate.LocalOverlay, *execution.MutationCollector) (CallbackResult, error) {
		cancel()
		return CallbackResult{}, nil
	}}
	service, err := NewCallbackService(CallbackConfig{Inbox: store, Store: store, Resolver: callbackTestResolver{}, Host: host, WorkerID: "worker"})
	if err != nil {
		t.Fatal(err)
	}
	if summary, err := service.ProcessOne(ctx); err == nil || summary.Status != eventstore.InboxStatusAmbiguous {
		t.Fatalf("commit cancellation summary=%+v err=%v", summary, err)
	}
	var row eventstoreInboxRowForTest
	if err := db.GORM().Table("inbox_messages").Where("inbox_id = ?", inbox.InboxID).Scan(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != eventstore.InboxStatusAmbiguous || string(row.Payload) == "" || host.calls != 1 {
		t.Fatalf("commit-canceled callback row=%#v host calls=%d", row, host.calls)
	}
	if _, err := service.ProcessOne(context.Background()); !errors.Is(err, eventstore.ErrNotFound) || host.calls != 1 {
		t.Fatalf("commit-canceled callback reran: err=%v host calls=%d", err, host.calls)
	}
}
