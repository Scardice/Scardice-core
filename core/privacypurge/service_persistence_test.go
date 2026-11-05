package privacypurge

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"Scardice-core/eventstore"
)

func openPrivacyServiceStore(t *testing.T) (*eventstore.GORMStore, *eventstore.Database) {
	t.Helper()
	db, err := eventstore.OpenDatabase(context.Background(), eventstore.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "privacy.db"), DatabaseIdentity: "privacy-service"})
	if err != nil {
		t.Fatal(err)
	}
	return eventstore.NewStore(db), db
}
func seedPrivacyServiceScope(t *testing.T, store *eventstore.GORMStore) {
	t.Helper()
	event := eventstore.NewEvent{EventType: "test", SchemaVersion: 1, Payload: []byte(`{"value":1}`), Metadata: eventstore.Metadata{EventID: "event", CommandID: "command", CorrelationID: "correlation", OccurredAt: time.Unix(1, 0).UTC()}}
	if _, err := store.Commit(context.Background(), eventstore.UnitOfWork{Streams: []eventstore.StreamAppend{{Stream: eventstore.StreamID{AggregateType: "group", AggregateID: "6:dice-a7:group-a"}, Events: []eventstore.NewEvent{event}}}}); err != nil {
		t.Fatal(err)
	}
}
func TestPrivacyServiceConfirmsOneAtomicDeleteThenInvalidatesCache(t *testing.T) {
	ctx := context.Background()
	store, db := openPrivacyServiceStore(t)
	defer db.Close()
	seedPrivacyServiceScope(t, store)
	invalidated := false
	service := NewService(store, WithGroupCacheInvalidator(func(ctx context.Context, group string) error {
		if group != "group-a" {
			t.Fatalf("group=%s", group)
		}
		events, err := store.Load(ctx, eventstore.StreamID{AggregateType: "group", AggregateID: "6:dice-a7:group-a"}, 0)
		if err != nil || len(events) != 0 {
			t.Fatalf("cache invalidated before commit: %d %v", len(events), err)
		}
		invalidated = true
		return nil
	}))
	req := Request{GroupID: "group-a", DiceIDs: []string{"dice-a"}, Scopes: []string{"group_record", "group_record"}, AllowActive: true}
	dry, err := service.DryRun(ctx, req)
	if err != nil || dry.Completed || dry.Counts.GroupRecord != 1 {
		t.Fatalf("dry run=%+v err=%v", dry, err)
	}
	req.ConfirmationDigest, req.ConfirmationVersion = dry.ConfirmationDigest, dry.ConfirmationVersion
	result, err := service.Confirm(ctx, req)
	if !errors.Is(err, ErrUncoveredData) || !result.Completed || result.Status != "completed-uncovered" || result.Deleted.GroupRecord != 1 || !invalidated {
		t.Fatalf("confirm=%+v err=%v invalidated=%t", result, err, invalidated)
	}
	var operations int64
	if err := db.GORM().Table("operations").Count(&operations).Error; err != nil || operations != 0 {
		t.Fatalf("privacy created resumable operation rows=%d err=%v", operations, err)
	}
	if _, err := service.Confirm(ctx, req); !errors.Is(err, ErrConfirmationMismatch) {
		t.Fatalf("old confirmation accepted after deletion: %v", err)
	}
}
func TestPrivacyServiceDryRunAndStaleConfirmationNeverMutate(t *testing.T) {
	ctx := context.Background()
	store, db := openPrivacyServiceStore(t)
	defer db.Close()
	seedPrivacyServiceScope(t, store)
	service := NewService(store)
	req := Request{GroupID: "group-a", DiceIDs: []string{"dice-a"}, DryRun: true}
	result, err := service.Confirm(ctx, req)
	if err != nil || result.Status != "dry-run" || result.Counts.GroupRecord != 1 {
		t.Fatalf("dry-run confirm=%+v err=%v", result, err)
	}
	req.DryRun = false
	req.ConfirmationDigest = []byte("stale")
	req.ConfirmationVersion = result.ConfirmationVersion
	rejected, err := service.Confirm(ctx, req)
	if !errors.Is(err, ErrConfirmationMismatch) || rejected.Completed || rejected.Deleted != (eventstore.PrivacyCounts{}) {
		t.Fatalf("rejected=%+v err=%v", rejected, err)
	}
	events, err := store.Load(ctx, eventstore.StreamID{AggregateType: "group", AggregateID: "6:dice-a7:group-a"}, 0)
	if err != nil || len(events) != 1 {
		t.Fatalf("stale confirmation deleted history: %d %v", len(events), err)
	}
}
func TestPrivacyServiceActiveGuardAndPostCommitInvalidationFailure(t *testing.T) {
	ctx := context.Background()
	store, db := openPrivacyServiceStore(t)
	defer db.Close()
	seedPrivacyServiceScope(t, store)
	invalidateErr := errors.New("cache unavailable")
	service := NewService(store, WithGroupCacheInvalidator(func(context.Context, string) error { return invalidateErr }))
	req := Request{GroupID: "group-a", DiceIDs: []string{"dice-a"}, ActiveDiceIDs: []string{"QQ:bot"}}
	if _, err := service.DryRun(ctx, req); !errors.Is(err, eventstore.ErrInvalidTransition) {
		t.Fatalf("active group allowed: %v", err)
	}
	req.AllowActive = true
	dry, err := service.DryRun(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	req.ConfirmationDigest, req.ConfirmationVersion = dry.ConfirmationDigest, dry.ConfirmationVersion
	result, err := service.Confirm(ctx, req)
	if !errors.Is(err, invalidateErr) || !result.Completed || result.Deleted.GroupRecord != 1 {
		t.Fatalf("post-commit failure misreported deletion: %+v %v", result, err)
	}
}
