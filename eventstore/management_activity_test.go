package eventstore

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestManagementActivityPersistenceNewestLimitAndStableTies(t *testing.T) {
	ctx := context.Background()
	dsn := filepath.Join(t.TempDir(), "management-activity.db")
	open := func() (*Database, *GORMStore) {
		t.Helper()
		database, err := OpenDatabase(ctx, DatabaseConfig{Type: "sqlite", DSN: dsn})
		if err != nil {
			t.Fatal(err)
		}
		return database, NewStore(database)
	}

	database, store := open()
	base := time.UnixMilli(1_791_124_568_000).UTC()
	items := []ManagementActivity{
		{ID: "tie-a", OccurredAt: base.Add(2 * time.Millisecond), Action: "settings-save", Label: "Save settings", Resource: "/sd-api/dice/config/set", Status: "succeeded", HTTPStatus: 200, Actor: "WebUI 管理员", SourceIP: "198.51.100.4"},
		{ID: "oldest", OccurredAt: base, Action: "settings-save", Label: "Save settings", Resource: "/sd-api/dice/config/set", Status: "failed", HTTPStatus: 400, Actor: "WebUI 管理员", SourceIP: "198.51.100.4"},
		{ID: "newest", OccurredAt: base.Add(time.Millisecond), Action: "settings-save", Label: "Save settings", Resource: "/sd-api/dice/config/set", Status: "accepted", HTTPStatus: 202, Actor: "WebUI 管理员", SourceIP: "2001:db8:1234:5678:90ab:cdef:1234:5678"},
		{ID: "tie-b", OccurredAt: base.Add(2 * time.Millisecond), Action: "settings-save", Label: "Save settings", Resource: "/sd-api/dice/config/set", Status: "succeeded", HTTPStatus: 200, Actor: "WebUI 管理员", SourceIP: "198.51.100.4"},
	}
	for _, item := range items {
		if err := store.AppendManagementActivity(ctx, item); err != nil {
			t.Fatalf("append activity %q: %v", item.ID, err)
		}
	}

	limited, err := store.RecentManagementActivities(ctx, 3)
	if err != nil {
		t.Fatal(err)
	}
	wantIDs := []string{"tie-b", "tie-a", "newest"}
	if len(limited) != len(wantIDs) {
		t.Fatalf("limited activity count=%d, want %d", len(limited), len(wantIDs))
	}
	for index, want := range wantIDs {
		if limited[index].ID != want {
			t.Fatalf("limited newest-first item[%d]=%q, want %q; got=%#v", index, limited[index].ID, want, limited)
		}
	}
	if err = database.Close(); err != nil {
		t.Fatal(err)
	}

	reopenedDatabase, reopenedStore := open()
	defer reopenedDatabase.Close()
	all, err := reopenedStore.RecentManagementActivities(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	wantIDs = []string{"tie-b", "tie-a", "newest", "oldest"}
	if len(all) != len(wantIDs) {
		t.Fatalf("reopened activity count=%d, want %d", len(all), len(wantIDs))
	}
	for index, want := range wantIDs {
		if all[index].ID != want {
			t.Fatalf("reopened activity item[%d]=%q, want %q; got=%#v", index, all[index].ID, want, all)
		}
	}
	if all[0].OccurredAt.UnixMilli() != base.Add(2*time.Millisecond).UnixMilli() || all[2].SourceIP != items[2].SourceIP {
		t.Fatalf("timestamp or full source IP changed across database reopen: %#v", all[2])
	}
}
