package eventsourcing

import (
	"context"
	"errors"
	"testing"
	"time"

	"Scardice-core/eventstore"
)

func TestStartupReadinessUsesCompletionRatherThanLegacyFilePresence(t *testing.T) {
	for _, tc := range []struct {
		name, mode        string
		legacy, populated bool
		want              error
	}{
		{"import with legacy", "import", true, true, nil},
		{"import without legacy", "import", false, true, nil},
		{"fresh empty", "fresh", false, false, nil},
		{"fresh current", "fresh", false, true, nil},
		{"legacy before first import", "fresh", true, false, ErrMigrationRequired},
		{"legacy and populated fresh conflict", "fresh", true, true, ErrLegacyStateConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := eventstore.Readiness{Mode: tc.mode, SchemaVersion: 2, DatabaseIdentity: "store"}
			if tc.mode == "import" {
				value.CompletedAt = time.Unix(1, 0).UTC()
			}
			repository := &readinessFake{value: value, hasState: tc.populated}
			_, err := ValidateStartupReadiness(context.Background(), repository, tc.legacy)
			if !errors.Is(err, tc.want) {
				t.Fatalf("startup=%v want=%v", err, tc.want)
			}
			if len(repository.sets) != 0 {
				t.Fatal("readiness gate mutated the store")
			}
		})
	}
}
