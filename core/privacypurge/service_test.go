package privacypurge

import (
	"context"
	"errors"
	"testing"

	"Scardice-core/eventstore"
)

type fakeHistoryStore struct {
	eventstore.PrivacyHistoryRepository
}

func (fakeHistoryStore) PrivacyDryRun(context.Context, eventstore.PrivacyDryRunRequest) (eventstore.PrivacyDryRunResult, error) {
	return eventstore.PrivacyDryRunResult{Version: 1, Digest: []byte("digest"), Counts: eventstore.PrivacyCounts{GroupRecord: 1}}, nil
}

func TestDryRunReturnsKeyedSelection(t *testing.T) {
	svc := NewService(fakeHistoryStore{})
	result, err := svc.DryRun(context.Background(), Request{GroupID: "g", DiceIDs: []string{"d"}, Scopes: []string{"group_record"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Version != 1 || string(result.ConfirmationDigest) != "digest" || result.Counts.GroupRecord != 1 {
		t.Fatalf("result=%+v", result)
	}
}

func TestCanonicalScopesKeepsLogsExplicitAndOrdered(t *testing.T) {
	defaultScopes, err := canonicalScopes(nil)
	if err != nil || len(defaultScopes) != 1 || defaultScopes[0] != "group_record" {
		t.Fatalf("default scopes=%v err=%v", defaultScopes, err)
	}
	scopes, err := canonicalScopes([]string{"logs", "attrs", "players", "group_record", "logs"})
	if err != nil {
		t.Fatalf("canonicalScopes(logs): %v", err)
	}
	want := []string{"group_record", "players", "attrs", "logs"}
	if len(scopes) != len(want) {
		t.Fatalf("canonical scopes=%v want=%v", scopes, want)
	}
	for i := range want {
		if scopes[i] != want[i] {
			t.Fatalf("canonical scopes=%v want=%v", scopes, want)
		}
	}
	if _, err := canonicalScopes([]string{"all"}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("unknown scope error=%v want %v", err, ErrInvalidRequest)
	}
}
