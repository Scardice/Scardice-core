package privacypurge

import (
    "context"
    "testing"

    "Scardice-core/eventstore"
)

type fakeHistoryStore struct { eventstore.PrivacyHistoryRepository }

func (fakeHistoryStore) PrivacyDryRun(context.Context, eventstore.PrivacyDryRunRequest) (eventstore.PrivacyDryRunResult, error) {
    return eventstore.PrivacyDryRunResult{Version: 1, Digest: []byte("digest"), Counts: eventstore.PrivacyCounts{GroupRecord: 1}}, nil
}

func TestDryRunReturnsKeyedSelection(t *testing.T) {
    svc := NewService(fakeHistoryStore{})
    result, err := svc.DryRun(context.Background(), Request{GroupID: "g", DiceIDs: []string{"d"}, Scopes: []string{"group_record"}})
    if err != nil { t.Fatal(err) }
    if result.Version != 1 || string(result.ConfirmationDigest) != "digest" || result.Counts.GroupRecord != 1 {
        t.Fatalf("result=%+v", result)
    }
}
