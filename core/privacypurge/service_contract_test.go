package privacypurge

import (
    "context"
    "errors"
    "testing"
    "Scardice-core/eventstore"
)

func TestDryRunRejectsActiveWithoutAllowActive(t *testing.T) {
    svc := NewService(fakeHistoryStore{})
    _, err := svc.DryRun(context.Background(), Request{GroupID: "g", DiceIDs: []string{"d"}, ActiveDiceIDs: []string{"d"}})
    if !errors.Is(err, eventstore.ErrInvalidTransition) { t.Fatalf("err=%v", err) }
}
func TestConfirmRejectsStaleDigestAndVersion(t *testing.T) {
    svc := NewService(fakeHistoryStore{})
    _, err := svc.Confirm(context.Background(), Request{GroupID: "g", DiceIDs: []string{"d"}, ConfirmationDigest: []byte("different"), ConfirmationVersion: 2})
    if !errors.Is(err, ErrConfirmationMismatch) { t.Fatalf("err=%v", err) }
}
