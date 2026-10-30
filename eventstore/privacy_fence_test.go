package eventstore

import (
	"context"
	"errors"
	"testing"
)

func TestPrivacyFenceBlocksMatchingStreamAppend(t *testing.T) {
	store, db, _ := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	subject, err := store.privacyHMAC(ctx, "privacy-subject/v1", "g")
	if err != nil {
		t.Fatal(err)
	}
	createErr := store.PrivacyCreateOperation(ctx, "privacy-fence-op", subject, PrivacyOperationContext{GroupID: "g", DiceIDs: []string{"d"}, Scopes: []string{"group_record"}, Phase: "fence"})
	if createErr != nil {
		t.Fatal(createErr)
	}
	_, fenceErr := store.PrivacyFence(ctx, subject, "group", "privacy-fence-op")
	if fenceErr != nil {
		t.Fatal(fenceErr)
	}
	stream := StreamID{AggregateType: "group", AggregateID: privacyCanonical("d", "g")}
	_, err = store.Commit(ctx, UnitOfWork{Streams: []StreamAppend{{Stream: stream, Events: []NewEvent{privacyEvent("fenced")}}}})
	if !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("append err=%v", err)
	}
}

func TestPrivacyFenceBlocksInboundSubjectAdmission(t *testing.T) {
	store, db, _ := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	subject, err := store.privacyHMAC(ctx, "privacy-subject/v1", "g")
	if err != nil {
		t.Fatal(err)
	}
	createErr := store.PrivacyCreateOperation(ctx, "privacy-inbox-fence-op", subject, PrivacyOperationContext{GroupID: "g", DiceIDs: []string{"d"}, Scopes: []string{"group_record"}, Phase: "fence"})
	if createErr != nil {
		t.Fatal(createErr)
	}
	_, fenceErr := store.PrivacyFence(ctx, subject, "group", "privacy-inbox-fence-op")
	if fenceErr != nil {
		t.Fatal(fenceErr)
	}
	inbox := newInboxTestUpdate("privacy-fenced-inbox", "privacy-fenced-provider", "privacy-fenced-lane")
	inbox.SubjectKey = subject
	if _, admissionErr := store.AcceptInbox(ctx, inbox); admissionErr == nil {
		t.Fatal("inbound admission unexpectedly accepted")
	}
}
