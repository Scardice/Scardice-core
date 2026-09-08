package eventstore

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestTask4WorkflowLinkAndInboxCompletionAreAtomic(t *testing.T) {
	store, db, _ := task5Store(t)
	defer db.Close()
	ctx := context.Background()
	inbox := task5Inbox("task4-workflow-inbox", "task4-workflow-provider", "task4-workflow-lane")
	if _, err := store.AcceptInbox(ctx, inbox); err != nil {
		t.Fatal(err)
	}
	lease, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "task4-worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{{
		InboxID: lease.Update.InboxID, ExpectedVersion: lease.Update.Version, Version: lease.Update.Version + 1,
		Status: InboxStatusCallbackStarted, LeaseOwner: lease.Update.LeaseOwner, LeaseEpoch: lease.Update.LeaseEpoch,
		AttemptID: lease.Update.AttemptID, LeaseExpiresAt: lease.Update.LeaseExpiresAt,
	}}}); err != nil {
		t.Fatal(err)
	}
	workflowID := "workflow-task4-1"
	event := NewEvent{EventType: MessageWorkflowTerminatedEventTypeForTest, SchemaVersion: 1, Payload: []byte(`{"workflowId":"workflow-task4-1"}`), Metadata: Metadata{EventID: "task4-workflow-event", CommandID: "task4-workflow-command", CorrelationID: "task4-workflow-correlation", OccurredAt: time.Unix(1, 0).UTC()}}
	if _, err := store.Commit(ctx, UnitOfWork{
		Streams:      []StreamAppend{{Stream: StreamID{AggregateType: "message-workflow", AggregateID: workflowID}, ExpectedVersion: 0, Events: []NewEvent{event}}},
		InboxUpdates: []InboxUpdate{{InboxID: lease.Update.InboxID, ExpectedVersion: lease.Update.Version + 1, Version: lease.Update.Version + 2, Status: InboxStatusConfirmedConsumed, WorkflowID: workflowID, LeaseOwner: lease.Update.LeaseOwner, LeaseEpoch: lease.Update.LeaseEpoch, AttemptID: lease.Update.AttemptID, LeaseExpiresAt: lease.Update.LeaseExpiresAt}},
	}); err != nil {
		t.Fatal(err)
	}
	var row inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", inbox.InboxID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != InboxStatusConfirmedConsumed || row.WorkflowID != workflowID || len(row.PayloadCiphertext) != 0 || len(row.PayloadNonce) != 0 {
		t.Fatalf("terminal workflow row = %#v", row)
	}
	workflowEvents, err := store.Load(ctx, StreamID{AggregateType: "message-workflow", AggregateID: workflowID}, 1)
	if err != nil || len(workflowEvents) != 1 {
		t.Fatalf("workflow events=%d err=%v", len(workflowEvents), err)
	}
}

func TestTask4WorkflowLinkRejectsInvalidIdentityWithoutPartialWrites(t *testing.T) {
	store, db, _ := task5Store(t)
	defer db.Close()
	ctx := context.Background()
	inbox, lease := task4PrepareStartedInbox(t, store, ctx, "task4-invalid-workflow")
	workflowID := "bad/id"
	work := UnitOfWork{
		Streams:      []StreamAppend{{Stream: StreamID{AggregateType: "message-workflow", AggregateID: workflowID}, ExpectedVersion: 0, Events: []NewEvent{{EventType: MessageWorkflowTerminatedEventTypeForTest, SchemaVersion: 1, Payload: []byte(`{}`), Metadata: Metadata{EventID: "invalid-workflow-event", CommandID: "invalid-workflow-command", CorrelationID: "invalid-workflow-correlation", OccurredAt: time.Unix(1, 0).UTC()}}}}},
		InboxUpdates: []InboxUpdate{{InboxID: inbox.InboxID, ExpectedVersion: lease.Update.Version + 1, Version: lease.Update.Version + 2, Status: InboxStatusConfirmedConsumed, WorkflowID: workflowID, LeaseOwner: lease.Update.LeaseOwner, LeaseEpoch: lease.Update.LeaseEpoch, AttemptID: lease.Update.AttemptID, LeaseExpiresAt: lease.Update.LeaseExpiresAt}},
	}
	if _, err := store.Commit(ctx, work); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("invalid workflow err=%v", err)
	}
	var row inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", inbox.InboxID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != InboxStatusCallbackStarted || row.WorkflowID != "" {
		t.Fatalf("inbox changed after rejected workflow=%#v", row)
	}
	if events, err := store.Load(ctx, StreamID{AggregateType: "message-workflow", AggregateID: workflowID}, 1); err != nil || len(events) != 0 {
		t.Fatalf("workflow partial events=%d err=%v", len(events), err)
	}
}

func TestTask4WorkflowLinkRollsBackOnParticipantFailure(t *testing.T) {
	store, db, _ := task5Store(t)
	defer db.Close()
	ctx := context.Background()
	inbox, lease := task4PrepareStartedInbox(t, store, ctx, "task4-workflow-rollback")
	workflowID := "workflow-rollback"
	work := UnitOfWork{
		Streams:         []StreamAppend{{Stream: StreamID{AggregateType: "message-workflow", AggregateID: workflowID}, ExpectedVersion: 0, Events: []NewEvent{{EventType: MessageWorkflowTerminatedEventTypeForTest, SchemaVersion: 1, Payload: []byte(`{}`), Metadata: Metadata{EventID: "rollback-workflow-event", CommandID: "rollback-workflow-command", CorrelationID: "rollback-workflow-correlation", OccurredAt: time.Unix(1, 0).UTC()}}}}},
		PluginKVUpdates: []PluginKVUpdate{{ExtensionID: "", KeyHMAC: []byte("invalid")}},
		InboxUpdates:    []InboxUpdate{{InboxID: inbox.InboxID, ExpectedVersion: lease.Update.Version + 1, Version: lease.Update.Version + 2, Status: InboxStatusConfirmedConsumed, WorkflowID: workflowID, LeaseOwner: lease.Update.LeaseOwner, LeaseEpoch: lease.Update.LeaseEpoch, AttemptID: lease.Update.AttemptID, LeaseExpiresAt: lease.Update.LeaseExpiresAt}},
	}
	if _, err := store.Commit(ctx, work); !errors.Is(err, ErrParticipantFailure) {
		t.Fatalf("participant failure err=%v", err)
	}
	var row inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", inbox.InboxID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != InboxStatusCallbackStarted || row.WorkflowID != "" {
		t.Fatalf("inbox changed after rollback=%#v", row)
	}
	if events, err := store.Load(ctx, StreamID{AggregateType: "message-workflow", AggregateID: workflowID}, 1); err != nil || len(events) != 0 {
		t.Fatalf("workflow partial events=%d err=%v", len(events), err)
	}
}

func task4PrepareStartedInbox(t *testing.T, store *GORMStore, ctx context.Context, id string) (InboxUpdate, InboxLease) {
	t.Helper()
	inbox := task5Inbox(id, id+"-provider", id+"-lane")
	if _, err := store.AcceptInbox(ctx, inbox); err != nil {
		t.Fatal(err)
	}
	lease, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: id + "-worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{{InboxID: lease.Update.InboxID, ExpectedVersion: lease.Update.Version, Version: lease.Update.Version + 1, Status: InboxStatusCallbackStarted, LeaseOwner: lease.Update.LeaseOwner, LeaseEpoch: lease.Update.LeaseEpoch, AttemptID: lease.Update.AttemptID}}}); err != nil {
		t.Fatal(err)
	}
	return inbox, lease
}

const MessageWorkflowTerminatedEventTypeForTest = "message-workflow.terminated"
