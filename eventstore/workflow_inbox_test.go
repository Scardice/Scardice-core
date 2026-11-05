package eventstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"gorm.io/gorm"
)

func TestWorkflowLinkAndInboxCompletionAreAtomic(t *testing.T) {
	store, db, _ := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()
	inbox := newInboxTestUpdate("task4-workflow-inbox", "task4-workflow-provider", "task4-workflow-lane")
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
	if row.Status != InboxStatusConfirmedConsumed || row.WorkflowID != workflowID || len(row.Payload) == 0 {
		t.Fatalf("terminal workflow row = %#v", row)
	}
	workflowEvents, err := store.Load(ctx, StreamID{AggregateType: "message-workflow", AggregateID: workflowID}, 1)
	if err != nil || len(workflowEvents) != 1 {
		t.Fatalf("workflow events=%d err=%v", len(workflowEvents), err)
	}
}

func TestWorkflowLinkRejectsInvalidIdentityWithoutPartialWrites(t *testing.T) {
	store, db, _ := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()
	inbox, lease := prepareCallbackStartedInbox(t, store, ctx, "task4-invalid-workflow")
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
func TestWorkflowLinkRejectsOverlayMarkerWithoutPartialWrites(t *testing.T) {
	store, db, _ := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()
	inbox, lease := prepareCallbackStartedInbox(t, store, ctx, "task4-overlay-workflow")
	workflowID := "$t-workflow"
	work := UnitOfWork{
		Streams: []StreamAppend{workflowTestStream(workflowID, MessageWorkflowTerminatedEventTypeForTest, "overlay-workflow-event")},
		InboxUpdates: []InboxUpdate{{
			InboxID: inbox.InboxID, ExpectedVersion: lease.Update.Version + 1, Version: lease.Update.Version + 2,
			Status: InboxStatusConfirmedConsumed, WorkflowID: workflowID, LeaseOwner: lease.Update.LeaseOwner,
			LeaseEpoch: lease.Update.LeaseEpoch, AttemptID: lease.Update.AttemptID, LeaseExpiresAt: lease.Update.LeaseExpiresAt,
		}},
	}
	if _, err := store.Commit(ctx, work); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("overlay workflow err=%v", err)
	}
	var row inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", inbox.InboxID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != InboxStatusCallbackStarted || row.WorkflowID != "" {
		t.Fatalf("inbox changed after rejected overlay workflow=%#v", row)
	}
	if events, err := store.Load(ctx, StreamID{AggregateType: "message-workflow", AggregateID: workflowID}, 1); err != nil || len(events) != 0 {
		t.Fatalf("workflow partial events=%d err=%v", len(events), err)
	}
}
func TestWorkflowEventRejectsOverlayMarkerWithoutPartialWrites(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		mutate  func(*NewEvent)
	}{
		{name: "escaped payload", payload: []byte(`{"value":"\u0024t"}`)},
		{name: "malformed trailing escaped payload", payload: []byte(`{"ok":1} {"value":"\u0024t"`)},
		{name: "duplicate escaped payload", payload: []byte(`{"value":"ok","value":"\u0024t"}`)},
		{name: "duplicate marker-free payload", payload: []byte(`{"value":1,"value":2}`)},
		{name: "metadata principal", mutate: func(event *NewEvent) { event.Metadata.PrincipalID = "$t-principal" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, db, _ := openQueueTestStore(t)
			defer db.Close()
			ctx := context.Background()
			inbox, lease := prepareCallbackStartedInbox(t, store, ctx, "task4-overlay-event-"+test.name)
			workflowID := "workflow-overlay-event-" + test.name
			stream := workflowTestStream(workflowID, MessageWorkflowTerminatedEventTypeForTest, "overlay-event-"+test.name)
			if test.payload != nil {
				stream.Events[0].Payload = test.payload
			}
			if test.mutate != nil {
				test.mutate(&stream.Events[0])
			}
			work := UnitOfWork{
				Streams: []StreamAppend{stream},
				InboxUpdates: []InboxUpdate{{
					InboxID: inbox.InboxID, ExpectedVersion: lease.Update.Version + 1, Version: lease.Update.Version + 2,
					Status: InboxStatusConfirmedConsumed, WorkflowID: workflowID, LeaseOwner: lease.Update.LeaseOwner,
					LeaseEpoch: lease.Update.LeaseEpoch, AttemptID: lease.Update.AttemptID, LeaseExpiresAt: lease.Update.LeaseExpiresAt,
				}},
			}
			if _, err := store.Commit(ctx, work); !errors.Is(err, ErrInvalidEvent) {
				t.Fatalf("overlay event err=%v", err)
			}
			var row inboxMessageRow
			if err := db.GORM().Where("inbox_id = ?", inbox.InboxID).First(&row).Error; err != nil {
				t.Fatal(err)
			}
			if row.Status != InboxStatusCallbackStarted || row.WorkflowID != "" {
				t.Fatalf("inbox changed after rejected overlay event=%#v", row)
			}
			if events, err := store.Load(ctx, StreamID{AggregateType: "message-workflow", AggregateID: workflowID}, 1); err != nil || len(events) != 0 {
				t.Fatalf("workflow partial events=%d err=%v", len(events), err)
			}
		})
	}
}
func TestAcceptInboxRejectsWorkflowLinkWithoutPartialWrites(t *testing.T) {
	store, db, _ := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()
	inbox := newInboxTestUpdate("task4-accept-workflow", "task4-accept-workflow-provider", "task4-accept-workflow-lane")
	inbox.WorkflowID = "workflow-accept-orphan"
	if _, err := store.AcceptInbox(ctx, inbox); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("accept workflow err=%v", err)
	}
	var row inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", inbox.InboxID).First(&row).Error; !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("accept workflow row err=%v row=%#v", err, row)
	}
}
func TestWorkflowLinkRequiresExactSameUOWParticipant(t *testing.T) {
	tests := []struct {
		name    string
		streams []StreamAppend
		link    string
	}{
		{name: "missing workflow stream", link: "workflow-exact"},
		{
			name:    "wrong aggregate",
			streams: []StreamAppend{workflowTestStream("workflow-other", MessageWorkflowTerminatedEventTypeForTest, "wrong-aggregate")},
			link:    "workflow-exact",
		},
		{
			name: "multiple workflow streams",
			streams: []StreamAppend{
				workflowTestStream("workflow-exact", MessageWorkflowTerminatedEventTypeForTest, "multiple-exact"),
				workflowTestStream("workflow-other", MessageWorkflowTerminatedEventTypeForTest, "multiple-other"),
			},
			link: "workflow-exact",
		},
		{
			name:    "wrong terminal event",
			streams: []StreamAppend{workflowTestStream("workflow-exact", "message-workflow.started", "wrong-event")},
			link:    "workflow-exact",
		},
		{
			name:    "missing inbox link",
			streams: []StreamAppend{workflowTestStream("workflow-exact", MessageWorkflowTerminatedEventTypeForTest, "missing-link")},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, db, _ := openQueueTestStore(t)
			defer db.Close()
			ctx := context.Background()
			inbox, lease := prepareCallbackStartedInbox(t, store, ctx, "task4-exact-"+test.name)
			update := InboxUpdate{
				InboxID: inbox.InboxID, ExpectedVersion: lease.Update.Version + 1, Version: lease.Update.Version + 2,
				Status: InboxStatusConfirmedConsumed, WorkflowID: test.link, LeaseOwner: lease.Update.LeaseOwner,
				LeaseEpoch: lease.Update.LeaseEpoch, AttemptID: lease.Update.AttemptID, LeaseExpiresAt: lease.Update.LeaseExpiresAt,
			}
			if test.link == "" {
				update.WorkflowID = ""
			}
			if _, err := store.Commit(ctx, UnitOfWork{Streams: test.streams, InboxUpdates: []InboxUpdate{update}}); !errors.Is(err, ErrInvalidTransition) {
				t.Fatalf("workflow participant err=%v", err)
			}
			var row inboxMessageRow
			if err := db.GORM().Where("inbox_id = ?", inbox.InboxID).First(&row).Error; err != nil {
				t.Fatal(err)
			}
			if row.Status != InboxStatusCallbackStarted || row.WorkflowID != "" {
				t.Fatalf("inbox changed after rejected workflow=%#v", row)
			}
			if events, err := store.Load(ctx, StreamID{AggregateType: "message-workflow", AggregateID: "workflow-exact"}, 1); err != nil || len(events) != 0 {
				t.Fatalf("workflow partial events=%d err=%v", len(events), err)
			}
		})
	}
}

func workflowTestStream(id, eventType, eventID string) StreamAppend {
	return StreamAppend{
		Stream:          StreamID{AggregateType: "message-workflow", AggregateID: id},
		ExpectedVersion: 0,
		Events: []NewEvent{{EventType: eventType, SchemaVersion: 1, Payload: []byte(`{}`), Metadata: Metadata{
			EventID: eventID, CommandID: eventID + "-command", CorrelationID: eventID + "-correlation", OccurredAt: time.Unix(1, 0).UTC(),
		}}},
	}
}

func TestWorkflowLinkRollsBackOnParticipantRejection(t *testing.T) {
	store, db, _ := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()
	inbox, lease := prepareCallbackStartedInbox(t, store, ctx, "task4-workflow-rollback")
	workflowID := "workflow-rollback"
	work := UnitOfWork{
		Streams:         []StreamAppend{{Stream: StreamID{AggregateType: "message-workflow", AggregateID: workflowID}, ExpectedVersion: 0, Events: []NewEvent{{EventType: MessageWorkflowTerminatedEventTypeForTest, SchemaVersion: 1, Payload: []byte(`{}`), Metadata: Metadata{EventID: "rollback-workflow-event", CommandID: "rollback-workflow-command", CorrelationID: "rollback-workflow-correlation", OccurredAt: time.Unix(1, 0).UTC()}}}}},
		PluginKVUpdates: []PluginKVUpdate{{ExtensionID: "", Key: "invalid"}},
		InboxUpdates:    []InboxUpdate{{InboxID: inbox.InboxID, ExpectedVersion: lease.Update.Version + 1, Version: lease.Update.Version + 2, Status: InboxStatusConfirmedConsumed, WorkflowID: workflowID, LeaseOwner: lease.Update.LeaseOwner, LeaseEpoch: lease.Update.LeaseEpoch, AttemptID: lease.Update.AttemptID, LeaseExpiresAt: lease.Update.LeaseExpiresAt}},
	}
	if _, err := store.Commit(ctx, work); err == nil {
		t.Fatal("participant rejection unexpectedly committed")
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
func TestDirectInboxUpdateRejectsCompletedAt(t *testing.T) {
	store, db, _ := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()
	inbox := newInboxTestUpdate("task4-completed-at", "task4-completed-at-provider", "task4-completed-at-lane")
	if _, err := store.AcceptInbox(ctx, inbox); err != nil {
		t.Fatal(err)
	}
	lease, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "task4-completed-at-worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateInbox(ctx, InboxUpdate{
		InboxID: lease.Update.InboxID, ExpectedVersion: lease.Update.Version, Status: InboxStatusCallbackStarted,
		LeaseOwner: lease.Update.LeaseOwner, LeaseEpoch: lease.Update.LeaseEpoch, AttemptID: lease.Update.AttemptID,
		CompletedAt: time.Now().UTC(),
	}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("completed-at direct update err=%v", err)
	}
	var row inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", inbox.InboxID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != InboxStatusLeased || row.CompletedAt != nil {
		t.Fatalf("inbox changed after rejected completed-at update=%#v", row)
	}
}
func TestTerminalInboxCommitRetainsPayload(t *testing.T) {
	store, db := openPlainTestStore(t)
	defer db.Close()
	ctx := context.Background()
	inbox := InboxUpdate{
		InboxID: "task4-a6-terminal", EndpointID: "endpoint", ProviderEventKey: "task4-a6-provider",
		Lane: "task4-a6-lane", Status: InboxStatusPending, Payload: []byte("payload"),
	}
	if _, err := store.AcceptInbox(ctx, inbox); err != nil {
		t.Fatal(err)
	}
	lease, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "task4-a6-worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	started := InboxUpdate{
		InboxID: lease.Update.InboxID, ExpectedVersion: lease.Update.Version, Version: lease.Update.Version + 1,
		Status: InboxStatusCallbackStarted, LeaseOwner: lease.Update.LeaseOwner, LeaseEpoch: lease.Update.LeaseEpoch,
		AttemptID: lease.Update.AttemptID, LeaseExpiresAt: lease.Update.LeaseExpiresAt,
	}
	if _, err := store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{started}}); err != nil {
		t.Fatal(err)
	}
	terminal := InboxUpdate{
		InboxID: lease.Update.InboxID, ExpectedVersion: started.Version, Version: started.Version + 1,
		Status: InboxStatusConfirmedConsumed, LeaseOwner: lease.Update.LeaseOwner, LeaseEpoch: lease.Update.LeaseEpoch,
		AttemptID: lease.Update.AttemptID, LeaseExpiresAt: lease.Update.LeaseExpiresAt, CompletedAt: time.Now().UTC(),
	}
	if _, err := store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{terminal}}); err != nil {
		t.Fatalf("A6 terminal status-only commit err=%v", err)
	}
	var row inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", inbox.InboxID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != InboxStatusConfirmedConsumed || string(row.Payload) != "payload" {
		t.Fatalf("terminal inbox row=%#v", row)
	}
}
func TestOpaqueInboxReplayRejectsWorkflowLink(t *testing.T) {
	store, db, _ := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()
	inbox, lease := prepareCallbackStartedInbox(t, store, ctx, "task4-opaque-workflow")
	workflowID := "workflow-opaque-replay"
	work := UnitOfWork{
		Streams: []StreamAppend{workflowTestStream(workflowID, MessageWorkflowTerminatedEventTypeForTest, "opaque-replay-event")},
		InboxUpdates: []InboxUpdate{{
			InboxID: inbox.InboxID, ExpectedVersion: lease.Update.Version + 1, Version: lease.Update.Version + 1,
			Status: InboxStatusPending, WorkflowID: workflowID, EndpointID: inbox.EndpointID,
			ProviderEventKey: inbox.ProviderEventKey, Lane: inbox.Lane,
			Payload: inbox.Payload, ContentDigest: inbox.ContentDigest,
		}},
	}
	if _, err := store.Commit(ctx, work); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("opaque workflow replay err=%v", err)
	}
	var row inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", inbox.InboxID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != InboxStatusCallbackStarted || row.WorkflowID != "" {
		t.Fatalf("inbox changed after rejected opaque workflow=%#v", row)
	}
	if events, err := store.Load(ctx, StreamID{AggregateType: "message-workflow", AggregateID: workflowID}, 1); err != nil || len(events) != 0 {
		t.Fatalf("workflow partial events=%d err=%v", len(events), err)
	}
}
func TestNewInboxRejectsUnlinkedWorkflow(t *testing.T) {
	store, db, _ := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()
	work := UnitOfWork{InboxUpdates: []InboxUpdate{{
		InboxID: "task4-unlinked-inbox", EndpointID: "endpoint", ProviderEventKey: "task4-unlinked-provider",
		Lane: "task4-unlinked-lane", Status: InboxStatusPending, WorkflowID: "workflow-unlinked",
		Payload: []byte("payload"),
	}}}
	if _, err := store.Commit(ctx, work); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("unlinked workflow insert err=%v", err)
	}
	var row inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", "task4-unlinked-inbox").First(&row).Error; !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("unlinked workflow row err=%v row=%#v", err, row)
	}
}

func TestUOWAmbiguousCASAllowsExpiredLease(t *testing.T) {
	store, db, clock := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()
	inbox, lease := prepareCallbackStartedInbox(t, store, ctx, "task4-uow-expired-lease")
	clock.now = clock.now.Add(2 * time.Minute)
	if _, err := store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{{
		InboxID: inbox.InboxID, ExpectedVersion: lease.Update.Version + 1, Version: lease.Update.Version + 2,
		Status: InboxStatusAmbiguous, LeaseOwner: lease.Update.LeaseOwner, LeaseEpoch: lease.Update.LeaseEpoch,
		AttemptID: lease.Update.AttemptID, LeaseExpiresAt: lease.Update.LeaseExpiresAt,
	}}}); err != nil {
		t.Fatal(err)
	}
	var row inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", inbox.InboxID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != InboxStatusAmbiguous || len(row.Payload) == 0 || row.LeaseExpiry != nil {
		t.Fatalf("expired UOW ambiguity row=%#v", row)
	}
}

func prepareCallbackStartedInbox(t *testing.T, store *GORMStore, ctx context.Context, id string) (InboxUpdate, InboxLease) {
	t.Helper()
	inbox := newInboxTestUpdate(id, id+"-provider", id+"-lane")
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
