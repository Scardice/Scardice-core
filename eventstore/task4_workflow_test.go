package eventstore

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"gorm.io/gorm"
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
func TestTask4WorkflowLinkRejectsOverlayMarkerWithoutPartialWrites(t *testing.T) {
	store, db, _ := task5Store(t)
	defer db.Close()
	ctx := context.Background()
	inbox, lease := task4PrepareStartedInbox(t, store, ctx, "task4-overlay-workflow")
	workflowID := "$t-workflow"
	work := UnitOfWork{
		Streams: []StreamAppend{task4WorkflowStream(workflowID, MessageWorkflowTerminatedEventTypeForTest, "overlay-workflow-event")},
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
func TestTask4WorkflowEventRejectsOverlayMarkerWithoutPartialWrites(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		mutate  func(*NewEvent)
	}{
		{name: "escaped payload", payload: []byte(`{"value":"\u0024t"}`)},
		{name: "malformed trailing escaped payload", payload: []byte(`{"ok":1} {"value":"\u0024t"`)},
		{name: "duplicate escaped payload", payload: []byte(`{"value":"ok","value":"\u0024t"}`)},
		{name: "metadata principal", mutate: func(event *NewEvent) { event.Metadata.PrincipalID = "$t-principal" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, db, _ := task5Store(t)
			defer db.Close()
			ctx := context.Background()
			inbox, lease := task4PrepareStartedInbox(t, store, ctx, "task4-overlay-event-"+test.name)
			workflowID := "workflow-overlay-event-" + test.name
			stream := task4WorkflowStream(workflowID, MessageWorkflowTerminatedEventTypeForTest, "overlay-event-"+test.name)
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
func TestTask4AcceptInboxRejectsWorkflowLinkWithoutPartialWrites(t *testing.T) {
	store, db, _ := task5Store(t)
	defer db.Close()
	ctx := context.Background()
	inbox := task5Inbox("task4-accept-workflow", "task4-accept-workflow-provider", "task4-accept-workflow-lane")
	inbox.WorkflowID = "workflow-accept-orphan"
	if _, err := store.AcceptInbox(ctx, inbox); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("accept workflow err=%v", err)
	}
	var row inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", inbox.InboxID).First(&row).Error; !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("accept workflow row err=%v row=%#v", err, row)
	}
}
func TestTask4AcceptExpiredDedupeRetainsCallbackUncertainty(t *testing.T) {
	for _, status := range []string{InboxStatusCallbackStarted, InboxStatusAmbiguous} {
		t.Run(status, func(t *testing.T) {
			store, db, _ := task5Store(t)
			defer db.Close()
			ctx := context.Background()
			inbox := task5Inbox("task4-expired-"+status, "task4-expired-provider-"+status, "task4-expired-lane-"+status)
			if _, err := store.AcceptInbox(ctx, inbox); err != nil {
				t.Fatal(err)
			}
			expiredAt := time.Unix(99, 0).UTC()
			if err := db.GORM().Model(&inboxMessageRow{}).Where("inbox_id = ?", inbox.InboxID).Updates(map[string]any{
				"status": status, "payload_expires_at": expiredAt,
			}).Error; err != nil {
				t.Fatal(err)
			}
			var before inboxMessageRow
			if err := db.GORM().Where("inbox_id = ?", inbox.InboxID).First(&before).Error; err != nil {
				t.Fatal(err)
			}
			if before.PayloadExpiresAt == nil || before.PayloadExpiresAt.After(time.Now()) {
				t.Fatalf("fixture expiry=%v", before.PayloadExpiresAt)
			}
			if before.Status != status {
				t.Fatalf("fixture status=%q want=%q", before.Status, status)
			}
			inbox.AllowExpiredDedupe = true
			if _, err := store.AcceptInbox(ctx, inbox); !errors.Is(err, ErrPayloadExpired) {
				t.Fatalf("expired uncertain dedupe err=%v", err)
			}
			var after inboxMessageRow
			if err := db.GORM().Where("inbox_id = ?", inbox.InboxID).First(&after).Error; err != nil {
				t.Fatal(err)
			}
			var count int64
			if err := db.GORM().Model(&inboxMessageRow{}).Where("endpoint_id = ? AND provider_event_id = ?", inbox.EndpointID, inbox.ProviderEventKey).Count(&count).Error; err != nil {
				t.Fatal(err)
			}
			if count != 1 || after.InboxID != before.InboxID || after.Version != before.Version || after.Status != status || after.OrderingSequence != before.OrderingSequence {
				t.Fatalf("uncertain row changed count=%d before=%#v after=%#v", count, before, after)
			}
		})
	}
}
func TestTask4RecoverExpiredCallbackStartedIsBounded(t *testing.T) {
	store, db, clock := task5Store(t)
	defer db.Close()
	ctx := context.Background()
	expiredAt := clock.Now().Add(-time.Minute)
	futureAt := clock.Now().Add(time.Minute)
	rows := make([]inboxMessageRow, 129)
	for i := range rows {
		rows[i] = inboxMessageRow{
			InboxID: fmt.Sprintf("task4-recovery-%03d", i), EndpointID: "endpoint",
			ProviderEventKey: fmt.Sprintf("task4-recovery-provider-%03d", i),
			LaneHMAC:         []byte(fmt.Sprintf("task4-recovery-lane-%03d", i)), OrderingSequence: 1,
			Status: InboxStatusCallbackStarted, Version: 1, PayloadVersion: 1,
			LeaseExpiry: &expiredAt, PayloadExpiresAt: &futureAt,
			PayloadCiphertext: []byte("ciphertext"), PayloadNonce: []byte("nonce"), EncryptionKeyID: "key",
		}
	}
	if err := db.GORM().Create(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "recovery-worker", RecoverExpiredCallbackStarted: true}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("recovery claim err=%v", err)
	}
	var ambiguous, callbackStarted int64
	if err := db.GORM().Model(&inboxMessageRow{}).Where("status = ?", InboxStatusAmbiguous).Count(&ambiguous).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Model(&inboxMessageRow{}).Where("status = ?", InboxStatusCallbackStarted).Count(&callbackStarted).Error; err != nil {
		t.Fatal(err)
	}
	if ambiguous != task5PayloadScrubBatchSize || callbackStarted != int64(len(rows)-task5PayloadScrubBatchSize) {
		t.Fatalf("recovery batch ambiguous=%d callback-started=%d", ambiguous, callbackStarted)
	}
	var first, last inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", "task4-recovery-000").First(&first).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Where("inbox_id = ?", "task4-recovery-128").First(&last).Error; err != nil {
		t.Fatal(err)
	}
	if first.Status != InboxStatusAmbiguous || last.Status != InboxStatusCallbackStarted {
		t.Fatalf("recovery order first=%q last=%q", first.Status, last.Status)
	}
}
func TestTask4WorkflowLinkRequiresExactSameUOWParticipant(t *testing.T) {
	tests := []struct {
		name    string
		streams []StreamAppend
		link    string
	}{
		{name: "missing workflow stream", link: "workflow-exact"},
		{
			name:    "wrong aggregate",
			streams: []StreamAppend{task4WorkflowStream("workflow-other", MessageWorkflowTerminatedEventTypeForTest, "wrong-aggregate")},
			link:    "workflow-exact",
		},
		{
			name: "multiple workflow streams",
			streams: []StreamAppend{
				task4WorkflowStream("workflow-exact", MessageWorkflowTerminatedEventTypeForTest, "multiple-exact"),
				task4WorkflowStream("workflow-other", MessageWorkflowTerminatedEventTypeForTest, "multiple-other"),
			},
			link: "workflow-exact",
		},
		{
			name:    "wrong terminal event",
			streams: []StreamAppend{task4WorkflowStream("workflow-exact", "message-workflow.started", "wrong-event")},
			link:    "workflow-exact",
		},
		{
			name:    "missing inbox link",
			streams: []StreamAppend{task4WorkflowStream("workflow-exact", MessageWorkflowTerminatedEventTypeForTest, "missing-link")},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, db, _ := task5Store(t)
			defer db.Close()
			ctx := context.Background()
			inbox, lease := task4PrepareStartedInbox(t, store, ctx, "task4-exact-"+test.name)
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

func task4WorkflowStream(id, eventType, eventID string) StreamAppend {
	return StreamAppend{
		Stream:          StreamID{AggregateType: "message-workflow", AggregateID: id},
		ExpectedVersion: 0,
		Events: []NewEvent{{EventType: eventType, SchemaVersion: 1, Payload: []byte(`{}`), Metadata: Metadata{
			EventID: eventID, CommandID: eventID + "-command", CorrelationID: eventID + "-correlation", OccurredAt: time.Unix(1, 0).UTC(),
		}}},
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
func TestTask4DirectInboxUpdateRejectsCompletedAt(t *testing.T) {
	store, db, _ := task5Store(t)
	defer db.Close()
	ctx := context.Background()
	inbox := task5Inbox("task4-completed-at", "task4-completed-at-provider", "task4-completed-at-lane")
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
func TestTask4A6TerminalStatusOnlyCommitSucceeds(t *testing.T) {
	store, db, source := task6Store(t)
	defer db.Close()
	ctx := context.Background()
	ciphertext, nonce, keyID, err := a6Seal(ctx, source, "inbox/v1", "task4-a6-terminal", "endpoint", 1, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	inbox := InboxUpdate{
		InboxID: "task4-a6-terminal", EndpointID: "endpoint", ProviderEventKey: "task4-a6-provider",
		LaneHMAC: []byte("task4-a6-lane"), Status: InboxStatusPending,
		PayloadCiphertext: ciphertext, PayloadNonce: nonce, PayloadEncryptionKeyID: keyID,
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
	if row.Status != InboxStatusConfirmedConsumed || len(row.PayloadCiphertext) != 0 || row.EncryptionKeyID != keyID {
		t.Fatalf("A6 terminal row=%#v", row)
	}
}
func TestTask4A6UOWPayloadVersionBindsInboxAndEffect(t *testing.T) {
	store, db, source := task6Store(t)
	defer db.Close()
	ctx := context.Background()
	const version = uint64(7)
	inboxCipher, inboxNonce, inboxKeyID, err := a6Seal(ctx, source, "inbox/v1", "task4-a6-uow-inbox", "endpoint", version, []byte("inbox-v7"))
	if err != nil {
		t.Fatal(err)
	}
	effectCipher, effectNonce, effectKeyID, err := a6Seal(ctx, source, "outbox/v1", "task4-a6-uow-effect", "endpoint", version, []byte("effect-v7"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{
		InboxUpdates: []InboxUpdate{{
			InboxID: "task4-a6-uow-inbox", EndpointID: "endpoint", ProviderEventKey: "task4-a6-uow-inbox-provider",
			LaneHMAC: []byte("task4-a6-uow-inbox-lane"), Status: InboxStatusPending, PayloadVersion: version,
			PayloadCiphertext: inboxCipher, PayloadNonce: inboxNonce, PayloadEncryptionKeyID: inboxKeyID,
		}},
		Effects: []NewEffect{{
			EffectID: "task4-a6-uow-effect", EndpointID: "endpoint", LaneHMAC: []byte("task4-a6-uow-effect-lane"),
			EffectType: "send", RiskClass: RiskPreDispatchRetryable, Status: OutboxStatusPending, PayloadVersion: version,
			PayloadCiphertext: effectCipher, PayloadNonce: effectNonce, PayloadEncryptionKeyID: effectKeyID,
		}},
	}); err != nil {
		t.Fatal(err)
	}
	var inboxRow inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", "task4-a6-uow-inbox").First(&inboxRow).Error; err != nil {
		t.Fatal(err)
	}
	if inboxRow.PayloadVersion != version {
		t.Fatalf("inbox payload version=%d want=%d", inboxRow.PayloadVersion, version)
	}
	if plain, err := a6Open(ctx, source, "inbox/v1", inboxRow.InboxID, inboxRow.EndpointID, version, inboxRow.EncryptionKeyID, inboxRow.PayloadCiphertext, inboxRow.PayloadNonce); err != nil || string(plain) != "inbox-v7" {
		t.Fatalf("inbox v7 open plain=%q err=%v", plain, err)
	}
	if _, err := a6Open(ctx, source, "inbox/v1", inboxRow.InboxID, inboxRow.EndpointID, 1, inboxRow.EncryptionKeyID, inboxRow.PayloadCiphertext, inboxRow.PayloadNonce); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("inbox v1 open err=%v", err)
	}
	var effectRow outboxEffectRow
	if err := db.GORM().Where("effect_id = ?", "task4-a6-uow-effect").First(&effectRow).Error; err != nil {
		t.Fatal(err)
	}
	if effectRow.PayloadVersion != version {
		t.Fatalf("effect payload version=%d want=%d", effectRow.PayloadVersion, version)
	}
	if plain, err := a6Open(ctx, source, "outbox/v1", effectRow.EffectID, effectRow.EndpointID, version, effectRow.EncryptionKeyID, effectRow.PayloadCiphertext, effectRow.PayloadNonce); err != nil || string(plain) != "effect-v7" {
		t.Fatalf("effect v7 open plain=%q err=%v", plain, err)
	}
	if _, err := a6Open(ctx, source, "outbox/v1", effectRow.EffectID, effectRow.EndpointID, 1, effectRow.EncryptionKeyID, effectRow.PayloadCiphertext, effectRow.PayloadNonce); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("effect v1 open err=%v", err)
	}
}
func TestTask4OpaqueInboxReplayRejectsWorkflowLink(t *testing.T) {
	store, db, _ := task5Store(t)
	defer db.Close()
	ctx := context.Background()
	inbox, lease := task4PrepareStartedInbox(t, store, ctx, "task4-opaque-workflow")
	workflowID := "workflow-opaque-replay"
	work := UnitOfWork{
		Streams: []StreamAppend{task4WorkflowStream(workflowID, MessageWorkflowTerminatedEventTypeForTest, "opaque-replay-event")},
		InboxUpdates: []InboxUpdate{{
			InboxID: inbox.InboxID, ExpectedVersion: lease.Update.Version + 1, Version: lease.Update.Version + 1,
			Status: InboxStatusPending, WorkflowID: workflowID, EndpointID: inbox.EndpointID,
			ProviderEventKey: inbox.ProviderEventKey, LaneHMAC: inbox.LaneHMAC,
			PayloadCiphertext: inbox.PayloadCiphertext, PayloadNonce: inbox.PayloadNonce,
			PayloadEncryptionKeyID: inbox.PayloadEncryptionKeyID, ContentDigest: inbox.ContentDigest,
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
func TestTask4NewInboxRejectsUnlinkedWorkflow(t *testing.T) {
	store, db, _ := task5Store(t)
	defer db.Close()
	ctx := context.Background()
	work := UnitOfWork{InboxUpdates: []InboxUpdate{{
		InboxID: "task4-unlinked-inbox", EndpointID: "endpoint", ProviderEventKey: "task4-unlinked-provider",
		LaneHMAC: []byte("task4-unlinked-lane"), Status: InboxStatusPending, WorkflowID: "workflow-unlinked",
		PayloadCiphertext: []byte("ciphertext"), PayloadNonce: []byte("nonce"), DigestKeyID: "key",
	}}}
	if _, err := store.Commit(ctx, work); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("unlinked workflow insert err=%v", err)
	}
	var row inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", "task4-unlinked-inbox").First(&row).Error; !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("unlinked workflow row err=%v row=%#v", err, row)
	}
}

func TestTask4CallbackClaimQuarantinesAuthenticationFailure(t *testing.T) {
	store, db, source := task6Store(t)
	defer db.Close()
	ctx := context.Background()
	firstCipher, firstNonce, keyID, err := a6Seal(ctx, source, "inbox/v1", "task4-auth-failure", "endpoint", 1, []byte("first"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptInbox(ctx, InboxUpdate{
		InboxID: "task4-auth-failure", EndpointID: "endpoint", ProviderEventKey: "task4-auth-failure-provider",
		LaneHMAC: []byte("task4-auth-failure-lane"), Status: InboxStatusPending,
		PayloadCiphertext: firstCipher, PayloadNonce: firstNonce, PayloadEncryptionKeyID: keyID,
	}); err != nil {
		t.Fatal(err)
	}
	secondCipher, secondNonce, secondKeyID, err := a6Seal(ctx, source, "inbox/v1", "task4-auth-success", "endpoint", 1, []byte("second"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptInbox(ctx, InboxUpdate{
		InboxID: "task4-auth-success", EndpointID: "endpoint", ProviderEventKey: "task4-auth-success-provider",
		LaneHMAC: []byte("task4-auth-failure-lane"), Status: InboxStatusPending,
		PayloadCiphertext: secondCipher, PayloadNonce: secondNonce, PayloadEncryptionKeyID: secondKeyID,
	}); err != nil {
		t.Fatal(err)
	}
	var firstRow inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", "task4-auth-failure").First(&firstRow).Error; err != nil {
		t.Fatal(err)
	}
	firstRow.PayloadCiphertext[0] ^= 1
	if err := db.GORM().Model(&inboxMessageRow{}).Where("inbox_id = ?", firstRow.InboxID).Update("payload_ciphertext", firstRow.PayloadCiphertext).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "task4-callback-worker", QuarantinePayloadErrors: true, TerminalizeExpired: true}); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("callback claim authentication err=%v", err)
	}
	if err := db.GORM().Where("inbox_id = ?", firstRow.InboxID).First(&firstRow).Error; err != nil {
		t.Fatal(err)
	}
	if firstRow.Status != InboxStatusFailed || firstRow.Version != 2 || len(firstRow.PayloadCiphertext) != 0 || firstRow.CompletedAt == nil {
		t.Fatalf("tampered callback row=%#v", firstRow)
	}
	lease, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "task4-callback-worker", QuarantinePayloadErrors: true, TerminalizeExpired: true})
	if err != nil || lease.Update.InboxID != "task4-auth-success" {
		t.Fatalf("lane remained blocked lease=%#v err=%v", lease, err)
	}
}

func TestTask4CallbackClaimTerminalizesExpiredPendingPayload(t *testing.T) {
	store, db, clock := task5Store(t)
	defer db.Close()
	ctx := context.Background()
	expiredAt := clock.Now().Add(-time.Minute)
	futureAt := clock.Now().Add(time.Hour)
	rows := []inboxMessageRow{
		{
			InboxID: "task4-expired-pending", EndpointID: "endpoint", ProviderEventKey: "expired-pending-provider",
			LaneHMAC: []byte("task4-expired-lane"), OrderingSequence: 1, Status: InboxStatusPending,
			Version: 1, PayloadVersion: 1, PayloadCiphertext: []byte("expired"), PayloadNonce: []byte("nonce"), EncryptionKeyID: "key",
			PayloadExpiresAt: &expiredAt,
		},
		{
			InboxID: "task4-after-expired", EndpointID: "endpoint", ProviderEventKey: "after-expired-provider",
			LaneHMAC: []byte("task4-expired-lane"), OrderingSequence: 2, Status: InboxStatusPending,
			Version: 1, PayloadVersion: 1, PayloadCiphertext: []byte("next"), PayloadNonce: []byte("nonce"), EncryptionKeyID: "key",
			PayloadExpiresAt: &futureAt,
		},
	}
	if err := db.GORM().Create(&rows).Error; err != nil {
		t.Fatal(err)
	}
	lease, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "task4-expiry-worker", QuarantinePayloadErrors: true, TerminalizeExpired: true})
	if err != nil || lease.Update.InboxID != "task4-after-expired" {
		t.Fatalf("expired pending row blocked lane lease=%#v err=%v", lease, err)
	}
	var expiredRow inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", "task4-expired-pending").First(&expiredRow).Error; err != nil {
		t.Fatal(err)
	}
	if expiredRow.Status != InboxStatusFailed || expiredRow.Version != 2 || len(expiredRow.PayloadCiphertext) != 0 || expiredRow.CompletedAt == nil {
		t.Fatalf("expired pending row=%#v", expiredRow)
	}
}
func TestTask4UOWAmbiguousCASAllowsExpiredLease(t *testing.T) {
	store, db, clock := task5Store(t)
	defer db.Close()
	ctx := context.Background()
	inbox, lease := task4PrepareStartedInbox(t, store, ctx, "task4-uow-expired-lease")
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
	if row.Status != InboxStatusAmbiguous || len(row.PayloadCiphertext) != 0 || row.LeaseExpiry != nil {
		t.Fatalf("expired UOW ambiguity row=%#v", row)
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
