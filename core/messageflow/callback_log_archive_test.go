package messageflow

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/playerstate"
	"Scardice-core/endpoint"
	"Scardice-core/eventstore"
)

func TestCallbackStoryLogAppendSharesInboxCommitAndRollback(t *testing.T) {
	for _, failLogInsert := range []bool{false, true} {
		name := "commit"
		if failLogInsert {
			name = "rollback"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			source := integrationKeySource{indexID: "callback-log-index", index: []byte("01234567890123456789012345678901"), rootID: "callback-log-root", root: []byte("abcdefghijklmnopqrstuvwxyz123456")}
			db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "callback-log.db"), KeySource: source, DatabaseIdentity: "callback-log"})
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			store := eventstore.NewStore(db)
			if err := store.SetReadiness(ctx, eventstore.Readiness{Mode: "import", SchemaVersion: 1, DatabaseIdentity: "callback-log", IndexRootID: source.indexID, EncryptionRootIDs: []string{source.rootID}, SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC()}); err != nil {
				t.Fatal(err)
			}
			if failLogInsert {
				if err := db.GORM().Exec("CREATE TRIGGER reject_story_log_entry BEFORE INSERT ON story_log_entries BEGIN SELECT RAISE(ABORT, 'forced log insert failure'); END").Error; err != nil {
					t.Fatal(err)
				}
			}

			now := time.Now().UTC()
			inbound, err := NewInboundService(store, store, WithIngressClock(fixedIngressClock{now: now}))
			if err != nil {
				t.Fatal(err)
			}
			fenced := endpoint.FencedInbound{EndpointID: "endpoint-1", Generation: 1, DesiredVersion: 1, Message: adapterapi.InboundMessage{
				ProviderEventID: "provider-message-1", Kind: adapterapi.InboundKindMessage,
				ConversationKind: adapterapi.ConversationKindGroup, Platform: "test", Sender: "user",
				Conversation: "group", Target: "group", Text: "hello",
			}}
			first, err := inbound.HandleInbound(ctx, fenced)
			if err != nil {
				t.Fatal(err)
			}
			duplicate, err := inbound.HandleInbound(ctx, fenced)
			if err != nil || duplicate.Outcome != adapterapi.IngressDuplicate || duplicate.InboxID != first.InboxID {
				t.Fatalf("duplicate ingress=%+v err=%v first=%+v", duplicate, err, first)
			}

			host := &callbackTestHost{fn: func(_ context.Context, request CallbackRequest, _ *playerstate.LocalOverlay, collector *MutationCollector) (CallbackResult, error) {
				if err := collector.AddStream(eventstore.StreamID{AggregateType: "callback-test", AggregateID: "message"}, 0, []eventstore.NewEvent{callbackEvent("callback.test", `{}`)}); err != nil {
					return CallbackResult{}, err
				}
				if err := collector.AddLogUpdate(eventstore.NewStoryLogAppendUpdate(eventstore.StoryLogEntry{
					DiceID: request.Scope.DiceID, GroupID: request.Scope.GroupID, LogName: "session",
					Message: "archived callback", Time: now.Unix(),
				})); err != nil {
					return CallbackResult{}, err
				}
				return CallbackResult{}, nil
			}}
			callback, err := NewCallbackService(CallbackConfig{
				Inbox: store, Store: store, BoundCodec: store, Resolver: callbackTestResolver{},
				Group: callbackTestGroupLoader{}, Player: callbackTestPlayerLoader{}, Host: host, WorkerID: "callback-log",
			})
			if err != nil {
				t.Fatal(err)
			}
			summary, callbackErr := callback.ProcessOne(ctx)
			if failLogInsert {
				if callbackErr == nil {
					t.Fatalf("callback unexpectedly committed after log insert failure: %+v", summary)
				}
			} else if callbackErr != nil || summary.Status != eventstore.InboxStatusConfirmedConsumed {
				t.Fatalf("callback summary=%+v err=%v", summary, callbackErr)
			}

			events, err := store.Load(ctx, eventstore.StreamID{AggregateType: "callback-test", AggregateID: "message"}, 0)
			if err != nil {
				t.Fatal(err)
			}
			var sessionCount, entryCount int64
			if err := db.GORM().Table("story_log_sessions").Count(&sessionCount).Error; err != nil {
				t.Fatal(err)
			}
			if err := db.GORM().Table("story_log_entries").Count(&entryCount).Error; err != nil {
				t.Fatal(err)
			}
			if failLogInsert {
				if len(events) != 0 || sessionCount != 0 || entryCount != 0 {
					t.Fatalf("failed callback leaked mutations: events=%d sessions=%d entries=%d", len(events), sessionCount, entryCount)
				}
			} else {
				entries, err := store.GetStoryLogEntries(ctx, "dice", "group", "session")
				if err != nil || len(events) != 1 || sessionCount != 1 || entryCount != 1 || len(entries) != 1 || entries[0].Message != "archived callback" {
					t.Fatalf("committed callback mutations: events=%d sessions=%d rows=%d entries=%#v err=%v", len(events), sessionCount, entryCount, entries, err)
				}
			}

			var inboxStatus string
			if err := db.GORM().Table("inbox_messages").Select("status").Where("inbox_id = ?", first.InboxID).Scan(&inboxStatus).Error; err != nil {
				t.Fatal(err)
			}
			wantStatus := eventstore.InboxStatusConfirmedConsumed
			if failLogInsert {
				wantStatus = eventstore.InboxStatusAmbiguous
			}
			if inboxStatus != wantStatus {
				t.Fatalf("inbox terminal status=%q want=%q", inboxStatus, wantStatus)
			}
		})
	}
}
