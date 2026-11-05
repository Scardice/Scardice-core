package eventstore

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestStoryLogAppendOnceKeepsOneEntryPerProviderMessage(t *testing.T) {
	ctx := context.Background()
	store, db := openPlainTestStore(t)
	defer db.Close()
	for _, name := range []string{"first", "second"} {
		if _, err := store.CreateStoryLog(ctx, "dice-a", "group-a", name); err != nil {
			t.Fatal(err)
		}
	}
	entry := func(logName, raw, message string) StoryLogEntry {
		return StoryLogEntry{DiceID: "dice-a", GroupID: "group-a", LogName: logName, Nickname: "Dice", IsDice: true, Message: message, RawMsgID: raw, Time: 100}
	}
	for _, update := range []StoryLogEntry{
		entry("first", "provider-1", "typed by hand"),
		entry("first", "provider-1", "reported again"),
		entry("first", "provider-2", "another"),
		entry("second", "provider-1", "same id in another log"),
	} {
		if err := store.commitLogUpdate(ctx, NewStoryLogAppendOnceUpdate(update)); err != nil {
			t.Fatal(err)
		}
	}
	first, err := store.GetStoryLogEntries(ctx, "dice-a", "group-a", "first")
	if err != nil || len(first) != 2 || first[0].Message != "typed by hand" || first[1].RawMsgID != "provider-2" {
		t.Fatalf("first log = %#v err=%v, want the first report of provider-1 and provider-2", first, err)
	}
	second, err := store.GetStoryLogEntries(ctx, "dice-a", "group-a", "second")
	if err != nil || len(second) != 1 {
		t.Fatalf("second log = %#v err=%v, want its own entry", second, err)
	}
	if err := store.commitLogUpdate(ctx, NewStoryLogAppendOnceUpdate(entry("deleted", "provider-9", "no such log"))); err != nil {
		t.Fatalf("append-once into a log that does not exist must be dropped, got %v", err)
	}
	if err := store.commitLogUpdate(ctx, NewStoryLogAppendOnceUpdate(entry("first", "", "no id"))); err == nil {
		t.Fatal("append-once without a raw message id was accepted")
	}
}

// Whichever of the provider's report and Core's terminal commit reaches the
// archive first, the log ends with one entry holding Core's own content.
func TestStoryLogProviderReportAndTerminalCommitAgreeInEitherOrder(t *testing.T) {
	for _, reportFirst := range []bool{true, false} {
		name := "terminal first"
		if reportFirst {
			name = "report first"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			clock := &outboxRecoveryClock{now: time.Unix(700, 0).UTC()}
			ids := &outboxRecoveryIDs{}

			store, db := openOutboxRecoveryStore(t, filepath.Join(t.TempDir(), "story-log-report.db"), clock, ids, true)
			defer db.Close()
			if _, err := store.CreateStoryLog(ctx, "dice-a", "group-a", "session"); err != nil {
				t.Fatal(err)
			}
			effect := newOutboxRecoveryEffect(t, clock, "report-effect", "lane-report", RiskProviderIdempotent)
			seedOutboxRecoveryEffect(t, store, effect, "report-op", "report-event", clock.Now())
			if err := store.QueueStoryLogIntent(ctx, StoryLogIntent{EffectID: "report-effect", Entry: StoryLogEntry{
				DiceID: "dice-a", GroupID: "group-a", LogName: "session", Nickname: "Dice", IsDice: true,
				Message: "core reply", Time: 50, Seq: new(int64(7)), RawMsgID: "local-id",
			}}); err != nil {
				t.Fatal(err)
			}
			if err := store.AppendStoryLogEntry(ctx, StoryLogEntry{DiceID: "dice-a", GroupID: "group-a", LogName: "session", Message: "before", Time: 40}); err != nil {
				t.Fatal(err)
			}
			report := StoryLogEntry{
				DiceID: "dice-a", GroupID: "group-a", LogName: "session", Nickname: "Dice", IsDice: true,
				Message: "reported text", Time: 51, Seq: new(int64(9)), RawMsgID: "provider-1",
			}
			complete := func() {
				t.Helper()
				lease, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "report-worker", LeaseDuration: time.Minute})
				if err != nil {
					t.Fatal(err)
				}
				dispatched, err := store.MarkOutboxDispatched(ctx, OutboxDispatchRequest{
					EffectID: lease.Effect.EffectID, WorkerID: lease.Effect.LeaseOwner,
					LeaseEpoch: lease.Effect.LeaseEpoch, AttemptID: lease.Effect.AttemptID,
				})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := store.CompleteOutbox(ctx, OutboxCompletionRequest{
					EffectID: "report-effect", WorkerID: dispatched.Effect.LeaseOwner, LeaseEpoch: dispatched.Effect.LeaseEpoch,
					AttemptID: dispatched.Effect.AttemptID, Status: OutboxStatusSucceeded, ResultCode: "ok", ProviderMessageID: "provider-1",
				}); err != nil {
					t.Fatal(err)
				}
			}
			if reportFirst {
				if err := store.commitLogUpdate(ctx, NewStoryLogAppendOnceUpdate(report)); err != nil {
					t.Fatal(err)
				}
				complete()
			} else {
				complete()
				if err := store.commitLogUpdate(ctx, NewStoryLogAppendOnceUpdate(report)); err != nil {
					t.Fatal(err)
				}
			}
			entries, err := store.GetStoryLogEntries(ctx, "dice-a", "group-a", "session")
			if err != nil || len(entries) != 2 {
				t.Fatalf("entries = %#v err=%v, want the earlier line and exactly one entry for provider-1", entries, err)
			}
			got := entries[1]
			if got.RawMsgID != "provider-1" || got.Message != "core reply" || got.Time != 50 || got.Seq == nil || *got.Seq != 7 || !got.IsDice {
				t.Fatalf("entry = %#v, want Core's content, time and sequence under the provider id", got)
			}
		})
	}
}
