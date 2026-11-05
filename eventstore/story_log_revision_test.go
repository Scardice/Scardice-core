package eventstore

import (
	"context"
	"errors"
	"testing"
)

func TestStoryLogStateSnapshotRevisionRejectsStaleMutation(t *testing.T) {
	ctx := context.Background()
	store, db := openLogArchiveTestStore(t, t.TempDir()+"/story-revision.db")
	defer db.Close()

	state, dependency, err := store.GetStoryLogStateSnapshot(ctx, "dice", "group")
	if err != nil {
		t.Fatal(err)
	}
	if state.DiceID != "dice" || state.GroupID != "group" || dependency.Catalog != storyLogRevisionCatalog || dependency.Owner == "" || dependency.ExpectedRevision != 0 {
		t.Fatalf("missing-state snapshot=%#v dependency=%#v", state, dependency)
	}
	first := StoryLogState{DiceID: "dice", GroupID: "group", BaselineSeq: 1}
	if _, err = store.Commit(ctx, UnitOfWork{
		CatalogReads: []CatalogReadExpectation{dependency},
		LogUpdates:   []LogUpdate{{Kind: logUpdateSetState, DiceID: "dice", GroupID: "group", State: first}},
	}); err != nil {
		t.Fatal(err)
	}
	_, stale, err := store.GetStoryLogStateSnapshot(ctx, "dice", "group")
	if err != nil {
		t.Fatal(err)
	}
	if stale.ExpectedRevision != 1 {
		t.Fatalf("revision after first mutation=%d, want 1", stale.ExpectedRevision)
	}
	if err = store.SetStoryLogState(ctx, StoryLogState{DiceID: "dice", GroupID: "group", BaselineSeq: 2}); err != nil {
		t.Fatal(err)
	}
	_, err = store.Commit(ctx, UnitOfWork{
		CatalogReads: []CatalogReadExpectation{stale},
		LogUpdates: []LogUpdate{{
			Kind: logUpdateSetState, DiceID: "dice", GroupID: "group",
			State: StoryLogState{DiceID: "dice", GroupID: "group", BaselineSeq: 3},
		}},
	})
	if !errors.Is(err, ErrParticipantConflict) {
		t.Fatalf("stale Story mutation err=%v, want conflict", err)
	}
}

func TestStoryLogStateSelectedByNameBindsSessionCreatedInSameUnit(t *testing.T) {
	ctx := context.Background()
	store, db := openLogArchiveTestStore(t, t.TempDir()+"/story-by-name.db")
	defer db.Close()

	_, dependency, err := store.GetStoryLogStateSnapshot(ctx, "dice", "group")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Commit(ctx, UnitOfWork{
		CatalogReads: []CatalogReadExpectation{dependency},
		LogUpdates: []LogUpdate{
			NewStoryLogCreateSessionUpdate("dice", "group", "fresh"),
			NewStoryLogStateUpdate(StoryLogState{DiceID: "dice", GroupID: "group", Name: "fresh", On: true, BaselineSeq: 4}),
			NewStoryLogStateUpdate(StoryLogState{DiceID: "dice", GroupID: "group", Name: "fresh", On: false, BaselineSeq: 5}),
		},
	}); err != nil {
		t.Fatalf("commit session creation with by-name state: %v", err)
	}
	sessions, err := store.ListStoryLogs(ctx, "dice", "group")
	if err != nil || len(sessions) != 1 || sessions[0].Name != "fresh" {
		t.Fatalf("sessions=%#v err=%v", sessions, err)
	}
	state, err := store.GetStoryLogState(ctx, "dice", "group")
	if err != nil {
		t.Fatal(err)
	}
	if state.SessionID != sessions[0].ID || state.Name != "fresh" || state.On || state.BaselineSeq != 5 {
		t.Fatalf("state=%#v, want the created session %d selected, off, baseline 5", state, sessions[0].ID)
	}

	if _, err = store.Commit(ctx, UnitOfWork{LogUpdates: []LogUpdate{
		NewStoryLogStateUpdate(StoryLogState{DiceID: "dice", GroupID: "group", Name: "absent", On: true}),
	}}); err == nil {
		t.Fatal("by-name state for a missing session was committed")
	}
}
