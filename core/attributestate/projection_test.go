package attributestate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"testing"

	"Scardice-core/eventstore"
)

func attributeProjectionTestStore(t *testing.T) (*eventstore.GORMStore, *eventstore.Database) {
	t.Helper()
	database, err := eventstore.OpenDatabase(context.Background(), eventstore.DatabaseConfig{
		Type: "sqlite",
		DSN:  filepath.Join(t.TempDir(), "attributes.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return eventstore.NewStore(database, eventstore.WithProjection(Projection())), database
}

func projectedTestState(diceID, id string) State {
	return State{
		Version:       1,
		DiceID:        diceID,
		ID:            id,
		SecretRef:     "vault:" + diceID + ":" + id,
		SecretVersion: 1,
	}
}

func appendProjectedTestState(t *testing.T, store *eventstore.GORMStore, sequence int, state State) {
	t.Helper()
	payload, err := MarshalBaselineImportedV1(NewBaselineImportedV1(state))
	if err != nil {
		t.Fatal(err)
	}
	identity := fmt.Sprintf("attribute-projection-%d", sequence)
	_, err = store.Commit(context.Background(), eventstore.UnitOfWork{Streams: []eventstore.StreamAppend{{
		Stream: Stream(state.DiceID, state.ID),
		Events: []eventstore.NewEvent{{
			EventType:     EventBaselineImported,
			SchemaVersion: EventSchemaVersion,
			Payload:       payload,
			Metadata: eventstore.Metadata{
				EventID: identity, CommandID: identity + "-command", CorrelationID: identity + "-correlation",
				OccurredAtUnixNanoUTC: int64(sequence + 1), OccurredAtUnixNanoSet: true,
			},
		}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
}

func sortedProjectedIDs(states []State) []string {
	ids := make([]string, len(states))
	for index, state := range states {
		ids[index] = state.ID
	}
	sort.Strings(ids)
	return ids
}

func TestListProjectedUsesExactDiceRangeAndStablePages(t *testing.T) {
	store, database := attributeProjectionTestStore(t)
	defer database.Close()

	states := []State{
		projectedTestState("a", "aa"),
		projectedTestState("a", ":%_雪"),
		projectedTestState("a1", "prefix-collision"),
		projectedTestState("A", "case-collision"),
		projectedTestState("骰:%_", "special:/%_雪"),
	}
	for index, state := range states {
		appendProjectedTestState(t, store, index, state)
	}

	snapshot, err := ValidateProjected(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Generation == "" {
		t.Fatal("validated snapshot has no generation")
	}

	cursor := ""
	got := make([]State, 0, 2)
	pages := 0
	for {
		page, pageErr := ListProjectedPage(context.Background(), store, ProjectedPageRequest{
			DiceID:           "a",
			AfterRowKey:      cursor,
			Limit:            1,
			ExpectedSnapshot: &snapshot,
		})
		if pageErr != nil {
			t.Fatal(pageErr)
		}
		pages++
		if page.Snapshot != snapshot {
			t.Fatalf("page snapshot = %+v, want %+v", page.Snapshot, snapshot)
		}
		if page.Done {
			if len(page.States) != 0 || page.NextRowKey != cursor {
				t.Fatalf("terminal page = %+v, cursor = %q", page, cursor)
			}
			break
		}
		if len(page.States) != 1 || page.NextRowKey == cursor {
			t.Fatalf("bounded page = %+v", page)
		}
		got = append(got, page.States...)
		cursor = page.NextRowKey
	}
	if want := []string{":%_雪", "aa"}; fmt.Sprint(sortedProjectedIDs(got)) != fmt.Sprint(want) {
		t.Fatalf("paged IDs = %v, want %v", sortedProjectedIDs(got), want)
	}
	if pages != 3 {
		t.Fatalf("page calls = %d, want two data pages plus empty terminal page", pages)
	}

	listed, err := ListProjected(context.Background(), store, "a")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{":%_雪", "aa"}; fmt.Sprint(sortedProjectedIDs(listed)) != fmt.Sprint(want) {
		t.Fatalf("listed IDs = %v, want %v", sortedProjectedIDs(listed), want)
	}
	special, err := ListProjected(context.Background(), store, "骰:%_")
	if err != nil || len(special) != 1 || special[0].ID != "special:/%_雪" {
		t.Fatalf("special Dice scope = %+v, error = %v", special, err)
	}
}

func TestProjectedGlobalValidationRemainsSeparateFromScopedRead(t *testing.T) {
	store, database := attributeProjectionTestStore(t)
	defer database.Close()
	for index, state := range []State{
		projectedTestState("dice-a", "aa"),
		projectedTestState("dice-a", "zz"),
		projectedTestState("dice-b", "bb"),
	} {
		appendProjectedTestState(t, store, index, state)
	}

	other := Stream("dice-b", "bb")
	if err := database.GORM().Table("projection_read_models").
		Where("projection_name = ? AND row_key = ?", ProjectionName, other.AggregateID).
		Update("payload", []byte("{")).Error; err != nil {
		t.Fatal(err)
	}

	states, err := ListProjected(context.Background(), store, "dice-a")
	if err != nil || fmt.Sprint(sortedProjectedIDs(states)) != fmt.Sprint([]string{"aa", "zz"}) {
		t.Fatalf("scoped states = %+v, error = %v", states, err)
	}
	if snapshot, validateErr := ValidateProjected(context.Background(), store); !errors.Is(validateErr, ErrInvalidState) || snapshot != (eventstore.ProjectionSnapshot{}) {
		t.Fatalf("global validation snapshot = %+v, error = %v", snapshot, validateErr)
	}
}

func TestListProjectedRejectsCorruptScopedRowsWithoutPartialResult(t *testing.T) {
	validMismatch, err := json.Marshal(projectedTestState("dice-a", "yy"))
	if err != nil {
		t.Fatal(err)
	}
	emptyID := projectedTestState("dice-a", "")
	emptyID.SecretRef = "vault:empty"
	emptyPayload, err := json.Marshal(emptyID)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		payload []byte
	}{
		{name: "malformed JSON", payload: []byte("{")},
		{name: "empty attribute ID", payload: emptyPayload},
		{name: "row key mismatch", payload: validMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, database := attributeProjectionTestStore(t)
			defer database.Close()
			appendProjectedTestState(t, store, 0, projectedTestState("dice-a", "aa"))
			appendProjectedTestState(t, store, 1, projectedTestState("dice-a", "zz"))

			corrupt := Stream("dice-a", "zz")
			if err := database.GORM().Table("projection_read_models").
				Where("projection_name = ? AND row_key = ?", ProjectionName, corrupt.AggregateID).
				Update("payload", tc.payload).Error; err != nil {
				t.Fatal(err)
			}
			states, listErr := ListProjected(context.Background(), store, "dice-a")
			if !errors.Is(listErr, ErrInvalidState) {
				t.Fatalf("corrupt scoped row error = %v", listErr)
			}
			if states != nil {
				t.Fatalf("corrupt scoped read returned partial states: %+v", states)
			}
		})
	}
}

func TestValidatedProjectionSnapshotFencesPrivacyChangeBeforeScopedPage(t *testing.T) {
	store, database := attributeProjectionTestStore(t)
	defer database.Close()
	appendProjectedTestState(t, store, 0, projectedTestState("dice-a", "aa"))
	appendProjectedTestState(t, store, 1, projectedTestState("dice-a", "zz"))

	snapshot, err := ValidateProjected(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	first, err := ListProjectedPage(context.Background(), store, ProjectedPageRequest{
		DiceID:           "dice-a",
		Limit:            1,
		ExpectedSnapshot: &snapshot,
	})
	if err != nil || first.Done || len(first.States) != 1 {
		t.Fatalf("first scoped page = %+v, error = %v", first, err)
	}

	tx := database.GORM().Begin()
	if tx.Error != nil {
		t.Fatal(tx.Error)
	}
	removed := Stream("dice-a", "zz")
	if err := tx.Table("projection_read_models").Where("projection_name = ? AND row_key = ?", ProjectionName, removed.AggregateID).Delete(&projectionRow{}).Error; err != nil {
		_ = tx.Rollback().Error
		t.Fatal(err)
	}
	if err := tx.Table("projection_control").Where("singleton_id = ?", "default").Update("history_revision", snapshot.HistoryRevision+1).Error; err != nil {
		_ = tx.Rollback().Error
		t.Fatal(err)
	}
	if err := tx.Commit().Error; err != nil {
		t.Fatal(err)
	}

	next, err := ListProjectedPage(context.Background(), store, ProjectedPageRequest{
		DiceID:           "dice-a",
		AfterRowKey:      first.NextRowKey,
		Limit:            1,
		ExpectedSnapshot: &snapshot,
	})
	if !errors.Is(err, eventstore.ErrParticipantConflict) {
		t.Fatalf("privacy-changed page error = %v", err)
	}
	if len(next.States) != 0 || next.NextRowKey != "" || next.Snapshot != (eventstore.ProjectionSnapshot{}) || next.Done {
		t.Fatalf("privacy conflict returned partial page: %+v", next)
	}
}

func TestCharacterMetadataListsRemainAvailableDuringLiveCommits(t *testing.T) {
	store, database := attributeProjectionTestStore(t)
	defer database.Close()
	appendProjectedTestState(t, store, 0, projectedTestState("dice-a", "character"))
	ctx := context.Background()
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		factory := eventstore.EventFactory{Clock: eventstore.SystemClock{}, IDs: eventstore.UUIDGenerator{}}
		stream := eventstore.StreamID{AggregateType: "unrelated", AggregateID: "live"}
		for version := range 64 {
			event, err := factory.NewEvent("changed", 1, json.RawMessage(`{"changed":true}`), eventstore.Metadata{})
			if err != nil {
				done <- err
				return
			}
			if _, err = store.Commit(ctx, eventstore.UnitOfWork{Streams: []eventstore.StreamAppend{{
				Stream: stream, ExpectedVersion: uint64(version), Events: []eventstore.NewEvent{event},
			}}}); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	<-started
	var listErr error
	for range 64 {
		states, err := ListProjected(ctx, store, "dice-a")
		if err != nil {
			listErr = err
			break
		}
		if len(states) != 1 || states[0].ID != "character" {
			listErr = fmt.Errorf("character metadata changed during unrelated commits: %+v", states)
			break
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if listErr != nil {
		t.Fatal(listErr)
	}
}
