package dice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"Scardice-core/core/playerstate"
	"Scardice-core/eventstore"
)

const banListEventStoreTestDiceID = "ban-list-eventstore-test"

func openBanListEventStore(t *testing.T, dsn string, initialize bool) (*eventstore.Database, *eventstore.GORMStore) {
	t.Helper()
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{
		Type: "sqlite", DSN: dsn, DatabaseIdentity: banListEventStoreTestDiceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	store := eventstore.NewStore(db,
		eventstore.WithKeySource(compatKeySource{}),
		eventstore.WithProjection(playerstate.ModerationProjection()),
	)
	if initialize {
		if err = store.SetReadiness(ctx, eventstore.Readiness{
			Mode: "import", SchemaVersion: 1, DatabaseIdentity: banListEventStoreTestDiceID,
			IndexRootID: "index-v1", EncryptionRootIDs: []string{"root-v1"},
			SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32),
			CompletedAt: time.Unix(1, 0).UTC(),
		}); err != nil {
			_ = db.Close()
			t.Fatal(err)
		}
	}
	if err = store.ValidateReadiness(ctx); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, store
}

func newBanListEventStoreTestDice(dataDir string, store eventstore.Store) (*Dice, *BanListInfo) {
	d := &Dice{
		BaseConfig:   BaseConfig{Name: banListEventStoreTestDiceID, DataDir: dataDir},
		DurableStore: store,
		Parent:       &DiceManager{},
	}
	list := &BanListInfo{Parent: d}
	list.Init()
	d.Config.BanList = list
	return d, list
}

func banListEventStoreTestSecretRef(id string) string {
	stream := playerstate.ModerationStream(banListEventStoreTestDiceID, "global", id)
	digest := sha256.Sum256([]byte(stream.AggregateID))
	return "vault:moderation-details:" + hex.EncodeToString(digest[:16])
}

func TestEventSourcedBanListUsesEncryptedEventStoreAcrossRestart(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dsn := filepath.Join(root, "events.db")
	dataDir := filepath.Join(root, "dice-data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	db, store := openBanListEventStore(t, dsn, true)
	dice, list := newBanListEventStoreTestDice(dataDir, store)
	list.Loads()
	if err := list.PersistenceError(); err != nil {
		t.Fatalf("load empty EventStore list: %v", err)
	}

	const id = "QQ:secret-member"
	seed := &BanListInfoItem{
		ID: id, Name: "Private Member", Rank: BanRankBanned, Score: 240,
		Times: []int64{11, 22}, Reasons: []string{"first private reason", "second private reason"},
		Places: []string{"QQ-Group:10", "QQ-Group:20"}, BanTime: 10, BanUpdatedAt: 23,
	}
	if err := list.ImportItems(dice, []*BanListInfoItem{seed}); err != nil {
		t.Fatalf("import ban item: %v", err)
	}

	state, err := playerstate.ReadProjectedModeration(ctx, store, banListEventStoreTestDiceID, "global", id)
	if err != nil || state.Version == 0 || state.Rank != int(BanRankBanned) || state.Score != 240 || state.Deleted {
		t.Fatalf("projected moderation = %#v, err=%v", state, err)
	}
	secret, err := store.ResolveSecret(ctx, banListEventStoreTestSecretRef(id), 1)
	if err != nil {
		t.Fatalf("resolve encrypted moderation details: %v", err)
	}
	var restored struct {
		BanListInfoItem
		BanUpdatedAt int64 `json:"banUpdatedAt"`
	}
	if err = json.Unmarshal(secret.Plaintext, &restored); err != nil {
		t.Fatalf("decode moderation details: %v", err)
	}
	if restored.ID != id || restored.Name != seed.Name || restored.BanUpdatedAt != seed.BanUpdatedAt ||
		!slices.Equal(restored.Times, seed.Times) || !slices.Equal(restored.Reasons, seed.Reasons) || !slices.Equal(restored.Places, seed.Places) {
		t.Fatalf("encrypted details did not preserve history: %#v", restored)
	}
	if data, readErr := os.ReadFile(dsn); readErr != nil {
		t.Fatal(readErr)
	} else if bytes.Contains(data, []byte(seed.Name)) || bytes.Contains(data, []byte(seed.Reasons[0])) {
		t.Fatal("moderation details were stored in plaintext in the EventStore database")
	}
	if _, statErr := os.Stat(filepath.Join(dataDir, "ban-list.json")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("legacy JSON sidecar exists: stat err=%v", statErr)
	}

	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	_, reopenedStore := openBanListEventStore(t, dsn, false)
	restartedDice, restartedList := newBanListEventStoreTestDice(dataDir, reopenedStore)
	restartedList.Loads()
	if err = restartedList.PersistenceError(); err != nil {
		t.Fatalf("load EventStore list after restart: %v", err)
	}
	got, ok := restartedList.GetByID(id)
	if !ok || got.Name != seed.Name || got.Score != seed.Score || got.BanUpdatedAt != seed.BanUpdatedAt ||
		!slices.Equal(got.Times, seed.Times) || !slices.Equal(got.Reasons, seed.Reasons) || !slices.Equal(got.Places, seed.Places) {
		t.Fatalf("restored item = %#v, exists=%v", got, ok)
	}

	if err = restartedList.DeleteByIDWithError(restartedDice, id); err != nil {
		t.Fatalf("delete EventStore ban item: %v", err)
	}
	state, err = playerstate.ReadProjectedModeration(ctx, reopenedStore, banListEventStoreTestDiceID, "global", id)
	if err != nil || !state.Deleted {
		t.Fatalf("deleted moderation state = %#v, err=%v", state, err)
	}
	if previous, resolveErr := reopenedStore.ResolveSecret(ctx, banListEventStoreTestSecretRef(id), 1); resolveErr != nil || !bytes.Equal(previous.Plaintext, secret.Plaintext) {
		t.Fatalf("delete discarded encrypted history: err=%v", resolveErr)
	}
	if err = restartedList.SetRankByID(restartedDice, id, BanRankTrusted, seed.Name, "admin", "restored"); err != nil {
		t.Fatalf("restore EventStore ban item: %v", err)
	}
	state, err = playerstate.ReadProjectedModeration(ctx, reopenedStore, banListEventStoreTestDiceID, "global", id)
	if err != nil || state.Deleted || state.Rank != int(BanRankTrusted) {
		t.Fatalf("restored moderation state = %#v, err=%v", state, err)
	}
	latest, err := reopenedStore.ResolveSecret(ctx, banListEventStoreTestSecretRef(id), 0)
	if err != nil || latest.SecretVersion != 2 {
		t.Fatalf("restored encrypted history version=%d err=%v", latest.SecretVersion, err)
	}
	var latestDetails struct {
		BanListInfoItem
		BanUpdatedAt int64 `json:"banUpdatedAt"`
	}
	if err = json.Unmarshal(latest.Plaintext, &latestDetails); err != nil {
		t.Fatal(err)
	}
	if latestDetails.ID != id || !slices.Contains(latestDetails.Reasons, "restored") {
		t.Fatalf("re-added item details = %#v", latestDetails)
	}
}
func TestEventSourcedBanListPersistsAutomaticScore(t *testing.T) {
	root := t.TempDir()
	_, store := openBanListEventStore(t, filepath.Join(root, "events.db"), true)
	_, list := newBanListEventStoreTestDice(filepath.Join(root, "dice-data"), store)
	list.Loads()
	list.AddScoreBase("QQ:scored-member", 17, "QQ-Group:10", "automatic moderation", nil)

	state, err := playerstate.ReadProjectedModeration(context.Background(), store, banListEventStoreTestDiceID, "global", "QQ:scored-member")
	if err != nil || state.Score != 17 || state.Rank != int(BanRankNormal) {
		t.Fatalf("automatic score was not committed to EventStore: state=%#v err=%v", state, err)
	}
}

func TestEventSourcedBanListRejectsStaleWriters(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	_, store := openBanListEventStore(t, filepath.Join(root, "events.db"), true)
	firstDice, firstList := newBanListEventStoreTestDice(filepath.Join(root, "first"), store)
	firstList.Loads()
	const subjectID = "QQ:shared-writer"
	if err := firstList.SetRankByID(firstDice, subjectID, BanRankNormal, "Member", "seed", "initial"); err != nil {
		t.Fatal(err)
	}

	secondDice, secondList := newBanListEventStoreTestDice(filepath.Join(root, "second"), store)
	secondList.Loads()
	staleItem, exists := secondList.GetByID(subjectID)
	if !exists {
		t.Fatal("second runtime did not load the seeded moderation item")
	}
	if err := firstList.SetRankByID(firstDice, subjectID, BanRankBanned, "Member", "admin", "latest change"); err != nil {
		t.Fatal(err)
	}
	if err := secondList.SetRankByID(secondDice, subjectID, BanRankWarn, "Member", "stale admin", "stale change"); !errors.Is(err, eventstore.ErrConflict) {
		t.Fatalf("stale rank update error = %v, want EventStore conflict", err)
	}

	repository, err := newModerationBanRepository(secondDice)
	if err != nil {
		t.Fatal(err)
	}
	if err = repository.delete(ctx, staleItem); !errors.Is(err, eventstore.ErrConflict) {
		t.Fatalf("stale delete error = %v, want EventStore conflict", err)
	}
	if err = repository.setScore(ctx, staleItem, 1); !errors.Is(err, eventstore.ErrConflict) {
		t.Fatalf("stale score update error = %v, want EventStore conflict", err)
	}

	_, restartedList := newBanListEventStoreTestDice(filepath.Join(root, "restarted"), store)
	restartedList.Loads()
	latest, exists := restartedList.GetByID(subjectID)
	if !exists || latest.Rank != BanRankBanned || slices.Contains(latest.Reasons, "stale change") {
		t.Fatalf("stale writer changed persisted moderation state: item=%#v exists=%v", latest, exists)
	}
}
func TestBanListLoadFailsClosedOnCorruptEventProjection(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	db, store := openBanListEventStore(t, filepath.Join(root, "events.db"), true)
	repository := playerstate.NewRepository(store)
	if _, err := repository.AppendModerationTyped(ctx, banListEventStoreTestDiceID, "global", "QQ:corrupt", 0,
		eventstore.Metadata{CommandID: "seed-corrupt-projection", CorrelationID: "seed-corrupt-projection", OccurredAt: time.Unix(1, 0).UTC()},
		[]playerstate.ModerationEvent{playerstate.NewModerationCreatedV1(banListEventStoreTestDiceID, "global", "QQ:corrupt", int(BanRankBanned), 200)},
	); err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Table("projection_read_models").
		Where("projection_name = ?", playerstate.ModerationProjectionName).
		Update("payload", []byte("{")).Error; err != nil {
		t.Fatal(err)
	}

	_, list := newBanListEventStoreTestDice(filepath.Join(root, "dice-data"), store)
	list.Loads()
	if err := list.PersistenceError(); err == nil {
		t.Fatal("corrupt EventStore moderation projection did not fail closed")
	}
	if _, exists := list.GetByID("QQ:corrupt"); exists {
		t.Fatal("corrupt projection populated a partial ban list")
	}
}

func TestBanListLoadFailsClosedWhenProjectionRowIsMissing(t *testing.T) {
	root := t.TempDir()
	db, store := openBanListEventStore(t, filepath.Join(root, "events.db"), true)
	dice, list := newBanListEventStoreTestDice(filepath.Join(root, "dice-data"), store)
	const subjectID = "QQ:projection-row-missing"
	if err := list.SetRankByID(dice, subjectID, BanRankBanned, "Private Member", "seed", "seed reason"); err != nil {
		t.Fatal(err)
	}
	stream := playerstate.ModerationStream(banListEventStoreTestDiceID, "global", subjectID)
	if err := db.GORM().Exec(
		"DELETE FROM projection_read_models WHERE projection_name = ? AND row_key = ?",
		playerstate.ModerationProjectionName, stream.AggregateID,
	).Error; err != nil {
		t.Fatal(err)
	}

	_, restartedList := newBanListEventStoreTestDice(filepath.Join(root, "restarted-data"), store)
	restartedList.Loads()
	if err := restartedList.PersistenceError(); err == nil {
		t.Fatal("missing moderation projection row did not fail closed")
	}
	if _, exists := restartedList.GetByID(subjectID); exists {
		t.Fatal("missing moderation projection row exposed a partial ban list")
	}
}

func TestBanListLoadFailsClosedOnProjectionStateMismatch(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	db, store := openBanListEventStore(t, filepath.Join(root, "events.db"), true)
	dice, list := newBanListEventStoreTestDice(filepath.Join(root, "dice-data"), store)
	const subjectID = "QQ:projection-state-mismatch"
	if err := list.SetRankByID(dice, subjectID, BanRankBanned, "Private Member", "seed", "seed reason"); err != nil {
		t.Fatal(err)
	}
	state, err := playerstate.ReadProjectedModeration(ctx, store, banListEventStoreTestDiceID, "global", subjectID)
	if err != nil {
		t.Fatal(err)
	}
	state.Score++
	payload, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	stream := playerstate.ModerationStream(banListEventStoreTestDiceID, "global", subjectID)
	if err := db.GORM().Exec(
		"UPDATE projection_read_models SET payload = ? WHERE projection_name = ? AND row_key = ?",
		payload, playerstate.ModerationProjectionName, stream.AggregateID,
	).Error; err != nil {
		t.Fatal(err)
	}

	_, restartedList := newBanListEventStoreTestDice(filepath.Join(root, "restarted-data"), store)
	restartedList.Loads()
	if err := restartedList.PersistenceError(); err == nil {
		t.Fatal("moderation projection that differs from its stream did not fail closed")
	}
	if _, exists := restartedList.GetByID(subjectID); exists {
		t.Fatal("mismatched moderation projection exposed a partial ban list")
	}
}
func TestBanListLoadFailsClosedWhenEncryptedHistoryIsMissing(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	_, store := openBanListEventStore(t, filepath.Join(root, "events.db"), true)
	repository := playerstate.NewRepository(store)
	if _, err := repository.AppendModerationTyped(ctx, banListEventStoreTestDiceID, "global", "QQ:missing-secret", 0,
		eventstore.Metadata{CommandID: "seed-missing-secret", CorrelationID: "seed-missing-secret", OccurredAt: time.Unix(1, 0).UTC()},
		[]playerstate.ModerationEvent{playerstate.NewModerationCreatedV1(banListEventStoreTestDiceID, "global", "QQ:missing-secret", int(BanRankBanned), 200)},
	); err != nil {
		t.Fatal(err)
	}

	_, list := newBanListEventStoreTestDice(filepath.Join(root, "dice-data"), store)
	list.Loads()
	if err := list.PersistenceError(); err == nil {
		t.Fatal("active moderation projection without encrypted history did not fail closed")
	}
	if _, exists := list.GetByID("QQ:missing-secret"); exists {
		t.Fatal("projection without encrypted history populated a partial ban list")
	}
}

type banListDeleteFriendSpy struct {
	PlatformAdapter
	deletedID string
}

func (s *banListDeleteFriendSpy) DeleteFriend(_ *MsgContext, id string) {
	s.deletedID = id
}

func TestAddScoreBaseDeletesQQPersonNotPlace(t *testing.T) {
	_, list := newBanListEventStoreTestDice("", nil)
	list.ThresholdWarn = 1
	list.ThresholdBan = 1
	adapter := &banListDeleteFriendSpy{}
	ctx := &MsgContext{EndPoint: &EndPointInfo{
		EndPointInfoBase: EndPointInfoBase{Platform: "QQ"},
		Adapter:          adapter,
	}}
	const userID, place = "QQ:person-123", "QQ-Group:group-456"

	list.AddScoreBase(userID, 1, place, "threshold reached", ctx)
	if adapter.deletedID != userID {
		t.Fatalf("DeleteFriend target = %q, want person ID %q", adapter.deletedID, userID)
	}
}

func TestSetTrustRefreshesBanListOrderingTimestamp(t *testing.T) {
	list := &BanListInfo{}
	list.Init()
	list.Map.Store("QQ:older", &BanListInfoItem{ID: "QQ:older", Rank: BanRankNormal, BanUpdatedAt: 1})
	list.Map.Store("QQ:newer", &BanListInfoItem{ID: "QQ:newer", Rank: BanRankTrusted, BanUpdatedAt: 100})

	list.SetTrustByID("QQ:older", "admin", "manual trust")
	item, ok := list.GetByID("QQ:older")
	if !ok || item.BanUpdatedAt <= 100 {
		t.Fatalf("trust update ordering timestamp = %#v, exists=%v", item, ok)
	}
	ordered := list.Snapshot()
	if len(ordered) != 2 || ordered[0].ID != "QQ:older" {
		t.Fatalf("trust update did not move the item to the top: %#v", ordered)
	}
}
