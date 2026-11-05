package dice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"Scardice-core/core/configstate"
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
		eventstore.WithProjection(configstate.ConfigProjection()),
		eventstore.WithProjection(playerstate.ModerationProjection()),
	)
	if initialize {
		if err = store.SetReadiness(ctx, eventstore.Readiness{
			Mode: "import", SchemaVersion: 2, DatabaseIdentity: banListEventStoreTestDiceID,
			CompletedAt: time.Unix(1, 0).UTC(),
		}); err != nil {
			_ = db.Close()
			t.Fatal(err)
		}
	}
	if initialize {
		configRepository := configstate.NewRepository(store)
		if _, err = configRepository.DecideAndAppend(ctx, configstate.State{}, 0, eventstore.Metadata{}, configstate.Command{
			Kind: configstate.CommandImportBaseline,
			Baseline: &configstate.Baseline{
				DiceID: banListEventStoreTestDiceID, ConfigVersion: 1,
				Base: configstate.BaseConfig{
					CommandCompatibleMode: true, MessageDelayRangeEnd: 1, UILogLimit: 100,
				},
				Rate: configstate.RateConfig{
					PersonalReplenishRate: "@every 3s", GroupReplenishRate: "@every 3s",
					PersonalBurst: 3, GroupBurst: 3, SpamSameCommandWindowSec: 30, SpamRecoveryMultiplierMax: 5,
				},
				Quit:          configstate.QuitConfig{QuitInactiveThreshold: "0s", QuitInactiveBatchSize: 10},
				Extension:     configstate.ExtensionConfig{MaxExecuteTime: 12, MaxCocCardGen: 5},
				StoryLog:      configstate.StoryLogConfig{LogSizeNoticeCount: 500},
				Advanced:      configstate.AdvancedConfig{CustomReplyCooldown: 5},
				CommandPrefix: []string{"."},
				Ban: configstate.BanConfig{
					RefuseReply: true, RefuseInvite: true, ThresholdWarn: 100, ThresholdBan: 200,
					AutoBanMinutes: 720, ScoreReducePerMinute: 1, ScoreGroupMuted: 100, ScoreGroupKicked: 200,
					ScoreTooManyCommand: 100, BanNotifyIntervalMinutes: 5,
					JointScorePercentOfGroup: 0.5, JointScorePercentOfInviter: 0.3,
				},
			},
		}); err != nil {
			_ = db.Close()
			t.Fatal(err)
		}
	}
	if _, err = store.GetReadiness(ctx); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, store
}

func newBanListEventStoreTestDice(t *testing.T, dataDir string, store eventstore.Store) (*Dice, *BanListInfo) {
	t.Helper()
	d := &Dice{
		BaseConfig:   BaseConfig{Name: banListEventStoreTestDiceID, DataDir: dataDir},
		DurableStore: store,
		Parent:       &DiceManager{},
	}
	if err := d.ReloadConfigView(context.Background()); err != nil {
		t.Fatal(err)
	}
	return d, d.Config().BanList
}

type failingModerationStore struct {
	*eventstore.GORMStore
	fail bool
}

func (s *failingModerationStore) Commit(ctx context.Context, work eventstore.UnitOfWork) (eventstore.CommitResult, error) {
	if s.fail {
		for _, stream := range work.Streams {
			if stream.Stream.AggregateType == playerstate.ModerationAggregateType {
				return eventstore.CommitResult{}, errors.New("injected moderation commit failure")
			}
		}
	}
	return s.GORMStore.Commit(ctx, work)
}

func banListEventStoreTestSecretRef(id string) string {
	stream := playerstate.ModerationStream(banListEventStoreTestDiceID, "global", id)
	return "vault:moderation-details:" + stream.AggregateID
}

func TestEventSourcedBanListPreservesDetailsAcrossRestart(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dsn := filepath.Join(root, "events.db")
	dataDir := filepath.Join(root, "dice-data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	db, store := openBanListEventStore(t, dsn, true)
	dice, list := newBanListEventStoreTestDice(t, dataDir, store)
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
		t.Fatalf("resolve moderation details: %v", err)
	}
	var restored struct {
		BanListInfoItem
		BanUpdatedAt int64 `json:"banUpdatedAt"`
	}
	if err = json.Unmarshal(secret.Value, &restored); err != nil {
		t.Fatalf("decode moderation details: %v", err)
	}
	if restored.ID != id || restored.Name != seed.Name || restored.BanUpdatedAt != seed.BanUpdatedAt ||
		!slices.Equal(restored.Times, seed.Times) || !slices.Equal(restored.Reasons, seed.Reasons) || !slices.Equal(restored.Places, seed.Places) {
		t.Fatalf("persisted details did not preserve history: %#v", restored)
	}
	if _, statErr := os.Stat(filepath.Join(dataDir, "ban-list.json")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("legacy JSON sidecar exists: stat err=%v", statErr)
	}

	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	_, reopenedStore := openBanListEventStore(t, dsn, false)
	restartedDice, restartedList := newBanListEventStoreTestDice(t, dataDir, reopenedStore)
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
	if previous, resolveErr := reopenedStore.ResolveSecret(ctx, banListEventStoreTestSecretRef(id), 1); resolveErr != nil || !bytes.Equal(previous.Value, secret.Value) {
		t.Fatalf("delete discarded moderation history: err=%v", resolveErr)
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
		t.Fatalf("restored moderation history version=%d err=%v", latest.SecretVersion, err)
	}
	var latestDetails struct {
		BanListInfoItem
		BanUpdatedAt int64 `json:"banUpdatedAt"`
	}
	if err = json.Unmarshal(latest.Value, &latestDetails); err != nil {
		t.Fatal(err)
	}
	if latestDetails.ID != id || !slices.Contains(latestDetails.Reasons, "restored") {
		t.Fatalf("re-added item details = %#v", latestDetails)
	}
}
func TestEventSourcedBanListPersistsAutomaticScore(t *testing.T) {
	root := t.TempDir()
	_, store := openBanListEventStore(t, filepath.Join(root, "events.db"), true)
	_, list := newBanListEventStoreTestDice(t, filepath.Join(root, "dice-data"), store)
	list.Loads()
	list.AddScoreBase("QQ:scored-member", 17, "QQ-Group:10", "automatic moderation", nil)

	state, err := playerstate.ReadProjectedModeration(context.Background(), store, banListEventStoreTestDiceID, "global", "QQ:scored-member")
	if err != nil || state.Score != 17 || state.Rank != int(BanRankNormal) {
		t.Fatalf("automatic score was not committed to EventStore: state=%#v err=%v", state, err)
	}
}

func TestModerationFailedCommitDoesNotPublishBusinessState(t *testing.T) {
	_, baseStore := openBanListEventStore(t, filepath.Join(t.TempDir(), "failed-commit.db"), true)
	store := &failingModerationStore{GORMStore: baseStore, fail: true}
	d, list := newBanListEventStoreTestDice(t, "", store)
	err := list.SetRankByID(d, "QQ:failed", BanRankBanned, "member", "admin", "must roll back")
	if err == nil {
		t.Fatal("moderation mutation unexpectedly committed")
	}
	if item, exists := list.GetByID("QQ:failed"); exists {
		t.Fatalf("failed moderation commit became readable: %#v", item)
	}
}

func TestModerationSnapshotTracksSameRootCreatesAndDeletes(t *testing.T) {
	_, store := openBanListEventStore(t, filepath.Join(t.TempDir(), "same-root-list.db"), true)
	d, list := newBanListEventStoreTestDice(t, "", store)
	const subjectID = "QQ:same-root"

	err := d.WithDomainExecution(context.Background(), "test-moderation-create-list", []byte(subjectID), func(transaction *DurableCallbackTransaction) error {
		messageCtx := &MsgContext{Dice: d, callbackTransaction: transaction}
		if mutateErr := list.SetRankByIDForContext(
			messageCtx, d, subjectID, BanRankBanned, "created", "admin", "same root create",
		); mutateErr != nil {
			return mutateErr
		}
		items, readErr := list.SnapshotForContext(messageCtx)
		if readErr != nil {
			return readErr
		}
		if len(items) != 1 || items[0].ID != subjectID || items[0].Rank != BanRankBanned {
			t.Fatalf("same-root create snapshot = %#v", items)
		}
		if _, exists := list.GetByID(subjectID); exists {
			t.Fatal("uncommitted same-root create leaked into committed reads")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := list.GetByID(subjectID); !exists {
		t.Fatal("committed same-root create is missing")
	}

	err = d.WithDomainExecution(context.Background(), "test-moderation-delete-list", []byte(subjectID), func(transaction *DurableCallbackTransaction) error {
		messageCtx := &MsgContext{Dice: d, callbackTransaction: transaction}
		if deleteErr := list.DeleteByIDForContext(messageCtx, d, subjectID); deleteErr != nil {
			return deleteErr
		}
		items, readErr := list.SnapshotForContext(messageCtx)
		if readErr != nil {
			return readErr
		}
		if len(items) != 0 {
			t.Fatalf("same-root delete snapshot = %#v", items)
		}
		if _, exists := list.GetByID(subjectID); !exists {
			t.Fatal("uncommitted same-root delete leaked into committed reads")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if item, exists := list.GetByID(subjectID); exists {
		t.Fatalf("committed same-root delete remains readable: %#v", item)
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

	_, list := newBanListEventStoreTestDice(t, filepath.Join(root, "dice-data"), store)
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
	dice, list := newBanListEventStoreTestDice(t, filepath.Join(root, "dice-data"), store)
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

	_, restartedList := newBanListEventStoreTestDice(t, filepath.Join(root, "restarted-data"), store)
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
	dice, list := newBanListEventStoreTestDice(t, filepath.Join(root, "dice-data"), store)
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

	_, restartedList := newBanListEventStoreTestDice(t, filepath.Join(root, "restarted-data"), store)
	restartedList.Loads()
	if err := restartedList.PersistenceError(); err == nil {
		t.Fatal("moderation projection that differs from its stream did not fail closed")
	}
	if _, exists := restartedList.GetByID(subjectID); exists {
		t.Fatal("mismatched moderation projection exposed a partial ban list")
	}
}
func TestBanListLoadFailsClosedWhenHistoryIsMissing(t *testing.T) {
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

	_, list := newBanListEventStoreTestDice(t, filepath.Join(root, "dice-data"), store)
	list.Loads()
	if err := list.PersistenceError(); err == nil {
		t.Fatal("active moderation projection without history did not fail closed")
	}
	if _, exists := list.GetByID("QQ:missing-secret"); exists {
		t.Fatal("projection without history populated a partial ban list")
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
	_, store := openBanListEventStore(t, filepath.Join(t.TempDir(), "delete-friend.db"), true)
	d, _ := newBanListEventStoreTestDice(t, "", store)
	updateCanonicalTestConfig(t, d, func(config *Config) {
		config.BanList.ThresholdWarn = 1
		config.BanList.ThresholdBan = 1
	})
	list := d.Config().BanList
	adapter := &banListDeleteFriendSpy{}
	ctx := &MsgContext{Dice: d, EndPoint: &EndPointInfo{
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
	_, store := openBanListEventStore(t, filepath.Join(t.TempDir(), "ordering.db"), true)
	d, list := newBanListEventStoreTestDice(t, "", store)
	if err := list.ImportItems(d, []*BanListInfoItem{
		{ID: "QQ:older", Rank: BanRankNormal, BanUpdatedAt: 1},
		{ID: "QQ:newer", Rank: BanRankTrusted, BanUpdatedAt: 100},
	}); err != nil {
		t.Fatal(err)
	}
	if err := list.SetTrustByIDWithError("QQ:older", "admin", "manual trust"); err != nil {
		t.Fatal(err)
	}
	item, ok := list.GetByID("QQ:older")
	if !ok || item.BanUpdatedAt <= 100 {
		t.Fatalf("trust update ordering timestamp = %#v, exists=%v", item, ok)
	}
	ordered := list.Snapshot()
	if len(ordered) != 2 || ordered[0].ID != "QQ:older" {
		t.Fatalf("trust update did not move the item to the top: %#v", ordered)
	}
}
