package dice

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"Scardice-core/dice/service"
	"Scardice-core/utils/dboperator/engine/sqlite"
)

func TestExpiredBanDeletionSerializesWithRankUpdate(t *testing.T) {
	operator := &sqlite.SQLiteEngine{DataDir: t.TempDir()}
	if err := operator.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer operator.Close()

	runtime := &Dice{Parent: &DiceManager{}, DBOperator: operator}
	list := &BanListInfo{Parent: runtime}
	list.Init()
	runtime.Config.BanList = list
	const id = "QQ:decay-race"
	item := &BanListInfoItem{ID: id, Rank: BanRankNormal, Score: 1, UpdatedAt: 1, BanUpdatedAt: 1}
	list.Map.Store(id, item)
	data, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	if err = service.BanItemSave(operator, id, item.UpdatedAt, item.BanUpdatedAt, data); err != nil {
		t.Fatal(err)
	}

	deleteStarted := make(chan struct{})
	releaseDelete := make(chan struct{})
	decayDone := make(chan error, 1)
	go func() {
		_, _, decayErr := list.decayScoresWithDelete(2, func(expiredID string) error {
			close(deleteStarted)
			<-releaseDelete
			return service.BanItemDel(operator, expiredID)
		})
		decayDone <- decayErr
	}()
	select {
	case <-deleteStarted:
	case <-time.After(time.Second):
		t.Fatal("cron deletion did not reach persistence")
	}
	if list.itemsMu.TryLock() {
		list.itemsMu.Unlock()
		t.Fatal("cron released the item lock before deleting the SQL row")
	}

	rankDone := make(chan error, 1)
	rankStarted := make(chan struct{})
	go func() {
		close(rankStarted)
		rankDone <- list.SetRankByID(runtime, id, BanRankBanned, "member", "admin", "manual ban")
	}()
	<-rankStarted
	select {
	case err = <-rankDone:
		t.Fatalf("rank update passed an in-flight cron delete: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseDelete)
	if err = <-decayDone; err != nil {
		t.Fatalf("decay and delete: %v", err)
	}
	if err = <-rankDone; err != nil {
		t.Fatalf("rank update after cron delete: %v", err)
	}

	var persisted BanListInfoItem
	found := false
	if err = service.BanItemList(operator, func(rowID string, _ int64, payload []byte) {
		if rowID == id {
			found = true
			if decodeErr := json.Unmarshal(payload, &persisted); decodeErr != nil {
				t.Errorf("decode final SQL item: %v", decodeErr)
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
	if !found || persisted.Rank != BanRankBanned {
		t.Fatalf("final SQL item = %#v, found=%v", persisted, found)
	}
	listed := runtime.GetBanList()
	if len(listed) != 1 || listed[0].ID != id || listed[0].BanUpdatedAt == 0 || listed[0].Rank != BanRankBanned {
		t.Fatalf("SQL list row lost identity, rank, or sort timestamp: %#v", listed)
	}
}
