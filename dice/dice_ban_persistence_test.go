package dice

import (
	"sync"
	"testing"
)

func TestBanListSnapshotsAreSafeDuringConcurrentMutations(t *testing.T) {
	manager := &DiceManager{}
	d := &Dice{Parent: manager}
	banList := &BanListInfo{Parent: d}
	banList.Init()
	d.Config.BanList = banList
	const (
		writers    = 4
		readers    = 4
		iterations = 300
		userID     = "QQ:concurrent"
	)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for worker := range writers + readers {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			<-start
			for n := range iterations {
				if worker < writers {
					switch worker % 3 {
					case 0:
						banList.AddScoreBase(userID, 1, "test", "score", nil)
					case 1:
						banList.SetTrustByID(userID, "test", "trust")
					case 2:
						banList.decayScores(int64(n))
					}
					continue
				}
				for _, item := range banList.Snapshot() {
					_ = item.Score
					_ = len(item.Reasons)
					_ = len(item.Places)
				}
				if item, ok := banList.GetByID(userID); ok {
					_ = item.Rank
					_ = len(item.Times)
				}
			}
		}(worker)
	}
	close(start)
	wg.Wait()
}
