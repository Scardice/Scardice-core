package service

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"Scardice-core/model"
	"Scardice-core/utils/constant"
	engine2 "Scardice-core/utils/dboperator/engine"
)

type mockDBOperator struct {
	db *gorm.DB
}

var _ engine2.DatabaseOperator = (*mockDBOperator)(nil)

func (m *mockDBOperator) Init(context.Context) error { return nil }
func (m *mockDBOperator) Type() string               { return "sqlite" }
func (m *mockDBOperator) DBCheck()                   {}
func (m *mockDBOperator) Close()                     {}
func (m *mockDBOperator) GetDataDB(constant.DBMode) *gorm.DB {
	return m.db
}
func (m *mockDBOperator) GetLogDB(constant.DBMode) *gorm.DB {
	return m.db
}
func (m *mockDBOperator) GetCensorDB(constant.DBMode) *gorm.DB {
	return m.db
}

func TestEndpointInfoSaveConcurrentRace(t *testing.T) {
	dsn := fmt.Sprintf("file:endpoint_info_race_%d?mode=memory&cache=shared&_busy_timeout=5000", time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite failed: %v", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get sql db failed: %v", err)
	}
	sqlDB.SetMaxOpenConns(64)
	sqlDB.SetMaxIdleConns(64)

	if err := db.AutoMigrate(&model.EndpointInfo{}); err != nil {
		t.Fatalf("auto migrate failed: %v", err)
	}

	op := &mockDBOperator{db: db}
	const (
		rounds  = 200
		workers = 32
	)

	for r := 0; r < rounds; r++ {
		if err := db.Exec("DELETE FROM endpoint_info").Error; err != nil {
			t.Fatalf("cleanup failed: %v", err)
		}

		start := make(chan struct{})
		errCh := make(chan error, workers)
		var wg sync.WaitGroup

		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				err := Save(op, &model.EndpointInfo{
					UserID:      "QQ:1234567890",
					CmdNum:      int64(i),
					CmdLastTime: time.Now().Unix(),
					OnlineTime:  int64(i),
					UpdatedAt:   time.Now().Unix(),
				})
				errCh <- err
			}(i)
		}

		close(start)
		wg.Wait()
		close(errCh)

		for err := range errCh {
			if err == nil {
				continue
			}
			if strings.Contains(err.Error(), "UNIQUE constraint failed: endpoint_info.user_id") {
				t.Fatalf("got UNIQUE constraint error after fix at round=%d: %v", r, err)
			}
			t.Fatalf("unexpected concurrent save error at round=%d: %v", r, err)
		}

		var count int64
		if err := db.Model(&model.EndpointInfo{}).Where("user_id = ?", "QQ:1234567890").Count(&count).Error; err != nil {
			t.Fatalf("count row failed at round=%d: %v", r, err)
		}
		if count != 1 {
			t.Fatalf("expect exactly one row after concurrent save at round=%d, got=%d", r, count)
		}

		var got model.EndpointInfo
		if err := db.Where("user_id = ?", "QQ:1234567890").First(&got).Error; err != nil {
			t.Fatalf("query endpoint info failed at round=%d: %v", r, err)
		}
		if got.CmdNum != workers-1 {
			t.Fatalf("expect cmd_num=%d by max-merge update at round=%d, got=%d", workers-1, r, got.CmdNum)
		}
	}
}
