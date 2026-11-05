package service_test

import (
	"path/filepath"
	"regexp"
	"testing"

	"gorm.io/gorm"

	"Scardice-core/model"
)

func newLogInfoTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	dbPath := filepath.ToSlash(filepath.Join(t.TempDir(), "log-info.db"))
	db, err := openLogInfoTestDB(dbPath)
	if err != nil {
		t.Fatalf("open sqlite db: %v", err)
	}
	if migrateErr := db.AutoMigrate(&model.LogInfo{}, &model.LogOneItem{}); migrateErr != nil {
		t.Fatalf("migrate log tables: %v", migrateErr)
	}
	sqlDB, dbErr := db.DB()
	if dbErr != nil {
		t.Fatalf("get sql db: %v", dbErr)
	}
	t.Cleanup(func() {
		_ = sqlDB.Close()
	})
	return db
}

func TestLogModelCreatesCompositeRawMsgIDIndexOnSQLite(t *testing.T) {
	db := newLogInfoTestDB(t)

	type sqliteIndexInfo struct {
		Name string `gorm:"column:name"`
		SQL  string `gorm:"column:sql"`
	}
	var indexes []sqliteIndexInfo
	if err := db.Raw("SELECT name, sql FROM sqlite_master WHERE type = 'index' AND tbl_name = 'log_items'").Scan(&indexes).Error; err != nil {
		t.Fatalf("query sqlite indexes: %v", err)
	}

	var found bool
	for _, idx := range indexes {
		if idx.Name != "idx_log_delete_by_id" {
			continue
		}
		found = true
		if !regexp.MustCompile("(?i)[(`]?group_id[)`]?,\\s*[(`]?raw_msg_id[)`]?,\\s*[(`]?id[)`]?").MatchString(idx.SQL) {
			t.Fatalf("idx_log_delete_by_id sql = %q, want composite (group_id, raw_msg_id, id)", idx.SQL)
		}
	}
	if !found {
		t.Fatal("expected idx_log_delete_by_id to exist on log_items")
	}
}
