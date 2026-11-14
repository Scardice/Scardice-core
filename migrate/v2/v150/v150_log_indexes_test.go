package v150

import (
	"path/filepath"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"Scardice-core/model"
)

// TestRecreateSQLiteLogItemsTableKeepsModelIndexes_1115 锁定首启迁移的回归：
// EnsureLogSchema 先按当前模型建好 log_items（含 gap_fill / idx_log_raw），
// 随后 V150 因列数不匹配重建该表。重建前必须删掉全部同名索引，否则
// SQLite 会报 “index ... already exists”，导致新表的索引没建全。
func TestRecreateSQLiteLogItemsTableKeepsModelIndexes_1115(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "logs.db")), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get sql handle: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	// 模拟启动顺序：先用当前模型建表（会创建全部索引）。
	if err := db.Migrator().CreateTable(&model.LogOneItem{}); err != nil {
		t.Fatalf("create modern log_items: %v", err)
	}
	columns, err := loadSQLiteTableColumns(db, "log_items")
	if err != nil {
		t.Fatalf("load log_items columns: %v", err)
	}

	if err := recreateSQLiteLogItemsTable(db, columns); err != nil {
		t.Fatalf("recreate log_items: %v", err)
	}

	for _, name := range []string{
		"idx_log_items_group_id",
		"idx_log_items_log_id",
		"idx_raw_msg_id",
		"idx_log_delete_by_id",
		"idx_log_items_gap_fill",
		"idx_log_raw",
	} {
		var count int64
		if err := db.Raw(
			"SELECT COUNT(1) FROM sqlite_master WHERE type='index' AND tbl_name='log_items' AND name=?",
			name,
		).Scan(&count).Error; err != nil {
			t.Fatalf("query index %s: %v", name, err)
		}
		if count != 1 {
			t.Fatalf("index %s missing after V150 recreate (count=%d)", name, count)
		}
	}
}
