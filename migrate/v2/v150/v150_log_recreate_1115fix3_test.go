package v150

import (
	"path/filepath"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"Scardice-core/model"
)

// 1115.fix3 回归：V150 重建 log_items 时必须保留 seq / is_gap_fill。
// 备份恢复（data-only，无 upgrade_metadata.json）会重跑 V150；旧实现只复制
// 14 个期望列，会把这些值清空。

func openFix3LogDB(t *testing.T) *gorm.DB {
	t.Helper()
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
	return db
}

func TestRecreateSQLiteLogItemsTablePreservesSeqAndGapFill_1115fix3(t *testing.T) {
	db := openFix3LogDB(t)
	if err := db.Migrator().CreateTable(&model.LogOneItem{}); err != nil {
		t.Fatalf("create modern log_items: %v", err)
	}
	seq := int64(12345)
	if err := db.Create(&model.LogOneItem{
		LogID: 1, GroupID: "QQ-Group:fix3", Nickname: "玩家", Message: "m",
		RawMsgID: "m-1", Seq: &seq, IsGapFill: true,
	}).Error; err != nil {
		t.Fatalf("insert row: %v", err)
	}

	columns, err := loadSQLiteTableColumns(db, "log_items")
	if err != nil {
		t.Fatalf("load columns: %v", err)
	}
	if err := recreateSQLiteLogItemsTable(db, columns); err != nil {
		t.Fatalf("recreate log_items: %v", err)
	}

	var got model.LogOneItem
	if err := db.First(&got).Error; err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got.Seq == nil || *got.Seq != seq {
		t.Fatalf("seq after recreate = %v, want %d", got.Seq, seq)
	}
	if !got.IsGapFill {
		t.Fatal("is_gap_fill after recreate = false, want true")
	}
}

func TestRecreateSQLiteLogItemsTablePreservesSeqFrom15ColumnTable_1115fix3(t *testing.T) {
	db := openFix3LogDB(t)
	// 模拟 1115.fix2 之前的备份库：有 seq、没有 is_gap_fill，共 15 列。
	if err := db.Exec(`
		CREATE TABLE log_items (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			log_id INTEGER,
			group_id TEXT,
			nickname TEXT,
			im_userid TEXT,
			time INTEGER,
			message TEXT,
			is_dice NUMERIC,
			command_id INTEGER,
			command_info TEXT,
			raw_msg_id TEXT,
			user_uniform_id TEXT,
			removed INTEGER,
			parent_id INTEGER,
			seq INTEGER
		)`).Error; err != nil {
		t.Fatalf("create 15-column log_items: %v", err)
	}
	if err := db.Exec(`
		INSERT INTO log_items (log_id, group_id, nickname, message, raw_msg_id, seq)
		VALUES (1, 'QQ-Group:fix3', '玩家', 'm', 'm-1', 777)`).Error; err != nil {
		t.Fatalf("insert 15-column row: %v", err)
	}

	columns, err := loadSQLiteTableColumns(db, "log_items")
	if err != nil {
		t.Fatalf("load columns: %v", err)
	}
	if err := recreateSQLiteLogItemsTable(db, columns); err != nil {
		t.Fatalf("recreate log_items: %v", err)
	}

	var got model.LogOneItem
	if err := db.First(&got).Error; err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got.Seq == nil || *got.Seq != 777 {
		t.Fatalf("seq after 15-column recreate = %v, want 777", got.Seq)
	}
	if got.IsGapFill {
		t.Fatal("is_gap_fill for missing source column = true, want false")
	}
}
