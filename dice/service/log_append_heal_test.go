package service

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"Scardice-core/model"
	"Scardice-core/utils/constant"
)

type healTestOperator struct {
	db *gorm.DB
}

func (o *healTestOperator) Init(_ context.Context) error           { return nil }
func (o *healTestOperator) Type() string                           { return constant.SQLITE }
func (o *healTestOperator) DBCheck()                               {}
func (o *healTestOperator) GetDataDB(_ constant.DBMode) *gorm.DB   { return o.db }
func (o *healTestOperator) GetLogDB(_ constant.DBMode) *gorm.DB    { return o.db }
func (o *healTestOperator) GetCensorDB(_ constant.DBMode) *gorm.DB { return o.db }
func (o *healTestOperator) Close()                                 {}

func TestLogAppendSelfHealsMissingSeqColumn(t *testing.T) {
	// Given/When/Then: old log_items without seq must self-heal on append.
	logSchemaHealed.Store(false)

	dbPath := filepath.ToSlash(filepath.Join(t.TempDir(), "old-logs.db"))
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql db: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	if err := db.Exec(`
CREATE TABLE logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  group_id TEXT,
  created_at INTEGER,
  updated_at INTEGER,
  size INTEGER,
  extra TEXT,
  upload_url TEXT,
  upload_time INTEGER
)`).Error; err != nil {
		t.Fatalf("create logs: %v", err)
	}
	if err := db.Exec(`
CREATE TABLE log_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  log_id INTEGER,
  group_id TEXT,
  nickname TEXT,
  im_userid TEXT,
  time INTEGER,
  message TEXT,
  is_dice INTEGER,
  command_id INTEGER,
  command_info TEXT,
  raw_msg_id TEXT,
  user_uniform_id TEXT,
  removed INTEGER,
  parent_id INTEGER
)`).Error; err != nil {
		t.Fatalf("create log_items: %v", err)
	}
	if db.Migrator().HasColumn(&model.LogOneItem{}, "seq") {
		t.Fatal("precondition: seq must be absent")
	}

	op := &healTestOperator{db: db}
	groupID := "QQ-Group:heal"
	seq := int64(7)

	ok := LogAppend(op, groupID, "story", &model.LogOneItem{
		Nickname: "n",
		IMUserID: "u",
		Message:  "hello",
		RawMsgID: "raw-1",
		Seq:      &seq,
	})
	if !ok {
		t.Fatal("LogAppend should succeed after schema self-heal")
	}
	if !db.Migrator().HasColumn(&model.LogOneItem{}, "seq") {
		t.Fatal("expected seq after heal")
	}
	var count int64
	if err := db.Model(&model.LogOneItem{}).Where("group_id = ?", groupID).Count(&count).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("log_items count = %d, want 1", count)
	}
}
