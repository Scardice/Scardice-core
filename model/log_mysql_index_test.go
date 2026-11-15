package model

import (
	"sync"
	"testing"

	"gorm.io/gorm/schema"
)

// TestLogOneItemHookMySQLPrefixIndexLength_1115fix 锁定 MySQL 去重索引的前缀长度：
// raw_msg_id 是 TEXT，idx_log_delete_by_id 必须用 (group_id(20), raw_msg_id(20), id)
// 形式；否则 MySQL 无法建索引，去重查询会退化为全表扫描。
func TestLogOneItemHookMySQLPrefixIndexLength_1115fix(t *testing.T) {
	s, err := schema.Parse(&LogOneItemHookMySQL{}, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatalf("parse LogOneItemHookMySQL: %v", err)
	}
	idx := s.LookIndex("idx_log_delete_by_id")
	if idx == nil {
		t.Fatal("idx_log_delete_by_id not found in MySQL model")
	}
	lengths := map[string]int{}
	for _, field := range idx.Fields {
		lengths[field.DBName] = field.Length
	}
	if lengths["group_id"] != 20 {
		t.Fatalf("idx_log_delete_by_id group_id prefix length = %d, want 20", lengths["group_id"])
	}
	if lengths["raw_msg_id"] != 20 {
		t.Fatalf("idx_log_delete_by_id raw_msg_id prefix length = %d, want 20", lengths["raw_msg_id"])
	}
	if lengths["id"] != 0 {
		t.Fatalf("idx_log_delete_by_id id length = %d, want 0 (full column)", lengths["id"])
	}
}
