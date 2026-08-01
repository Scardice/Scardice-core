package v160

import "testing"

func Test_V160LogIDZeroCleanMigrate_succeeds_when_size_column_is_missing(t *testing.T) {
	// Given
	operator := newMigrationTestOperator(t)
	database := operator.database
	mustExecMigrationSQL(t, database, `CREATE TABLE logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT
	)`)
	mustExecMigrationSQL(t, database, `CREATE TABLE log_items (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		log_id INTEGER,
		removed INTEGER
	)`)
	mustExecMigrationSQL(t, database, `INSERT INTO logs (id, name) VALUES (0, NULL), (1, 'legacy')`)
	mustExecMigrationSQL(t, database, `INSERT INTO log_items (log_id, removed) VALUES (0, NULL), (1, NULL)`)

	// When
	err := V160LogIDZeroCleanMigrate(operator, func(string) {})

	// Then
	if err != nil {
		t.Fatalf("clean log_id=0 without logs.size: %v", err)
	}
	var zeroLogs int
	if err := database.Raw("SELECT COUNT(1) FROM logs WHERE id = 0").Scan(&zeroLogs).Error; err != nil {
		t.Fatalf("count zero-ID logs: %v", err)
	}
	var zeroItems int
	if err := database.Raw("SELECT COUNT(1) FROM log_items WHERE log_id = 0").Scan(&zeroItems).Error; err != nil {
		t.Fatalf("count zero-ID log items: %v", err)
	}
	if zeroLogs != 0 || zeroItems != 0 {
		t.Fatalf("zero-ID rows remain: logs=%d log_items=%d", zeroLogs, zeroItems)
	}
}
