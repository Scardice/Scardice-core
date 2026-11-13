package v160

import (
	"testing"

	"Scardice-core/model"
)

func Test_V160LogSizeRepairMigrate_succeeds_for_fresh_database(t *testing.T) {
	// Given
	operator := newMigrationTestOperator(t)

	// When
	cleanErr := V160LogIDZeroCleanMigrate(operator, func(string) {})
	repairErr := V160LogSizeRepairMigrate(operator, func(string) {})

	// Then
	if cleanErr != nil {
		t.Fatalf("clean fresh database: %v", cleanErr)
	}
	if repairErr != nil {
		t.Fatalf("repair fresh database: %v", repairErr)
	}
}

func Test_V160LogSizeRepairMigrate_adds_missing_column_and_recounts_active_items(t *testing.T) {
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
	mustExecMigrationSQL(t, database, `INSERT INTO logs (id, name) VALUES (1, 'first'), (2, 'second')`)
	mustExecMigrationSQL(t, database, `INSERT INTO log_items (log_id, removed) VALUES
		(1, NULL), (1, NULL), (1, 1), (2, NULL)`)
	if database.Migrator().HasColumn(&model.LogInfo{}, "size") {
		t.Fatal("fixture unexpectedly contains logs.size")
	}

	// When
	err := V160LogSizeRepairMigrate(operator, func(string) {})

	// Then
	if err != nil {
		t.Fatalf("repair missing logs.size: %v", err)
	}
	if !database.Migrator().HasColumn(&model.LogInfo{}, "size") {
		t.Fatal("repair did not add logs.size")
	}
	if size := scanLogSize(t, database, 1); size != 2 {
		t.Fatalf("log 1 size = %d, want 2", size)
	}
	if size := scanLogSize(t, database, 2); size != 1 {
		t.Fatalf("log 2 size = %d, want 1", size)
	}
}
