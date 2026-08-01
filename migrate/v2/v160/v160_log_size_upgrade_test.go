package v160

import (
	"path/filepath"
	"testing"

	"Scardice-core/model"
	upgrade "Scardice-core/utils/upgrader"
	"Scardice-core/utils/upgrader/store"
)

func newLogSizeMigrationManager(operator *migrationTestOperator, metadataPath string) *upgrade.Manager {
	manager := &upgrade.Manager{
		Store:    store.NewJSONStore(metadataPath),
		Database: operator,
	}
	manager.Register(V160LogSizeRepairMigration)
	return manager
}

func Test_V160LogSizeRepairMigration_records_success_once_and_skips_previous_upgrade(t *testing.T) {
	// Given
	operator := newMigrationTestOperator(t)
	database := operator.database
	metadataPath := filepath.Join(t.TempDir(), "upgrade_metadata.json")
	mustExecMigrationSQL(t, database, `CREATE TABLE logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT,
		size INTEGER
	)`)
	mustExecMigrationSQL(t, database, `CREATE TABLE log_items (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		log_id INTEGER,
		removed INTEGER
	)`)
	mustExecMigrationSQL(t, database, `INSERT INTO logs (id, name, size) VALUES (1, 'legacy', 99)`)
	mustExecMigrationSQL(t, database, `INSERT INTO log_items (log_id, removed) VALUES (1, NULL), (1, NULL)`)

	// When
	if err := newLogSizeMigrationManager(operator, metadataPath).ApplyAll(); err != nil {
		t.Fatalf("apply logs.size migration: %v", err)
	}
	mustExecMigrationSQL(t, database, `UPDATE logs SET size = 77 WHERE id = 1`)
	if err := newLogSizeMigrationManager(operator, metadataPath).ApplyAll(); err != nil {
		t.Fatalf("reapply previously successful logs.size migration: %v", err)
	}

	// Then
	if size := scanLogSize(t, database, 1); size != 77 {
		t.Fatalf("previously upgraded log size = %d, want unchanged 77", size)
	}
	records, err := store.NewJSONStore(metadataPath).LoadRecords()
	if err != nil {
		t.Fatalf("load logs.size migration records: %v", err)
	}
	if len(records) != 1 || records[0].ID != V160LogSizeRepairMigration.ID || !records[0].Success {
		t.Fatalf("migration records = %#v, want one successful 010 record", records)
	}
}

func Test_V160LogSizeRepairMigration_retries_partial_failure_without_duplicate_durable_state(t *testing.T) {
	// Given
	operator := newMigrationTestOperator(t)
	database := operator.database
	metadataPath := filepath.Join(t.TempDir(), "upgrade_metadata.json")
	mustExecMigrationSQL(t, database, `CREATE TABLE logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT
	)`)
	mustExecMigrationSQL(t, database, `INSERT INTO logs (id, name) VALUES (1, 'legacy')`)

	// When
	firstErr := newLogSizeMigrationManager(operator, metadataPath).ApplyAll()

	// Then
	if firstErr == nil {
		t.Fatal("first migration attempt without log_items must fail")
	}
	if !database.Migrator().HasColumn(&model.LogInfo{}, "size") {
		t.Fatal("partial attempt did not durably add logs.size")
	}

	// Given
	mustExecMigrationSQL(t, database, `CREATE TABLE log_items (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		log_id INTEGER,
		removed INTEGER
	)`)
	mustExecMigrationSQL(t, database, `INSERT INTO log_items (log_id, removed) VALUES
		(1, NULL), (1, NULL), (1, 1)`)

	// When
	if err := newLogSizeMigrationManager(operator, metadataPath).ApplyAll(); err != nil {
		t.Fatalf("retry logs.size migration: %v", err)
	}
	mustExecMigrationSQL(t, database, `UPDATE logs SET size = 77 WHERE id = 1`)
	if err := newLogSizeMigrationManager(operator, metadataPath).ApplyAll(); err != nil {
		t.Fatalf("skip completed logs.size migration: %v", err)
	}

	// Then
	if size := scanLogSize(t, database, 1); size != 77 {
		t.Fatalf("completed migration reran: size = %d, want unchanged 77", size)
	}
	var sizeColumns int
	if err := database.Raw("SELECT COUNT(1) FROM pragma_table_info('logs') WHERE name = 'size'").Scan(&sizeColumns).Error; err != nil {
		t.Fatalf("count logs.size columns: %v", err)
	}
	if sizeColumns != 1 {
		t.Fatalf("logs.size column count = %d, want 1", sizeColumns)
	}
	records, err := store.NewJSONStore(metadataPath).LoadRecords()
	if err != nil {
		t.Fatalf("load retry records: %v", err)
	}
	if len(records) != 2 || records[0].Success || !records[1].Success {
		t.Fatalf("retry records = %#v, want one failed then one successful attempt", records)
	}
}
