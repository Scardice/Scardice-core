package v160

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"Scardice-core/utils/constant"
)

type migrationTestOperator struct {
	database *gorm.DB
}

func newMigrationTestOperator(t *testing.T) *migrationTestOperator {
	t.Helper()

	database, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "logs.db")), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open migration test database: %v", err)
	}
	sqlDatabase, err := database.DB()
	if err != nil {
		t.Fatalf("get migration test database handle: %v", err)
	}
	t.Cleanup(func() {
		if err := sqlDatabase.Close(); err != nil {
			t.Errorf("close migration test database: %v", err)
		}
	})

	return &migrationTestOperator{database: database}
}

func (o *migrationTestOperator) Init(context.Context) error {
	return nil
}

func (o *migrationTestOperator) Type() string {
	return constant.SQLITE
}

func (o *migrationTestOperator) DBCheck() {}

func (o *migrationTestOperator) GetDataDB(constant.DBMode) *gorm.DB {
	return o.database
}

func (o *migrationTestOperator) GetLogDB(constant.DBMode) *gorm.DB {
	return o.database
}

func (o *migrationTestOperator) GetCensorDB(constant.DBMode) *gorm.DB {
	return o.database
}

func (o *migrationTestOperator) Close() {}

func mustExecMigrationSQL(t *testing.T, database *gorm.DB, query string) {
	t.Helper()
	if err := database.Exec(query).Error; err != nil {
		t.Fatalf("execute migration fixture SQL: %v\nSQL: %s", err, query)
	}
}

func scanLogSize(t *testing.T, database *gorm.DB, id int) int {
	t.Helper()
	var size int
	if err := database.Raw("SELECT size FROM logs WHERE id = ?", id).Scan(&size).Error; err != nil {
		t.Fatalf("scan logs.size for id %d: %v", id, err)
	}
	return size
}
