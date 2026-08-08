package schema_test

import (
	"path/filepath"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"Scardice-core/model"
	"Scardice-core/utils/constant"
	"Scardice-core/utils/dboperator/schema"
)

func TestEnsureSchemasCreateMissingTables(t *testing.T) {
	t.Parallel()

	db := openSchemaTestDB(t)

	// Given: empty database (no core tables)
	for _, name := range []string{
		"group_player_info", "group_info", "ban_info", "endpoint_info", "attrs",
		"official_qq_identity_mapping",
		"logs", "log_items",
		"censor_log",
	} {
		if db.Migrator().HasTable(name) {
			t.Fatalf("precondition: table %s should not exist", name)
		}
	}

	// When: ensure schemas on empty DB
	if err := schema.EnsureDataSchema(db); err != nil {
		t.Fatalf("EnsureDataSchema: %v", err)
	}
	if err := schema.EnsureLogSchema(db, constant.SQLITE); err != nil {
		t.Fatalf("EnsureLogSchema: %v", err)
	}
	if err := schema.EnsureCensorSchema(db); err != nil {
		t.Fatalf("EnsureCensorSchema: %v", err)
	}

	// Then: all core tables exist
	wantModels := []any{
		&model.GroupPlayerInfoBase{},
		&model.GroupInfo{},
		&model.BanInfo{},
		&model.EndpointInfo{},
		&model.AttributesItemModel{},
		&model.OfficialQQIdentityMapping{},
		&model.LogInfo{},
		&model.LogOneItem{},
		&model.CensorLog{},
	}
	for _, m := range wantModels {
		if !db.Migrator().HasTable(m) {
			t.Fatalf("expected table for %T after ensure", m)
		}
	}
}

func TestEnsureSchemasIdempotent(t *testing.T) {
	t.Parallel()

	db := openSchemaTestDB(t)

	// Given: schemas already ensured once
	if err := schema.EnsureDataSchema(db); err != nil {
		t.Fatalf("EnsureDataSchema first: %v", err)
	}
	if err := schema.EnsureLogSchema(db, constant.SQLITE); err != nil {
		t.Fatalf("EnsureLogSchema first: %v", err)
	}
	if err := schema.EnsureCensorSchema(db); err != nil {
		t.Fatalf("EnsureCensorSchema first: %v", err)
	}

	// When: ensure again (idempotent self-heal path)
	if err := schema.EnsureDataSchema(db); err != nil {
		t.Fatalf("EnsureDataSchema second: %v", err)
	}
	if err := schema.EnsureLogSchema(db, constant.SQLITE); err != nil {
		t.Fatalf("EnsureLogSchema second: %v", err)
	}
	if err := schema.EnsureCensorSchema(db); err != nil {
		t.Fatalf("EnsureCensorSchema second: %v", err)
	}

	// Then: tables still present; second ensure is a no-op success
	if !db.Migrator().HasTable(&model.CensorLog{}) {
		t.Fatal("censor_log missing after second ensure")
	}
}

func TestEnsureRejectsNilDB(t *testing.T) {
	t.Parallel()

	if err := schema.EnsureDataSchema(nil); err == nil {
		t.Fatal("EnsureDataSchema(nil) should error")
	}
	if err := schema.EnsureLogSchema(nil, constant.SQLITE); err == nil {
		t.Fatal("EnsureLogSchema(nil) should error")
	}
	if err := schema.EnsureCensorSchema(nil); err == nil {
		t.Fatal("EnsureCensorSchema(nil) should error")
	}
}

func openSchemaTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	path := filepath.ToSlash(filepath.Join(t.TempDir(), "schema.db"))
	db, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql db: %v", err)
	}
	t.Cleanup(func() {
		_ = sqlDB.Close()
	})
	return db
}
