package sqlite_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"Scardice-core/model"
	"Scardice-core/utils/constant"
	"Scardice-core/utils/dboperator/engine/sqlite"
)

func TestSQLiteEngineInitCreatesMissingTables(t *testing.T) {
	// Given: empty data dir (fresh DBs with no tables)
	dir := t.TempDir()
	t.Setenv("DATADIR", dir)

	eng := &sqlite.SQLiteEngine{}
	// When: engine Init opens DBs and ensures schema
	if err := eng.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(eng.Close)

	// Then: data / log / censor core tables exist
	dataDB := eng.GetDataDB(constant.WRITE)
	logDB := eng.GetLogDB(constant.WRITE)
	censorDB := eng.GetCensorDB(constant.WRITE)

	for _, m := range []any{
		&model.GroupInfo{},
		&model.GroupPlayerInfoBase{},
		&model.BanInfo{},
		&model.EndpointInfo{},
		&model.AttributesItemModel{},
		&model.OfficialQQIdentityMapping{},
	} {
		if !dataDB.Migrator().HasTable(m) {
			t.Fatalf("data table missing for %T", m)
		}
	}
	if !logDB.Migrator().HasTable(&model.LogInfo{}) || !logDB.Migrator().HasTable(&model.LogOneItem{}) {
		t.Fatal("log tables missing")
	}
	if !censorDB.Migrator().HasTable(&model.CensorLog{}) {
		t.Fatal("censor_log missing")
	}

	// And: physical DB files were created under DATADIR
	for _, name := range []string{"data.db", "data-logs.db", "data-censor.db"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("expected %s: %v", name, err)
		}
	}
}
