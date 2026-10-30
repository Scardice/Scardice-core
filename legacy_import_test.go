package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/glebarez/go-sqlite"

	"Scardice-core/eventstore"
	"Scardice-core/migrate/eventsourcing"
)

func TestLegacySourceRootUsesInstallationDataDirectory(t *testing.T) {
	installationRoot := t.TempDir()
	dataRoot := filepath.Join(installationRoot, "data")
	if err := os.Mkdir(dataRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataRoot, "dice.yaml"), []byte("diceConfigs: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := legacySourceRoot(installationRoot)
	if err != nil {
		t.Fatal(err)
	}
	if got != dataRoot {
		t.Fatalf("legacy source root = %q, want %q", got, dataRoot)
	}
}

func TestFinishLegacyImportCleansOnlyAfterSuccessfulPublication(t *testing.T) {
	root := t.TempDir()
	names := filepath.Join(root, "names")
	if err := os.Mkdir(names, 0o700); err != nil {
		t.Fatal(err)
	}
	artifacts := []string{"data-logs.db", "names.zip", "serve.yaml"}
	for _, name := range artifacts {
		if err := os.WriteFile(filepath.Join(names, name), []byte("legacy"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	failed := errors.New("publication failed")
	if _, err := finishLegacyImport(root, eventsourcing.ImportResult{}, failed); !errors.Is(err, failed) {
		t.Fatalf("failed import error = %v", err)
	}
	for _, name := range artifacts {
		if _, err := os.Stat(filepath.Join(names, name)); err != nil {
			t.Fatalf("failed import removed %s: %v", name, err)
		}
	}
	if _, err := finishLegacyImport(root, eventsourcing.ImportResult{}, nil); err != nil {
		t.Fatal(err)
	}
	for _, name := range artifacts {
		if _, err := os.Stat(filepath.Join(names, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("successful import retained %s: %v", name, err)
		}
	}
}

func TestLegacyImportSourceFromEnvUsesRemoteSQLSnapshot(t *testing.T) {
	values := map[string]string{
		"DB_TYPE":       "POSTGRESQL",
		"DB_DSN":        "postgres://db.example/legacy?sslmode=verify-full",
		"DB_TLS_VERIFY": "true",
	}
	source, err := legacyImportSourceFromEnv("/srv/scardice/data", func(key string) string { return values[key] }, nil)
	if err != nil {
		t.Fatal(err)
	}
	remote, ok := source.(*eventsourcing.RemoteSQLSource)
	if !ok {
		t.Fatalf("source = %T", source)
	}
	if remote.Root != "/srv/scardice/data" || remote.Config.Type != "postgres" || !remote.Config.TLSVerify {
		t.Fatalf("remote source = %#v", remote)
	}
}

func TestLegacyImportTargetFromEnvBuildsInactiveRemoteSlot(t *testing.T) {
	slotFile := filepath.Join(t.TempDir(), "active-slot")
	if err := os.WriteFile(slotFile, []byte("blue\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	values := map[string]string{
		"SCARDICE_ENDPOINT_DB_SLOT_FILE":        slotFile,
		"SCARDICE_ENDPOINT_IMPORT_SLOT":         "green",
		"SCARDICE_ENDPOINT_DB_GREEN":            "postgres://db.example/green?sslmode=verify-full",
		"SCARDICE_ENDPOINT_DB_GREEN_TYPE":       "postgres",
		"SCARDICE_ENDPOINT_DB_GREEN_ID":         "target-green",
		"SCARDICE_ENDPOINT_DB_GREEN_TLS_VERIFY": "true",
		"SCARDICE_ENDPOINT_KEY_INDEX":           "/var/lib/scardice/index.key",
		"SCARDICE_ENDPOINT_KEY_ROOTS":           "/var/lib/scardice/roots",
	}
	target, identity, err := legacyImportTargetFromEnv(eventstore.DatabaseConfig{
		Type: "postgres", DSN: "postgres://db.example/blue?sslmode=verify-full", DatabaseIdentity: "target-blue",
	}, time.Unix(1, 0), func(key string) string { return values[key] })
	if err != nil {
		t.Fatal(err)
	}
	if target == nil || identity != "target-green" {
		t.Fatalf("remote target/identity = %T/%q", target, identity)
	}
}

func TestEndpointDatabaseSlotActivationRejectsWrongIdentityThenSwitches(t *testing.T) {
	path := filepath.Join(t.TempDir(), "active-slot")
	if err := os.WriteFile(path, []byte("blue\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	activate := endpointDatabaseSlotActivation(path, "green", "target-green")
	if err := activate(context.Background(), "wrong"); !errors.Is(err, eventsourcing.ErrTargetIdentity) {
		t.Fatalf("wrong identity error = %v", err)
	}
	slot, err := readEndpointDatabaseSlot(path)
	if err != nil || slot != "blue" {
		t.Fatalf("slot after rejected activation = %q, %v", slot, err)
	}
	if err = activate(context.Background(), "target-green"); err != nil {
		t.Fatal(err)
	}
	slot, err = readEndpointDatabaseSlot(path)
	if err != nil || slot != "green" {
		t.Fatalf("slot after activation = %q, %v", slot, err)
	}
}

func TestCaptureImportPersistentStateFailsClosedWithoutCapability(t *testing.T) {
	if _, err := captureImportPersistentState(context.Background(), nil); err == nil {
		t.Fatal("nil repository was treated as an empty database")
	}
}

// TestLegacyImportReusesFreshTargetIdentityEndToEnd reproduces the real
// --import-legacy path: a fresh event store is opened, its persistent-state
// fact is captured, the store is closed, and the captured snapshot drives the
// real importer against a real legacy fixture and SQLite publication target.
// The import must publish into the same identity the fresh store used.
func TestLegacyImportReusesFreshTargetIdentityEndToEnd(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	keySource := writeLegacyImportKeyMaterial(t, root)
	activePath := filepath.Join(root, "events.db")

	active := eventstore.DatabaseConfig{
		Type: "sqlite", DSN: activePath, KeySource: keySource, DatabaseIdentity: "import-smoke",
	}
	database, err := eventstore.OpenDatabase(ctx, active)
	if err != nil {
		t.Fatal(err)
	}
	store := eventstore.NewStore(database)
	if err = store.ValidateReadiness(ctx); err != nil {
		t.Fatalf("fresh store readiness: %v", err)
	}
	readiness, err := store.GetReadiness(ctx)
	if err != nil || readiness.DatabaseIdentity != "import-smoke" {
		t.Fatalf("fresh readiness = %#v, err=%v", readiness, err)
	}
	persistentState, err := captureImportPersistentState(ctx, store)
	if err != nil {
		t.Fatalf("capture persistent state: %v", err)
	}
	if persistentState.value {
		t.Fatal("fresh event store reported persistent runtime state")
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}

	fixtureRoot := writeLegacyImportFixture(t, root)
	candidatePath := activePath + ".import"
	result, err := eventsourcing.NewImporter(eventsourcing.ImporterOptions{
		Readiness:      importReadinessSnapshot{value: readiness, persistentState: persistentState},
		Source:         eventsourcing.NewLegacySourceWithKeySource(fixtureRoot, keySource),
		Target:         eventsourcing.NewSQLitePublicationTarget(candidatePath, activePath, keySource),
		SnapshotRoot:   filepath.Join(root, "snapshot"),
		TargetIdentity: "import-smoke",
	}).Run(ctx, eventsourcing.Request{Mode: eventsourcing.ModeImport})
	if err != nil {
		t.Fatalf("legacy import rejected fresh target: %v", err)
	}
	if result.Mode != eventsourcing.ModeImport || result.Batches == 0 || len(result.ManifestDigest) != 32 {
		t.Fatalf("import result = %#v", result)
	}
	if _, err = os.Stat(activePath); err != nil {
		t.Fatalf("published event database missing: %v", err)
	}
	published, err := eventstore.OpenDatabase(ctx, active)
	if err != nil {
		t.Fatalf("reopen published target: %v", err)
	}
	defer published.Close()
	publishedStore := eventstore.NewStore(published)
	publishedReadiness, err := publishedStore.GetReadiness(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if publishedReadiness.Mode != "import" || publishedReadiness.DatabaseIdentity != "import-smoke" {
		t.Fatalf("published readiness = %#v", publishedReadiness)
	}
}

// TestLegacyImportStillRejectsPopulatedFreshTarget proves identity reuse is not
// a blanket bypass: when the active database already holds runtime rows, the
// captured state is true and the importer keeps the occupied identity.
func TestLegacyImportStillRejectsPopulatedFreshTarget(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	keySource := writeLegacyImportKeyMaterial(t, root)
	activePath := filepath.Join(root, "events.db")

	active := eventstore.DatabaseConfig{
		Type: "sqlite", DSN: activePath, KeySource: keySource, DatabaseIdentity: "import-smoke",
	}
	database, err := eventstore.OpenDatabase(ctx, active)
	if err != nil {
		t.Fatal(err)
	}
	store := eventstore.NewStore(database)
	if err = store.ValidateReadiness(ctx); err != nil {
		t.Fatalf("fresh store readiness: %v", err)
	}
	readiness, err := store.GetReadiness(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Commit(ctx, eventstore.UnitOfWork{Streams: []eventstore.StreamAppend{{
		Stream: eventstore.StreamID{AggregateType: "smoke", AggregateID: "existing"},
		Events: []eventstore.NewEvent{{
			EventType: "smoke.created", SchemaVersion: 1, Payload: json.RawMessage(`{"ok":true}`),
			Metadata: eventstore.Metadata{
				EventID: "smoke-event", CommandID: "smoke-command", CorrelationID: "smoke-correlation",
				Producer: "test", OccurredAt: time.Unix(1, 0).UTC(),
			},
		}},
		ExpectedVersion: 0,
	}}}); err != nil {
		t.Fatal(err)
	}
	persistentState, err := captureImportPersistentState(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	if !persistentState.value {
		t.Fatal("populated event store reported no persistent state")
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}

	fixtureRoot := writeLegacyImportFixture(t, root)
	result, err := eventsourcing.NewImporter(eventsourcing.ImporterOptions{
		Readiness:      importReadinessSnapshot{value: readiness, persistentState: persistentState},
		Source:         eventsourcing.NewLegacySourceWithKeySource(fixtureRoot, keySource),
		Target:         eventsourcing.NewSQLitePublicationTarget(activePath+".import", activePath, keySource),
		SnapshotRoot:   filepath.Join(root, "snapshot"),
		TargetIdentity: "import-smoke",
	}).Run(ctx, eventsourcing.Request{Mode: eventsourcing.ModeImport})
	if !errors.Is(err, eventsourcing.ErrTargetIdentity) || !errors.Is(err, eventsourcing.ErrQuarantined) {
		t.Fatalf("populated target error = %v", err)
	}
	if result.QuarantineMarker == "" {
		t.Fatalf("populated target was not quarantined: %#v", result)
	}
}

func writeLegacyImportKeyMaterial(t *testing.T, root string) eventstore.KeySource {
	t.Helper()
	keys := filepath.Join(root, "keys")
	roots := filepath.Join(keys, "roots")
	if err := os.MkdirAll(roots, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keys, "index"), []byte("01234567890123456789012345678901"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(roots, "root-v1.key"), []byte("abcdefghijklmnopqrstuvwxyz123456"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(roots, "current"), []byte("root-v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	return eventstore.NewLocalFileKeySource(filepath.Join(keys, "index"), roots)
}

func writeLegacyImportFixture(t *testing.T, root string) string {
	t.Helper()
	fixtureRoot := filepath.Join(root, "legacy")
	instance := filepath.Join(fixtureRoot, "default")
	if err := os.MkdirAll(instance, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixtureRoot, "dice.yaml"), []byte("diceConfigs:\n  - name: default\n    dataDir: default\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	serve := []byte("diceMasters: [\"QQ:master\"]\nimSession:\n  endPoints:\n    - baseInfo:\n        id: legacy-onebot\n        platform: QQ\n        protocolType: pureonebot\n        enable: true\n        isPublic: true\n        userId: QQ:12345\n      adapter:\n        mode: client\n        connectUrl: ws://127.0.0.1:6700\n        token: endpoint-secret\n")
	if err := os.WriteFile(filepath.Join(instance, "serve.yaml"), serve, 0o600); err != nil {
		t.Fatal(err)
	}
	database, err := sql.Open("sqlite", filepath.Join(instance, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	statements := []string{
		`CREATE TABLE group_info (id TEXT PRIMARY KEY, created_at INTEGER, updated_at INTEGER, data BLOB)`,
		`CREATE TABLE group_player_info (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, user_id TEXT, last_command_time INTEGER, auto_set_name_template TEXT, dice_side_num INTEGER, group_id TEXT)`,
		`CREATE TABLE attrs (id TEXT, data BLOB, attrs_type TEXT, binding_sheet_id TEXT, name TEXT, owner_id TEXT, sheet_type TEXT, is_hidden INTEGER, created_at INTEGER, updated_at INTEGER)`,
		`CREATE TABLE ban_info (id TEXT PRIMARY KEY, ban_updated_at INTEGER, updated_at INTEGER, data BLOB)`,
	}
	for _, statement := range statements {
		if _, err = database.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	group, err := json.Marshal(map[string]any{
		"active": true, "groupId": "QQ-Group:100", "groupName": "Legacy Group", "enteredTime": int64(99),
		"diceIdActiveMap": map[string]bool{"QQ:bot": true}, "diceIdExistsMap": map[string]bool{"QQ:bot": true},
		"activatedExtList": []map[string]string{{"name": "coc7"}}, "system": "coc7", "diceSideNum": int64(100),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = database.Exec(`INSERT INTO group_info (id, created_at, data) VALUES (?, ?, ?)`, "QQ-Group:100", nil, group); err != nil {
		t.Fatal(err)
	}
	if _, err = database.Exec(`INSERT INTO group_player_info (name, user_id, last_command_time, auto_set_name_template, dice_side_num, group_id) VALUES (?, ?, ?, ?, ?, ?)`, nil, "QQ:200", nil, nil, nil, "QQ-Group:100"); err != nil {
		t.Fatal(err)
	}
	return fixtureRoot
}
