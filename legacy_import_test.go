package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
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
	source, err := legacyImportSourceFromEnv("/srv/scardice/data", func(key string) string { return values[key] })
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
	activePath := filepath.Join(root, "events.db")

	active := eventstore.DatabaseConfig{
		Type: "sqlite", DSN: activePath, DatabaseIdentity: "import-smoke",
	}
	database, err := eventstore.OpenDatabase(ctx, active)
	if err != nil {
		t.Fatal(err)
	}
	store := eventstore.NewStore(database)
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
		Source:         eventsourcing.NewLegacySource(fixtureRoot),
		Target:         eventsourcing.NewSQLitePublicationTarget(candidatePath, activePath),
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
	activePath := filepath.Join(root, "events.db")

	active := eventstore.DatabaseConfig{
		Type: "sqlite", DSN: activePath, DatabaseIdentity: "import-smoke",
	}
	database, err := eventstore.OpenDatabase(ctx, active)
	if err != nil {
		t.Fatal(err)
	}
	store := eventstore.NewStore(database)
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
		Source:         eventsourcing.NewLegacySource(fixtureRoot),
		Target:         eventsourcing.NewSQLitePublicationTarget(activePath+".import", activePath),
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

// legacyImportFixtureWithBadRows is a fresh-target import whose legacy data
// holds, next to the good group, rows the importer cannot decide.
type legacyImportFixture struct {
	root, activePath, fixtureRoot string
	active                        eventstore.DatabaseConfig
	options                       eventsourcing.ImporterOptions
}

func newLegacyImportFixtureWithBadRows(t *testing.T) legacyImportFixture {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	activePath := filepath.Join(root, "events.db")
	active := eventstore.DatabaseConfig{Type: "sqlite", DSN: activePath, DatabaseIdentity: "import-smoke"}
	database, err := eventstore.OpenDatabase(ctx, active)
	if err != nil {
		t.Fatal(err)
	}
	store := eventstore.NewStore(database)
	readiness, err := store.GetReadiness(ctx)
	if err != nil {
		t.Fatal(err)
	}
	persistentState, err := captureImportPersistentState(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}

	fixtureRoot := writeLegacyImportFixture(t, root)
	legacy, err := sql.Open("sqlite", filepath.Join(fixtureRoot, "default", "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	for _, statement := range []string{
		`INSERT INTO group_info (id, created_at, updated_at, data) VALUES ('QQ-Group:scalar', 7, 8, '{"active":"yes"}')`,
		`INSERT INTO group_info (id, created_at, updated_at, data) VALUES ('QQ-Group:null-data', 7, 8, NULL)`,
		`INSERT INTO group_info (id, created_at, updated_at, data) VALUES ('QQ-Group:zero-created', 0, 8, '{"active":true}')`,
		`INSERT INTO group_info (id, created_at, updated_at, data) VALUES ('QQ-Group:bad-log', 7, 8, '{"logCurName":3}')`,
		`INSERT INTO ban_info (id, ban_updated_at, data) VALUES ('QQ:empty-ban', 9, X'')`,
		`INSERT INTO ban_info (id, ban_updated_at, data) VALUES ('QQ:garbage-ban', 9, 'not json')`,
		`INSERT INTO attrs (id, data, created_at, updated_at) VALUES ('', '{"t":7,"v":{"dict":{"hp":{"t":0,"v":60}}}}', 1, 2)`,
		`INSERT INTO group_player_info (name, user_id, group_id) VALUES ('NoUser', '', 'QQ-Group:100')`,
		`INSERT INTO group_info (id, created_at, updated_at, data) VALUES ('QQ-Group:nosession', 7, 8, '{"logCurName":"gone","logOn":true}')`,
	} {
		if _, err = legacy.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	return legacyImportFixture{
		root: root, activePath: activePath, fixtureRoot: fixtureRoot, active: active,
		options: eventsourcing.ImporterOptions{
			Readiness:      importReadinessSnapshot{value: readiness, persistentState: persistentState},
			Source:         eventsourcing.NewLegacySource(fixtureRoot),
			Target:         eventsourcing.NewSQLitePublicationTarget(activePath+".import", activePath),
			SnapshotRoot:   filepath.Join(root, "snapshot"),
			TargetIdentity: "import-smoke",
			DropRecordsDir: fixtureRoot,
		},
	}
}

// Rows the importer cannot decide no longer abort the import: the other
// groups publish, and one record file lists every dropped row.
func TestLegacyImportDropsUndecidableRowsAndRecordsThemEndToEnd(t *testing.T) {
	ctx := context.Background()
	fixture := newLegacyImportFixtureWithBadRows(t)
	result, err := eventsourcing.NewImporter(fixture.options).Run(ctx, eventsourcing.Request{Mode: eventsourcing.ModeImport})
	if err != nil {
		t.Fatalf("legacy import aborted on undecidable rows: %v", err)
	}
	if result.Dropped != 9 {
		t.Fatalf("dropped rows = %d, want 9 (%#v)", result.Dropped, result)
	}
	recordsDir := filepath.Join(fixture.fixtureRoot, "migration-drops")
	if filepath.Dir(result.DropRecordsPath) != recordsDir || !strings.HasPrefix(filepath.Base(result.DropRecordsPath), "legacy-import-") ||
		!strings.HasSuffix(result.DropRecordsPath, ".jsonl") {
		t.Fatalf("drop record path = %q", result.DropRecordsPath)
	}
	entries, err := os.ReadDir(recordsDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("record directory = %v/%v, want exactly one file", entries, err)
	}
	content, err := os.ReadFile(result.DropRecordsPath)
	if err != nil {
		t.Fatal(err)
	}
	reasons := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(content), "\n"), "\n") {
		var record struct {
			Source, Kind, Identity, Reason string
			Detail                         map[string]any
		}
		if err = json.Unmarshal([]byte(line), &record); err != nil || record.Source != "legacy-import" {
			t.Fatalf("drop record line %q: %v", line, err)
		}
		reasons[record.Kind+"/"+record.Identity] = record.Reason
	}
	want := map[string]string{
		"group_info/QQ-Group:scalar":       "invalid-data",
		"group_info/QQ-Group:null-data":    "data-null",
		"group_info/QQ-Group:zero-created": "created-at-not-positive",
		"group_info/QQ-Group:bad-log":      "invalid-story-log-state",
		"ban_info/QQ:empty-ban":            "data-empty",
		"ban_info/QQ:garbage-ban":          "invalid-data",
		"attrs/":                           "attrs-missing-id",
		"group_player_info/QQ-Group:100|":  "player-missing-identity",
		"group_info/QQ-Group:nosession":    "story-log-session-missing",
	}
	if len(reasons) != len(want) {
		t.Fatalf("drop reasons = %v, want %v", reasons, want)
	}
	for key, reason := range want {
		if reasons[key] != reason {
			t.Fatalf("drop reasons = %v, want %v", reasons, want)
		}
	}

	published, err := eventstore.OpenDatabase(ctx, fixture.active)
	if err != nil {
		t.Fatalf("reopen published target: %v", err)
	}
	defer published.Close()
	readiness, err := eventstore.NewStore(published).GetReadiness(ctx)
	if err != nil || readiness.Mode != "import" {
		t.Fatalf("published readiness = %#v/%v", readiness, err)
	}
	warning := legacyImportDropWarning(result)
	if !strings.Contains(warning, "dropped 9") || !strings.Contains(warning, result.DropRecordsPath) {
		t.Fatalf("drop warning = %q", warning)
	}
	if legacyImportDropWarning(eventsourcing.ImportResult{}) != "" {
		t.Fatal("a run without drops produced a warning")
	}
}

// A record file that cannot be written aborts the import before publication:
// no row may be dropped without a durable record.
func TestLegacyImportAbortsWhenDropRecordsCannotBeWritten(t *testing.T) {
	ctx := context.Background()
	fixture := newLegacyImportFixtureWithBadRows(t)
	if err := os.WriteFile(filepath.Join(fixture.fixtureRoot, "migration-drops"), []byte("in the way"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := eventsourcing.NewImporter(fixture.options).Run(ctx, eventsourcing.Request{Mode: eventsourcing.ModeImport})
	if err == nil || !errors.Is(err, eventsourcing.ErrQuarantined) || result.QuarantineMarker == "" {
		t.Fatalf("import with unwritable drop records = %#v / %v", result, err)
	}
	database, openErr := eventstore.OpenDatabase(ctx, fixture.active)
	if openErr != nil {
		t.Fatal(openErr)
	}
	defer database.Close()
	readiness, readErr := eventstore.NewStore(database).GetReadiness(ctx)
	if readErr != nil || readiness.Mode == "import" {
		t.Fatalf("event database was published despite the failed record: %#v/%v", readiness, readErr)
	}
}
