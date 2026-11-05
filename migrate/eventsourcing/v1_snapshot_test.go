package eventsourcing

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Copy an uncheckpointed WAL into a stopped installation. The original writer
// is closed before conversion starts; no process holds the installation open.
func copyV1WALFixture(t *testing.T) (database, keys string) {
	t.Helper()
	_, original, keys := copyV1Fixture(t)
	raw, err := sql.Open("sqlite", original)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	for _, statement := range []string{`PRAGMA journal_mode=WAL`, `CREATE TABLE wal_snapshot_marker (value TEXT)`, `INSERT INTO wal_snapshot_marker VALUES ('committed only in WAL')`} {
		if _, err = raw.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	database = filepath.Join(t.TempDir(), "events.db")
	for _, suffix := range []string{"", "-wal", "-shm"} {
		data, err := os.ReadFile(original + suffix)
		if err != nil {
			t.Fatal(err)
		}
		if suffix == "-wal" && len(data) == 0 {
			t.Fatal("fixture has no committed WAL")
		}
		if err = os.WriteFile(database+suffix, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err = raw.Close(); err != nil {
		t.Fatal(err)
	}
	return database, keys
}

func TestV1WALSnapshotAndPublicationRollbackNeverMutateSource(t *testing.T) {
	for _, stage := range []string{"verify", "activate", "activated", "success"} {
		t.Run(stage, func(t *testing.T) {
			ctx := context.Background()
			database, keys := copyV1WALFixture(t)
			identity := v1FixtureIdentity(t, database, keys)
			before, err := v1SQLiteMetadata(ctx, database)
			if err != nil {
				t.Fatal(err)
			}
			keyDigest := fileDigest(t, filepath.Join(keys, "index.key"))
			// Detection sees the committed WAL using a private snapshot too.
			if _, err = DetectSQLiteFormat(ctx, database); err != nil {
				t.Fatal(err)
			}
			if err = recheckV1SQLite(ctx, database, before); err != nil {
				t.Fatalf("detection changed source: %v", err)
			}
			injected := errors.New("injected " + stage)
			result, err := ConvertV1(ctx, V1ConvertOptions{ActivePath: database, KeysDir: keys, Identity: identity, Inject: FailureFunc(func(name string) error {
				if name == stage {
					return injected
				}
				return nil
			})})
			if stage == "success" {
				if err != nil {
					t.Fatal(err)
				}
				for _, item := range before.Files {
					suffix := item.Name[len(filepath.Base(database)):]
					if fileDigest(t, result.BackupPath+suffix) != item.Digest {
						t.Fatalf("backup%s changed", suffix)
					}
				}
				for _, suffix := range []string{"-wal", "-shm"} {
					if _, err := os.Lstat(database + suffix); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("stale active %s: %v", suffix, err)
					}
				}
			} else {
				if !errors.Is(err, injected) {
					t.Fatalf("error=%v", err)
				}
				if err = recheckV1SQLite(ctx, database, before); err != nil {
					t.Fatalf("source not restored: %v", err)
				}
			}
			if fileDigest(t, filepath.Join(keys, "index.key")) != keyDigest {
				t.Fatal("conversion changed keys")
			}
		})
	}
}

func TestV1ConversionDoesNotReadOrCarryTransientPayloads(t *testing.T) {
	ctx := context.Background()
	_, database, keys := copyV1Fixture(t)
	identity := v1FixtureIdentity(t, database, keys)
	raw, err := sql.Open("sqlite", database)
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"inbox_messages", "outbox_effects", "operations", "operation_artifacts", "execution_receipts", "story_log_outbound_intents"} {
		if _, err = raw.Exec("DROP TABLE IF EXISTS " + table); err != nil {
			t.Fatal(err)
		}
		columns := "id INTEGER"
		if table == "outbox_effects" {
			columns = "status TEXT"
		}
		if _, err = raw.Exec("CREATE TABLE " + table + " (" + columns + ")"); err != nil {
			t.Fatal(err)
		}
		if table == "outbox_effects" {
			if _, err = raw.Exec(`INSERT INTO outbox_effects VALUES ('pending'),('leased'),('succeeded'),('failed'),('ambiguous')`); err != nil {
				t.Fatal(err)
			}
		} else if _, err = raw.Exec("INSERT INTO " + table + " VALUES (1)"); err != nil {
			t.Fatal(err)
		}
	}
	if err = raw.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := ConvertV1(ctx, V1ConvertOptions{ActivePath: database, KeysDir: keys, Identity: identity})
	if err != nil {
		t.Fatal(err)
	}
	if result.LeftBehindQueueRows != 9 || result.NonterminalOutboxRows != 2 || result.LeftBehindStoryIntents != 1 {
		t.Fatalf("excluded counts=%+v", result)
	}
	raw, err = sql.Open("sqlite", database)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	for _, table := range []string{"inbox_messages", "outbox_effects", "operations", "operation_artifacts", "execution_receipts", "story_log_outbound_intents"} {
		var count int
		if err = raw.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("transient %s survived: %d/%v", table, count, err)
		}
	}
}
