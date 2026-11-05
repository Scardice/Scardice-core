package main

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"

	"Scardice-core/eventstore"
	"Scardice-core/migrate/eventsourcing"
)

func copyRootV1Fixture(t *testing.T, database string) eventstore.DatabaseConfig {
	t.Helper()
	source, err := filepath.Abs(filepath.Join("migrate", "eventsourcing", "v1reader", "testdata", "v1"))
	if err != nil {
		t.Fatal(err)
	}
	copyFile := func(from, to string) {
		t.Helper()
		data, err := os.ReadFile(from)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(to, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	copyFile(filepath.Join(source, "events.db"), database)
	keys := filepath.Join(filepath.Dir(database), "keys")
	copyFile(filepath.Join(source, "keys", "index.key"), filepath.Join(keys, "index.key"))
	entries, err := os.ReadDir(filepath.Join(source, "keys", "roots"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		copyFile(filepath.Join(source, "keys", "roots", entry.Name()), filepath.Join(keys, "roots", entry.Name()))
	}
	raw, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: filepath.ToSlash(database), RawQuery: "mode=ro&immutable=1"}).String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var identity string
	if err = raw.QueryRow(`SELECT database_identity FROM store_readiness WHERE singleton_id = 'default'`).Scan(&identity); err != nil {
		t.Fatal(err)
	}
	return eventstore.DatabaseConfig{Type: "sqlite", DSN: database, DatabaseIdentity: identity}
}

func emptyRootV1State(t *testing.T, config eventstore.DatabaseConfig, mode string) {
	t.Helper()
	raw, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: filepath.ToSlash(config.DSN)}).String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	for _, table := range []string{"domain_events", "aggregate_heads", "projection_read_models", "adapter_secrets", "plugin_kv", "story_log_sessions", "story_log_states", "story_log_entries", "story_log_outbound_intents", "story_log_imports", "management_activities", "inbox_messages", "outbox_effects", "operations", "operation_artifacts", "execution_receipts"} {
		var exists int
		if err = raw.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if exists != 0 {
			if _, err = raw.Exec("DELETE FROM " + table); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err = raw.Exec(`UPDATE store_readiness SET mode = ?`, mode); err != nil {
		t.Fatal(err)
	}
	if err = raw.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestV1SourceSelectionUsesMeaningfulStateAndReadiness(t *testing.T) {
	for _, tc := range []struct {
		name, mode    string
		empty, legacy bool
		want          installationImportSource
		conflict      bool
	}{
		{"old startup empty schema with legacy", "fresh", true, true, installationSourceLegacy, false},
		{"fresh current state with legacy", "fresh", false, true, "", true},
		{"fresh current state without legacy", "fresh", false, false, installationSourceV1, false},
		{"completed import with legacy", "import", false, true, installationSourceV1, false},
		{"completed empty import", "import", true, true, installationSourceV1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := copyRootV1Fixture(t, filepath.Join(t.TempDir(), "events.db"))
			if tc.empty {
				emptyRootV1State(t, config, tc.mode)
			} else if tc.mode == "import" {
				raw, err := sql.Open("sqlite", config.DSN)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = raw.Exec(`UPDATE store_readiness SET mode = 'import'`); err != nil {
					t.Fatal(err)
				}
				if err = raw.Close(); err != nil {
					t.Fatal(err)
				}
			}
			got, err := v1InstallationSource(context.Background(), config, tc.legacy)
			if tc.conflict {
				if !errors.Is(err, eventsourcing.ErrLegacyStateConflict) {
					t.Fatalf("selection=%s/%v", got, err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("selection=%s/%v want=%s", got, err, tc.want)
			}
		})
	}
}

func TestEmptyV1WithLegacyImportsSourceAWithoutOpeningOrRequiringOldKeys(t *testing.T) {
	root := t.TempDir()
	fixture := writeLegacyImportFixture(t, root)
	if err := os.Rename(fixture, filepath.Join(root, "data")); err != nil {
		t.Fatal(err)
	}
	active := filepath.Join(root, "data", "endpoint", "events.db")
	config := copyRootV1Fixture(t, active)
	emptyRootV1State(t, config, "fresh")
	if err := os.RemoveAll(filepath.Join(filepath.Dir(active), "keys")); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	t.Setenv("DB_TYPE", "sqlite")
	if !runInstallationImport(zap.NewNop().Sugar(), config) {
		t.Fatal("empty old startup schema selected source B or failed source A")
	}
	database, err := openCurrentEventDatabase(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store := eventstore.NewStore(database)
	readiness, err := store.GetReadiness(context.Background())
	if err != nil || readiness.Mode != "import" {
		t.Fatalf("readiness=%+v/%v", readiness, err)
	}
	var groups int64
	if err = database.GORM().Table("projection_read_models").Where("projection_name = ?", "group-record").Count(&groups).Error; err != nil || groups == 0 {
		t.Fatalf("legacy groups were not imported: %d/%v", groups, err)
	}
	if err = eventsourcing.CheckUnfinishedV1Publication(active); err != nil {
		t.Fatal(err)
	}
	if backups, _ := filepath.Glob(active + ".v1.*.bak"); len(backups) != 1 {
		t.Fatalf("old empty schema backup=%v", backups)
	}
}

func TestLiteralPercentSQLiteFilenamesAreNotURIDecoded(t *testing.T) {
	for _, name := range []string{"events%20literal.db", "events%bad.db"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), name)
			config := copyRootV1Fixture(t, path)
			resolved, ok := plainSQLitePath(config)
			if !ok || resolved != path {
				t.Fatalf("literal filename resolved as %q/%v", resolved, ok)
			}
			if old, err := detectV1Store(context.Background(), config); err != nil || !old {
				t.Fatalf("actual v1 file was bypassed: %v/%v", old, err)
			}
			keys := filepath.Join(filepath.Dir(path), "keys")
			if _, err := eventsourcing.ConvertV1(context.Background(), eventsourcing.V1ConvertOptions{ActivePath: path, KeysDir: keys, Identity: config.DatabaseIdentity}); err != nil {
				t.Fatal(err)
			}
			database, err := openCurrentEventDatabase(context.Background(), config)
			if err != nil {
				t.Fatal(err)
			}
			if err = database.Close(); err != nil {
				t.Fatal(err)
			}
			uri := config
			uri.DSN = (&url.URL{Scheme: "file", Path: filepath.ToSlash(path)}).String()
			if decoded, ok := plainSQLitePath(uri); !ok || decoded != path {
				t.Fatalf("escaped URI resolved as %q/%v", decoded, ok)
			}
		})
	}
}

func TestUnfinishedV1SwapBlocksDatabaseCreationBeforeFreshOpen(t *testing.T) {
	for _, suffix := range []string{".v1-swap.json", ".v1-swap.json.writing"} {
		t.Run(suffix, func(t *testing.T) {
			active := filepath.Join(t.TempDir(), "events.db")
			if err := os.WriteFile(active+suffix, []byte("interrupted publication"), 0o600); err != nil {
				t.Fatal(err)
			}
			config := eventstore.DatabaseConfig{Type: "sqlite", DSN: active, DatabaseIdentity: "interrupted-publication"}
			if database, err := openCurrentEventDatabase(context.Background(), config); !errors.Is(err, eventsourcing.ErrUnfinishedV1Publication) {
				if database != nil {
					_ = database.Close()
				}
				t.Fatalf("incomplete swap was not rejected before open: %v", err)
			}
			if _, err := os.Stat(active); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("fresh database was created over an incomplete swap: %v", err)
			}
		})
	}
}
