package eventsourcing

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	mysql "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"

	"Scardice-core/core/groupstate"
	"Scardice-core/eventstore"
)

func TestRemoteSQLSourceGroupProofDetectsRawRowDrift(t *testing.T) {
	for _, test := range []struct {
		name       string
		before     string
		after      string
		beforeDrop string
		afterDrop  string
	}{
		{
			name:       "updated_at_zero_to_positive",
			before:     "UPDATE group_info SET updated_at = 0",
			after:      "UPDATE group_info SET updated_at = 1",
			beforeDrop: "updated-at-not-positive",
		},
		{
			name:   "updated_at_positive_to_positive",
			before: "UPDATE group_info SET updated_at = 1",
			after:  "UPDATE group_info SET updated_at = 2",
		},
		{
			name:      "created_at_null_to_zero",
			before:    "UPDATE group_info SET created_at = NULL, updated_at = 1",
			after:     "UPDATE group_info SET created_at = 0",
			afterDrop: "created-at-not-positive",
		},
		{
			name:       "created_at_zero_to_null",
			before:     "UPDATE group_info SET created_at = 0, updated_at = 1",
			after:      "UPDATE group_info SET created_at = NULL",
			beforeDrop: "created-at-not-positive",
		},
		{
			name:      "updated_at_null_to_zero",
			before:    "UPDATE group_info SET updated_at = NULL",
			after:     "UPDATE group_info SET updated_at = 0",
			afterDrop: "updated-at-not-positive",
		},
		{
			name:       "updated_at_zero_to_null",
			before:     "UPDATE group_info SET updated_at = 0",
			after:      "UPDATE group_info SET updated_at = NULL",
			beforeDrop: "updated-at-not-positive",
		},
		{
			name:       "data_null_to_empty",
			before:     "UPDATE group_info SET data = NULL",
			after:      "UPDATE group_info SET data = X''",
			beforeDrop: "data-null",
			afterDrop:  "data-empty",
		},
		{
			name:       "data_empty_to_null",
			before:     "UPDATE group_info SET data = X''",
			after:      "UPDATE group_info SET data = NULL",
			beforeDrop: "data-empty",
			afterDrop:  "data-null",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			source, database := newRemoteGroupProofFixture(t)
			if _, err := database.ExecContext(ctx, test.before); err != nil {
				t.Fatal(err)
			}
			before, err := source.Inventory(ctx)
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := source.Snapshot(ctx, filepath.Join(t.TempDir(), "snapshot"))
			if err != nil {
				t.Fatal(err)
			}
			if !before.Metadata.Equal(snapshot.Metadata) {
				t.Fatal("unchanged remote source produced different inventory and snapshot metadata")
			}
			if err = source.Recheck(ctx, snapshot.Metadata); err != nil {
				t.Fatalf("unchanged remote source failed recheck: %v", err)
			}
			assertRemoteGroupProofSnapshot(t, snapshot, test.beforeDrop)

			if _, err = database.ExecContext(ctx, test.after); err != nil {
				t.Fatal(err)
			}
			after, err := source.Inventory(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if snapshot.Metadata.Equal(after.Metadata) {
				t.Error("remote group raw-row mutation did not change source metadata")
			}
			if err = source.Recheck(ctx, snapshot.Metadata); !errors.Is(err, ErrSourceDrift) {
				t.Errorf("remote group mutation recheck error = %v, want ErrSourceDrift", err)
			}
			updated, err := source.Snapshot(ctx, filepath.Join(t.TempDir(), "snapshot"))
			if err != nil {
				t.Fatal(err)
			}
			assertRemoteGroupProofSnapshot(t, updated, test.afterDrop)
		})
	}
}

func TestRemoteSQLSourceGroupProofWithoutUpdatedAtRemainsRecheckable(t *testing.T) {
	ctx := context.Background()
	source, database := newRemoteGroupProofFixture(t)
	if _, err := database.ExecContext(ctx, "ALTER TABLE group_info DROP COLUMN updated_at"); err != nil {
		t.Fatal(err)
	}
	before, err := source.Inventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := source.Snapshot(ctx, filepath.Join(t.TempDir(), "snapshot"))
	if err != nil {
		t.Fatalf("snapshot without optional updated_at: %v", err)
	}
	if !before.Metadata.Equal(snapshot.Metadata) {
		t.Fatal("missing optional updated_at produced unstable metadata")
	}
	if err = source.Recheck(ctx, snapshot.Metadata); err != nil {
		t.Fatalf("unchanged source without updated_at failed recheck: %v", err)
	}
	assertRemoteGroupProofSnapshot(t, snapshot, "")
	if _, err = database.ExecContext(ctx, "UPDATE group_info SET created_at = 0"); err != nil {
		t.Fatal(err)
	}
	if err = source.Recheck(ctx, snapshot.Metadata); !errors.Is(err, ErrSourceDrift) {
		t.Fatalf("source without updated_at stopped detecting drift: %v", err)
	}
}

func TestRemoteSQLSourceGroupProofPropagatesProbeErrors(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
	}{
		{"mysql_permission", &mysql.MySQLError{Number: 1143, Message: "SELECT command denied for column updated_at"}},
		{"postgres_permission", &pgconn.PgError{Code: "42501", Message: "permission denied for column updated_at"}},
		{"connection_failure", errors.New("connection interrupted while reading updated_at")},
	} {
		t.Run(test.name, func(t *testing.T) {
			source, _ := newRemoteGroupProofFixture(t)
			database, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = database.Close() })
			source.open = func(context.Context, eventstore.DatabaseConfig) (*sql.DB, error) {
				return database, nil
			}
			mock.ExpectBegin()
			for _, query := range []string{
				"SELECT id, data, attrs_type, binding_sheet_id, name, owner_id, sheet_type, is_hidden, created_at, updated_at FROM attrs WHERE 1=0",
				"SELECT id, data FROM ban_info WHERE 1=0",
				"SELECT id, created_at, data FROM group_info WHERE 1=0",
				"SELECT name, user_id, last_command_time, auto_set_name_template, dice_side_num, group_id FROM group_player_info WHERE 1=0",
			} {
				mock.ExpectQuery(query).WillReturnRows(sqlmock.NewRows([]string{"unused"}))
			}
			mock.ExpectExec("SAVEPOINT scardice_group_updated_at_probe").WillReturnResult(sqlmock.NewResult(0, 0))
			mock.ExpectQuery("SELECT updated_at FROM group_info WHERE 1=0").WillReturnError(test.err)
			mock.ExpectExec("ROLLBACK TO SAVEPOINT scardice_group_updated_at_probe").WillReturnResult(sqlmock.NewResult(0, 0))
			mock.ExpectExec("RELEASE SAVEPOINT scardice_group_updated_at_probe").WillReturnResult(sqlmock.NewResult(0, 0))
			mock.ExpectRollback()
			mock.ExpectClose()

			if err = source.Recheck(context.Background(), SourceMetadata{}); !errors.Is(err, test.err) {
				t.Errorf("group probe failure = %v, want original error %v", err, test.err)
			}
			if err = mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func newRemoteGroupProofFixture(t *testing.T) (*RemoteSQLSource, *sql.DB) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "data")
	if err := os.MkdirAll(filepath.Join(root, "default"), SnapshotTreeMode); err != nil {
		t.Fatal(err)
	}
	writeLegacyFixtureFile(t, filepath.Join(root, "dice.yaml"), []byte("diceConfigs:\n  - name: default\n    dataDir: default\n"))
	writeLegacyFixtureFile(t, filepath.Join(root, "default", "serve.yaml"), []byte("{}\n"))
	remotePath := filepath.Join(t.TempDir(), "remote.db")
	createLegacySQLiteFixture(t, remotePath)
	database, err := sql.Open("sqlite", remotePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	source := NewRemoteSQLSource(root, eventstore.DatabaseConfig{Type: "mysql", DSN: "unused"})
	source.open = func(context.Context, eventstore.DatabaseConfig) (*sql.DB, error) {
		return sql.Open("sqlite", "file:"+filepath.ToSlash(remotePath)+"?mode=ro")
	}
	return source, database
}

func assertRemoteGroupProofSnapshot(t *testing.T, snapshot SnapshotResult, wantDrop string) {
	t.Helper()
	drops := newDropRecorder(t.TempDir(), dropSourceLegacyImport, legacyDropFixedNow)
	t.Cleanup(func() { _, _, _ = drops.Close() })
	snapshot.Source.(interface{ bindDropRecorder(*dropRecorder) }).bindDropRecorder(drops)
	created := 0
	if err := snapshot.Source.(RecordStreamer).StreamRecords(context.Background(), func(batch []SourceRecord) error {
		for _, record := range batch {
			if record.Kind == string(groupstate.EventGroupCreated) {
				created++
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	dropPath, count, err := drops.Close()
	if err != nil {
		t.Fatal(err)
	}
	if wantDrop == "" {
		if created != 1 || count != 0 {
			t.Fatalf("snapshot imported groups/drops = %d/%d, want 1/0", created, count)
		}
		return
	}
	if created != 0 || count != 1 {
		t.Fatalf("snapshot imported groups/drops = %d/%d, want 0/1", created, count)
	}
	if record := readDropRecords(t, dropPath)["QQ-Group:100"]; record["reason"] != wantDrop {
		t.Fatalf("snapshot group drop = %#v, want reason %q", record, wantDrop)
	}
}
