package eventsourcing

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"Scardice-core/eventstore"
	"Scardice-core/migrate/eventsourcing/v1reader"
)

func copyV1Fixture(t *testing.T) (dir, database, keys string) {
	t.Helper()
	root := filepath.Join("v1reader", "testdata", "v1")
	dir = t.TempDir()
	database, keys = filepath.Join(dir, "events.db"), filepath.Join(dir, "keys")
	copyFile := func(source, destination string) {
		t.Helper()
		data, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(destination, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	copyFile(filepath.Join(root, "events.db"), database)
	copyFile(filepath.Join(root, "keys", "index.key"), filepath.Join(keys, "index.key"))
	entries, err := os.ReadDir(filepath.Join(root, "keys", "roots"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		copyFile(filepath.Join(root, "keys", "roots", entry.Name()), filepath.Join(keys, "roots", entry.Name()))
	}
	return dir, database, keys
}

func fileDigest(t *testing.T, path string) [sha256.Size]byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(data)
}

func v1FixtureIdentity(t *testing.T, database, keys string) string {
	t.Helper()
	source, err := v1reader.Open(database, v1reader.OpenKeys(filepath.Join(keys, "index.key"), filepath.Join(keys, "roots")))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	identity, err := source.DatabaseIdentity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func TestConvertV1ProducesCurrentStateBaselineAndKeepsOriginal(t *testing.T) {
	ctx := context.Background()
	_, database, keys := copyV1Fixture(t)
	identity := v1FixtureIdentity(t, database, keys)
	before := fileDigest(t, database)
	source, err := v1reader.Open(database, v1reader.OpenKeys(filepath.Join(keys, "index.key"), filepath.Join(keys, "roots")))
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := source.Inventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := source.LatestSecrets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	plugin, err := source.PluginKVs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := source.ProjectionRows(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	baseline := newV1Baseline()
	for _, row := range rows {
		if err = baseline.addProjection(row); err != nil {
			t.Fatal(err)
		}
	}
	if err = source.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := ConvertV1(ctx, V1ConvertOptions{ActivePath: database, KeysDir: keys, Identity: identity, Now: func() time.Time { return time.Date(2026, 11, 2, 3, 4, 5, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	if result.Events == 0 || result.ReferencedSecrets != len(baseline.secretVersions) || result.OmittedSecrets != inventory.Secrets-result.ReferencedSecrets || result.SecretVersions != result.Secrets || result.PluginKV != inventory.PluginKV || result.StorySessions != inventory.StorySessions || result.StoryStates != inventory.StoryStates || result.StoryEntries != inventory.StoryEntries {
		t.Fatalf("result=%+v inventory=%+v", result, inventory)
	}
	if fileDigest(t, result.BackupPath) != before || !strings.Contains(result.BackupPath, "events.db.v1.") || !strings.HasSuffix(result.BackupPath, ".bak") {
		t.Fatal("original backup changed or misnamed")
	}
	if candidates, _ := filepath.Glob(database + ".import-*"); len(candidates) != 0 {
		t.Fatalf("candidate files remain: %v", candidates)
	}
	opened, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: database, DatabaseIdentity: identity})
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	store := eventstore.NewStore(opened)
	readiness, err := store.GetReadiness(ctx)
	if err != nil || readiness.Mode != "import" || readiness.SchemaVersion != 2 || readiness.DatabaseIdentity != identity || readiness.CompletedAt.IsZero() {
		t.Fatalf("readiness=%+v err=%v", readiness, err)
	}
	for _, secret := range secrets {
		if _, referenced := baseline.secretVersions[secret.Ref]; !referenced {
			continue
		}
		ref := secret.Ref
		if mapped, ok := baseline.secretAliases[ref]; ok {
			ref = mapped
		}
		resolved, err := store.ResolveSecret(ctx, ref, 1)
		if err != nil || !bytes.Equal(resolved.Value, secret.Plaintext) {
			t.Fatalf("latest secret %q lost: %v", ref, err)
		}
		update, err := store.PrepareSecretUpdate(ctx, eventstore.SecretPutRequest{SecretRef: ref, EndpointID: secret.EndpointID, AdapterID: secret.AdapterID, ExpectedVersion: 1, Value: []byte{}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = store.Commit(ctx, eventstore.UnitOfWork{SecretUpdates: []eventstore.SecretUpdate{update}}); err != nil {
			t.Fatalf("next write %q: %v", ref, err)
		}
	}
	for _, item := range plugin {
		got, err := store.GetPluginKV(ctx, item.ExtensionID, item.Key)
		if err != nil || !bytes.Equal(got.Value, item.Value) {
			t.Fatalf("plugin %s/%s lost: %v", item.ExtensionID, item.Key, err)
		}
	}
	if _, err = ConvertV1(ctx, V1ConvertOptions{ActivePath: database, KeysDir: keys, Identity: identity}); !errors.Is(err, ErrNotV1Store) {
		t.Fatalf("second conversion: %v", err)
	}
}

func TestConvertV1IgnoresHistoricalEventsAndRetiredSecretVersions(t *testing.T) {
	ctx := context.Background()
	_, database, keys := copyV1Fixture(t)
	identity := v1FixtureIdentity(t, database, keys)
	raw, err := sql.Open("sqlite", database)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{`UPDATE domain_events SET payload = 'obsolete corrupt historical event'`, `UPDATE adapter_secrets SET ciphertext = X'00' WHERE secret_version < (SELECT MAX(s.secret_version) FROM adapter_secrets s WHERE s.secret_ref = adapter_secrets.secret_ref)`} {
		if _, err = raw.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if err = raw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = ConvertV1(ctx, V1ConvertOptions{ActivePath: database, KeysDir: keys, Identity: identity}); err != nil {
		t.Fatalf("baseline read obsolete history: %v", err)
	}
}

func TestConvertV1DoesNotDecryptUnreferencedOwners(t *testing.T) {
	_, database, keys := copyV1Fixture(t)
	identity := v1FixtureIdentity(t, database, keys)
	raw, err := sql.Open("sqlite", database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = raw.Exec(`UPDATE adapter_secrets SET encryption_key_id = 'missing-retired-key' WHERE secret_ref IN ('cred-onebot','cred-discord')`); err != nil {
		t.Fatal(err)
	}
	if err = raw.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := ConvertV1(context.Background(), V1ConvertOptions{ActivePath: database, KeysDir: keys, Identity: identity})
	if err != nil {
		t.Fatalf("an orphan owner blocked current-state import: %v", err)
	}
	if result.OmittedSecrets < 2 {
		t.Fatalf("orphan owners not accounted for: %+v", result)
	}
}

func TestConvertV1FailsClosedForReferencedSecretOrUnpublishedProjection(t *testing.T) {
	for _, statement := range []string{
		`UPDATE adapter_secrets SET ciphertext = X'00' WHERE secret_ref = 'vault:manager-auth'`,
		`UPDATE projection_control SET publication_state = 'rebuilding'`,
	} {
		t.Run(statement, func(t *testing.T) {
			_, database, keys := copyV1Fixture(t)
			identity := v1FixtureIdentity(t, database, keys)
			raw, err := sql.Open("sqlite", database)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = raw.Exec(statement); err != nil {
				t.Fatal(err)
			}
			if err = raw.Close(); err != nil {
				t.Fatal(err)
			}
			before := fileDigest(t, database)
			if _, err = ConvertV1(context.Background(), V1ConvertOptions{ActivePath: database, KeysDir: keys, Identity: identity}); err == nil {
				t.Fatal("damaged current state was published")
			}
			if fileDigest(t, database) != before {
				t.Fatal("failed current-state validation changed source")
			}
		})
	}
}

func TestConvertV1KeepsImportReadinessWithOnlyLightMetadata(t *testing.T) {
	ctx := context.Background()
	_, database, keys := copyV1Fixture(t)
	identity := v1FixtureIdentity(t, database, keys)
	raw, err := sql.Open("sqlite", database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = raw.Exec(`UPDATE store_readiness SET mode = 'import'`); err != nil {
		t.Fatal(err)
	}
	if err = raw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = ConvertV1(ctx, V1ConvertOptions{ActivePath: database, KeysDir: keys, Identity: identity}); err != nil {
		t.Fatal(err)
	}
	opened, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: database, DatabaseIdentity: identity})
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if _, err = ValidateStartupReadiness(ctx, eventstore.NewStore(opened), true); err != nil {
		t.Fatal(err)
	}
}

func TestConvertV1FailureRestoresOriginalAtEveryPublicationBoundary(t *testing.T) {
	for _, stage := range []string{"events", "secrets", "story-log", "rebuild", "reopen", "verify", "publish", "backup", "activate", "activated"} {
		t.Run(stage, func(t *testing.T) {
			_, database, keys := copyV1Fixture(t)
			identity := v1FixtureIdentity(t, database, keys)
			before := fileDigest(t, database)
			injected := errors.New("injected " + stage)
			_, err := ConvertV1(context.Background(), V1ConvertOptions{ActivePath: database, KeysDir: keys, Identity: identity, Inject: FailureFunc(func(name string) error {
				if name == stage {
					return injected
				}
				return nil
			})})
			if !errors.Is(err, injected) {
				t.Fatalf("error=%v", err)
			}
			if fileDigest(t, database) != before {
				t.Fatal("original changed")
			}
			for _, pattern := range []string{".import-*", ".v1.*.bak"} {
				if files, _ := filepath.Glob(database + pattern); len(files) > 0 {
					t.Fatalf("leftovers=%v", files)
				}
			}
		})
	}
}

func TestConvertV1DoesNotRemovePreexistingCandidate(t *testing.T) {
	_, database, keys := copyV1Fixture(t)
	identity := v1FixtureIdentity(t, database, keys)
	now := time.Date(2026, 11, 2, 3, 4, 5, 0, time.UTC)
	candidate := database + ".import-" + now.Format("20060102T150405.000000000Z")
	if err := os.WriteFile(candidate, []byte("owned by another attempt"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := fileDigest(t, candidate)
	if _, err := ConvertV1(context.Background(), V1ConvertOptions{ActivePath: database, KeysDir: keys, Identity: identity, Now: func() time.Time { return now }}); err == nil {
		t.Fatal("candidate collision accepted")
	}
	if fileDigest(t, candidate) != before {
		t.Fatal("unowned candidate removed or changed")
	}
}
