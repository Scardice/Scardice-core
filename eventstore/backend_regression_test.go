package eventstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func runBackendRegressionStores(t *testing.T, test func(*testing.T, *GORMStore, *Database)) {
	t.Helper()
	for _, backend := range []struct {
		name string
		env  string
	}{
		{name: "sqlite"},
		{name: "mysql", env: "SCARDICE_EVENTSTORE_MYSQL_DSN"},
		{name: "postgres", env: "SCARDICE_EVENTSTORE_POSTGRES_DSN"},
	} {
		t.Run(backend.name, func(t *testing.T) {
			dsn := os.Getenv(backend.env)
			if backend.name == "sqlite" {
				dsn = filepath.Join(t.TempDir(), "backend-regressions.db")
			} else if dsn == "" {
				t.Skipf("%s is unset; opt-in backend regression skipped", backend.env)
			}
			database, err := OpenDatabase(context.Background(), DatabaseConfig{
				Type: backend.name, DSN: dsn, TLSVerify: true, AllowInsecureLoopback: true,
				ConnectTimeout: 5 * time.Second, QueryTimeout: 5 * time.Second,
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = database.Close() })
			test(t, NewStore(database), database)
		})
	}
}

func TestBackendSecretOwnersRetainMultibyteCapacity(t *testing.T) {
	runBackendRegressionStores(t, func(t *testing.T, store *GORMStore, database *Database) {
		ctx := context.Background()
		// Both owners fit the former varchar(255) character capacity, but not a
		// 255-byte binary column. Their differing final characters share the
		// first 255 bytes, so owner resolution also catches silent truncation.
		endpoint := strings.Repeat("端", 254) + "甲"
		adapter := strings.Repeat("🙂", 254) + "甲"
		otherEndpoint := strings.Repeat("端", 254) + "乙"
		otherAdapter := strings.Repeat("🙂", 254) + "乙"
		ref := fmt.Sprintf("backend-owner-%d", time.Now().UnixNano())
		t.Cleanup(func() {
			if err := rawStringQuery(database.GORM(), "secret_ref", ref).Delete(&adapterSecretRow{}).Error; err != nil {
				t.Errorf("remove secret regression fixture: %v", err)
			}
		})

		request := SecretPutRequest{SecretRef: ref, EndpointID: endpoint, AdapterID: adapter, Value: []byte("first version")}
		created, err := store.PutSecret(ctx, request)
		if err != nil || created.SecretVersion != 1 || string(created.Value) != "first version" {
			t.Fatalf("put multibyte-owned secret = %+v, error = %v", created, err)
		}
		for _, owner := range []struct{ endpoint, adapter string }{
			{endpoint: otherEndpoint, adapter: adapter},
			{endpoint: endpoint, adapter: otherAdapter},
			{endpoint: endpoint + " ", adapter: adapter},
			{endpoint: endpoint, adapter: adapter + " "},
		} {
			if _, err := store.ResolveSecretForOwner(ctx, owner.endpoint, owner.adapter, ref, 1); !errors.Is(err, ErrNotFound) {
				t.Fatalf("different long owner resolved the secret: %v", err)
			}
		}
		resolved, err := store.ResolveSecretForOwner(ctx, endpoint, adapter, ref, 1)
		if err != nil || resolved.SecretRef != ref || resolved.SecretVersion != 1 || string(resolved.Value) != "first version" {
			t.Fatalf("resolve multibyte-owned secret = %+v, error = %v", resolved, err)
		}

		request.ExpectedVersion = 1
		request.Value = []byte("second version")
		updated, err := store.PutSecret(ctx, request)
		if err != nil || updated.SecretVersion != 2 {
			t.Fatalf("update multibyte-owned secret = %+v, error = %v", updated, err)
		}
		latest, err := store.ResolveSecretForOwner(ctx, endpoint, adapter, ref, 0)
		if err != nil || latest.SecretVersion != 2 || string(latest.Value) != "second version" {
			t.Fatalf("resolve latest multibyte-owned secret = %+v, error = %v", latest, err)
		}
		original, err := store.ResolveSecret(ctx, ref, 1)
		if err != nil || string(original.Value) != "first version" {
			t.Fatalf("resolve original secret version = %+v, error = %v", original, err)
		}
		request.ExpectedVersion = 2
		request.EndpointID = otherEndpoint
		if _, err := store.PutSecret(ctx, request); !errors.Is(err, ErrInvalidMetadata) {
			t.Fatalf("changing the long secret owner was not rejected: %v", err)
		}
	})
}

func TestBackendProjectionLIKEReadersMatchLiteralCharacters(t *testing.T) {
	runBackendRegressionStores(t, func(t *testing.T, store *GORMStore, database *Database) {
		ctx := context.Background()
		var control projectionControlRow
		if err := database.ReadGORM().Where("singleton_id = ?", "default").First(&control).Error; err != nil {
			t.Fatal(err)
		}
		namespace := fmt.Sprintf("backend-like-%d", time.Now().UnixNano())
		for _, tc := range []struct{ name, prefix, decoy string }{
			{name: "percent", prefix: "owner%", decoy: "ownerX"},
			{name: "underscore", prefix: "owner_", decoy: "ownerX"},
			{name: "exclamation", prefix: "owner!", decoy: "owner"},
			{name: "backslash", prefix: `owner\`, decoy: "owner"},
			{name: "combined", prefix: `owner%_!\:`, decoy: "ownerXY:"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				projection := namespace + "-" + tc.name
				insertProjectionPageRows(t, database, control.ActiveGeneration, projection, []string{
					tc.prefix + "a", tc.prefix + "b", "left/" + tc.prefix + "middle",
					tc.decoy + "a", "left/" + tc.decoy + "middle", "separate-fragment",
				})
				t.Cleanup(func() {
					if err := database.GORM().Where("projection_name = ?", projection).Delete(&projectionReadModelRow{}).Error; err != nil {
						t.Errorf("remove projection regression fixture: %v", err)
					}
				})
				wantPrefix := []string{tc.prefix + "a", tc.prefix + "b"}
				for _, reader := range []struct {
					name string
					read func() ([]ProjectionRow, error)
				}{
					{name: "prefix list", read: func() ([]ProjectionRow, error) {
						return store.ListProjectionRowsByRowKeyPrefix(ctx, projection, tc.prefix)
					}},
					{name: "projection page", read: func() ([]ProjectionRow, error) {
						page, err := store.ListProjectionRowsPage(ctx, ProjectionPageRequest{
							ProjectionName: projection, RowKeyPrefix: tc.prefix, Limit: 10,
						})
						return page.Rows, err
					}},
					{name: "catalog page", read: func() ([]ProjectionRow, error) {
						page, err := store.ListCatalogProjectionSnapshot(ctx, CatalogProjectionListRequest{
							Catalog: "literal-prefix", Owner: projection, ProjectionName: projection,
							RowKeyPrefix: tc.prefix, Limit: 10,
						})
						return page.Rows, err
					}},
				} {
					t.Run(reader.name, func(t *testing.T) {
						rows, err := reader.read()
						if err != nil {
							t.Fatal(err)
						}
						assertBackendProjectionKeys(t, rows, wantPrefix)
					})
				}
				rows, err := store.ListProjectionRowsByRowKeyFragments(ctx, projection, []string{tc.prefix, "separate-fragment"})
				if err != nil {
					t.Fatal(err)
				}
				assertBackendProjectionKeys(t, rows, []string{
					"left/" + tc.prefix + "middle", tc.prefix + "a", tc.prefix + "b", "separate-fragment",
				})
			})
		}
	})
}

func assertBackendProjectionKeys(t *testing.T, rows []ProjectionRow, want []string) {
	t.Helper()
	got := make([]string, len(rows))
	for i, row := range rows {
		got[i] = row.RowKey
		if string(row.Payload) != row.RowKey {
			t.Fatalf("projection row payload = %q, want %q", row.Payload, row.RowKey)
		}
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("projection row keys = %q, want %q", got, want)
	}
}
