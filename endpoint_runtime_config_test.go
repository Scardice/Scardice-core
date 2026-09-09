package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"Scardice-core/dice"
	"Scardice-core/endpoint"
	"Scardice-core/eventstore"
)

func TestEndpointDatabaseConfigRequiresExplicitKeyMaterial(t *testing.T) {
	values := map[string]string{"SCARDICE_ENDPOINT_DB": "events.db", "SCARDICE_ENDPOINT_DB_ID": "core-events-v1"}
	_, err := endpointDatabaseConfigFromEnv(func(key string) string { return values[key] })
	if !errors.Is(err, errEndpointBootstrapConfig) { t.Fatalf("missing key config error = %v", err) }
}

func TestEndpointDatabaseConfigBuildsStableSQLiteConfig(t *testing.T) {
	values := map[string]string{
		"SCARDICE_ENDPOINT_DB": "events.db", "SCARDICE_ENDPOINT_DB_ID": "core-events-v1",
		"SCARDICE_ENDPOINT_KEY_INDEX": "/var/lib/scardice/index.key", "SCARDICE_ENDPOINT_KEY_ROOTS": "/var/lib/scardice/roots",
	}
	config, err := endpointDatabaseConfigFromEnv(func(key string) string { return values[key] })
	if err != nil { t.Fatal(err) }
	if config.Type != "sqlite" || config.DSN != "events.db" || config.DatabaseIdentity != "core-events-v1" || config.KeySource == nil { t.Fatalf("config = %#v", config) }
}

func TestConfiguredBootstrapReachesFreshReadiness(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	indexPath := filepath.Join(dir, "index.key")
	rootsPath := filepath.Join(dir, "roots")
	if err := os.Mkdir(rootsPath, 0o700); err != nil { t.Fatal(err) }
	if err := os.WriteFile(indexPath, []byte("01234567890123456789012345678901"), 0o600); err != nil { t.Fatal(err) }
	if err := os.WriteFile(filepath.Join(rootsPath, "root-v1.key"), []byte("abcdefghijklmnopqrstuvwxyz123456"), 0o600); err != nil { t.Fatal(err) }
	if err := os.WriteFile(filepath.Join(rootsPath, "current"), []byte("root-v1"), 0o600); err != nil { t.Fatal(err) }
	values := map[string]string{
		"SCARDICE_ENDPOINT_DB": filepath.Join(dir, "events.db"), "SCARDICE_ENDPOINT_DB_ID": "configured-events-v1",
		"SCARDICE_ENDPOINT_KEY_INDEX": indexPath, "SCARDICE_ENDPOINT_KEY_ROOTS": rootsPath,
	}
	config, err := endpointDatabaseConfigFromEnv(func(key string) string { return values[key] })
	if err != nil { t.Fatal(err) }
	database, err := eventstore.OpenDatabase(ctx, config)
	if err != nil { t.Fatal(err) }
	store := eventstore.NewStore(database)
	bootstrap, err := endpoint.NewBootstrap(store, nil, dice.NewOnebotDescriptor())
	if err != nil { _ = database.Close(); t.Fatal(err) }
	if _, err = bootstrap.Startup(ctx); err != nil { _ = bootstrap.Shutdown(ctx); t.Fatal(err) }
	if err := bootstrap.Shutdown(ctx); err != nil { t.Fatal(err) }
}
