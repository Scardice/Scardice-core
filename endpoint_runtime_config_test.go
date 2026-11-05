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

func TestEndpointDatabaseConfigRequiresExplicitIdentity(t *testing.T) {
	values := map[string]string{"SCARDICE_ENDPOINT_DB": "events.db"}
	_, err := endpointDatabaseConfigFromEnv(func(key string) string { return values[key] })
	if !errors.Is(err, errEndpointBootstrapConfig) {
		t.Fatalf("missing identity config error = %v", err)
	}
}

func TestEndpointDatabaseConfigCreatesLocalDefaults(t *testing.T) {
	dir := t.TempDir()
	empty := func(string) string { return "" }

	first, err := ensureEndpointDatabaseConfig(empty, dir)
	if err != nil {
		t.Fatal(err)
	}
	if first.Type != "sqlite" || first.DSN != filepath.Join(dir, "data", "endpoint", "events.db") || first.DatabaseIdentity == "" {
		t.Fatalf("first config = %#v", first)
	}
	configPath := filepath.Join(dir, "data", "endpoint", "config.json")
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config permissions = %o, want 600", info.Mode().Perm())
	}

	second, err := ensureEndpointDatabaseConfig(empty, dir)
	if err != nil {
		t.Fatal(err)
	}
	if first.DSN != second.DSN || first.DatabaseIdentity != second.DatabaseIdentity {
		t.Fatalf("local config changed across startup: first=%#v second=%#v", first, second)
	}
}

func TestEndpointDatabaseConfigReportsBootstrapEvents(t *testing.T) {
	dir := t.TempDir()
	var events []endpointBootstrapEvent
	audit := func(event endpointBootstrapEvent) {
		events = append(events, event)
	}

	if _, err := ensureEndpointDatabaseConfigWithAudit(func(string) string { return "" }, dir, audit); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("first bootstrap events = %#v, want one creation", events)
	}
	for _, event := range events {
		if !event.Created || event.Resource == "" || event.Path == "" {
			t.Fatalf("invalid creation event = %#v", event)
		}
	}

	events = nil
	if _, err := ensureEndpointDatabaseConfigWithAudit(func(string) string { return "" }, dir, audit); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Created || events[0].Resource != endpointBootstrapResourceReuse {
		t.Fatalf("reuse events = %#v, want one reuse event", events)
	}
}

func TestEndpointDatabaseConfigRejectsIncompleteLocalDefaults(t *testing.T) {
	dir := t.TempDir()
	endpointDir := filepath.Join(dir, "data", "endpoint")
	if err := os.MkdirAll(endpointDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(endpointDir, "events.db"), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := ensureEndpointDatabaseConfig(func(string) string { return "" }, dir)
	if !errors.Is(err, errLocalEndpointBootstrapIncomplete) {
		t.Fatalf("incomplete local config error = %v", err)
	}
}

func TestEndpointDatabaseConfigPreservesExplicitEnvironment(t *testing.T) {
	dir := t.TempDir()
	values := map[string]string{
		"SCARDICE_ENDPOINT_DB":    "events.db",
		"SCARDICE_ENDPOINT_DB_ID": "explicit-events-v1",
	}
	config, err := ensureEndpointDatabaseConfig(func(key string) string { return values[key] }, dir)
	if err != nil {
		t.Fatal(err)
	}
	if config.DSN != "events.db" || config.DatabaseIdentity != "explicit-events-v1" {
		t.Fatalf("explicit config = %#v", config)
	}
	if _, err := os.Stat(filepath.Join(dir, "data", "endpoint", "config.json")); !os.IsNotExist(err) {
		t.Fatalf("explicit configuration created local config: %v", err)
	}
}

func TestEndpointDatabaseConfigBuildsStableSQLiteConfig(t *testing.T) {
	values := map[string]string{
		"SCARDICE_ENDPOINT_DB": "events.db", "SCARDICE_ENDPOINT_DB_ID": "core-events-v1",
	}
	config, err := endpointDatabaseConfigFromEnv(func(key string) string { return values[key] })
	if err != nil {
		t.Fatal(err)
	}
	if config.Type != "sqlite" || config.DSN != "events.db" || config.DatabaseIdentity != "core-events-v1" {
		t.Fatalf("config = %#v", config)
	}
}

func TestEndpointDatabaseConfigBuildsRemoteLoopbackConfig(t *testing.T) {
	values := map[string]string{
		"SCARDICE_ENDPOINT_DB":                         "postgres://scardice:secret@127.0.0.1:5432/events?sslmode=disable",
		"SCARDICE_ENDPOINT_DB_TYPE":                    "postgres",
		"SCARDICE_ENDPOINT_DB_ID":                      "remote-events-v1",
		"SCARDICE_ENDPOINT_DB_ALLOW_INSECURE_LOOPBACK": "true",
	}
	config, err := endpointDatabaseConfigFromEnv(func(key string) string { return values[key] })
	if err != nil {
		t.Fatal(err)
	}
	if config.Type != "postgres" || !config.AllowInsecureLoopback || config.TLSVerify || config.DatabaseIdentity != "remote-events-v1" {
		t.Fatalf("config = %#v", config)
	}
}

func TestEndpointDatabaseConfigReadsActiveRemoteSlot(t *testing.T) {
	slotFile := filepath.Join(t.TempDir(), "active-slot")
	if err := os.WriteFile(slotFile, []byte("blue\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	values := map[string]string{
		"SCARDICE_ENDPOINT_DB_SLOT_FILE":       slotFile,
		"SCARDICE_ENDPOINT_DB_BLUE":            "postgres://db.example/events?sslmode=verify-full",
		"SCARDICE_ENDPOINT_DB_BLUE_TYPE":       "postgres",
		"SCARDICE_ENDPOINT_DB_BLUE_ID":         "remote-blue",
		"SCARDICE_ENDPOINT_DB_BLUE_TLS_VERIFY": "true",
	}
	config, err := endpointDatabaseConfigFromEnv(func(key string) string { return values[key] })
	if err != nil {
		t.Fatal(err)
	}
	if config.Type != "postgres" || config.DatabaseIdentity != "remote-blue" || !config.TLSVerify {
		t.Fatalf("slot config = %#v", config)
	}
}

func TestWriteEndpointDatabaseSlotAtomicallyChangesSelection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "active-slot")
	if err := os.WriteFile(path, []byte("blue\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeEndpointDatabaseSlot(path, "green"); err != nil {
		t.Fatal(err)
	}
	slot, err := readEndpointDatabaseSlot(path)
	if err != nil {
		t.Fatal(err)
	}
	if slot != "green" {
		t.Fatalf("active slot = %q", slot)
	}
}

func TestEndpointDatabaseConfigRejectsInvalidBoolean(t *testing.T) {
	values := map[string]string{
		"SCARDICE_ENDPOINT_DB": "events.db", "SCARDICE_ENDPOINT_DB_ID": "core-events-v1",
		"SCARDICE_ENDPOINT_DB_TLS_VERIFY": "sometimes",
	}
	if _, err := endpointDatabaseConfigFromEnv(func(key string) string { return values[key] }); !errors.Is(err, errEndpointBootstrapConfig) {
		t.Fatalf("invalid bool error = %v", err)
	}
}

func TestConfiguredBootstrapReachesFreshReadiness(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	values := map[string]string{
		"SCARDICE_ENDPOINT_DB": filepath.Join(dir, "events.db"), "SCARDICE_ENDPOINT_DB_ID": "configured-events-v1",
	}
	config, err := endpointDatabaseConfigFromEnv(func(key string) string { return values[key] })
	if err != nil {
		t.Fatal(err)
	}
	database, err := eventstore.OpenDatabase(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	store := eventstore.NewStore(database)
	bootstrap, err := endpoint.NewBootstrap(store, nil, dice.NewOnebotDescriptor())
	if err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	if _, err = bootstrap.Startup(ctx); err != nil {
		_ = bootstrap.Shutdown(ctx)
		t.Fatal(err)
	}
	if err := bootstrap.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}
