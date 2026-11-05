package v1reader

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testdata/v1 is a database written by the real v1 application: two groups
// with players, attribute sheets and a Story log each, plus adapter secrets
// (one with two versions) and plugin storage added through the v1 store API.
// The key files are throwaway test keys.

func fixtureKeys(t *testing.T) (dbPath string, keys *Keys) {
	t.Helper()
	root := filepath.Join("testdata", "v1")
	return filepath.Join(root, "events.db"), OpenKeys(filepath.Join(root, "keys", "index.key"), filepath.Join(root, "keys", "roots"))
}

func fileDigest(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func newSQLite(t *testing.T, statements ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "store.db")
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	for _, statement := range statements {
		if _, err = database.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func TestDetectDistinguishesTheStoreFormats(t *testing.T) {
	ctx := context.Background()
	fixture, _ := fixtureKeys(t)
	for _, tc := range []struct {
		name string
		path string
		want Format
	}{
		{"missing file", filepath.Join(t.TempDir(), "absent.db"), FormatNone},
		{"encrypted v1 store", fixture, FormatV1Encrypted},
		{"empty database", newSQLite(t, `CREATE TABLE disposable (id INTEGER)`, `DROP TABLE disposable`), FormatEmpty},
		{"unrelated database", newSQLite(t, `CREATE TABLE unrelated (id INTEGER)`), FormatUnknown},
		{"event tables but no readiness", newSQLite(t, `CREATE TABLE domain_events (id INTEGER)`), FormatUnknown},
		{"plaintext v2 store", newSQLite(t,
			`CREATE TABLE domain_events (id INTEGER)`,
			`CREATE TABLE store_readiness (singleton_id TEXT, mode TEXT, schema_version TEXT, database_identity TEXT, completed_at DATETIME)`,
			`INSERT INTO store_readiness VALUES ('default', 'fresh', '2', 'plain-test', NULL)`), FormatV2Plain},
		{"readiness of an unknown version", newSQLite(t,
			`CREATE TABLE store_readiness (singleton_id TEXT, mode TEXT, schema_version TEXT)`,
			`INSERT INTO store_readiness VALUES ('default', 'fresh', '9')`), FormatUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Detect(ctx, tc.path)
			if err != nil || got != tc.want {
				t.Fatalf("Detect = %s, %v; want %s", got, err, tc.want)
			}
		})
	}
}

// Everything the v1 store holds is read back, class by class, and the number
// of decrypted rows equals the number of rows in the database: nothing is
// skipped silently.
func TestReaderReturnsEveryClassOfData(t *testing.T) {
	ctx := context.Background()
	dbPath, keys := fixtureKeys(t)
	before := fileDigest(t, dbPath)

	source, err := Open(dbPath, keys)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	inventory, err := source.Inventory(ctx)
	if err != nil {
		t.Fatal(err)
	}

	secrets, err := source.Secrets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != inventory.Secrets {
		t.Fatalf("secrets = %d, database has %d references", len(secrets), inventory.Secrets)
	}
	byRef := map[string]Secret{}
	for _, secret := range secrets {
		byRef[secret.Ref] = secret
	}
	if got := byRef["cred-onebot"]; got.Version != 2 || string(got.Plaintext) != `{"token":"onebot-secret-token-v2"}` ||
		got.EndpointID != "endpoint-onebot" || got.AdapterID != "onebot" {
		t.Fatalf("cred-onebot must be its newest version: %+v", got)
	}
	if got := byRef["cred-discord"]; !strings.Contains(string(got.Plaintext), "discord-bot-token") {
		t.Fatalf("cred-discord = %+v", got)
	}
	attributeSheets := 0
	for ref, secret := range byRef {
		if !strings.HasPrefix(ref, "vault:attributes-") {
			continue
		}
		attributeSheets++
		if !json.Valid(secret.Plaintext) {
			t.Fatalf("attribute sheet %s is not JSON: %q", ref, secret.Plaintext)
		}
	}
	if attributeSheets != inventory.ProjectionRows["attributes"] {
		t.Fatalf("attribute sheets = %d, attribute projection rows = %d", attributeSheets, inventory.ProjectionRows["attributes"])
	}

	kv, err := source.PluginKVs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(kv) != inventory.PluginKV {
		t.Fatalf("plugin storage = %d, database has %d", len(kv), inventory.PluginKV)
	}
	got := map[string]string{}
	for _, entry := range kv {
		got[entry.ExtensionID+"\x00"+entry.Key] = string(entry.Value)
	}
	for key, want := range map[string]string{
		"fixture-ext\x00counter": "42",
		"fixture-ext\x00中文键":     `{"nested":["a","b"]}`,
		"other-ext\x00":          "empty-key-value",
	} {
		if got[key] != want {
			t.Errorf("plugin storage %q = %q, want %q", key, got[key], want)
		}
	}

	rows, err := source.ProjectionRows(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	perProjection := map[string]int{}
	for _, row := range rows {
		perProjection[row.Name]++
		if !json.Valid(row.Payload) {
			t.Fatalf("projection %s row %q is not JSON", row.Name, row.RowKey)
		}
	}
	for name, want := range inventory.ProjectionRows {
		if perProjection[name] != want {
			t.Errorf("projection %s = %d rows, database has %d", name, perProjection[name], want)
		}
	}
	groups, err := source.ProjectionRows(ctx, "group-record")
	if err != nil || len(groups) != 3 {
		t.Fatalf("group-record rows = %d, %v", len(groups), err)
	}

	story, err := source.StoryLog(ctx)
	if err != nil {
		t.Fatal(err)
	}
	perKind := make(map[StoryKind]int)
	var messages []string
	for _, row := range story {
		perKind[row.Kind]++
		if row.Kind == StoryEntry {
			var entry struct {
				GroupID string `json:"groupId"`
				Message string `json:"message"`
			}
			if err = json.Unmarshal(row.Plain, &entry); err != nil {
				t.Fatalf("entry %d: %v", row.ID, err)
			}
			messages = append(messages, entry.GroupID+"|"+entry.Message)
		}
	}
	if perKind[StorySession] != inventory.StorySessions || perKind[StoryState] != inventory.StoryStates ||
		perKind[StoryEntry] != inventory.StoryEntries || perKind[StoryIntent] != inventory.StoryIntents {
		t.Fatalf("story rows %v, database has %+v", perKind, inventory)
	}
	for _, group := range []string{"UI-Group:2001", "UI-Group:2002"} {
		found := false
		for _, message := range messages {
			found = found || message == group+"|大家好，今天的故事开始了"
		}
		if !found {
			t.Errorf("the line spoken in %s is missing from the decrypted log", group)
		}
	}

	if after := fileDigest(t, dbPath); after != before {
		t.Fatal("reading modified the database file")
	}
}

// The frozen keyed-digest derivation must equal what the v1 store stored, or
// the fallback that recovers a group from its scope digest would be wrong.
func TestScopeDigestMatchesWhatTheStoreWrote(t *testing.T) {
	ctx := context.Background()
	dbPath, keys := fixtureKeys(t)
	source, err := Open(dbPath, keys)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	story, err := source.StoryLog(ctx)
	if err != nil {
		t.Fatal(err)
	}

	resolved, err := keys.ResolveScopes([]GroupRef{
		{DiceID: "default", GroupID: "UI-Group:2001"},
		{DiceID: "default", GroupID: "UI-Group:2002"},
		{DiceID: "default", GroupID: "UI-Group:9999"},
	})
	if err != nil {
		t.Fatal(err)
	}
	dice, err := keys.ResolveDice([]string{"default", "another"})
	if err != nil {
		t.Fatal(err)
	}
	matched := map[string]bool{}
	for _, row := range story {
		if row.Kind != StorySession {
			continue
		}
		var payload struct {
			GroupID string `json:"groupId"`
		}
		if err = json.Unmarshal(row.Plain, &payload); err != nil {
			t.Fatal(err)
		}
		ref, ok := resolved[hex.EncodeToString(row.Scope)]
		if !ok || ref.GroupID != payload.GroupID {
			t.Fatalf("scope of session %d resolved to %+v, payload says %q", row.ID, ref, payload.GroupID)
		}
		if id := dice[hex.EncodeToString(row.Dice)]; id != "default" {
			t.Fatalf("dice digest of session %d resolved to %q", row.ID, id)
		}
		matched[payload.GroupID] = true
	}
	if len(matched) != 2 {
		t.Fatalf("matched groups = %v", matched)
	}
}

func copyFixture(t *testing.T) (dbPath, keysDir string) {
	t.Helper()
	dir := t.TempDir()
	read := func(rel string) []byte {
		raw, err := os.ReadFile(filepath.Join("testdata", "v1", rel))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	write := func(rel string, raw []byte) string {
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	dbPath = write("events.db", read("events.db"))
	write("keys/index.key", read("keys/index.key"))
	write("keys/roots/root-v1.key", read("keys/roots/root-v1.key"))
	return dbPath, filepath.Join(dir, "keys")
}

func TestReaderRefusesWrongMissingAndTamperedKeys(t *testing.T) {
	ctx := context.Background()

	t.Run("wrong encryption root", func(t *testing.T) {
		dbPath, keysDir := copyFixture(t)
		if err := os.WriteFile(filepath.Join(keysDir, "roots", "root-v1.key"), []byte(strings.Repeat("x", 32)), 0o600); err != nil {
			t.Fatal(err)
		}
		source, err := Open(dbPath, OpenKeys(filepath.Join(keysDir, "index.key"), filepath.Join(keysDir, "roots")))
		if err != nil {
			t.Fatal(err)
		}
		defer source.Close()
		if _, err = source.Secrets(ctx); !errors.Is(err, ErrAuthenticationFailed) {
			t.Fatalf("err = %v, want authentication failure", err)
		}
	})

	t.Run("missing key file", func(t *testing.T) {
		dbPath, keysDir := copyFixture(t)
		if err := os.Remove(filepath.Join(keysDir, "roots", "root-v1.key")); err != nil {
			t.Fatal(err)
		}
		source, err := Open(dbPath, OpenKeys(filepath.Join(keysDir, "index.key"), filepath.Join(keysDir, "roots")))
		if err != nil {
			t.Fatal(err)
		}
		defer source.Close()
		if _, err = source.PluginKVs(ctx); !errors.Is(err, ErrKeyUnavailable) {
			t.Fatalf("err = %v, want key unavailable", err)
		}
	})

	t.Run("key file of the wrong size", func(t *testing.T) {
		dbPath, keysDir := copyFixture(t)
		if err := os.WriteFile(filepath.Join(keysDir, "roots", "root-v1.key"), []byte("short"), 0o600); err != nil {
			t.Fatal(err)
		}
		source, err := Open(dbPath, OpenKeys(filepath.Join(keysDir, "index.key"), filepath.Join(keysDir, "roots")))
		if err != nil {
			t.Fatal(err)
		}
		defer source.Close()
		if _, err = source.Secrets(ctx); !errors.Is(err, ErrKeyUnavailable) {
			t.Fatalf("err = %v, want key unavailable", err)
		}
	})

	t.Run("altered ciphertext", func(t *testing.T) {
		dbPath, keysDir := copyFixture(t)
		database, err := sql.Open("sqlite", dbPath)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = database.Exec(`UPDATE adapter_secrets SET ciphertext = X'00' || substr(ciphertext, 2) WHERE secret_ref = 'cred-discord'`); err != nil {
			t.Fatal(err)
		}
		database.Close()
		source, err := Open(dbPath, OpenKeys(filepath.Join(keysDir, "index.key"), filepath.Join(keysDir, "roots")))
		if err != nil {
			t.Fatal(err)
		}
		defer source.Close()
		_, err = source.Secrets(ctx)
		if !errors.Is(err, ErrAuthenticationFailed) || !strings.Contains(err.Error(), "cred-discord") {
			t.Fatalf("err = %v, want authentication failure naming the secret", err)
		}
	})
}
