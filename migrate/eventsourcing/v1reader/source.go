package v1reader

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
)

// Source reads the current state out of a v1 event-store database. It never
// writes to it.
type Source struct {
	db   *sql.DB
	keys *Keys
}

// Open opens the v1 database at path read-only.
func Open(path string, keys *Keys) (*Source, error) {
	if keys == nil {
		return nil, ErrKeyUnavailable
	}
	database, err := openReadOnly(path)
	if err != nil {
		return nil, err
	}
	return &Source{db: database, keys: keys}, nil
}

// Close releases the database.
func (s *Source) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Keys returns the key reader, for callers that need to recompute digests.
func (s *Source) Keys() *Keys { return s.keys }

// Secret is one adapter secret (a credential, or a stored attribute sheet) in
// plaintext. Only the newest version of each reference is returned.
type Secret struct {
	Ref        string
	EndpointID string
	AdapterID  string
	Version    uint64
	Plaintext  []byte
}

// Secrets returns the newest version of every adapter secret, decrypted.
func (s *Source) Secrets(ctx context.Context) ([]Secret, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT secret_ref, secret_version, endpoint_id, adapter_id, ciphertext, nonce, encryption_key_id FROM adapter_secrets ORDER BY secret_ref, secret_version`)
	if err != nil {
		return nil, fmt.Errorf("v1reader: read adapter secrets: %w", err)
	}
	defer rows.Close()
	latest := map[string]Secret{}
	var order []string
	for rows.Next() {
		var ref, endpoint, adapter, keyID string
		var version uint64
		var ciphertext, nonce []byte
		if err = rows.Scan(&ref, &version, &endpoint, &adapter, &ciphertext, &nonce, &keyID); err != nil {
			return nil, err
		}
		plain, openErr := s.keys.open("adapter-secret/v1", ref, endpoint+"/"+adapter, version, keyID, ciphertext, nonce)
		if openErr != nil {
			return nil, fmt.Errorf("v1reader: adapter secret %q version %d: %w", ref, version, openErr)
		}
		if _, seen := latest[ref]; !seen {
			order = append(order, ref)
		}
		latest[ref] = Secret{Ref: ref, EndpointID: endpoint, AdapterID: adapter, Version: version, Plaintext: plain}
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	out := make([]Secret, 0, len(order))
	for _, ref := range order {
		out = append(out, latest[ref])
	}
	return out, nil
}

// PluginKV is one plugin storage entry in plaintext.
type PluginKV struct {
	ExtensionID string
	Key         string
	Value       []byte
}

// PluginKVs returns every plugin storage entry, decrypted.
func (s *Source) PluginKVs(ctx context.Context) ([]PluginKV, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT extension_id, key_hmac, encrypted_key, key_nonce, encrypted_value, value_nonce, row_version, encryption_key_id FROM plugin_kv ORDER BY extension_id, key_hmac`)
	if err != nil {
		return nil, fmt.Errorf("v1reader: read plugin storage: %w", err)
	}
	defer rows.Close()
	var out []PluginKV
	for rows.Next() {
		var extension, keyID string
		var index, encKey, keyNonce, encValue, valueNonce []byte
		var version uint64
		if err = rows.Scan(&extension, &index, &encKey, &keyNonce, &encValue, &valueNonce, &version, &keyID); err != nil {
			return nil, err
		}
		key, openErr := s.keys.open("plugin-kv-key/v1", string(index), extension, version, keyID, encKey, keyNonce)
		if openErr != nil {
			return nil, fmt.Errorf("v1reader: plugin storage key of %q: %w", extension, openErr)
		}
		value, openErr := s.keys.open("plugin-kv-value/v1", string(index), extension, version, keyID, encValue, valueNonce)
		if openErr != nil {
			return nil, fmt.Errorf("v1reader: plugin storage value of %q key %q: %w", extension, key, openErr)
		}
		out = append(out, PluginKV{ExtensionID: extension, Key: string(key), Value: value})
	}
	return out, rows.Err()
}

// ProjectionRow is one row of a projection's current read model. The payloads
// are plain JSON in the v1 store already.
type ProjectionRow struct {
	Name    string
	RowKey  string
	Payload []byte
}

// ProjectionRows returns the rows of the published projection generation, or
// every projection if name is empty.
func (s *Source) ProjectionRows(ctx context.Context, name string) ([]ProjectionRow, error) {
	var generation string
	err := s.db.QueryRowContext(ctx, `SELECT active_generation FROM projection_control WHERE singleton_id = 'default'`).Scan(&generation)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("v1reader: read projection control: %w", err)
	}
	query := `SELECT projection_name, row_key, payload FROM projection_read_models WHERE projection_generation = ? AND payload_present = 1`
	args := []any{generation}
	if name != "" {
		query += ` AND projection_name = ?`
		args = append(args, name)
	}
	rows, err := s.db.QueryContext(ctx, query+` ORDER BY projection_name, row_key`, args...)
	if err != nil {
		return nil, fmt.Errorf("v1reader: read projection rows: %w", err)
	}
	defer rows.Close()
	var out []ProjectionRow
	for rows.Next() {
		var row ProjectionRow
		if err = rows.Scan(&row.Name, &row.RowKey, &row.Payload); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// StoryKind names a Story-log table.
type StoryKind string

const (
	StorySession StoryKind = "session"
	StoryState   StoryKind = "state"
	StoryEntry   StoryKind = "entry"
	StoryIntent  StoryKind = "intent"
)

// StoryRow is one decrypted Story-log row. The v1 store identifies the Dice,
// group and owner only by keyed digests; Scope and Dice carry them as stored
// and ResolveScope / ResolveDice turn them back into IDs.
type StoryRow struct {
	Kind      StoryKind
	ID        uint64 // session or entry row ID; 0 for states and intents
	SessionID uint64 // entries and intents
	EffectID  string // intents
	Scope     []byte
	Dice      []byte // sessions only
	Version   uint64
	CreatedAt int64 // sessions only
	UpdatedAt int64 // sessions only
	Plain     []byte
}

func (s *Source) storyOpen(domain string, scope, owner []byte, id, version uint64, keyID string, ciphertext, nonce []byte) ([]byte, error) {
	identity := fmt.Sprintf("%x/%d", scope, id)
	return s.keys.open(domain, identity, "hmac:"+hex.EncodeToString(owner), version, keyID, ciphertext, nonce)
}

// StoryLog returns every Story-log session, state, entry and pending outbound
// intent, decrypted: sessions, then states, entries and intents, each in key
// order.
func (s *Source) StoryLog(ctx context.Context) ([]StoryRow, error) {
	var out []StoryRow
	for _, read := range []func(context.Context) ([]StoryRow, error){s.storySessions, s.storyStates, s.storyEntries, s.storyIntents} {
		rows, err := read(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, rows...)
	}
	return out, nil
}

func (s *Source) storySessions(ctx context.Context) ([]StoryRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, dice_hmac, scope_hmac, owner_hmac, payload, nonce, encryption_key_id, version, created_at, updated_at FROM story_log_sessions ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("v1reader: read story sessions: %w", err)
	}
	defer rows.Close()
	var out []StoryRow
	for rows.Next() {
		var row StoryRow
		var owner, ciphertext, nonce []byte
		var keyID string
		if err = rows.Scan(&row.ID, &row.Dice, &row.Scope, &owner, &ciphertext, &nonce, &keyID, &row.Version, &row.CreatedAt, &row.UpdatedAt); err != nil {
			return nil, err
		}
		row.Kind = StorySession
		if row.Plain, err = s.storyOpen("story-log-session/v1", row.Scope, owner, row.ID, row.Version, keyID, ciphertext, nonce); err != nil {
			return nil, fmt.Errorf("v1reader: story session %d: %w", row.ID, err)
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (s *Source) storyStates(ctx context.Context) ([]StoryRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT scope_hmac, owner_hmac, payload, nonce, encryption_key_id, version FROM story_log_states ORDER BY scope_hmac`)
	if err != nil {
		return nil, fmt.Errorf("v1reader: read story states: %w", err)
	}
	defer rows.Close()
	var out []StoryRow
	for rows.Next() {
		var row StoryRow
		var owner, ciphertext, nonce []byte
		var keyID string
		if err = rows.Scan(&row.Scope, &owner, &ciphertext, &nonce, &keyID, &row.Version); err != nil {
			return nil, err
		}
		row.Kind = StoryState
		if row.Plain, err = s.storyOpen("story-log-state/v1", row.Scope, owner, 0, row.Version, keyID, ciphertext, nonce); err != nil {
			return nil, fmt.Errorf("v1reader: story state: %w", err)
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (s *Source) storyEntries(ctx context.Context) ([]StoryRow, error) {
	var out []StoryRow
	err := s.StoryEntries(ctx, func(row StoryRow) error {
		out = append(out, row)
		return nil
	})
	return out, err
}

// StoryEntries streams every Story-log entry in ID order, decrypted, one at a
// time, so a log of a million lines is never held in memory.
func (s *Source) StoryEntries(ctx context.Context, yield func(StoryRow) error) error {
	rows, err := s.db.QueryContext(ctx, `SELECT id, scope_hmac, owner_hmac, session_id, payload, nonce, encryption_key_id, version FROM story_log_entries ORDER BY id`)
	if err != nil {
		return fmt.Errorf("v1reader: read story entries: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var row StoryRow
		var owner, ciphertext, nonce []byte
		var keyID string
		if err = rows.Scan(&row.ID, &row.Scope, &owner, &row.SessionID, &ciphertext, &nonce, &keyID, &row.Version); err != nil {
			return err
		}
		row.Kind = StoryEntry
		if row.Plain, err = s.storyOpen("story-log-entry/v1", row.Scope, owner, row.ID, row.Version, keyID, ciphertext, nonce); err != nil {
			return fmt.Errorf("v1reader: story entry %d: %w", row.ID, err)
		}
		if err = yield(row); err != nil {
			return err
		}
	}
	return rows.Err()
}

// StorySessions and StoryStates return the (small) session and current-state
// rows, decrypted.
func (s *Source) StorySessions(ctx context.Context) ([]StoryRow, error) { return s.storySessions(ctx) }
func (s *Source) StoryStates(ctx context.Context) ([]StoryRow, error)   { return s.storyStates(ctx) }

func (s *Source) storyIntents(ctx context.Context) ([]StoryRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT effect_id, scope_hmac, owner_hmac, session_id, payload, nonce, encryption_key_id, version FROM story_log_outbound_intents ORDER BY effect_id`)
	if err != nil {
		return nil, fmt.Errorf("v1reader: read story intents: %w", err)
	}
	defer rows.Close()
	var out []StoryRow
	for rows.Next() {
		var row StoryRow
		var owner, ciphertext, nonce []byte
		var keyID string
		if err = rows.Scan(&row.EffectID, &row.Scope, &owner, &row.SessionID, &ciphertext, &nonce, &keyID, &row.Version); err != nil {
			return nil, err
		}
		row.Kind = StoryIntent
		// The intent AAD binds a digest of the effect ID in place of a row ID.
		if row.Plain, err = s.storyOpen("story-log-intent/v2", row.Scope, owner, intentAADID(row.EffectID), row.Version, keyID, ciphertext, nonce); err != nil {
			return nil, fmt.Errorf("v1reader: story intent %q: %w", row.EffectID, err)
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// Inventory counts the rows the reader is expected to return, straight from
// the database, so a caller can check that nothing was silently skipped.
type Inventory struct {
	Secrets         int
	PluginKV        int
	ProjectionRows  map[string]int
	StorySessions   int
	StoryStates     int
	StoryEntries    int
	StoryIntents    int
	TransientQueues int // inbox + outbox + operations + artifacts: not migrated
}

// Inventory returns the per-class row counts of the database.
func (s *Source) Inventory(ctx context.Context) (Inventory, error) {
	inv := Inventory{ProjectionRows: map[string]int{}}
	count := func(query string, args ...any) (int, error) {
		var n int
		err := s.db.QueryRowContext(ctx, query, args...).Scan(&n)
		return n, err
	}
	var err error
	if inv.Secrets, err = count(`SELECT COUNT(DISTINCT secret_ref) FROM adapter_secrets`); err != nil {
		return inv, err
	}
	if inv.PluginKV, err = count(`SELECT COUNT(*) FROM plugin_kv`); err != nil {
		return inv, err
	}
	if inv.StorySessions, err = count(`SELECT COUNT(*) FROM story_log_sessions`); err != nil {
		return inv, err
	}
	if inv.StoryStates, err = count(`SELECT COUNT(*) FROM story_log_states`); err != nil {
		return inv, err
	}
	if inv.StoryEntries, err = count(`SELECT COUNT(*) FROM story_log_entries`); err != nil {
		return inv, err
	}
	if inv.StoryIntents, err = count(`SELECT COUNT(*) FROM story_log_outbound_intents`); err != nil {
		return inv, err
	}
	for _, table := range []string{"inbox_messages", "outbox_effects", "operations", "operation_artifacts"} {
		n, countErr := count(`SELECT COUNT(*) FROM ` + table)
		if countErr != nil {
			return inv, countErr
		}
		inv.TransientQueues += n
	}
	var generation string
	if scanErr := s.db.QueryRowContext(ctx, `SELECT active_generation FROM projection_control WHERE singleton_id = 'default'`).Scan(&generation); scanErr == nil {
		rows, queryErr := s.db.QueryContext(ctx, `SELECT projection_name, COUNT(*) FROM projection_read_models WHERE projection_generation = ? AND payload_present = 1 GROUP BY projection_name`, generation)
		if queryErr != nil {
			return inv, queryErr
		}
		defer rows.Close()
		for rows.Next() {
			var name string
			var n int
			if err = rows.Scan(&name, &n); err != nil {
				return inv, err
			}
			inv.ProjectionRows[name] = n
		}
		err = rows.Err()
	}
	return inv, err
}
