package v1reader

import (
	"context"
	"fmt"
)

// CurrentState distinguishes an old startup's empty fresh schema from real
// event-store data. Structural readiness/projection controls are not business
// state. No key is loaded and no encrypted value is read by this inspection.
type CurrentState struct {
	Mode               string
	DatabaseIdentity   string
	HasPersistentState bool
}

func InspectCurrentState(ctx context.Context, path string) (CurrentState, error) {
	var state CurrentState
	database, err := openReadOnly(path)
	if err != nil {
		return state, err
	}
	defer database.Close()
	if err = database.QueryRowContext(ctx, `SELECT mode, database_identity FROM store_readiness WHERE singleton_id = 'default'`).Scan(&state.Mode, &state.DatabaseIdentity); err != nil {
		return state, err
	}
	if state.Mode != "fresh" && state.Mode != "import" {
		return state, fmt.Errorf("v1reader: unsupported readiness mode %q", state.Mode)
	}
	for _, table := range []string{"domain_events", "aggregate_heads", "projection_read_models", "adapter_secrets", "plugin_kv", "story_log_sessions", "story_log_states", "story_log_entries", "story_log_outbound_intents", "story_log_imports", "management_activities", "inbox_messages", "outbox_effects", "operations", "operation_artifacts", "execution_receipts"} {
		var exists int
		if err = database.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&exists); err != nil {
			return state, err
		}
		if exists == 0 {
			continue
		}
		query := `SELECT EXISTS(SELECT 1 FROM ` + table + ` LIMIT 1)`
		if table == "projection_read_models" {
			query = `SELECT EXISTS(SELECT 1 FROM projection_read_models WHERE payload_present = 1 LIMIT 1)`
		}
		var populated bool
		if err = database.QueryRowContext(ctx, query).Scan(&populated); err != nil {
			return state, err
		}
		if populated {
			state.HasPersistentState = true
			return state, nil
		}
	}
	return state, nil
}
