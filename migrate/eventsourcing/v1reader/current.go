package v1reader

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// LatestSecrets decrypts only the current version of each reference. Unlike
// Secrets/SecretHistory it never needs a retired key for obsolete history.
func (s *Source) LatestSecrets(ctx context.Context) ([]Secret, error) {
	return s.readLatestSecrets(ctx, "", nil)
}

// ReferencedSecrets reads only the current owners requested by the converter.
// Unreferenced remnants cannot force loading an obsolete encryption key.
func (s *Source) ReferencedSecrets(ctx context.Context, refs []string) ([]Secret, error) {
	var out []Secret
	for start := 0; start < len(refs); start += 400 {
		batch := refs[start:min(start+400, len(refs))]
		args := make([]any, len(batch))
		for i := range batch {
			args[i] = batch[i]
		}
		filter := " WHERE secret_ref IN (" + strings.TrimSuffix(strings.Repeat("?,", len(batch)), ",") + ")"
		items, err := s.readLatestSecrets(ctx, filter, args)
		if err != nil {
			for i := range out {
				clear(out[i].Plaintext)
			}
			return nil, err
		}
		out = append(out, items...)
	}
	return out, nil
}

func (s *Source) readLatestSecrets(ctx context.Context, filter string, args []any) ([]Secret, error) {
	// #nosec G202 -- filter is empty or a fixed secret_ref IN clause of ? placeholders; references are bound through args.
	rows, err := s.db.QueryContext(ctx, `SELECT s.secret_ref, s.secret_version, s.endpoint_id, s.adapter_id, s.ciphertext, s.nonce, s.encryption_key_id FROM adapter_secrets s JOIN (SELECT secret_ref, MAX(secret_version) AS version FROM adapter_secrets`+filter+` GROUP BY secret_ref) latest ON s.secret_ref = latest.secret_ref AND s.secret_version = latest.version ORDER BY s.secret_ref`, args...)
	if err != nil {
		return nil, fmt.Errorf("v1reader: read current secrets: %w", err)
	}
	defer rows.Close()
	var out []Secret
	for rows.Next() {
		var item Secret
		var keyID string
		var ciphertext, nonce []byte
		if err = rows.Scan(&item.Ref, &item.Version, &item.EndpointID, &item.AdapterID, &ciphertext, &nonce, &keyID); err != nil {
			return nil, err
		}
		item.Plaintext, err = s.keys.open("adapter-secret/v1", item.Ref, item.EndpointID+"/"+item.AdapterID, item.Version, keyID, ciphertext, nonce)
		if err != nil {
			return nil, fmt.Errorf("v1reader: current secret %q: %w", item.Ref, err)
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// TransientCounts records what a baseline intentionally leaves behind. Story
// intents are pending replies tied to excluded outbox effects, not entries
// already archived in a Story session.
type TransientCounts struct {
	Rows              int
	NonterminalOutbox int
	StoryIntents      int
}

func (s *Source) Transients(ctx context.Context) (TransientCounts, error) {
	var out TransientCounts
	for _, table := range []string{"inbox_messages", "outbox_effects", "operations", "operation_artifacts", "execution_receipts"} {
		var exists int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&exists); err != nil {
			return out, err
		}
		if exists == 0 {
			continue
		}
		var count int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table).Scan(&count); err != nil {
			return out, err
		}
		out.Rows += count
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox_effects WHERE status NOT IN ('succeeded','failed','ambiguous')`).Scan(&out.NonterminalOutbox); err != nil {
		return out, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM story_log_outbound_intents`).Scan(&out.StoryIntents); err != nil {
		return out, err
	}
	return out, nil
}

// PublishedProjectionRows refuses a missing or in-progress publication rather
// than interpreting damaged projection control as an empty installation.
func (s *Source) PublishedProjectionRows(ctx context.Context) ([]ProjectionRow, error) {
	var generation, state string
	if err := s.db.QueryRowContext(ctx, `SELECT active_generation, publication_state FROM projection_control WHERE singleton_id = 'default'`).Scan(&generation, &state); err != nil {
		return nil, err
	}
	if generation == "" || state != "published" {
		return nil, errors.New("v1reader: current projections are not published")
	}
	return s.ProjectionRows(ctx, "")
}

func (s *Source) SecretReferenceCount(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT secret_ref) FROM adapter_secrets`).Scan(&count)
	return count, err
}
