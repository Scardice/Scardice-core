package v1reader

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// SecretRow is one stored version of an adapter secret, in plaintext.
type SecretRow struct {
	Ref           string
	EndpointID    string
	AdapterID     string
	SecretVersion uint64
	RowVersion    uint64
	Plaintext     []byte
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// SecretHistory streams every stored version of every adapter secret,
// decrypted, in the order the rows are laid out in the table. That is the
// cheap order on a large database: ordering by reference sends the reader to a
// random place in the file for every row. The versions of one reference still
// arrive in order, interleaved with those of other references.
func (s *Source) SecretHistory(ctx context.Context, yield func(SecretRow) error) error {
	rows, err := s.db.QueryContext(ctx, `SELECT secret_ref, secret_version, row_version, endpoint_id, adapter_id, ciphertext, nonce, encryption_key_id, created_at, updated_at FROM adapter_secrets ORDER BY rowid`)
	if err != nil {
		return fmt.Errorf("v1reader: read adapter secret history: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var row SecretRow
		var keyID string
		var ciphertext, nonce []byte
		var created, updated sql.NullString
		if err = rows.Scan(&row.Ref, &row.SecretVersion, &row.RowVersion, &row.EndpointID, &row.AdapterID, &ciphertext, &nonce, &keyID, &created, &updated); err != nil {
			return err
		}
		row.CreatedAt, row.UpdatedAt = parseStoredTime(created.String), parseStoredTime(updated.String)
		if row.Plaintext, err = s.keys.open("adapter-secret/v1", row.Ref, row.EndpointID+"/"+row.AdapterID, row.SecretVersion, keyID, ciphertext, nonce); err != nil {
			return fmt.Errorf("v1reader: adapter secret %q version %d: %w", row.Ref, row.SecretVersion, err)
		}
		if err = yield(row); err != nil {
			return err
		}
	}
	return rows.Err()
}

// parseStoredTime reads the text form SQLite keeps a time in. A value that
// cannot be read is the zero time, which the caller replaces.
func parseStoredTime(value string) time.Time {
	for _, layout := range []string{"2006-01-02 15:04:05.999999999-07:00", time.RFC3339Nano, "2006-01-02 15:04:05"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC()
		}
	}
	return time.Time{}
}

// SecretRowCount is the number of stored secret versions, straight from the
// database.
func (s *Source) SecretRowCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM adapter_secrets`).Scan(&n)
	return n, err
}
