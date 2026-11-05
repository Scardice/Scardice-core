package eventsourcing

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"Scardice-core/eventstore"
	"Scardice-core/migrate/eventsourcing/v1reader"
)

// DetectRemoteFormat inspects an existing remote schema without invoking the
// event-store migrator. Encrypted/unknown schemas are never auto-migrated by
// startup; v1 file conversion is intentionally SQLite-only.
func DetectRemoteFormat(ctx context.Context, config eventstore.DatabaseConfig) (format v1reader.Format, detectErr error) {
	source := NewRemoteSQLSource(".", config)
	database, err := source.openDatabase(ctx)
	if err != nil {
		return v1reader.FormatUnknown, err
	}
	defer database.Close()
	transaction, err := database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return v1reader.FormatUnknown, err
	}
	defer func() {
		if rollbackErr := transaction.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			detectErr = errors.Join(detectErr, rollbackErr)
		}
	}()
	query := `SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = current_schema() AND table_name IN ('store_readiness','domain_events')`
	if strings.EqualFold(strings.TrimSpace(config.Type), "mysql") {
		query = `SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name IN ('store_readiness','domain_events')`
	}
	readiness, events, encrypted := false, false, false
	columns := make(map[string]bool)
	if err = func() (readErr error) {
		rows, queryErr := transaction.QueryContext(ctx, query)
		if queryErr != nil {
			return queryErr
		}
		defer func() { readErr = errors.Join(readErr, rows.Close()) }()
		for rows.Next() {
			var table, column string
			if scanErr := rows.Scan(&table, &column); scanErr != nil {
				return scanErr
			}
			readiness = readiness || table == "store_readiness"
			events = events || table == "domain_events"
			encrypted = encrypted || table == "store_readiness" && column == "encryption_root_ids"
			if table == "store_readiness" {
				columns[column] = true
			}
		}
		return rows.Err()
	}(); err != nil {
		return v1reader.FormatUnknown, err
	}
	if !readiness {
		countQuery := `SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'`
		if strings.EqualFold(strings.TrimSpace(config.Type), "mysql") {
			countQuery = `SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE'`
		}
		var tables int
		if err := transaction.QueryRowContext(ctx, countQuery).Scan(&tables); err != nil {
			return v1reader.FormatUnknown, err
		}
		if events || tables != 0 {
			return v1reader.FormatUnknown, nil
		}
		return v1reader.FormatEmpty, nil
	}
	if encrypted {
		return v1reader.FormatV1Encrypted, nil
	}
	if len(columns) != 5 || !columns["singleton_id"] || !columns["mode"] || !columns["schema_version"] || !columns["database_identity"] || !columns["completed_at"] {
		return v1reader.FormatUnknown, nil
	}
	if !events {
		return v1reader.FormatUnknown, nil
	}
	var version int
	if err = transaction.QueryRowContext(ctx, `SELECT schema_version FROM store_readiness WHERE singleton_id = 'default'`).Scan(&version); err != nil {
		return v1reader.FormatUnknown, err
	}
	if version != readinessSchemaVersion {
		return v1reader.FormatUnknown, nil
	}
	if err = transaction.Commit(); err != nil {
		return v1reader.FormatUnknown, err
	}
	return v1reader.FormatV2Plain, nil
}
