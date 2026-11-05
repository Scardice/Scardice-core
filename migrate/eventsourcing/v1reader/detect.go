package v1reader

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	_ "github.com/glebarez/go-sqlite" // registers the "sqlite" driver
)

// Format is what kind of event store a database file holds.
type Format int

const (
	// FormatNone: the file does not exist.
	FormatNone Format = iota
	// FormatEmpty: a database file without any application tables.
	FormatEmpty
	// FormatV1Encrypted: the encrypted store this package reads.
	FormatV1Encrypted
	// FormatV2Plain: the plaintext store.
	FormatV2Plain
	// FormatUnknown: a database whose schema neither supported format explains.
	FormatUnknown
)

func (f Format) String() string {
	switch f {
	case FormatNone:
		return "none"
	case FormatEmpty:
		return "empty"
	case FormatV1Encrypted:
		return "v1-encrypted"
	case FormatV2Plain:
		return "v2-plain"
	default:
		return "unknown"
	}
}

// openReadOnly opens a SQLite file without creating or modifying it. Detecting
// the format must happen before the regular store opens the file, because the
// regular store would migrate the schema of what it opens.
func openReadOnly(path string) (*sql.DB, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dsn := (&url.URL{Scheme: "file", Path: filepath.ToSlash(absolute), RawQuery: "mode=ro&immutable=1"}).String()
	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	database.SetMaxOpenConns(1)
	return database, nil
}

// Detect reports the format of the SQLite event-store file at path without
// changing it. It reads only the schema and the readiness row.
func Detect(ctx context.Context, path string) (Format, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return FormatNone, nil
	} else if err != nil {
		return FormatUnknown, err
	}
	database, err := openReadOnly(path)
	if err != nil {
		return FormatUnknown, err
	}
	defer database.Close()

	hasTable := func(name string) (bool, error) {
		var count int
		err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, name).Scan(&count)
		return count > 0, err
	}
	readiness, err := hasTable("store_readiness")
	if err != nil {
		return FormatUnknown, fmt.Errorf("v1reader: inspect %s: %w", path, err)
	}
	if !readiness {
		var tables int
		if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`).Scan(&tables); err != nil {
			return FormatUnknown, err
		}
		if tables != 0 {
			return FormatUnknown, nil
		}
		return FormatEmpty, nil
	}

	rows, err := database.QueryContext(ctx, `PRAGMA table_info(store_readiness)`)
	if err != nil {
		return FormatUnknown, err
	}
	defer rows.Close()
	encryptionRoots := false
	columns := make(map[string]bool)
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var def sql.NullString
		if err = rows.Scan(&cid, &name, &typ, &notNull, &def, &pk); err != nil {
			return FormatUnknown, err
		}
		columns[name] = true
		if name == "encryption_root_ids" {
			encryptionRoots = true
		}
	}
	if err = rows.Err(); err != nil {
		return FormatUnknown, err
	}
	if encryptionRoots {
		return FormatV1Encrypted, nil
	}
	if len(columns) != 5 || !columns["singleton_id"] || !columns["mode"] || !columns["schema_version"] || !columns["database_identity"] || !columns["completed_at"] {
		return FormatUnknown, nil
	}

	var version sql.NullString
	err = database.QueryRowContext(ctx, `SELECT schema_version FROM store_readiness LIMIT 1`).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		return FormatUnknown, nil
	}
	if err != nil {
		return FormatUnknown, err
	}
	if version.Valid && version.String == "2" {
		events, err := hasTable("domain_events")
		if err != nil {
			return FormatUnknown, err
		}
		if !events {
			return FormatUnknown, nil
		}
		return FormatV2Plain, nil
	}
	return FormatUnknown, nil
}
