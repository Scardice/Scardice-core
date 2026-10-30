package eventsourcing

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"Scardice-core/eventstore"
)

const (
	MaxBatchRecords                  = eventstore.MaxUnitOfWorkEvents
	MaxBatchBytes                    = 8 * 1024 * 1024
	MaxSnapshotFileBytes             = 512 * 1024 * 1024
	MaxSnapshotBytes                 = 1024 * 1024 * 1024
	SnapshotTreeMode     os.FileMode = 0o700
	SnapshotFileMode     os.FileMode = 0o600
)

type Mode string

const (
	ModeFresh  Mode = "fresh"
	ModeImport Mode = "import"
	FreshMode       = ModeFresh
	ImportMode      = ModeImport
)

type SourceKind string

const (
	SourceKindLegacy    SourceKind = "legacy"
	SourceKindSQLite    SourceKind = "sqlite"
	SourceKindRemoteSQL SourceKind = "remote-sql"
)

type RecordType string

const (
	RecordTypeEvent      RecordType = "event"
	RecordTypeSecret     RecordType = "secret"
	RecordTypePluginKV   RecordType = "plugin-kv"
	RecordTypeProjection RecordType = "projection"
	RecordTypeLogArchive RecordType = "log-archive"
)

var (
	ErrInvalidMode          = errors.New("eventsourcing: invalid mode")
	ErrSourceRequired       = errors.New("eventsourcing: source required")
	ErrSourceMutation       = errors.New("eventsourcing: source mutation is forbidden")
	ErrTargetRequired       = errors.New("eventsourcing: import target required")
	ErrSourceDrift          = errors.New("eventsourcing: source changed during snapshot")
	ErrTargetIdentity       = errors.New("eventsourcing: target identity is invalid")
	ErrBatchLimit           = errors.New("eventsourcing: batch limit exceeded")
	ErrPublication          = errors.New("eventsourcing: readiness publication failed")
	ErrQuarantined          = errors.New("eventsourcing: import quarantined")
	ErrValidation           = errors.New("eventsourcing: validation failed")
	ErrUnsupportedPreflight = errors.New("eventsourcing: unsupported preflight")
)

type UnsupportedPreflightError struct{ Feature string }

func (e *UnsupportedPreflightError) Error() string {
	if e == nil || strings.TrimSpace(e.Feature) == "" {
		return ErrUnsupportedPreflight.Error()
	}
	return fmt.Sprintf("%s: %s", ErrUnsupportedPreflight, e.Feature)
}
func (e *UnsupportedPreflightError) Unwrap() error { return ErrUnsupportedPreflight }

type SourceMetadata struct {
	Identity string
	Files    []FileMetadata
}

type FileMetadata struct {
	Name            string
	Size            int64
	Mode            os.FileMode
	ModTimeUnixNano int64
	Digest          [sha256.Size]byte
}

func (m SourceMetadata) Equal(other SourceMetadata) bool {
	if m.Identity != other.Identity || len(m.Files) != len(other.Files) {
		return false
	}
	for i := range m.Files {
		a, b := m.Files[i], other.Files[i]
		if a.Name != b.Name || a.Size != b.Size || a.Mode.Perm() != b.Mode.Perm() || a.ModTimeUnixNano != b.ModTimeUnixNano || a.Digest != b.Digest {
			return false
		}
	}
	return true
}

type SourceRecord struct {
	Domain        string
	RecordType    RecordType
	Identity      string
	Kind          string
	SchemaVersion uint16
	EventID       string
	CommandID     string
	CorrelationID string
	ContentDigest []byte
	Payload       []byte
	Version       uint64
	Sensitive     bool
	Size          uint64
}

func validateSourceRecord(record SourceRecord) error {
	switch record.RecordType {
	case RecordTypeEvent, RecordTypeSecret, RecordTypePluginKV, RecordTypeLogArchive:
	default:
		return fmt.Errorf("%w: unsupported record type", ErrValidation)
	}
	if strings.TrimSpace(record.Domain) == "" {
		return fmt.Errorf("%w: missing domain", ErrValidation)
	}
	if strings.TrimSpace(record.Kind) == "" {
		return fmt.Errorf("%w: missing kind", ErrValidation)
	}
	if record.RecordType != RecordTypePluginKV && strings.TrimSpace(record.Identity) == "" {
		return fmt.Errorf("%w: missing identity", ErrValidation)
	}
	if record.SchemaVersion == 0 {
		return fmt.Errorf("%w: missing schema version", ErrValidation)
	}
	if record.Version == 0 {
		return fmt.Errorf("%w: missing record version", ErrValidation)
	}
	hasEventMetadata := record.EventID != "" || record.CommandID != "" || record.CorrelationID != ""
	if record.RecordType != RecordTypeEvent && hasEventMetadata {
		return fmt.Errorf("%w: event metadata on non-event record", ErrValidation)
	}
	if hasEventMetadata {
		for _, value := range []string{record.EventID, record.CommandID, record.CorrelationID} {
			if strings.TrimSpace(value) == "" || len(value) > 255 {
				return fmt.Errorf("%w: incomplete or oversized event metadata", ErrValidation)
			}
		}
	}
	if uint64(len(record.Payload)) != record.Size {
		return fmt.Errorf("%w: payload size mismatch (declared=%d actual=%d)", ErrValidation, record.Size, len(record.Payload))
	}
	if len(record.Payload) > MaxBatchBytes {
		return fmt.Errorf("%w: payload exceeds %d bytes", ErrBatchLimit, MaxBatchBytes)
	}
	if record.Sensitive {
		if len(record.ContentDigest) != 0 {
			return fmt.Errorf("%w: sensitive record includes a content digest", ErrValidation)
		}
		if record.RecordType == RecordTypeLogArchive {
			if err := validateLegacyLogArchiveSourceRecord(record); err != nil {
				return fmt.Errorf("invalid sensitive log archive: %w", err)
			}
		}
		return nil
	}
	if record.RecordType == RecordTypeLogArchive {
		return fmt.Errorf("%w: log archive record is not marked sensitive", ErrValidation)
	}
	digest := sha256.Sum256(record.Payload)
	if !bytes.Equal(record.ContentDigest, digest[:]) {
		return fmt.Errorf("%w: content digest mismatch", ErrValidation)
	}
	return nil
}

type SourceInventory struct {
	Kind                    SourceKind
	Identity                string
	Metadata                SourceMetadata
	Records                 []SourceRecord
	BackupIdentity          string
	PendingMigrations       []string
	LegacyOwnershipComplete bool
}

type SnapshotResult struct {
	Root     string
	Metadata SourceMetadata
	Files    []string
	Source   Source
}

type Source interface {
	Inventory(ctx context.Context) (SourceInventory, error)
	Snapshot(ctx context.Context, target string) (SnapshotResult, error)
	Recheck(ctx context.Context, metadata SourceMetadata) error
}

// RecordStreamer emits source records in bounded batches. The callback must
// consume each batch before returning; implementations may reuse its storage.
type RecordStreamer interface {
	StreamRecords(ctx context.Context, yield func([]SourceRecord) error) error
}

// Target owns the fresh event database used by one import attempt. Initialize
// must reject a non-empty or previously initialized target. ImportBatch must
// commit the supplied records atomically and encrypt secret-bearing payloads.
// Reopen verifies the exact target after projection rebuild, before readiness
// can be published.
type Target interface {
	Initialize(ctx context.Context, identity string) error
	ImportBatch(ctx context.Context, records []SourceRecord) error
	ProjectionManifest(ctx context.Context) ([]byte, []byte, error)
	Rebuild(ctx context.Context) (eventstore.RebuildResult, error)
	Manifest(ctx context.Context) (SemanticManifest, error)
	Reopen(ctx context.Context) error
	Close() error
	eventstore.ReadinessRepository
}

// PublicationTarget atomically makes a fully validated import target active.
// Readiness is already committed when Publish is called.
type PublicationTarget interface {
	Publish(ctx context.Context) error
}

type SQLiteSource struct {
	MainPath string
	fs       FileSystem
}
type SQLiteSourceOption func(*SQLiteSource)

func WithSQLiteFileSystem(fs FileSystem) SQLiteSourceOption {
	return func(source *SQLiteSource) {
		if fs != nil {
			source.fs = fs
		}
	}
}
func NewSQLiteSource(mainPath string, options ...SQLiteSourceOption) *SQLiteSource {
	source := &SQLiteSource{MainPath: mainPath}
	for _, option := range options {
		if option != nil {
			option(source)
		}
	}
	return source
}
func sourceFS(source *SQLiteSource) FileSystem {
	if source != nil && source.fs != nil {
		return source.fs
	}
	return osFileSystem{}
}
func (s *SQLiteSource) Inventory(ctx context.Context) (SourceInventory, error) {
	if s == nil || strings.TrimSpace(s.MainPath) == "" {
		return SourceInventory{}, ErrSourceRequired
	}
	metadata, err := sqliteMetadata(ctx, s.MainPath)
	if err != nil {
		return SourceInventory{}, err
	}
	return SourceInventory{Kind: SourceKindSQLite, Identity: metadata.Identity, Metadata: metadata,
		// A local database has no trustworthy complete ownership map at this seam.
		LegacyOwnershipComplete: false}, nil
}
func (s *SQLiteSource) Recheck(ctx context.Context, before SourceMetadata) error {
	if s == nil {
		return ErrSourceRequired
	}
	after, err := sqliteMetadata(ctx, s.MainPath)
	if err != nil {
		return err
	}
	if !before.Equal(after) {
		return ErrSourceDrift
	}
	return nil
}
func (s *SQLiteSource) Snapshot(ctx context.Context, target string) (SnapshotResult, error) {
	if s == nil || strings.TrimSpace(s.MainPath) == "" {
		return SnapshotResult{}, ErrSourceRequired
	}
	before, err := sqliteMetadata(ctx, s.MainPath)
	if err != nil {
		return SnapshotResult{}, err
	}
	files, err := copySQLiteFiles(ctx, sourceFS(s), s.MainPath, target)
	if err != nil {
		return SnapshotResult{}, err
	}
	return SnapshotResult{
		Root: target, Metadata: before, Files: files,
		Source: NewSQLiteSource(filepath.Join(target, filepath.Base(s.MainPath)), WithSQLiteFileSystem(sourceFS(s))),
	}, nil
}
func sqliteMetadata(ctx context.Context, mainPath string) (SourceMetadata, error) {
	if err := ctx.Err(); err != nil {
		return SourceMetadata{}, err
	}
	clean := filepath.Clean(mainPath)
	info, err := os.Lstat(clean)
	if err != nil {
		return SourceMetadata{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return SourceMetadata{}, ErrSourceMutation
	}
	names := []string{filepath.Base(clean)}
	for _, suffix := range []string{"-wal", "-shm"} {
		candidate := clean + suffix
		if sidecar, statErr := os.Lstat(candidate); statErr == nil {
			if sidecar.Mode()&os.ModeSymlink != 0 || !sidecar.Mode().IsRegular() {
				return SourceMetadata{}, ErrSourceMutation
			}
			names = append(names, filepath.Base(candidate))
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return SourceMetadata{}, statErr
		}
	}
	metadata := SourceMetadata{Identity: filepath.Base(clean), Files: make([]FileMetadata, 0, len(names))}
	for _, name := range names {
		path := filepath.Join(filepath.Dir(clean), name)
		file, fileErr := metadataFile(ctx, path, name)
		if fileErr != nil {
			return SourceMetadata{}, fileErr
		}
		metadata.Files = append(metadata.Files, file)
	}
	return metadata, nil
}

func metadataFile(ctx context.Context, path, name string) (FileMetadata, error) {
	if err := ctx.Err(); err != nil {
		return FileMetadata{}, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return FileMetadata{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > MaxSnapshotFileBytes {
		return FileMetadata{}, ErrBatchLimit
	}
	file, err := openReadOnlyNoFollow(path)
	if err != nil {
		return FileMetadata{}, ErrSourceMutation
	}
	defer file.Close()
	h := sha256.New()
	if _, err := io.CopyN(h, file, MaxSnapshotFileBytes+1); err != nil && !errors.Is(err, io.EOF) {
		return FileMetadata{}, err
	}
	var digest [sha256.Size]byte
	copy(digest[:], h.Sum(nil))
	return FileMetadata{Name: name, Size: info.Size(), Mode: info.Mode(), ModTimeUnixNano: info.ModTime().UTC().UnixNano(), Digest: digest}, nil
}
