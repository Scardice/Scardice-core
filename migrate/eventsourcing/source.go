package eventsourcing

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	MaxBatchRecords = 500
	MaxBatchBytes   = 8 * 1024 * 1024
	MaxSnapshotFileBytes = 512 * 1024 * 1024
	MaxSnapshotBytes = 1024 * 1024 * 1024
	SnapshotTreeMode os.FileMode = 0o700
	SnapshotFileMode os.FileMode = 0o600
)

type Mode string
const (
	ModeFresh  Mode = "fresh"
	ModeImport Mode = "import"
	FreshMode = ModeFresh
	ImportMode = ModeImport
)
type SourceKind string
const (
	SourceKindLegacy    SourceKind = "legacy"
	SourceKindSQLite    SourceKind = "sqlite"
	SourceKindRemoteSQL SourceKind = "remote-sql"
)

var (
	ErrInvalidMode       = errors.New("eventsourcing: invalid mode")
	ErrSourceRequired    = errors.New("eventsourcing: source required")
	ErrSourceMutation    = errors.New("eventsourcing: source mutation is forbidden")
	ErrSourceDrift       = errors.New("eventsourcing: source changed during snapshot")
	ErrTargetIdentity    = errors.New("eventsourcing: target identity is invalid")
	ErrBatchLimit        = errors.New("eventsourcing: batch limit exceeded")
	ErrPublication       = errors.New("eventsourcing: readiness publication failed")
	ErrQuarantined       = errors.New("eventsourcing: import quarantined")
	ErrValidation        = errors.New("eventsourcing: validation failed")
	ErrUnsupportedPreflight = errors.New("eventsourcing: unsupported preflight")
)

type UnsupportedPreflightError struct { Feature string }
func (e *UnsupportedPreflightError) Error() string {
	if e == nil || strings.TrimSpace(e.Feature) == "" { return ErrUnsupportedPreflight.Error() }
	return fmt.Sprintf("%s: %s", ErrUnsupportedPreflight, e.Feature)
}
func (e *UnsupportedPreflightError) Unwrap() error { return ErrUnsupportedPreflight }

type SourceMetadata struct {
	Identity string
	Files []FileMetadata
}

type FileMetadata struct {
	Name string
	Size int64
	Mode os.FileMode
	ModTimeUnixNano int64
	Digest [sha256.Size]byte
}

func (m SourceMetadata) Equal(other SourceMetadata) bool {
	if m.Identity != other.Identity || len(m.Files) != len(other.Files) { return false }
	for i := range m.Files {
		a, b := m.Files[i], other.Files[i]
		if a.Name != b.Name || a.Size != b.Size || a.Mode.Perm() != b.Mode.Perm() || a.ModTimeUnixNano != b.ModTimeUnixNano || a.Digest != b.Digest { return false }
	}
	return true
}

type SourceRecord struct {
	Domain string
	Identity string
	Kind string
	SchemaVersion uint16
	ContentDigest []byte
	Size uint64
}

type SourceInventory struct {
	Kind SourceKind
	Identity string
	Metadata SourceMetadata
	Records []SourceRecord
	LegacyOwnershipComplete bool
}

type SnapshotResult struct {
	Root string
	Metadata SourceMetadata
	Files []string
}

type Source interface {
	Inventory(context.Context) (SourceInventory, error)
	Snapshot(context.Context, string) (SnapshotResult, error)
	Recheck(context.Context, SourceMetadata) error
}

// RemoteSQLSource is deliberately unsupported until a read-only snapshot
// protocol and complete legacy ownership map are available.
type RemoteSQLSource struct { Address string }
func NewRemoteSQLSource(address string) *RemoteSQLSource { return &RemoteSQLSource{Address: address} }
func (s *RemoteSQLSource) Inventory(context.Context) (SourceInventory, error) {
	return SourceInventory{}, &UnsupportedPreflightError{Feature: "remote SQL snapshot"}
}
func (s *RemoteSQLSource) Snapshot(context.Context, string) (SnapshotResult, error) {
	return SnapshotResult{}, &UnsupportedPreflightError{Feature: "remote SQL snapshot"}
}
func (s *RemoteSQLSource) Recheck(context.Context, SourceMetadata) error {
	return &UnsupportedPreflightError{Feature: "remote SQL snapshot"}
}

type SQLiteSource struct { MainPath string; fs FileSystem }
type SQLiteSourceOption func(*SQLiteSource)
func WithSQLiteFileSystem(fs FileSystem) SQLiteSourceOption {
	return func(source *SQLiteSource) { if fs != nil { source.fs = fs } }
}
func NewSQLiteSource(mainPath string, options ...SQLiteSourceOption) *SQLiteSource {
	source := &SQLiteSource{MainPath: mainPath}
	for _, option := range options { if option != nil { option(source) } }
	return source
}
func sourceFS(source *SQLiteSource) FileSystem {
	if source != nil && source.fs != nil { return source.fs }
	return osFileSystem{}
}
func (s *SQLiteSource) Inventory(ctx context.Context) (SourceInventory, error) {
	if s == nil || strings.TrimSpace(s.MainPath) == "" { return SourceInventory{}, ErrSourceRequired }
	metadata, err := sqliteMetadata(ctx, s.MainPath)
	if err != nil { return SourceInventory{}, err }
	return SourceInventory{Kind: SourceKindSQLite, Identity: metadata.Identity, Metadata: metadata,
		// A local database has no trustworthy complete ownership map at this seam.
		LegacyOwnershipComplete: false}, nil
}
func (s *SQLiteSource) Recheck(ctx context.Context, before SourceMetadata) error {
	if s == nil { return ErrSourceRequired }
	after, err := sqliteMetadata(ctx, s.MainPath)
	if err != nil { return err }
	if !before.Equal(after) { return ErrSourceDrift }
	return nil
}
func (s *SQLiteSource) Snapshot(ctx context.Context, target string) (SnapshotResult, error) {
	if s == nil || strings.TrimSpace(s.MainPath) == "" { return SnapshotResult{}, ErrSourceRequired }
	before, err := sqliteMetadata(ctx, s.MainPath)
	if err != nil { return SnapshotResult{}, err }
	files, err := copySQLiteFiles(ctx, sourceFS(s), s.MainPath, target)
	if err != nil { return SnapshotResult{}, err }
	return SnapshotResult{Root: target, Metadata: before, Files: files}, nil
}
func sqliteMetadata(ctx context.Context, mainPath string) (SourceMetadata, error) {
	if err := ctx.Err(); err != nil { return SourceMetadata{}, err }
	clean := filepath.Clean(mainPath)
	info, err := os.Lstat(clean)
	if err != nil { return SourceMetadata{}, err }
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() { return SourceMetadata{}, ErrSourceMutation }
	names := []string{filepath.Base(clean)}
	for _, suffix := range []string{"-wal", "-shm"} {
		candidate := clean + suffix
		if sidecar, statErr := os.Lstat(candidate); statErr == nil {
			if sidecar.Mode()&os.ModeSymlink != 0 || !sidecar.Mode().IsRegular() { return SourceMetadata{}, ErrSourceMutation }
			names = append(names, filepath.Base(candidate))
		} else if !errors.Is(statErr, os.ErrNotExist) { return SourceMetadata{}, statErr }
	}
	metadata := SourceMetadata{Identity: filepath.Base(clean), Files: make([]FileMetadata, 0, len(names))}
	for _, name := range names {
		path := filepath.Join(filepath.Dir(clean), name)
		file, fileErr := metadataFile(ctx, path, name)
		if fileErr != nil { return SourceMetadata{}, fileErr }
		metadata.Files = append(metadata.Files, file)
	}
	return metadata, nil
}

func metadataFile(ctx context.Context, path, name string) (FileMetadata, error) {
	if err := ctx.Err(); err != nil { return FileMetadata{}, err }
	info, err := os.Lstat(path)
	if err != nil { return FileMetadata{}, err }
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > MaxSnapshotFileBytes { return FileMetadata{}, ErrBatchLimit }
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil { return FileMetadata{}, ErrSourceMutation }
	file := os.NewFile(uintptr(fd), name)
	if file == nil { _ = syscall.Close(fd); return FileMetadata{}, ErrSourceMutation }
	defer file.Close()
	h := sha256.New()
	if _, err := io.CopyN(h, file, MaxSnapshotFileBytes+1); err != nil && !errors.Is(err, io.EOF) { return FileMetadata{}, err }
	var digest [sha256.Size]byte
	copy(digest[:], h.Sum(nil))
	return FileMetadata{Name: name, Size: info.Size(), Mode: info.Mode(), ModTimeUnixNano: info.ModTime().UTC().UnixNano(), Digest: digest}, nil
}
