package eventsourcing

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// DropRecordsDirName is the data-dir child that holds the human-auditable
	// records of everything a migration decided not to carry forward.
	DropRecordsDirName = "migration-drops"

	dropSourceLegacyImport = "legacy-import"
)

// dropRecord is one JSON line of a drop record file.
type dropRecord struct {
	Source    string `json:"source"`
	DroppedAt string `json:"droppedAt"`
	Kind      string `json:"kind"`
	Identity  string `json:"identity"`
	Reason    string `json:"reason"`
	Detail    any    `json:"detail"`
}

// dropRecorder writes the drop records of one run into exactly one file under
// <dataDir>/migration-drops/. The file is created lazily on the first Add, so
// a run that drops nothing leaves no file behind. Records are buffered; the
// caller MUST call Close (which flushes and fsyncs) and abort on error before
// taking any decision that makes the dropped data unrecoverable.
type dropRecorder struct {
	mu      sync.Mutex
	dataDir string
	source  string
	now     func() time.Time

	path   string
	file   *os.File
	writer *bufio.Writer
	count  int
	err    error
	closed bool
}

// dropRecordPath is where a run that starts recording at `at` writes its file.
func dropRecordPath(dataDir, source string, at time.Time) string {
	return filepath.Join(dataDir, DropRecordsDirName, source+"-"+at.UTC().Format("20060102T150405Z")+".jsonl")
}

func newDropRecorder(dataDir, source string, now func() time.Time) *dropRecorder {
	if now == nil {
		now = time.Now
	}
	return &dropRecorder{dataDir: dataDir, source: source, now: now}
}

// Add appends one record. The first failure is sticky: later Adds and Close
// report it, so a half-written record file can never be mistaken for complete.
func (r *dropRecorder) Add(kind, identity, reason string, detail any) error {
	if r == nil {
		return errors.New("drop recorder unavailable")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	if r.closed {
		r.err = errors.New("drop recorder already closed")
		return r.err
	}
	now := r.now().UTC()
	if r.file == nil {
		if err := r.open(now); err != nil {
			r.err = err
			return err
		}
	}
	encoded, err := json.Marshal(dropRecord{
		Source: r.source, DroppedAt: now.Format(time.RFC3339Nano),
		Kind: kind, Identity: identity, Reason: reason, Detail: detail,
	})
	if err != nil {
		r.err = fmt.Errorf("encode drop record: %w", err)
		return r.err
	}
	encoded = append(encoded, '\n')
	if _, err = r.writer.Write(encoded); err != nil {
		r.err = fmt.Errorf("write drop record: %w", err)
		return r.err
	}
	r.count++
	return nil
}

func (r *dropRecorder) open(now time.Time) error {
	if r.dataDir == "" {
		return errors.New("drop record data dir is empty")
	}
	dir := filepath.Join(r.dataDir, DropRecordsDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create drop record dir: %w", err)
	}
	path := dropRecordPath(r.dataDir, r.source, now)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("create drop record file: %w", err)
	}
	if err = file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("protect drop record file: %w", err)
	}
	r.path, r.file, r.writer = path, file, bufio.NewWriterSize(file, 64*1024)
	return nil
}

// Sync makes every record added so far durable without closing the recorder,
// so a caller can fsync once per batch before a destructive step.
func (r *dropRecorder) Sync() error {
	if r == nil {
		return errors.New("drop recorder unavailable")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	if r.file == nil || r.closed {
		return nil
	}
	if err := r.writer.Flush(); err != nil {
		r.err = fmt.Errorf("write drop record: %w", err)
		return r.err
	}
	if err := r.file.Sync(); err != nil {
		r.err = fmt.Errorf("persist drop records: %w", err)
		return r.err
	}
	return nil
}

// Close flushes, fsyncs the file and its directory, and returns the file path
// and number of records written. With nothing recorded it returns ("", 0, nil).
func (r *dropRecorder) Close() (string, int, error) {
	if r == nil {
		return "", 0, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return r.path, r.count, r.err
	}
	r.closed = true
	if r.file == nil {
		return "", 0, r.err
	}
	err := r.err
	if err == nil {
		err = r.writer.Flush()
	}
	if err == nil {
		err = r.file.Sync()
	}
	if closeErr := r.file.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		// Directory fsync makes the new name durable. Platforms that cannot
		// open a directory for sync (Windows) fall back to the file fsync.
		if dir, openErr := os.Open(filepath.Dir(r.path)); openErr == nil {
			_ = dir.Sync()
			_ = dir.Close()
		}
	}
	if err != nil {
		r.err = fmt.Errorf("persist drop records: %w", err)
	}
	return r.path, r.count, r.err
}

// Path reports the record file path, empty until the first record is added.
func (r *dropRecorder) Path() string {
	if r == nil {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.path
}

// Count reports the number of records added so far.
func (r *dropRecorder) Count() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.count
}
