package eventsourcing

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var ErrUnfinishedV1Publication = errors.New("eventsourcing: unfinished v1 database publication")

type v1SwapIntent struct {
	Version   int            `json:"version"`
	Active    string         `json:"active"`
	Candidate string         `json:"candidate"`
	Backup    string         `json:"backup"`
	Source    SourceMetadata `json:"source"`
}

func v1SwapIntentPath(active string) string { return active + ".v1-swap.json" }

// CheckUnfinishedV1Publication must precede even a missing-file/fresh decision.
// Recovery is deliberately fail-closed: never infer success from an absent
// active file, and never remove another attempt's candidate or backup.
func CheckUnfinishedV1Publication(active string) error {
	for _, path := range []string{v1SwapIntentPath(active), v1SwapIntentPath(active) + ".writing"} {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("%w: %s; preserve the active/candidate/backup files and restore the complete original backup, including WAL/SHM, before clearing the intent", ErrUnfinishedV1Publication, path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func persistV1SwapIntent(intent v1SwapIntent) error {
	if err := CheckUnfinishedV1Publication(intent.Active); err != nil {
		return err
	}
	path := v1SwapIntentPath(intent.Active)
	// Reserve the visible guard first. A process killed during writing is also
	// refused on restart, even if it left only an empty/truncated intent.
	reservation, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, SnapshotFileMode)
	if err != nil {
		return err
	}
	if err = reservation.Close(); err != nil {
		return errors.Join(err, removeOwnedV1SwapIntent(intent.Active))
	}
	temporary := path + ".writing"
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, SnapshotFileMode)
	if err != nil {
		return errors.Join(err, removeOwnedV1SwapIntent(intent.Active))
	}
	cleanup := func(cause error) error {
		removeErr := os.Remove(temporary)
		if errors.Is(removeErr, os.ErrNotExist) {
			removeErr = nil
		}
		return errors.Join(cause, removeErr, removeOwnedV1SwapIntent(intent.Active))
	}
	if err = json.NewEncoder(file).Encode(intent); err == nil {
		err = file.Sync()
	}
	if err = errors.Join(err, file.Close()); err != nil {
		return cleanup(err)
	}
	// MoveFileEx WRITE_THROUGH is used on Windows; Unix additionally fsyncs
	// the directory. No original database rename precedes this durable guard.
	if err = replaceSQLiteDatabase(temporary, path); err != nil {
		return cleanup(err)
	}
	if err = syncSQLiteDatabaseParent(filepath.Dir(path)); err != nil {
		return cleanup(err)
	}
	return nil
}

// Only the attempt which reserved this intent calls this helper. Ordinary
// startup only checks the guard; it does not interpret or mutate recovery data.
func removeOwnedV1SwapIntent(active string) error {
	err := os.Remove(v1SwapIntentPath(active))
	if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	return errors.Join(err, syncSQLiteDatabaseParent(filepath.Dir(active)))
}
