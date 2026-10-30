//go:build !windows

package eventsourcing

import (
	"errors"
	"os"
)

func replaceSQLiteDatabase(source, target string) error {
	return os.Rename(source, target)
}

func syncSQLiteDatabaseParent(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}
