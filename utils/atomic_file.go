package utils

import (
	"io"
	"os"
	"path/filepath"
)

// AtomicWriteFile writes data to filename by writing a temporary file in the
// target directory and renaming it into place after the data is flushed.
func AtomicWriteFile(filename string, data []byte, perm os.FileMode) error {
	return atomicWrite(filename, perm, func(tmp *os.File) error {
		if n, err := tmp.Write(data); err != nil {
			return err
		} else if n != len(data) {
			return io.ErrShortWrite
		}
		return nil
	})
}

// AtomicWriteReader writes the contents of r to filename using the same atomic
// replacement semantics as AtomicWriteFile.
func AtomicWriteReader(filename string, r io.Reader, perm os.FileMode) error {
	return atomicWrite(filename, perm, func(tmp *os.File) error {
		_, err := io.Copy(tmp, r)
		return err
	})
}

func atomicWrite(filename string, perm os.FileMode, write func(*os.File) error) error {
	dir := filepath.Dir(filename)
	base := filepath.Base(filename)

	mode := perm
	if info, err := os.Stat(filename); err == nil {
		mode = info.Mode().Perm()
	} else if !os.IsNotExist(err) {
		return err
	}

	tmp, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	removeTmp := true
	defer func() {
		if removeTmp {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := write(tmp); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmpName, filename); err != nil {
		return err
	}
	removeTmp = false

	syncDir(dir)
	return nil
}

func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	defer func() { _ = d.Close() }()
	_ = d.Sync()
}
