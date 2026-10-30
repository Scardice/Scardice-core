//go:build windows

package eventstore

func backupLocalKeyFile(path string) ([]byte, error) {
	if _, err := readSecureFile(path, 32); err != nil {
		return nil, err
	}
	return readWindowsFile(path, 64*1024)
}
