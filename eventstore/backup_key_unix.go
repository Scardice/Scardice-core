//go:build !windows

package eventstore

func backupLocalKeyFile(path string) ([]byte, error) {
	return readSecureFile(path, 32)
}
