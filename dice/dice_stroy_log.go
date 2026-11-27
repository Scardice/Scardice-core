package dice

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type StoryLogBackup struct {
	Name     string `json:"name"`
	FileSize int64  `json:"fileSize"`
}

// storyLogBackupPath 只接受 log-exports 目录下的直接文件名，
// 防止 ../、绝对路径或分隔符越过目录读取/删除任意文件。
func storyLogBackupPath(dirpath, name string) (string, bool) {
	if name == "" || name == "." || name == ".." {
		return "", false
	}
	if strings.ContainsAny(name, `/\`) || name != filepath.Base(name) {
		return "", false
	}
	return filepath.Join(dirpath, name), true
}

func StoryLogBackupList(d *Dice) ([]StoryLogBackup, error) {
	dirpath := filepath.Join(d.BaseConfig.DataDir, "log-exports")
	backups, err := os.ReadDir(dirpath)
	if err != nil {
		return nil, err
	}

	var res []StoryLogBackup
	for _, backup := range backups {
		info, err := backup.Info()
		if err != nil {
			return nil, err
		}
		res = append(res, StoryLogBackup{
			Name:     backup.Name(),
			FileSize: info.Size(),
		})
	}
	return res, nil
}

func StoryLogBackupDownloadPath(d *Dice, backup string) (string, error) {
	dirpath := filepath.Join(d.BaseConfig.DataDir, "log-exports")
	backupPath, ok := storyLogBackupPath(dirpath, backup)
	if !ok {
		return "", errors.New("invalid backup name")
	}
	_, err := os.Stat(backupPath)
	if err != nil {
		return "", err
	}
	return backupPath, nil
}

func StoryLogBackupBatchDelete(d *Dice, backups []string) []string {
	if len(backups) == 0 {
		return nil
	}
	dirpath := filepath.Join(d.BaseConfig.DataDir, "log-exports")
	var fails []string
	for _, backupName := range backups {
		backupPath, ok := storyLogBackupPath(dirpath, backupName)
		if !ok {
			fails = append(fails, backupName)
			continue
		}
		err := os.Remove(backupPath)
		if err != nil {
			fails = append(fails, backupName)
		}
	}
	return fails
}
