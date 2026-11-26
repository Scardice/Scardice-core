package storylog

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"Scardice-core/dice/service"
)

// ExportLocalZip 生成一份用于本地下载的 V1 日志 zip（README + 文本 + JSON），
// 不访问网络，也不写入 log-exports 备份目录。
// 返回 zip 路径与下载文件名，调用方负责删除返回文件所在的临时目录。
func ExportLocalZip(env UploadEnv) (string, string, error) {
	lines, err := service.LogGetAllLines(env.Db, env.GroupID, env.LogName)
	if err != nil {
		return "", "", err
	}
	if len(lines) == 0 {
		return "", "", errors.New("此log不存在，或条目数为空，名字是否正确？")
	}
	env.lines = lines

	dir, err := os.MkdirTemp("", "scardice-log-export-*")
	if err != nil {
		return "", "", fmt.Errorf("创建日志导出临时目录失败: %w", err)
	}
	env.Dir = dir
	if err = formatAndBackup(&env); err != nil {
		_ = os.RemoveAll(dir)
		return "", "", err
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		_ = os.RemoveAll(dir)
		return "", "", fmt.Errorf("读取日志导出目录失败: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".zip" {
			continue
		}
		return filepath.Join(dir, entry.Name()), entry.Name(), nil
	}
	_ = os.RemoveAll(dir)
	return "", "", errors.New("日志导出文件未生成")
}
