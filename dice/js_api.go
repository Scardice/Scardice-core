package dice

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

	"Scardice-core/logger"
	"Scardice-core/utils"
)

func Base64ToImageFunc() func(string) (string, error) {
	return func(b64 string) (string, error) {
		log := logger.M()
		// 解码 Base64 值
		data, e := base64.StdEncoding.DecodeString(b64)
		if e != nil {
			// 出现错误，拒绝向下执行
			return "", errors.New("不合法的base64值：" + b64)
		}
		// 计算 MD5 哈希值作为文件名
		hash := md5.Sum(data) //nolint:gosec
		filename := hex.EncodeToString(hash[:])
		tempDir := os.TempDir()
		// 构建文件路径
		imageurlPath := filepath.Join(tempDir, filename)
		imageurlPath = filepath.ToSlash(imageurlPath)
		// 将数据写入文件
		if err := utils.AtomicWriteFile(imageurlPath, data, 0o664); err != nil {
			return "", errors.New("写入文件出错:" + err.Error())
		}
		log.Info("File saved to:", imageurlPath)
		return "file://" + imageurlPath, nil
	}
}
