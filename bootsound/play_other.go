//go:build !linux && !windows && !darwin

package bootsound

import (
	"errors"
	"time"
)

// playAudioFile 在未适配的平台上跳过播放。
func playAudioFile(_ string, _ time.Duration) (string, error) {
	return "", errors.New("当前平台不支持音频播放")
}
