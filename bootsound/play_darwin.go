//go:build darwin

package bootsound

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

// playAudioFile 调用系统 afplay 播放 WAV，阻塞到播放结束。
func playAudioFile(path string, _ time.Duration) (string, error) {
	if _, err := exec.LookPath("afplay"); err != nil {
		return "", errors.New("未检测到 afplay")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if runErr := exec.CommandContext(ctx, "afplay", path).Run(); runErr != nil {
		return "afplay", fmt.Errorf("afplay 播放失败：%w", runErr)
	}
	return "afplay", nil
}
