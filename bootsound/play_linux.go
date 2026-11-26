//go:build linux

package bootsound

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

// playAudioFile 使用 mpv 播放 WAV，阻塞到播放结束。
// 只允许 mpv，避免回退到会把文件重采样成 44.1 kHz 双声道的播放器。
func playAudioFile(path string, _ time.Duration) (string, error) {
	mpvPath, err := exec.LookPath("mpv")
	if err != nil {
		return "", errors.New("未检测到 mpv")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, mpvPath,
		"--no-config",
		"--no-video",
		"--audio-display=no",
		"--really-quiet",
		"--audio-samplerate=48000",
		"--audio-channels=mono",
		"--audio-format=s16",
		path,
	)
	if runErr := cmd.Run(); runErr != nil {
		return "mpv", fmt.Errorf("mpv 播放失败：%w", runErr)
	}
	return "mpv", nil
}
