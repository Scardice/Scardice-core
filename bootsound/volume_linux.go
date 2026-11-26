//go:build linux

package bootsound

import (
	"context"
	"math"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func commandOutput(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Output()
}

func parseWpctlVolume(text string) (float64, bool, bool) {
	muted := strings.Contains(text, "MUTED")
	fields := strings.Fields(text)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "Volume:" {
			if value, err := strconv.ParseFloat(strings.TrimSpace(fields[i+1]), 64); err == nil {
				return math.Pow(value, 3), muted, true
			}
		}
	}
	return 0, false, false
}

func parsePactlVolume(text string) (float64, bool) {
	if idx := strings.Index(text, "%"); idx > 0 {
		j := idx - 1
		for j >= 0 && text[j] >= '0' && text[j] <= '9' {
			j--
		}
		if j < idx-1 {
			if value, err := strconv.ParseFloat(text[j+1:idx], 64); err == nil {
				return math.Pow(value/100, 3), true
			}
		}
	}
	return 0, false
}

// parsePactlMuted 解析 pactl get-sink-mute 的 "Mute: yes/no"。
// 音量接口本身不返回静音状态，需要单独查一次。
func parsePactlMuted(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Mute:") {
			return strings.Contains(strings.ToLower(line), "yes")
		}
	}
	return false
}

// systemVolume 读取默认输出音量，并换算成实际幅度（0~1）。
// PipeWire/PulseAudio 的百分比按三次方映射，80% 约等于 -5.8 dB。
func systemVolume() (float64, bool, bool) {
	if out, err := commandOutput("wpctl", "get-volume", "@DEFAULT_AUDIO_SINK@"); err == nil {
		return parseWpctlVolume(string(out))
	}
	if out, err := commandOutput("pactl", "get-sink-volume", "@DEFAULT_SINK@"); err == nil {
		if level, ok := parsePactlVolume(string(out)); ok {
			muted := false
			if muteOut, muteErr := commandOutput("pactl", "get-sink-mute", "@DEFAULT_SINK@"); muteErr == nil {
				muted = parsePactlMuted(string(muteOut))
			}
			return level, muted, true
		}
	}
	return 0, false, false
}
