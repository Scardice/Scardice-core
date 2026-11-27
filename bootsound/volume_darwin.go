//go:build darwin

package bootsound

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// systemVolume 通过 osascript 读取系统输出音量（0~1）。
func systemVolume() (float64, bool, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "osascript", "-e", "output volume of (get volume settings)").Output()
	if err != nil {
		return 0, false, false
	}
	value, parseErr := strconv.ParseFloat(strings.TrimSpace(string(out)), 64)
	if parseErr != nil {
		return 0, false, false
	}
	return value / 100, false, true
}
