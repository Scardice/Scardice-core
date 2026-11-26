//go:build darwin

package bootsound

import "os/exec"

// Availability 检查当前设备是否有可用的播放路径。
func Availability() (bool, string) {
	if _, err := exec.LookPath("afplay"); err != nil {
		return false, ""
	}
	return true, "afplay"
}
