//go:build linux

package bootsound

import "os/exec"

// Availability 检查当前设备是否有可用的 48 kHz 单声道播放路径。
func Availability() (bool, string) {
	if _, err := exec.LookPath("mpv"); err != nil {
		return false, ""
	}
	return true, "mpv"
}
