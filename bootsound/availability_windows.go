//go:build windows

package bootsound

// Availability 检查当前设备是否有可用的播放路径。
func Availability() (bool, string) {
	return true, "winmm"
}
