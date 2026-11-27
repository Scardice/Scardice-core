//go:build !linux && !windows && !darwin

package bootsound

// systemVolume 在未适配的平台上不可用。
func systemVolume() (float64, bool, bool) {
	return 0, false, false
}
