//go:build !linux && !windows && !darwin

package bootsound

// Availability 在未适配的平台上不可用。
func Availability() (bool, string) {
	return false, ""
}
