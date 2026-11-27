//go:build windows

package bootsound

import (
	"errors"
	"syscall"
	"time"
	"unsafe"
)

var (
	winmm            = syscall.NewLazyDLL("winmm.dll")
	playSound        = winmm.NewProc("PlaySoundW")
	waveOutGetVolume = winmm.NewProc("waveOutGetVolume")
)

const (
	sndAsync     = 0x0001
	sndNoDefault = 0x0002
	sndFilename  = 0x00020000
)

// systemVolume 读取默认波形输出设备的音量（0~1）。
func systemVolume() (float64, bool, bool) {
	var volume uint32
	result, _, _ := waveOutGetVolume.Call(0, uintptr(unsafe.Pointer(&volume)))
	if result != 0 {
		return 0, false, false
	}
	left := volume & 0xFFFF
	return float64(left) / 65535.0, false, true
}

// playAudioFile 用 winmm 异步播放 48 kHz 单声道 WAV，并按音频时长等待，
// 保证串行队列里的下一句不会覆盖这一句。
func playAudioFile(path string, duration time.Duration) (string, error) {
	ptr, tokenErr := syscall.UTF16PtrFromString(path)
	if tokenErr != nil {
		return "", errors.New("音频路径无效")
	}
	result, _, _ := playSound.Call(uintptr(unsafe.Pointer(ptr)), 0, sndFilename|sndAsync|sndNoDefault)
	if result == 0 {
		return "winmm", errors.New("winmm 播放失败")
	}
	if duration <= 0 {
		duration = 3 * time.Second
	}
	time.Sleep(duration)
	return "winmm", nil
}
