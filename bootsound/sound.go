// Package bootsound 在余烬启动流程中按事件顺序播放内置 UI 音频。
//
// 音频随二进制内嵌，发布包不需要额外的声音文件。所有事件进入同一个串行队列，
// 按事件真实发生时间拉开间隔，前一句播完才播下一句，避免同时出声或互相重叠。
// 播放前会读取系统输出音量，把实际到达扬声器的峰值调整到目标响度，避免在低音量
// 机器上听不见、在高音量机器上过响。播放是尽力而为：没有音频设备、系统静音或
// 没有可用播放器时静默跳过，绝不影响启动。
package bootsound

import (
	_ "embed"
	"encoding/binary"
	"errors"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Event 是启动流程中的一个 UI 音频事件。
type Event string

const (
	EventStartup          Event = "startup"            // 核心启动音频
	EventSelfTestStart    Event = "self-test-start"    // 开机自检开始
	EventSelfTestComplete Event = "self-test-complete" // 开机自检完成
	EventUIEnabled        Event = "ui-enabled"         // UI 界面已打开
	EventPasswordCorrect  Event = "password-correct"   // 密码正确
	EventJSLoaded         Event = "js-loaded"          // JS 插件全部加载完成
	EventDeckLoaded       Event = "deck-loaded"        // 牌堆加载完成
	EventAccountConnected Event = "account-connected"  // 任一账号连接成功
)

//go:embed scardice-startup.wav
var startupWAV []byte

//go:embed self-test-start.wav
var selfTestStartWAV []byte

//go:embed self-test-complete.wav
var selfTestCompleteWAV []byte

//go:embed ui-enabled.wav
var uiEnabledWAV []byte

//go:embed password-correct.wav
var passwordCorrectWAV []byte

//go:embed js-loaded.wav
var jsLoadedWAV []byte

//go:embed deck-loaded.wav
var deckLoadedWAV []byte

//go:embed account-connected.wav
var accountConnectedWAV []byte

var eventWAVs = map[Event][]byte{
	EventStartup:          startupWAV,
	EventSelfTestStart:    selfTestStartWAV,
	EventSelfTestComplete: selfTestCompleteWAV,
	EventUIEnabled:        uiEnabledWAV,
	EventPasswordCorrect:  passwordCorrectWAV,
	EventJSLoaded:         jsLoadedWAV,
	EventDeckLoaded:       deckLoadedWAV,
	EventAccountConnected: accountConnectedWAV,
}

// eventCacheNames 是每个事件固定的缓存文件名。每次播放覆盖同一个文件，
// 不会随音量或播放次数累积。
var eventCacheNames = map[Event]string{
	EventStartup:          "event-startup.wav",
	EventSelfTestStart:    "event-self-test-start.wav",
	EventSelfTestComplete: "event-self-test-complete.wav",
	EventUIEnabled:        "event-ui-enabled.wav",
	EventPasswordCorrect:  "event-password-correct.wav",
	EventJSLoaded:         "event-js-loaded.wav",
	EventDeckLoaded:       "event-deck-loaded.wav",
	EventAccountConnected: "event-account-connected.wav",
}

var eventLabels = map[Event]string{
	EventStartup:          "核心启动",
	EventSelfTestStart:    "开机自检开始",
	EventSelfTestComplete: "开机自检完成",
	EventUIEnabled:        "UI 界面已打开",
	EventPasswordCorrect:  "密码正确",
	EventJSLoaded:         "JS 插件加载完成",
	EventDeckLoaded:       "牌堆加载完成",
	EventAccountConnected: "账号连接成功",
}

// targetEffectivePeakDB 是希望实际到达扬声器的峰值电平（dBFS）。
const targetEffectivePeakDB = -14.0

// maxScaledPeakDB 是缩放后文件允许的最高峰值，确保任何设备上都不会削波失真。
const maxScaledPeakDB = -1.0

// assumedAmplitude 在无法读取系统音量时假设的输出幅度（PipeWire 80% 的等效值）。
const assumedAmplitude = 0.512

// minGain/maxGain 限制自适应增益，避免极端音量下严重削波或完全听不见。
const (
	minGain = 0.5
	maxGain = 8.0
)

var (
	errMuted   = errors.New("系统已静音或音量为 0")
	errPrepare = errors.New("无法准备音频文件")
)

// Status 是最近一次 UI 音频播放尝试的结果，供 WebUI 展示。
type Status struct {
	Event     string `json:"event,omitempty"`
	Player    string `json:"player"`
	Played    bool   `json:"played"`
	Error     string `json:"error,omitempty"`
	Message   string `json:"message"`
	UpdatedAt int64  `json:"updatedAt"`
}

var (
	statusMu   sync.RWMutex
	lastStatus = Status{Message: "尚未尝试播放"}
)

func setStatus(status Status) {
	status.UpdatedAt = time.Now().Unix()
	statusMu.Lock()
	lastStatus = status
	statusMu.Unlock()
}

// StatusSnapshot 返回最近一次播放尝试的结果。
func StatusSnapshot() Status {
	statusMu.RLock()
	defer statusMu.RUnlock()
	return lastStatus
}

type queueItem struct {
	ev Event
	at time.Time
}

var (
	processStartedAt  = time.Now()
	queueMu           sync.Mutex
	pendingItems      []queueItem
	queuedEvents      = map[Event]bool{}
	draining          bool
	lastEventAt       time.Time
	lastPlaybackStart time.Time
)

// PlayEvent 把事件加入串行播放队列。同一事件在一个进程内只播放一次，
// 因此多个账号同时连接、重复加载牌堆或插件都不会重复出声。
//
// 队列按事件进入队列的时间差拉开间隔：上一句播完后，如果距上一句入队
// 的时间差还没到，就等到对应时刻再播下一句；间隔短于上一句音频长度时
// 会被自然压缩，保证任何两句都不会重叠。
func PlayEvent(ev Event) {
	at := time.Now()
	// 核心启动与自检开始对应进程启动和第一条 [自检] 日志，
	// 用包初始化时间做基准，后续事件按收到日志的时间差排开。
	if ev == EventStartup || ev == EventSelfTestStart {
		at = processStartedAt
	}
	enqueueEvent(ev, at)
}

func enqueueEvent(ev Event, at time.Time) {
	if _, ok := eventWAVs[ev]; !ok {
		return
	}
	queueMu.Lock()
	if queuedEvents[ev] {
		queueMu.Unlock()
		return
	}
	queuedEvents[ev] = true
	pendingItems = append(pendingItems, queueItem{ev: ev, at: at})
	if !draining {
		draining = true
		go drainQueue()
	}
	queueMu.Unlock()
}

// PlayStartupSound 保留旧调用入口，等价于 PlayEvent(EventStartup)。
func PlayStartupSound() {
	PlayEvent(EventStartup)
}

func drainQueue() {
	defer func() {
		if r := recover(); r != nil {
			queueMu.Lock()
			draining = false
			queueMu.Unlock()
			setStatus(Status{Message: "音频播放队列异常，已停止本次播放"})
		}
	}()
	for {
		queueMu.Lock()
		if len(pendingItems) == 0 {
			draining = false
			queueMu.Unlock()
			return
		}
		item := pendingItems[0]
		pendingItems = pendingItems[1:]
		prevAt := lastEventAt
		prevStart := lastPlaybackStart
		queueMu.Unlock()

		// 按两句真实发生的时间差排开；上一句还没播完时，队列会在
		// playEvent 里等它播完，保证不重叠。
		if !prevAt.IsZero() {
			if gap := item.at.Sub(prevAt); gap > 0 {
				if wait := time.Until(prevStart.Add(gap)); wait > 0 {
					time.Sleep(wait)
				}
			}
		}
		startedAt := playEvent(item.ev)
		queueMu.Lock()
		lastEventAt = item.at
		lastPlaybackStart = startedAt
		queueMu.Unlock()
	}
}

func playEvent(ev Event) time.Time {
	startedAt := time.Now()
	wav := eventWAVs[ev]
	label := eventLabels[ev]
	path, prepErr := prepareEventAudio(wav, eventCacheNames[ev])
	if prepErr != nil {
		if errors.Is(prepErr, errMuted) {
			setStatus(Status{
				Event:   string(ev),
				Message: "系统已静音或音量为 0，「" + label + "」未播放",
			})
			return startedAt
		}
		setStatus(Status{
			Event:   string(ev),
			Error:   "无法准备音频文件",
			Message: "「" + label + "」音频准备失败",
		})
		return startedAt
	}
	startedAt = time.Now()
	player, playErr := playAudioFile(path, wavDuration(wav))
	if playErr != nil {
		setStatus(Status{
			Event:   string(ev),
			Player:  player,
			Error:   playErr.Error(),
			Message: "「" + label + "」未播放",
		})
		return startedAt
	}
	setStatus(Status{
		Event:   string(ev),
		Player:  player,
		Played:  true,
		Message: "已使用 " + player + " 播放「" + label + "」",
	})
	return startedAt
}

func cacheDir() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil || dir == "" {
		dir = os.TempDir()
	}
	dir = filepath.Join(dir, "scardice")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

var cleanupOnce sync.Once

// cleanupCache 清理旧版本按增益命名的缓存和不再使用的事件缓存。
// 每次进程只执行一次；当前事件缓存随后会被覆盖写入，不会累积。
func cleanupCache(dir string) {
	cleanupOnce.Do(func() {
		keep := map[string]bool{}
		for _, name := range eventCacheNames {
			keep[name] = true
		}
		patterns := []string{
			"startup-auto-*.wav",
			"startup-auto.wav",
			"startup.wav",
			"event-*.wav",
		}
		for _, pattern := range patterns {
			matches, err := filepath.Glob(filepath.Join(dir, pattern))
			if err != nil {
				continue
			}
			for _, match := range matches {
				if !keep[filepath.Base(match)] {
					_ = os.Remove(match)
				}
			}
		}
	})
}

// scaleWAVBytes 返回按 gain 缩放后的完整 WAV（16-bit PCM），并给出缩放后的峰值（0~1）。
func scaleWAVBytes(wav []byte, gain float64) ([]byte, float64, bool) {
	if len(wav) < 12 || string(wav[:4]) != "RIFF" || string(wav[8:12]) != "WAVE" {
		return nil, 0, false
	}
	for off := 12; off+8 <= len(wav); {
		chunkID := string(wav[off : off+4])
		size := int(binary.LittleEndian.Uint32(wav[off+4 : off+8]))
		if chunkID == "data" {
			end := off + 8 + size
			if end > len(wav) {
				end = len(wav)
			}
			data := wav[off+8 : end]
			out := make([]byte, len(wav))
			copy(out, wav)
			peak := 0.0
			for i := 0; i+1 < len(data); i += 2 {
				sample := int16(binary.LittleEndian.Uint16(data[i : i+2]))
				value := float64(sample) * gain
				if value > 32767 {
					value = 32767
				} else if value < -32768 {
					value = -32768
				}
				binary.LittleEndian.PutUint16(out[off+8+i:], uint16(int16(value)))
				if abs := math.Abs(value); abs > peak {
					peak = abs
				}
			}
			return out, peak / 32767.0, true
		}
		off += 8 + size + (size & 1)
	}
	return nil, 0, false
}

// scaleWAV 保留旧测试入口，缩放核心启动音频。
func scaleWAV(gain float64) ([]byte, float64, bool) {
	return scaleWAVBytes(startupWAV, gain)
}

// computeGain 根据原始峰值和系统输出幅度，算出达到目标响度所需的增益。
func computeGain(basePeak, systemAmplitude float64) float64 {
	if basePeak <= 0 {
		return 1
	}
	level := systemAmplitude
	if level <= 0 {
		level = assumedAmplitude
	}
	target := math.Pow(10, targetEffectivePeakDB/20)
	gain := target / basePeak / level
	if gain < minGain {
		gain = minGain
	}
	if gain > maxGain {
		gain = maxGain
	}
	// 再按文件峰值限制一次，保证缩放后不超过 -1 dBFS，不会削波。
	if noClipGain := math.Pow(10, maxScaledPeakDB/20) / basePeak; gain > noClipGain {
		gain = noClipGain
	}
	return gain
}

// prepareEventAudio 读取系统音量并生成按目标响度缩放后的 WAV 文件。
// 系统静音或音量为零时返回 errMuted；低音量仍会尝试放大播放，不能当成静音跳过。
// 缓存文件名固定，每次覆盖写入。
func prepareEventAudio(wav []byte, cacheName string) (string, error) {
	level, muted, ok := systemVolume()
	if ok {
		if muted || level <= 0 {
			return "", errMuted
		}
	}
	_, basePeak, okScale := scaleWAVBytes(wav, 1.0)
	if !okScale || basePeak <= 0 {
		return "", errPrepare
	}
	gain := computeGain(basePeak, level)
	if !ok {
		gain = computeGain(basePeak, assumedAmplitude)
	}
	scaled, _, okScale := scaleWAVBytes(wav, gain)
	if !okScale {
		return "", errPrepare
	}
	dir, err := cacheDir()
	if err != nil {
		return "", errPrepare
	}
	cleanupCache(dir)
	path := filepath.Join(dir, cacheName)
	if err := os.WriteFile(path, scaled, 0o644); err != nil {
		return "", errPrepare
	}
	return path, nil
}

// wavDuration 从 16-bit PCM WAV 头计算时长，供异步播放器等待播放结束。
func wavDuration(wav []byte) time.Duration {
	if len(wav) < 12 || string(wav[:4]) != "RIFF" || string(wav[8:12]) != "WAVE" {
		return 0
	}
	byteRate := 0
	dataSize := 0
	for off := 12; off+8 <= len(wav); {
		chunkID := string(wav[off : off+4])
		size := int(binary.LittleEndian.Uint32(wav[off+4 : off+8]))
		switch chunkID {
		case "fmt ":
			if size >= 12 && off+8+12 <= len(wav) {
				byteRate = int(binary.LittleEndian.Uint32(wav[off+16 : off+20]))
			}
		case "data":
			if size > len(wav)-off-8 {
				size = len(wav) - off - 8
			}
			dataSize = size
		}
		if chunkID == "data" {
			break
		}
		off += 8 + size + (size & 1)
	}
	if byteRate <= 0 || dataSize <= 0 {
		return 0
	}
	return time.Duration(float64(dataSize) / float64(byteRate) * float64(time.Second))
}
