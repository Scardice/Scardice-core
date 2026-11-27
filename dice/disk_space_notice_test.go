package dice

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/robfig/cron/v3"

	sealdiceLogger "Scardice-core/logger"
)

func newDiskSpaceNoticeTestDice(t *testing.T, available *uint64, total uint64) (*Dice, func()) {
	t.Helper()

	originalProbe := probePackageDiskSpace
	probePackageDiskSpace = func(string) (packageDiskSpace, error) {
		return packageDiskSpace{Volume: "test", Available: *available, Total: total}, nil
	}

	d := &Dice{Logger: sealdiceLogger.M()}
	d.Config = NewConfig(d)
	d.Config.DiskSpaceNoticeEnable = true
	d.Config.DiskSpaceNoticeThresholdMB = 1
	d.Config.DiskSpaceNoticeInterval = "@every 10m"
	d.Config.DiskSpaceNoticeCooldownMinutes = 60
	d.BaseConfig.DataDir = "/var/lib/scardice/data/default"

	return d, func() { probePackageDiskSpace = originalProbe }
}

func TestDiskSpaceNoticeAlertCooldownAndRecovery(t *testing.T) {
	available := uint64(512 << 10) // 低于 1 MiB 阈值
	d, cleanup := newDiskSpaceNoticeTestDice(t, &available, 100<<20)
	defer cleanup()

	var messages []string
	notify := func(text string) { messages = append(messages, text) }

	t0 := time.Date(2026, 11, 27, 10, 0, 0, 0, time.Local)
	d.checkDiskSpaceNoticeAt(t0, notify)
	if len(messages) != 1 {
		t.Fatalf("首次低空间应告警一次，实际 %d 条", len(messages))
	}
	if !strings.Contains(messages[0], "磁盘空间告警") || !strings.Contains(messages[0], "data/default") {
		t.Fatalf("告警文案异常: %q", messages[0])
	}
	if strings.Contains(messages[0], "/var/lib") {
		t.Fatalf("告警不应泄漏绝对路径: %q", messages[0])
	}

	// 冷却内继续低：不重复
	d.checkDiskSpaceNoticeAt(t0.Add(30*time.Minute), notify)
	if len(messages) != 1 {
		t.Fatalf("冷却内不应重复告警，实际 %d 条", len(messages))
	}

	// 到达冷却：再提醒一次
	d.checkDiskSpaceNoticeAt(t0.Add(60*time.Minute), notify)
	if len(messages) != 2 {
		t.Fatalf("冷却后应再次告警，实际 %d 条", len(messages))
	}

	// 处在阈值和恢复阈值之间：保持低空间状态，不误报恢复
	available = 32 << 20
	d.checkDiskSpaceNoticeAt(t0.Add(61*time.Minute), notify)
	if len(messages) != 2 {
		t.Fatalf("恢复滞回区间内不应发恢复通知，实际 %d 条", len(messages))
	}

	// 高于恢复阈值：发恢复通知
	available = 70 << 20
	d.checkDiskSpaceNoticeAt(t0.Add(62*time.Minute), notify)
	if len(messages) != 3 || !strings.Contains(messages[2], "磁盘空间恢复") {
		t.Fatalf("恢复后应发恢复通知，实际 %v", messages)
	}

	// 恢复后再次低于阈值：立即重新告警，不受上次冷却影响
	available = 512 << 10
	d.checkDiskSpaceNoticeAt(t0.Add(63*time.Minute), notify)
	if len(messages) != 4 || !strings.Contains(messages[3], "磁盘空间告警") {
		t.Fatalf("恢复后再次低空间应立即告警，实际 %v", messages)
	}
}

func TestDiskSpaceNoticeProbeErrorDoesNotAlert(t *testing.T) {
	originalProbe := probePackageDiskSpace
	defer func() { probePackageDiskSpace = originalProbe }()
	probePackageDiskSpace = func(string) (packageDiskSpace, error) {
		return packageDiskSpace{}, errors.New("probe failed")
	}

	d := &Dice{Logger: sealdiceLogger.M()}
	d.Config = NewConfig(d)
	d.Config.DiskSpaceNoticeEnable = true
	d.BaseConfig.DataDir = "data/default"

	var messages []string
	notify := func(text string) { messages = append(messages, text) }
	d.checkDiskSpaceNoticeAt(time.Now(), notify)
	if len(messages) != 0 {
		t.Fatalf("探测失败不应发送通知，实际 %v", messages)
	}
	if d.diskSpaceNoticeLow {
		t.Fatal("探测失败不应改变低空间状态")
	}
}

func TestDiskSpaceNoticeApplySchedulesAndRemoves(t *testing.T) {
	d := &Dice{Logger: sealdiceLogger.M(), Cron: cron.New()}
	d.Config = NewConfig(d)
	d.BaseConfig.DataDir = "data/default"

	d.Config.DiskSpaceNoticeEnable = true
	d.Config.DiskSpaceNoticeInterval = "@every 10m"
	d.ApplyDiskSpaceNotice()
	if d.DiskSpaceNoticeEntry == 0 {
		t.Fatal("启用后应创建磁盘空间告警任务")
	}

	d.Config.DiskSpaceNoticeEnable = false
	d.ApplyDiskSpaceNotice()
	if d.DiskSpaceNoticeEntry != 0 {
		t.Fatal("关闭后应移除磁盘空间告警任务")
	}
}

func TestDiskSpaceNoticeInvalidIntervalFallsBack(t *testing.T) {
	d := &Dice{Logger: sealdiceLogger.M(), Cron: cron.New()}
	d.Config = NewConfig(d)
	d.BaseConfig.DataDir = "data/default"
	d.Config.DiskSpaceNoticeEnable = true
	d.Config.DiskSpaceNoticeInterval = "not-a-valid-cron"

	d.ApplyDiskSpaceNotice()
	if d.DiskSpaceNoticeEntry == 0 {
		t.Fatal("无效间隔应回退到默认间隔并创建任务")
	}
}

func TestDiskSpaceNoticeDisplayPath(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "data/default", want: "data/default"},
		{in: "/srv/scardice/data/default", want: "data/default"},
		{in: ".", want: "data"},
		{in: "", want: "data"},
	}
	for _, tt := range tests {
		if got := diskSpaceNoticeDisplayPath(tt.in); got != tt.want {
			t.Fatalf("diskSpaceNoticeDisplayPath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestDiskSpaceNoticeDefaults(t *testing.T) {
	if DefaultConfig.DiskSpaceNoticeEnable {
		t.Fatal("磁盘空间告警应默认关闭")
	}
	if DefaultConfig.DiskSpaceNoticeThresholdMB != 1024 {
		t.Fatalf("默认阈值 = %d, want 1024", DefaultConfig.DiskSpaceNoticeThresholdMB)
	}
	if DefaultConfig.DiskSpaceNoticeInterval != "@every 10m" {
		t.Fatalf("默认间隔 = %q, want @every 10m", DefaultConfig.DiskSpaceNoticeInterval)
	}
	if DefaultConfig.DiskSpaceNoticeCooldownMinutes != 360 {
		t.Fatalf("默认冷却 = %d, want 360", DefaultConfig.DiskSpaceNoticeCooldownMinutes)
	}
}
