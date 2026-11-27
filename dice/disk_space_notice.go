package dice

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultDiskSpaceNoticeThresholdMB     int64  = 1024
	defaultDiskSpaceNoticeInterval               = "@every 10m"
	defaultDiskSpaceNoticeCooldownMinutes        = 360
	maxDiskSpaceNoticeThresholdMB         int64  = 1 << 20 // 1 TiB
	maxDiskSpaceNoticeCooldownMinutes            = 10080   // 7 天
	diskSpaceNoticeRecoveryGraceMin       uint64 = 64 << 20
	diskSpaceNoticeProbeErrLogInterval           = 10 * time.Minute
)

type diskSpaceNoticeSettings struct {
	thresholdMB    int64
	thresholdBytes uint64
	cooldown       time.Duration
	interval       string
}

func (d *Dice) diskSpaceNoticeSettings() diskSpaceNoticeSettings {
	settings := diskSpaceNoticeSettings{
		thresholdMB: defaultDiskSpaceNoticeThresholdMB,
		cooldown:    time.Duration(defaultDiskSpaceNoticeCooldownMinutes) * time.Minute,
		interval:    defaultDiskSpaceNoticeInterval,
	}
	if d == nil {
		settings.thresholdBytes = uint64(settings.thresholdMB) << 20
		return settings
	}

	thresholdMB := d.Config.DiskSpaceNoticeThresholdMB
	if thresholdMB <= 0 {
		thresholdMB = defaultDiskSpaceNoticeThresholdMB
	}
	if thresholdMB > maxDiskSpaceNoticeThresholdMB {
		thresholdMB = maxDiskSpaceNoticeThresholdMB
	}
	settings.thresholdMB = thresholdMB
	settings.thresholdBytes = uint64(thresholdMB) << 20

	cooldownMinutes := d.Config.DiskSpaceNoticeCooldownMinutes
	if cooldownMinutes <= 0 {
		cooldownMinutes = defaultDiskSpaceNoticeCooldownMinutes
	}
	if cooldownMinutes > maxDiskSpaceNoticeCooldownMinutes {
		cooldownMinutes = maxDiskSpaceNoticeCooldownMinutes
	}
	settings.cooldown = time.Duration(cooldownMinutes) * time.Minute

	if interval := strings.TrimSpace(d.Config.DiskSpaceNoticeInterval); interval != "" {
		settings.interval = interval
	}
	return settings
}

// ApplyDiskSpaceNotice 重建磁盘空间告警定时任务。
// 关闭时只移除任务并清空内存状态，不改变其他配置。
func (d *Dice) ApplyDiskSpaceNotice() {
	if d == nil {
		return
	}
	if d.Cron != nil && d.DiskSpaceNoticeEntry != 0 {
		d.Cron.Remove(d.DiskSpaceNoticeEntry)
		d.DiskSpaceNoticeEntry = 0
	}

	d.diskSpaceNoticeMu.Lock()
	d.diskSpaceNoticeLow = false
	d.diskSpaceNoticeLastAlert = time.Time{}
	d.diskSpaceNoticeLastProbeErrAt = time.Time{}
	d.diskSpaceNoticeMu.Unlock()

	if !d.Config.DiskSpaceNoticeEnable {
		return
	}
	if d.Cron == nil {
		if d.Logger != nil {
			d.Logger.Error("创建磁盘空间告警任务失败: Cron 未初始化")
		}
		return
	}

	settings := d.diskSpaceNoticeSettings()
	entry, err := d.Cron.AddFunc(settings.interval, d.checkDiskSpaceNotice)
	if err != nil {
		if d.Logger != nil {
			d.Logger.Errorf("创建磁盘空间告警任务失败，间隔 %q 无效: %v，将使用默认间隔 %s", settings.interval, err, defaultDiskSpaceNoticeInterval)
		}
		settings.interval = defaultDiskSpaceNoticeInterval
		entry, err = d.Cron.AddFunc(settings.interval, d.checkDiskSpaceNotice)
	}
	if err != nil {
		if d.Logger != nil {
			d.Logger.Error("创建磁盘空间告警任务失败: ", err)
		}
		return
	}

	d.DiskSpaceNoticeEntry = entry
	if d.Logger != nil {
		d.Logger.Infof("创建磁盘空间告警任务成功，间隔 %s，阈值 %d MiB", settings.interval, settings.thresholdMB)
	}
}

func (d *Dice) checkDiskSpaceNotice() {
	if d == nil || !d.Config.DiskSpaceNoticeEnable {
		return
	}
	// 没有可用的系统通知目标时先不记账，等端点连上后的下一次检查再提醒。
	if !d.hasDiskSpaceNoticeTarget() {
		return
	}
	d.checkDiskSpaceNoticeAt(time.Now(), d.sendDiskSpaceNotice)
}

// checkDiskSpaceNoticeAt 执行一次检查；now 和 notify 可注入，便于测试冷却与恢复。
func (d *Dice) checkDiskSpaceNoticeAt(now time.Time, notify func(string)) {
	if d == nil || !d.Config.DiskSpaceNoticeEnable {
		return
	}

	settings := d.diskSpaceNoticeSettings()
	dataDir := strings.TrimSpace(d.BaseConfig.DataDir)
	if dataDir == "" {
		dataDir = "data"
	}

	space, err := probePackageDiskSpace(dataDir)
	if err != nil {
		d.logDiskSpaceProbeError(now, dataDir, err)
		return
	}

	recoverThreshold := settings.thresholdBytes + settings.thresholdBytes/10
	if recoverThreshold < settings.thresholdBytes {
		recoverThreshold = ^uint64(0)
	}
	if grace := settings.thresholdBytes / 10; grace < diskSpaceNoticeRecoveryGraceMin {
		recoverThreshold = settings.thresholdBytes + diskSpaceNoticeRecoveryGraceMin
	}

	displayPath := diskSpaceNoticeDisplayPath(dataDir)

	var alertText string
	var recoveryText string

	d.diskSpaceNoticeMu.Lock()
	if !d.diskSpaceNoticeLow {
		if space.Available < settings.thresholdBytes {
			d.diskSpaceNoticeLow = true
			d.diskSpaceNoticeLastAlert = now
			alertText = buildDiskSpaceAlertMessage(displayPath, space, settings)
		}
	} else if space.Available >= recoverThreshold {
		d.diskSpaceNoticeLow = false
		d.diskSpaceNoticeLastAlert = time.Time{}
		recoveryText = buildDiskSpaceRecoveryMessage(displayPath, space, settings)
	} else if now.Sub(d.diskSpaceNoticeLastAlert) >= settings.cooldown {
		d.diskSpaceNoticeLastAlert = now
		alertText = buildDiskSpaceAlertMessage(displayPath, space, settings)
	}
	d.diskSpaceNoticeMu.Unlock()

	if alertText != "" {
		if d.Logger != nil {
			d.Logger.Warnf("%s", alertText)
		}
		if notify != nil {
			notify(alertText)
		}
	}
	if recoveryText != "" {
		if d.Logger != nil {
			d.Logger.Infof("%s", recoveryText)
		}
		if notify != nil {
			notify(recoveryText)
		}
	}
}

func (d *Dice) sendDiskSpaceNotice(text string) {
	if d == nil || text == "" {
		return
	}
	d.NoticeForEveryEndpoint(text, false, NoticeTypeSystem)
}

func (d *Dice) hasDiskSpaceNoticeTarget() bool {
	if d == nil {
		return false
	}
	if d.Config.MailEnable {
		if !d.CanSendMail() {
			return false
		}
		// SendMail 只认 QQ: 和 Mail: 目标；通知列表里只有群目标时不能算可用。
		for _, target := range filterNoticeTargets(d.Config.NoticeIDs, NoticeTypeSystem) {
			if strings.HasPrefix(target.ID, "QQ:") || strings.HasPrefix(target.ID, "Mail:") {
				return true
			}
		}
		return false
	}
	if d.ImSession == nil {
		return false
	}
	for _, ep := range d.ImSession.EndPointsRawSnapshot() {
		if ep == nil || !ep.Enable || ep.State != StateConnected {
			continue
		}
		if len(filterNoticeTargetsForEndpoint(d.Config.NoticeIDs, NoticeTypeSystem, ep)) > 0 {
			return true
		}
	}
	return false
}

func (d *Dice) logDiskSpaceProbeError(now time.Time, dataDir string, err error) {
	d.diskSpaceNoticeMu.Lock()
	if now.Sub(d.diskSpaceNoticeLastProbeErrAt) < diskSpaceNoticeProbeErrLogInterval {
		d.diskSpaceNoticeMu.Unlock()
		return
	}
	d.diskSpaceNoticeLastProbeErrAt = now
	d.diskSpaceNoticeMu.Unlock()

	if d.Logger != nil {
		d.Logger.Warnf("磁盘空间检查失败（%s）: %v", filepath.Clean(dataDir), err)
	}
}

func diskSpaceNoticeDisplayPath(dataDir string) string {
	clean := filepath.Clean(strings.TrimSpace(dataDir))
	if clean == "" || clean == "." {
		return "data"
	}
	if !filepath.IsAbs(clean) {
		return clean
	}
	base := filepath.Base(clean)
	if base == "" || base == "." || base == string(filepath.Separator) {
		return "data"
	}
	return filepath.Join("data", base)
}

func buildDiskSpaceAlertMessage(displayPath string, space packageDiskSpace, settings diskSpaceNoticeSettings) string {
	return fmt.Sprintf(
		"【磁盘空间告警】数据目录可用空间不足\n目录: %s\n可用: %s / %s（%s）\n阈值: %s\n持续不足时每 %s 提醒一次；空间恢复后会自动通知。",
		displayPath,
		formatPackageBytes(space.Available),
		formatPackageBytes(space.Total),
		formatDiskSpacePercent(space.Available, space.Total),
		formatPackageBytes(settings.thresholdBytes),
		formatDiskSpaceCooldown(settings.cooldown),
	)
}

func buildDiskSpaceRecoveryMessage(displayPath string, space packageDiskSpace, settings diskSpaceNoticeSettings) string {
	return fmt.Sprintf(
		"【磁盘空间恢复】数据目录可用空间已恢复\n目录: %s\n可用: %s / %s（%s）\n阈值: %s",
		displayPath,
		formatPackageBytes(space.Available),
		formatPackageBytes(space.Total),
		formatDiskSpacePercent(space.Available, space.Total),
		formatPackageBytes(settings.thresholdBytes),
	)
}

func formatDiskSpacePercent(available, total uint64) string {
	if total == 0 {
		return "未知"
	}
	percent := float64(available) / float64(total) * 100
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}
	return fmt.Sprintf("%.2f%%", percent)
}

func formatDiskSpaceCooldown(duration time.Duration) string {
	if duration >= time.Hour && duration%time.Hour == 0 {
		return fmt.Sprintf("%d 小时", int64(duration/time.Hour))
	}
	return fmt.Sprintf("%d 分钟", int64(duration/time.Minute))
}
