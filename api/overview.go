package api

import (
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v4"

	"Scardice-core/dice"
	"Scardice-core/model"
	"Scardice-core/utils/constant"
)

// overviewEndpointInfo 是运行概览页展示的端点快照。
// 只读取展示字段，不暴露适配器、会话或连接对象。
type overviewEndpointInfo struct {
	Nickname       string `json:"nickname"`
	UserID         string `json:"userId"`
	Platform       string `json:"platform"`
	ProtocolType   string `json:"protocolType"`
	State          int    `json:"state"`
	Enable         bool   `json:"enable"`
	GroupNum       int64  `json:"groupNum"`
	CmdExecutedNum int64  `json:"cmdExecutedNum"`
}

type overviewProcessInfo struct {
	CPUPercent     float64 `json:"cpuPercent"`
	RSSBytes       uint64  `json:"rssBytes"`
	HeapAllocBytes uint64  `json:"heapAllocBytes"`
	SysBytes       uint64  `json:"sysBytes"`
	Goroutines     int     `json:"goroutines"`
	NumGC          uint32  `json:"numGC"`
	GOMAXPROCS     int     `json:"gomaxprocs"`
	NumCPU         int     `json:"numCPU"`
}

type overviewSystemInfo struct {
	Available         bool    `json:"available"`
	CPUAvailable      bool    `json:"cpuAvailable"`
	MemoryAvailable   bool    `json:"memoryAvailable"`
	DiskAvailable     bool    `json:"diskAvailable"`
	CPUPercent        float64 `json:"cpuPercent"`
	CPUCount          int     `json:"cpuCount"`
	Load1             float64 `json:"load1"`
	Load5             float64 `json:"load5"`
	Load15            float64 `json:"load15"`
	MemTotalBytes     uint64  `json:"memTotalBytes"`
	MemAvailableBytes uint64  `json:"memAvailableBytes"`
	MemUsedPercent    float64 `json:"memUsedPercent"`
	DiskTotalBytes    uint64  `json:"diskTotalBytes"`
	DiskFreeBytes     uint64  `json:"diskFreeBytes"`
	DiskUsedPercent   float64 `json:"diskUsedPercent"`
}

type overviewStorageInfo struct {
	DataDir      string `json:"dataDir"`
	DataBytes    int64  `json:"dataBytes"`
	DefaultBytes int64  `json:"defaultBytes"`
	DecksBytes   int64  `json:"decksBytes"`
	ImagesBytes  int64  `json:"imagesBytes"`
	HelpdocBytes int64  `json:"helpdocBytes"`
	LogsDBBytes  int64  `json:"logsDbBytes"`
	BackupsBytes int64  `json:"backupsBytes"`
}

type overviewCounts struct {
	Groups            int64 `json:"groups"`
	Players           int64 `json:"players"`
	Logs              int64 `json:"logs"`
	LogItems          int64 `json:"logItems"`
	TodayActiveGroups int64 `json:"todayActiveGroups"`
	TodayMessages     int64 `json:"todayMessages"`
	TodayCommands     int64 `json:"todayCommands"`
}

type overviewBackupInfo struct {
	AutoEnable     bool   `json:"autoEnable"`
	AutoTime       string `json:"autoTime"`
	BackupDir      string `json:"backupDir"`
	BackupCount    int    `json:"backupCount"`
	LastBackupTime int64  `json:"lastBackupTime"`
	LastBackupSize int64  `json:"lastBackupSize"`
}

type overviewResponse struct {
	Version       string                 `json:"version"`
	UptimeSeconds int64                  `json:"uptimeSeconds"`
	CollectedAt   int64                  `json:"collectedAt"`
	Process       overviewProcessInfo    `json:"process"`
	System        overviewSystemInfo     `json:"system"`
	Storage       overviewStorageInfo    `json:"storage"`
	Counts        overviewCounts         `json:"counts"`
	Backup        overviewBackupInfo     `json:"backup"`
	Endpoints     []overviewEndpointInfo `json:"endpoints"`
}

type overviewHostMetrics struct {
	Available       bool
	CPUAvailable    bool
	MemoryAvailable bool
	DiskAvailable   bool
	CPUPercent      float64
	CPUCount        int
	Load1           float64
	Load5           float64
	Load15          float64
	MemTotal        uint64
	MemAvailable    uint64
	DiskTotal       uint64
	DiskFree        uint64
}

var overviewStorageCache struct {
	mu   sync.Mutex
	at   time.Time
	data overviewStorageInfo
}

var overviewCountsCache struct {
	mu   sync.Mutex
	at   time.Time
	dice *dice.Dice
	data overviewCounts
}

// sampleProcessCPU 返回进程启动以来的平均 CPU 占用。
// 空闲时短窗口采样容易得到 0，这里用累计 CPU 时间 / 运行时长，数值稳定且不会误报。
func sampleProcessCPU() float64 {
	cpuSeconds, ok := readProcSelfCPUSeconds()
	if !ok {
		return 0
	}
	elapsed := time.Now().Unix() - startTime
	if elapsed <= 0 {
		return 0
	}
	return cpuSeconds / float64(elapsed) * 100
}

const (
	overviewStorageCacheTTL = 60 * time.Second
	overviewCountsCacheTTL  = 30 * time.Second
)

func overviewGet(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}

	if myDice == nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "core not ready"})
	}

	host := sampleHostAndProcess(myDice.BaseConfig.DataDir)
	host.CPUCount = runtime.NumCPU()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	process := overviewProcessInfo{
		CPUPercent:     round2(sampleProcessCPU()),
		RSSBytes:       readProcessRSSBytes(),
		HeapAllocBytes: m.HeapAlloc,
		SysBytes:       m.Sys,
		Goroutines:     runtime.NumGoroutine(),
		NumGC:          m.NumGC,
		GOMAXPROCS:     runtime.GOMAXPROCS(0),
		NumCPU:         runtime.NumCPU(),
	}

	system := overviewSystemInfo{
		Available:         host.Available,
		CPUAvailable:      host.CPUAvailable,
		MemoryAvailable:   host.MemoryAvailable,
		DiskAvailable:     host.DiskAvailable,
		CPUPercent:        round2(host.CPUPercent),
		CPUCount:          host.CPUCount,
		Load1:             round2(host.Load1),
		Load5:             round2(host.Load5),
		Load15:            round2(host.Load15),
		MemTotalBytes:     host.MemTotal,
		MemAvailableBytes: host.MemAvailable,
		DiskTotalBytes:    host.DiskTotal,
		DiskFreeBytes:     host.DiskFree,
	}
	if host.MemTotal > 0 {
		system.MemUsedPercent = round2(float64(host.MemTotal-host.MemAvailable) / float64(host.MemTotal) * 100)
	}
	if host.DiskTotal > 0 {
		system.DiskUsedPercent = round2(float64(host.DiskTotal-host.DiskFree) / float64(host.DiskTotal) * 100)
	}

	uptime := time.Now().Unix() - startTime
	if uptime < 0 {
		uptime = 0
	}

	return c.JSON(http.StatusOK, overviewResponse{
		Version:       dice.VERSION.String(),
		UptimeSeconds: uptime,
		CollectedAt:   time.Now().Unix(),
		Process:       process,
		System:        system,
		Storage:       collectOverviewStorage(myDice.BaseConfig.DataDir),
		Counts:        collectOverviewCounts(myDice),
		Backup:        collectOverviewBackup(),
		Endpoints:     collectOverviewEndpoints(myDice),
	})
}

func collectOverviewEndpoints(d *dice.Dice) []overviewEndpointInfo {
	items := make([]overviewEndpointInfo, 0)
	if d == nil || d.ImSession == nil {
		return items
	}
	for _, ep := range d.ImSession.EndPoints {
		if ep == nil {
			continue
		}
		items = append(items, overviewEndpointInfo{
			Nickname:       ep.Nickname,
			UserID:         ep.UserID,
			Platform:       ep.Platform,
			ProtocolType:   ep.ProtocolType,
			State:          int(ep.State),
			Enable:         ep.Enable,
			GroupNum:       ep.GroupNum,
			CmdExecutedNum: ep.CmdExecutedNum,
		})
	}
	sort.SliceStable(items, func(i, j int) bool {
		rankI := overviewEndpointStateRank(items[i].State)
		rankJ := overviewEndpointStateRank(items[j].State)
		if rankI != rankJ {
			return rankI < rankJ
		}
		if items[i].Platform != items[j].Platform {
			return items[i].Platform < items[j].Platform
		}
		return items[i].Nickname < items[j].Nickname
	})
	return items
}

// overviewEndpointStateRank 让已连接的端点排在前面，断开状态排在最后。
func overviewEndpointStateRank(state int) int {
	switch state {
	case 1: // 已连接
		return 0
	case 2: // 连接中
		return 1
	case 3: // 连接失败
		return 2
	default: // 断开
		return 3
	}
}

func collectOverviewBackup() overviewBackupInfo {
	info := overviewBackupInfo{BackupDir: dice.BackupDir}
	if dm != nil {
		info.AutoEnable = dm.AutoBackupEnable
		info.AutoTime = dm.AutoBackupTime
	}

	entries, err := os.ReadDir(dice.BackupDir)
	if err != nil {
		return info
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".zip") {
			continue
		}
		fileInfo, err := entry.Info()
		if err != nil {
			continue
		}
		info.BackupCount++
		if fileInfo.ModTime().Unix() > info.LastBackupTime {
			info.LastBackupTime = fileInfo.ModTime().Unix()
			info.LastBackupSize = fileInfo.Size()
		}
	}
	return info
}

func collectOverviewStorage(dataDir string) overviewStorageInfo {
	overviewStorageCache.mu.Lock()
	defer overviewStorageCache.mu.Unlock()

	if time.Since(overviewStorageCache.at) < overviewStorageCacheTTL {
		return overviewStorageCache.data
	}

	dataDirAbs, _ := filepath.Abs(dataDir)
	dataRoot := filepath.Dir(dataDirAbs)

	info := overviewStorageInfo{DataDir: dataDirAbs}
	_ = filepath.WalkDir(dataRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		fileInfo, err := d.Info()
		if err != nil {
			return nil
		}
		size := fileInfo.Size()
		info.DataBytes += size

		rel, err := filepath.Rel(dataRoot, path)
		if err != nil {
			return nil
		}
		top := strings.Split(rel, string(os.PathSeparator))[0]
		switch top {
		case "default":
			info.DefaultBytes += size
		case "decks":
			info.DecksBytes += size
		case "images":
			info.ImagesBytes += size
		case "helpdoc":
			info.HelpdocBytes += size
		}
		return nil
	})

	if fileInfo, err := os.Stat(filepath.Join(dataDirAbs, "data-logs.db")); err == nil {
		info.LogsDBBytes = fileInfo.Size()
	}
	info.BackupsBytes = dirSizeAbs(dice.BackupDir)

	overviewStorageCache.at = time.Now()
	overviewStorageCache.data = info
	return info
}

func collectOverviewCounts(d *dice.Dice) overviewCounts {
	overviewCountsCache.mu.Lock()
	defer overviewCountsCache.mu.Unlock()

	if overviewCountsCache.dice == d && time.Since(overviewCountsCache.at) < overviewCountsCacheTTL {
		return overviewCountsCache.data
	}

	counts := overviewCounts{}
	if d != nil && d.DBOperator != nil {
		dataDB := d.DBOperator.GetDataDB(constant.READ)
		if dataDB != nil {
			_ = dataDB.Model(&model.GroupInfo{}).Count(&counts.Groups).Error
			_ = dataDB.Model(&model.GroupPlayerInfoBase{}).Count(&counts.Players).Error
		}

		logDB := d.DBOperator.GetLogDB(constant.READ)
		if logDB != nil {
			_ = logDB.Model(&model.LogInfo{}).Count(&counts.Logs).Error
			_ = logDB.Model(&model.LogOneItem{}).Where("removed IS NULL").Count(&counts.LogItems).Error

			todayStart := time.Date(time.Now().Year(), time.Now().Month(), time.Now().Day(), 0, 0, 0, 0, time.Local).Unix()
			_ = logDB.Model(&model.LogOneItem{}).
				Where("removed IS NULL AND time >= ?", todayStart).
				Count(&counts.TodayMessages).Error
			_ = logDB.Model(&model.LogOneItem{}).
				Where("removed IS NULL AND time >= ? AND command_id > 0", todayStart).
				Count(&counts.TodayCommands).Error
			_ = logDB.Model(&model.LogOneItem{}).
				Where("removed IS NULL AND time >= ?", todayStart).
				Distinct("group_id").
				Count(&counts.TodayActiveGroups).Error
		}
	}

	overviewCountsCache.at = time.Now()
	overviewCountsCache.dice = d
	overviewCountsCache.data = counts
	return counts
}

func dirSizeAbs(path string) int64 {
	var total int64
	_ = filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if fileInfo, err := d.Info(); err == nil {
			total += fileInfo.Size()
		}
		return nil
	})
	return total
}

func round2(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 100 && v < 1000 {
		// 进程 CPU 在多核机器上可能超过 100%，保留一位小数即可。
		return float64(int(v*10+0.5)) / 10
	}
	return float64(int(v*100+0.5)) / 100
}
