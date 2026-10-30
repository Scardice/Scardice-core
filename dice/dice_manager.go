package dice

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dop251/goja_nodejs/require"
	"github.com/robfig/cron/v3"

	"Scardice-core/core/managerstate"
	"Scardice-core/eventstore"
	"Scardice-core/logger"
	"Scardice-core/utils/dboperator/engine"
)

type VersionInfo struct {
	VersionLatest           string `json:"versionLatest"           yaml:"versionLatest"`
	VersionLatestDetail     string `json:"versionLatestDetail"     yaml:"versionLatestDetail"`
	VersionLatestCode       int64  `json:"versionLatestCode"       yaml:"versionLatestCode"`
	VersionLatestNote       string `json:"versionLatestNote"       yaml:"versionLatestNote"`
	MinUpdateSupportVersion int64  `json:"minUpdateSupportVersion" yaml:"minUpdateSupportVersion"`
	NewVersionURLPrefix     string `json:"newVersionUrlPrefix"     yaml:"newVersionUrlPrefix"`
	UpdaterURLPrefix        string `json:"updaterUrlPrefix"        yaml:"updaterUrlPrefix"`
}

// MaxTrayTooltipPrefixLength 自定义托盘提示前缀的最大字符数。
const MaxTrayTooltipPrefixLength = 10

type GroupNameCacheItem struct {
	Name                string
	MemberCount         uint32
	MaxMemberCount      uint32
	MemberCountKnown    bool
	MaxMemberCountKnown bool
	time                int64
}

type DiceManager struct { //nolint:revive
	Dice                 []*Dice
	diceLock             sync.RWMutex
	Operator             engine.DatabaseOperator
	EventSourcedMode     bool `json:"-" yaml:"-"`
	durableStore         eventstore.Store
	managerState         managerstate.State
	managerStateMu       sync.Mutex
	ServeAddress         string
	trayTooltip          string
	trayTooltipLock      sync.RWMutex
	Help                 *HelpManager
	IsHelpReloading      atomic.Bool `yaml:"-" json:"-"`
	helpReloadLock       sync.RWMutex
	helpStartupMu        sync.Mutex
	initialHelpLoadDone  chan struct{}
	initialHelpLoadErr   error
	UseDictForTokenizer  bool
	HelpDocEngineType    int
	progressExitGroupWin ProcessExitGroup

	IsNamesReloading bool
	NamesGenerator   *NamesGenerator
	NamesInfo        map[string]map[string][]string
	namesLoadWG      sync.WaitGroup

	DiceRandomMode string
	UIPasswordHash string
	UIPasswordSalt string
	AccessTokens   SyncMap[string, bool]
	IsReady        bool

	// AssetImageToken 是 /assets-img/:token/* 静态路由的鉴权 token。
	// 启动时生成一次，进程生命周期内固定
	AssetImageToken string `yaml:"-" json:"-"`

	AutoBackupEnable    bool
	AutoBackupTime      string
	AutoBackupSelection BackupSelection
	backupEntryID       cron.EntryID
	backupJobMu         sync.RWMutex
	backupJob           *BackupJob

	// 备份自动清理配置
	BackupCleanStrategy  BackupCleanStrategy // 关闭 / 保留一定数量 / 保留一定时间
	BackupCleanKeepCount int                 // 保留的数量
	BackupCleanKeepDur   time.Duration       // 保留的时间
	BackupCleanTrigger   BackupCleanTrigger  // 触发方式: cron触发 / 随自动备份触发 (多种方式按位OR)
	BackupCleanCron      string              // 如果使用cron触发, 表达式
	backupCleanCronID    cron.EntryID

	AppBootTime      int64
	AppVersionCode   int64
	AppVersionOnline *VersionInfo

	UpdateRequestChan      chan *Dice
	UpdateDownloadedChan   chan string
	RebootRequestChan      chan int
	UpdateCheckRequestChan chan int

	groupNameCacheMu sync.Mutex

	GroupNameCache SyncMap[string, *GroupNameCacheItem] // 群名缓存，全局共享, key string value *GroupNameCacheItem
	UserNameCache  SyncMap[string, *GroupNameCacheItem] // 用户缓存，全局共享, key string value *GroupNameCacheItem
	UserIDCache    SyncMap[string, int64]               // 用户id缓存 key username (string) value int64 目前仅Telegram adapter使用

	Cron                 *cron.Cron
	ServiceName          string
	JustForTest          bool
	JsRegistry           *require.Registry
	UpdateScardiceByFile func(packName string) bool // 使用指定压缩包升级余烬，如果出错返回false，如果成功进程会自动结束

	ContainerMode bool          // 容器模式：禁用内置适配器，不允许使用内置Lagrange和旧的内置Gocq
	CleanupFlag   atomic.Uint32 // 1 为正在清理，0为普通状态
}

type Configs struct { //nolint:revive
	DiceConfigs       []BaseConfig `yaml:"diceConfigs"`
	ServeAddress      string       `yaml:"serveAddress"`
	TrayTooltip       string       `yaml:"trayTooltip"`
	WebUIAddress      string       `yaml:"webUIAddress"`
	HelpDocEngineType int          `yaml:"helpDocEngineType"`
	DiceRandomMode    string       `yaml:"diceRandomMode"`

	UIPasswordSalt string   `yaml:"UIPasswordFrontendSalt"`
	UIPasswordHash string   `yaml:"uiPasswordHash"`
	AccessTokens   []string `yaml:"accessTokens"` //nolint:gosec

	AutoBackupEnable    bool   `yaml:"autoBackupEnable"`
	AutoBackupTime      string `yaml:"autoBackupTime"`
	AutoBackupSelection uint64 `yaml:"autoBackupSelection"`

	BackupClean struct {
		Strategy  int    `yaml:"strategy"`
		KeepCount int    `yaml:"keepCount"`
		KeepDur   int64  `yaml:"keepDur"`
		Trigger   int    `yaml:"trigger"`
		Cron      string `yaml:"cron"`
	} `yaml:"backupClean"`

	ServiceName string `yaml:"serviceName"`

	ConfigVersion int `yaml:"configVersion"`
}

func (dm *DiceManager) InitHelp() {
	if err := dm.reloadHelp(false); err == nil {
		dm.clearHelpDocStartupError()
	}
}

// WithHelpDocManagerRead serializes access against initial publication, reloads, and writes.
// The callback runs with the manager read lock held and must not re-enter
// any HelpDocManager access method.
func (dm *DiceManager) WithHelpDocManagerRead(fn func(*HelpManager) error) error {
	return dm.WithHelpDocManagerReadContext(context.Background(), fn)
}

// WithHelpDocManagerReadContext waits for initial publication before taking the read lock.
func (dm *DiceManager) WithHelpDocManagerReadContext(ctx context.Context, fn func(*HelpManager) error) error {
	if err := dm.WaitForHelpDocStartup(ctx); err != nil {
		return err
	}
	dm.helpReloadLock.RLock()
	defer dm.helpReloadLock.RUnlock()
	return fn(dm.Help)
}

// WithHelpDocManagerWrite serializes mutations against initial publication, reads, and reloads.
// The callback runs with the manager write lock held and must not re-enter
// any HelpDocManager access method.
func (dm *DiceManager) WithHelpDocManagerWrite(fn func(*HelpManager) error) error {
	return dm.WithHelpDocManagerWriteContext(context.Background(), fn)
}

// WithHelpDocManagerWriteContext waits for initial publication before taking the write lock.
func (dm *DiceManager) WithHelpDocManagerWriteContext(ctx context.Context, fn func(*HelpManager) error) error {
	if err := dm.WaitForHelpDocStartup(ctx); err != nil {
		return err
	}
	dm.helpReloadLock.Lock()
	defer dm.helpReloadLock.Unlock()
	return fn(dm.Help)
}

// IsHelpDocLoading reports either the asynchronous initial publication or an active reload.
func (dm *DiceManager) IsHelpDocLoading() bool {
	if dm == nil {
		return false
	}
	if dm.IsHelpReloading.Load() {
		return true
	}
	dm.helpStartupMu.Lock()
	done := dm.initialHelpLoadDone
	dm.helpStartupMu.Unlock()
	if done == nil {
		return false
	}
	select {
	case <-done:
		return false
	default:
		return true
	}
}

// WaitForHelpDocStartup waits for the initial HelpDoc publication and returns its concrete failure.
func (dm *DiceManager) WaitForHelpDocStartup(ctx context.Context) error {
	if dm == nil {
		return errors.New("dice manager is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	dm.helpStartupMu.Lock()
	done := dm.initialHelpLoadDone
	dm.helpStartupMu.Unlock()
	if done == nil {
		return nil
	}
	select {
	case <-done:
		dm.helpStartupMu.Lock()
		err := dm.initialHelpLoadErr
		dm.helpStartupMu.Unlock()
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (dm *DiceManager) clearHelpDocStartupError() {
	dm.helpStartupMu.Lock()
	defer dm.helpStartupMu.Unlock()
	done := dm.initialHelpLoadDone
	if done == nil {
		return
	}
	select {
	case <-done:
		dm.initialHelpLoadErr = nil
	default:
	}
}

func (dm *DiceManager) startHelpDocLoadAsync() {
	dm.helpStartupMu.Lock()
	if dm.initialHelpLoadDone != nil {
		dm.helpStartupMu.Unlock()
		return
	}
	done := make(chan struct{})
	dm.initialHelpLoadDone = done
	dm.initialHelpLoadErr = nil
	dm.helpStartupMu.Unlock()

	log := logger.M()
	go func() {
		var loadErr error
		var finishOnce sync.Once
		finish := func() {
			finishOnce.Do(func() {
				dm.helpStartupMu.Lock()
				dm.initialHelpLoadErr = loadErr
				close(done)
				dm.helpStartupMu.Unlock()
			})
		}
		handlePanic := func(r any, help *HelpManager) {
			loadErr = fmt.Errorf("帮助文档初始加载失败: %v", r)
			log.Warn("帮助文档加载失败。可能是由于退出程序过快，帮助文档还未加载完成所致", r)
			if help != nil {
				log.Warn("帮助文件加载失败:", help.LoadingFn)
			}
		}
		defer func() {
			if r := recover(); r != nil {
				dm.helpReloadLock.Lock()
				func() {
					defer dm.helpReloadLock.Unlock()
					handlePanic(r, dm.Help)
					finish()
				}()
			}
		}()

		// Wait before locking: a startup script may synchronously call ReloadHelp.
		for _, d := range dm.Dice {
			if d != nil {
				d.WaitStartupJsLoaded()
			}
		}
		dm.helpReloadLock.Lock()
		func() {
			defer dm.helpReloadLock.Unlock()
			defer func() {
				if r := recover(); r != nil {
					handlePanic(r, dm.Help)
				}
				finish()
			}()
			loadErr = dm.reloadHelpLocked(dm.Help != nil)
		}()
	}()
}

// ReloadHelp does not wait for startup JS because a startup script may call it synchronously.
func (dm *DiceManager) ReloadHelp() error {
	err := dm.reloadHelp(true)
	if err == nil {
		dm.clearHelpDocStartupError()
	}
	return err
}

func (dm *DiceManager) reloadHelp(closeCurrent bool) error {
	dm.helpReloadLock.Lock()
	defer dm.helpReloadLock.Unlock()
	return dm.reloadHelpLocked(closeCurrent)
}

func (dm *DiceManager) reloadHelpLocked(closeCurrent bool) error {
	log := logger.M()
	dm.IsHelpReloading.Store(true)
	defer dm.IsHelpReloading.Store(false)
	_ = os.MkdirAll("./data/helpdoc", 0755)
	if closeCurrent && dm.Help != nil {
		dm.Help.Close()
	}
	if len(dm.Dice) == 0 {
		err := errors.New("Dice实例不存在")
		log.Error(err)
		return err
	}
	log.Info("帮助文档开始异步加载")
	nextHelp := dm.Help
	if nextHelp == nil || closeCurrent {
		nextHelp = &HelpManager{EngineType: EngineType(dm.HelpDocEngineType)}
	}
	nextHelp.Load(dm.Dice[0], dm.Dice[0].CmdMap, dm.Dice[0].ExtList)
	if !nextHelp.IsAvailable() {
		err := errors.New("帮助文档搜索引擎不可用")
		log.Error(err)
		return err
	}
	dm.Help = nextHelp
	log.Info("帮助文档异步加载结束")
	return nil
}

// InitializeRuntime prepares process-owned runtime infrastructure without
// reading or mutating legacy configuration. Event-sourced startup calls this
// only after the event-store readiness gate has passed.
func (dm *DiceManager) InitializeRuntime() error {
	if dm == nil {
		return errors.New("dice manager is nil")
	}
	dm.EventSourcedMode = true
	dm.AppVersionCode = VERSION_CODE
	dm.AppBootTime = time.Now().Unix()
	dm.JsRegistry = new(require.Registry)
	dm.Cron = cron.New()
	dm.Cron.Start()
	dm.AccessTokens = SyncMap[string, bool]{}
	if dm.UIPasswordSalt == "" {
		salt, err := GenerateCryptoToken(32)
		if err != nil {
			return err
		}
		dm.UIPasswordSalt = salt
	}
	if dm.AssetImageToken == "" {
		token, err := GenerateCryptoToken(32)
		if err != nil {
			return err
		}
		dm.AssetImageToken = token
	}
	dm.AutoBackupEnable = true
	dm.AutoBackupTime = "@every 12h"
	return nil
}

func (dm *DiceManager) Save() {
	if dm == nil {
		return
	}
	if err := dm.saveEventSourcedManager(); err != nil {
		logger.M().Errorf("保存事件源管理器配置失败: %v", err)
	}
}

func (dm *DiceManager) GetTrayTooltip() string {
	dm.trayTooltipLock.RLock()
	defer dm.trayTooltipLock.RUnlock()
	return dm.trayTooltip
}

// NormalizeTrayTooltipPrefix 规范化托盘提示前缀，并按 Unicode 字符数限制长度。
func NormalizeTrayTooltipPrefix(tooltip string) string {
	tooltip = strings.TrimSpace(tooltip)
	runes := []rune(tooltip)
	if len(runes) > MaxTrayTooltipPrefixLength {
		return string(runes[:MaxTrayTooltipPrefixLength])
	}
	return tooltip
}

func (dm *DiceManager) SetTrayTooltip(tooltip string) {
	dm.trayTooltipLock.Lock()
	defer dm.trayTooltipLock.Unlock()
	dm.trayTooltip = NormalizeTrayTooltipPrefix(tooltip)
}

// DiceSnapshot 返回当前 Dice 实例切片的副本。
func (dm *DiceManager) DiceSnapshot() []*Dice {
	dm.diceLock.RLock()
	defer dm.diceLock.RUnlock()
	return append([]*Dice(nil), dm.Dice...)
}

// DeferStartupJSLoad keeps production plugin evaluation behind application
// composition. Call it before InitDice; standalone constructors remain
// immediate unless they explicitly opt in through this manager boundary.
func (dm *DiceManager) DeferStartupJSLoad() error {
	if dm == nil {
		return errors.New("dice: nil manager cannot defer startup JavaScript")
	}
	for _, instance := range dm.DiceSnapshot() {
		if instance == nil {
			continue
		}
		if err := instance.deferStartupJSLoad(); err != nil {
			return fmt.Errorf("dice %q: defer startup JavaScript: %w", instance.BaseConfig.Name, err)
		}
	}
	return nil
}

// StartDeferredStartupJSLoad releases each opted-in runtime exactly once.
// A runtime whose process-stop admission is already closed remains canceled.
func (dm *DiceManager) StartDeferredStartupJSLoad() {
	if dm == nil {
		return
	}
	for _, instance := range dm.DiceSnapshot() {
		if instance != nil {
			instance.startDeferredStartupJSLoad()
		}
	}
}

func (dm *DiceManager) InitDice(writer *logger.UIWriter) {
	log := logger.M()
	startTime := time.Now()
	dm.UpdateRequestChan = make(chan *Dice, 1)
	dm.RebootRequestChan = make(chan int, 1)
	dm.UpdateCheckRequestChan = make(chan int, 1)
	dm.UpdateDownloadedChan = make(chan string, 1)
	if dm.EventSourcedMode {
		for _, instance := range dm.Dice {
			if instance == nil {
				continue
			}
			instance.Parent = dm
			instance.initEventSourcedRuntime(writer)
		}
		dm.DiceRandomMode = string(normalizeGlobalDiceRandomMode(dm.DiceRandomMode, nil))
		dm.syncDiceRandomMode()
		if err := dm.ActivateDiceRandomMode(); err != nil {
			log.Warnf("[随机源] 激活全局模式 %s 失败，当前生效模式为 %s: %v", dm.GetDiceRandomMode(), globalRandSource.CurrentMode(), err)
		}
		globalRandSource.LogActiveMode(log)
		dm.LoadNamesAsync()
		dm.startHelpDocLoadAsync()
		log.Infof("事件源 Core 壳初始化完成，耗时 %dms", time.Since(startTime).Milliseconds())
		return
	}

	dm.LoadNamesAsync()

	g, err := NewProcessExitGroup()
	if err != nil {
		log.Warn("进程组创建失败，若进程崩溃，gocqhttp进程可能需要手动结束。")
	} else {
		dm.progressExitGroupWin = g
	}

	for _, i := range dm.Dice {
		i.Parent = dm
		i.Init(dm.Operator, writer)
	}
	legacyModes := make([]BaseConfig, 0, len(dm.Dice))
	for _, d := range dm.Dice {
		if d != nil {
			legacyModes = append(legacyModes, d.Config.BaseConfig)
		}
	}
	configuredMode := strings.TrimSpace(dm.DiceRandomMode)
	dm.DiceRandomMode = string(normalizeGlobalDiceRandomMode(dm.DiceRandomMode, legacyModes))
	for _, legacy := range legacyModes {
		if strings.TrimSpace(legacy.DiceRandomMode) == "" {
			continue
		}
		legacyMode := normalizeGlobalDiceRandomMode(legacy.DiceRandomMode, nil)
		if legacyMode != dm.GetDiceRandomMode() {
			log.Warnf("[随机源] 忽略 Dice 级随机模式 %s，使用全局模式 %s", legacyMode, dm.GetDiceRandomMode())
		}
	}
	if configuredMode == "" {
		log.Infof("[随机源] 已从旧版 Dice 配置迁移全局模式: %s", dm.GetDiceRandomMode())
	}
	dm.syncDiceRandomMode()
	if err := dm.ActivateDiceRandomMode(); err != nil {
		log.Warnf("[随机源] 激活全局配置模式 %s 失败，当前生效模式为 %s: %v", dm.GetDiceRandomMode(), globalRandSource.CurrentMode(), err)
	}
	globalRandSource.LogActiveMode(log)

	dm.startHelpDocLoadAsync()

	dm.ResetAutoBackup()
	dm.ResetBackupClean()
	log.Infof("启动同步初始化完成，耗时 %dms（不含 names/deck/js/helpdoc 异步加载）", time.Since(startTime).Milliseconds())
}

func (dm *DiceManager) ResetAutoBackup() {
	log := logger.M()
	if dm.backupEntryID != 0 {
		dm.Cron.Remove(dm.backupEntryID)
		dm.backupEntryID = 0
	}
	if dm.AutoBackupEnable {
		var err error
		dm.backupEntryID, err = dm.Cron.AddFunc(dm.AutoBackupTime, func() {
			errBackup := dm.BackupAuto()
			if errBackup != nil {
				log.Errorf("自动备份失败: %v", errBackup)
				return
			}
			if errBackup = dm.BackupClean(true); errBackup != nil {
				log.Errorf("滚动清理备份失败: %v", errBackup)
			}
		})
		if err != nil {
			log.Errorf("设定的自动备份间隔有误: %v", err)
			return
		}
	}
}

func (dm *DiceManager) ResetBackupClean() {
	log := logger.M()
	if dm.backupCleanCronID > 0 {
		dm.Cron.Remove(dm.backupCleanCronID)
		dm.backupCleanCronID = 0
	}

	if (dm.BackupCleanTrigger & BackupCleanTriggerCron) > 0 {
		var err error
		dm.backupCleanCronID, err = dm.Cron.AddFunc(dm.BackupCleanCron, func() {
			errBackup := dm.BackupClean(false)
			if errBackup != nil {
				log.Errorf("定时清理备份失败: %v", errBackup)
			}
		})
		if err != nil {
			log.Errorf("设定的备份清理cron有误: %q %v", dm.BackupCleanCron, err)
			return
		}
	}
}

func (dm *DiceManager) TryCreateDefault() {
	if dm.ServeAddress == "" {
		dm.ServeAddress = "0.0.0.0:3211"
	}

	dm.diceLock.Lock()
	defer dm.diceLock.Unlock()
	if len(dm.Dice) == 0 {
		defaultDice := new(Dice)
		defaultDice.BaseConfig.Name = "default"
		defaultDice.Config.MessageDelayRangeStart = DefaultConfig.MessageDelayRangeStart
		defaultDice.Config.MessageDelayRangeEnd = DefaultConfig.MessageDelayRangeEnd
		defaultDice.MarkModified()
		defaultDice.ContainerMode = dm.ContainerMode
		dm.Dice = append(dm.Dice, defaultDice)
	}
}

func (dm *DiceManager) LoadNames() {
	dm.IsNamesReloading = true
	ng := &NamesGenerator{}
	ng.Load()
	dm.NamesGenerator = ng
	dm.NamesInfo = ng.NamesInfo
	dm.IsNamesReloading = false
}

func (dm *DiceManager) LoadNamesAsync() {
	dm.namesLoadWG.Add(1)
	go func() {
		defer dm.namesLoadWG.Done()
		logger.M().Info("随机名字资源开始异步加载")
		dm.LoadNames()
		logger.M().Info("随机名字资源异步加载完成")
	}()
}

func (dm *DiceManager) WaitNamesLoaded() {
	dm.namesLoadWG.Wait()
}

func (dm *DiceManager) TryGetGroupName(id string) string {
	item, exists := dm.GroupNameCache.Load(id)
	if exists {
		return item.Name
	}
	return "%未知群名%"
}

// ShouldRefreshGroupInfo 检查是否应该刷新群信息，内置30秒CD
// 返回 true 表示可以刷新（不在CD中），false 表示在CD中应跳过
// 注意：返回 true 时会立即更新时间戳，防止并发调用重复触发刷新
func (dm *DiceManager) ShouldRefreshGroupInfo(id string) bool {
	dm.groupNameCacheMu.Lock()
	defer dm.groupNameCacheMu.Unlock()

	now := time.Now().Unix()
	item, exists := dm.GroupNameCache.Load(id)
	if exists && item != nil && now-item.time < 30 {
		return false // 30秒内不重复刷新
	}
	// 立即更新时间戳，防止并发重复刷新，同时保留已观测到的名称和人数。
	next := GroupNameCacheItem{time: now}
	if exists && item != nil {
		next = *item
		next.time = now
	}
	dm.GroupNameCache.Store(id, &next)
	return true
}

func (dm *DiceManager) TryGetUserName(id string) string {
	item, exists := dm.UserNameCache.Load(id)
	if exists {
		return item.Name
	}
	return "%未知用户%"
}
