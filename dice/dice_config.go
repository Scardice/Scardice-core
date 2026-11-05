package dice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/robfig/cron/v3"
	"golang.org/x/time/rate"
	"gopkg.in/yaml.v3"

	"Scardice-core/core/configstate"
	"Scardice-core/core/execution"
	"Scardice-core/dice/censor"
	"Scardice-core/eventstore"
	"Scardice-core/utils"
)

// ConfigVersion 当前设置版本
const (
	ConfigVersion     = 1
	ConfigVersionCode = 10300 // 旧的设置版本标记
)

type configViewSource struct {
	version    uint64
	dependency eventstore.DependencySnapshot
}

type Config struct {
	d             *Dice `yaml:"-"`
	source        configViewSource
	ConfigVersion int `json:"configVersion" yaml:"configVersion"` // 配置版本

	// 基础设置
	BaseConfig `yaml:",inline"`
	// 刷屏警告设置
	RateLimitConfig `yaml:",inline"`
	// 退出不活跃设置
	QuitInactiveConfig `yaml:",inline"`
	// 扩展设置
	ExtConfig `yaml:",inline"`
	// 黑名单设置
	BanConfig `yaml:",inline"`
	// js 设置
	JsConfig `yaml:",inline"`
	// 跑团日志设置
	StoryLogConfig `yaml:",inline"`
	// 邮件设置
	MailConfig `yaml:",inline"`
	// 新闻设置
	NewsConfig `yaml:",inline"`
	// 敏感词设置
	CensorConfig `yaml:",inline"`
	// 公骰设置
	PublicDiceConfig `yaml:",inline"`
	// 商店设置
	StoreConfig `yaml:",inline"`

	// 其它设置，包含由于被导出无法从 Dice 上迁移过来的配置项，为了在 DefaultConfig 上统一设置默认值增加此结构
	DirtyConfig `yaml:",inline"`
}

var (
	ErrConfigViewUnavailable = errors.New("dice: immutable config view is unavailable")
	ErrConfigViewChanged     = errors.New("dice: config projection changed while building read view")
)

// configReadView is the immutable, source-versioned runtime representation of
// configstate.State. A pointer is atomically replaced only after a committed
// state has been read from one dependency snapshot.
type configReadView struct {
	version    uint64
	dependency eventstore.DependencySnapshot
	state      configstate.State
	config     Config
	advanced   AdvancedConfig
}

func defaultAdvancedConfig() AdvancedConfig {
	return AdvancedConfig{CustomReplyCooldown: DefaultCustomReplyCooldown}
}

func cloneConfigStrings(values []string) []string {
	if values == nil {
		return nil
	}
	cloned := make([]string, len(values))
	copy(cloned, values)
	return cloned
}

func cloneExtDefaultSettings(settings []*ExtDefaultSettingItem) []*ExtDefaultSettingItem {
	if settings == nil {
		return nil
	}
	cloned := make([]*ExtDefaultSettingItem, len(settings))
	for index, setting := range settings {
		if setting == nil {
			continue
		}
		item := *setting
		if setting.DisabledCommand != nil {
			item.DisabledCommand = make(map[string]bool, len(setting.DisabledCommand))
			for command, disabled := range setting.DisabledCommand {
				item.DisabledCommand[command] = disabled
			}
		}
		cloned[index] = &item
	}
	return cloned
}

func cloneConfigViewValue(source Config, owner *Dice) Config {
	cloned := source
	cloned.d = owner
	if source.LastSavedTime != nil {
		lastSaved := *source.LastSavedTime
		cloned.LastSavedTime = &lastSaved
	}
	cloned.NoticeIDs = cloneConfigStrings(source.NoticeIDs)
	cloned.ExtDefaultSettings = cloneExtDefaultSettings(source.ExtDefaultSettings)
	cloned.JsRuntimeOptions = cloneJSRuntimeOptions(source.JsRuntimeOptions)
	cloned.JsRuntimeRoutes = cloneJSRuntimeRoutes(source.JsRuntimeRoutes)
	cloned.DisabledJsScripts = cloneDisabledJsScripts(source.DisabledJsScripts)
	cloned.EndpointIDs = cloneConfigStrings(source.EndpointIDs)
	if source.CensorThresholds != nil {
		cloned.CensorThresholds = make(map[censor.Level]int, len(source.CensorThresholds))
		for level, threshold := range source.CensorThresholds {
			cloned.CensorThresholds[level] = threshold
		}
	}
	if source.CensorHandlers != nil {
		cloned.CensorHandlers = make(map[censor.Level]uint8, len(source.CensorHandlers))
		for level, handler := range source.CensorHandlers {
			cloned.CensorHandlers[level] = handler
		}
	}
	if source.CensorScores != nil {
		cloned.CensorScores = make(map[censor.Level]int, len(source.CensorScores))
		for level, score := range source.CensorScores {
			cloned.CensorScores[level] = score
		}
	}
	cloned.BackendUrls = cloneConfigStrings(source.BackendUrls)
	cloned.DisabledBackendUrls = cloneConfigStrings(source.DisabledBackendUrls)
	cloned.DeckList = append([]*DeckInfo(nil), source.DeckList...)
	cloned.CommandPrefix = cloneConfigStrings(source.CommandPrefix)
	cloned.DiceMasters = cloneConfigStrings(source.DiceMasters)
	if source.BanList != nil {
		cloned.BanList = source.BanList.cloneReadView(owner)
	}
	return cloned
}

func newConfigReadView(owner *Dice, config Config, advanced AdvancedConfig, state configstate.State, dependency eventstore.DependencySnapshot) *configReadView {
	source := configViewSource{version: state.Version, dependency: dependency}
	config.source = source
	advanced.source = source
	if config.BanList != nil {
		config.BanList.source = source
	}
	return &configReadView{
		version:    state.Version,
		dependency: dependency,
		state:      state.Clone(),
		config:     cloneConfigViewValue(config, owner),
		advanced:   advanced,
	}
}

func newDefaultConfigReadView(owner *Dice) *configReadView {
	config := NewConfig(owner)
	if owner != nil {
		if owner.BaseConfig.Name != "" {
			config.BaseConfig.Name = owner.BaseConfig.Name
		}
		if owner.BaseConfig.DataDir != "" {
			config.DataDir = owner.BaseConfig.DataDir
		}
	}
	return newConfigReadView(owner, config, defaultAdvancedConfig(), configstate.State{}, eventstore.DependencySnapshot{})
}

// initializeDefaultConfigView publishes defaults once. Event-sourced startup
// replaces this view with a projection-derived one before admitting work.
func (d *Dice) initializeDefaultConfigView() {
	if d == nil || d.configView.Load() != nil {
		return
	}
	d.configView.CompareAndSwap(nil, newDefaultConfigReadView(d))
}

func (d *Dice) currentConfigView() *configReadView {
	if d == nil {
		return nil
	}
	view := d.configView.Load()
	if view == nil {
		d.initializeDefaultConfigView()
		view = d.configView.Load()
	}
	return view
}

// Config returns the atomically published immutable runtime config. Callers
// must never mutate the returned value or any referenced slice/map.
func (d *Dice) Config() *Config {
	view := d.currentConfigView()
	if view == nil {
		return nil
	}
	return &view.config
}

func (d *Dice) AdvancedConfig() AdvancedConfig {
	view := d.currentConfigView()
	if view == nil {
		return defaultAdvancedConfig()
	}
	return view.advanced
}

// CommandPrefixes and DiceMasterIDs return immutable slices owned by the
// current config view. Read-only hot paths may iterate them without allocation.
func (d *Dice) CommandPrefixes() []string {
	view := d.currentConfigView()
	if view == nil {
		return nil
	}
	return view.config.CommandPrefix
}

func (d *Dice) DiceMasterIDs() []string {
	view := d.currentConfigView()
	if view == nil {
		return nil
	}
	return view.config.DiceMasters
}

// ConfigEditSnapshot returns detached DTOs for API/config input processing.
func (d *Dice) ConfigEditSnapshot() (Config, AdvancedConfig) {
	view := d.currentConfigView()
	if view == nil {
		return NewConfig(d), defaultAdvancedConfig()
	}
	return cloneConfigViewValue(view.config, d), view.advanced
}

// ConfigStateSnapshot returns the source state carried by the same atomically
// published view as Config. It is detached and safe for API serialization.
func (d *Dice) ConfigStateSnapshot() configstate.State {
	view := d.currentConfigView()
	if view == nil {
		return configstate.State{}
	}
	return view.state.Clone()
}

func (d *Dice) configReadViewFromState(
	state configstate.State,
	dependency eventstore.DependencySnapshot,
	previous *configReadView,
) (*configReadView, error) {
	if d == nil {
		return nil, ErrConfigViewUnavailable
	}
	var view *configReadView
	if state.Version == 0 {
		view = newDefaultConfigReadView(d)
		view.dependency = dependency
		source := configViewSource{dependency: dependency}
		view.config.source = source
		view.advanced.source = source
		if view.config.BanList != nil {
			view.config.BanList.source = source
		}
	} else {
		config, advanced, err := d.legacyConfigViewFromState(state)
		if err != nil {
			return nil, err
		}
		if previous != nil && previous.config.BanList != nil && config.BanList != nil {
			config.BanList.runtime = previous.config.BanList.runtime
		}
		view = newConfigReadView(d, config, advanced, state, dependency)
	}
	return view, nil
}

func configReadViewsEqual(left, right *configReadView) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.version == right.version &&
		left.dependency == right.dependency &&
		reflect.DeepEqual(left.state, right.state)
}

func (d *Dice) readCurrentConfigView(ctx context.Context, previous *configReadView) (*configReadView, error) {
	reader, ok := d.DurableStore.(eventstore.ProjectionDependencyRepository)
	if !ok {
		return nil, fmt.Errorf("%w: projection dependency reader is unsupported", ErrConfigViewUnavailable)
	}
	stream := configstate.ConfigStream(d.BaseConfig.Name)
	snapshot, err := reader.ReadProjectionDependency(ctx, configstate.ConfigProjectionName, stream.AggregateID, stream)
	if err != nil {
		return nil, err
	}
	if !snapshot.Found {
		if snapshot.StreamVersion != 0 {
			return nil, fmt.Errorf("%w: config projection row is missing", ErrConfigViewChanged)
		}
		return d.configReadViewFromState(configstate.State{}, snapshot.Snapshot, previous)
	}
	var state configstate.State
	if err = json.Unmarshal(snapshot.Row.Payload, &state); err != nil {
		return nil, fmt.Errorf("dice: decode config projection: %w", err)
	}
	if err = configstate.ValidateState(state); err != nil {
		return nil, fmt.Errorf("dice: validate config projection: %w", err)
	}
	if state.DiceID != d.BaseConfig.Name || state.Version != snapshot.StreamVersion {
		return nil, ErrConfigViewChanged
	}
	return d.configReadViewFromState(state, snapshot.Snapshot, previous)
}

func (d *Dice) refreshConfigView(ctx context.Context) (*configReadView, error) {
	if d == nil || d.DurableStore == nil {
		return nil, ErrConfigViewUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		previous := d.configView.Load()
		candidate, err := d.readCurrentConfigView(ctx, previous)
		if err != nil {
			return nil, err
		}
		if d.configView.Load() != previous {
			continue
		}
		if configReadViewsEqual(previous, candidate) {
			return previous, nil
		}
		if d.configView.CompareAndSwap(previous, candidate) {
			return candidate, nil
		}
	}
}

// ReloadConfigView atomically publishes a projection-derived view. A slower
// reload can never overwrite a view published after its read began.
func (d *Dice) ReloadConfigView(ctx context.Context) error {
	_, err := d.refreshConfigView(ctx)
	return err
}

// ContributeConfigView refreshes stale generation/privacy epochs before Host
// runs, then registers the exact value and proof selected for this root.
func (d *Dice) ContributeConfigView(ctx context.Context, tx *execution.DomainTx) error {
	view, err := d.refreshConfigView(ctx)
	if err != nil {
		return err
	}
	_, _, err = d.configOwnerFromView(ctx, tx, view)
	return err
}

func NewConfig(d *Dice) Config {
	c := cloneConfigViewValue(DefaultConfig, d)

	// set other default
	c.BanList = &BanListInfo{Parent: c.d}
	c.BanList.Init()
	return c
}

func (c *Config) LoadYamlConfig(data []byte) error {
	err := yaml.Unmarshal(data, &c)
	if err != nil {
		return err
	}
	c.migrateOld2Version1()
	return nil
}

// migrateOld2Version1 旧格式设置项的迁移
func (c *Config) migrateOld2Version1() {
	if c.ConfigVersion != 0 {
		return
	}
	c.ConfigVersion = ConfigVersion

	c.CommandCompatibleMode = DefaultConfig.CommandCompatibleMode

	if c.MaxExecuteTime == 0 {
		c.MaxExecuteTime = DefaultConfig.MaxExecuteTime
	}

	if c.MaxCocCardGen == 0 {
		c.MaxCocCardGen = DefaultConfig.MaxCocCardGen
	}

	if c.PersonalReplenishRateStr == "" {
		c.PersonalReplenishRateStr = DefaultConfig.PersonalReplenishRateStr
		c.PersonalReplenishRate = DefaultConfig.PersonalReplenishRate
	} else {
		if parsed, errParse := utils.ParseRate(c.PersonalReplenishRateStr); errParse == nil {
			c.PersonalReplenishRate = parsed
		} else {
			c.d.Logger.Errorf("解析PersonalReplenishRate失败: %v", errParse)
			c.PersonalReplenishRateStr = DefaultConfig.PersonalReplenishRateStr
			c.PersonalReplenishRate = DefaultConfig.PersonalReplenishRate
		}
	}

	if c.PersonalBurst == 0 {
		c.PersonalBurst = DefaultConfig.PersonalBurst
	}

	if c.GroupReplenishRateStr == "" {
		c.GroupReplenishRateStr = DefaultConfig.GroupReplenishRateStr
		c.GroupReplenishRate = DefaultConfig.GroupReplenishRate
	} else {
		if parsed, errParse := utils.ParseRate(c.GroupReplenishRateStr); errParse == nil {
			c.GroupReplenishRate = parsed
		} else {
			c.d.Logger.Errorf("解析GroupReplenishRate失败: %v", errParse)
			c.GroupReplenishRateStr = DefaultConfig.GroupReplenishRateStr
			c.GroupReplenishRate = DefaultConfig.GroupReplenishRate
		}
	}

	if c.GroupBurst == 0 {
		c.GroupBurst = DefaultConfig.GroupBurst
	}

	if c.SpamSameCommandWindowSec <= 0 {
		c.SpamSameCommandWindowSec = DefaultConfig.SpamSameCommandWindowSec
	}

	if c.SpamRecoveryMultiplierMax <= 0 {
		c.SpamRecoveryMultiplierMax = DefaultConfig.SpamRecoveryMultiplierMax
	}

	if c.VersionCode != 0 && c.VersionCode < 10001 {
		c.AliveNoticeValue = DefaultConfig.AliveNoticeValue
	}

	if c.VersionCode != 0 && c.VersionCode < 10003 {
		c.LogSizeNoticeCount = DefaultConfig.LogSizeNoticeCount
		c.LogSizeNoticeEnable = DefaultConfig.LogSizeNoticeEnable
		c.CustomReplyConfigEnable = DefaultConfig.CustomReplyConfigEnable
	}

	if c.VersionCode != 0 && c.VersionCode < 10004 {
		c.AutoReloginEnable = DefaultConfig.AutoReloginEnable
	}
}

type BaseConfig struct {
	CommandCompatibleMode   bool       `json:"-"                       yaml:"commandCompatibleMode"`
	LastSavedTime           *time.Time `json:"-"                       yaml:"lastSavedTime"`
	NoticeIDs               []string   `json:"noticeIds"               yaml:"noticeIds"`               // 通知ID
	OnlyLogCommandInGroup   bool       `json:"onlyLogCommandInGroup"   yaml:"onlyLogCommandInGroup"`   // 日志中仅记录命令
	OnlyLogCommandInPrivate bool       `json:"onlyLogCommandInPrivate" yaml:"onlyLogCommandInPrivate"` // 日志中仅记录命令
	VersionCode             int        `json:"versionCode"             yaml:"versionCode"`             // 版本ID(配置文件)
	MessageDelayRangeStart  float64    `json:"messageDelayRangeStart"  yaml:"messageDelayRangeStart"`  // 指令延迟区间
	MessageDelayRangeEnd    float64    `json:"messageDelayRangeEnd"    yaml:"messageDelayRangeEnd"`
	WorkInQQChannel         bool       `json:"workInQQChannel"         yaml:"workInQQChannel"`
	QQChannelAutoOn         bool       `json:"QQChannelAutoOn"         yaml:"QQChannelAutoOn"`         // QQ频道中自动开启(默认不开)
	QQChannelLogMessage     bool       `json:"QQChannelLogMessage"     yaml:"QQChannelLogMessage"`     // QQ频道中记录消息(默认不开)
	QQEnablePoke            bool       `json:"QQEnablePoke"            yaml:"QQEnablePoke"`            // 启用戳一戳
	TextCmdTrustOnly        bool       `json:"textCmdTrustOnly"        yaml:"textCmdTrustOnly"`        // 只允许信任用户或master使用text指令
	IgnoreUnaddressedBotCmd bool       `json:"ignoreUnaddressedBotCmd" yaml:"ignoreUnaddressedBotCmd"` // 不响应群聊裸bot指令
	UILogLimit              int64      `json:"-"                       yaml:"UILogLimit"`
	FriendAddComment        string     `json:"friendAddComment"        yaml:"friendAddComment"` // 加好友验证信息
	CustomReplyConfigEnable bool       `json:"customReplyConfigEnable" yaml:"customReplyConfigEnable"`
	AutoReloginEnable       bool       `json:"autoReloginEnable"       yaml:"autoReloginEnable"`    // 启用自动重新登录
	RefuseGroupInvite       bool       `json:"refuseGroupInvite"       yaml:"refuseGroupInvite"`    // 拒绝加入新群
	UpgradeWindowID         string     `json:"-"                       yaml:"upgradeWindowId"`      // 执行升级指令的窗口
	UpgradeEndpointID       string     `json:"-"                       yaml:"upgradeEndpointId"`    // 执行升级指令的端点
	BotExtFreeSwitch        bool       `json:"botExtFreeSwitch"        yaml:"botExtFreeSwitch"`     // 允许任意人员开关: 否则邀请者、群主、管理员、master有权限
	BotExitWithoutAt        bool       `json:"botExitWithoutAt"        yaml:"botExitWithoutAt"`     // 不@骰娘即可执行退群指令
	TrustOnlyMode           bool       `json:"trustOnlyMode"           yaml:"trustOnlyMode"`        // 只有信任的用户/master可以拉群和使用
	AliveNoticeEnable       bool       `json:"aliveNoticeEnable"       yaml:"aliveNoticeEnable"`    // 定时通知
	AliveNoticeValue        string     `json:"aliveNoticeValue"        yaml:"aliveNoticeValue"`     // 定时通知间隔
	ReplyDebugMode          bool       `json:"replyDebugMode"          yaml:"replyDebugMode"`       // 回复调试
	PlayerNameWrapEnable    bool       `json:"playerNameWrapEnable"    yaml:"playerNameWrapEnable"` // 启用玩家名称外框
	DiceRandomMode          string     `json:"diceRandomMode"          yaml:"diceRandomMode"`       // 骰点随机模式

	VMVersionForReply      string `json:"VMVersionForReply"      yaml:"VMVersionForReply"`      // 自定义回复使用的vm版本
	VMVersionForDeck       string `json:"VMVersionForDeck"       yaml:"VMVersionForDeck"`       // 牌堆使用的vm版本
	VMVersionForCustomText string `json:"VMVersionForCustomText" yaml:"VMVersionForCustomText"` // 自定义文案使用的vm版本
	VMVersionForMsg        string `json:"VMVersionForMsg"        yaml:"VMVersionForMsg"`        // 消息里使用的vm版本，也包括可能的一些边角类型的执行选择

	// TODO: 历史遗留问题，由于不输出DICE日志效果过差，已经抹除日志输出选项，剩余两个选项，私以为可以想办法也抹除掉。
	Name    string `yaml:"name"`    // 名称，默认为default
	DataDir string `yaml:"dataDir"` // 数据路径，为./data/{name}，例如data/default
}

type RateLimitConfig struct {
	RateLimitEnabled          bool       `json:"rateLimitEnabled"      yaml:"rateLimitEnabled"`              // 启用频率限制 (刷屏限制)
	PersonalReplenishRateStr  string     `json:"personalReplenishRate" yaml:"personalReplenishRate"`         // 个人刷屏警告速率，字符串格式
	PersonalReplenishRate     rate.Limit `json:"-"                     yaml:"-"`                             // 个人刷屏警告速率
	GroupReplenishRateStr     string     `json:"groupReplenishRate"    yaml:"groupReplenishRate"`            // 群组刷屏警告速率，字符串格式
	GroupReplenishRate        rate.Limit `json:"-"                     yaml:"-"`                             // 群组刷屏警告速率
	PersonalBurst             int64      `json:"personalBurst"         yaml:"personalBurst"`                 // 个人自定义上限
	GroupBurst                int64      `json:"groupBurst"            yaml:"groupBurst"`                    // 群组自定义上限
	SpamSameCommandWindowSec  int64      `json:"spamSameCommandWindowSec" yaml:"spamSameCommandWindowSec"`   // 连续相同指令判定窗口（秒）
	SpamRecoveryMultiplierMax int64      `json:"spamRecoveryMultiplierMax" yaml:"spamRecoveryMultiplierMax"` // 连续相同指令恢复倍率上限
}

type QuitInactiveConfig struct {
	QuitInactiveThreshold time.Duration `json:"-" yaml:"quitInactiveThreshold"` // 退出不活跃群组的时间阈值
	quitInactiveCronEntry cron.EntryID

	QuitInactiveThresholdDays float64 `json:"quitInactiveThreshold" yaml:"-"` // 为了和前端通信

	QuitInactiveNoticeSummaryMode bool `json:"quitInactiveNoticeSummaryMode" yaml:"quitInactiveNoticeSummaryMode"` // 自动退群通知改为任务开始/结束摘要

	QuitInactiveBatchSize int64 `json:"quitInactiveBatchSize" yaml:"quitInactiveBatchSize"` // 退出不活跃群组的批量大小
	QuitInactiveBatchWait int64 `json:"quitInactiveBatchWait" yaml:"quitInactiveBatchWait"` // 退出不活跃群组的批量等待时间（分）
}

type ExtConfig struct {
	DefaultCocRuleIndex int64 `jsbind:"defaultCocRuleIndex" json:"-" yaml:"defaultCocRuleIndex"`                   // 默认coc index
	MaxExecuteTime      int64 `jsbind:"maxExecuteTime"      json:"-" yaml:"maxExecuteTime"`                        // 最大骰点次数
	MaxCocCardGen       int64 `jsbind:"maxCocCardGen"       json:"-" yaml:"maxCocCardGen"`                         // 最大coc制卡数
	CocCardMergeForward bool  `jsbind:"cocCardMergeForward" json:"cocCardMergeForward" yaml:"cocCardMergeForward"` // COC制卡是否使用合并转发（默认关闭）

	ExtDefaultSettings []*ExtDefaultSettingItem `json:"extDefaultSettings" yaml:"extDefaultSettings"` // 新群扩展按此顺序加载
}

type BanConfig struct {
	BanList *BanListInfo `json:"-" yaml:"banList"`
}

type JSRuntimeOptions map[string]json.RawMessage

func (options *JSRuntimeOptions) UnmarshalYAML(node *yaml.Node) error {
	if node == nil || node.Tag == "!!null" {
		*options = nil
		return nil
	}
	values := map[string]any{}
	if err := node.Decode(&values); err != nil {
		return err
	}
	decoded := make(JSRuntimeOptions, len(values))
	for id, value := range values {
		payload, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("marshal runtime options %q: %w", id, err)
		}
		decoded[id] = payload
	}
	*options = decoded
	return nil
}

func (options JSRuntimeOptions) MarshalYAML() (any, error) {
	encoded := make(map[string]any, len(options))
	for id, payload := range options {
		if !json.Valid(payload) {
			return nil, fmt.Errorf("runtime options %q contain invalid JSON", id)
		}
		decoder := json.NewDecoder(bytes.NewReader(payload))
		decoder.UseNumber()
		var value any
		if err := decoder.Decode(&value); err != nil {
			return nil, fmt.Errorf("decode runtime options %q: %w", id, err)
		}
		converted, err := runtimeOptionsYAMLValue(value)
		if err != nil {
			return nil, fmt.Errorf("convert runtime options %q to YAML: %w", id, err)
		}
		encoded[id] = converted
	}
	return encoded, nil
}

func runtimeOptionsYAMLValue(value any) (any, error) {
	switch typed := value.(type) {
	case json.Number:
		text := typed.String()
		if strings.ContainsAny(text, ".eE") {
			return strconv.ParseFloat(text, 64)
		}
		if strings.HasPrefix(text, "-") {
			return strconv.ParseInt(text, 10, 64)
		}
		return strconv.ParseUint(text, 10, 64)
	case []any:
		for index, item := range typed {
			converted, err := runtimeOptionsYAMLValue(item)
			if err != nil {
				return nil, err
			}
			typed[index] = converted
		}
	case map[string]any:
		for key, item := range typed {
			converted, err := runtimeOptionsYAMLValue(item)
			if err != nil {
				return nil, err
			}
			typed[key] = converted
		}
	}
	return value, nil
}

type JsConfig struct {
	JsEnable                       bool              `json:"jsEnable"                         yaml:"jsEnable"`
	JsEngine                       string            `json:"jsEngine"                         yaml:"jsEngine"` // runtime provider ID；空值兼容旧配置
	JsRuntimeOptions               JSRuntimeOptions  `json:"jsRuntimeOptions,omitempty" yaml:"jsRuntimeOptions,omitempty"`
	JsRuntimeRoutes                map[string]string `json:"jsRuntimeRoutes,omitempty" yaml:"jsRuntimeRoutes,omitempty"`
	QuickJSMemoryLimitMiB          uint64            `json:"quickJSMemoryLimitMiB"            yaml:"quickJSMemoryLimitMiB"`
	QuickJSGCThresholdMiB          uint64            `json:"quickJSGCThresholdMiB"            yaml:"quickJSGCThresholdMiB"`
	QuickJSMaxStackSizeKiB         uint64            `json:"quickJSMaxStackSizeKiB"           yaml:"quickJSMaxStackSizeKiB"`
	QuickJSExecuteTimeoutSeconds   uint64            `json:"quickJSExecuteTimeoutSeconds"     yaml:"quickJSExecuteTimeoutSeconds"`
	QuickJSMaxFetchConcurrent      uint64            `json:"quickJSMaxFetchConcurrent"        yaml:"quickJSMaxFetchConcurrent"`
	QuickJSMaxFetchResponseMiB     uint64            `json:"quickJSMaxFetchResponseMiB"       yaml:"quickJSMaxFetchResponseMiB"`
	QuickJSMaxWebSocketConnections uint64            `json:"quickJSMaxWebSocketConnections"   yaml:"quickJSMaxWebSocketConnections"`
	QuickJSMaxWebSocketMessageMiB  uint64            `json:"quickJSMaxWebSocketMessageMiB"    yaml:"quickJSMaxWebSocketMessageMiB"`
	QuickJSMaxFilesystemReadMiB    uint64            `json:"quickJSMaxFilesystemReadMiB"      yaml:"quickJSMaxFilesystemReadMiB"`
	QuickJSMaxFilesystemWriteMiB   uint64            `json:"quickJSMaxFilesystemWriteMiB"     yaml:"quickJSMaxFilesystemWriteMiB"`
	QuickJSMaxPBKDF2Iterations     uint64            `json:"quickJSMaxPBKDF2Iterations"       yaml:"quickJSMaxPBKDF2Iterations"`
	QuickJSMaxPBKDF2OutputBytes    uint64            `json:"quickJSMaxPBKDF2OutputBytes"      yaml:"quickJSMaxPBKDF2OutputBytes"`
	DisabledJsScripts              map[string]bool   `json:"disabledJsScripts"                yaml:"disabledJsScripts"` // 作为set
}

func cloneJSRuntimeRoutes(routes map[string]string) map[string]string {
	if routes == nil {
		return nil
	}
	cloned := make(map[string]string, len(routes))
	for extensionID, runtimeID := range routes {
		cloned[extensionID] = runtimeID
	}
	return cloned
}

func cloneDisabledJsScripts(scripts map[string]bool) map[string]bool {
	if scripts == nil {
		return nil
	}
	cloned := make(map[string]bool, len(scripts))
	for name, disabled := range scripts {
		cloned[name] = disabled
	}
	return cloned
}

type StoryLogConfig struct {
	LogSizeNoticeEnable bool `json:"logSizeNoticeEnable" yaml:"logSizeNoticeEnable"` // 开启日志数量提示
	LogSizeNoticeCount  int  `json:"logSizeNoticeCount"  yaml:"LogSizeNoticeCount"`  // 日志数量提示阈值，默认500
}

type MailConfig struct {
	MailEnable   bool   `json:"mailEnable"   yaml:"mailEnable"`   // 是否启用
	MailFrom     string `json:"mailFrom"     yaml:"mailFrom"`     // 邮箱来源
	MailPassword string `json:"mailPassword" yaml:"mailPassword"` // 邮箱密钥/密码
	MailSMTP     string `json:"mailSmtp"     yaml:"mailSmtp"`     // 邮箱 smtp 地址
}

type NewsConfig struct {
	NewsMark string `json:"newsMark" yaml:"newsMark"` // 已读新闻的md5
}

type PublicDiceConfig struct {
	Enable      bool     `json:"publicDiceEnable" yaml:"publicDiceEnable"`
	ID          string   `json:"publicDiceId"     yaml:"publicDiceId"`
	Name        string   `json:"publicDiceName"   yaml:"publicDiceName"`
	Brief       string   `json:"publicDiceBrief"  yaml:"publicDiceBrief"`
	Note        string   `json:"publicDiceNote"   yaml:"publicDiceNote"`
	Avatar      string   `json:"publicDiceAvatar" yaml:"publicDiceAvatar"`
	EndpointIDs []string `json:"publicDiceEndpointIds,omitempty" yaml:"publicDiceEndpointIds,omitempty"`
}

type CensorConfig struct {
	EnableCensor         bool                   `json:"enableCensor"         yaml:"enableCensor"` // 启用敏感词审查
	CensorMode           CensorMode             `json:"censorMode"           yaml:"censorMode"`
	CensorThresholds     map[censor.Level]int   `json:"censorThresholds"     yaml:"censorThresholds"` // 敏感词阈值
	CensorHandlers       map[censor.Level]uint8 `json:"censorHandlers"       yaml:"censorHandlers"`
	CensorScores         map[censor.Level]int   `json:"censorScores"         yaml:"censorScores"`         // 敏感词怒气值
	CensorCaseSensitive  bool                   `json:"censorCaseSensitive"  yaml:"censorCaseSensitive"`  // 敏感词大小写敏感
	CensorMatchPinyin    bool                   `json:"censorMatchPinyin"    yaml:"censorMatchPinyin"`    // 敏感词匹配拼音
	CensorFilterRegexStr string                 `json:"censorFilterRegexStr" yaml:"censorFilterRegexStr"` // 敏感词过滤字符正则
}

type DirtyConfig struct {
	DeckList      []*DeckInfo `yaml:"-"` // 牌堆信息
	CommandPrefix []string    `yaml:"-"` // 指令前导
	DiceMasters   []string    `yaml:"-"` // 骰主设置，需要格式: 平台:帐号
}

type StoreConfig struct {
	BackendUrls         []string `json:"backendUrls" yaml:"backendUrls"`
	DisabledBackendUrls []string `json:"disabledBackendUrls" yaml:"disabledBackendUrls"`
}
