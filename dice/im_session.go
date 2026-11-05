package dice

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	randv2 "math/rand/v2"
	"regexp"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"go.uber.org/zap"

	"Scardice-core/adapterapi"
	"Scardice-core/core/groupstate"
	"Scardice-core/dice/events"
	"Scardice-core/dice/service"
	"Scardice-core/eventstore"
	"Scardice-core/logger"
	"Scardice-core/message"
	"Scardice-core/model"
	"Scardice-core/utils/jsengine"
	gojaengine "Scardice-core/utils/jsengine/goja"

	"github.com/golang-module/carbon"
	ds "github.com/sealdice/dicescript"
	rand2 "golang.org/x/exp/rand" //nolint:staticcheck // against my better judgment, but this was mandated due to a strongly held opinion from you know who

	"github.com/dop251/goja"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

type SenderBase struct {
	Nickname  string `jsbind:"nickname" json:"nickname"`
	UserID    string `jsbind:"userId"   json:"userId"`
	IsRobot   bool   `jsbind:"isRobot"  json:"isRobot"`
	GroupRole string `json:"-"` // 群内角色 admin管理员 owner群主
}

const jsSolveAwaitTimeout = 10 * time.Second
const jsSolveEmptyResultGraceWindow = 150 * time.Millisecond

var errJSSolveEmptyResult = errors.New("solve returned empty result")
var errJSSolveTimeout = errors.New("timeout")

// Message 消息的重要信息
// 时间
// 发送地点(群聊/私聊)
// 人物(是谁发的)
// 内容
type Message struct {
	Time        int64       `jsbind:"time"        json:"time"`        // 发送时间
	MessageType string      `jsbind:"messageType" json:"messageType"` // group private
	GroupID     string      `jsbind:"groupId"     json:"groupId"`     // 群号，如果是群聊消息
	GuildID     string      `jsbind:"guildId"     json:"guildId"`     // 服务器群组号，会在discord,kook,dodo等平台见到
	ChannelID   string      `jsbind:"channelId"   json:"channelId"`
	Sender      SenderBase  `jsbind:"sender"      json:"sender"`   // 发送者
	Message     string      `jsbind:"message"     json:"message"`  // 消息内容
	RawID       interface{} `jsbind:"rawId"       json:"rawId"`    // 原始信息ID，用于处理撤回等
	Platform    string      `jsbind:"platform"    json:"platform"` // 当前平台
	GroupName   string      `json:"groupName"`
	TmpUID      string      `json:"-"             yaml:"-"`
	// TestUIOutputSplitLength applies only to responses from the UI command tester.
	TestUIOutputSplitLength    int  `json:"-" yaml:"-"`
	TestUIOutputSplitLengthSet bool `json:"-" yaml:"-"`
	recovered                  bool
	Seq                        int64 `jsbind:"seq"         json:"seq"` // 平台消息序号，0=不可用/不支持
	// Note(Szzrain): 这里是消息段，为了支持多种消息类型，目前只有 Milky 支持，其他平台也应该尽快迁移支持，并使用 Session.ExecuteNew 方法
	Segment []message.IMessageElement `jsbind:"segment" json:"-" yaml:"-"`
}

type EndpointState int

type EndPointInfoBase struct {
	ID                  string        `jsbind:"id"                  json:"id"                  yaml:"id"` // uuid
	Nickname            string        `jsbind:"nickname"            json:"nickname"            yaml:"nickname"`
	State               EndpointState `jsbind:"state"               json:"state"               yaml:"state"` // 状态 0断开 1已连接 2连接中 3连接失败
	UserID              string        `jsbind:"userId"              json:"userId"              yaml:"userId"`
	GroupNum            int64         `jsbind:"groupNum"            json:"groupNum"            yaml:"groupNum"`            // 拥有群数
	CmdExecutedNum      int64         `jsbind:"cmdExecutedNum"      json:"cmdExecutedNum"      yaml:"cmdExecutedNum"`      // 指令执行次数
	CmdExecutedLastTime int64         `jsbind:"cmdExecutedLastTime" json:"cmdExecutedLastTime" yaml:"cmdExecutedLastTime"` // 指令执行次数
	OnlineTotalTime     int64         `jsbind:"onlineTotalTime"     json:"onlineTotalTime"     yaml:"onlineTotalTime"`     // 在线时长

	Platform     string `jsbind:"platform"   json:"platform"     yaml:"platform"` // 平台，如QQ等
	RelWorkDir   string `json:"relWorkDir"   yaml:"relWorkDir"`                   // 工作目录
	Enable       bool   `jsbind:"enable"     json:"enable"       yaml:"enable"`   // 是否启用
	ProtocolType string `json:"protocolType" yaml:"protocolType"`                 // 协议类型，如onebot、koishi等

	IsPublic bool       `json:"isPublic" yaml:"isPublic"`
	Session  *IMSession `json:"-"        yaml:"-"`
}

const (
	StateDisconnected     EndpointState = iota // 0: 断开
	StateConnected                             // 1: 已连接
	StateConnecting                            // 2: 连接中
	StateConnectionFailed                      // 3: 连接失败
)

type EndPointInfo struct {
	EndPointInfoBase `jsbind:"baseInfo" yaml:"baseInfo"`

	Adapter PlatformAdapter `json:"adapter" yaml:"adapter"`
}

func (ep *EndPointInfo) UnmarshalYAML(value *yaml.Node) error {
	if ep.Adapter != nil {
		return value.Decode(ep)
	}

	var val struct {
		EndPointInfoBase `yaml:"baseInfo"`
	}
	err := value.Decode(&val)
	if err != nil {
		return err
	}
	ep.EndPointInfoBase = val.EndPointInfoBase

	return err
}

// StatsRestore 尝试从数据库中恢复EP的统计数据
func (ep *EndPointInfo) StatsRestore(d *Dice) {
	if len(ep.UserID) == 0 {
		return // 尚未连接完成的新账号没有UserId, 跳过
	}

	m := model.EndpointInfo{UserID: ep.UserID}
	err := service.Query(d.DBOperator, &m)
	if err != nil {
		d.Logger.Errorf("恢复endpoint统计数据失败 %v : %v", ep.UserID, err)
		return
	}

	if m.UpdatedAt <= ep.CmdExecutedLastTime {
		// 只在数据库中保存的数据比当前数据新时才替换, 避免上次Dump之后新的指令统计被覆盖
		return
	}

	// 虽然觉得不至于, 还是判断一下, 只进行增长方向的更新
	if ep.CmdExecutedNum < m.CmdNum {
		ep.CmdExecutedNum = m.CmdNum
	}
	if ep.CmdExecutedLastTime < m.CmdLastTime {
		ep.CmdExecutedLastTime = m.CmdLastTime
	}
	if ep.OnlineTotalTime < m.OnlineTime {
		ep.OnlineTotalTime = m.OnlineTime
	}
}

// StatsDump EP统计数据落库
func (ep *EndPointInfo) StatsDump(d *Dice) {
	if len(ep.UserID) == 0 {
		return // 尚未连接完成的新账号没有UserId, 跳过
	}

	m := model.EndpointInfo{UserID: ep.UserID, CmdNum: ep.CmdExecutedNum, CmdLastTime: ep.CmdExecutedLastTime, OnlineTime: ep.OnlineTotalTime}
	err := service.Save(d.DBOperator, &m)
	if err != nil {
		d.Logger.Errorf("保存endpoint数据到数据库失败 %v : %v", ep.UserID, err)
	}
}

type messageParserMode uint8

const (
	messageParserLegacy messageParserMode = iota
	messageParserSegments
)

type messageExecutionOptions struct {
	parser              messageParserMode
	runInSync           bool
	callbackTransaction *DurableCallbackTransaction
	callbackMetadata    eventstore.Metadata
}

type messageExecutionResult struct {
	command     *CmdArgs
	mentioned   bool
	intercepted bool
	unsupported bool
	context     *MsgContext
	err         error
}

type IMSession struct {
	Parent       *Dice                              `yaml:"-"`
	PendingQuits *SyncMap[string, *PendingQuitInfo] `json:"-" yaml:"-"`

	runtimeRegistryMu sync.Mutex
	runtimeRegistry   *GroupPlayerRuntimeRegistry

	// PureOnebotInboundExecutor is the durable ingress seam for provider-neutral
	// OneBot messages. It is intentionally absent by default for legacy sessions.
	PureOnebotInboundExecutor adapterapi.CorePort `yaml:"-"`

	groupMemberWelcomeMu   sync.Mutex
	lastGroupMemberWelcome *LastWelcomeInfo
}

// EndPointDisplaySnapshot 是托盘菜单所需的端点展示值快照。
// 它不包含适配器、会话、锁或通道，发布后不会随原端点对象继续变化。
type EndPointDisplaySnapshot struct {
	Nickname string
	UserID   string
	State    EndpointState
}

// EndPointsSnapshot 返回 endpoint projection 的展示值采样。
func (s *IMSession) EndPointsSnapshot() []EndPointDisplaySnapshot {
	endpoints := s.EndPointsReadOnly()
	display := make([]EndPointDisplaySnapshot, 0, len(endpoints))
	for _, endpoint := range endpoints {
		if endpoint == nil {
			continue
		}
		display = append(display, EndPointDisplaySnapshot{
			Nickname: endpoint.Nickname,
			UserID:   endpoint.UserID,
			State:    endpoint.State,
		})
	}
	return display
}

func (s *IMSession) ResolveLiveEndpoint(ep *EndPointInfo) (*EndPointInfo, error) {
	if ep == nil {
		return nil, errors.New("endpoint is nil")
	}
	if s == nil {
		return nil, errors.New("session is nil")
	}
	if ep.Session == s {
		return ep, nil
	}
	endpoints := s.EndPointsReadOnly()
	if ep.ID != "" {
		for _, current := range endpoints {
			if current != nil && current.ID == ep.ID {
				return current, nil
			}
		}
	}
	var matched *EndPointInfo
	for _, current := range endpoints {
		if current == nil {
			continue
		}
		if current.UserID != ep.UserID || current.Platform != ep.Platform || current.ProtocolType != ep.ProtocolType {
			continue
		}
		if matched != nil {
			return nil, fmt.Errorf("endpoint resolution ambiguous for userId=%s platform=%s protocolType=%s", ep.UserID, ep.Platform, ep.ProtocolType)
		}
		matched = current
	}
	if matched != nil {
		return matched, nil
	}

	if ep.Platform == "UI" && ep.Session == s {
		return ep, nil
	}

	return nil, fmt.Errorf("endpoint not found: id=%s userId=%s platform=%s protocolType=%s", ep.ID, ep.UserID, ep.Platform, ep.ProtocolType)
}

type PendingQuitInfo struct {
	Origin    string
	CreatedAt time.Time
	ExpireAt  time.Time
}

const (
	QuitOriginAutoInactive = "auto_inactive"
)

func makePendingQuitKey(groupID string, endpointID string) string {
	return groupID + "\x00" + endpointID
}

func (s *IMSession) MarkPendingQuit(groupID string, endpointID string, origin string, ttl time.Duration) {
	if s == nil {
		return
	}
	now := time.Now()
	s.PendingQuits.Store(makePendingQuitKey(groupID, endpointID), &PendingQuitInfo{
		Origin:    origin,
		CreatedAt: now,
		ExpireAt:  now.Add(ttl),
	})
}

func (s *IMSession) ConsumePendingQuit(groupID string, endpointID string) *PendingQuitInfo {
	if s == nil {
		return nil
	}
	info, ok := s.PendingQuits.LoadAndDelete(makePendingQuitKey(groupID, endpointID))
	if !ok || info == nil {
		return nil
	}
	if time.Now().After(info.ExpireAt) {
		return nil
	}
	return info
}

func (s *IMSession) pruneExpiredPendingQuits(now time.Time) {
	if s == nil || s.PendingQuits == nil {
		return
	}
	s.PendingQuits.Range(func(key string, info *PendingQuitInfo) bool {
		if info == nil || now.After(info.ExpireAt) {
			// A new registration may replace this key while Range is running.
			s.PendingQuits.m.CompareAndDelete(key, info)
		}
		return true
	})
}

type MsgContext struct {
	MessageType string
	Group       *GroupInfo       `jsbind:"group"`  // 当前群信息
	Player      *GroupPlayerInfo `jsbind:"player"` // 当前群的玩家数据

	IsCompatibilityTest bool // 是否为兼容性测试环境，用于跳过不必要的数据库查询

	EndPoint        *EndPointInfo `jsbind:"endPoint"` // 对应的Endpoint
	Session         *IMSession    // 对应的IMSession
	Dice            *Dice         // 对应的 Dice
	IsCurGroupBotOn bool          `jsbind:"isCurGroupBotOn"` // 在群内是否bot on

	IsPrivate            bool        `jsbind:"isPrivate"` // 是否私聊
	CommandID            int64       // 指令ID
	CurrentCommand       string      // 当前解析到的指令名(小写)
	CommandHideFlag      string      `jsbind:"commandHideFlag"` // 暗骰来源群号
	CommandInfo          interface{} // 命令信息
	PrivilegeLevel       int         `jsbind:"privilegeLevel"` // 权限等级 -30ban 40邀请者 50管理 60群主 70信任 100master
	GroupRoleLevel       int         // 群内权限 40邀请者 50管理 60群主 70信任 100master，相当于不考虑ban的权限等级
	DelegateText         string      `jsbind:"delegateText"`  // 代骰附加文本
	AliasPrefixText      string      `json:"aliasPrefixText"` // 快捷指令回复前缀文本
	uiTestSplitLength    int
	uiTestSplitLengthSet bool
	callbackTransaction  *DurableCallbackTransaction
	callbackMetadata     eventstore.Metadata
	facadeRegistryMu     sync.Mutex
	facadeRegistry       *invocationFacadeRegistry
	// executionContext bounds host-owned callbacks which do not have a durable
	// transaction, such as global adapter events.
	executionContext context.Context
	// outboundDelay defers every durable effect this context submits instead of
	// making the caller sleep inside a callback lease.
	outboundDelay  time.Duration
	skipLogArchive bool
	// Recovered replies retain their trigger's log position, not delivery time.
	logReplyTime   int64
	logReplySeq    int64
	CommandReplied bool `json:"-"` // 当前命令是否已通过统一回复路径发出消息

	commandRepliedMu  sync.RWMutex
	deckDepth         int                                         // 抽牌递归深度
	DeckPools         map[*DeckInfo]map[string]*ShuffleRandomPool // 不放回抽取的缓存
	diceExprOverwrite string                                      // 默认骰表达式覆盖
	SystemTemplate    *GameSystemTemplate
	Censored          bool // 已检查过敏感词
	SpamCheckedGroup  bool
	SpamCheckedPerson bool

	adapterEventUnattributed bool

	splitKeyMu           sync.RWMutex
	splitKey             string
	forwardStart         string
	forwardEnd           string
	vm                   *ds.Context
	randomMu             sync.Mutex // RNG caches may be used by retained JS methods during cleanup.
	_v1Rand              ds.DiceSource
	diceRandSrc          ds.DiceSource
	diceRollSource       ds.DiceSource
	diceRollRaw          ds.DiceSource
	diceRollGroup        *GroupInfo
	chooserRand          *randv2.Rand
	chooserSrc           ds.DiceSource
	executionReleaseOnce sync.Once
	executionReleased    atomic.Bool
	executionParent      *MsgContext
	jsExecutionMu        sync.Mutex
	executionErrMu       sync.Mutex
	executionErr         error
	jsExecution          *jsMessageExecution
	standaloneSendScope  bool
}

func (ctx *MsgContext) releaseExecutionState() {
	if ctx == nil {
		return
	}
	ctx.executionReleaseOnce.Do(func() {
		_ = ctx.stopJSExecution()
		ctx.executionReleased.Store(true)
		ctx.jsExecutionMu.Lock()
		ctx.executionContext = nil
		ctx.jsExecutionMu.Unlock()
		ctx.vm = nil
		ctx.CommandInfo = nil
		ctx.DeckPools = nil
		ctx.deckDepth = 0
		ctx.diceExprOverwrite = ""
		ctx.randomMu.Lock()
		ctx._v1Rand = nil
		ctx.diceRandSrc = nil
		ctx.diceRollSource = nil
		ctx.diceRollRaw = nil
		ctx.diceRollGroup = nil
		ctx.chooserRand = nil
		ctx.chooserSrc = nil
		ctx.randomMu.Unlock()
	})
}

func (ctx *MsgContext) setExecutionError(err error) {
	if err == nil {
		return
	}
	for current := ctx; current != nil; current = current.executionParent {
		current.executionErrMu.Lock()
		if current.executionErr == nil {
			current.executionErr = err
		}
		current.executionErrMu.Unlock()
	}
}

func (ctx *MsgContext) getExecutionError() error {
	if ctx == nil {
		return nil
	}
	ctx.executionErrMu.Lock()
	defer ctx.executionErrMu.Unlock()
	return ctx.executionErr
}

func (ctx *MsgContext) SetCommandReplied(replied bool) {
	if ctx == nil {
		return
	}
	ctx.commandRepliedMu.Lock()
	defer ctx.commandRepliedMu.Unlock()
	ctx.CommandReplied = replied
}

func (ctx *MsgContext) IsCommandReplied() bool {
	if ctx == nil {
		return false
	}
	ctx.commandRepliedMu.RLock()
	defer ctx.commandRepliedMu.RUnlock()
	return ctx.CommandReplied
}

func ensureMessageTextFromSegments(msg *Message) {
	if msg == nil || msg.Message != "" || len(msg.Segment) == 0 {
		return
	}
	msg.Message = message.ConvertMessageElementsToString(msg.Segment)
}

// logSafeName 去掉昵称里的控制字符与非法 UTF-8 字节，避免昵称携带换行等内容时
// 把日志拆成多行或破坏终端输出。
func logSafeName(name string) string {
	if name == "" {
		return name
	}
	clean := true
	for _, r := range name {
		if unicode.IsControl(r) || r == utf8.RuneError {
			clean = false
			break
		}
	}
	if clean {
		return name
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == utf8.RuneError {
			return -1
		}
		return r
	}, name)
}

func incomingMessageLogText(msg *Message) string {
	if msg == nil {
		return ""
	}
	var builder strings.Builder
	builder.WriteString(msg.Message)
	var appendNodes func([]message.ForwardNode, string)
	appendNodes = func(nodes []message.ForwardNode, indent string) {
		for index, node := range nodes {
			content := strings.TrimSpace(message.ConvertMessageElementsToString(node.Elements))
			_, _ = fmt.Fprintf(&builder, "\n%s[%d] <%s>(%s): %s", indent, index+1, node.SenderName, node.SenderID, content)
			for _, element := range node.Elements {
				if nested, ok := element.(*message.ForwardElement); ok && nested.Loaded {
					appendNodes(nested.Nodes, indent+"  ")
				}
			}
		}
	}
	for _, element := range msg.Segment {
		forward, ok := element.(*message.ForwardElement)
		if !ok {
			continue
		}
		if forward.Loaded {
			builder.WriteString("\n[合并转发解析]")
			appendNodes(forward.Nodes, "  ")
		} else if forward.LoadError != "" {
			_, _ = fmt.Fprintf(&builder, "\n[合并转发解析失败: %s]", forward.LoadError)
		}
	}
	return builder.String()
}

func normalizeIncomingMessageText(d *Dice, msg *Message, text string) {
	normalized := message.ImageRewrite(text, message.SealCodeToCqCode)
	msg.Message = normalized
	msg.Segment = message.ConvertStringMessage(
		normalized,
		message.WithLogger(d.Logger.Named("message-preprocess")),
	)
}

func isBotMentionedInSegments(msg *Message, botUserID string) bool {
	if msg == nil {
		return false
	}
	for _, elem := range msg.Segment {
		if e, ok := elem.(*message.AtElement); ok && msg.Platform+":"+e.Target == botUserID {
			return true
		}
	}
	return false
}

func (s *IMSession) runMessagePreprocessHooks(mctx *MsgContext, msg *Message) bool {
	if mctx == nil || msg == nil || mctx.Group == nil || !mctx.Group.IsActive(mctx) || mctx.PrivilegeLevel == -30 {
		return false
	}
	for _, wrapper := range mctx.Group.GetActivatedExtList(mctx.Dice) {
		ext := wrapper.GetRealExt()
		if ext == nil || !ext.HasOnMessagePreprocess() {
			continue
		}
		decision := wrapper.CallOnMessagePreprocess(mctx.Dice, mctx, msg)
		if mctx.abortAfterJSCallback() {
			return true
		}
		switch decision.action {
		case messagePreprocessRewrite:
			normalizeIncomingMessageText(mctx.Dice, msg, decision.message)
		case messagePreprocessIntercept:
			if decision.reason != "" {
				mctx.Dice.Logger.Infof("扩展<%s>在解析前拦截消息: %s", ext.Name, decision.reason)
			} else {
				mctx.Dice.Logger.Infof("扩展<%s>在解析前拦截消息", ext.Name)
			}
			return true
		case messagePreprocessNoop:
		}
	}
	return false
}

// fillPrivilege 填写MsgContext中的权限字段, 并返回填写的权限等级
//   - msg 使用其中的msg.Sender.GroupRole
//
// MsgContext.Dice需要指向一个有效的Dice对象
func (ctx *MsgContext) fillPrivilege(msg *Message) int {
	switch {
	case msg.Sender.GroupRole == "owner":
		ctx.PrivilegeLevel = 60 // 群主
	case ctx.IsPrivate || msg.Sender.GroupRole == "admin":
		ctx.PrivilegeLevel = 50 // 群管理
	case ctx.Group != nil && msg.Sender.UserID == ctx.Group.InviteUserID():
		ctx.PrivilegeLevel = 40 // 邀请者
	default: /* no-op */
	}

	ctx.GroupRoleLevel = ctx.PrivilegeLevel

	if ctx.Dice == nil || ctx.Player == nil {
		return ctx.PrivilegeLevel
	}
	// 加入黑名单相关权限
	if val, exists := ctx.Dice.Config().BanList.GetByID(ctx.Player.UserID()); exists {
		switch val.Rank {
		case BanRankBanned:
			ctx.PrivilegeLevel = -30
		case BanRankTrusted:
			ctx.PrivilegeLevel = 70
		default: /* no-op */
		}
	}

	groupID := ""
	if ctx.Group != nil {
		groupID = ctx.Group.GroupID()
	}
	// master 权限大于黑名单权限
	if ctx.Dice.MasterCheck(groupID, ctx.Player.UserID()) {
		ctx.PrivilegeLevel = 100
	}

	return ctx.PrivilegeLevel
}
func (s *IMSession) Execute(ep *EndPointInfo, msg *Message, runInSync bool) {
	s.executeIndependentMessage(ep, msg, messageExecutionOptions{parser: messageParserLegacy, runInSync: runInSync})
}

func (s *IMSession) ExecuteNew(ep *EndPointInfo, msg *Message) {
	s.executeIndependentMessage(ep, msg, messageExecutionOptions{parser: messageParserSegments, runInSync: false})
}

// executeIndependentMessage gives legacy direct callers an explicit root.
// Adapter callbacks already supply their root through executeMessage and must
// not enter here.
func (s *IMSession) executeIndependentMessage(ep *EndPointInfo, msg *Message, options messageExecutionOptions) {
	if s == nil || s.Parent == nil || ep == nil || msg == nil {
		return
	}
	if options.parser == messageParserSegments {
		ensureMessageTextFromSegments(msg)
	}
	executionMessage := msg
	if !options.runInSync {
		executionMessage = cloneMessageForPreprocess(msg)
	}
	d := s.Parent
	canonical, err := json.Marshal(struct {
		EndpointID string            `json:"endpointId"`
		Parser     messageParserMode `json:"parser"`
		Message    *Message          `json:"message"`
	}{EndpointID: ep.ID, Parser: options.parser, Message: executionMessage})
	if err != nil {
		d.Logger.Errorf("独立消息执行请求编码失败: %v", err)
		return
	}
	digest := sha256.Sum256(canonical)
	identity := d.DomainExecutionIdentity("direct-message", fmt.Sprintf("%s:%x", ep.ID, digest))
	runInCaller := options.runInSync
	run := func() {
		var result messageExecutionResult
		runErr := d.WithDomainExecution(context.Background(), identity, canonical, func(transaction *DurableCallbackTransaction) error {
			rootOptions := options
			rootOptions.callbackTransaction = transaction
			// A root cannot commit while command/hooks still mutate it.
			rootOptions.runInSync = true
			result = s.executeMessage(ep, executionMessage, rootOptions)
			return result.err
		})
		if result.context != nil {
			result.context.releaseExecutionState()
		}
		if runErr != nil {
			d.Logger.Errorf("独立消息执行失败: %v", runErr)
		}
	}
	if runInCaller {
		run()
		return
	}
	go run()
}

// executeMessage is the single internal message execution algorithm. Public
// wrappers only select parser and scheduling policy; all hook and dispatch
// decisions are made from this result.

func (s *IMSession) executeMessage(ep *EndPointInfo, msg *Message, options messageExecutionOptions) (result messageExecutionResult) {
	d := s.Parent
	config := d.Config()

	mctx := &MsgContext{}
	result.context = mctx
	// DurableCallbackHost still needs this context while finalizing the collected mutations.
	releaseOnReturn := options.callbackTransaction == nil
	defer func() {
		if releaseOnReturn {
			mctx.releaseExecutionState()
		}
	}()
	mctx.Dice = d
	mctx.MessageType = msg.MessageType
	mctx.IsPrivate = mctx.MessageType == "private"
	mctx.callbackTransaction = options.callbackTransaction
	mctx.callbackMetadata = options.callbackMetadata
	mctx.logReplySeq = msg.Seq
	if msg.recovered {
		mctx.logReplyTime = msg.Time
	}
	mctx.Session = s
	mctx.EndPoint = ep
	log := d.Logger
	if options.parser == messageParserSegments || msg.MessageType == "group" || msg.MessageType == "private" {
		ensureMessageTextFromSegments(msg)
	}
	if msg.MessageType != "group" && msg.MessageType != "private" {
		result.unsupported = true
		return result
	}

	if msg.MessageType == "group" || msg.MessageType == "private" { //nolint:nestif
		if msg.MessageType == "group" {
			groupInfo, err := mctx.ResolveGroup(mctx.domainContext(), msg.GroupID)
			if err != nil {
				result.err = err
				return result
			}
			newGroup := groupInfo.Version() == 0
			autoOn := true
			if msg.Platform == "QQ-CH" {
				autoOn = config.QQChannelAutoOn
			}
			if newGroup {
				groupInfo, err = ensureGroupActivation(mctx, msg.GroupID, autoOn)
			} else {
				err = groupInfo.SetDiceExists(ep.UserID, true)
			}
			if err != nil {
				result.err = err
				return result
			}
			if msg.GroupName != "" {
				if err = groupInfo.SetGroupName(msg.GroupName); err != nil {
					result.err = err
					return result
				}
			}
			if newGroup {
				groupName := msg.GroupName
				if options.parser == messageParserLegacy {
					dm := d.Parent
					groupName = dm.TryGetGroupName(groupInfo.GroupID())
					if dm.ShouldRefreshGroupInfo(msg.GroupID) {
						ep.GetGroupInfoAsync(msg.GroupID)
					}
				}
				txt := fmt.Sprintf("自动激活: 发现无记录群组%s(%s)，因为已是群成员，所以自动激活，开启状态: %t", groupName, groupInfo.GroupID(), autoOn)
				log.Info(txt)
				mctx.Notice(txt, NoticeTypeGroup)
				if options.parser == messageParserSegments && (msg.Platform == "QQ" || msg.Platform == "TG") {
					for _, wrapper := range groupInfo.GetActivatedExtList(mctx.Dice) {
						extension := wrapper.GetRealExt()
						if extension == nil {
							continue
						}
						extension.CallOnGroupJoined(mctx.Dice, mctx, msg)
						if mctx.abortAfterJSCallback() {
							result.intercepted = true
							return result
						}
					}
				}
			}
		}

		var err error
		mctx.Group, mctx.Player, err = GetPlayerInfoBySender(mctx, msg)
		if err != nil {
			result.err = err
			return result
		}
		mctx.IsCurGroupBotOn = msg.MessageType == "group" && mctx.Group.IsActive(mctx)
		if mctx.Group.System() != "" {
			mctx.SystemTemplate = mctx.Group.GetCharTemplate(d)
		}

		// 权限号设置
		_ = mctx.fillPrivilege(msg)

		if mctx.Group != nil && mctx.Group.IsActive(mctx) {
			if mctx.PrivilegeLevel != -30 {
				for _, wrapper := range mctx.Group.GetActivatedExtList(mctx.Dice) {
					ext := wrapper.GetRealExt()
					if ext == nil {
						continue
					}
					ext.CallOnMessageReceived(mctx.Dice, mctx, msg)
					if mctx.abortAfterJSCallback() {
						result.intercepted = true
						return result
					}
				}
			}
		}

		if s.runMessagePreprocessHooks(mctx, msg) {
			result.intercepted = true
			return result
		}
		if mctx.abortAfterJSCallback() {
			result.intercepted = true
			return result
		}

		// 消息预处理可能改写前缀或@，这里必须使用改写后的内容。
		maybeCommand := CommandCheckPrefix(msg.Message, d.CommandPrefixes(), msg.Platform)

		amIBeMentioned := false
		if options.parser == messageParserSegments {
			amIBeMentioned = isBotMentionedInSegments(msg, ep.UserID)
		} else {
			_, ats := AtParse(msg.Message, msg.Platform)
			tmpUID := ep.UserID
			if msg.TmpUID != "" {
				tmpUID = msg.TmpUID
			}
			for _, i := range ats {
				if i.UserID == tmpUID {
					amIBeMentioned = true
					break
				} else if strings.HasPrefix(i.UserID, "OpenQQ:") ||
					strings.HasPrefix(i.UserID, "OpenQQCH:") {
					uid := strings.TrimPrefix(tmpUID, "OpenQQ:")
					if i.UserID == "OpenQQ:"+uid || i.UserID == "OpenQQCH:"+uid {
						amIBeMentioned = true
						break
					}
				}
			}
		}
		if notReply := checkBan(mctx, msg); notReply {
			result.intercepted = true
			return result
		}

		var cmdArgs *CmdArgs
		if options.parser == messageParserSegments {
			cmdArgs = CommandParseNew(mctx, msg)
		} else {
			var cmdLst []string
			if maybeCommand {
				for k := range d.CmdMap {
					cmdLst = append(cmdLst, k)
				}
				if g := mctx.Group; g != nil {
					for _, wrapper := range g.GetActivatedExtList(d) {
						for k := range wrapper.GetCmdMap() {
							cmdLst = append(cmdLst, k)
						}
					}
				}
				sort.Sort(ByLength(cmdLst))
			}
			platformPrefix := msg.Platform
			cmdArgs = CommandParse(msg.Message, cmdLst, d.CommandPrefixes(), platformPrefix, false)
			if cmdArgs != nil {
				mctx.CommandID = getNextCommandID()
				tmpUID := ep.UserID
				if platformPrefix == "OpenQQCH" {
					uid := strings.TrimPrefix(ep.UserID, "OpenQQ:")
					tmpUID = "OpenQQCH:" + uid
				}
				if msg.TmpUID != "" {
					tmpUID = msg.TmpUID
				}
				cmdArgs.SetupAtInfo(tmpUID)
			}
		}
		result.command = cmdArgs
		result.mentioned = amIBeMentioned
		if cmdArgs != nil && options.parser == messageParserSegments {
			mctx.CommandID = getNextCommandID()
		}

		// 收到群 test(1111) 内 XX(222) 的消息: 好看 (1232611291)
		if msg.MessageType == "group" {
			if mctx.CommandID != 0 {
				// 关闭状态下，如果被@，且是第一个被@的，那么视为开启
				if !mctx.IsCurGroupBotOn && cmdArgs.AmIBeMentionedFirst {
					mctx.IsCurGroupBotOn = true
				}

				log.Infof("收到群(%s)内<%s>(%s)的指令: %s", msg.GroupID, logSafeName(msg.Sender.Nickname), msg.Sender.UserID, incomingMessageLogText(msg))
			} else {
				doLog := true
				if config.OnlyLogCommandInGroup {
					// 检查上级选项
					doLog = false
				}
				if doLog {
					// 检查QQ频道的独立选项
					if msg.Platform == "QQ-CH" && !config.QQChannelLogMessage {
						doLog = false
					}
				}
				if doLog {
					log.Infof("收到群(%s)内<%s>(%s)的消息: %s", msg.GroupID, logSafeName(msg.Sender.Nickname), msg.Sender.UserID, incomingMessageLogText(msg))
					// fmt.Printf("消息长度 %v 内容 %v \n", len(msg.Message), []byte(msg.Message))
				}
			}
		}
		if msg.MessageType == "private" {
			if mctx.CommandID != 0 {
				log.Infof("收到<%s>(%s)的私聊指令: %s", logSafeName(msg.Sender.Nickname), msg.Sender.UserID, incomingMessageLogText(msg))
			} else if !config.OnlyLogCommandInPrivate {
				log.Infof("收到<%s>(%s)的私聊消息: %s", logSafeName(msg.Sender.Nickname), msg.Sender.UserID, incomingMessageLogText(msg))
			}
		}

		// 敏感词拦截：全部输入
		if mctx.IsCurGroupBotOn && config.EnableCensor && config.CensorMode == AllInput {
			hit, words, needToTerminate, _ := d.CensorMsg(mctx, msg, msg.Message, "")
			if needToTerminate {
				result.intercepted = true
				return result
			}
			if hit {
				text := DiceFormatTmpl(mctx, "核心:拦截_完全拦截_收到的所有消息")
				if text != "" {
					ReplyToSender(mctx, msg, text)
				}
				if msg.MessageType == "group" {
					log.Infof(
						"拒绝处理命中敏感词「%s」的内容「%s」- 来自群(%s)内<%s>(%s)",
						strings.Join(words, "|"),
						msg.Message, msg.GroupID, msg.Sender.Nickname, msg.Sender.UserID,
					)
				} else {
					log.Infof(
						"拒绝处理命中敏感词「%s」的内容「%s」- 来自<%s>(%s)",
						strings.Join(words, "|"),
						msg.Message,
						msg.Sender.Nickname,
						msg.Sender.UserID,
					)
				}
				result.intercepted = true
				return result
			}
		}
		SetTempVars(mctx, msg.Sender.Nickname)

		if result.command != nil {
			// Hook filtering, censoring, and command execution are shared by
			// both public wrappers; only scheduling is selected by the wrapper.
			dispatch := func() { s.PreTriggerCommand(mctx, msg, result.command) }
			if options.runInSync {
				dispatch()
				if dispatchErr := mctx.getExecutionError(); dispatchErr != nil {
					result.err = dispatchErr
					return result
				}
			} else {
				releaseOnReturn = false
				go func() {
					defer mctx.releaseExecutionState()
					dispatch()
					if dispatchErr := mctx.getExecutionError(); dispatchErr != nil {
						log.Errorf("异步指令执行失败: %v", dispatchErr)
					}
				}()
			}
		} else {
			if mctx.PrivilegeLevel == -30 {
				// 黑名单用户
				return result
			}

			// 试图匹配自定义回复
			isSenderBot := false
			if mctx.MessageType == "group" {
				if mctx.Group != nil && mctx.Group.IsBot(msg.Sender.UserID, msg.Sender.IsRobot) {
					isSenderBot = true
				}
			}

			if !isSenderBot {
				if mctx.Group != nil && (mctx.Group.IsActive(mctx) || result.mentioned) {
					var asyncCallbacks []func()
					for _, wrapper := range mctx.Group.GetActivatedExtList(mctx.Dice) {
						ext := wrapper.GetRealExt()
						if ext == nil {
							continue
						}
						i := ext // 保留引用
						if i.HasOnNotCommandReceived() {
							notCommandReceiveCall := func() {
								i.CallOnNotCommandReceived(d, mctx, msg)
							}

							if options.runInSync {
								notCommandReceiveCall()
							} else {
								asyncCallbacks = append(asyncCallbacks, notCommandReceiveCall)
							}
						}
					}
					if len(asyncCallbacks) > 0 {
						releaseOnReturn = false
						dispatchMessageCallbacksAsync(mctx, asyncCallbacks)
					}
				}
			}
		}
	}
	return result
}

func dispatchMessageCallbacksAsync(ctx *MsgContext, callbacks []func()) {
	var remaining atomic.Int32
	remaining.Store(int32(len(callbacks)))
	for _, callback := range callbacks {
		go func() {
			defer func() {
				if remaining.Add(-1) == 0 {
					ctx.releaseExecutionState()
				}
			}()
			callback()
		}()
	}
}

func (s *IMSession) PreTriggerCommand(mctx *MsgContext, msg *Message, cmdArgs *CmdArgs) {
	d := s.Parent
	config := d.Config()
	ep := mctx.EndPoint
	log := d.Logger
	defer func() {
		if r := recover(); r != nil {
			//  + fmt.Sprintf("%s", r)
			log.Errorf("异常: %v 堆栈: %v", r, string(debug.Stack()))
			ReplyToSender(mctx, msg, DiceFormatTmpl(mctx, "核心:骰子执行异常"))
		}
	}()

	// 敏感词拦截：命令输入
	if (msg.MessageType == "private" || mctx.IsCurGroupBotOn) && config.EnableCensor && config.CensorMode == OnlyInputCommand {
		hit, words, needToTerminate, _ := d.CensorMsg(mctx, msg, msg.Message, "")
		if needToTerminate {
			return
		}
		if hit {
			text := DiceFormatTmpl(mctx, "核心:拦截_完全拦截_收到的指令")
			if text != "" {
				ReplyToSender(mctx, msg, text)
			}
			if msg.MessageType == "group" {
				log.Infof(
					"拒绝处理命中敏感词「%s」的指令「%s」- 来自群(%s)内<%s>(%s)",
					strings.Join(words, "|"),
					msg.Message,
					msg.GroupID,
					msg.Sender.Nickname,
					msg.Sender.UserID,
				)
			} else {
				log.Infof(
					"拒绝处理命中敏感词「%s」的指令「%s」- 来自<%s>(%s)",
					strings.Join(words, "|"),
					msg.Message,
					msg.Sender.Nickname,
					msg.Sender.UserID,
				)
			}
			return
		}
	}

	if cmdArgs != nil {
		mctx.CurrentCommand = strings.ToLower(strings.TrimSpace(cmdArgs.Command))
	}

	if cmdArgs.Command != "botlist" && !cmdArgs.AmIBeMentioned {
		myuid := ep.UserID
		// 屏蔽机器人发送的消息
		if mctx.MessageType == "group" {
			// fmt.Println("YYYYYYYYY", myuid, mctx.Group != nil)
			if mctx.Group.IsBot(msg.Sender.UserID, msg.Sender.IsRobot) {
				log.Infof("忽略指令(机器人): 来自群(%s)内<%s>(%s): %s", msg.GroupID, msg.Sender.Nickname, msg.Sender.UserID, msg.Message)
				return
			}
			// 当其他机器人被@，不回应
			for _, i := range cmdArgs.At {
				uid := i.UserID
				if uid == myuid {
					// 忽略自己
					continue
				}
				if mctx.Group.IsBot(uid, i.IsRobot) {
					return
				}
			}
		}
	}
	ep.TriggerCommand(mctx, msg, cmdArgs)
}

func (ep *EndPointInfo) TriggerCommand(mctx *MsgContext, msg *Message, cmdArgs *CmdArgs) bool {
	s := mctx.Session
	d := mctx.Dice
	log := d.Logger

	handled := false
	logIgnoredCommand := func(result commandSolveResult) {
		reasonText := formatCommandIgnoreReasonForInfo(result)
		log.Debugw("command ignored detail",
			"reason", result.IgnoreReason,
			"command", cmdArgs.Command,
			"disabledSources", result.DisabledSources,
			"unavailableSources", result.UnavailableSources,
			"inactiveSources", result.InactiveSources,
			"executeMatched", result.ExecuteMatched,
			"executeSolved", result.ExecuteSolved,
			"executeLocation", result.ExecuteLocation,
			"executeError", result.ExecuteError,
		)
		if msg.MessageType == "group" {
			log.Infof("忽略指令(%s): 来自群(%s)内<%s>(%s): %s", reasonText, msg.GroupID, msg.Sender.Nickname, msg.Sender.UserID, msg.Message)
		}

		if msg.MessageType == "private" {
			log.Infof("忽略指令(%s): 来自<%s>(%s)的私聊: %s", reasonText, msg.Sender.Nickname, msg.Sender.UserID, msg.Message)
		}
	}

	// 试图匹配自定义指令
	if mctx.Group != nil && mctx.Group.IsActive(mctx) {
		for _, wrapper := range commandExtensionOrder(mctx.Group, mctx.Dice) {
			ext := wrapper.GetRealExt()
			if ext == nil {
				continue
			}
			overridden := ext.CallOnCommandOverride(mctx.Dice, mctx, msg, cmdArgs)
			if mctx.abortAfterJSCallback() {
				return false
			}
			if overridden {
				handled = true
				break
			}
		}
	}

	var solveResult commandSolveResult
	if !handled {
		// 若自定义指令未匹配，匹配标准指令
		solveResult = s.commandSolve(mctx, msg, cmdArgs)
		if mctx.abortAfterJSCallback() {
			return false
		}
		switch solveResult.Status {
		case commandSolveSolved:
			handled = true
		case commandSolveConflict:
			handled = true
			ReplyToSender(mctx, msg, fmt.Sprintf("指令[%s]存在冲突，可用扩展有: %s。请禁用其中之一后重试。", cmdArgs.Command, strings.Join(solveResult.AvailableSources, ", ")))
			log.Infof("指令冲突: 群(%s) 指令[%s] 可用扩展: %s", msg.GroupID, cmdArgs.Command, strings.Join(solveResult.AvailableSources, ", "))
		case commandSolveBlocked:
			handled = true
			logIgnoredCommand(solveResult)
		case commandSolveFailed:
			handled = true
			log.Info(formatCommandFailureForInfo(cmdArgs.Command, solveResult))
		case commandSolveUnmatched:
		}
	}

	if handled {
		if solveResult.Status != commandSolveBlocked {
			// 刷屏检测已经迁移到 im_helpers.go，此处不再处理
			ep.CmdExecutedNum++
			ep.CmdExecutedLastTime = time.Now().Unix()
			if err := mctx.Player.SetLastCommandAt(ep.CmdExecutedLastTime); err != nil {
				mctx.setExecutionError(err)
				log.Errorf("记录玩家最后指令时间失败: %v", err)
			}
		}
	} else {
		logIgnoredCommand(solveResult)
	}
	return handled
}

// OnGroupJoined 群组进群事件处理，其他 Adapter 应当尽快迁移至此方法实现
func (s *IMSession) OnGroupJoined(ctx *MsgContext, msg *Message) {
	d := ctx.Dice
	log := d.Logger
	ep := ctx.EndPoint
	dm := d.Parent
	// 判断进群的人是自己，自动启动
	group, err := SetBotOnAtGroup(ctx, msg.GroupID)
	if err != nil {
		ctx.setExecutionError(err)
		log.Errorf("记录进群状态失败: %v", err)
		return
	}
	ctx.Group = group
	if err = group.SetInvitation(msg.Sender.UserID, time.Now().Unix()); err != nil {
		ctx.setExecutionError(err)
		log.Errorf("记录进群邀请信息失败: %v", err)
		return
	}
	// A durable callback stages the group info refresh itself and must not hold
	// its lease while waiting, so the legacy pauses become a delay on the
	// welcome effect.
	inCallback := ctx.callbackTransaction != nil
	if !inCallback && dm.ShouldRefreshGroupInfo(msg.GroupID) {
		ep.GetGroupInfoAsync(msg.GroupID)
	}
	if !inCallback {
		time.Sleep(2 * time.Second)
	}
	groupName := dm.TryGetGroupName(msg.GroupID)
	sendWelcome := func() {
		log.Infof("发送入群致辞，群: <%s>(%s)", groupName, msg.GroupID)
		text := DiceFormatTmpl(ctx, "核心:骰子进群")
		// forward() 的边界必须先由统一回复规划器解析；提前按 SPLIT
		// 切分会把起止边界拆到不同消息并泄漏 FORWARD-END 标记。
		ReplyGroup(ctx, msg, text)
	}
	if inCallback {
		ctx.setOutboundDelay(botJoinedWelcomeDelay)
		sendWelcome()
		ctx.setOutboundDelay(0)
	} else {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Errorf("入群致辞异常: %v 堆栈: %v", r, string(debug.Stack()))
				}
			}()

			// 稍作等待后发送入群致词
			time.Sleep(2 * time.Second)
			sendWelcome()
		}()
	}
	txt := fmt.Sprintf("加入群组: <%s>(%s)", groupName, msg.GroupID)
	log.Info(txt)
	ctx.Notice(txt, NoticeTypeGroup)
	for _, wrapper := range group.GetActivatedExtList(ctx.Dice) {
		ext := wrapper.GetRealExt()
		if ext == nil {
			continue
		}
		ext.CallOnGroupJoined(d, ctx, msg)
	}
}

func (s *IMSession) isDuplicateGroupMemberWelcome(msg *Message) bool {
	s.groupMemberWelcomeMu.Lock()
	defer s.groupMemberWelcomeMu.Unlock()

	last := s.lastGroupMemberWelcome
	isDuplicate := last != nil &&
		msg.GroupID == last.GroupID &&
		msg.Sender.UserID == last.UserID &&
		msg.Time == last.Time
	s.lastGroupMemberWelcome = &LastWelcomeInfo{
		GroupID: msg.GroupID,
		UserID:  msg.Sender.UserID,
		Time:    msg.Time,
	}
	return isDuplicate
}

// OnGroupMemberJoined 群成员进群事件处理，除了 bot 自己以外的群成员入群时调用。其他 Adapter 应当尽快迁移至此方法实现
func (s *IMSession) OnGroupMemberJoined(ctx *MsgContext, msg *Message) {
	log := s.Parent.Logger

	groupInfo, err := ctx.ResolveGroup(ctx.domainContext(), msg.GroupID)
	if err != nil {
		ctx.setExecutionError(err)
		log.Errorf("读取迎新群状态失败: %v", err)
		return
	}
	needWelcome := false
	reason := "group_not_loaded"
	if groupInfo.Version() != 0 {
		if groupInfo.ShowGroupWelcome() {
			needWelcome = true
			reason = "welcome_enabled"
		} else {
			reason = "welcome_disabled"
		}
	}
	if !needWelcome {
		log.Infof("检查是否需要迎新: need_welcome=%t reason=%s group_id=%s user_id=%s", needWelcome, reason, msg.GroupID, msg.Sender.UserID)
		return
	}

	// 进群的是别人，是否迎新？
	// 这里很诡异，当手机QQ客户端审批进群时，入群后会有一句默认发言
	// 此时会收到两次完全一样的某用户入群信息，导致发两次欢迎词
	if s.isDuplicateGroupMemberWelcome(msg) {
		log.Infof("检查是否需要迎新: need_welcome=false reason=duplicate_event group_id=%s user_id=%s", msg.GroupID, msg.Sender.UserID)
		return
	}

	log.Infof("检查是否需要迎新: need_welcome=true reason=%s group_id=%s user_id=%s", reason, msg.GroupID, msg.Sender.UserID)
	func() {
		defer func() {
			if r := recover(); r != nil {
				log.Errorf("迎新致辞异常: %v 堆栈: %v", r, string(debug.Stack()))
			}
		}()

		// Ensure context has group set for formatting and attrs access
		var resolveErr error
		ctx.Group, ctx.Player, resolveErr = GetPlayerInfoBySender(ctx, msg)
		if resolveErr != nil {
			ctx.setExecutionError(resolveErr)
			log.Errorf("解析迎新玩家失败: %v", resolveErr)
			return
		}
		uidRaw := UserIDExtract(msg.Sender.UserID)
		VarSetValueStr(ctx, "$t帐号ID_RAW", uidRaw)
		VarSetValueStr(ctx, "$t账号ID_RAW", uidRaw)
		stdID := msg.Sender.UserID
		VarSetValueStr(ctx, "$t帐号ID", stdID)
		VarSetValueStr(ctx, "$t账号ID", stdID)
		text := DiceFormat(ctx, groupInfo.GroupWelcomeMessage())
		log.Infof("发送迎新消息: group_id=%s user_id=%s text=%q", msg.GroupID, msg.Sender.UserID, text)
		for _, i := range ctx.SplitText(text) {
			doSleepQQ(ctx)
			ReplyGroup(ctx, msg, strings.TrimSpace(i))
		}
	}()
}

var platformRE = regexp.MustCompile(`^(.*)-Group:`)

// LongTimeQuitInactiveGroupReborn
// 完全抛弃当初不懂Go的时候的方案，改成如下方案：
// 每次尝试找到n个符合要求的群，然后启一个线程，将群统一干掉
// 这样子牺牲了可显示的总群数，但大大增强了稳定性，而且总群数的参考并无意义，因为已经在的群很可能突然活了而不符合判定
// 当前版本的问题：如果用户设置了很短的时间，那可能之前的群还没退完，就又退那部分的群，造成一些奇怪的问题，但应该概率不大 + 豹错会被捕获
func (s *IMSession) LongTimeQuitInactiveGroupReborn(threshold time.Time, groupsPerRound int) {
	d := s.Parent
	if d == nil || d.DurableStore == nil {
		return
	}
	config := d.Config()
	d.Logger.Infof("开始清理不活跃群聊. 判定线 %s, 本次退群数: %d", threshold.Format(time.RFC3339), groupsPerRound)
	type groupEndpointPair struct {
		group    groupstate.State
		endpoint *EndPointInfo
		last     time.Time
	}
	isEndpointReady := func(group groupstate.State, endpoint *EndPointInfo, platform, phase string) bool {
		if endpoint == nil {
			d.Logger.Debugf("自动退群已跳过: 找不到对应账号连接，暂时无法处理该群。phase=%s group=%s platform=%s", phase, group.GroupID, platform)
			return false
		}
		durableReady := d.OutboundBridge != nil
		legacyReady := endpoint.Adapter != nil && !isPureOnebotEndpoint(endpoint)
		if endpoint.Session == nil || (!durableReady && !legacyReady) {
			d.Logger.Debugf(
				"自动退群已跳过: 账号连接尚未准备完成，暂时无法处理该群。phase=%s group=%s platform=%s endpoint=%s adapter_nil=%t outbound_bridge_nil=%t session_nil=%t",
				phase, group.GroupID, platform, endpoint.UserID, endpoint.Adapter == nil, d.OutboundBridge == nil, endpoint.Session == nil,
			)
			return false
		}
		if endpoint.Platform != platform || !group.DiceIDExists[endpoint.UserID] {
			return false
		}
		return endpoint.Enable && endpoint.State == StateConnected
	}

	projected, err := groupstate.ListProjected(context.Background(), d.DurableStore, d.BaseConfig.Name)
	if err != nil {
		d.Logger.Errorf("读取自动退群投影失败: %v", err)
		return
	}
	selected := make([]groupEndpointPair, 0, groupsPerRound)
	for _, group := range projected {
		if group.Deleted || strings.HasPrefix(group.GroupID, "PG-") {
			continue
		}
		if config.BanList != nil {
			if info, ok := config.BanList.GetByID(group.GroupID); ok && info.Rank > BanRankNormal {
				continue
			}
		}
		match := platformRE.FindStringSubmatch(group.GroupID)
		if len(match) != 2 || match[1] != "QQ" {
			continue
		}
		lastUnix := int64(0)
		if resources := s.runtimeResources().Group(d.BaseConfig.Name, group.GroupID); resources != nil {
			lastUnix = resources.recentDiceSendTime.Load()
		}
		last := time.Unix(lastUnix, 0)
		if entered := time.Unix(group.EnteredAt, 0); entered.After(last) {
			last = entered
		}
		if last.Unix() <= 0 || !last.Before(threshold) {
			continue
		}
		for _, endpoint := range s.EndPointsReadOnly() {
			if !isEndpointReady(group, endpoint, "QQ", "select") {
				continue
			}
			selected = append(selected, groupEndpointPair{group: group, endpoint: endpoint, last: last})
			if len(selected) >= groupsPerRound {
				break
			}
		}
		if len(selected) >= groupsPerRound {
			break
		}
	}
	if len(selected) == 0 {
		return
	}

	summaryMode := config.QuitInactiveNoticeSummaryMode
	emitNotice := func(endpoint *EndPointInfo, identity, text string) {
		request, _ := json.Marshal(struct {
			EndpointID string `json:"endpointId"`
			Text       string `json:"text"`
		}{EndpointID: endpoint.ID, Text: text})
		if noticeErr := d.WithDomainExecution(context.Background(), identity, request, func(transaction *DurableCallbackTransaction) error {
			carrier := &MsgContext{EndPoint: endpoint, Session: s, Dice: d, callbackTransaction: transaction, executionContext: context.Background()}
			defer carrier.releaseExecutionState()
			carrier.Notice(text, NoticeTypeInactive)
			return transaction.Domain().Err()
		}); noticeErr != nil {
			d.Logger.Errorf("提交自动退群通知失败: %v", noticeErr)
		}
	}
	if summaryMode {
		emitNotice(selected[0].endpoint, "auto-inactive-group-quit:start:"+uuid.NewString(), fmt.Sprintf("自动退群任务开始：本轮预计处理 %d 个群。", len(selected)))
	}

	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				zap.S().Named(logger.LogKeyAdapter).Errorf("自动退群异常: %v 堆栈: %v", recovered, string(debug.Stack()))
			}
		}()
		processed, skipped, cancelled, quitStarted := 0, 0, 0, 0
		for index, pair := range selected {
			if !isEndpointReady(pair.group, pair.endpoint, "QQ", "send") {
				d.Logger.Infof("自动退群已跳过: 当前账号已离线或不可用，暂不对该群执行退群。group=%s endpoint=%s", pair.group.GroupID, pair.endpoint.UserID)
				skipped++
				continue
			}
			processed++
			hint := fmt.Sprintf("检测到群 %s 上次活动时间为 %s，尝试退出,当前为本轮第 %d 个", pair.group.GroupID, pair.last.Format(time.RFC3339), index+1)
			d.Logger.Info(hint)
			attemptID := uuid.NewString()
			request, _ := json.Marshal(struct {
				GroupID    string `json:"groupId"`
				EndpointID string `json:"endpointId"`
				AttemptID  string `json:"attemptId"`
			}{GroupID: pair.group.GroupID, EndpointID: pair.endpoint.ID, AttemptID: attemptID})
			s.MarkPendingQuit(pair.group.GroupID, pair.endpoint.UserID, QuitOriginAutoInactive, 5*time.Minute)
			runErr := d.WithDomainExecution(context.Background(), "auto-inactive-group-quit:"+attemptID, request, func(transaction *DurableCallbackTransaction) error {
				message := &Message{MessageType: "group", Sender: SenderBase{UserID: pair.endpoint.UserID}, GroupID: pair.group.GroupID}
				messageContext := &MsgContext{
					MessageType: "group", EndPoint: pair.endpoint, Session: s, Dice: d,
					callbackTransaction: transaction, executionContext: context.Background(),
				}
				defer messageContext.releaseExecutionState()
				var resolveErr error
				messageContext.Group, messageContext.Player, resolveErr = GetPlayerInfoBySender(messageContext, message)
				if resolveErr != nil {
					return resolveErr
				}
				if !messageContext.Group.DiceIDExists(pair.endpoint.UserID) {
					return errors.New("dice: auto-quit endpoint membership changed")
				}
				messageContext.CurrentCommand = "auto-inactive-group-quit:" + attemptID
				farewell := DiceFormatTmpl(messageContext, "核心:骰子自动退群告别语")
				ReplyGroupRaw(messageContext, &Message{GroupID: pair.group.GroupID}, farewell, "")
				if quitErr := QuitGroup(messageContext, pair.group.GroupID); quitErr != nil {
					return quitErr
				}
				if activationErr := messageContext.Group.SetActivation(pair.endpoint.UserID, false, false); activationErr != nil {
					return activationErr
				}
				if !summaryMode {
					messageContext.Notice(hint, NoticeTypeInactive)
				}
				return transaction.Domain().Err()
			})
			if runErr != nil {
				s.ConsumePendingQuit(pair.group.GroupID, pair.endpoint.UserID)
				d.Logger.Errorf("自动退群请求提交失败: group=%s endpoint=%s error=%v", pair.group.GroupID, pair.endpoint.UserID, runErr)
				cancelled++
				continue
			}
			quitStarted++
			randomSleep := time.Duration(randv2.IntN(3000)+8000) * time.Millisecond
			logger.M().Infof("退群等待，等待 %f 秒后继续", randomSleep.Seconds())
			time.Sleep(randomSleep)
		}
		if summaryMode {
			emitNotice(selected[0].endpoint, "auto-inactive-group-quit:finish:"+uuid.NewString(), fmt.Sprintf(
				"自动退群任务结束：候选 %d 个，开始处理 %d 个，已发起退群 %d 个，跳过 %d 个，取消 %d 个。",
				len(selected), processed, quitStarted, skipped, cancelled,
			))
		}
	}()
}

// FormatBlacklistReasons 格式化黑名单原因文本
func FormatBlacklistReasons(v *BanListInfoItem) string {
	var sb strings.Builder
	sb.WriteString("黑名单原因：")
	if v == nil {
		sb.WriteString("\n")
		sb.WriteString("原因未知，请联系开发者获取进一步信息")
		return sb.String()
	}
	for i, reason := range v.Reasons {
		sb.WriteString("\n")
		sb.WriteString(carbon.CreateFromTimestamp(v.Times[i]).ToDateTimeString())
		sb.WriteString("在「")
		sb.WriteString(v.Places[i])
		sb.WriteString("」，原因：")
		sb.WriteString(reason)
	}
	reasontext := sb.String()
	return reasontext
}

func checkBanBlacklistedUser(ctx *MsgContext, msg *Message, isWhiteGroup bool, banQuitGroup func()) bool {
	d := ctx.Dice
	config := d.Config()
	log := d.Logger
	groupLevel := ctx.GroupRoleLevel
	if (config.BanList.BanBehaviorQuitIfAdmin || config.BanList.BanBehaviorQuitIfAdminSilentIfNotAdmin) && msg.MessageType == "group" {
		// 黑名单用户 - 立即退出所在群
		banListInfoItem, _ := config.BanList.GetByID(msg.Sender.UserID)
		reasontext := FormatBlacklistReasons(banListInfoItem)
		groupID := msg.GroupID
		if groupLevel >= 40 {
			if isWhiteGroup {
				log.Infof("收到群(%s)内邀请者以上权限黑名单用户<%s>(%s)的消息，但在信任群所以不尝试退群", groupID, msg.Sender.Nickname, msg.Sender.UserID)
			} else {
				text := fmt.Sprintf("警告: <%s>(%s)是黑名单用户，将对骰主进行通知并退群。", msg.Sender.Nickname, msg.Sender.UserID)
				ReplyGroupRaw(ctx, &Message{GroupID: groupID}, text, "")

				noticeMsg := fmt.Sprintf("检测到群(%s)内黑名单用户<%s>(%s)，因是管理以上权限，执行通告后自动退群\n%s", groupID, msg.Sender.Nickname, msg.Sender.UserID, reasontext)
				log.Info(noticeMsg)
				ctx.Notice(noticeMsg, NoticeTypeBan)
				banQuitGroup()
			}
			return true
		}
		if isWhiteGroup {
			log.Infof("收到群(%s)内普通群员黑名单用户<%s>(%s)的消息，但在信任群所以不做其他操作", groupID, msg.Sender.Nickname, msg.Sender.UserID)
			return true
		}
		if config.BanList.BanBehaviorQuitIfAdmin {
			if !config.BanList.CanNotifyBlacklistedUser(groupID, msg.Sender.UserID, time.Now()) {
				return true
			}
			noticeMsg := fmt.Sprintf("检测到群(%s)内黑名单用户<%s>(%s)，因是普通群员，进行群内通告\n%s", groupID, msg.Sender.Nickname, msg.Sender.UserID, reasontext)
			log.Info(noticeMsg)

			text := fmt.Sprintf("警告: <%s>(%s)是黑名单用户，将对骰主进行通知。\n%s", msg.Sender.Nickname, msg.Sender.UserID, reasontext)
			ReplyGroupRaw(ctx, &Message{GroupID: groupID}, text, "")

			ctx.Notice(noticeMsg, NoticeTypeBan)
		} else {
			noticeMsg := fmt.Sprintf("检测到群(%s)内黑名单用户<%s>(%s)，因是普通群员，忽略黑名单用户信息，不做其他操作\n%s", groupID, msg.Sender.Nickname, msg.Sender.UserID, reasontext)
			log.Info(noticeMsg)
		}
		return true
	}
	if config.BanList.BanBehaviorQuitPlaceImmediately && msg.MessageType == "group" {
		// 黑名单用户 - 立即退出所在群
		groupID := msg.GroupID
		if isWhiteGroup {
			log.Infof("收到群(%s)内黑名单用户<%s>(%s)的消息，但在信任群所以不尝试退群", groupID, msg.Sender.Nickname, msg.Sender.UserID)
		} else {
			banQuitGroup()
		}
		return true
	}
	if config.BanList.BanBehaviorRefuseReply {
		// 黑名单用户 - 拒绝回复
		log.Infof("忽略黑名单用户信息: 来自群(%s)内<%s>(%s): %s", msg.GroupID, msg.Sender.Nickname, msg.Sender.UserID, msg.Message)
		return true
	}
	return false
}

// checkBan 黑名单拦截
func checkBan(ctx *MsgContext, msg *Message) (notReply bool) {
	d := ctx.Dice
	config := d.Config()
	log := d.Logger
	var isBanGroup, isWhiteGroup bool
	// log.Info("check ban ", msg.MessageType, " ", msg.GroupID, " ", ctx.PrivilegeLevel)
	if msg.MessageType == "group" {
		value, exists := config.BanList.GetByID(msg.GroupID)
		if exists {
			if value.Rank == BanRankBanned {
				isBanGroup = true
			}
			if value.Rank == BanRankTrusted {
				isWhiteGroup = true
			}
		}
	}

	banQuitGroup := func() {
		banListInfoItem, _ := config.BanList.GetByID(msg.Sender.UserID)
		reasontext := FormatBlacklistReasons(banListInfoItem)
		groupID := msg.GroupID
		noticeMsg := fmt.Sprintf("检测到群(%s)内黑名单用户<%s>(%s)，自动退群\n%s", groupID, msg.Sender.Nickname, msg.Sender.UserID, reasontext)
		log.Info(noticeMsg)

		text := fmt.Sprintf("因<%s>(%s)是黑名单用户，将自动退群。", msg.Sender.Nickname, msg.Sender.UserID)
		ReplyGroupRaw(ctx, &Message{GroupID: groupID}, text, "")

		ctx.Notice(noticeMsg, NoticeTypeBan)

		if d.OutboundBridge == nil && ctx.EndPoint != nil && ctx.EndPoint.Adapter != nil && !isPureOnebotEndpoint(ctx.EndPoint) {
			time.Sleep(time.Second)
		}
		if err := QuitGroup(ctx, groupID); err != nil {
			log.Errorf("黑名单用户触发退群请求提交失败: group=%s error=%v", groupID, err)
		}
	}

	if ctx.PrivilegeLevel == -30 {
		return checkBanBlacklistedUser(ctx, msg, isWhiteGroup, banQuitGroup)
	}
	if isBanGroup {
		if config.BanList.BanBehaviorQuitPlaceImmediately && !isWhiteGroup {
			notReply = true
			// 黑名单群 - 立即退出
			// 退群使用GroupID进行判断
			banListInfoItem, _ := config.BanList.GetByID(msg.GroupID)
			reasontext := FormatBlacklistReasons(banListInfoItem)
			groupID := msg.GroupID
			if isWhiteGroup {
				log.Infof("群(%s)处于黑名单中，但在信任群所以不尝试退群", groupID)
			} else {
				noticeMsg := fmt.Sprintf("群(%s)处于黑名单中，自动退群\n%s", groupID, reasontext)
				log.Info(noticeMsg)

				ReplyGroupRaw(ctx, &Message{GroupID: groupID}, "因本群处于黑名单中，将自动退群。", "")

				ctx.Notice(noticeMsg, NoticeTypeBan)

				if d.OutboundBridge == nil && ctx.EndPoint != nil && ctx.EndPoint.Adapter != nil && !isPureOnebotEndpoint(ctx.EndPoint) {
					time.Sleep(time.Second)
				}
				if err := QuitGroup(ctx, groupID); err != nil {
					log.Errorf("黑名单群触发退群请求提交失败: group=%s error=%v", groupID, err)
				}
			}
		} else if config.BanList.BanBehaviorRefuseReply {
			notReply = true
			// 黑名单群 - 拒绝回复
			log.Infof("忽略黑名单群消息: 来自群(%s)内<%s>(%s): %s", msg.GroupID, msg.Sender.Nickname, msg.Sender.UserID, msg.Message)
		}
	}
	return notReply
}

type commandSolveStatus int

const (
	commandSolveUnmatched commandSolveStatus = iota
	commandSolveSolved
	commandSolveConflict
	commandSolveBlocked
	commandSolveFailed
)

type commandIgnoreReason string

const (
	commandIgnoreReasonNone               commandIgnoreReason = ""
	commandIgnoreReasonUnknownCommand     commandIgnoreReason = "unknown_command"
	commandIgnoreReasonBotOff             commandIgnoreReason = "bot_off"
	commandIgnoreReasonExtensionInactive  commandIgnoreReason = "extension_inactive"
	commandIgnoreReasonCommandDisabled    commandIgnoreReason = "command_disabled"
	commandIgnoreReasonMentionOther       commandIgnoreReason = "mention_other"
	commandIgnoreReasonPrivateUnavailable commandIgnoreReason = "private_unavailable"
	commandIgnoreReasonNoAvailable        commandIgnoreReason = "no_available_candidate"
	commandIgnoreReasonCandidateDeclined  commandIgnoreReason = "candidate_declined"
)

type commandSolveCandidate struct {
	Ext  *ExtInfo
	Item *CmdItemInfo
}

type commandUnavailableSource struct {
	Reason commandIgnoreReason
	Source string
}

type commandSolveResult struct {
	Status             commandSolveStatus
	AvailableSources   []string
	DisabledSources    []string
	UnavailableSources []commandUnavailableSource
	InactiveSources    []string
	IgnoreReason       commandIgnoreReason
	ExecuteMatched     bool
	ExecuteSolved      bool
	ExecuteLocation    string
	ExecuteError       string
}

func normalizeRuleIdentity(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

func addRuleIdentity(set map[string]struct{}, raw string) {
	if set == nil {
		return
	}
	name := normalizeRuleIdentity(raw)
	if name == "" {
		return
	}
	set[name] = struct{}{}
}

func hasRuleIdentityIntersection(left map[string]struct{}, right map[string]struct{}) bool {
	if len(left) == 0 || len(right) == 0 {
		return false
	}
	for name := range left {
		if _, ok := right[name]; ok {
			return true
		}
	}
	return false
}

// collectTemplateSelfRuleIdentities 仅收集模板“本体”标识，不包含依赖标识。
// 这里我们认为 relatedExt 中除本模板自身外的项视为本体的依赖依赖，不参与本体识别。
func collectTemplateSelfRuleIdentities(system string, tmpl *GameSystemTemplate) map[string]struct{} {
	ids := make(map[string]struct{})
	if tmpl == nil {
		return ids
	}

	addRuleIdentity(ids, system)
	addRuleIdentity(ids, tmpl.Name)
	addRuleIdentity(ids, tmpl.FullName)

	keys := tmpl.Commands.Set.Keys
	if len(keys) == 0 {
		keys = tmpl.SetConfig.Keys
	}
	for _, key := range keys {
		addRuleIdentity(ids, key)
	}

	relatedExt := tmpl.Commands.Set.RelatedExt
	if len(relatedExt) == 0 {
		relatedExt = tmpl.SetConfig.RelatedExt
	}

	matchedSelfInRelated := 0
	for _, extName := range relatedExt {
		name := normalizeRuleIdentity(extName)
		if name == "" {
			continue
		}
		if _, ok := ids[name]; ok {
			matchedSelfInRelated++
		}
	}

	// 如果 relatedExt 只有一个项且未与已有本体标识对齐，仍视为本体标识。
	if matchedSelfInRelated == 0 && len(relatedExt) == 1 {
		addRuleIdentity(ids, relatedExt[0])
	}

	return ids
}

func collectCandidateRuleIdentities(candidate commandSolveCandidate) map[string]struct{} {
	ids := make(map[string]struct{})
	if candidate.Ext == nil {
		return ids
	}

	addRuleIdentity(ids, candidate.Ext.Name)
	for _, alias := range candidate.Ext.Aliases {
		addRuleIdentity(ids, alias)
	}
	addRuleIdentity(ids, candidate.Ext.TargetName)

	realExt := candidate.Ext.GetRealExt()
	if realExt != nil {
		addRuleIdentity(ids, realExt.Name)
		for _, alias := range realExt.Aliases {
			addRuleIdentity(ids, alias)
		}
	}
	return ids
}

func collectRuleExtNameSetBySystem(ctx *MsgContext) (map[string]struct{}, map[string]struct{}) {
	ruleExtNames := make(map[string]struct{})
	preferredRuleExtNames := make(map[string]struct{})
	if ctx == nil || ctx.Dice == nil || ctx.Dice.GameSystemMap == nil {
		return ruleExtNames, preferredRuleExtNames
	}

	currentSystem := ""
	if ctx.Group != nil {
		currentSystem = strings.TrimSpace(ctx.Group.System())
	}

	addSystemRuleIDs := func(system string, ids map[string]struct{}) {
		isCurrentSystem := currentSystem != "" && strings.EqualFold(currentSystem, system)
		for name := range ids {
			ruleExtNames[name] = struct{}{}
			if isCurrentSystem {
				preferredRuleExtNames[name] = struct{}{}
			}
		}
	}

	ctx.Dice.GameSystemMap.Range(func(system string, tmpl *GameSystemTemplate) bool {
		if tmpl == nil {
			return true
		}
		addSystemRuleIDs(system, collectTemplateSelfRuleIdentities(system, tmpl))
		return true
	})

	return ruleExtNames, preferredRuleExtNames
}

func selectRulePluginCandidateByGroupSystem(ctx *MsgContext, candidates []commandSolveCandidate) (commandSolveCandidate, bool) {
	var empty commandSolveCandidate
	if len(candidates) < 2 {
		return empty, false
	}

	ruleExtNames, preferredRuleExtNames := collectRuleExtNameSetBySystem(ctx)
	if len(ruleExtNames) == 0 || len(preferredRuleExtNames) == 0 {
		return empty, false
	}

	matchedCount := 0
	selected := empty
	for _, candidate := range candidates {
		if candidate.Ext == nil {
			return empty, false
		}

		candidateIDs := collectCandidateRuleIdentities(candidate)
		if !hasRuleIdentityIntersection(candidateIDs, ruleExtNames) {
			return empty, false
		}

		if hasRuleIdentityIntersection(candidateIDs, preferredRuleExtNames) {
			selected = candidate
			matchedCount++
		}
	}

	if matchedCount != 1 {
		return empty, false
	}
	return selected, true
}

// selectPreferredTierCandidate 在当前规则模板关联层级内择优（REFS #1769）。
// 仅当恰有一个候选属于该层级时选中，避免同层歧义被静默裁决。
func selectPreferredTierCandidate(ctx *MsgContext, candidates []commandSolveCandidate) (commandSolveCandidate, bool) {
	var empty commandSolveCandidate
	if ctx == nil || len(candidates) < 2 {
		return empty, false
	}

	preferred := commandPreferredExtNames(ctx.Group, ctx.Dice)
	if len(preferred) == 0 {
		return empty, false
	}

	matchedCount := 0
	selected := empty
	for _, candidate := range candidates {
		if candidate.Ext == nil {
			continue
		}
		if !hasRuleIdentityIntersection(collectCandidateRuleIdentities(candidate), preferred) {
			continue
		}
		selected = candidate
		matchedCount++
	}
	if matchedCount != 1 {
		return empty, false
	}
	return selected, true
}

func commandCandidateSourceName(candidate commandSolveCandidate) string {
	if candidate.Ext == nil {
		return "core"
	}
	return candidate.Ext.Name
}

func commandCandidateDisplayName(candidate commandSolveCandidate) string {
	source := commandCandidateSourceName(candidate)
	if source == "core" {
		source = "核心"
	}
	if candidate.Item == nil || candidate.Item.Name == "" {
		return source
	}
	return source + "." + candidate.Item.Name
}

func commandCandidateSourceLocation(candidate commandSolveCandidate) string {
	if candidate.Item != nil {
		if location := strings.TrimSpace(candidate.Item.SourceLocation); location != "" {
			return location
		}
	}
	ext := candidate.Ext
	if ext == nil {
		return ""
	}
	if realExt := ext.GetRealExt(); realExt != nil {
		ext = realExt
	}
	if ext.Source == nil {
		return ""
	}
	return formatSourceLocationForLog(ext.Source.Filename, 0, 0)
}

func commandIgnoreReasonPriority(reason commandIgnoreReason) int {
	switch reason {
	case commandIgnoreReasonBotOff:
		return 10
	case commandIgnoreReasonCommandDisabled:
		return 20
	case commandIgnoreReasonExtensionInactive:
		return 30
	case commandIgnoreReasonPrivateUnavailable:
		return 40
	case commandIgnoreReasonMentionOther:
		return 50
	case commandIgnoreReasonUnknownCommand:
		return 60
	case commandIgnoreReasonCandidateDeclined:
		return 65
	case commandIgnoreReasonNoAvailable:
		return 70
	default:
		return 100
	}
}

func selectCommandIgnoreReason(sources []commandUnavailableSource, inactiveSources []string, fallback commandIgnoreReason) commandIgnoreReason {
	selected := commandIgnoreReasonNone
	selectedPriority := commandIgnoreReasonPriority(commandIgnoreReasonNone)
	for _, source := range sources {
		if source.Reason == commandIgnoreReasonNone {
			continue
		}
		if priority := commandIgnoreReasonPriority(source.Reason); priority < selectedPriority {
			selected = source.Reason
			selectedPriority = priority
		}
	}
	if selected != commandIgnoreReasonNone {
		return selected
	}
	if len(inactiveSources) > 0 {
		return commandIgnoreReasonExtensionInactive
	}
	if fallback != commandIgnoreReasonNone {
		return fallback
	}
	return commandIgnoreReasonUnknownCommand
}

func commandUnavailableSourceNamesByReason(sources []commandUnavailableSource, reason commandIgnoreReason) []string {
	names := make([]string, 0, len(sources))
	seen := map[string]struct{}{}
	for _, source := range sources {
		if source.Reason != reason || source.Source == "" {
			continue
		}
		if _, ok := seen[source.Source]; ok {
			continue
		}
		seen[source.Source] = struct{}{}
		names = append(names, source.Source)
	}
	sort.Strings(names)
	return names
}

func formatCommandIgnoreReasonForInfo(result commandSolveResult) string {
	reason := result.IgnoreReason
	if reason == commandIgnoreReasonNone {
		reason = selectCommandIgnoreReason(result.UnavailableSources, result.InactiveSources, commandIgnoreReasonUnknownCommand)
	}

	switch reason {
	case commandIgnoreReasonBotOff:
		return "骰子未在当前群开启"
	case commandIgnoreReasonExtensionInactive:
		if len(result.InactiveSources) > 0 {
			sources := append([]string{}, result.InactiveSources...)
			sort.Strings(sources)
			return "相关扩展未开启: " + strings.Join(sources, ", ")
		}
		return "相关扩展未开启"
	case commandIgnoreReasonCommandDisabled:
		sources := commandUnavailableSourceNamesByReason(result.UnavailableSources, commandIgnoreReasonCommandDisabled)
		if len(sources) == 0 {
			sources = append([]string{}, result.DisabledSources...)
			sort.Strings(sources)
		}
		if len(sources) > 0 {
			return "扩展指令已禁用: " + strings.Join(sources, ", ")
		}
		return "扩展指令已禁用"
	case commandIgnoreReasonMentionOther:
		return "指令目标不是当前骰子"
	case commandIgnoreReasonPrivateUnavailable:
		return "该指令不能在私聊使用"
	case commandIgnoreReasonNoAvailable:
		return "指令当前不可用"
	case commandIgnoreReasonCandidateDeclined:
		return "指令已匹配但本次不响应"
	case commandIgnoreReasonUnknownCommand:
		return "指令不存在"
	default:
		return "指令当前不可用"
	}
}

func formatCommandFailureForInfo(command string, result commandSolveResult) string {
	base := fmt.Sprintf("指令[%s]执行失败 Match:%t Solved:%t", command, result.ExecuteMatched, result.ExecuteSolved)
	switch {
	case result.ExecuteLocation != "" && result.ExecuteError != "":
		return fmt.Sprintf("%s Location:%s\nError:%s", base, result.ExecuteLocation, result.ExecuteError)
	case result.ExecuteLocation != "":
		return fmt.Sprintf("%s Location:%s", base, result.ExecuteLocation)
	case result.ExecuteError != "":
		return fmt.Sprintf("%s Error:%s", base, result.ExecuteError)
	default:
		return base
	}
}

func extCommandExists(ext *ExtInfo, command string) bool {
	if ext == nil || command == "" {
		return false
	}
	for key, item := range ext.GetCmdMap() {
		if strings.EqualFold(key, command) {
			return true
		}
		if item != nil && strings.EqualFold(item.Name, command) {
			return true
		}
	}
	return false
}

func findActivatedExtensionCommandSources(ctx *MsgContext, command string) []string {
	if ctx == nil || ctx.Group == nil || ctx.Dice == nil {
		return nil
	}
	var sources []string
	for _, ext := range ctx.Group.GetActivatedExtList(ctx.Dice) {
		if extCommandExists(ext, command) {
			sources = append(sources, ext.Name)
		}
	}
	sort.Strings(sources)
	return sources
}

func findInactiveExtensionCommandSources(ctx *MsgContext, command string) []string {
	if ctx == nil || ctx.Group == nil || ctx.Dice == nil {
		return nil
	}
	active := map[string]struct{}{}
	for _, ext := range ctx.Group.GetActivatedExtList(ctx.Dice) {
		if ext != nil {
			active[ext.Name] = struct{}{}
		}
	}

	var sources []string
	for _, ext := range ctx.Dice.ExtList {
		if ext == nil {
			continue
		}
		if _, ok := active[ext.Name]; ok {
			continue
		}
		if extCommandExists(ext, command) {
			sources = append(sources, ext.Name)
		}
	}
	sort.Strings(sources)
	return sources
}

func formatJSSolveError(err error) error {
	if err == nil {
		return nil
	}
	var exception *goja.Exception
	if errors.As(err, &exception) && exception != nil {
		return errors.New(exception.Error())
	}
	return err
}

func formatJSSolveRecoveredError(recovered any) error {
	switch v := recovered.(type) {
	case *goja.Exception:
		return errors.New(v.Error())
	case error:
		return formatJSSolveError(v)
	default:
		return fmt.Errorf("panic: %v", recovered)
	}
}

func parseJSSolveEngineResult(ctx *MsgContext, solveName string, value jsengine.Value) (CmdExecuteResult, error) {
	if value == nil {
		// 兼容旧插件：很多 JS solve 只 reply，不显式返回结果。
		// 仅当本次命令已通过统一回复路径发过消息时，才把空返回视为成功，避免吞掉真实插件错误。
		if ctx != nil && ctx.IsCommandReplied() {
			logger.M().Debugf("JS solve 返回空结果，且已回复消息，按兼容模式处理: %s", solveName)
			return CmdExecuteResult{Matched: true, Solved: true}, nil
		}
		return CmdExecuteResult{}, errJSSolveEmptyResult
	}

	object := value.Object()
	if object == nil {
		_, err := value.ExportPrimitive()
		if errors.Is(err, jsengine.ErrNoPrimitiveValue) {
			if ctx != nil && ctx.IsCommandReplied() {
				logger.M().Debugf("JS solve 返回空结果，且已回复消息，按兼容模式处理: %s", solveName)
				return CmdExecuteResult{Matched: true, Solved: true}, nil
			}
			return CmdExecuteResult{}, errJSSolveEmptyResult
		}
		return CmdExecuteResult{}, errors.New("invalid solve result")
	}
	if !object.Has("matched") && !object.Has("solved") && !object.Has("showHelp") {
		return CmdExecuteResult{}, errors.New("invalid solve result: missing matched/solved/showHelp")
	}

	return CmdExecuteResult{
		Matched:  engineValueToBoolean(object.Get("matched")),
		Solved:   engineValueToBoolean(object.Get("solved")),
		ShowHelp: engineValueToBoolean(object.Get("showHelp")),
	}, nil
}

func engineValueToBoolean(value jsengine.Value) bool {
	return value != nil && value.ToBoolean()
}

func waitForCommandReply(ctx *MsgContext, timeout time.Duration) bool {
	if ctx == nil || timeout <= 0 {
		return false
	}
	if ctx.IsCommandReplied() {
		return true
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timer.C:
			return ctx.IsCommandReplied()
		case <-ticker.C:
			if ctx.IsCommandReplied() {
				return true
			}
		}
	}
}

func logJSSolveEmptyResultWarning(log *zap.SugaredLogger, candidate commandSolveCandidate, solveName string, ctx *MsgContext, msg *Message) {
	if log == nil || msg == nil {
		return
	}

	source := commandCandidateSourceName(candidate)
	commandName := solveName
	if candidate.Item != nil && candidate.Item.Name != "" {
		commandName = candidate.Item.Name
	}

	platform := ""
	messageType := msg.MessageType
	groupID := msg.GroupID
	senderID := msg.Sender.UserID
	commandReplied := false
	if ctx != nil {
		if ctx.EndPoint != nil {
			platform = ctx.EndPoint.Platform
		}
		commandReplied = ctx.IsCommandReplied()
	}

	log.Warnw("JS solve returned empty result after grace window; suppressed user-facing exception",
		"source", source,
		"command", commandName,
		"solveName", solveName,
		"commandReplied", commandReplied,
		"platform", platform,
		"messageType", messageType,
		"groupID", groupID,
		"senderID", senderID,
	)
}

func (s *IMSession) executeSolveRawValue(
	ctx *MsgContext,
	msg *Message,
	cmdArgs *CmdArgs,
	item *CmdItemInfo,
	plugin *ExtInfo,
	generation int64,
) (CmdExecuteResult, error) {
	var result CmdExecuteResult
	err := s.Parent.ExtLoopManager.dispatchJSCallback(jsCallbackRequest{
		Generation: generation,
		Realm:      jsContextForMessage(plugin, ctx),
		Kind:       jsCallbackCommand,
		ValueCallback: func(runtime jsengine.Runtime) (value jsengine.Value, callbackErr error) {
			defer func() {
				if recovered := recover(); recovered != nil {
					callbackErr = formatJSSolveRecoveredError(recovered)
				}
			}()
			if _, ok := gojaengine.Raw(runtime); !ok {
				return nil, errors.New("legacy Goja solve callback requires a Goja runtime")
			}
			raw := item.SolveRaw(ctx, msg, cmdArgs)
			return gojaengine.WrapValueForRuntime(runtime, raw)
		},
		ConsumeValue: func(value jsengine.Value) error {
			var parseErr error
			result, parseErr = parseJSSolveEngineResult(ctx, item.Name, value)
			return parseErr
		},
		Message: ctx,
	}, false)
	return result, err
}

func (s *IMSession) executeSolveEngine(ctx *MsgContext, msg *Message, cmdArgs *CmdArgs, item *CmdItemInfo, plugin *ExtInfo) (CmdExecuteResult, error) {
	if plugin != nil {
		plugin = plugin.GetRealExt()
	}
	if s.Parent.ExtLoopManager == nil {
		executeErr := errors.New("loop manager is nil")
		s.Parent.Logger.Errorf("扩展注册的指令<%s>运行环境不可用: %v", item.Name, executeErr)
		return CmdExecuteResult{Matched: true, Solved: false}, executeErr
	}

	generation := item.JSLoopVersion
	if item.SolveCallback != nil && plugin != nil && plugin.JSLoopVersion != 0 {
		// A public neutral solve callback belongs to the extension that installed
		// it. An ext.find copy can retain the source command's generation.
		generation = plugin.JSLoopVersion
	}
	loop, err := s.Parent.ExtLoopManager.GetLoop(generation)
	if err == nil && loop == nil {
		err = errors.New("JavaScript runtime is unavailable")
	}
	if err != nil {
		s.Parent.Logger.Errorf("扩展注册的指令<%s>运行环境已经过期: %v", item.Name, err)
		return CmdExecuteResult{Matched: true, Solved: false}, err
	}

	var result CmdExecuteResult
	callback := func(runtime jsengine.Runtime) (jsengine.Value, error) {
		if item.SolveEngine != nil {
			return item.SolveEngine(runtime, ctx, msg, cmdArgs)
		}
		return item.SolveCallback(ctx, msg, cmdArgs)
	}
	err = s.Parent.ExtLoopManager.dispatchJSCallback(jsCallbackRequest{
		Generation:    generation,
		Realm:         jsContextForMessage(plugin, ctx),
		Kind:          jsCallbackCommand,
		ValueCallback: callback,
		ConsumeValue: func(value jsengine.Value) error {
			var parseErr error
			result, parseErr = parseJSSolveEngineResult(ctx, item.Name, value)
			return parseErr
		},
		Message: ctx,
	}, false)
	if err == nil {
		return result, nil
	}
	if errors.Is(err, errJSSolveEmptyResult) && waitForCommandReply(ctx, jsSolveEmptyResultGraceWindow) {
		return CmdExecuteResult{Matched: true, Solved: true}, nil
	}
	ctx.recordJSExecutionError(err)

	ReplyToSender(ctx, msg, fmt.Sprintf("JS执行异常，请反馈给该扩展的作者：\n%v", err))
	return CmdExecuteResult{Matched: true, Solved: false}, err
}

func (s *IMSession) commandSolve(ctx *MsgContext, msg *Message, cmdArgs *CmdArgs) commandSolveResult {
	// 设置临时变量
	if ctx.Player != nil {
		SetTempVars(ctx, msg.Sender.Nickname)
		VarSetValueStr(ctx, "$tMsgID", fmt.Sprintf("%v", msg.RawID))
		VarSetValueInt64(ctx, "$t轮数", int64(cmdArgs.SpecialExecuteTimes))
	}

	checkCandidateAvailable := func(ext *ExtInfo, item *CmdItemInfo) (available bool, reason commandIgnoreReason) {
		if item == nil {
			return false, commandIgnoreReasonUnknownCommand
		}

		if item.Raw { //nolint:nestif
			if item.CheckCurrentBotOn {
				if !ctx.IsCurGroupBotOn && !ctx.IsPrivate {
					return false, commandIgnoreReasonBotOff
				}
			}

			if item.CheckMentionOthers {
				if cmdArgs.SomeoneBeMentionedButNotMe {
					return false, commandIgnoreReasonMentionOther
				}
			}
		} else { //nolint:gocritic
			// 默认模式行为：需要在当前群/私聊开启，或@自己时生效(需要为第一个@目标)
			if !ctx.IsCurGroupBotOn && !ctx.IsPrivate {
				return false, commandIgnoreReasonBotOff
			}
		}

		if ext != nil && ext.DefaultSetting != nil && ext.DefaultSetting.DisabledCommand[item.Name] {
			return false, commandIgnoreReasonCommandDisabled
		}

		if !item.Raw {
			if item.DisabledInPrivate && ctx.IsPrivate {
				ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:提示_私聊不可用"))
				return false, commandIgnoreReasonPrivateUnavailable
			}

			if !item.AllowDelegate && cmdArgs.SomeoneBeMentionedButNotMe {
				// 如果其他人被@了就不管
				// 注: 如果被@的对象在botlist列表，那么不会走到这一步
				return false, commandIgnoreReasonMentionOther
			}
		}

		return true, commandIgnoreReasonNone
	}

	var executeErr error
	executeCandidate := func(candidate commandSolveCandidate) CmdExecuteResult {
		item := candidate.Item
		if item == nil {
			return CmdExecuteResult{}
		}

		// Note(Szzrain): TODO: 意义不明，需要想办法干掉
		if item.EnableExecuteTimesParse {
			cmdArgs.RevokeExecuteTimesParse(ctx, msg)
		}

		if ctx.Player != nil {
			VarSetValueInt64(ctx, "$t轮数", int64(cmdArgs.SpecialExecuteTimes))
		}
		ctx.SetCommandReplied(false)

		if !item.Raw && item.AllowDelegate {
			// 允许代骰时，发一句话
			cur := -1
			for index, i := range cmdArgs.At {
				if i.UserID == ctx.EndPoint.UserID {
					continue
				} else if strings.HasPrefix(ctx.EndPoint.UserID, "OpenQQ:") {
					// 特殊处理 OpenQQ频道
					uid := strings.TrimPrefix(i.UserID, "OpenQQCH:")
					diceId := strings.TrimPrefix(ctx.EndPoint.UserID, "OpenQQ:")
					if uid == diceId {
						continue
					}
				}
				cur = index
			}

			if cur != -1 {
				if ctx.Dice.Config().PlayerNameWrapEnable {
					ctx.DelegateText = fmt.Sprintf("由<%s>代骰:\n", ctx.Player.Name())
				} else {
					ctx.DelegateText = fmt.Sprintf("由%s代骰:\n", ctx.Player.Name())
				}
			}
		}

		// 加载规则模板
		// TODO: 注意一下这里使用群模板还是个人卡模板，目前群模板，可有情况特殊？
		tmpl := ctx.SystemTemplate
		if tmpl != nil {
			ctx.Eval(tmpl.InitScript, nil)
			if tmpl.Name == "dnd5e" {
				// 这里面有buff机制的代码，所以需要加载
				ctx.setDndReadForVM(false)
			}
		}

		var executionPlugin *ExtInfo
		if candidate.Ext != nil {
			executionPlugin = candidate.Ext.GetRealExt()
		}

		var ret CmdExecuteResult
		// JS compatibility execution paths:
		// 1. Engine-neutral command callbacks (SolveEngine/SolveCallback).
		// 2. Native Goja JS commands (IsJsSolveFunc=true).
		// 3. Non-JS commands overwritten through the legacy Goja binding (SolveRaw).
		if item.SolveEngine != nil || item.SolveCallback != nil {
			ret, executeErr = s.executeSolveEngine(ctx, msg, cmdArgs, item, executionPlugin)
			if executeErr != nil {
				return ret
			}
		} else if item.IsJsSolveFunc || item.SolveRaw != nil {
			if s.Parent.ExtLoopManager == nil {
				executeErr = errors.New("loop manager is nil")
				s.Parent.Logger.Errorf("扩展注册的指令<%s>运行环境不可用: %v", item.Name, executeErr)
				return CmdExecuteResult{Matched: true, Solved: false}
			}

			generation := item.JSLoopVersion
			loop, err := s.Parent.ExtLoopManager.GetLoop(generation)
			if err == nil && loop == nil {
				err = errJSRuntimeUnavailable
			}
			if err != nil {
				// Compatibility branch for non-JS commands overwritten by a
				// legacy Goja SolveRaw callback with no generation metadata.
				if !item.IsJsSolveFunc && item.SolveRaw != nil {
					loop, generation = s.Parent.ExtLoopManager.CurrentLoop()
					if loop != nil {
						err = nil
					}
				}
				if err != nil || loop == nil {
					executeErr = err
					s.Parent.Logger.Errorf("扩展注册的指令<%s>运行环境已经过期: %v", item.Name, err)
					return CmdExecuteResult{Matched: true, Solved: false}
				}
			}

			if item.SolveRaw == nil {
				// Compatibility for a few old objects that mark themselves as
				// JavaScript commands but retain a synchronous Solve callback.
				realm := jsContextForMessage(executionPlugin, ctx)
				err = jsengine.RunWithContext(loop, realm, func(runtime jsengine.Runtime) (runErr error) {
					defer func() {
						if recovered := recover(); recovered != nil {
							runErr = formatJSSolveRecoveredError(recovered)
						}
					}()
					return realm.withRuntime(runtime, func() error {
						ret = item.Solve(ctx, msg, cmdArgs)
						return nil
					})
				})
			} else {
				ret, err = s.executeSolveRawValue(ctx, msg, cmdArgs, item, executionPlugin, generation)
			}
			if errors.Is(err, context.DeadlineExceeded) {
				err = errors.Join(errJSSolveTimeout, err)
			}
			if err != nil {
				if errors.Is(err, errJSSolveTimeout) {
					executeErr = err
					ctx.recordJSExecutionError(err)
					s.Parent.Logger.Warnf("扩展注册的指令<%s>执行超时（>%s），建议检查扩展逻辑", item.Name, jsSolveAwaitTimeout)
					return CmdExecuteResult{Matched: true, Solved: false}
				}
				if errors.Is(err, errJSSolveEmptyResult) {
					if waitForCommandReply(ctx, jsSolveEmptyResultGraceWindow) {
						ret = CmdExecuteResult{Matched: true, Solved: true}
					} else {
						executeErr = err
						ctx.recordJSExecutionError(err)
						logJSSolveEmptyResultWarning(s.Parent.Logger, candidate, item.Name, ctx, msg)
						return CmdExecuteResult{Matched: true, Solved: false}
					}
				} else {
					executeErr = err
					ctx.recordJSExecutionError(err)
					ReplyToSender(ctx, msg, fmt.Sprintf("JS执行异常，请反馈给该扩展的作者：\n%v", err))
					return CmdExecuteResult{Matched: true, Solved: false}
				}
			}
		} else {
			ret = item.Solve(ctx, msg, cmdArgs)
		}

		if ret.Solved {
			if ret.ShowHelp {
				help := ""
				// 优先考虑函数
				if item.HelpFunc != nil {
					help = item.HelpFunc(false)
				}
				// 其次考虑help
				if help == "" {
					help = item.Help
				}
				// 最后用短help拼
				if help == "" {
					// 这是为了防止别的骰子误触发
					help = item.Name + ":\n" + item.ShortHelp
				}
				ReplyToSender(ctx, msg, help)
			}

			return ret
		}
		return ret
	}

	group := ctx.Group
	var candidates []commandSolveCandidate
	item := ctx.Session.Parent.CmdMap[cmdArgs.Command]
	if item != nil {
		candidates = append(candidates, commandSolveCandidate{Ext: nil, Item: item})
	}

	if group != nil && (group.Active() || ctx.IsCurGroupBotOn) {
		for _, wrapper := range group.GetActivatedExtList(ctx.Dice) {
			cmdMap := wrapper.GetCmdMap()
			item = cmdMap[cmdArgs.Command]
			if item == nil {
				wrapper.dropJSCommandBeforeLoad(ctx, msg, cmdArgs.Command)
				continue
			}
			candidates = append(candidates, commandSolveCandidate{Ext: wrapper, Item: item})
		}
	}

	if len(candidates) == 0 {
		inactiveSources := findInactiveExtensionCommandSources(ctx, cmdArgs.Command)
		if !ctx.IsPrivate && !ctx.IsCurGroupBotOn && len(findActivatedExtensionCommandSources(ctx, cmdArgs.Command)) > 0 {
			return commandSolveResult{
				Status:       commandSolveUnmatched,
				IgnoreReason: commandIgnoreReasonBotOff,
			}
		}
		if len(inactiveSources) > 0 {
			return commandSolveResult{
				Status:          commandSolveUnmatched,
				InactiveSources: inactiveSources,
				IgnoreReason:    commandIgnoreReasonExtensionInactive,
			}
		}
		return commandSolveResult{
			Status:       commandSolveUnmatched,
			IgnoreReason: commandIgnoreReasonUnknownCommand,
		}
	}

	var available []commandSolveCandidate
	var disabled []commandSolveCandidate
	var unavailable []commandUnavailableSource
	for _, candidate := range candidates {
		ok, reason := checkCandidateAvailable(candidate.Ext, candidate.Item)
		if ok {
			available = append(available, candidate)
			continue
		}
		if reason != commandIgnoreReasonNone {
			unavailable = append(unavailable, commandUnavailableSource{
				Reason: reason,
				Source: commandCandidateDisplayName(candidate),
			})
		}
		if reason == commandIgnoreReasonCommandDisabled {
			disabled = append(disabled, candidate)
		}
	}

	if len(available) > 1 {
		selected, ok := selectRulePluginCandidateByGroupSystem(ctx, available)
		if !ok {
			// 规则模板关联层级择优（REFS #1769）：当前规则关联的扩展优先于无关扩展，
			// 仅在层级内唯一时选中，同层多个候选仍按冲突提示交由用户处置。
			selected, ok = selectPreferredTierCandidate(ctx, available)
		}
		if ok {
			available = []commandSolveCandidate{selected}
		} else {
			names := make([]string, 0, len(available))
			for _, candidate := range available {
				names = append(names, fmt.Sprintf("%s:%s", commandCandidateSourceName(candidate), candidate.Item.Name))
			}
			return commandSolveResult{
				Status:           commandSolveConflict,
				AvailableSources: names,
			}
		}
	}

	var executeResult CmdExecuteResult
	var executeLocation string
	var executeErrorText string
	if len(available) == 1 {
		executeLocation = commandCandidateSourceLocation(available[0])
		executeResult = executeCandidate(available[0])
		if executeErr != nil {
			executeErrorText = executeErr.Error()
		}
	}
	if failure := ctx.jsCallbackFailure(); failure != nil {
		ctx.recordJSExecutionError(failure)
		return commandSolveResult{
			Status:       commandSolveFailed,
			ExecuteError: failure.Error(),
		}
	}

	if group != nil && (group.Active() || ctx.IsCurGroupBotOn) {
		for _, wrapper := range group.GetActivatedExtList(ctx.Dice) {
			ext := wrapper.GetRealExt()
			if ext == nil {
				continue
			}
			ext.CallOnCommandReceived(ctx.Dice, ctx, msg, cmdArgs)
			if failure := ctx.jsCallbackFailure(); failure != nil {
				ctx.recordJSExecutionError(failure)
				return commandSolveResult{
					Status:       commandSolveFailed,
					ExecuteError: failure.Error(),
				}
			}
		}
	}

	if len(available) == 1 {
		if executeResult.Solved {
			return commandSolveResult{
				Status:          commandSolveSolved,
				ExecuteMatched:  executeResult.Matched,
				ExecuteSolved:   executeResult.Solved,
				ExecuteLocation: executeLocation,
				ExecuteError:    executeErrorText,
			}
		}
		if !executeResult.Matched {
			inactiveSources := findInactiveExtensionCommandSources(ctx, cmdArgs.Command)
			return commandSolveResult{
				Status:             commandSolveUnmatched,
				UnavailableSources: unavailable,
				InactiveSources:    inactiveSources,
				IgnoreReason:       commandIgnoreReasonCandidateDeclined,
				ExecuteMatched:     executeResult.Matched,
				ExecuteSolved:      executeResult.Solved,
				ExecuteLocation:    executeLocation,
				ExecuteError:       executeErrorText,
			}
		}
		return commandSolveResult{
			Status:          commandSolveFailed,
			ExecuteMatched:  executeResult.Matched,
			ExecuteSolved:   executeResult.Solved,
			ExecuteLocation: executeLocation,
			ExecuteError:    executeErrorText,
		}
	}

	if len(disabled) > 0 {
		names := make([]string, 0, len(disabled))
		for _, candidate := range disabled {
			names = append(names, commandCandidateDisplayName(candidate))
		}
		return commandSolveResult{
			Status:             commandSolveBlocked,
			DisabledSources:    names,
			UnavailableSources: unavailable,
			IgnoreReason:       commandIgnoreReasonCommandDisabled,
		}
	}

	inactiveSources := findInactiveExtensionCommandSources(ctx, cmdArgs.Command)
	return commandSolveResult{
		Status:             commandSolveUnmatched,
		UnavailableSources: unavailable,
		InactiveSources:    inactiveSources,
		IgnoreReason:       selectCommandIgnoreReason(unavailable, inactiveSources, commandIgnoreReasonNoAvailable),
	}
}

func (s *IMSession) OnMessageDeleted(mctx *MsgContext, msg *Message) {
	if mctx == nil || msg == nil {
		return
	}
	d := mctx.Dice
	mctx.MessageType = msg.MessageType
	mctx.IsPrivate = mctx.MessageType == "private"
	conversationID := msg.GroupID
	if msg.MessageType != "group" {
		if msg.Sender.UserID == "" {
			return
		}
		conversationID = "PG-" + msg.Sender.UserID
	}
	if err := mctx.ResolveExistingDomainConversation(conversationID, msg.Sender.UserID); err != nil {
		mctx.setExecutionError(err)
		d.Logger.Errorf("读取撤回消息会话状态失败: %v", err)
		return
	}
	if mctx.Group == nil {
		return
	}

	mctx.IsCurGroupBotOn = msg.MessageType == "group" && mctx.Group.IsActive(mctx)
	if mctx.Group != nil && mctx.Group.System() != "" {
		mctx.SystemTemplate = mctx.Group.GetCharTemplate(d)
		// tmpl, _ := d.GameSystemMap.Load(group.System)
		// mctx.SystemTemplate = tmpl
	}

	_ = mctx.fillPrivilege(msg)

	log := d.Logger
	if msg.MessageType == "group" {
		log.Infof("收到群(%s)内<%s>(%s)的撤回消息事件: rawId=%v", msg.GroupID, logSafeName(msg.Sender.Nickname), msg.Sender.UserID, msg.RawID)
	} else {
		log.Infof("收到<%s>(%s)的撤回消息事件: rawId=%v", logSafeName(msg.Sender.Nickname), msg.Sender.UserID, msg.RawID)
	}

	for _, i := range s.Parent.ExtList {
		i.CallOnMessageDeleted(mctx.Dice, mctx, msg)
	}
}

func (s *IMSession) OnMessageSend(ctx *MsgContext, msg *Message, flag string) {
	for _, i := range s.Parent.ExtList {
		i.CallOnMessageSend(ctx.Dice, ctx, msg, flag)
	}
}

func (s *IMSession) OnPoke(ctx *MsgContext, event *events.PokeEvent) {
	if ctx == nil || event == nil {
		return
	}
	// A poke can observe only existing conversation/player facts. It must not
	// manufacture a group merely because the provider could not enrich it.
	if ctx.Group == nil && event.GroupID != "" {
		if err := ctx.ResolveExistingDomainConversation(event.GroupID, event.SenderID); err != nil {
			ctx.setExecutionError(err)
			s.Parent.Logger.Errorf("读取戳一戳群状态失败: %v", err)
			return
		}
	}
	if ctx.Group == nil {
		return
	}
	if ctx.MessageType == "group" && !ctx.Group.IsActive(ctx) {
		return
	}
	for _, wrapper := range ctx.Group.GetActivatedExtList(ctx.Dice) {
		ext := wrapper.GetRealExt()
		if ext == nil {
			continue
		}
		ext.CallOnPoke(ctx.Dice, ctx, event)
	}
}

func (s *IMSession) OnGroupLeave(ctx *MsgContext, event *events.GroupLeaveEvent) {
	for _, i := range s.Parent.ExtList {
		i.CallOnGroupLeave(ctx.Dice, ctx, event)
	}
}

// OnMessageEdit 消息编辑事件
//
// msg.Message 应为更新后的消息, msg.Time 应为更新时间而非发送时间，同时
// msg.RawID 应确保为原消息的 ID (一些 API 同时会有系统事件 ID，勿混淆)
//
// 依据 API，Sender 不一定存在，ctx 信息亦不一定有效
func (s *IMSession) OnMessageEdit(ctx *MsgContext, msg *Message) {
	if ctx == nil || msg == nil {
		return
	}
	ctx.MessageType = msg.MessageType
	ctx.IsPrivate = msg.MessageType == "private"
	m := fmt.Sprintf("来自%s的消息修改事件: %s",
		msg.GroupID,
		msg.Message,
	)
	s.Parent.Logger.Info(m)

	conversationID := msg.GroupID
	if msg.MessageType != "group" {
		if msg.Sender.UserID == "" {
			return
		}
		conversationID = "PG-" + msg.Sender.UserID
	}
	if err := ctx.ResolveExistingDomainConversation(conversationID, msg.Sender.UserID); err != nil {
		ctx.setExecutionError(err)
		s.Parent.Logger.Errorf("读取编辑消息会话状态失败: %v", err)
		return
	}
	group := ctx.Group
	if group == nil {
		return
	}

	if group.Active() || ctx.IsCurGroupBotOn {
		for _, wrapper := range group.GetActivatedExtList(ctx.Dice) {
			ext := wrapper.GetRealExt()
			if ext == nil {
				continue
			}
			ext.CallOnMessageEdit(ctx.Dice, ctx, msg)
		}
	}
}

// GetEpByPlatform
// 在 EndPoints 中找到第一个符合平台 p 且启用的
func (s *IMSession) GetEpByPlatform(p string) *EndPointInfo {
	for _, ep := range s.EndPointsReadOnly() {
		if ep.Enable && ep.Platform == p {
			return ep
		}
	}
	return nil
}

func (ep *EndPointInfo) bindCompatibilityRuntime(session *IMSession) {
	if ep == nil {
		return
	}
	ep.Session = session
	if binder, ok := ep.Adapter.(endpointRuntimeBinder); ok {
		binder.bindEndpoint(ep)
	}
}

func (ep *EndPointInfo) RefreshGroupNum() {
	if ep == nil || ep.Session == nil || ep.Session.Parent == nil || ep.Session.Parent.DurableStore == nil {
		return
	}
	d := ep.Session.Parent
	groups, err := groupstate.ListProjected(context.Background(), d.DurableStore, d.BaseConfig.Name)
	if err != nil {
		d.Logger.Errorf("刷新 endpoint 群数失败: %v", err)
		return
	}
	serveCount := 0
	for _, group := range groups {
		if group.Deleted || group.GroupID == "" || strings.HasPrefix(group.GroupID, "PG-") {
			continue
		}
		if group.DiceIDExists[ep.UserID] {
			serveCount++
		}
	}
	ep.GroupNum = int64(serveCount)
}

func sendNoticeToTarget(ctx *MsgContext, target NoticeTarget, txt string) {
	if target.IsGroup() {
		ReplyGroup(ctx, &Message{GroupID: target.ID}, txt)
	} else {
		ReplyPerson(ctx, &Message{Sender: SenderBase{UserID: target.ID}}, txt)
	}
}

func sendStandaloneNoticeToTarget(session *IMSession, ep *EndPointInfo, target NoticeTarget, txt string) bool {
	if session == nil || session.Parent == nil || ep == nil || session.Parent.DurableStore == nil {
		return false
	}
	if ep.Session == nil {
		ep.bindCompatibilityRuntime(session)
	}
	liveEndpoint, err := session.ResolveLiveEndpoint(ep)
	if err != nil {
		session.Parent.Logger.Errorf("解析通知账号失败: %v", err)
		return false
	}
	request, err := json.Marshal(struct {
		EndpointID string       `json:"endpointId"`
		Target     NoticeTarget `json:"target"`
		Text       string       `json:"text"`
	}{EndpointID: liveEndpoint.ID, Target: target, Text: txt})
	if err != nil {
		session.Parent.Logger.Errorf("编码通知请求失败: %v", err)
		return false
	}
	identity := session.Parent.DomainExecutionIdentity("notice-send", uuid.NewString())
	err = session.Parent.WithDomainExecution(context.Background(), identity, request, func(transaction *DurableCallbackTransaction) error {
		messageType := "private"
		conversationID := "PG-" + target.ID
		if target.IsGroup() {
			messageType = "group"
			conversationID = target.ID
		}
		messageContext := &MsgContext{
			Dice: session.Parent, Session: session, EndPoint: liveEndpoint,
			MessageType: messageType, IsPrivate: messageType == "private",
			callbackTransaction: transaction, callbackMetadata: transaction.metadata,
			executionContext: transaction.executionContext,
		}
		if resolveErr := messageContext.ResolveExistingDomainConversation(conversationID, target.ID); resolveErr != nil {
			return resolveErr
		}
		if scopeErr := messageContext.runStandaloneMessageScope(func() {
			sendNoticeToTarget(messageContext, target, txt)
		}); scopeErr != nil {
			return scopeErr
		}
		if executionErr := messageContext.getExecutionError(); executionErr != nil {
			return executionErr
		}
		return transaction.Domain().Err()
	})
	if err != nil {
		session.Parent.Logger.Errorf("提交通知失败: target=%s error=%v", target.ID, err)
		return false
	}
	return true
}

func findNoticeEndpoint(session *IMSession, target NoticeTarget) *EndPointInfo {
	if session == nil {
		return nil
	}
	for _, ep := range session.EndPointsReadOnly() {
		if ep != nil && ep.Enable && ep.State == StateConnected && noticeTargetMatchesEndpoint(target, ep) {
			return ep
		}
	}
	return nil
}

// noticeSession is the session notices are routed through.
func (ctx *MsgContext) noticeSession() *IMSession {
	if ctx.Session == nil && ctx.Dice != nil {
		return ctx.Dice.ImSession
	}
	return ctx.Session
}

func sendNoticeTargetCrossPlatform(ctx *MsgContext, target NoticeTarget, txt string) bool {
	if ctx == nil {
		return false
	}
	session := ctx.noticeSession()
	ep := ctx.EndPoint
	if ep == nil || !ep.Enable || !noticeTargetMatchesEndpoint(target, ep) {
		ep = findNoticeEndpoint(session, target)
	}
	if ep == nil {
		return false
	}
	// The notice goes out after the command that raised it may have returned,
	// so it is sent from a context of its own.
	return sendStandaloneNoticeToTarget(session, ep, target, txt)
}

func (d *Dice) NoticeForEveryEndpoint(txt string, allowCrossPlatform bool, noticeTypes ...NoticeType) {
	_ = allowCrossPlatform
	noticeType := NoticeTypeSystem
	if len(noticeTypes) > 0 {
		noticeType = noticeTypes[0]
	}
	config := d.Config()
	foo := func() {
		defer func() {
			if r := recover(); r != nil {
				d.Logger.Errorf("发送通知异常: %v 堆栈: %v", r, string(debug.Stack()))
			}
		}()

		if config.MailEnable {
			if err := d.SendMail(txt, MailTypeNotice, noticeType); err != nil {
				d.Logger.Errorf("邮件通知发送失败: %v", err)
			}
			return
		}

		for _, ep := range d.ImSession.EndPointsReadOnly() {
			if ep == nil || !ep.Enable || ep.State != StateConnected {
				continue
			}
			targets := filterNoticeTargetsForEndpoint(config.NoticeIDs, noticeType, ep)
			for index, target := range targets {
				sendStandaloneNoticeToTarget(d.ImSession, ep, target, txt)
				if index < len(targets)-1 {
					time.Sleep(time.Second)
				}
			}
		}
	}
	go foo()
}

func (ctx *MsgContext) NoticeCrossPlatform(txt string, noticeTypes ...NoticeType) {
	noticeType := NoticeTypeSystem
	if len(noticeTypes) > 0 {
		noticeType = noticeTypes[0]
	}
	config := ctx.Dice.Config()
	foo := func() {
		defer func() {
			if r := recover(); r != nil {
				ctx.Dice.Logger.Errorf("发送通知异常: %v 堆栈: %v", r, string(debug.Stack()))
			}
		}()

		if config.MailEnable {
			if err := ctx.Dice.SendMail(txt, MailTypeNotice, noticeType); err != nil {
				ctx.Dice.Logger.Errorf("邮件通知发送失败: %v", err)
			}
			return
		}

		sent := false
		targets := filterNoticeTargets(config.NoticeIDs, noticeType)
		for index, target := range targets {
			if !sendNoticeTargetCrossPlatform(ctx, target, txt) {
				ctx.Dice.Logger.Errorf("尝试跨平台后仍未能向 %s 发送通知：%s", target.ID, txt)
			} else {
				sent = true
				if index < len(targets)-1 {
					time.Sleep(time.Second)
				}
			}
		}

		if !sent {
			platform := "<未知平台>"
			if ctx.EndPoint != nil {
				platform = ctx.EndPoint.Platform
			}
			ctx.Dice.Logger.Errorf("未能发送来自%s的通知：%s", platform, txt)
		}
	}
	go foo()
}

func (ctx *MsgContext) Notice(txt string, noticeTypes ...NoticeType) {
	noticeType := NoticeTypeSystem
	if len(noticeTypes) > 0 {
		noticeType = noticeTypes[0]
	}
	config := ctx.Dice.Config()
	if ctx.callbackTransaction != nil && !config.MailEnable {
		ctx.noticeInTransaction(txt, noticeType)
		return
	}
	foo := func() {
		defer func() {
			if r := recover(); r != nil {
				ctx.Dice.Logger.Errorf("发送通知异常: %v 堆栈: %v", r, string(debug.Stack()))
			}
		}()

		if config.MailEnable {
			if err := ctx.Dice.SendMail(txt, MailTypeNotice, noticeType); err != nil {
				ctx.Dice.Logger.Errorf("邮件通知发送失败: %v", err)
			}
			return
		}

		sent := false
		if ctx.EndPoint != nil && ctx.EndPoint.Enable {
			targets := filterNoticeTargetsForEndpoint(config.NoticeIDs, noticeType, ctx.EndPoint)
			for index, target := range targets {
				// The notice goes out after the command that raised it may have
				// returned, so it is sent from a context of its own.
				if sendStandaloneNoticeToTarget(ctx.noticeSession(), ctx.EndPoint, target, txt) {
					sent = true
				}
				if index < len(targets)-1 {
					time.Sleep(time.Second)
				}
			}
		}

		if !sent {
			platform := "<未知平台>"
			if ctx.EndPoint != nil {
				platform = ctx.EndPoint.Platform
			}
			if len(filterNoticeTargets(config.NoticeIDs, noticeType)) != 0 {
				ctx.Dice.Logger.Errorf("未能发送来自%s的通知：%s", platform, txt)
			} else {
				ctx.Dice.Logger.Warnf("因为没有启用接收 %s 分类的通知目标，无法发送来自%s的通知：%s", noticeType, platform, txt)
			}
		}
	}
	go foo()
}

var randSourceSplitKey = rand2.NewSource(uint64(time.Now().Unix()))

func (ctx *MsgContext) InitSplitKey() {
	ctx.splitKeyMu.RLock()
	if len(ctx.splitKey) > 0 {
		ctx.splitKeyMu.RUnlock()
		return
	}
	ctx.splitKeyMu.RUnlock()

	ctx.splitKeyMu.Lock()
	defer ctx.splitKeyMu.Unlock()
	if len(ctx.splitKey) > 0 {
		return
	}
	r := randSourceSplitKey.Uint64()
	bArray := make([]byte, 12)
	binary.LittleEndian.PutUint64(bArray[:8], r)
	r = randSourceSplitKey.Uint64()
	binary.LittleEndian.PutUint32(bArray[8:], uint32(r))

	s := base64.StdEncoding.EncodeToString(bArray)
	ctx.splitKey = "###" + s + "###"
	ctx.forwardStart = "\x1dFORWARD-BEGIN:" + s + "\x1d"
	ctx.forwardEnd = "\x1dFORWARD-END:" + s + "\x1d"
}

func (ctx *MsgContext) SetSplitKey(key string) {
	ctx.splitKeyMu.Lock()
	ctx.splitKey = key
	markerKey := strings.TrimSuffix(strings.TrimPrefix(key, "###"), "###")
	ctx.forwardStart = "\x1dFORWARD-BEGIN:" + markerKey + "\x1d"
	ctx.forwardEnd = "\x1dFORWARD-END:" + markerKey + "\x1d"
	ctx.splitKeyMu.Unlock()
}

func (ctx *MsgContext) wrapForward(text string) string {
	ctx.InitSplitKey()
	ctx.splitKeyMu.RLock()
	defer ctx.splitKeyMu.RUnlock()
	return ctx.forwardStart + text + ctx.forwardEnd
}

type replyPlanItem struct {
	Forward bool
	Text    string
}

func (ctx *MsgContext) compileReplyPlan(text string) []replyPlanItem {
	ctx.InitSplitKey()
	ctx.splitKeyMu.RLock()
	start, end := ctx.forwardStart, ctx.forwardEnd
	ctx.splitKeyMu.RUnlock()
	ret := make([]replyPlanItem, 0, 3)
	for len(text) > 0 {
		i := strings.Index(text, start)
		if i < 0 {
			if text != "" {
				ret = append(ret, replyPlanItem{Text: text})
			}
			break
		}
		if i > 0 {
			ret = append(ret, replyPlanItem{Text: text[:i]})
		}
		text = text[i+len(start):]
		j := strings.Index(text, end)
		if j < 0 {
			ret = append(ret, replyPlanItem{Text: start + text})
			break
		}
		ret = append(ret, replyPlanItem{Forward: true, Text: text[:j]})
		text = text[j+len(end):]
	}
	return ret
}

func (ctx *MsgContext) getSplitKey() string {
	ctx.splitKeyMu.RLock()
	defer ctx.splitKeyMu.RUnlock()
	return ctx.splitKey
}

func (ctx *MsgContext) ShallowCopy() *MsgContext {
	if ctx == nil {
		return nil
	}
	ctx.randomMu.Lock()
	copyCtx := &MsgContext{
		MessageType:         ctx.MessageType,
		Group:               ctx.Group,
		Player:              ctx.Player,
		IsCompatibilityTest: ctx.IsCompatibilityTest,
		EndPoint:            ctx.EndPoint,
		Session:             ctx.Session,
		Dice:                ctx.Dice,
		IsCurGroupBotOn:     ctx.IsCurGroupBotOn,
		IsPrivate:           ctx.IsPrivate,
		CommandID:           ctx.CommandID,
		CurrentCommand:      ctx.CurrentCommand,
		CommandHideFlag:     ctx.CommandHideFlag,
		CommandInfo:         ctx.CommandInfo,
		PrivilegeLevel:      ctx.PrivilegeLevel,
		GroupRoleLevel:      ctx.GroupRoleLevel,
		DelegateText:        ctx.DelegateText,
		AliasPrefixText:     ctx.AliasPrefixText,
		callbackTransaction: ctx.callbackTransaction,
		callbackMetadata:    ctx.callbackMetadata,
		facadeRegistry:      ctx.facadeRegistry,
		outboundDelay:       ctx.outboundDelay,
		logReplyTime:        ctx.logReplyTime,
		logReplySeq:         ctx.logReplySeq,
		deckDepth:           ctx.deckDepth,
		DeckPools:           ctx.DeckPools,
		diceExprOverwrite:   ctx.diceExprOverwrite,
		SystemTemplate:      ctx.SystemTemplate,
		Censored:            ctx.Censored,
		SpamCheckedGroup:    ctx.SpamCheckedGroup,
		SpamCheckedPerson:   ctx.SpamCheckedPerson,
		vm:                  ctx.vm,
		diceRandSrc:         ctx.diceRandSrc,
		diceRollSource:      ctx.diceRollSource,
		diceRollRaw:         ctx.diceRollRaw,
		diceRollGroup:       ctx.diceRollGroup,
		chooserRand:         ctx.chooserRand,
		chooserSrc:          ctx.chooserSrc,
		_v1Rand:             ctx._v1Rand,
		executionParent:     ctx,
	}
	copyCtx.adapterEventUnattributed = ctx.adapterEventUnattributed
	ctx.randomMu.Unlock()
	copyCtx.SetSplitKey(ctx.getSplitKey())
	return copyCtx
}

func (ctx *MsgContext) TranslateSplit(s string) string {
	if len(ctx.getSplitKey()) == 0 {
		ctx.InitSplitKey()
	}
	splitKey := ctx.getSplitKey()
	s = strings.ReplaceAll(s, "#{SPLIT}", splitKey)
	s = strings.ReplaceAll(s, "{FormFeed}", splitKey)
	s = strings.ReplaceAll(s, "{formfeed}", splitKey)
	s = strings.ReplaceAll(s, "\f", splitKey)
	s = strings.ReplaceAll(s, "\\f", splitKey)
	return s
}

func (ctx *MsgContext) SplitText(text string) []string {
	splitKey := ctx.getSplitKey()
	if len(splitKey) == 0 {
		return []string{text}
	}
	return strings.Split(text, splitKey)
}

var curCommandID int64 = 0

func getNextCommandID() int64 {
	curCommandID++
	return curCommandID
}
