package dice

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	ds "github.com/sealdice/dicescript"

	"Scardice-core/adapterapi"
	"Scardice-core/logger"
	"Scardice-core/message"
)

var (
	sealCodeRe                    = regexp.MustCompile(`\[(img|图|文本|text|语音|voice|视频|video):(.+?)]`)
	cqCodeRe                      = regexp.MustCompile(`\[CQ:.+?]`)
	errFileSendUnavailable        = errors.New("文件发送不可用：拒绝发送未持久化文件路径")
	errFileSendAdapterUnavailable = errors.New("文件发送适配器不可用")
)

type forwardMsgSender interface {
	SendGroupForwardMsg(ctx *MsgContext, groupID string, nodes []message.ForwardNode) bool
	SendPrivateForwardMsg(ctx *MsgContext, userID string, nodes []message.ForwardNode) bool
}

func buildForwardNodes(senderName string, senderUin string, title string, contents []string) []message.ForwardNode {
	nodes := make([]message.ForwardNode, 0, len(contents)+1)
	if title != "" {
		nodes = append(nodes, message.ForwardNode{
			SenderName: senderName,
			SenderID:   senderUin,
			Elements:   message.ConvertStringMessage(title),
		})
	}

	for _, c := range contents {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}

		nodes = append(nodes, message.ForwardNode{
			SenderName: senderName,
			SenderID:   senderUin,
			Elements:   message.ConvertStringMessage(c),
		})
	}
	return nodes
}

func BuildForwardNodesFromContext(ctx *MsgContext, title string, contents []string) []message.ForwardNode {
	if ctx == nil || ctx.EndPoint == nil {
		return nil
	}
	name := ctx.EndPoint.Nickname

	trimmed := strings.TrimPrefix(ctx.EndPoint.UserID, "PG-")
	trimmed = strings.TrimPrefix(trimmed, "QQ-Group:")
	trimmed = strings.TrimPrefix(trimmed, "QQ-CH-Group:")
	trimmed = strings.TrimPrefix(trimmed, "QQ-CH:")
	trimmed = strings.TrimPrefix(trimmed, "QQ:")
	if trimmed == ctx.EndPoint.UserID {
		return nil
	}
	uin := trimmed
	if uin == "" {
		return nil
	}
	return buildForwardNodes(name, uin, title, contents)
}

func forwardNodesToText(nodes []message.ForwardNode) string {
	parts := make([]string, 0, len(nodes))
	for _, n := range nodes {
		text := strings.TrimSpace(message.ConvertMessageElementsToString(n.Elements))
		if text != "" {
			parts = append(parts, text)
		}
	}
	return strings.TrimSpace(strings.Join(parts, "\n"))
}

func stripForwardSplitMarkers(text string, splitKey string) string {
	if splitKey == "" {
		return text
	}
	quoted := regexp.QuoteMeta(splitKey)
	// A marker placed on its own line owns that line ending. Removing only the
	// marker would leave two adjacent newlines and produce a blank line.
	text = regexp.MustCompile(`(?m)^[\t ]*`+quoted+`[\t ]*(?:\r?\n|$)`).ReplaceAllString(text, "")
	// If the template already has a line break after SPLIT, preserve that one
	// break and consume only the marker plus horizontal spacing.
	text = regexp.MustCompile(`[\t ]*`+quoted+`[\t ]*(\r?\n)`).ReplaceAllString(text, "$1")
	// A marker at the beginning of a non-empty line already has the preceding
	// line break as its separator.
	text = regexp.MustCompile(`(?m)^[\t ]*`+quoted+`[\t ]*`).ReplaceAllString(text, "")
	// With no adjacent line break, SPLIT itself becomes exactly one line break.
	return regexp.MustCompile(`[\t ]*`+quoted+`[\t ]*`).ReplaceAllString(text, "\n")
}

// TryReplyToSenderMergedForward 尝试用“合并转发”发送多条内容。
//
// 返回值含义：
//   - true：已发送（或当前平台支持且已处理）
//   - false：当前平台/适配器不支持，调用方应自行回退到普通 ReplyToSender
func TryReplyToSenderMergedForward(ctx *MsgContext, msg *Message, title string, contents []string) bool {
	if ctx == nil || msg == nil || ctx.Dice == nil || ctx.EndPoint == nil || ctx.EndPoint.Adapter == nil || isPureOnebotEndpoint(ctx.EndPoint) {
		return false
	}
	if len(contents) == 0 {
		return false
	}

	if ctx.Dice.Config.EnableCensor && ctx.Dice.Config.CensorMode == OnlyOutputReply {
		for i, content := range contents {
			checkText := sealCodeRe.ReplaceAllString(content, "")
			checkText = cqCodeRe.ReplaceAllString(checkText, "")

			hit, words, needToTerminate, _ := ctx.Dice.CensorMsg(ctx, msg, checkText, content)
			if needToTerminate {
				return true
			}
			if hit {
				ctx.Dice.Logger.Infof(
					"拒绝回复命中敏感词「%s」的内容（合并转发）- 来自<%s>(%s)",
					strings.Join(words, "|"),
					msg.Sender.Nickname,
					msg.Sender.UserID,
				)
				contents[i] = DiceFormatTmpl(ctx, "核心:拦截_完全拦截_发出的消息")
			}
		}
	}

	if ctx.Dice.Config.RateLimitEnabled && msg.Platform == "QQ" {
		if msg.MessageType == "group" {
			if !spamCheckPerson(ctx, msg) {
				spamCheckGroup(ctx, msg)
			}
		} else {
			spamCheckPerson(ctx, msg)
		}
	}

	if ctx.AliasPrefixText != "" {
		title = ctx.AliasPrefixText + title
		ctx.AliasPrefixText = ""
	}
	if ctx.DelegateText != "" {
		title = ctx.DelegateText + title
		ctx.DelegateText = ""
	}

	s, ok := ctx.EndPoint.Adapter.(forwardMsgSender)
	if !ok {
		return false
	}

	nodes := BuildForwardNodesFromContext(ctx, title, contents)
	if len(nodes) == 0 {
		return false
	}
	switch msg.MessageType {
	case "group":
		ok := s.SendGroupForwardMsg(ctx, msg.GroupID, nodes)
		if ok && ctx.Group != nil {
			atomic.StoreInt64(&ctx.Group.RecentDiceSendTime, time.Now().Unix())
			ctx.Group.MarkDirty(ctx.Dice)
		}
		return ok
	case "private":
		return s.SendPrivateForwardMsg(ctx, msg.Sender.UserID, nodes)
	default:
		return false
	}
}

// ReplyForward lets extensions resend received structured nodes or construct
// their own. Missing sender identity is normalized to the current endpoint.
func ReplyForward(ctx *MsgContext, msg *Message, nodes []message.ForwardNode) bool {
	if ctx == nil || msg == nil || ctx.EndPoint == nil || ctx.EndPoint.Adapter == nil || len(nodes) == 0 || isPureOnebotEndpoint(ctx.EndPoint) {
		return false
	}
	for i := range nodes {
		if nodes[i].SenderName == "" {
			nodes[i].SenderName = ctx.EndPoint.Nickname
		}
		if nodes[i].SenderID == "" {
			normalized := BuildForwardNodesFromContext(ctx, "", []string{"placeholder"})
			if len(normalized) > 0 {
				nodes[i].SenderID = normalized[0].SenderID
			}
		}
	}
	sender, ok := ctx.EndPoint.Adapter.(forwardMsgSender)
	if !ok {
		// Platforms such as Discord and Kook have no merged-forward primitive.
		// Flatten all nodes into one ordinary message instead of dropping the
		// reply or unexpectedly turning node boundaries into message splits.
		text := forwardNodesToText(nodes)
		if text == "" {
			return false
		}
		if msg.MessageType == "group" {
			ctx.EndPoint.Adapter.SendToGroup(ctx, msg.GroupID, text, "")
			return true
		}
		if msg.MessageType == "private" {
			ctx.EndPoint.Adapter.SendToPerson(ctx, msg.Sender.UserID, text, "")
			return true
		}
		return false
	}
	if msg.MessageType == "group" {
		return sender.SendGroupForwardMsg(ctx, msg.GroupID, nodes)
	}
	if msg.MessageType == "private" {
		return sender.SendPrivateForwardMsg(ctx, msg.Sender.UserID, nodes)
	}
	return false
}

func IsCurGroupBotOnByID(session *IMSession, ep *EndPointInfo, messageType string, groupID string) bool {
	// Pinenutn: 总觉得这里还能优化，但是又想不到怎么优化，可恶，要长脑子了
	a := messageType == "group" && session.ServiceAtNew.Exists(groupID)
	if !a {
		return false
	}
	groupInfo, ok := session.ServiceAtNew.Load(groupID)
	if !ok {
		// Pinenutn: 这里是否要打一下日志呢……
		return false
	}
	_, exists := groupInfo.DiceIDActiveMap.Load(ep.UserID)
	return exists
}

func SetBotOffAtGroup(ctx *MsgContext, groupID string) {
	session := ctx.Session
	groupInfo, ok := session.ServiceAtNew.Load(groupID)
	if ok {
		if groupInfo.DiceIDActiveMap == nil {
			groupInfo.DiceIDActiveMap = new(SyncMap[string, bool])
		}

		// TODO: 进行更好的是否变更的检查
		groupInfo.DiceIDActiveMap.Delete(ctx.EndPoint.UserID)
		if groupInfo.DiceIDActiveMap.Len() == 0 {
			groupInfo.Active = false
		}
		groupInfo.MarkDirty(ctx.Dice)
	}
}

// SetBotOnAtGroup 在群内开启
func SetBotOnAtGroup(ctx *MsgContext, groupID string) *GroupInfo {
	session := ctx.Session
	group, ok := session.ServiceAtNew.Load(groupID)
	if ok {
		if group.DiceIDActiveMap == nil {
			group.DiceIDActiveMap = new(SyncMap[string, bool])
		}
		if group.DiceIDExistsMap == nil {
			group.DiceIDExistsMap = new(SyncMap[string, bool])
		}
		if group.InactivatedExtSet == nil {
			group.InactivatedExtSet = StringSet{}
		}
		group.DiceIDActiveMap.Store(ctx.EndPoint.UserID, true)
		group.Active = true
	} else {
		// 设定扩展情况
		sort.Sort(ExtDefaultSettingItemSlice(session.Parent.Config.ExtDefaultSettings))
		var extLst []*ExtInfo
		for _, i := range session.Parent.Config.ExtDefaultSettings {
			if i.ExtItem != nil {
				if i.AutoActive {
					extLst = append(extLst, i.ExtItem)
				}
			}
		}
		group = &GroupInfo{
			Active:            true,
			activatedExtList:  extLst,
			ExtAppliedTime:    session.Parent.ExtUpdateTime, // 标记已初始化
			InactivatedExtSet: StringSet{},
			Players:           new(SyncMap[string, *GroupPlayerInfo]),
			GroupID:           groupID,
			DiceIDActiveMap:   new(SyncMap[string, bool]),
			DiceIDExistsMap:   new(SyncMap[string, bool]),
			CocRuleIndex:      int(session.Parent.Config.DefaultCocRuleIndex),
			UpdatedAtTime:     time.Now().Unix(),
		}
		session.ServiceAtNew.Store(groupID, group)
	}

	if group.DiceIDActiveMap == nil {
		group.DiceIDActiveMap = new(SyncMap[string, bool])
	}
	if group.DiceIDExistsMap == nil {
		group.DiceIDExistsMap = new(SyncMap[string, bool])
	}
	if group.BotList == nil {
		group.BotList = new(SyncMap[string, bool])
	}

	group.DiceIDActiveMap.Store(ctx.EndPoint.UserID, true)
	group.MarkDirty(ctx.Dice)
	return group
}

// GetPlayerInfoBySender 获取玩家群内信息，没有就创建
func GetPlayerInfoBySender(ctx *MsgContext, msg *Message) (*GroupInfo, *GroupPlayerInfo) {
	wrapper := MessageWrapper{
		MessageType: msg.MessageType,
		GroupID:     msg.GroupID,
		Sender: struct {
			UserID   string
			Nickname string
		}{
			UserID:   msg.Sender.UserID,
			Nickname: msg.Sender.Nickname,
		},
		GuildID:   msg.GuildID,
		ChannelID: msg.ChannelID,
	}
	return GetPlayerInfoBySenderRaw(ctx, &wrapper)
}

// GetPlayerInfoBySenderRaw 获取玩家群内信息的轻量版，不依赖完整的msg信息，因为实质上，大部分数据并没什么卵用。
func GetPlayerInfoBySenderRaw(ctx *MsgContext, msg *MessageWrapper) (*GroupInfo, *GroupPlayerInfo) {
	session := ctx.Session
	var groupID string
	if msg.MessageType == "group" {
		// 群信息
		groupID = msg.GroupID
	} else {
		// 私聊信息 PrivateGroup
		groupID = "PG-" + msg.Sender.UserID
		SetBotOnAtGroup(ctx, groupID)
	}

	// Pinenutn:ServiceAtNew
	groupInfo, ok := session.ServiceAtNew.Load(groupID)
	if !ok {
		groupInfo = SetBotOnAtGroup(ctx, groupID)
	}
	if msg.GuildID != "" {
		groupInfo.GuildID = msg.GuildID
	}
	if msg.ChannelID != "" {
		groupInfo.ChannelID = msg.ChannelID
	}

	if ctx.Dice != nil {
		groupInfo.SyncWrapperStatus(ctx.Dice)       // 移除无效 wrapper
		groupInfo.SyncExtensionsOnMessage(ctx.Dice) // 新增 AutoActive 扩展
	}

	p := groupInfo.PlayerGet(ctx.Dice.DBOperator, msg.Sender.UserID)
	if p == nil {
		p = &GroupPlayerInfo{
			Name:         msg.Sender.Nickname,
			UserID:       msg.Sender.UserID,
			ValueMapTemp: &ds.ValueMap{},
		}
		groupInfo.Players.Store(msg.Sender.UserID, p)
	}
	if p.ValueMapTemp == nil {
		p.ValueMapTemp = &ds.ValueMap{}
	}
	p.InGroup = true
	return groupInfo, p
}

type MessageWrapper struct {
	MessageType string // "group" 或私聊
	GroupID     string
	Sender      struct {
		UserID   string
		Nickname string
	}
	GuildID   string // 可选
	ChannelID string // 可选
}

func ReplyToSenderRaw(ctx *MsgContext, msg *Message, text string, flag string) {
	inGroup := msg.MessageType == "group"
	if inGroup {
		ReplyGroupRaw(ctx, msg, text, flag)
	} else {
		ReplyPersonRaw(ctx, msg, text, flag)
	}
}

func replyToSenderRawNoCheck(ctx *MsgContext, msg *Message, text string, flag string) {
	inGroup := msg.MessageType == "group"
	if inGroup {
		replyGroupRawNoCheck(ctx, msg, text, flag)
	} else {
		replyPersonRawNoCheck(ctx, msg, text, flag)
	}
}
func isTransientUIEndpoint(endpoint *EndPointInfo) bool {
	if endpoint == nil || endpoint.Platform != "UI" {
		return false
	}
	_, ok := endpoint.Adapter.(*PlatformAdapterHTTP)
	return ok
}

func ReplyToSender(ctx *MsgContext, msg *Message, text string) {
	if ctx == nil || msg == nil || ctx.Dice == nil {
		logger.M().Errorf("ReplyToSender 被调用，但没有正确传递参数！请检查您的参数！: ctx=%v, msg=%v", ctx, msg)
		return
	}
	// 回复必须在调用方释放消息上下文前完成，旧适配器也不能逃逸到异步 goroutine。
	defer func() {
		if recovered := recover(); recovered != nil {
			logger.M().Errorf("ReplyToSender 执行异常: %v", recovered)
		}
	}()
	ReplyToSenderRaw(ctx, msg, text, "")
}

func ReplyToSenderNoCheck(ctx *MsgContext, msg *Message, text string) {
	if ctx == nil || msg == nil || ctx.Dice == nil {
		logger.M().Errorf("ReplyToSenderNoCheck 被调用，但没有正确传递参数！请检查您的参数！: ctx=%v, msg=%v", ctx, msg)
		return
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			logger.M().Errorf("ReplyToSenderNoCheck 执行异常: %v", recovered)
		}
	}()
	replyToSenderRawNoCheck(ctx, msg, text, "")
}

func ReplyGroupRaw(ctx *MsgContext, msg *Message, text string, flag string) {
	if ctx.AliasPrefixText != "" {
		text = ctx.AliasPrefixText + text
		ctx.AliasPrefixText = ""
	}
	if ctx.DelegateText != "" {
		text = ctx.DelegateText + text
		ctx.DelegateText = ""
	}

	if ctx.Dice.Config.RateLimitEnabled && msg.Platform == "QQ" {
		if !spamCheckPerson(ctx, msg) {
			spamCheckGroup(ctx, msg)
		}
	}

	d := ctx.Dice
	if d != nil {
		visibleText := visibleReplyText(ctx, text)
		d.Logger.Infof("发给(群%s): %s", msg.GroupID, visibleText)
		// 敏感词拦截：回复（群）
		if d.Config.EnableCensor && d.Config.CensorMode == OnlyOutputReply {
			// 先拿掉余烬码和CQ码再检查敏感词
			checkText := sealCodeRe.ReplaceAllString(visibleText, "")
			checkText = cqCodeRe.ReplaceAllString(checkText, "")

			hit, words, needToTerminate, _ := d.CensorMsg(ctx, msg, checkText, text)
			if needToTerminate {
				return
			}
			if hit {
				d.Logger.Infof(
					"拒绝回复命中敏感词「%s」的内容「%s」，原消息「%s」- 来自群(%s)内<%s>(%s)",
					strings.Join(words, "|"),
					text, msg.Message,
					msg.GroupID,
					msg.Sender.Nickname,
					msg.Sender.UserID,
				)
				text = DiceFormatTmpl(ctx, "核心:拦截_完全拦截_发出的消息")
			}
		}
	}
	replyGroupRawNoCheck(ctx, msg, text, flag)
}

func replyGroupRawNoCheck(ctx *MsgContext, msg *Message, text string, flag string) {
	if ctx.AliasPrefixText != "" {
		text = ctx.AliasPrefixText + text
		ctx.AliasPrefixText = ""
	}
	if ctx.DelegateText != "" {
		text = ctx.DelegateText + text
		ctx.DelegateText = ""
	}
	if lenWithoutBase64(text) > 15000 {
		text = "要发送的文本过长"
	}
	accepted := deliverReplyPlan(ctx, msg, strings.TrimSpace(text), flag, true)
	if accepted && ctx != nil && ctx.Group != nil {
		atomic.StoreInt64(&ctx.Group.RecentDiceSendTime, time.Now().Unix())
		ctx.Group.MarkDirty(ctx.Dice)
	}
	if ctx != nil && accepted {
		ctx.SetCommandReplied(true)
	}
}

func ReplyGroup(ctx *MsgContext, msg *Message, text string) {
	ReplyGroupRaw(ctx, msg, text, "")
}

func ReplyPersonRaw(ctx *MsgContext, msg *Message, text string, flag string) {
	if ctx.AliasPrefixText != "" {
		text = ctx.AliasPrefixText + text
		ctx.AliasPrefixText = ""
	}
	if ctx.DelegateText != "" {
		text = ctx.DelegateText + text
		ctx.DelegateText = ""
	}

	if ctx.Dice.Config.RateLimitEnabled && msg.Platform == "QQ" {
		spamCheckPerson(ctx, msg)
	}

	d := ctx.Dice
	if d != nil {
		visibleText := visibleReplyText(ctx, text)
		d.Logger.Infof("发给(帐号%s): %s", msg.Sender.UserID, visibleText)
		// 敏感词拦截：回复（个人）
		if d.Config.EnableCensor && d.Config.CensorMode == OnlyOutputReply {
			// 先拿掉余烬码和CQ码再检查敏感词
			checkText := sealCodeRe.ReplaceAllString(visibleText, "")
			checkText = cqCodeRe.ReplaceAllString(checkText, "")

			hit, words, needToTerminate, _ := d.CensorMsg(ctx, msg, checkText, text)
			if needToTerminate {
				return
			}
			if hit {
				d.Logger.Infof("拒绝回复命中敏感词「%s」的内容「%s」，原消息「%s」- 来自<%s>(%s)",
					strings.Join(words, "|"),
					text,
					msg.Message,
					msg.Sender.Nickname,
					msg.Sender.UserID,
				)
				text = DiceFormatTmpl(ctx, "核心:拦截_完全拦截_发出的消息")
			}
		}
	}
	replyPersonRawNoCheck(ctx, msg, text, flag)
}

func replyPersonRawNoCheck(ctx *MsgContext, msg *Message, text string, flag string) {
	if ctx.AliasPrefixText != "" {
		text = ctx.AliasPrefixText + text
		ctx.AliasPrefixText = ""
	}
	if ctx.DelegateText != "" {
		text = ctx.DelegateText + text
		ctx.DelegateText = ""
	}
	if lenWithoutBase64(text) > 15000 {
		text = "要发送的文本过长"
	}
	accepted := deliverReplyPlan(ctx, msg, strings.TrimSpace(text), flag, false)
	if ctx != nil && accepted {
		ctx.SetCommandReplied(true)
	}
}

// submitDurableText hands one text to the durable outbox. The reply has already
// been announced in the log by the time it gets here, so a refusal is logged too:
// otherwise the message vanishes and the log claims it was sent.
func submitDurableText(ctx *MsgContext, bridge OutboundBridgePort, msg *Message, text, flag string, group bool) bool {
	err := bridge.SubmitText(ctx, msg, text, flag, group)
	if err == nil {
		return true
	}
	target := msg.Sender.UserID
	if group {
		target = msg.GroupID
	}
	ctx.Dice.Logger.Errorf("回复未能发出: 目标=%s: %v", target, err)
	return false
}

func deliverReplyPlan(ctx *MsgContext, msg *Message, text string, flag string, group bool) bool {
	if ctx == nil || !ctx.standaloneSendScope {
		return deliverReplyPlanNow(ctx, msg, text, flag, group)
	}
	// Only the first host send establishes the standalone owner. Reentrant
	// replies from its onMessageSend hook must join that owner rather than try
	// to acquire the execution gate again from inside its read-side entry.
	ctx.standaloneSendScope = false
	accepted := false
	_ = ctx.runStandaloneMessageScope(func() {
		accepted = deliverReplyPlanNow(ctx, msg, text, flag, group)
	})
	return accepted
}

func deliverReplyPlanNow(ctx *MsgContext, msg *Message, text string, flag string, group bool) bool {
	if ctx == nil || ctx.EndPoint == nil {
		return false
	}
	if err := ctx.checkExecution(); err != nil {
		return false
	}
	var bridge OutboundBridgePort
	if ctx.Dice != nil {
		bridge = ctx.Dice.OutboundBridge
	}
	durable := bridge != nil && !isTransientUIEndpoint(ctx.EndPoint)
	if !durable && (ctx.EndPoint.Adapter == nil || isPureOnebotEndpoint(ctx.EndPoint)) {
		return false
	}
	accepted := false
	for _, item := range ctx.compileReplyPlan(text) {
		if item.Forward {
			parts := ctx.SplitText(item.Text)
			contents := make([]string, 0, len(parts))
			for _, part := range parts {
				if part = strings.TrimSpace(part); part != "" {
					contents = append(contents, part)
				}
			}
			if len(contents) == 0 {
				continue
			}
			if durable {
				if isPureOnebotEndpoint(ctx.EndPoint) {
					if forwardBridge, ok := bridge.(durableOutboundForwardPort); ok {
						nodes := BuildForwardNodesFromContext(ctx, "", contents)
						if len(nodes) > 0 {
							if err := forwardBridge.submitForward(ctx, msg, nodes, flag, group); err != nil {
								target := ""
								if msg != nil {
									target = msg.Sender.UserID
									if group {
										target = msg.GroupID
									}
								}
								ctx.Dice.Logger.Errorf("合并转发未能发出: 目标=%s: %v", target, err)
							} else {
								accepted = true
							}
							continue
						}
					}
				}
				fallbackText := strings.TrimSpace(stripForwardSplitMarkers(item.Text, ctx.getSplitKey()))
				if fallbackText != "" && submitDurableText(ctx, bridge, msg, fallbackText, flag, group) {
					accepted = true
				}
				continue
			}
			if sender, ok := ctx.EndPoint.Adapter.(forwardMsgSender); ok {
				nodes := BuildForwardNodesFromContext(ctx, "", contents)
				if group {
					accepted = sender.SendGroupForwardMsg(ctx, msg.GroupID, nodes) || accepted
				} else {
					accepted = sender.SendPrivateForwardMsg(ctx, msg.Sender.UserID, nodes) || accepted
				}
				continue
			}
			// Unsupported platforms receive the whole block as one ordinary
			// message. SPLIT only controls forward nodes, so remove its marker
			// without splitting the fallback message.
			fallbackText := strings.TrimSpace(stripForwardSplitMarkers(item.Text, ctx.getSplitKey()))
			if fallbackText == "" {
				continue
			}
			if group {
				ctx.EndPoint.Adapter.SendToGroup(ctx, msg.GroupID, fallbackText, flag)
			} else {
				ctx.EndPoint.Adapter.SendToPerson(ctx, msg.Sender.UserID, fallbackText, flag)
			}
			accepted = true
			continue
		}
		parts := ctx.SplitText(item.Text)
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if durable {
				if submitDurableText(ctx, bridge, msg, part, flag, group) {
					accepted = true
				}
				continue
			}
			if ctx.EndPoint.Platform == "QQ" {
				doSleepQQ(ctx)
			}
			if group {
				ctx.EndPoint.Adapter.SendToGroup(ctx, msg.GroupID, part, flag)
			} else {
				ctx.EndPoint.Adapter.SendToPerson(ctx, msg.Sender.UserID, part, flag)
			}
			accepted = true
		}
	}
	return accepted
}

func visibleReplyText(ctx *MsgContext, text string) string {
	if ctx == nil {
		return text
	}
	var builder strings.Builder
	for _, item := range ctx.compileReplyPlan(text) {
		builder.WriteString(item.Text)
	}
	return builder.String()
}

// CrossMsgBySearch
// 在 se 中找到第一个平台等于 p 且启用的 EndPointInfo, 并向目标 t 发送消息,
// pr 判断是否为私聊消息
func CrossMsgBySearch(se *IMSession, p, t, txt string, pr bool) bool {
	ep := se.GetEpByPlatform(p)
	if ep == nil {
		return false
	}
	mctx := &MsgContext{
		EndPoint: ep,
		Session:  ep.Session,
		Dice:     ep.Session.Parent,
	}

	if groupInfo, ok := mctx.Session.ServiceAtNew.Load(t); ok {
		mctx.IsCurGroupBotOn = groupInfo.Active
		mctx.Group = groupInfo
	}

	if !pr {
		mctx.MessageType = "group"
		ReplyGroup(mctx, &Message{GroupID: t}, txt)
	} else {
		mctx.IsPrivate = true
		mctx.MessageType = "private"
		ReplyPerson(mctx, &Message{Sender: SenderBase{UserID: t}}, txt)
	}

	return true
}
func ReplyPerson(ctx *MsgContext, msg *Message, text string) {
	ReplyPersonRaw(ctx, msg, text, "")
}

func SendFileToSenderRaw(ctx *MsgContext, msg *Message, path string, flag string) (adapterapi.EffectResult, error) {
	if msg == nil {
		return adapterapi.UnsupportedResult("file_send_invalid_message"), errFileSendAdapterUnavailable
	}
	if msg.MessageType == "group" {
		return SendFileToGroupRaw(ctx, msg, path, flag)
	}
	return SendFileToPersonRaw(ctx, msg, path, flag)
}

// TODO: CrossMsgById 用指定 Id 的 EndPoint 发送跨平台消息，现在似乎没有这个需求
func SendFileToPersonRaw(ctx *MsgContext, msg *Message, path string, flag string) (adapterapi.EffectResult, error) {
	if err := fileSendBoundaryError(ctx, msg); err != nil {
		return adapterapi.UnsupportedResult("file_send_boundary_rejected"), err
	}
	return validateFileSendResult(ctx.EndPoint.Adapter.SendFileToPerson(ctx, msg.Sender.UserID, path, flag))
}

func SendFileToGroupRaw(ctx *MsgContext, msg *Message, path string, flag string) (adapterapi.EffectResult, error) {
	if err := fileSendBoundaryError(ctx, msg); err != nil {
		return adapterapi.UnsupportedResult("file_send_boundary_rejected"), err
	}
	return validateFileSendResult(ctx.EndPoint.Adapter.SendFileToGroup(ctx, msg.GroupID, path, flag))
}

func validateFileSendResult(result adapterapi.EffectResult) (adapterapi.EffectResult, error) {
	if err := result.Validate(); err != nil {
		return adapterapi.AmbiguousResult("file_send_invalid_result", "provider returned an invalid file-send result"),
			fmt.Errorf("文件发送适配器返回了无效结果: %w", err)
	}
	return result, nil
}

func fileSendBoundaryError(ctx *MsgContext, msg *Message) error {
	if ctx == nil || msg == nil || ctx.Dice == nil || ctx.EndPoint == nil {
		return errFileSendAdapterUnavailable
	}
	if ctx.callbackTransaction != nil || ctx.Dice.OutboundBridge != nil || isPureOnebotEndpoint(ctx.EndPoint) {
		if ctx.Dice.Logger != nil {
			ctx.Dice.Logger.Errorf("拒绝发送未持久化文件路径")
		}
		return errFileSendUnavailable
	}
	if ctx.EndPoint.Adapter == nil {
		return errFileSendAdapterUnavailable
	}
	return nil
}

func durableManagementTarget(ctx *MsgContext, groupID string, userID string) (adapterapi.EffectTarget, bool) {
	if ctx == nil || ctx.Dice == nil || ctx.EndPoint == nil {
		return adapterapi.EffectTarget{}, false
	}
	groupID = strings.TrimSpace(groupID)
	userID = strings.TrimSpace(userID)
	if isPureOnebotEndpoint(ctx.EndPoint) {
		groupID = canonicalOnebotGroupID(groupID)
		if userID != "" {
			userID = canonicalOnebotUserID(userID)
		}
	}
	target := adapterapi.EffectTarget{
		Kind:         adapterapi.TargetGroup,
		Conversation: adapterapi.ConversationID(groupID),
		Member:       adapterapi.PrincipalID(userID),
	}
	if err := target.Validate(); err != nil {
		ctx.Dice.Logger.Errorf("拒绝提交无效的群管理动作: %v", err)
		return adapterapi.EffectTarget{}, false
	}
	return target, true
}

func submitDurableManagementAction(ctx *MsgContext, payload adapterapi.EffectPayload) {
	bridge, ok := ctx.Dice.OutboundBridge.(durableOutboundActionPort)
	if !ok {
		ctx.Dice.Logger.Errorf("拒绝绕过 durable outbound bridge 执行群管理动作")
		return
	}
	if err := bridge.SubmitAction(ctx, payload); err != nil {
		ctx.Dice.Logger.Errorf("提交群管理动作失败: %v", err)
	}
}

func MemberBan(ctx *MsgContext, groupID string, userID string, duration int64) {
	if duration <= 0 || uint64(duration) > uint64(^uint32(0)) {
		return
	}
	target, ok := durableManagementTarget(ctx, groupID, userID)
	if !ok {
		return
	}
	submitDurableManagementAction(ctx, adapterapi.EffectPayload{
		Kind:            adapterapi.EffectPayloadBan,
		Target:          target,
		DurationSeconds: uint32(duration),
	})
}

func MemberKick(ctx *MsgContext, groupID string, userID string) {
	target, ok := durableManagementTarget(ctx, groupID, userID)
	if !ok {
		return
	}
	submitDurableManagementAction(ctx, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadKick, Target: target})
}

func QuitGroup(ctx *MsgContext, groupID string) error {
	if ctx == nil || ctx.Dice == nil || ctx.EndPoint == nil || strings.TrimSpace(groupID) == "" {
		return adapterapi.ErrInvalidContract
	}
	if bridge, ok := ctx.Dice.OutboundBridge.(durableOutboundActionPort); ok {
		target, valid := durableManagementTarget(ctx, groupID, "")
		if !valid {
			return adapterapi.ErrInvalidContract
		}
		return bridge.SubmitAction(ctx, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadQuit, Target: target})
	}
	if ctx.callbackTransaction != nil || ctx.Dice.OutboundBridge != nil || isPureOnebotEndpoint(ctx.EndPoint) || ctx.EndPoint.Adapter == nil {
		return adapterapi.ErrUnsupportedAction
	}
	ctx.EndPoint.Adapter.QuitGroup(ctx, groupID)
	return nil
}

// GetGroupInfoAsync refreshes group metadata through the durable action
// boundary when one is installed, while retaining legacy adapter behavior.
func (ep *EndPointInfo) GetGroupInfoAsync(groupID string) {
	log := logger.M()
	if ep != nil && ep.Session != nil && ep.Session.Parent != nil && ep.Session.Parent.Logger != nil {
		log = ep.Session.Parent.Logger
	}
	if ep == nil {
		log.Error("群信息刷新失败：endpoint 不存在")
		return
	}
	if !ep.Enable {
		log.Errorf("群信息刷新失败：endpoint %s 已禁用", ep.ID)
		return
	}
	if ep.Session == nil || ep.Session.Parent == nil {
		log.Errorf("群信息刷新失败：endpoint %s 未绑定会话", ep.ID)
		return
	}
	d := ep.Session.Parent
	groupID = strings.TrimSpace(groupID)
	if groupID == "" {
		log.Errorf("群信息刷新失败：endpoint %s 的群组 ID 无效", ep.ID)
		return
	}
	if d.OutboundBridge != nil {
		bridge, ok := d.OutboundBridge.(durableOutboundActionPort)
		if !ok {
			log.Errorf("群信息刷新失败：endpoint %s 的 durable outbound bridge 不支持群信息动作", ep.ID)
			return
		}
		if isPureOnebotEndpoint(ep) {
			groupID = canonicalOnebotGroupID(groupID)
		}
		target := adapterapi.EffectTarget{
			Kind:         adapterapi.TargetGroup,
			Conversation: adapterapi.ConversationID(groupID),
		}
		if err := target.Validate(); err != nil {
			log.Errorf("群信息刷新失败：endpoint %s 的群组目标无效: %v", ep.ID, err)
			return
		}
		ctx := &MsgContext{Dice: d, Session: ep.Session, EndPoint: ep}
		if err := bridge.SubmitAction(ctx, adapterapi.EffectPayload{
			Kind:   adapterapi.EffectPayloadGroupInfoRefresh,
			Target: target,
		}); err != nil {
			log.Errorf("群信息刷新失败：endpoint %s 提交 durable 动作失败: %v", ep.ID, err)
		}
		return
	}
	if ep.Adapter == nil {
		log.Errorf("群信息刷新失败：endpoint %s 没有可用适配器", ep.ID)
		return
	}
	ep.Adapter.GetGroupInfoAsync(groupID)
}

type ByLength []string

func (s ByLength) Len() int {
	return len(s)
}

func (s ByLength) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s ByLength) Less(i, j int) bool {
	return len(s[i]) > len(s[j])
}

func CompatibleReplace(ctx *MsgContext, s string) string {
	s = ctx.TranslateSplit(s)

	// 匹配 #{DRAW-$1}, 其中$1执行最短匹配且允许左侧右侧各有一个花括号
	// #{DRAW-aaa} => aaa
	// #{DRAW-{aaa} => {aaa
	// #{DRAW-aaa}} => aaa}
	// #{DRAW-{aaa}} => {aaa}
	// 这允许在牌组名中使用不含空格的表达式(主要是为了变量)
	re := regexp.MustCompile(`#\{DRAW-(\{?\S+?\}?)\}`)
	s = re.ReplaceAllString(s, "###DRAW-$1###")

	if ctx != nil {
		s = DeckRewrite(s, func(deckName string) string {
			// 如果牌组名中含有表达式, 在此进行求值
			// 不含表达式也无妨, 求值完还是原来的字符串
			r, _, err := DiceExprTextBase(ctx, deckName, RollExtraFlags{})
			if err == nil {
				deckName = r.ToString()
			}

			exists, result, err := deckDraw(ctx, deckName, false)
			if !exists {
				return "<%未知牌组-" + deckName + "%>"
			}
			if err != nil {
				return "<%抽取错误-" + deckName + "%>"
			}
			return result
		})
	}
	return s
}

func FormatDiceID(ctx *MsgContext, id interface{}, isGroup bool) string {
	prefix := ctx.EndPoint.Platform
	if isGroup {
		prefix += "-Group"
	}
	return fmt.Sprintf("%s:%v", prefix, id)
}

func calcSpamRecoveryMultiplier(lastCommand string, lastAt int64, sameCount int, currentCommand string, now int64, windowSec int64, maxMultiplier int) (string, int64, int, int) {
	if currentCommand == "" {
		return "", 0, 0, 1
	}
	if windowSec <= 0 {
		windowSec = DefaultConfig.SpamSameCommandWindowSec
	}
	if maxMultiplier <= 0 {
		maxMultiplier = int(DefaultConfig.SpamRecoveryMultiplierMax)
	}

	nextCount := 1
	if lastCommand == currentCommand && now-lastAt <= windowSec {
		nextCount = sameCount + 1
	}

	multiplier := nextCount
	if multiplier < 1 {
		multiplier = 1
	}
	if multiplier > maxMultiplier {
		multiplier = maxMultiplier
	}
	return currentCommand, now, nextCount, multiplier
}

func applyRateLimiterPenalty(limiter *rate.Limiter, base rate.Limit, multiplier int) {
	if limiter == nil || base <= 0 {
		return
	}

	target := base
	if multiplier > 1 {
		target = base / rate.Limit(multiplier)
	}
	limiter.SetLimit(target)
}

func spamCheckPerson(ctx *MsgContext, msg *Message) bool {
	if ctx.SpamCheckedPerson {
		return false
	}

	// 同一个 ctx 只需检查一次
	defer func() {
		ctx.SpamCheckedPerson = true
	}()

	if ctx.PrivilegeLevel >= 100 {
		return false
	}

	if ctx.Player.RateLimiter == nil {
		ctx.Player.RateLimitWarned = false
		if ctx.Dice.Config.PersonalReplenishRateStr == "" {
			ctx.Dice.Config.PersonalReplenishRateStr = DefaultConfig.PersonalReplenishRateStr
			ctx.Dice.Config.PersonalReplenishRate = DefaultConfig.PersonalReplenishRate
		}
		if ctx.Dice.Config.PersonalBurst == 0 {
			ctx.Dice.Config.PersonalBurst = DefaultConfig.PersonalBurst
		}
		ctx.Player.RateLimiter = rate.NewLimiter(
			ctx.Dice.Config.PersonalReplenishRate,
			int(ctx.Dice.Config.PersonalBurst),
		)
	}

	now := time.Now().Unix()
	lastCmd, lastAt, sameCount, recoveryMultiplier := calcSpamRecoveryMultiplier(
		ctx.Player.SpamLastCommand,
		ctx.Player.SpamLastCommandAt,
		ctx.Player.SpamSameCommandCount,
		ctx.CurrentCommand,
		now,
		ctx.Dice.Config.SpamSameCommandWindowSec,
		int(ctx.Dice.Config.SpamRecoveryMultiplierMax),
	)
	ctx.Player.SpamLastCommand = lastCmd
	ctx.Player.SpamLastCommandAt = lastAt
	ctx.Player.SpamSameCommandCount = sameCount
	applyRateLimiterPenalty(ctx.Player.RateLimiter, ctx.Dice.Config.PersonalReplenishRate, recoveryMultiplier)

	if ctx.Player.RateLimiter.Allow() {
		ctx.Player.RateLimitWarned = false
		return false
	}

	// Check if user is already banned to avoid sending multiple warnings in concurrent scenarios
	if banItem, exists := ctx.Dice.Config.BanList.GetByID(ctx.Player.UserID); exists && banItem.Rank == BanRankBanned {
		return true
	}

	if ctx.Player.RateLimitWarned {
		ctx.Dice.Config.BanList.AddScoreByCommandSpam(ctx.Player.UserID, msg.GroupID, ctx)
	} else {
		ctx.Player.RateLimitWarned = true
		replyToSenderRawNoCheck(
			ctx, msg,
			DiceFormatTmpl(ctx, "核心:刷屏_警告内容_个人"),
			"",
		)
	}

	return true
}

func spamCheckGroup(ctx *MsgContext, msg *Message) bool {
	if ctx.SpamCheckedGroup {
		return false
	}

	// 同一个 ctx 只需检查一次
	defer func() {
		ctx.SpamCheckedGroup = true
	}()

	// Skip privileged groups
	for _, g := range ctx.Dice.DiceMasters {
		if ctx.Group.GroupID == g {
			return false
		}
	}

	if ctx.Group.RateLimiter == nil {
		ctx.Group.RateLimitWarned = false
		if ctx.Dice.Config.GroupReplenishRateStr == "" {
			ctx.Dice.Config.GroupReplenishRateStr = DefaultConfig.GroupReplenishRateStr
			ctx.Dice.Config.GroupReplenishRate = DefaultConfig.GroupReplenishRate
		}
		if ctx.Dice.Config.GroupBurst == 0 {
			ctx.Dice.Config.GroupBurst = DefaultConfig.GroupBurst
		}
		ctx.Group.RateLimiter = rate.NewLimiter(
			ctx.Dice.Config.GroupReplenishRate,
			int(ctx.Dice.Config.GroupBurst),
		)
	}

	now := time.Now().Unix()
	lastCmd, lastAt, sameCount, recoveryMultiplier := calcSpamRecoveryMultiplier(
		ctx.Group.SpamLastCommand,
		ctx.Group.SpamLastCommandAt,
		ctx.Group.SpamSameCommandCount,
		ctx.CurrentCommand,
		now,
		ctx.Dice.Config.SpamSameCommandWindowSec,
		int(ctx.Dice.Config.SpamRecoveryMultiplierMax),
	)
	ctx.Group.SpamLastCommand = lastCmd
	ctx.Group.SpamLastCommandAt = lastAt
	ctx.Group.SpamSameCommandCount = sameCount
	applyRateLimiterPenalty(ctx.Group.RateLimiter, ctx.Dice.Config.GroupReplenishRate, recoveryMultiplier)

	if ctx.Group.RateLimiter.Allow() {
		ctx.Group.RateLimitWarned = false
		return false
	}

	// Check if group is already banned to avoid sending multiple warnings in concurrent scenarios
	if banItem, exists := ctx.Dice.Config.BanList.GetByID(ctx.Group.GroupID); exists && banItem.Rank == BanRankBanned {
		return true
	}

	// If not allow
	if ctx.Group.RateLimitWarned {
		ctx.Dice.Config.BanList.AddScoreByCommandSpam(ctx.Group.GroupID, msg.GroupID, ctx)
	} else {
		ctx.Group.RateLimitWarned = true
		replyToSenderRawNoCheck(
			ctx, msg,
			DiceFormatTmpl(ctx, "核心:刷屏_警告内容_群组"),
			"",
		)
	}

	return true
}

func lenWithoutBase64(text string) int {
	re := regexp.MustCompile(`base64://[A-Za-z0-9+/=]+`)
	croppedText := re.ReplaceAllString(text, "")
	return len(croppedText)
}
