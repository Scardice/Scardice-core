package dice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"

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

// forwardSenderFromContext derives the QQ-numeric sender identity merged-forward
// nodes need from the endpoint. ok is false when the endpoint has no such id.
func forwardSenderFromContext(ctx *MsgContext) (name string, uin string, ok bool) {
	if ctx == nil || ctx.EndPoint == nil {
		return "", "", false
	}
	trimmed := strings.TrimPrefix(ctx.EndPoint.UserID, "PG-")
	trimmed = strings.TrimPrefix(trimmed, "QQ-Group:")
	trimmed = strings.TrimPrefix(trimmed, "QQ-CH-Group:")
	trimmed = strings.TrimPrefix(trimmed, "QQ-CH:")
	trimmed = strings.TrimPrefix(trimmed, "QQ:")
	if trimmed == ctx.EndPoint.UserID || trimmed == "" {
		return "", "", false
	}
	return ctx.EndPoint.Nickname, trimmed, true
}

func BuildForwardNodesFromContext(ctx *MsgContext, title string, contents []string) []message.ForwardNode {
	name, uin, ok := forwardSenderFromContext(ctx)
	if !ok {
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
	config := ctx.Dice.Config()

	if config.EnableCensor && config.CensorMode == OnlyOutputReply {
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

	if config.RateLimitEnabled && msg.Platform == "QQ" {
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
			ctx.Group.SetRecentDiceSendTime(time.Now().Unix())
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
			if _, uin, ok := forwardSenderFromContext(ctx); ok {
				nodes[i].SenderID = uin
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

func IsCurGroupBotOnByID(ctx *MsgContext, messageType, groupID string) (bool, error) {
	if messageType != "group" {
		return false, nil
	}
	if ctx == nil || ctx.EndPoint == nil {
		return false, errors.New("dice: endpoint unavailable for group activation lookup")
	}
	group, err := ctx.ResolveGroup(ctx.domainContext(), groupID)
	if err != nil {
		return false, err
	}
	return group.Version() != 0 && group.DiceIDActive(ctx.EndPoint.UserID), nil
}

func SetBotOffAtGroup(ctx *MsgContext, groupID string) error {
	if ctx == nil || ctx.EndPoint == nil {
		return errors.New("dice: endpoint unavailable for group deactivation")
	}
	group, err := ctx.ResolveGroup(ctx.domainContext(), groupID)
	if err != nil {
		return err
	}
	if group.Version() == 0 {
		return fmt.Errorf("dice: cannot deactivate unknown group %q", groupID)
	}
	return group.SetActivation(ctx.EndPoint.UserID, false, true)
}

// SetBotOnAtGroup enables one endpoint in the canonical group aggregate.
func ensureGroupActivation(ctx *MsgContext, groupID string, active bool) (*GroupInfo, error) {
	if ctx == nil || ctx.Dice == nil || ctx.EndPoint == nil {
		return nil, errors.New("dice: endpoint unavailable for group activation")
	}
	group, err := ctx.ResolveGroup(ctx.domainContext(), groupID)
	if err != nil {
		return nil, err
	}
	if group.Version() == 0 {
		if err = group.create(ctx.Dice.BaseConfig.Name, groupID, "", "", time.Now().Unix()); err != nil {
			return nil, err
		}
		if err = group.SetCocRuleIndex(int(ctx.Dice.Config().DefaultCocRuleIndex)); err != nil {
			return nil, err
		}
		for _, extension := range ctx.Dice.ExtList {
			if extension == nil || extension.Name == "" {
				continue
			}
			enabled := extension.AutoActive ||
				(extension.DefaultSetting != nil && extension.DefaultSetting.AutoActive)
			if err = group.SetExtension(extension.Name, enabled); err != nil {
				return nil, err
			}
		}
	}
	if err = group.SetActivation(ctx.EndPoint.UserID, active, true); err != nil {
		return nil, err
	}
	return group, nil
}

func SetBotOnAtGroup(ctx *MsgContext, groupID string) (*GroupInfo, error) {
	return ensureGroupActivation(ctx, groupID, true)
}

// GetPlayerInfoBySender resolves request-local facades and creates missing
// canonical group/player aggregates in the current root transaction.
func GetPlayerInfoBySender(ctx *MsgContext, msg *Message) (*GroupInfo, *GroupPlayerInfo, error) {
	if msg == nil {
		return nil, nil, errors.New("dice: message unavailable")
	}
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

// GetPlayerInfoBySenderRaw is the allocation-light resolver used by command
// contexts which already have normalized message identity.
func GetPlayerInfoBySenderRaw(ctx *MsgContext, msg *MessageWrapper) (*GroupInfo, *GroupPlayerInfo, error) {
	if ctx == nil || ctx.Dice == nil || msg == nil || msg.Sender.UserID == "" {
		return nil, nil, errors.New("dice: incomplete player identity")
	}
	groupID := msg.GroupID
	if msg.MessageType != "group" {
		groupID = "PG-" + msg.Sender.UserID
	}
	group, err := ctx.ResolveGroup(ctx.domainContext(), groupID)
	if err != nil {
		return nil, nil, err
	}
	if group.Version() == 0 {
		group, err = SetBotOnAtGroup(ctx, groupID)
		if err != nil {
			return nil, nil, err
		}
	}
	switch {
	case msg.GuildID != "" && msg.ChannelID != "":
		err = group.SetIdentity(msg.GuildID, msg.ChannelID)
	case msg.GuildID != "":
		err = group.SetGuildID(msg.GuildID)
	case msg.ChannelID != "":
		err = group.SetChannelID(msg.ChannelID)
	}
	if err != nil {
		return nil, nil, err
	}
	group.SyncWrapperStatus(ctx.Dice)
	if err = group.SyncExtensionsOnMessage(ctx.Dice); err != nil {
		return nil, nil, err
	}
	player, err := ctx.ResolvePlayer(ctx.domainContext(), groupID, msg.Sender.UserID)
	if err != nil {
		return nil, nil, err
	}
	if player.Version() == 0 {
		if err = player.create(ctx.Dice.BaseConfig.Name, groupID, msg.Sender.UserID, msg.Sender.Nickname); err != nil {
			return nil, nil, err
		}
	}
	player.SetInGroup(true)
	return group, player, nil
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
	config := ctx.Dice.Config()

	if config.RateLimitEnabled && msg.Platform == "QQ" {
		if !spamCheckPerson(ctx, msg) {
			spamCheckGroup(ctx, msg)
		}
	}

	d := ctx.Dice
	if d != nil {
		visibleText := visibleReplyText(ctx, text)
		d.Logger.Infof("发给(群%s): %s", msg.GroupID, visibleText)
		// 敏感词拦截：回复（群）
		if config.EnableCensor && config.CensorMode == OnlyOutputReply {
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
		ctx.Group.SetRecentDiceSendTime(time.Now().Unix())
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
	config := ctx.Dice.Config()

	if config.RateLimitEnabled && msg.Platform == "QQ" {
		spamCheckPerson(ctx, msg)
	}

	d := ctx.Dice
	if d != nil {
		visibleText := visibleReplyText(ctx, text)
		d.Logger.Infof("发给(帐号%s): %s", msg.Sender.UserID, visibleText)
		// 敏感词拦截：回复（个人）
		if config.EnableCensor && config.CensorMode == OnlyOutputReply {
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

func submitDurableForward(ctx *MsgContext, bridge durableOutboundForwardPort, msg *Message, nodes []message.ForwardNode, flag string, group bool) bool {
	err := bridge.submitForward(ctx, msg, nodes, flag, group)
	if err == nil {
		return true
	}
	target := ""
	if msg != nil {
		target = msg.Sender.UserID
	}
	if msg != nil && group {
		target = msg.GroupID
	}
	ctx.Dice.Logger.Errorf("合并转发未能发出: 目标=%s: %v", target, err)
	return false
}

func deliverForwardReplyNow(ctx *MsgContext, bridge OutboundBridgePort, msg *Message, text, flag string, group, durable bool) bool {
	parts := ctx.SplitText(text)
	contents := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			contents = append(contents, part)
		}
	}
	if len(contents) == 0 {
		return false
	}
	if durable && isPureOnebotEndpoint(ctx.EndPoint) {
		if forwardBridge, ok := bridge.(durableOutboundForwardPort); ok {
			nodes := BuildForwardNodesFromContext(ctx, "", contents)
			if len(nodes) > 0 {
				return submitDurableForward(ctx, forwardBridge, msg, nodes, flag, group)
			}
		}
	}
	if !durable {
		if sender, ok := ctx.EndPoint.Adapter.(forwardMsgSender); ok {
			nodes := BuildForwardNodesFromContext(ctx, "", contents)
			if group {
				return sender.SendGroupForwardMsg(ctx, msg.GroupID, nodes)
			}
			return sender.SendPrivateForwardMsg(ctx, msg.Sender.UserID, nodes)
		}
	}
	// SPLIT controls forward nodes, not ordinary fallback messages.
	fallbackText := strings.TrimSpace(stripForwardSplitMarkers(text, ctx.getSplitKey()))
	if fallbackText == "" {
		return false
	}
	if durable {
		return submitDurableText(ctx, bridge, msg, fallbackText, flag, group)
	}
	if group {
		ctx.EndPoint.Adapter.SendToGroup(ctx, msg.GroupID, fallbackText, flag)
	} else {
		ctx.EndPoint.Adapter.SendToPerson(ctx, msg.Sender.UserID, fallbackText, flag)
	}
	return true
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
			accepted = deliverForwardReplyNow(ctx, bridge, msg, item.Text, flag, group, durable) || accepted
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
	if se == nil || se.Parent == nil {
		return false
	}
	ep := se.GetEpByPlatform(p)
	if ep == nil || ep.Session == nil || ep.Session.Parent == nil {
		return false
	}
	request, err := json.Marshal(struct {
		EndpointID string `json:"endpointId"`
		Target     string `json:"target"`
		Text       string `json:"text"`
		Private    bool   `json:"private"`
	}{EndpointID: ep.ID, Target: t, Text: txt, Private: pr})
	if err != nil {
		se.Parent.Logger.Errorf("跨会话消息请求编码失败: %v", err)
		return false
	}
	identity := se.Parent.DomainExecutionIdentity("cross-message", uuid.NewString())
	var messageContext *MsgContext
	runErr := se.Parent.WithDomainExecution(context.Background(), identity, request, func(transaction *DurableCallbackTransaction) error {
		messageContext = &MsgContext{
			EndPoint: ep, Session: ep.Session, Dice: ep.Session.Parent,
			callbackTransaction: transaction, callbackMetadata: transaction.metadata,
			executionContext: transaction.executionContext,
		}
		conversationID := t
		if pr {
			conversationID = "PG-" + t
			messageContext.IsPrivate = true
			messageContext.MessageType = "private"
		} else {
			messageContext.MessageType = "group"
		}
		if resolveErr := messageContext.ResolveExistingDomainConversation(conversationID, ""); resolveErr != nil {
			return resolveErr
		}
		if messageContext.Group != nil && !pr {
			messageContext.IsCurGroupBotOn = messageContext.Group.IsActive(messageContext)
		}
		if pr {
			ReplyPerson(messageContext, &Message{MessageType: "private", Sender: SenderBase{UserID: t}}, txt)
		} else {
			ReplyGroup(messageContext, &Message{MessageType: "group", GroupID: t}, txt)
		}
		if executionErr := messageContext.getExecutionError(); executionErr != nil {
			return executionErr
		}
		return transaction.Domain().Err()
	})
	if messageContext != nil {
		messageContext.releaseExecutionState()
	}
	if runErr != nil {
		se.Parent.Logger.Errorf("跨会话消息执行失败: %v", runErr)
		return false
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

	if ctx.Player == nil || ctx.Player.requireRuntimeAuthority() != nil {
		return false
	}
	resources := ctx.Player.runtime
	config := ctx.Dice.Config()
	personalRate := config.PersonalReplenishRate
	if config.PersonalReplenishRateStr == "" {
		personalRate = DefaultConfig.PersonalReplenishRate
	}
	personalBurst := config.PersonalBurst
	if personalBurst == 0 {
		personalBurst = DefaultConfig.PersonalBurst
	}
	resources.limiterMu.Lock()
	if resources.limiter == nil {
		resources.rateLimitWarned = false
		resources.limiter = rate.NewLimiter(
			personalRate,
			int(personalBurst),
		)
	}
	now := time.Now().Unix()
	var recoveryMultiplier int
	resources.spamLastCommand, resources.spamLastCommandAt, resources.spamSameCommandCount, recoveryMultiplier =
		calcSpamRecoveryMultiplier(
			resources.spamLastCommand,
			resources.spamLastCommandAt,
			resources.spamSameCommandCount,
			ctx.CurrentCommand,
			now,
			config.SpamSameCommandWindowSec,
			int(config.SpamRecoveryMultiplierMax),
		)
	applyRateLimiterPenalty(resources.limiter, personalRate, recoveryMultiplier)
	if resources.limiter.Allow() {
		resources.rateLimitWarned = false
		resources.limiterMu.Unlock()
		return false
	}
	wasWarned := resources.rateLimitWarned
	resources.rateLimitWarned = true
	resources.limiterMu.Unlock()

	userID := ctx.Player.UserID()
	// Check if user is already banned to avoid sending multiple warnings in concurrent scenarios
	if banItem, exists := config.BanList.GetByID(userID); exists && banItem.Rank == BanRankBanned {
		return true
	}
	if wasWarned {
		if err := config.BanList.AddScoreByCommandSpamForContext(userID, msg.GroupID, ctx); err != nil {
			ctx.setExecutionError(err)
		}
	} else {
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

	if ctx.Group == nil || ctx.Group.requireRuntimeAuthority() != nil {
		return false
	}
	// Skip privileged groups
	for _, groupID := range ctx.Dice.DiceMasterIDs() {
		if ctx.Group.GroupID() == groupID {
			return false
		}
	}
	resources := ctx.Group.runtime
	config := ctx.Dice.Config()
	groupRate := config.GroupReplenishRate
	if config.GroupReplenishRateStr == "" {
		groupRate = DefaultConfig.GroupReplenishRate
	}
	groupBurst := config.GroupBurst
	if groupBurst == 0 {
		groupBurst = DefaultConfig.GroupBurst
	}
	resources.limiterMu.Lock()
	if resources.limiter == nil {
		resources.rateLimitWarned = false
		resources.limiter = rate.NewLimiter(
			groupRate,
			int(groupBurst),
		)
	}
	now := time.Now().Unix()
	var recoveryMultiplier int
	resources.spamLastCommand, resources.spamLastCommandAt, resources.spamSameCommandCount, recoveryMultiplier =
		calcSpamRecoveryMultiplier(
			resources.spamLastCommand,
			resources.spamLastCommandAt,
			resources.spamSameCommandCount,
			ctx.CurrentCommand,
			now,
			config.SpamSameCommandWindowSec,
			int(config.SpamRecoveryMultiplierMax),
		)
	applyRateLimiterPenalty(resources.limiter, groupRate, recoveryMultiplier)
	if resources.limiter.Allow() {
		resources.rateLimitWarned = false
		resources.limiterMu.Unlock()
		return false
	}
	wasWarned := resources.rateLimitWarned
	resources.rateLimitWarned = true
	resources.limiterMu.Unlock()

	groupID := ctx.Group.GroupID()
	// Check if group is already banned to avoid sending multiple warnings in concurrent scenarios
	if banItem, exists := config.BanList.GetByID(groupID); exists && banItem.Rank == BanRankBanned {
		return true
	}
	if wasWarned {
		if err := config.BanList.AddScoreByCommandSpamForContext(groupID, msg.GroupID, ctx); err != nil {
			ctx.setExecutionError(err)
		}
	} else {
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
