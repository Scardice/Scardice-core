package dice

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	qqbot "github.com/sealdice/botgo"
	"github.com/sealdice/botgo/dto"
	qqapi "github.com/sealdice/botgo/openapi"
	qqtoken "github.com/sealdice/botgo/token"

	"Scardice-core/message"
)

type PlatformAdapterOfficialQQ struct {
	EndPoint    *EndPointInfo `json:"-" yaml:"-"`
	DiceServing bool          `yaml:"-"`

	AppID       uint64 `json:"appID"       yaml:"appID"`
	AppSecret   string `json:"appSecret"   yaml:"appSecret"`
	Token       string `json:"token"       yaml:"token"`
	OnlyQQGuild bool   `json:"onlyQQGuild" yaml:"onlyQQGuild"`

	Api            qqapi.OpenAPI          `json:"-" yaml:"-"`
	SessionManager qqbot.SessionManager   `json:"-" yaml:"-"`
	Ctx            context.Context        `json:"-" yaml:"-"`
	CancelFunc     context.CancelFunc     `json:"-" yaml:"-"`
	QRLoginState   OfficialQQQRLoginState `json:"qrLoginState" yaml:"-"`
	QRURL          string                 `json:"qrURL"        yaml:"-"`
	QRCodeData     []byte                 `json:"-"            yaml:"-"`

	eventQueueMu        sync.Mutex
	eventQueue          *officialQQEventQueue
	eventQueueAccepting bool
	memberEventSink     func(officialQQGroupMemberEvent)
	qrClient            officialQQQRClient
	qrEncoder           officialQQQREncoder
	c2cSendQuota        *OfficialQQSendQuota
	groupSendQuota      *OfficialQQSendQuota
	sendQuotaOnce       sync.Once
}

func (pa *PlatformAdapterOfficialQQ) Serve() int {
	ep := pa.EndPoint
	s := pa.EndPoint.Session
	log := s.Parent.Logger
	d := pa.EndPoint.Session.Parent

	if pa.Ctx != nil {
		log.Info("official qq session already running, skip Serve")
		return 0
	}
	log.Debug("official qq server")
	qqbot.SetLogger(NewDummyLogger())
	ctx, cancel := context.WithCancel(context.Background())
	pa.Ctx, pa.CancelFunc = ctx, cancel
	if pa.AppID == 0 {
		ep.State = StateConnecting
		if err := pa.beginQRLogin(ctx, "scardice"); err != nil {
			ep.State = StateConnectionFailed
			cancel()
			pa.Ctx = nil
			pa.CancelFunc = nil
			return 1
		}
		return 0
	}

	pa.startOfficialQQEventQueue()
	appID := strconv.FormatUint(pa.AppID, 10)
	tokenSource := qqtoken.NewQQBotTokenSource(&qqtoken.QQBotCredentials{
		AppID:     appID,
		AppSecret: pa.AppSecret,
	})
	pa.Api = qqbot.NewOpenAPI(appID, tokenSource).WithTimeout(3 * time.Second)
	pa.SessionManager = qqbot.NewSessionManager()

	ep.State = 2
	log.Debug("official qq connecting")
	ws, err := pa.Api.WS(ctx, nil, "")
	if err != nil || ws == nil {
		log.Error("official qq 获取 ws 接入点失败: ", err)
		log.Error("official qq 提示：请确认在机器人后台配置了 IP 白名单，并检查 AppID/Token 是否正确")
		ep.State = 3
		if pa.CancelFunc != nil {
			pa.CancelFunc()
		}
		pa.Api = nil
		pa.SessionManager = nil
		pa.Ctx = nil
		pa.CancelFunc = nil
		pa.closeOfficialQQEventQueue()
		return 1
	}
	if err := validateOfficialQQWebsocketAP(ws); err != nil {
		log.Error("official qq websocket access point invalid: ", err)
		ep.State = 3
		if pa.CancelFunc != nil {
			pa.CancelFunc()
		}
		pa.Api = nil
		pa.SessionManager = nil
		pa.Ctx = nil
		pa.CancelFunc = nil
		pa.closeOfficialQQEventQueue()
		return 1
	}

	intent := pa.registerOfficialQQHandlers()
	go func() {
		currentCtx := ctx
		defer func() {
			isCurrent := pa.Ctx == currentCtx
			// 防止崩掉进程
			if r := recover(); r != nil {
				log.Error("official qq 启动失败: ", r)
				if isCurrent {
					ep.State = 3
				}
			}
			if isCurrent {
				pa.closeOfficialQQEventQueue()
				pa.Ctx = nil
				pa.CancelFunc = nil
				pa.SessionManager = nil
			}
		}()
		if startErr := runOfficialQQSession(currentCtx, func(runCtx context.Context) error {
			return pa.SessionManager.Start(runCtx, ws, tokenSource, &intent)
		}); startErr != nil {
			log.Error("official qq session manager 启动失败: ", startErr)
			if pa.Ctx == currentCtx {
				ep.State = 3
			}
		}
	}()
	ep.State = 1
	ep.Enable = true
	d.LastUpdatedTime = time.Now().Unix()
	d.Save(false)
	log.Info("official qq 连接成功")

	botInfo, err := pa.Api.Me(ctx)
	if err == nil {
		if acceptErr := pa.acceptVerifiedAccount(ctx, d, botInfo); acceptErr != nil {
			if errors.Is(acceptErr, ErrOfficialQQDuplicateAccount) {
				cancel()
				ep.State = StateConnectionFailed
				return 1
			}
			log.Warnf("official qq verified identity migration deferred after failure: %v", acceptErr)
		}
	}

	return 0
}

func (pa *PlatformAdapterOfficialQQ) ChannelAtMessageReceive(event *dto.WSPayload, data *dto.WSATMessageData) error {
	s := pa.EndPoint.Session
	log := s.Parent.Logger
	log.Debugf("official qq: 收到文字频道消息：%v, %v", event, data)
	if pa.detectBotAccount(data.Author) {
		return nil
	}

	msg := pa.channelMsgToStdMsg(data)
	pa.enqueueOfficialQQEvent(func() {
		s.Execute(pa.EndPoint, msg, false)
	})
	return nil
}

func (pa *PlatformAdapterOfficialQQ) channelMsgToStdMsg(msgQQ *dto.WSATMessageData) *Message {
	msg := new(Message)
	timestamp, _ := msgQQ.Timestamp.Time()
	msg.Time = timestamp.Unix()
	msg.MessageType = "group"
	msg.Message = msgQQ.Content
	msg.RawID = msgQQ.ID
	msg.Platform = "OpenQQCH"
	msg.GuildID = formatDiceIDOfficialQQChGuild(msgQQ.GuildID)
	channelID := formatDiceIDOfficialQQChannel(msgQQ.GuildID, msgQQ.ChannelID)
	msg.GroupID = channelID
	msg.ChannelID = channelID
	if msgQQ.Author != nil {
		msg.Sender.Nickname = msgQQ.Author.Username
		msg.Sender.UserID = formatDiceIDOfficialQQCh(msgQQ.Author.ID)
	}
	return msg
}

func (pa *PlatformAdapterOfficialQQ) GuildDirectMessageReceive(event *dto.WSPayload, data *dto.WSDirectMessageData) error {
	s := pa.EndPoint.Session
	log := s.Parent.Logger
	log.Debugf("official qq: 收到频道私信消息：%v, %v", event, data)
	if pa.detectBotAccount(data.Author) {
		return nil
	}

	msg := pa.guildDirectMsgToStdMsg(data)
	pa.enqueueOfficialQQEvent(func() {
		s.Execute(pa.EndPoint, msg, false)
	})
	return nil
}

func (pa *PlatformAdapterOfficialQQ) guildDirectMsgToStdMsg(msgQQ *dto.WSDirectMessageData) *Message {
	msg := new(Message)
	timestamp, _ := msgQQ.Timestamp.Time()
	msg.Time = timestamp.Unix()
	msg.MessageType = "private"
	msg.Message = msgQQ.Content
	msg.RawID = msgQQ.ID
	msg.Platform = "OpenQQCH"
	// 频道私信需要私信频道的 guild_id 和 channel_id
	channelID := formatDiceIDOfficialQQChannel(msgQQ.GuildID, msgQQ.ChannelID)
	msg.GroupID = channelID
	msg.ChannelID = channelID
	if msgQQ.Author != nil {
		msg.Sender.Nickname = msgQQ.Author.Username
		msg.Sender.UserID = formatDiceIDOfficialQQCh(msgQQ.Author.ID)
	}
	return msg
}

func (pa *PlatformAdapterOfficialQQ) GroupAtMessageReceive(event *dto.WSPayload, data *dto.WSGroupATMessageData) error {
	s := pa.EndPoint.Session
	log := s.Parent.Logger
	log.Debugf("official qq: 收到群聊消息：%v, %v", event, data)
	if pa.detectBotAccount(data.Author) {
		return nil
	}

	msg := pa.groupMsgToStdMsg(data)
	pa.enqueueOfficialQQEvent(func() {
		s.Execute(pa.EndPoint, msg, false)
	})
	return nil
}

func (pa *PlatformAdapterOfficialQQ) groupMsgToStdMsg(msgQQ *dto.WSGroupATMessageData) *Message {
	appID := strconv.FormatUint(pa.AppID, 10)
	msg := new(Message)
	timestamp, _ := msgQQ.Timestamp.Time()
	msg.Time = timestamp.Unix()
	msg.MessageType = "group"
	msg.Message = msgQQ.Content
	msg.RawID = msgQQ.ID
	msg.Platform = "OpenQQ"
	msg.GroupID = formatDiceIDOfficialQQGroupOpenID(appID, msgQQ.GroupOpenID)
	if msgQQ.Author != nil {
		// FIXME: 我要用户名啊kora
		msg.Sender.Nickname = "用户" + msgQQ.Author.MemberOpenID[len(msgQQ.Author.MemberOpenID)-4:]
		msg.Sender.UserID = formatDiceIDOfficialQQMemberOpenID(appID, msgQQ.GroupOpenID, msgQQ.Author.MemberOpenID)
		msg.Sender.GroupRole = msgQQ.Author.MemberRole
	}
	return msg
}

func (pa *PlatformAdapterOfficialQQ) detectBotAccount(author *dto.User) bool {
	if author == nil || author.ID == "" || pa.EndPoint == nil {
		return false
	}
	trustedID, ok := strings.CutPrefix(pa.EndPoint.UserID, "OpenQQ:")
	return ok && trustedID != "" && author.ID == trustedID
}

func (pa *PlatformAdapterOfficialQQ) DoRelogin() bool {
	if pa.CancelFunc != nil {
		pa.CancelFunc()
	}
	pa.closeOfficialQQEventQueue()
	pa.EndPoint.Session.Parent.Logger.Infof("正在启用 official qq 服务")
	pa.EndPoint.State = 0
	pa.Api = nil
	pa.SessionManager = nil
	pa.Ctx = nil
	pa.CancelFunc = nil
	pa.QRLoginState = OfficialQQQRInitial
	pa.QRURL = ""
	pa.QRCodeData = nil
	return pa.Serve() == 0
}

func (pa *PlatformAdapterOfficialQQ) SetEnable(enable bool) {
	d := pa.EndPoint.Session.Parent
	ep := pa.EndPoint
	if enable {
		if pa.Ctx == nil {
			ep.Enable = false
			pa.DiceServing = false
			ep.State = 2
			ServerOfficialQQ(d, ep)
		} else {
			if pa.QRLoginState == OfficialQQQRWaitingForScan {
				ep.Enable = false
				ep.State = StateConnecting
			} else {
				ep.Enable = true
				ep.State = StateConnected
			}
		}
	} else {
		ep.State = 0
		ep.Enable = false
		if pa.CancelFunc != nil {
			pa.CancelFunc()
		}
		pa.closeOfficialQQEventQueue()
		pa.CancelFunc = nil
		pa.Ctx = nil
		pa.QRLoginState = OfficialQQQRInitial
		pa.QRURL = ""
		pa.QRCodeData = nil
	}
	d.LastUpdatedTime = time.Now().Unix()
}

func (pa *PlatformAdapterOfficialQQ) SendSegmentToGroup(ctx *MsgContext, groupID string, msg []message.IMessageElement, flag string) {
}

func (pa *PlatformAdapterOfficialQQ) SendSegmentToPerson(ctx *MsgContext, userID string, msg []message.IMessageElement, flag string) {
}

func (pa *PlatformAdapterOfficialQQ) SendToPerson(ctx *MsgContext, uid string, text string, flag string) {
	userID, idType := pa.mustExtractID(uid)
	if idType != OpenQQCHUser {
		// 说明不是频道信息
		pa.EndPoint.Session.Parent.Logger.Error("official qq 发送私聊消息失败：不支持该功能")
		return
	}
	channelID, guildID, _ := pa.mustExtractTwoID(ctx.Group.ChannelID)
	rowID, ok := VarGetValueStr(ctx, "$tMsgID")
	if !ok || ctx.MessageType == "group" {
		// 需要主动发起私聊
		g, c, err := pa.createQQGuildDirectChannel(ctx, guildID, userID)
		if err != nil {
			pa.EndPoint.Session.Parent.Logger.Error("official qq 发送频道私信消息失败：", err.Error())
			return
		}
		guildID = g
		channelID = c
	}
	pa.sendQQGuildDirectMsgRaw(ctx, rowID, guildID, channelID, text)
}

func (pa *PlatformAdapterOfficialQQ) createQQGuildDirectChannel( /* ctx */ _ *MsgContext, guildID, userID string) (string, string, error) {
	if guildID == "" || userID == "" {
		err := errors.New("创建私信频道的参数不全")
		pa.EndPoint.Session.Parent.Logger.Error("official qq 创建私信频道失败：" + err.Error())
		return "", "", err
	}
	qctx := context.Background()
	toCreate := &dto.DirectMessageToCreate{
		SourceGuildID: guildID,
		RecipientID:   userID,
	}
	info, err := pa.Api.CreateDirectMessage(qctx, toCreate)
	if err != nil {
		pa.EndPoint.Session.Parent.Logger.Error("official qq 创建私信频道失败：" + err.Error())
		return "", "", err
	}
	return info.GuildID, info.ChannelID, nil
}

func (pa *PlatformAdapterOfficialQQ) sendQQGuildDirectMsgRaw( /* ctx */ _ *MsgContext, rowMsgID string, guildID, channelID string, text string) {
	qctx := context.Background()
	elems := message.ConvertStringMessage(text)
	var (
		content  string
		toCreate *dto.MessageToCreate
	)

	for _, elem := range elems {
		switch e := elem.(type) {
		case *message.TextElement:
			content += e.Content
		case *message.ImageElement:
		}
	}

	dMsg := &dto.DirectMessage{
		GuildID:   guildID,
		ChannelID: channelID,
	}
	toCreate = &dto.MessageToCreate{
		Content: content,
		MsgType: 0,
		MsgID:   rowMsgID,
	}
	if _, err := pa.Api.PostDirectMessage(qctx, dMsg, toCreate); err != nil {
		pa.EndPoint.Session.Parent.Logger.Error("official qq 发送频道私信消息失败：" + err.Error())
	}
}

func (pa *PlatformAdapterOfficialQQ) SendToGroup(ctx *MsgContext, uid string, text string, flag string) {
	rowID, ok := VarGetValueStr(ctx, "$tMsgID")
	eventID, hasEventID := VarGetValueStr(ctx, "$tEventID")
	groupId, idType := pa.mustExtractID(uid)
	switch idType {
	case OpenQQGroupOpenid:
		if !ok {
			rowID = ""
		}
		if !hasEventID {
			eventID = ""
		}
		pa.sendQQGroupMsgRaw(ctx, rowID, eventID, groupId, text)
	case OpenQQCHChannel:
		if !ok {
			pa.EndPoint.Session.Parent.Logger.Error("official qq 发送频道消息失败：无法直接发送消息")
			return
		}
		pa.sendQQChannelMsgRaw(ctx, rowID, groupId, text)
	default:
		pa.EndPoint.Session.Parent.Logger.Errorf("official qq 发送群聊消息失败：错误的群聊id[%s]类型-%d", uid, idType)
		return
	}
}

func (pa *PlatformAdapterOfficialQQ) sendQQGroupMsgRaw( /* ctx */ _ *MsgContext, rowMsgID, eventID, groupID string, text string) {
	qctx := context.Background()
	elems := message.ConvertStringMessage(text)
	var (
		content  string
		toCreate *dto.MessageToCreate
	)

	toCreate = &dto.MessageToCreate{
		MsgID:   rowMsgID,
		EventID: eventID,
	}

	for _, element := range elems {
		switch elem := element.(type) {
		case *message.TextElement:
			// QQ官方API中不能发送链接，所以全部进行转写绕过
			content += textLinkStrip(elem.Content)
		case *message.AtElement:
			pa.EndPoint.Session.Parent.Logger.Warn("official qq 群聊消息暂不支持 AT 他人，跳过该部分")
		case *message.ImageElement:
			url := elem.File.URL
			// 目前不支持本地发送，检查一下url
			if url == "" ||
				strings.Contains(url, "localhost") ||
				strings.Contains(url, "127.0.0.1") {
				pa.EndPoint.Session.Parent.Logger.Warn("official qq 群聊消息暂不支持发送本地图片，跳过该部分")
			}
			fMsg := &dto.MessageMediaToCreate{
				FileType:   1,
				URL:        url,
				SrvSendMsg: false,
			}
			media, err := pa.Api.PostGroupFile(qctx, groupID, fMsg)
			if err != nil {
				pa.EndPoint.Session.Parent.Logger.Error("official qq 发送群聊消息时，准备图片信息失败：" + err.Error())
				continue
			}

			toCreate.MsgType = dto.RichMediaMsg
			toCreate.Media = newOfficialQQMediaInfo(media.FileInfo)
		case *message.RecordElement:
			url := elem.File.URL
			// 目前不支持本地发送，检查一下url
			if url == "" ||
				strings.Contains(url, "localhost") ||
				strings.Contains(url, "127.0.0.1") {
				pa.EndPoint.Session.Parent.Logger.Warn("official qq 群聊消息暂不支持发送本地语音，跳过该部分")
			}
			fMsg := &dto.MessageMediaToCreate{
				FileType:   3,
				URL:        url,
				SrvSendMsg: false,
			}
			media, err := pa.Api.PostGroupFile(qctx, groupID, fMsg)
			if err != nil {
				pa.EndPoint.Session.Parent.Logger.Error("official qq 发送群聊消息时，准备语音信息失败：" + err.Error())
				continue
			}

			toCreate.MsgType = dto.RichMediaMsg
			toCreate.Media = newOfficialQQMediaInfo(media.FileInfo)
		}
	}

	toCreate.Content = content
	if toCreate.MsgID == "" && toCreate.EventID == "" {
		if err := pa.waitGroupActiveQuota(qctx, groupID); err != nil {
			pa.EndPoint.Session.Parent.Logger.Error("official qq 主动发送群聊消息失败：" + err.Error())
			return
		}
	}

	if _, err := pa.Api.PostGroupMessage(qctx, groupID, toCreate); err != nil {
		pa.EndPoint.Session.Parent.Logger.Error("official qq 发送群聊消息失败：" + err.Error())
	}
}

func newOfficialQQMediaInfo(fileInfo string) *dto.MediaInfo {
	decoded, err := base64.StdEncoding.DecodeString(fileInfo)
	if err != nil {
		decoded = []byte(fileInfo)
	}
	return &dto.MediaInfo{FileInfo: decoded}
}

func (pa *PlatformAdapterOfficialQQ) sendQQChannelMsgRaw( /* ctx */ _ *MsgContext, rowMsgID, channelID string, text string) {
	qctx := context.Background()
	elems := message.ConvertStringMessage(text)
	var (
		content  string
		toCreate *dto.MessageToCreate
	)

	for _, elem := range elems {
		switch e := elem.(type) {
		case *message.TextElement:
			// QQ官方API中不能发送链接，所以全部进行转写绕过
			content += textLinkStrip(e.Content)
		case *message.AtElement:
			if e.Target == "all" {
				content += "@everyone"
			} else {
				content += fmt.Sprintf("<@%s>", e.Target)
			}
		case *message.ImageElement:
		}
	}

	toCreate = &dto.MessageToCreate{
		Content: content,
		MsgType: 0,
		MsgID:   rowMsgID,
	}
	if _, err := pa.Api.PostMessage(qctx, channelID, toCreate); err != nil {
		pa.EndPoint.Session.Parent.Logger.Error("official qq 发送频道消息失败：" + err.Error())
	}
}

func (pa *PlatformAdapterOfficialQQ) GetGroupInfoAsync(groupID string) {
	// 警告太频繁了，拿掉
	// pa.EndPoint.Session.Parent.Logger.Infof("official qq 更新群信息失败：不支持该功能")
}

func formatDiceIDOfficialQQCh(userID string) string {
	return fmt.Sprintf("OpenQQCH:%s", userID)
}

func formatDiceIDOfficialQQChGuild(guildID string) string {
	return fmt.Sprintf("OpenQQCH-Guild:%s", guildID)
}

func formatDiceIDOfficialQQChannel(guildID, channelID string) string {
	return fmt.Sprintf("OpenQQCH-Channel:%s-%s", guildID, channelID)
}

func formatDiceIDOfficialQQ(userUnionID string) string {
	return fmt.Sprintf("OpenQQ:%s", userUnionID)
}

func formatDiceIDOfficialQQGroupOpenID(botID, groupOpenID string) string {
	// 在没有qq_unionid时的临时方案
	return fmt.Sprintf("OpenQQ-Group-T:%s-%s", botID, groupOpenID)
}

func formatDiceIDOfficialQQMemberOpenID(botID, groupOpenID, memberOpenID string) string {
	// 在没有qq_unionid时的临时方案
	return fmt.Sprintf("OpenQQ-Member-T:%s-%s-%s", botID, groupOpenID, memberOpenID)
}

type OpenQQIDType = int

const (
	OpenQQUnknown OpenQQIDType = iota

	OpenQQUser
	OpenQQGroupOpenid
	OpenQQGroupMemberOpenid

	OpenQQCHUser
	OpenQQCHGuild
	OpenQQCHChannel
)

func (pa *PlatformAdapterOfficialQQ) mustExtractID(text string) (string, OpenQQIDType) {
	id, _, idType := pa.mustExtractTwoID(text)
	return id, idType
}

func (pa *PlatformAdapterOfficialQQ) mustExtractTwoID(text string) (string, string, OpenQQIDType) {
	if strings.HasPrefix(text, "OpenQQ:") {
		return text[len("OpenQQ:"):], "", OpenQQUser
	}
	if strings.HasPrefix(text, "OpenQQ-Group-T:") {
		temp := text[len("OpenQQ-Group-T:"):]
		lst := strings.Split(temp, "-")
		return lst[1], "", OpenQQGroupOpenid
	}
	if strings.HasPrefix(text, "OpenQQ-Member-T:") {
		temp := text[len("OpenQQ-Member-T:"):]
		lst := strings.Split(temp, "-")
		return lst[2], lst[1], OpenQQGroupMemberOpenid
	}
	if strings.HasPrefix(text, "OpenQQCH:") {
		return text[len("OpenQQCH:"):], "", OpenQQCHUser
	}
	if strings.HasPrefix(text, "OpenQQCH-Guild:") {
		return text[len("OpenQQCH-Guild:"):], "", OpenQQCHGuild
	}
	if strings.HasPrefix(text, "OpenQQCH-Channel:") {
		temp := text[len("OpenQQCH-Channel:"):]
		lst := strings.Split(temp, "-")
		return lst[1], lst[0], OpenQQCHChannel
	}
	return "", "", OpenQQUnknown
}

func (pa *PlatformAdapterOfficialQQ) SendFileToPerson(ctx *MsgContext, uid string, path string, flag string) {
	pa.SendToPerson(ctx, uid, fmt.Sprintf("[尝试发送文件: %s，但不支持]", filepath.Base(path)), flag)
}

func (pa *PlatformAdapterOfficialQQ) SendFileToGroup(ctx *MsgContext, uid string, path string, flag string) {
	pa.SendToPerson(ctx, uid, fmt.Sprintf("[尝试发送文件: %s，但不支持]", filepath.Base(path)), flag)
}

func (pa *PlatformAdapterOfficialQQ) QuitGroup(_ *MsgContext, _ string) {
	pa.EndPoint.Session.Parent.Logger.Error("official qq 退出群组失败：不支持该功能")
}

func (pa *PlatformAdapterOfficialQQ) SetGroupCardName(_ *MsgContext, _ string) {
	pa.EndPoint.Session.Parent.Logger.Error("official qq 修改名片失败：不支持该功能")
}

func (pa *PlatformAdapterOfficialQQ) MemberBan(_ string, _ string, _ int64) {
	pa.EndPoint.Session.Parent.Logger.Error("official qq 禁言用户失败：不支持该功能")
}

func (pa *PlatformAdapterOfficialQQ) MemberKick(_ string, _ string) {
	pa.EndPoint.Session.Parent.Logger.Error("official qq 踢出用户失败：不支持该功能")
}

func (pa *PlatformAdapterOfficialQQ) EditMessage(_ *MsgContext, _, _ string) {}

func (pa *PlatformAdapterOfficialQQ) RecallMessage(_ *MsgContext, _ string) {}
