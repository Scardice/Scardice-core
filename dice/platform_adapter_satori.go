package dice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/message"
	"Scardice-core/utils/satori"

	ds "github.com/sealdice/dicescript"
)

const SatoriProtocolVersion = "v1"

func satoriEndpoints(version, host string, port int) (*url.URL, *url.URL, error) {
	if version == "" || host == "" || port <= 0 || port > 65535 {
		return nil, nil, errors.New("satori: invalid connection config")
	}
	address := net.JoinHostPort(host, strconv.Itoa(port))
	return &url.URL{Scheme: "ws", Host: address, Path: "/" + version + "/events"},
		&url.URL{Scheme: "http", Host: address, Path: "/" + version}, nil
}

type PlatformAdapterSatori struct {
	EndPoint    *EndPointInfo `json:"-" yaml:"-"`
	DiceServing bool          `yaml:"-"`

	Version  string `json:"version"  yaml:"version"`
	Platform string `json:"platform" yaml:"platform"`
	Host     string `json:"host"     yaml:"host"`
	Port     int    `json:"port"     yaml:"port"`
	Token    string `json:"token"    yaml:"token"`

	httpUrl *url.URL

	Ctx        context.Context    `json:"-" yaml:"-"`
	CancelFunc context.CancelFunc `json:"-" yaml:"-"`
}

// refreshGroups 更新群信息
func (pa *PlatformAdapterSatori) refreshGroups() {
	session := pa.EndPoint.Session
	d := session.Parent
	log := d.Logger
	dm := d.Parent

	next := ""
	for {
		req := make(map[string]interface{})
		if next != "" {
			req["next"] = next
		}
		reqJson, _ := json.Marshal(req)
		data, err := pa.post("guild.list", bytes.NewBuffer(reqJson))
		if err != nil {
			log.Error("satori 获取群列表失败:", err)
			return
		}
		var groupPage struct {
			Data []SatoriGuild `json:"data"`
			Next string        `json:"next"`
		}
		next = groupPage.Next
		err = json.Unmarshal(data, &groupPage)
		if err != nil {
			log.Error("satori 获取群列表失败:", err)
			return
		}
		for _, group := range groupPage.Data {
			if group.Name == "" {
				continue
			}
			groupID := formatDiceIDSatoriGroup(pa.Platform, group.ID)
			dm.GroupNameCache.Store(groupID, &GroupNameCacheItem{
				Name: group.Name,
				time: time.Now().Unix(),
			})

			groupInfo, ok := session.ServiceAtNew.Load(groupID)
			if !ok {
				// 新检测到群
				ctx := &MsgContext{
					Session:  session,
					EndPoint: pa.EndPoint,
					Dice:     d,
				}
				SetBotOnAtGroup(ctx, groupID)
			} else if group.Name != "" && groupInfo.GroupName != group.Name {
				// 更新群名
				groupInfo.GroupName = group.Name
				groupInfo.MarkDirty(d)
			}

			// 触发群成员更新
			go pa.refreshMembers(group)
		}
		if next == "" {
			break
		}
	}
}

func (pa *PlatformAdapterSatori) refreshMembers(group SatoriGuild) {
	session := pa.EndPoint.Session
	d := session.Parent
	log := d.Logger

	groupID := formatDiceIDSatoriGroup(pa.Platform, group.ID)
	groupInfo, ok := session.ServiceAtNew.Load(groupID)
	next := ""
	for {
		req := map[string]interface{}{
			"guild_id": group.ID,
		}
		if next != "" {
			req["next"] = next
		}

		reqJson, _ := json.Marshal(req)
		data, err := pa.post("guild.member.list", bytes.NewBuffer(reqJson))
		if err != nil {
			log.Error("satori 获取群成员列表失败:", err)
			return
		}
		var memberPage struct {
			Data []SatoriGuildMember `json:"data"`
			Next string              `json:"next"`
		}
		next = memberPage.Next
		err = json.Unmarshal(data, &memberPage)
		if err != nil {
			log.Error("satori 获取群成员列表失败:", err)
			return
		}
		for _, member := range memberPage.Data {
			mem := member
			userID := formatDiceIDSatori(pa.Platform, mem.User.ID)
			if ok {
				p := groupInfo.PlayerGet(d.DBOperator, userID)
				if p == nil {
					name := mem.Nick
					if name == "" {
						if mem.User.Name != "" {
							name = mem.User.Name
						}
						if mem.User.Nick != "" {
							name = mem.User.Nick
						}
					}
					p = &GroupPlayerInfo{
						Name:         name,
						UserID:       userID,
						ValueMapTemp: &ds.ValueMap{},
					}
					groupInfo.Players.Store(userID, p)
				}
			}
		}
		if next == "" {
			break
		}
	}
}

func (pa *PlatformAdapterSatori) QuitGroup(ctx *MsgContext, _ string) {
	log := pa.EndPoint.Session.Parent.Logger
	log.Errorf("satori %s 平台暂不支持退群", pa.Platform)
}

func (pa *PlatformAdapterSatori) SendToPerson(ctx *MsgContext, userID string, text string, flag string) {
	log := pa.EndPoint.Session.Parent.Logger
	if pa.Platform == "QQ" {
		id := UserIDExtract(userID)
		pa.sendMsgRaw(ctx, "private:"+id, text, flag, "private")
	} else {
		log.Errorf("satori %s 平台暂不支持私聊消息发送", pa.Platform)
	}
}

func (pa *PlatformAdapterSatori) SendToGroup(ctx *MsgContext, groupID string, text string, flag string) {
	pa.sendMsgRaw(ctx, UserIDExtract(groupID), text, flag, "group")
}

func (pa *PlatformAdapterSatori) sendMsgRaw( /* ctx */ _ *MsgContext, channelID string, text string /* flag */, _ string, msgType string) {
	log := pa.EndPoint.Session.Parent.Logger
	req, err := json.Marshal(map[string]interface{}{
		"channel_id": channelID,
		"content":    pa.encodeMessage(text),
	})
	var msgTypeStr string
	if msgType == "private" {
		msgTypeStr = "私聊"
	} else {
		msgTypeStr = "群"
	}
	if err != nil {
		log.Errorf("satori 发送%s(%s)消息失败: %s", msgTypeStr, channelID, err)
		return
	}
	data, err := pa.post("message.create", bytes.NewBuffer(req))
	if err != nil {
		log.Errorf("satori 发送%s(%s)消息失败: %s", msgTypeStr, channelID, err)
		return
	}
	var messages []SatoriMessage
	err = json.Unmarshal(data, &messages)
	if err != nil {
		log.Errorf("satori 发送%s(%s)消息失败: %s", msgTypeStr, channelID, err)
		return
	}
}

func (pa *PlatformAdapterSatori) SendSegmentToGroup(ctx *MsgContext, groupID string, msg []message.IMessageElement, flag string) {
}

func (pa *PlatformAdapterSatori) SendSegmentToPerson(ctx *MsgContext, userID string, msg []message.IMessageElement, flag string) {
}

func (pa *PlatformAdapterSatori) SetGroupCardName(ctx *MsgContext, name string) {
	log := pa.EndPoint.Session.Parent.Logger
	log.Errorf("satori %s 平台暂不支持设置群成员名片", pa.Platform)
}

func (*PlatformAdapterSatori) SendFileToPerson(_ *MsgContext, _ string, _ string, _ string) adapterapi.EffectResult {
	return adapterapi.UnsupportedResult("satori_file_send_unsupported")
}

func (*PlatformAdapterSatori) SendFileToGroup(_ *MsgContext, _ string, _ string, _ string) adapterapi.EffectResult {
	return adapterapi.UnsupportedResult("satori_file_send_unsupported")
}

func (pa *PlatformAdapterSatori) MemberBan(groupID string, userID string, duration int64) {
	pa.EndPoint.Session.Parent.Logger.Errorf("satori %s 平台暂不支持禁言群(%s)内成员%s", pa.Platform, groupID, userID)
}

func (pa *PlatformAdapterSatori) MemberKick(groupID string, userID string) {
	req, err := json.Marshal(map[string]interface{}{
		"guild_id":  UserIDExtract(groupID),
		"user_id":   UserIDExtract(userID),
		"permanent": false,
	})
	if err != nil {
		pa.EndPoint.Session.Parent.Logger.Errorf("satori 踢出群(%s)内成员(%s)失败：%s", groupID, userID, err)
		return
	}
	_, err = pa.post("guild.member.kick", bytes.NewBuffer(req))
	if err != nil {
		pa.EndPoint.Session.Parent.Logger.Errorf("satori 踢出群(%s)内成员(%s)失败：%s", groupID, userID, err)
		return
	}
}

func (pa *PlatformAdapterSatori) GetGroupInfoAsync(groupID string) {
	logger := pa.EndPoint.Session.Parent.Logger
	req, err := json.Marshal(map[string]interface{}{
		"guild_id": UserIDExtract(groupID),
	})
	if err != nil {
		logger.Errorf("satori 获取群(%s)信息失败：%s", groupID, err)
		return
	}
	data, err := pa.post("guild.get", bytes.NewBuffer(req))
	if err != nil {
		logger.Errorf("satori 获取群(%s)信息失败：%s", groupID, err)
		return
	}
	var groupInfo SatoriGuild
	err = json.Unmarshal(data, &groupInfo)
	if err != nil {
		logger.Errorf("satori 获取群(%s)信息失败：%s", groupID, err)
		return
	}

	go pa.refreshGroups()
}

func (pa *PlatformAdapterSatori) EditMessage(ctx *MsgContext, msgID, message string) {
	log := pa.EndPoint.Session.Parent.Logger
	log.Errorf("satori %s 平台暂不支持编辑消息", pa.Platform)
}

func (pa *PlatformAdapterSatori) RecallMessage(ctx *MsgContext, msgID string) {
	log := pa.EndPoint.Session.Parent.Logger
	log.Errorf("satori %s 平台暂不支持撤回消息", pa.Platform)
}

func (pa *PlatformAdapterSatori) post(resource string, body io.Reader) ([]byte, error) {
	apiUrl := pa.httpUrl.String() + "/" + resource
	client := http.Client{}
	request, _ := http.NewRequest(http.MethodPost, apiUrl, body)
	request.Header.Add("Content-Type", "application/json")
	if pa.Token != "" {
		request.Header.Add("Authorization", "Bearer "+pa.Token)
	}
	request.Header.Add("X-Platform", pa.Platform)
	//nolint:canonicalheader
	request.Header.Add("X-Self-ID", UserIDExtract(pa.EndPoint.UserID))
	resp, err := client.Do(request) //nolint:gosec
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return io.ReadAll(resp.Body)
	case http.StatusBadRequest:
		return nil, errors.New("请求参数有误(400)")
	case http.StatusUnauthorized:
		return nil, errors.New("缺失鉴权(401)")
	case http.StatusForbidden:
		return nil, errors.New("权限不足(403)")
	case http.StatusNotFound:
		return nil, errors.New("未找到资源(404)")
	case http.StatusMethodNotAllowed:
		return nil, errors.New("请求方法不允许(405)")
	default:
		errMsg, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("(%d)", resp.StatusCode)
		}
		return nil, fmt.Errorf("(%d) - %s", resp.StatusCode, errMsg)
	}
}

func decodeMessage(text string) string {
	msgRoot := satori.ElementParse(text)
	content := strings.Builder{}
	msgRoot.Traverse(func(el *satori.Element) {
		switch el.Type {
		case "at":
			if el.Attrs["role"] != "all" {
				_, _ = fmt.Fprintf(&content, "[CQ:at,qq=%s]", el.Attrs["id"])
			}
		case "img":
			_, _ = fmt.Fprintf(&content, "[CQ:image,url=%s]", el.Attrs["src"])
		case "root":
			// pass
		default:
			content.WriteString(el.ToString())
		}
	})
	return content.String()
}

func satoriMessageCreatedInbound(platform string, event *SatoriEvent) (adapterapi.InboundMessage, error) {
	if event == nil || event.Type != "message-created" || event.ID.String() == "" || event.Message == nil || event.Message.ID == "" || event.Message.User == nil || event.Message.User.ID == "" {
		return adapterapi.InboundMessage{}, errors.New("satori: incomplete message-created event")
	}
	conversation := ""
	conversationKind := adapterapi.ConversationKindDirect
	if event.Message.Guild != nil {
		conversationKind = adapterapi.ConversationKindGroup
		if event.Message.Guild.ID == "" {
			return adapterapi.InboundMessage{}, errors.New("satori: message-created event has empty guild")
		}
		conversation = formatDiceIDSatoriGroup(platform, event.Message.Guild.ID)
	}
	inbound := adapterapi.InboundMessage{
		ProviderEventID:  adapterapi.ProviderEventID(event.ID.String()),
		MessageID:        adapterapi.MessageID(event.Message.ID),
		Platform:         platform,
		Sender:           adapterapi.PrincipalID(formatDiceIDSatori(platform, event.Message.User.ID)),
		Conversation:     adapterapi.ConversationID(conversation),
		ConversationKind: conversationKind,
		Kind:             adapterapi.InboundKindMessage,
		Text:             decodeMessage(event.Message.Content),
	}
	if event.Timestamp > 0 {
		inbound.OccurredAt = time.UnixMilli(event.Timestamp).UTC()
	}
	if err := inbound.Validate(); err != nil {
		return adapterapi.InboundMessage{}, err
	}
	return inbound, nil
}

func satoriMessageMutationInbound(platform string, event *SatoriEvent) (adapterapi.InboundMessage, error) {
	if event == nil || event.ID.String() == "" || event.Message == nil || event.Message.ID == "" {
		return adapterapi.InboundMessage{}, errors.New("satori: incomplete message mutation event")
	}
	var kind adapterapi.InboundKind
	switch event.Type {
	case "message-updated":
		kind = adapterapi.InboundKindMessageUpdated
	case "message-deleted":
		kind = adapterapi.InboundKindMessageDeleted
	default:
		return adapterapi.InboundMessage{}, errors.New("satori: unsupported message mutation event")
	}
	conversation := ""
	conversationKind := adapterapi.ConversationKindDirect
	if event.Channel != nil && event.Channel.Type != SatoriDirectChannel {
		conversationKind = adapterapi.ConversationKindGroup
		if event.Channel.ID == "" {
			return adapterapi.InboundMessage{}, errors.New("satori: message mutation event has empty channel")
		}
		conversation = formatDiceIDSatoriGroup(platform, event.Channel.ID)
	}
	sender := ""
	if event.User != nil && event.User.ID != "" {
		sender = formatDiceIDSatori(platform, event.User.ID)
	}
	inbound := adapterapi.InboundMessage{
		ProviderEventID:  adapterapi.ProviderEventID(event.ID.String()),
		MessageID:        adapterapi.MessageID(event.Message.ID),
		Platform:         platform,
		Sender:           adapterapi.PrincipalID(sender),
		Conversation:     adapterapi.ConversationID(conversation),
		ConversationKind: conversationKind,
		Kind:             kind,
	}
	if kind == adapterapi.InboundKindMessageUpdated {
		inbound.Text = decodeMessage(event.Message.Content)
	}
	if event.Timestamp > 0 {
		inbound.OccurredAt = time.UnixMilli(event.Timestamp).UTC()
	}
	if err := inbound.Validate(); err != nil {
		return adapterapi.InboundMessage{}, err
	}
	return inbound, nil
}

func (pa *PlatformAdapterSatori) encodeMessage(content string) string {
	elems := message.ConvertStringMessage(content)
	var msg strings.Builder
	for _, elem := range elems {
		switch e := elem.(type) {
		case *message.TextElement:
			msg.WriteString(satori.ContentEscape(e.Content))
		case *message.AtElement:
			if e.Target == "all" {
				msg.WriteString(`<at type="all"/>`)
			} else {
				_, _ = fmt.Fprintf(&msg, `<at id="%s"/>`, e.Target)
			}
		case *message.FileElement:
			node := &satori.Element{
				// Type:  "file",
				Attrs: make(satori.Dict),
			}
			if e.File != "" {
				node.Attrs["title"] = e.File
			}
			if e.Stream != nil {
				fileName := e.File
				if fileName == "" {
					fileName = "temp"
				}
				temp, _ := os.CreateTemp("", fileName)
				_, err := io.Copy(temp, e.Stream)
				if err != nil {
					continue
				}
				node.Attrs["src"] = "file:///" + temp.Name()
			} else if e.URL != "" {
				node.Attrs["src"] = e.URL
			}
			// cc 0.2.2 发送 file QQ 会直接爆炸
			// msg.WriteString(node.ToString())
		case *message.ImageElement:
			file := e.File
			node := &satori.Element{
				Type:  "img",
				Attrs: make(satori.Dict),
			}
			if file.File != "" {
				node.Attrs["title"] = file.File
			}
			if file.Stream != nil {
				fileName := file.File
				if fileName == "" {
					fileName = "temp"
				}
				temp, _ := os.CreateTemp("", fileName)
				_, err := io.Copy(temp, file.Stream)
				if err != nil {
					continue
				}
				node.Attrs["src"] = "file:///" + temp.Name()
			} else if e.File.URL != "" {
				node.Attrs["src"] = e.File.URL
			}
			msg.WriteString(node.ToString())
		}
	}
	result := msg.String()
	return result
}

//nolint:unused
func (pa *PlatformAdapterSatori) guildAddedHandle(e *SatoriEvent) {

}

//nolint:unused
func (pa *PlatformAdapterSatori) guildRemovedHandle(e *SatoriEvent) {

}

//nolint:unused
func (pa *PlatformAdapterSatori) guildRequestHandle(e *SatoriEvent) {
	d := pa.EndPoint.Session.Parent
	dm := d.Parent
	log := d.Logger

	uid := formatDiceIDSatori(pa.Platform, e.User.ID)
	userName := dm.TryGetUserName(uid)
	guildID := formatDiceIDSatoriGroup(pa.Platform, e.Guild.ID)
	guildName := dm.TryGetGroupName(guildID)
	log.Infof("satori: 收到平台 %s 加群邀请: 群组<%s>(%s) 邀请人:<%s>(%s)",
		pa.Platform, guildName, guildID, userName, uid)

	eid := e.ID.String()
	// 邀请人在黑名单上
	banInfo, ok := d.Config.BanList.GetByID(uid)
	if ok {
		if banInfo.Rank == BanRankBanned && d.Config.BanList.BanBehaviorRefuseInvite {
			pa.sendGuildRequestResult(eid, false, "黑名单")
			return
		}
	}
	// 信任模式，如果不是信任，又不是 master 则拒绝拉群邀请
	isMaster := d.IsMaster(uid)
	if d.Config.TrustOnlyMode && ((banInfo != nil && banInfo.Rank != BanRankTrusted) && !isMaster) {
		pa.sendGuildRequestResult(eid, false, "只允许骰主设置信任的人拉群")
		return
	}
	// 群在黑名单上
	banInfo, ok = d.Config.BanList.GetByID(guildID)
	if ok {
		if banInfo.Rank == BanRankBanned {
			pa.sendGuildRequestResult(eid, false, "群黑名单")
			return
		}
	}
	// 拒绝加群
	if d.Config.RefuseGroupInvite {
		pa.sendGuildRequestResult(eid, false, "设置拒绝加群")
		return
	}
	pa.sendGuildRequestResult(eid, true, "")
}

// sendGuildRequestResult 发送入群邀请处理结果
//
//nolint:unused
func (pa *PlatformAdapterSatori) sendGuildRequestResult(id string, approve bool, comment string) {
	d := pa.EndPoint.Session.Parent
	log := d.Logger
	req := map[string]any{
		"message_id": id,
		"approve":    approve,
		"comment":    comment,
	}
	reqJson, _ := json.Marshal(req)
	_, err := pa.post("guild.approve", bytes.NewBuffer(reqJson))
	if err != nil {
		log.Error("satori 发送入群邀请处理结果失败:", err)
		return
	}
}

//nolint:unused
func (pa *PlatformAdapterSatori) friendRequestHandle(e *SatoriEvent) {
	s := pa.EndPoint.Session
	d := s.Parent
	dm := d.Parent
	log := d.Logger

	uid := formatDiceIDSatori(pa.Platform, e.User.ID)
	userName := dm.TryGetUserName(uid)
	log.Infof("satori: 收到平台 %s 好友请求: 申请人:<%s>(%s)", pa.Platform, userName, uid)

	eid := e.ID.String()
	// 申请人在黑名单上
	banInfo, ok := d.Config.BanList.GetByID(uid)
	if ok {
		if banInfo.Rank == BanRankBanned && d.Config.BanList.BanBehaviorRefuseInvite {
			pa.sendGuildRequestResult(eid, false, "为被禁止用户，准备自动拒绝")
			return
		}
	}

	if strings.TrimSpace(d.Config.FriendAddComment) == "" {
		pa.sendFriendRequestResult(eid, true, "")
	} else {
		pa.sendFriendRequestResult(eid, false, "存在好友问题校验，准备自动拒绝，请联系骰主")
	}
}

// sendFriendRequestResult 发送好友申请处理结果
//
//nolint:unused
func (pa *PlatformAdapterSatori) sendFriendRequestResult(id string, approve bool, comment string) {
	d := pa.EndPoint.Session.Parent
	log := d.Logger
	req := map[string]any{
		"message_id": id,
		"approve":    approve,
		"comment":    comment,
	}
	reqJson, _ := json.Marshal(req)
	_, err := pa.post("friend.approve", bytes.NewBuffer(reqJson))
	if err != nil {
		log.Error("satori 发送好友申请处理结果失败:", err)
		return
	}
}

func formatDiceIDSatori(platform string, diceSatori string) string {
	if platform != "" {
		return fmt.Sprintf("%s:%s", platform, diceSatori)
	} else {
		return fmt.Sprintf("Satori(unknown):%s", diceSatori)
	}
}

func formatDiceIDSatoriGroup(platform, diceSatori string) string {
	if platform != "" {
		return fmt.Sprintf("%s-Group:%s", platform, diceSatori)
	}
	return fmt.Sprintf("Satori(unknown)-Group:%s", diceSatori)
}

//nolint:unused
func formatDiceIDSatoriCh(platform, diceSatori string) string {
	if platform != "" {
		return fmt.Sprintf("%s-CH:%s", platform, diceSatori)
	}
	return fmt.Sprintf("Satori(unknown)-CH:%s", diceSatori)
}
