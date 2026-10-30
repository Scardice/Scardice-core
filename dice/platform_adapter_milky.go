package dice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	milky "github.com/Szzrain/Milky-go-sdk"
	"go.uber.org/zap"

	"Scardice-core/adapterapi"
	"Scardice-core/logger"
	"Scardice-core/message"
	"Scardice-core/utils/procs"
)

// Merged-forward expansion is bounded so a hostile or cyclic forward cannot
// grow without limit.
const (
	maxForwardExpandDepth = 3
	maxForwardNodeCount   = 100
)

type PlatformAdapterMilky struct {
	EndPoint            *EndPointInfo  `json:"-"                     yaml:"-"`
	IntentSession       *milky.Session `json:"-"                     yaml:"-"`
	WsGateway           string         `json:"ws_gateway"            yaml:"ws_gateway"`
	RestGateway         string         `json:"rest_gateway"          yaml:"rest_gateway"`
	Token               string         `json:"-"                     yaml:"token"`
	IgnoreFriendRequest bool           `json:"ignore_friend_request" yaml:"ignore_friend_request"`
	// 内置
	// BuiltInMode 留空则视为分离，目前支持的字段为 lagrangeV2
	BuiltInMode       string          `json:"built_in_mode" yaml:"built_in_mode"`
	MilkyProcess      *procs.Process  `json:"-" yaml:"-"`
	BuiltInLoginState MilkyLoginState `json:"loginState" yaml:"-"`
	QrCodeData        []byte          `json:"-"                          yaml:"-"`
}

type MilkyLoginState int64

const (
	MilkyLoginStateInit MilkyLoginState = iota
	MilkyLoginStatePlaceholder
	MilkyLoginStateQRWaitingForScan
	MilkyLoginStateConnecting
	MilkyLoginStateQRConnected
	MilkyLoginStateFailed
	MilkyLoginStateQRWaitingForConfirm MilkyLoginState = 8
	MilkyLoginStateCancelled           MilkyLoginState = 9
	MilkyLoginStateCodeExpired         MilkyLoginState = 12
)

func (pa *PlatformAdapterMilky) SendSegmentToGroup(ctx *MsgContext, groupID string, msg []message.IMessageElement, flag string) {
	log := zap.S().Named(logger.LogKeyAdapter)
	id, err := strconv.ParseInt(ExtractQQGroupID(groupID), 10, 64)
	if err != nil {
		log.Errorf("Invalid group ID %s: %v", groupID, err)
		return
	}
	elements := ParseMessageToMilky(msg)
	if len(elements) == 0 {
		log.Warnf("Skipping Milky group message to %s: no supported message elements", groupID)
		return
	}
	ret, err := pa.IntentSession.SendGroupMessage(id, &elements)
	if err != nil {
		log.Errorf("Failed to send group message to %s: %v", groupID, err)
		return
	}
	pa.EndPoint.Session.OnMessageSend(ctx, &Message{
		Platform:    "QQ",
		MessageType: "group",
		Segment:     msg,
		GroupID:     groupID,
		Sender: SenderBase{
			UserID:   pa.EndPoint.UserID,
			Nickname: pa.EndPoint.Nickname,
		},
		RawID: ret.MessageSeq,
	}, flag)
}

func (pa *PlatformAdapterMilky) SendSegmentToPerson(ctx *MsgContext, userID string, msg []message.IMessageElement, flag string) {
	log := zap.S().Named(logger.LogKeyAdapter)
	id, err := strconv.ParseInt(ExtractQQUserID(userID), 10, 64)
	if err != nil {
		log.Errorf("Invalid user ID %s: %v", userID, err)
		return
	}
	elements := ParseMessageToMilky(msg)
	if len(elements) == 0 {
		log.Warnf("Skipping Milky private message to %s: no supported message elements", userID)
		return
	}
	ret, err := pa.IntentSession.SendPrivateMessage(id, &elements)
	if err != nil {
		log.Errorf("Failed to send private message to %s: %v", userID, err)
		return
	}
	pa.EndPoint.Session.OnMessageSend(ctx, &Message{
		Platform:    "QQ",
		MessageType: "private",
		Segment:     msg,
		Sender: SenderBase{
			UserID:   pa.EndPoint.UserID,
			Nickname: pa.EndPoint.Nickname,
		},
		RawID: ret.MessageSeq,
	}, flag)
}

func (pa *PlatformAdapterMilky) GetGroupInfoAsync(groupID string) {
	log := zap.S().Named(logger.LogKeyAdapter)
	id, err := strconv.ParseInt(ExtractQQGroupID(groupID), 10, 64)
	if err != nil {
		log.Errorf("Invalid group ID %s: %v", groupID, err)
		return
	}
	groupInfoMilky, err := pa.IntentSession.GetGroupInfo(id, true)
	if err != nil {
		log.Errorf("Failed to get group info for %s: %v", groupID, err)
		return
	}
	if groupInfoMilky == nil {
		log.Warnf("Group info for %s is nil", groupID)
		return
	}
	dm := pa.EndPoint.Session.Parent.Parent
	dm.GroupNameCache.Store(groupID, &GroupNameCacheItem{
		Name: groupInfoMilky.Name,
		time: time.Now().Unix(),
	})
	session := pa.EndPoint.Session
	groupInfo, ok := session.ServiceAtNew.Load(groupID)
	if ok {
		if groupInfoMilky.Name != groupInfo.GroupName {
			// 更新群名
			groupInfo.GroupName = groupInfoMilky.Name
			groupInfo.MarkDirty(session.Parent)
		}
	}
}

func (pa *PlatformAdapterMilky) convertMilkyReceivedSegments(segments []milky.IMessageElement, depth int) []message.IMessageElement {
	ret := make([]message.IMessageElement, 0, len(segments))
	for _, segment := range segments {
		switch seg := segment.(type) {
		case *milky.TextElement:
			ret = append(ret, &message.TextElement{Content: seg.Text})
		case *milky.ImageElement:
			ret = append(ret, &message.ImageElement{URL: seg.TempURL})
		case *milky.AtElement:
			ret = append(ret, &message.AtElement{Target: strconv.FormatInt(seg.UserID, 10), IsRobot: isQQBotUIN(seg.UserID)})
		case *milky.ReplyElement:
			ret = append(ret, &message.ReplyElement{ReplySeq: strconv.FormatInt(seg.MessageSeq, 10)})
		case *milky.ForwardElement:
			ret = append(ret, pa.loadMilkyForward(seg.ForwardID, depth))
		}
	}
	return ret
}

func (pa *PlatformAdapterMilky) loadMilkyForward(forwardID string, depth int) *message.ForwardElement {
	ret := &message.ForwardElement{Kind: "forward", ForwardID: forwardID}
	if depth >= maxForwardExpandDepth {
		ret.LoadError = "forward nesting limit reached"
		return ret
	}
	if pa == nil || pa.IntentSession == nil || forwardID == "" {
		ret.LoadError = "Milky session or forward ID unavailable"
		return ret
	}
	requestCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	raw, err := pa.IntentSession.Request("POST", milky.EndpointGetForwardedMessages, map[string]interface{}{"forward_id": forwardID}, milky.WithContext(requestCtx))
	if err != nil {
		ret.LoadError = err.Error()
		return ret
	}
	var response struct {
		Status  string `json:"status"`
		RetCode int    `json:"retcode"`
		Message string `json:"message"`
		Data    struct {
			Messages []struct {
				MessageSeq int64           `json:"message_seq"`
				SenderID   int64           `json:"sender_id"`
				UserID     int64           `json:"user_id"`
				SenderName string          `json:"sender_name"`
				AvatarURL  string          `json:"avatar_url"`
				Time       int64           `json:"time"`
				Segments   json.RawMessage `json:"segments"`
			} `json:"messages"`
		} `json:"data"`
	}
	if err = json.Unmarshal(raw, &response); err != nil {
		ret.LoadError = err.Error()
		return ret
	}
	if response.RetCode != 0 || response.Status != "ok" {
		ret.LoadError = response.Message
		return ret
	}
	for index, node := range response.Data.Messages {
		if index >= maxForwardNodeCount {
			break
		}
		senderID := node.SenderID
		if senderID == 0 {
			senderID = node.UserID
		}
		segments, parseErr := milky.UnmarshalIMessageElements(node.Segments)
		if parseErr != nil {
			ret.LoadError = parseErr.Error()
			continue
		}
		ret.Nodes = append(ret.Nodes, message.ForwardNode{
			MessageID: strconv.FormatInt(node.MessageSeq, 10), SenderID: strconv.FormatInt(senderID, 10),
			SenderName: node.SenderName, AvatarURL: node.AvatarURL, Time: node.Time,
			Elements: pa.convertMilkyReceivedSegments(segments, depth+1),
		})
	}
	ret.Loaded = true
	return ret
}

func (pa *PlatformAdapterMilky) SetGroupAddRequest(groupId int64, invitationSeq int64, approve bool) {
	log := zap.S().Named(logger.LogKeyAdapter)
	if approve {
		err := pa.IntentSession.AcceptGroupInvitation(groupId, invitationSeq)
		if err != nil {
			log.Errorf("Failed to accept group invitation: %v", err)
			return
		}
	} else {
		// 拒绝加群邀请
		err := pa.IntentSession.RejectGroupInvitation(groupId, invitationSeq)
		if err != nil {
			log.Errorf("Failed to refuse group invitation: %v", err)
			return
		}
	}
}

func (pa *PlatformAdapterMilky) SetFriendAddRequest(initiatorUid string, approve bool, reason string) {
	log := zap.S().Named(logger.LogKeyAdapter)
	if approve {
		// 同意好友请求，目前都是 unfiltered 的
		err := pa.IntentSession.AcceptFriendRequest(initiatorUid, false)
		if err != nil {
			log.Errorf("Failed to accept friend request: %v", err)
			return
		}
	} else {
		// 拒绝好友请求
		err := pa.IntentSession.RejectFriendRequest(initiatorUid, false, reason)
		if err != nil {
			log.Errorf("Failed to refuse friend request: %v", err)
			return
		}
	}
}

func ParseMessageToMilky(send []message.IMessageElement) []milky.IMessageElement {
	log := zap.S().Named(logger.LogKeyAdapter)
	var elements []milky.IMessageElement
	for _, elem := range send {
		switch e := elem.(type) {
		case *message.TextElement:
			elements = append(elements, &milky.TextElement{Text: e.Content})
		case *message.ImageElement:
			log.Debugf("Image: %s", e.URL)
			elements = append(elements, &milky.ImageElement{URI: e.URL, Summary: e.File.File, SubType: "normal"})
		case *message.AtElement:
			log.Debugf("At user: %s", e.Target)
			if uid, err := strconv.ParseInt(e.Target, 10, 64); err == nil {
				elements = append(elements, &milky.AtElement{UserID: uid})
			}
		case *message.ReplyElement:
			if seq, err := strconv.ParseInt(e.ReplySeq, 10, 64); err == nil {
				elements = append(elements, &milky.ReplyElement{MessageSeq: seq})
			}
		case *message.RecordElement:
			log.Debugf("Record: %s", e.File.URL)
			elements = append(elements, &milky.RecordElement{URI: e.File.URL})
		case *message.PokeElement:
			continue
		default:
			log.Warnf("Unsupported message element type: %T", elem)
		}
	}
	return elements
}

func (pa *PlatformAdapterMilky) SendToPerson(ctx *MsgContext, uid string, text string, flag string) {
	log := zap.S().Named(logger.LogKeyAdapter)
	send := message.ConvertStringMessage(text)
	elements := ParseMessageToMilky(send)
	id, err := strconv.ParseInt(ExtractQQUserID(uid), 10, 64)
	if err != nil {
		log.Errorf("Invalid user ID %s: %v", uid, err)
		return
	}
	if len(elements) == 0 {
		log.Warnf("Skipping Milky private message to %s: no supported message elements", uid)
		return
	}
	ret, err := pa.IntentSession.SendPrivateMessage(id, &elements)
	if err != nil {
		log.Errorf("Failed to send private message to %s: %v", uid, err)
		return
	}
	pa.EndPoint.Session.OnMessageSend(ctx, &Message{
		Platform:    "QQ",
		MessageType: "private",
		Message:     text,
		Sender: SenderBase{
			UserID:   pa.EndPoint.UserID,
			Nickname: pa.EndPoint.Nickname,
		},
		RawID: ret.MessageSeq,
	}, flag)
}

func (pa *PlatformAdapterMilky) SendToGroup(ctx *MsgContext, groupID string, text string, flag string) {
	log := zap.S().Named(logger.LogKeyAdapter)
	send := message.ConvertStringMessage(text)
	elements := ParseMessageToMilky(send)
	id, err := strconv.ParseInt(ExtractQQGroupID(groupID), 10, 64)
	if err != nil {
		log.Errorf("Invalid group ID %s: %v", groupID, err)
		return
	}
	nudgeTargets := make([]int64, 0)
	for _, element := range send {
		poke, ok := element.(*message.PokeElement)
		if !ok {
			continue
		}
		userID, parseErr := strconv.ParseInt(poke.Target, 10, 64)
		if parseErr != nil || userID <= 0 {
			log.Warnf("Skipping invalid Milky group nudge target %q", poke.Target)
			continue
		}
		nudgeTargets = append(nudgeTargets, userID)
	}
	if len(elements) == 0 && len(nudgeTargets) == 0 {
		log.Warnf("Skipping Milky group message to %s: no supported message elements", groupID)
		return
	}
	var ret *milky.MessageRet
	if len(elements) == 0 {
		ret = &milky.MessageRet{}
	} else {
		ret, err = pa.IntentSession.SendGroupMessage(id, &elements)
	}
	if err != nil {
		log.Errorf("Failed to send group message to %s: %v", groupID, err)
		return
	}
	go func(targets []int64) {
		for _, userID := range targets {
			log.Debugf("Sending group Nudge: %d", userID)
			_ = pa.IntentSession.SendGroupNudge(id, userID)
			doSleepQQ(ctx)
		}
	}(nudgeTargets)
	pa.EndPoint.Session.OnMessageSend(ctx, &Message{
		Platform:    "QQ",
		MessageType: "group",
		Message:     text,
		GroupID:     groupID,
		Sender: SenderBase{
			UserID:   pa.EndPoint.UserID,
			Nickname: pa.EndPoint.Nickname,
		},
		RawID: ret.MessageSeq,
	}, flag)
}

func (*PlatformAdapterMilky) SendFileToPerson(_ *MsgContext, _ string, _ string, _ string) adapterapi.EffectResult {
	return adapterapi.UnsupportedResult("milky_private_file_send_unsupported")
}

type milkyGroupFileUploader interface {
	UploadGroupFile(groupID int64, fileURI string, fileName string, parentFolderID string) (string, error)
}

func uploadMilkyGroupFile(uploader milkyGroupFileUploader, groupID int64, fileURI string, fileName string) (adapterapi.EffectResult, error) {
	fileID, err := uploader.UploadGroupFile(groupID, fileURI, fileName, "")
	if err != nil {
		return adapterapi.AmbiguousResult("milky_file_upload_unconfirmed", "provider upload outcome is unknown"), err
	}
	if fileID == "" {
		return adapterapi.AmbiguousResult("milky_file_upload_unconfirmed", "provider returned no upload file ID"), nil
	}
	return adapterapi.SucceededResult(fileID), nil
}

func (pa *PlatformAdapterMilky) SendFileToGroup(_ *MsgContext, groupID string, path string, _ string) adapterapi.EffectResult {
	if pa == nil || pa.IntentSession == nil {
		return adapterapi.TerminalResult("milky_provider_unavailable", "Milky upload session is unavailable")
	}
	log := zap.S().Named(logger.LogKeyAdapter)
	id := ExtractQQGroupID(groupID)
	rawID, err := strconv.ParseInt(id, 10, 64)
	if err != nil || rawID <= 0 {
		if err != nil {
			log.Errorf("Invalid group ID %s: %v", groupID, err)
		} else {
			log.Errorf("Invalid group ID %s", groupID)
		}
		return adapterapi.UnsupportedResult("milky_invalid_group_id")
	}
	filename := filepath.Base(path)
	if parsed, parseErr := url.Parse(path); parseErr == nil && parsed.Scheme == "file" {
		filename = filepath.Base(parsed.Path)
	}
	result, err := uploadMilkyGroupFile(pa.IntentSession, rawID, path, filename)
	if err != nil {
		log.Errorf("Failed to send file to group %s: %v", groupID, err)
	} else if result.Outcome == adapterapi.EffectAmbiguous {
		log.Errorf("File upload to group %s was not confirmed: %s", groupID, result.Message)
	}
	return result
}

func (pa *PlatformAdapterMilky) QuitGroup(ctx *MsgContext, groupID string) {
	log := zap.S().Named(logger.LogKeyAdapter)
	id, err := strconv.ParseInt(ExtractQQGroupID(groupID), 10, 64)
	if err != nil {
		log.Errorf("Invalid group ID %s: %v", groupID, err)
		return
	}
	err = pa.IntentSession.QuitGroup(id)
	if err != nil {
		log.Errorf("Failed to quit group %s: %v", groupID, err)
		return
	}
	log.Infof("Successfully quit group %s", groupID)
}

func (pa *PlatformAdapterMilky) GetGroupMemberInfo(groupID string, userID string) (*milky.GroupMemberInfo, error) {
	return pa.getGroupMemberInfo(groupID, userID, false)
}

func (pa *PlatformAdapterMilky) getGroupMemberInfo(groupID string, userID string, noCache bool) (*milky.GroupMemberInfo, error) {
	if pa == nil || pa.IntentSession == nil {
		return nil, errors.New("milky session unavailable")
	}

	rawGroupID := strings.TrimSpace(ExtractQQGroupID(groupID))
	rawUserID := strings.TrimSpace(ExtractQQUserID(userID))
	if rawGroupID == "" || rawUserID == "" {
		return nil, errors.New("cannot resolve milky group/user id")
	}

	groupIDInt, err := strconv.ParseInt(rawGroupID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid milky group id %q: %w", groupID, err)
	}
	userIDInt, err := strconv.ParseInt(rawUserID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid milky user id %q: %w", userID, err)
	}

	return pa.IntentSession.GetGroupMemberInfo(groupIDInt, userIDInt, noCache)
}

func (pa *PlatformAdapterMilky) SetGroupCardName(ctx *MsgContext, cardName string) {
	log := zap.S().Named(logger.LogKeyAdapter)
	groupID := ctx.Group.GroupID
	rawGroupID := ExtractQQGroupID(groupID)
	rawGroupIDInt, err := strconv.ParseInt(rawGroupID, 10, 64)
	if err != nil {
		log.Errorf("Invalid group ID %s: %v", groupID, err)
		return
	}
	userID := ctx.Player.UserID
	rawUserID := ExtractQQUserID(userID)
	rawUserIDInt, err := strconv.ParseInt(rawUserID, 10, 64)
	if err != nil {
		log.Errorf("Invalid user ID %s: %v", userID, err)
		return
	}
	err = pa.IntentSession.SetGroupMemberCard(rawGroupIDInt, rawUserIDInt, cardName)
	if err != nil {
		log.Errorf("Failed to set group card name for %s in group %s: %v", userID, groupID, err)
	}
}

func (pa *PlatformAdapterMilky) MemberBan(_ string, _ string, _ int64) {}

func (pa *PlatformAdapterMilky) MemberKick(_ string, _ string) {}

func (pa *PlatformAdapterMilky) EditMessage(_ *MsgContext, _, _ string) {}

func (pa *PlatformAdapterMilky) RecallMessage(_ *MsgContext, _ string) {}

func ExtractQQUserID(id string) string {
	if strings.HasPrefix(id, "QQ:") {
		return id[len("QQ:"):]
	}
	return id
}

func ExtractQQGroupID(id string) string {
	if strings.HasPrefix(id, "QQ-Group:") {
		return id[len("QQ-Group:"):]
	}
	return id
}
