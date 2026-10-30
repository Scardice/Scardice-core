package dice

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/sacOO7/gowebsocket"

	"Scardice-core/adapterapi"
	"Scardice-core/message"
	"Scardice-core/utils/procs"
)

/* 定义结构体 */

type PlatformAdapterWalleQ struct {
	EndPoint        *EndPointInfo       `json:"-"               yaml:"-"`
	Socket          *gowebsocket.Socket `json:"-"               yaml:"-"`
	ConnectURL      string              `json:"connectUrl"      yaml:"connectUrl"`      // 连接地址
	UseInPackWalleQ bool                `json:"useInPackWalleQ" yaml:"useInPackWalleQ"` // 是否使用内置的WalleQ
	WalleQState     int                 `json:"loginState"      yaml:"-"`               // 当前状态
	CurLoginIndex   int                 `json:"curLoginIndex"   yaml:"-"`               // 当前登录序号，如果正在进行的登录不是该Index，证明过时

	WalleQProcess           *procs.Process `json:"-"                    yaml:"-"`
	WalleQLoginFailedReason string         `json:"curLoginFailedReason" yaml:"-"` // 当前登录失败原因

	WalleQLoginVerifyCode    string `json:"WalleQLoginVerifyCode"    yaml:"-"`
	WalleQLoginDeviceLockURL string `json:"WalleQLoginDeviceLockUrl" yaml:"-"`
	WalleQQrcodeData         []byte `json:"-"                        yaml:"-"` // 二维码数据

	WalleQLastAutoLoginTime  int64 `json:"-"                          yaml:"inPackGoCqLastAutoLoginTime"` // 上次自动重新登录的时间
	WalleQLoginSucceeded     bool  `json:"-"                          yaml:"inPackWalleQLoginSucceeded"`  // 是否登录成功过
	WalleQLastRestrictedTime int64 `json:"inPackWalleQLastRestricted" yaml:"inPackWalleQLastRestricted"`  // 上次风控时间

	InPackWalleQProtocol       int      `json:"inPackWalleQProtocol" yaml:"inPackWalleQProtocol"`
	InPackWalleQPassword       string   `json:"-"                    yaml:"inPackWalleQPassword"`
	DiceServing                bool     `yaml:"-"`                                               // 是否正在连接中
	InPackWalleQDisconnectedCH chan int `json:"-"                    yaml:"-"`                   // 信号量，用于关闭连接
	IgnoreFriendRequest        bool     `json:"ignoreFriendRequest"  yaml:"ignoreFriendRequest"` // 忽略好友请求处理开关

	echoMap        *SyncMap[string, chan *EventWalleQBase] `yaml:"-"`
	FileMap        *SyncMap[string, string]                // 记录上传文件后得到的 id
	Implementation string                                  `json:"implementation" yaml:"implementation"`
}

type EventWalleQBase struct {
	ID         string  `json:"id"`          // 事件唯一标识符
	Self       Self    `json:"self"`        // 机器人自身标识
	Time       float64 `json:"time"`        // 事件发生时间（Unix 时间戳），单位：秒
	Type       string  `json:"type"`        // meta、message、notice、request 中的一个，分别表示元事件、消息事件、通知事件和请求事件
	DetailType string  `json:"detail_type"` // 详细
	SubType    string  `json:"sub_type"`    // 子类型
	// 下面这些虽然不是共有字段 但基本也算
	UserID    string `json:"user_id"`
	UserName  string `json:"user_name"`
	UserCard  string `json:"user_card"` // 群名片
	GroupID   string `json:"group_id"`
	GroupName string `json:"group_name"`
	GuildID   string `json:"guild_id"`
	ChannelID string `json:"channel_id"`
}

type Bot struct {
	Self   Self `json:"self"`
	Online bool `json:"online"`
}

// EventWalleQMeta 元事件特有字段
type EventWalleQMeta struct {
	Version struct {
		Impl          string `json:"impl"`
		Version       string `json:"version"`
		OneBotVersion string `json:"onebot_version"`
	} `json:"version"`
	Status struct {
		Good bool  `json:"good"`
		Bots []Bot `json:"bots"`
	} `json:"status"`
}

// EventWalleQMsg 消息事件特有字段
type EventWalleQMsg struct {
	MessageID  string           `json:"message_id"`  // 消息id
	Message    []MessageSegment `json:"message"`     // 消息段
	AltMessage string           `json:"alt_message"` // 文本化
}

// EventWalleQNotice 通知事件特有字段
type EventWalleQNotice struct {
	MessageID  string `json:"message_id"`  // 消息id
	OperatorID string `json:"operator_id"` // 操作者账号
	ReceiverID string `json:"receiver_id"` // 戳一戳的接收者
	Duration   int64  `json:"duration"`
}

// EventWalleQReq 请求事件特有字段
type EventWalleQReq struct {
	Message     string `json:"message"`
	RequestID   int64  `json:"request_id"` // 请求者
	Suspicious  bool   `json:"suspicious"`
	InvitorID   string `json:"invitor_id"`   // 邀请者
	InvitorName string `json:"invitor_name"` // 邀请者名
}

type Self struct {
	Platform string `json:"platform"`
	UserID   string `json:"user_id"`
}

type MessageSegment struct {
	Type string `json:"type"`
	Data MSData `json:"data"`
}

type MSData struct {
	ID        int64   `json:"id,omitempty"`
	Text      string  `json:"text,omitempty"`
	UserID    string  `json:"user_id,omitempty"`
	UserName  string  `json:"user_name,omitempty"`
	Face      string  `json:"face,omitempty"`
	MessageID string  `json:"message_id,omitempty"`
	FileID    string  `json:"fileId,omitempty"`
	Time      float64 `json:"time,omitempty"`
	URL       string  `json:"url,omitempty"`
}

type EchoWalleQ struct {
	Status  string `json:"status"`
	RetCode int64  `json:"retcode"`
	// 先简单处理一下
	Data    map[string]interface{} `json:"data"`
	Message string                 `json:"message"`
	Echo    string                 `json:"echo"`
}

type LastWelcomeInfoWQ struct {
	UserID  string
	GroupID string
	Time    float64
}

type OneBotV12Command struct {
	Action string      `json:"action"`
	Params interface{} `json:"params"`
	Echo   string      `json:"echo"`
}

type OnebotV12UserInfo struct {
	// 个人信息
	Nickname string `json:"nickname"`
	UserID   string `json:"user_id"`

	// 群信息
	GroupID         string `json:"group_id"`          // 群号
	GroupCreateTime uint32 `json:"group_create_time"` // 群号
	MemberCount     int64  `json:"member_count"`
	GroupName       string `json:"group_name"`
	MaxMemberCount  int32  `json:"max_member_count"`
	Card            string `json:"card"`
}

/* 标准方法实现 */

func (pa *PlatformAdapterWalleQ) GetGroupInfoAsync(id string) {
	type GroupMessageParams struct {
		GroupID string `json:"group_id"`
	}
	realGroupID, idType := pa.mustExtractID(id)
	if idType != QQUidGroup {
		return
	}

	a, _ := json.Marshal(OneBotV12Command{
		"get_group_info",
		GroupMessageParams{
			realGroupID,
		},
		"get_group_info",
	})

	socketSendText(pa.Socket, string(a))
}

func (pa *PlatformAdapterWalleQ) SendSegmentToGroup(ctx *MsgContext, groupID string, msg []message.IMessageElement, flag string) {
}

func (pa *PlatformAdapterWalleQ) SendSegmentToPerson(ctx *MsgContext, userID string, msg []message.IMessageElement, flag string) {
}

func (pa *PlatformAdapterWalleQ) SendToPerson(ctx *MsgContext, userID string, text string, flag string) {
	rawID, idType := pa.mustExtractID(userID)
	if idType != QQUidPerson {
		return
	}

	for _, i := range ctx.Dice.ExtList {
		if i.HasOnMessageSend() {
			i.CallOnMessageSend(ctx.Dice, ctx, &Message{
				Platform:    "QQ",
				Message:     text,
				MessageType: "private",
				Sender: SenderBase{
					UserID:   pa.EndPoint.UserID,
					Nickname: pa.EndPoint.Nickname,
				},
			}, flag)
		}
	}

	text = textAssetsConvert(text)
	texts := textSplit(text)
	for _, subText := range texts {
		pa.SendMessage(subText, "private", rawID, "")
		doSleepQQ(ctx)
	}
}

func (pa *PlatformAdapterWalleQ) SendToGroup(ctx *MsgContext, groupID string, text string, flag string) {
	if groupID == "" {
		return
	}
	rawID, idType := pa.mustExtractID(groupID)
	if idType == 0 {
		// pa.SendToChannelGroup(ctx, groupId, text, flag) wq 未实现
		return
	}

	// 触发扩展钩子
	if groupInfo, ok := ctx.Session.ServiceAtNew.Load(groupID); ok {
		msgToSend := &Message{
			Platform:    "QQ",
			Message:     text,
			MessageType: "group",
			GroupID:     groupID,
			Sender: SenderBase{
				UserID:   pa.EndPoint.UserID,
				Nickname: pa.EndPoint.Nickname,
			},
		}
		for _, wrapper := range groupInfo.GetActivatedExtList(ctx.Dice) {
			wrapper.CallOnMessageSend(ctx.Dice, ctx, msgToSend, flag)
		}
	}

	text = textAssetsConvert(text)
	texts := textSplit(text)

	for index, subText := range texts {
		pa.SendMessage(subText, "group", rawID, "")
		if len(texts) > 1 && index != 0 {
			doSleepQQ(ctx)
		}
	}
}

func (*PlatformAdapterWalleQ) SendFileToPerson(_ *MsgContext, _ string, _ string, _ string) adapterapi.EffectResult {
	return adapterapi.UnsupportedResult("walleq_file_send_unsupported")
}

func (*PlatformAdapterWalleQ) SendFileToGroup(_ *MsgContext, _ string, _ string, _ string) adapterapi.EffectResult {
	return adapterapi.UnsupportedResult("walleq_file_send_unsupported")
}

func (pa *PlatformAdapterWalleQ) QuitGroup(_ *MsgContext, id string) {
	groupID, idType := pa.mustExtractID(id)
	if idType != QQUidGroup {
		return
	}
	type GroupMessageParams struct {
		GroupID string `json:"group_id"`
	}

	a, _ := json.Marshal(oneBotCommand{
		Action: "leave_group",
		Params: GroupMessageParams{
			groupID,
		},
	})

	socketSendText(pa.Socket, string(a))
}

func (pa *PlatformAdapterWalleQ) SetGroupCardName(_ *MsgContext, _ string) {
	// wq 暂无该扩展 api
}

func (pa *PlatformAdapterWalleQ) MemberBan(groupID string, userID string, last int64) {
	type P struct {
		GroupID  string `json:"groupId"`
		UserID   string `json:"userId"`
		Duration int64  `json:"duration"`
	}
	a, _ := json.Marshal(&OneBotV12Command{
		Action: "ban_group_member",
		Params: P{
			groupID, userID, last,
		},
	})
	socketSendText(pa.Socket, string(a))
}

func (pa *PlatformAdapterWalleQ) MemberKick(groupID string, userID string) {
	type P struct {
		GroupID string `json:"groupId"`
		UserID  string `json:"userId"`
	}
	a, _ := json.Marshal(&OneBotV12Command{
		Action: "kick_group_member",
		Params: P{
			groupID, userID,
		},
	})
	socketSendText(pa.Socket, string(a))
}

func (pa *PlatformAdapterWalleQ) EditMessage(_ *MsgContext, _, _ string) {}

func (pa *PlatformAdapterWalleQ) RecallMessage(_ *MsgContext, _ string) {}

/* 扩展方法实现 */

func (pa *PlatformAdapterWalleQ) waitGroupMemberInfoEcho(echo string, beforeWait func()) *EventWalleQBase {
	// pa.echoList = append(pa.echoList, )
	ch := make(chan *EventWalleQBase, 1)

	if pa.echoMap == nil {
		pa.echoMap = new(SyncMap[string, chan *EventWalleQBase])
	}
	pa.echoMap.Store(echo, ch)

	beforeWait()
	return <-ch
}

// func (pa *PlatformAdapterWalleQ) waitEcho2(echo string, value interface{}, beforeWait func(emi *echoMapInfo)) error {
//	if pa.echoMap2 == nil {
//		pa.echoMap2 = InitializeSyncMap[string, *echoMapInfo]()
//	}
//
//	emi := &echoMapInfo{ch: make(chan string, 1)}
//	beforeWait(emi)
//
//	pa.echoMap2.Store(echo, emi)
//	val := <-emi.ch
//	if val == "" {
//		return errors.New("超时")
//	}
//	return json.Unmarshal([]byte(val), value)
// }

// SendMessage 原始的发消息 API
func (pa *PlatformAdapterWalleQ) SendMessage(text string, ty string, id string, cid string) {
	type Params struct {
		DetailType string           `json:"detail_type"`
		GroupID    string           `json:"group_id,omitempty"`
		UserID     string           `json:"user_id,omitempty"`
		GuildID    string           `json:"guild_id,omitempty"`
		ChannelID  string           `json:"channel_id,omitempty"`
		Message    []MessageSegment `json:"message"`
	}
	var (
		uid  string
		gid  string
		g2id string // 2级群组 wq 未实现
	)
	switch ty {
	case "private":
		uid = id
	case "group":
		gid = id
	case "channel":
		g2id = id
	}
	a, _ := json.Marshal(OneBotV12Command{
		Action: "send_message",
		Echo:   "send_message",
		Params: Params{
			DetailType: ty,
			GroupID:    gid,
			UserID:     uid,
			GuildID:    g2id,
			ChannelID:  cid,
			Message:    pa.TextToMessageSegment(text),
		},
	})
	socketSendText(pa.Socket, string(a))
}

// GetLoginInfo 获取登录号信息
func (pa *PlatformAdapterWalleQ) GetLoginInfo() {
	a, _ := json.Marshal(OneBotV12Command{
		Action: "get_self_info",
		Echo:   "get_self_info",
		Params: &struct{}{},
	})
	socketSendText(pa.Socket, string(a))
}

// GetGroupMemberInfo 获取群成员信息
func (pa *PlatformAdapterWalleQ) GetGroupMemberInfo(groupID string, userID string) *OnebotV12UserInfo {
	type DetailParams struct {
		GroupID string `json:"group_id"`
		UserID  string `json:"user_id"`
	}

	echo := "get_group_member_info"
	a, _ := json.Marshal(OneBotV12Command{
		Action: "get_group_member_info",
		Params: DetailParams{
			GroupID: groupID,
			UserID:  userID,
		},
		Echo: echo,
	})

	d := pa.waitGroupMemberInfoEcho(echo, func() {
		socketSendText(pa.Socket, string(a))
	})

	return &OnebotV12UserInfo{
		Nickname: d.UserName,
		UserID:   d.UserID,
		GroupID:  d.GroupID,
		Card:     d.UserCard,
	}
}

// SetGroupAddRequest 同意加群
func (pa *PlatformAdapterWalleQ) SetGroupAddRequest(rid int64, gid string, accept bool) {
	type DetailParams struct {
		ReqID  int64  `json:"request_id"`
		UserID string `json:"user_id"`
		Accept bool   `json:"accept"`
	}

	a, _ := json.Marshal(oneBotCommand{
		Action: "set_group_invited",
		Params: DetailParams{
			rid, gid, accept,
		},
	})

	socketSendText(pa.Socket, string(a))
}

// SetFriendAddRequest 同意好友
func (pa *PlatformAdapterWalleQ) SetFriendAddRequest(reqID int64, userID string, accept bool) {
	type DetailParams struct {
		ReqID  int64  `json:"request_id"`
		UserID string `json:"user_id"`
		Accept bool   `json:"accept"`
	}

	a, _ := json.Marshal(struct {
		Action string       `json:"action"`
		Params DetailParams `json:"params"`
	}{
		"set_new_friend",
		DetailParams{
			reqID, userID, accept,
		},
	})

	socketSendText(pa.Socket, string(a))
}

// DeleteFriend 删除好友
func (pa *PlatformAdapterWalleQ) DeleteFriend(_ *MsgContext, id string) {
	friendID, idType := pa.mustExtractID(id)
	if idType != QQUidPerson {
		return
	}
	type GroupMessageParams struct {
		UserID string `json:"user_id"`
	}

	a, _ := json.Marshal(oneBotCommand{
		Action: "delete_friend",
		Params: GroupMessageParams{
			friendID,
		},
	})

	socketSendText(pa.Socket, string(a))
}

func (pa *PlatformAdapterWalleQ) UpVoiceFile(path string) {
	type P struct {
		Type     string `json:"type"`
		Path     string `json:"path,omitempty"`
		FileType string `json:"file_type"`
	}
	a, _ := json.Marshal(OneBotV12Command{
		Action: "upload_file",
		Echo:   "upload_file_voice",
		Params: P{"path", path, "voice"},
	})
	socketSendText(pa.Socket, string(a))
}

/** 格式化与反格式化 */

func MessageSegmentToText(ms []MessageSegment) string {
	var s string
	for _, i := range ms {
		switch i.Type {
		case "text":
			s += i.Data.Text
		case "mention":
			cq := CQCommand{
				Type: "at",
				Args: map[string]string{"qq": i.Data.UserID},
			}
			s += cq.Compile()
		case "mention_all":
			cq := CQCommand{
				Type: "at",
				Args: map[string]string{"qq": "all"},
			}
			s += cq.Compile()
		case "image":
			cq := CQCommand{
				Type: "image",
				Args: map[string]string{"file": i.Data.URL},
			}
			s += cq.Compile()
		case "voice":
			cq := CQCommand{
				Type: "voice",
				Args: map[string]string{"file": i.Data.FileID},
			}
			s += cq.Compile()
		case "audio": // 这个是音频文件 wq 未支持 or QQ 没有
		case "video":
			cq := CQCommand{
				Type: "voice",
				Args: map[string]string{"file": i.Data.FileID},
			}
			s += cq.Compile()
		case "file":
		case "location":
		case "reply":
			cq := CQCommand{
				Type: "reply",
				Args: map[string]string{"user_id": i.Data.UserID, "message_id": i.Data.MessageID},
			}
			s += cq.Compile()
		}
	}
	return s
}

func (pa *PlatformAdapterWalleQ) TextToMessageSegment(text string) []MessageSegment {
	arr := getCqCodePairs(text)
	var m []MessageSegment
	// 解析 cq 参数
	f := func(input string) map[string]string {
		pairs := strings.Split(input, ",")
		params := make(map[string]string)
		for _, pair := range pairs {
			kv := strings.Split(pair, "=")
			params[kv[0]] = kv[1]
		}
		return params
	}
	// 路径转换
	f2 := func(path string) string {
		if strings.HasPrefix(path, "http") || strings.HasPrefix(path, "base64") || strings.HasPrefix(path, "file:///") {
			return path
		}
		if filepath.IsAbs(path) {
			return "file:///" + path
		}
		pa2, err := filepath.Abs(path)
		if err != nil {
			pa.EndPoint.Session.Parent.Logger.Info("路径转换错误，将使用原路径", err)
			pa2 = path
		}
		return pa2
	}
	// 余烬码 转 cq 码 // 有点麻
	for _, i := range arr {
		if strings.HasPrefix(i, "[") { // 是 [ 开头的就转一下
			i = message.SealCodeToCqCode(i)
		}
		isCq := strings.HasPrefix(i, "[CQ")
		if isCq {
			i = i[4 : len(i)-1]
			j := strings.Index(i, ",")
			if j < 0 {
				panic("no comma in CQ code")
			}
			cqT := i[:j]
			i = i[:j]
			cqP := f(i)
			switch cqT {
			case "at":
				p := cqP["qq"]
				if p == "all" {
					m = append(m, MessageSegment{Type: "mention_all", Data: MSData{}})
				} else {
					m = append(m, MessageSegment{Type: "mention", Data: MSData{UserID: p}})
				}
				continue
			case "image":
				p := cqP["file"]
				p = f2(p)
				m = append(m, MessageSegment{"image", MSData{URL: p}})
				continue
			case "reply":
				p := cqP["id"]
				m = append(m, MessageSegment{"reply", MSData{MessageID: p}})
				continue
			case "record":
				continue
			}
		}
	}
	return m
}

// FormatDiceIDQQV12 QQ:122
func FormatDiceIDQQV12(diceWalleQ string) string {
	return fmt.Sprintf("QQ:%s", diceWalleQ)
}

// FormatDiceIDQQGroupV12 QQ-Group:122
func FormatDiceIDQQGroupV12(diceWalleQ string) string {
	return fmt.Sprintf("QQ-Group:%s", diceWalleQ)
}

func (pa *PlatformAdapterWalleQ) mustExtractID(id string) (string, QQUidType) {
	if strings.HasPrefix(id, "QQ:") {
		return id[len("QQ:"):], QQUidPerson
	}
	if strings.HasPrefix(id, "QQ-Group:") {
		return id[len("QQ-Group:"):], QQUidGroup
	}
	if strings.HasPrefix(id, "PG-QQ:") {
		return id[len("PG-QQ:"):], QQUidPerson
	}
	return "", 0
}

func getCqCodePairs(text string) []string {
	var res []string // 我感觉木落写过类似的函数，比如牌堆里，但是我没找到（
	start := 0
	for i := 0; i < len(text); i++ {
		if text[i] == '[' {
			if start != i {
				res = append(res, text[start:i])
			}
			end := strings.Index(text[i:], "]")
			if end == -1 {
				break
			}
			res = append(res, text[i:i+end+1])
			i += end
			start = i + 1
		}
	}
	if start < len(text) {
		res = append(res, text[start:])
	}
	return res
}
