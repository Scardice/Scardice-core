package dice

import (
	"strconv"
	"strings"
	"sync"

	"github.com/google/uuid"

	"Scardice-core/adapterapi"
	"Scardice-core/message"
	"Scardice-core/utils"
)

type HTTPSimpleMessage struct {
	UID         string `json:"uid"`
	Message     string `json:"message"`
	MessageType string `json:"messageType"`
}

type HTTPMessageBatch struct {
	Cursor    string              `json:"cursor"`
	Messages  []HTTPSimpleMessage `json:"messages"`
	Truncated bool                `json:"truncated"`
}

const uiReplyHistoryLimit = 256

type PlatformAdapterHTTP struct {
	EndPoint *EndPointInfo

	mu             sync.Mutex
	recentMessages [uiReplyHistoryLimit]HTTPSimpleMessage
	replySequence  uint64
	replyStream    string
}

func newUIEndpoint(session *IMSession) *EndPointInfo {
	adapter := &PlatformAdapterHTTP{}
	endpoint := &EndPointInfo{Adapter: adapter}
	endpoint.Enable = true
	endpoint.Platform = "UI"
	endpoint.ID = "1"
	endpoint.State = StateConnected
	endpoint.UserID = "UI:1000"
	endpoint.Session = session
	adapter.EndPoint = endpoint
	return endpoint
}

// RecentMessagesSince 不消费共享记录，每个页面独立保存游标。
// 空游标只订阅后续回复；流标识让 core 重启后的旧游标可以恢复读取。
func (pa *PlatformAdapterHTTP) RecentMessagesSince(cursor string) HTTPMessageBatch {
	pa.mu.Lock()
	defer pa.mu.Unlock()
	if pa.replyStream == "" {
		pa.replyStream = uuid.NewString()
	}
	after := pa.replySequence
	truncated := false
	if cursor != "" {
		stream, sequence, ok := strings.Cut(cursor, ":")
		parsed, err := strconv.ParseUint(sequence, 10, 64)
		if !ok || err != nil || stream != pa.replyStream || parsed > pa.replySequence {
			after, truncated = 0, true
		} else {
			after = parsed
		}
	}
	if pa.replySequence > uiReplyHistoryLimit && after < pa.replySequence-uiReplyHistoryLimit {
		after, truncated = pa.replySequence-uiReplyHistoryLimit, true
	}
	messages := make([]HTTPSimpleMessage, 0, pa.replySequence-after)
	for sequence := after; sequence < pa.replySequence; sequence++ {
		messages = append(messages, pa.recentMessages[sequence%uiReplyHistoryLimit])
	}
	return HTTPMessageBatch{
		Cursor:    pa.replyStream + ":" + strconv.FormatUint(pa.replySequence, 10),
		Messages:  messages,
		Truncated: truncated,
	}
}

func (pa *PlatformAdapterHTTP) appendRecentMessages(ctx *MsgContext, uid, text, messageType string) {
	splitLength := 300
	if ctx != nil && ctx.uiTestSplitLengthSet {
		splitLength = ctx.uiTestSplitLength
	}
	parts := utils.SplitLongText(text, splitLength, utils.DefaultSplitPaginationHint)
	pa.mu.Lock()
	defer pa.mu.Unlock()
	for _, part := range parts {
		pa.recentMessages[pa.replySequence%uiReplyHistoryLimit] = HTTPSimpleMessage{UID: uid, Message: part, MessageType: messageType}
		pa.replySequence++
	}
}

func (pa *PlatformAdapterHTTP) SendSegmentToGroup(ctx *MsgContext, groupID string, msg []message.IMessageElement, flag string) {
}

func (pa *PlatformAdapterHTTP) SendSegmentToPerson(ctx *MsgContext, userID string, msg []message.IMessageElement, flag string) {
}

func (pa *PlatformAdapterHTTP) GetGroupInfoAsync(_ string) {}

func (pa *PlatformAdapterHTTP) SendToPerson(ctx *MsgContext, uid string, text string, flag string) {
	pa.appendRecentMessages(ctx, uid, text, "private")
	pa.EndPoint.Session.OnMessageSend(ctx, &Message{
		MessageType: "private",
		Platform:    "UI",
		Message:     text,
		Sender: SenderBase{
			UserID:   pa.EndPoint.UserID,
			Nickname: pa.EndPoint.Nickname,
		},
	}, flag)
}

func (pa *PlatformAdapterHTTP) SendToGroup(ctx *MsgContext, uid string, text string, flag string) {
	pa.appendRecentMessages(ctx, uid, text, "group")
	pa.EndPoint.Session.OnMessageSend(ctx, &Message{
		MessageType: "group",
		Platform:    "UI",
		Message:     text,
		GroupID:     uid,
		Sender: SenderBase{
			UserID:   pa.EndPoint.UserID,
			Nickname: pa.EndPoint.Nickname,
		},
	}, flag)
}

func (*PlatformAdapterHTTP) SendFileToPerson(_ *MsgContext, _ string, _ string, _ string) adapterapi.EffectResult {
	return adapterapi.UnsupportedResult("http_file_send_unsupported")
}

func (*PlatformAdapterHTTP) SendFileToGroup(_ *MsgContext, _ string, _ string, _ string) adapterapi.EffectResult {
	return adapterapi.UnsupportedResult("http_file_send_unsupported")
}

func (pa *PlatformAdapterHTTP) QuitGroup(_ *MsgContext, _ string) {}

func (pa *PlatformAdapterHTTP) SetGroupCardName(_ *MsgContext, _ string) {}

func (pa *PlatformAdapterHTTP) MemberBan(_ string, _ string, _ int64) {}

func (pa *PlatformAdapterHTTP) MemberKick(_ string, _ string) {}

func (pa *PlatformAdapterHTTP) EditMessage(_ *MsgContext, _, _ string) {}

func (pa *PlatformAdapterHTTP) RecallMessage(_ *MsgContext, _ string) {}
