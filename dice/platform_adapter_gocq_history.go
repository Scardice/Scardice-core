package dice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"go.uber.org/zap"

	"Scardice-core/logger"
)

type gocqHistoryParams struct {
	GroupID    int64 `json:"group_id"`
	MessageSeq int64 `json:"message_seq"`
	Count      int   `json:"count"`
}

type gocqHistoryResponse struct {
	Status  string `json:"status"`
	Retcode int    `json:"retcode"`
	Data    struct {
		Messages []json.RawMessage `json:"messages"`
	} `json:"data"`
}

// fetchGocqHistoryPage 拉取“以 anchorSeq 为窗口终点、向旧”的一页历史。
// 这是 go-cqhttp 的 get_group_msg_history 实际语义；并不要求 anchorSeq
// 对应的消息存在，窗口是 [anchorSeq-18, anchorSeq]（go-cqhttp 固定 19 条，
// 其它实现可能按 count 返回）。
func (pa *PlatformAdapterGocq) fetchGocqHistoryPage(ctx context.Context, gid, anchorSeq int64, count int) ([]*Message, error) {
	if ctx != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
	}
	if pa.Socket == nil {
		return nil, errors.New("gocq socket 未连接")
	}
	if count <= 0 {
		return []*Message{}, nil
	}

	echo := pa.getCustomEcho()
	payload, _ := json.Marshal(oneBotCommand{
		Action: "get_group_msg_history",
		Params: gocqHistoryParams{
			GroupID:    gid,
			MessageSeq: anchorSeq,
			Count:      count,
		},
		Echo: echo,
	})

	var rsp gocqHistoryResponse
	if err := pa.waitEcho2(echo, &rsp, func(_ *echoMapInfo) {
		socketSendText(pa.Socket, string(payload))
	}); err != nil {
		return nil, err
	}
	if rsp.Retcode != 0 {
		return nil, fmt.Errorf("get_group_msg_history 返回错误: retcode=%d status=%s", rsp.Retcode, rsp.Status)
	}

	log := zap.S().Named(logger.LogKeyAdapter)
	messages := make([]*Message, 0, len(rsp.Data.Messages))
	for _, raw := range rsp.Data.Messages {
		var m MessageQQ
		var probe struct {
			Message json.RawMessage `json:"message"`
		}
		_ = json.Unmarshal(raw, &probe)
		if len(probe.Message) > 0 && probe.Message[0] == '[' {
			// 部分实现（napcat/lagrange）的历史消息使用消息段数组。
			if err := tryParseOneBot11ArrayMessage(log, string(raw), &m); err != nil {
				log.Warnf("历史消息解析失败: %v", err)
				continue
			}
		} else if err := json.Unmarshal(raw, &m); err != nil {
			log.Warnf("历史消息解析失败: %v", err)
			continue
		}

		msg := m.toStdMessage()
		if msg.MessageType == "" {
			msg.MessageType = "group"
		}
		if msg.GroupID == "" {
			msg.GroupID = FormatDiceIDQQGroup(strconv.FormatInt(gid, 10))
			msg.MessageType = "group"
		}
		messages = append(messages, msg)
	}

	return messages, nil
}

// FetchGroupMsgHistory 是兼容旧实现的单页接口。
//
// Deprecated: 它的 fromSeq+1 语义只适合“起点在 fromSeq 之后”的正向实现，
// go-cqhttp/SnowLuma 都不是这个语义。日志补全已改用 FetchGroupMsgHistoryRange。
func (pa *PlatformAdapterGocq) FetchGroupMsgHistory(ctx context.Context, groupID string, fromSeq int64, count int) ([]*Message, error) {
	gid := ExtractQQEmitterGroupID(groupID)
	if gid == 0 {
		return nil, fmt.Errorf("无效的群ID: %s", groupID)
	}
	return pa.fetchGocqHistoryPage(ctx, gid, fromSeq+1, count)
}

// FetchGroupMsgHistoryRange 实现 HistoryRangeFetcher：
// 以 ToSeq 为锚点向旧翻页，直到覆盖 FromSeq+1 或平台没有更多历史。
func (pa *PlatformAdapterGocq) FetchGroupMsgHistoryRange(ctx context.Context, req HistoryRangeRequest) (HistoryRangeResult, error) {
	if pa == nil || pa.Socket == nil {
		return HistoryRangeResult{}, errors.New("gocq socket 未连接")
	}
	gid := ExtractQQEmitterGroupID(req.GroupID)
	if gid == 0 {
		return HistoryRangeResult{}, fmt.Errorf("无效的群ID: %s", req.GroupID)
	}
	msgs, reachedStart, boundary, err := fetchHistoryBySeqBackward(ctx, req.FromSeq, req.ToSeq,
		func(ctx context.Context, anchor int64, count int) ([]*Message, error) {
			return pa.fetchGocqHistoryPage(ctx, gid, anchor, count)
		})
	if err != nil {
		return HistoryRangeResult{}, err
	}
	return HistoryRangeResult{Messages: msgs, ReachedStart: reachedStart, Boundary: boundary}, nil
}

// FetchLatestHistorySeq 取 go-cqhttp 当前群最新一条历史消息。
// message_seq=0 表示从最新开始；实现忽略/不支持时返回空，由下一条消息触发。
func (pa *PlatformAdapterGocq) FetchLatestHistorySeq(ctx context.Context, groupID string) (int64, interface{}, error) {
	if pa == nil || pa.Socket == nil {
		return 0, nil, errors.New("gocq socket 未连接")
	}
	gid := ExtractQQEmitterGroupID(groupID)
	if gid == 0 {
		return 0, nil, fmt.Errorf("无效的群ID: %s", groupID)
	}
	msgs, err := pa.fetchGocqHistoryPage(ctx, gid, 0, 1)
	if err != nil {
		return 0, nil, err
	}
	var latest *Message
	for _, m := range msgs {
		if m != nil && m.Seq > 0 && (latest == nil || m.Seq > latest.Seq) {
			latest = m
		}
	}
	if latest == nil {
		return 0, nil, nil
	}
	return latest.Seq, latest.RawID, nil
}
