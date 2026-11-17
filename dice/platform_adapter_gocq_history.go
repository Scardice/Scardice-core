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

// FetchGroupMsgHistory 实现 HistoryFetcher，供日志断层补全拉取群历史消息。
// 与 pureonebot 的语义保持一致：fromSeq 为已处理的最后一条，拉取 (fromSeq, toSeq) 区间。
func (pa *PlatformAdapterGocq) FetchGroupMsgHistory(ctx context.Context, groupID string, fromSeq int64, count int) ([]*Message, error) {
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
	gid := ExtractQQEmitterGroupID(groupID)
	if gid == 0 {
		return nil, fmt.Errorf("无效的群ID: %s", groupID)
	}
	if count <= 0 {
		return []*Message{}, nil
	}

	type params struct {
		GroupID    int64 `json:"group_id"`
		MessageSeq int64 `json:"message_seq"`
		Count      int   `json:"count"`
	}
	type response struct {
		Status  string `json:"status"`
		Retcode int    `json:"retcode"`
		Data    struct {
			Messages []json.RawMessage `json:"messages"`
		} `json:"data"`
	}

	echo := pa.getCustomEcho()
	payload, _ := json.Marshal(oneBotCommand{
		Action: "get_group_msg_history",
		Params: params{
			GroupID:    gid,
			MessageSeq: fromSeq + 1, // 该接口的 message_seq 为起始消息（包含）
			Count:      count,
		},
		Echo: echo,
	})

	var rsp response
	if err := pa.waitEcho2(echo, &rsp, func(_ *echoMapInfo) {
		socketSendText(pa.Socket, string(payload))
	}); err != nil {
		return nil, err
	}
	if rsp.Retcode != 0 {
		return nil, fmt.Errorf("get_group_msg_history 返回错误: retcode=%d status=%s", rsp.Retcode, rsp.Status)
	}

	logger := zap.S().Named(logger.LogKeyAdapter)

	messages := make([]*Message, 0, len(rsp.Data.Messages))
	for _, raw := range rsp.Data.Messages {
		var m MessageQQ
		var probe struct {
			Message json.RawMessage `json:"message"`
		}
		_ = json.Unmarshal(raw, &probe)
		if len(probe.Message) > 0 && probe.Message[0] == '[' {
			// 部分实现（napcat/lagrange）的历史消息使用消息段数组。
			if err := tryParseOneBot11ArrayMessage(logger, string(raw), &m); err != nil {
				logger.Warnf("历史消息解析失败: %v", err)
				continue
			}
		} else if err := json.Unmarshal(raw, &m); err != nil {
			logger.Warnf("历史消息解析失败: %v", err)
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
