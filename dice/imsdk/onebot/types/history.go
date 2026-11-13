package types

import (
	"github.com/bytedance/sonic"
)

type GetGroupMsgHistoryReq struct {
	GroupID    int64 `json:"group_id"`
	MessageSeq int64 `json:"message_seq"`
	Count      int   `json:"count"`
}

type GetGroupMsgHistoryRes struct {
	Messages []sonic.NoCopyRawMessage `json:"messages"`
}
