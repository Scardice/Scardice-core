package types

type GetGroupMsgHistoryReq struct {
	GroupID    int64 `json:"group_id"`
	MessageSeq int64 `json:"message_seq"`
	Count      int   `json:"count"`
}
