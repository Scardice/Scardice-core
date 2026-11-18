package dice

import "context"

// HistoryFetcher 历史消息拉取能力接口。
//
// Deprecated: 单页接口无法表达平台的翻页方向。go-cqhttp 的 message_seq 是窗口
// 终点、向旧返回；SnowLuma/Lagrange 等实现只认 message_id；把两者都当成
// “fromSeq 之后”会导致丢缺口首条、漏掉离线 .log on，甚至把 off 段补进日志。
// 新实现应优先实现 HistoryRangeFetcher；两者都实现时后者优先。
type HistoryFetcher interface {
	// FetchGroupMsgHistory 拉取群历史消息（兼容旧实现）。
	// groupID: 群组标准ID（如 "QQ-Group:123456"）
	// fromSeq: 调用方假设的起点（不包含）
	// count: 拉取条数
	// 返回消息列表（按时间升序），失败返回error
	FetchGroupMsgHistory(ctx context.Context, groupID string, fromSeq int64, count int) ([]*Message, error)
}

// HistoryRangeRequest 描述一次按区间拉取历史的请求。
// FromSeq/ToSeq 是开区间 (FromSeq, ToSeq)，与日志补录窗口一致。
// FromRawID/ToRawID 是区间两端消息的平台原始 ID（可能为 nil）。
// Count 是期望的缺口条数，适配器可用它选择首屏大小。
type HistoryRangeRequest struct {
	GroupID   string
	FromSeq   int64
	ToSeq     int64
	Count     int
	FromRawID interface{}
	ToRawID   interface{}
}

// HistoryRangeFetcher 是 HistoryFetcher 的可选增强：适配器自己负责按平台
// 语义翻页（message_id + reverse_order、message_seq 向旧等），返回
// (FromSeq, ToSeq) 内能拿到的消息，并报告是否已经覆盖到区间起点或平台历史
// 边界。
//
// complete=true 表示调用方可以把本段视为已扫描完（包括“平台确实没有更多
// 历史/消息已删除”）；complete=false 表示还没扫到起点，调用方必须保留
// pending，不能用“拿到了最新一页”冒充补全完成。
type HistoryRangeFetcher interface {
	FetchGroupMsgHistoryRange(ctx context.Context, req HistoryRangeRequest) (msgs []*Message, complete bool, err error)
}
