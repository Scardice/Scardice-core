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

// HistoryRangeResult 描述一次区间拉取的覆盖状态。
//
// 1119 只用 complete 一个 bool，导致“部分页非空”和“平台明确没有更早历史”
// 混在一起，调用方无法判断能否前移 pending。1120 拆成两个明确事实：
//   - ReachedStart：已经取到 (FromSeq, ToSeq) 的左边界，整段扫描完成；
//   - Boundary：平台明确表示没有更早历史（保留期/空群/消息已删除），
//     即使没到左边界，本段也可视为“平台能给的就这些”。首屏即空页时不
//     置位（无法区分真实空群和瞬时失败），调用方保留 pending。
//
// 两者都为 false 表示“还没扫完，且平台没有给出边界”，调用方必须保留
// pending 并退避，不能把已取到消息的最大 seq 当成整段覆盖。
type HistoryRangeResult struct {
	Messages     []*Message
	ReachedStart bool
	Boundary     bool
}

// HistoryRangeFetcher 是 HistoryFetcher 的可选增强：适配器自己负责按平台
// 语义翻页（message_id + reverse_order、message_seq 向旧等），返回
// (FromSeq, ToSeq) 内能拿到的消息，并报告覆盖状态。
type HistoryRangeFetcher interface {
	FetchGroupMsgHistoryRange(ctx context.Context, req HistoryRangeRequest) (HistoryRangeResult, error)
}

// HistoryLatestSeqFetcher 是启动对账的可选能力：不依赖新消息，直接取当前
// 群最新历史消息的 seq 与 raw id。用于核心重启后 10s 主动发现离线缺口；
// 未实现或平台不支持时跳过，仍由下一条群消息触发补全。
type HistoryLatestSeqFetcher interface {
	FetchLatestHistorySeq(ctx context.Context, groupID string) (seq int64, rawID interface{}, err error)
}
