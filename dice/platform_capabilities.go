package dice

import "context"

// HistoryFetcher 历史消息拉取能力接口
// 平台适配器可选实现此接口以支持掉线期间的日志断层自动补全
type HistoryFetcher interface {
	// FetchGroupMsgHistory 拉取群历史消息
	// groupID: 群组标准ID（如 "QQ-Group:123456"）
	// fromSeq: 起始序号（不包含），拉取 fromSeq+1 开始的消息
	// count: 拉取条数
	// 返回消息列表（按时间升序），失败返回error
	FetchGroupMsgHistory(ctx context.Context, groupID string, fromSeq int64, count int) ([]*Message, error)
}
