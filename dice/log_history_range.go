package dice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/bytedance/sonic"

	emitter "Scardice-core/dice/imsdk/onebot"
)

// errLogGapHistoryNoProgress 表示适配器既没有拿到区间内的消息，也没有取得
// 任何可用的翻页进度。调用方必须保留 pending 并退避，不能把“拿到了最新一页”
// 当成补全完成。
var errLogGapHistoryNoProgress = errors.New("历史拉取没有取得可用的进度")

const (
	logHistoryRangePageSize    = 100
	logHistoryRangeMaxPageSize = 200  // SnowLuma/NapCat 等实现的单页上限
	logHistoryRangeMaxPages    = 2000 // 单次最多翻 2000 页；5000 缺口在 19/页下约 264 页
)

// rawIDToInt64 把各平台 Message.RawID 的常见表示转成 int64。
// OneBot 的 message_id 可能是 int64/字符串；SnowLuma 是 signed int32 hash；
// JSON 反序列化后也可能是 float64 或 json.Number。
func rawIDToInt64(v interface{}) (int64, bool) {
	switch x := v.(type) {
	case nil:
		return 0, false
	case int:
		return int64(x), true
	case int8:
		return int64(x), true
	case int16:
		return int64(x), true
	case int32:
		return int64(x), true
	case int64:
		return x, true
	case uint:
		if uint64(x) > math.MaxInt64 {
			return 0, false
		}
		return int64(x), true
	case uint8:
		return int64(x), true
	case uint16:
		return int64(x), true
	case uint32:
		return int64(x), true
	case uint64:
		if x > math.MaxInt64 {
			return 0, false
		}
		return int64(x), true
	case float32:
		return rawFloatToInt64(float64(x))
	case float64:
		return rawFloatToInt64(x)
	case json.Number:
		i, err := strconv.ParseInt(string(x), 10, 64)
		return i, err == nil
	case string:
		s := strings.TrimSpace(x)
		if s == "" {
			return 0, false
		}
		i, err := strconv.ParseInt(s, 10, 64)
		return i, err == nil
	case []byte:
		return rawIDToInt64(string(x))
	default:
		return rawIDToInt64(fmt.Sprintf("%v", v))
	}
}

func rawFloatToInt64(f float64) (int64, bool) {
	if math.IsNaN(f) || math.IsInf(f, 0) || f != math.Trunc(f) ||
		f < float64(math.MinInt64) || f > float64(math.MaxInt64) {
		return 0, false
	}
	return int64(f), true
}

func sortMessagesBySeq(msgs []*Message) {
	sort.SliceStable(msgs, func(i, j int) bool {
		if msgs[i] == nil {
			return false
		}
		if msgs[j] == nil {
			return true
		}
		return msgs[i].Seq < msgs[j].Seq
	})
}

// historyRangeFilter 只保留 (fromSeq, toSeq) 内、seq 可用的消息，按 seq 升序去重。
func historyRangeFilter(msgs []*Message, fromSeq, toSeq int64) []*Message {
	out := make([]*Message, 0, len(msgs))
	seen := make(map[int64]struct{}, len(msgs))
	for _, m := range msgs {
		if m == nil || m.Seq <= fromSeq || m.Seq >= toSeq {
			continue
		}
		if _, ok := seen[m.Seq]; ok {
			continue
		}
		seen[m.Seq] = struct{}{}
		out = append(out, m)
	}
	sortMessagesBySeq(out)
	return out
}

// historyRangeOldestSeq 返回消息集合中的最小 seq；空集合返回 0。
func historyRangeOldestSeq(msgs []*Message) int64 {
	var oldest int64
	for _, m := range msgs {
		if m == nil || m.Seq <= 0 {
			continue
		}
		if oldest == 0 || m.Seq < oldest {
			oldest = m.Seq
		}
	}
	return oldest
}

// mergeHistoryRangeMessages 合并两条翻页路径的结果，按 seq 去重后升序返回。
// 1119.fix1: message_id 路径与 message_seq 回退路径可能各拿到一部分区间，
// 不能因为 message_id 路径“非空”就完全丢弃 seq 路径的结果。
func mergeHistoryRangeMessages(lists ...[]*Message) []*Message {
	total := 0
	for _, list := range lists {
		total += len(list)
	}
	out := make([]*Message, 0, total)
	seen := make(map[int64]struct{}, total)
	for _, list := range lists {
		for _, m := range list {
			if m == nil || m.Seq <= 0 {
				continue
			}
			if _, ok := seen[m.Seq]; ok {
				continue
			}
			seen[m.Seq] = struct{}{}
			out = append(out, m)
		}
	}
	sortMessagesBySeq(out)
	return out
}

func historyRangeCapHint(fromSeq, toSeq int64) int {
	n := toSeq - fromSeq
	if n <= 0 {
		return 0
	}
	if n > 4096 {
		n = 4096
	}
	return int(n)
}

// fetchHistoryBySeqBackward 实现“锚点是窗口终点、向旧翻页”的通用分页，
// 适配 go-cqhttp 的 message_seq 语义，也用于 pureonebot 在 message_id 不可用
// 时的回退路径。
//
// fetch(anchor, count) 必须返回“以 anchor 为终点、向旧最多 count 条”的消息，
// 包含 anchor 本身也可以（按 seq 去重）。
func fetchHistoryBySeqBackward(
	ctx context.Context,
	fromSeq, toSeq int64,
	fetch func(context.Context, int64, int) ([]*Message, error),
) ([]*Message, bool, bool, error) {
	if toSeq <= fromSeq+1 {
		return nil, true, false, nil
	}
	anchor := toSeq
	lastOldest := int64(0)
	collected := make([]*Message, 0, historyRangeCapHint(fromSeq, toSeq))
	seen := make(map[int64]struct{}, historyRangeCapHint(fromSeq, toSeq))
	reachedStart := false
	boundary := false

	for page := range logHistoryRangeMaxPages {
		if err := ctx.Err(); err != nil {
			return historyRangeFilter(collected, fromSeq, toSeq), false, false, err
		}
		count := logHistoryRangePageSize
		if page == 0 {
			// 首屏多取一条：anchor 自身 + 缺口。go-cqhttp 会忽略 count，
			// 其它实现会按 count 返回；两种都不会影响后续翻页。
			want := int(toSeq - fromSeq)
			if want < 1 {
				want = 1
			}
			if want > logHistoryRangeMaxPageSize {
				want = logHistoryRangeMaxPageSize
			}
			count = want
		}

		pageMsgs, err := fetch(ctx, anchor, count)
		if err != nil {
			return historyRangeFilter(collected, fromSeq, toSeq), false, false, err
		}
		if len(pageMsgs) == 0 {
			// 向旧翻页实现返回空页：只有已经取到过消息时才视为“平台没有
			// 更早历史”。首屏就是空页时无法区分“确实空群/保留期截断”和
			// “平台瞬时失败返回空”，按 fail-closed 保留 pending。
			if len(collected) > 0 {
				boundary = true
			}
			break
		}

		sortMessagesBySeq(pageMsgs)
		oldest := int64(0)
		for _, m := range pageMsgs {
			if m == nil || m.Seq <= 0 {
				continue
			}
			if oldest == 0 || m.Seq < oldest {
				oldest = m.Seq
			}
			if _, ok := seen[m.Seq]; ok {
				continue
			}
			seen[m.Seq] = struct{}{}
			collected = append(collected, m)
		}
		if oldest == 0 {
			// 没有任何可用 seq：不能继续翻页，交给调用方保留 pending。
			break
		}
		if oldest <= fromSeq+1 {
			reachedStart = true
			break
		}
		if lastOldest > 0 && oldest >= lastOldest {
			// 锚点没有前进，防止实现忽略参数时死循环。
			break
		}
		lastOldest = oldest
		next := oldest - 1
		if next <= fromSeq {
			reachedStart = true
			break
		}
		anchor = next
	}
	return historyRangeFilter(collected, fromSeq, toSeq), reachedStart, boundary, nil
}

// onebotHistoryParams 同时覆盖两种主流 get_group_msg_history 方言：
//   - message_id + reverse_order：SnowLuma / Lagrange / LLOneBot 等；
//   - message_seq：go-cqhttp / NapCat 等。
//
// 用 omitempty 保证不会给只认其中一种的实现传多余的 0 值参数。
type onebotHistoryParams struct {
	GroupID      int64 `json:"group_id"`
	MessageID    int64 `json:"message_id,omitempty"`
	MessageSeq   int64 `json:"message_seq,omitempty"`
	Count        int   `json:"count,omitempty"`
	ReverseOrder *bool `json:"reverse_order,omitempty"`
}

type onebotHistoryRawRes struct {
	Status  string `json:"status"`
	Retcode int    `json:"retcode"`
	Data    struct {
		Messages []sonic.NoCopyRawMessage `json:"messages"`
	} `json:"data"`
}

func (p *PlatformAdapterOnebot) fetchOnebotHistoryPage(
	ctx context.Context, groupID string, gid int64, params onebotHistoryParams,
) ([]*Message, error) {
	raw, err := p.sendEmitter.Raw(ctx, emitter.ACTION_GET_GROUP_MSG_HISTORY, params)
	if err != nil {
		return nil, err
	}
	var res onebotHistoryRawRes
	if err := sonic.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("解析 get_group_msg_history 响应失败: %w", err)
	}
	if strings.EqualFold(res.Status, "failed") || res.Retcode != 0 {
		return nil, fmt.Errorf("get_group_msg_history 返回错误: retcode=%d status=%s", res.Retcode, res.Status)
	}

	messages := make([]*Message, 0, len(res.Data.Messages))
	for _, rawMsg := range res.Data.Messages {
		msg, err := arrayByte2ScardiceMessage(p.logger, rawMsg)
		if err != nil {
			if p.logger != nil {
				p.logger.Warnf("历史消息解析失败: %v", err)
			}
			continue
		}
		if msg.GroupID == "" {
			msg.GroupID = canonicalOnebotGroupID(groupID)
			msg.MessageType = "group"
		}
		messages = append(messages, msg)
	}
	return messages, nil
}

// onebotHistoryPageFetcher 抽象一次 get_group_msg_history 调用，便于测试
// 直接注入 SnowLuma / go-cqhttp 两种方言，而不需要构造完整 Emitter。
type onebotHistoryPageFetcher func(context.Context, onebotHistoryParams) ([]*Message, error)

// fetchOnebotRangeByMessageID 按 message_id + reverse_order=true 从 ToRawID
// 向旧翻页。这是 SnowLuma 的实际语义；如果实现忽略 message_id，会在第一页
// 后因 oldest 不前进而退出，由调用方回退到 message_seq。
func fetchOnebotRangeByMessageID(
	ctx context.Context, req HistoryRangeRequest, fetch onebotHistoryPageFetcher,
) ([]*Message, bool, bool, error) {
	anchor, hasAnchor := rawIDToInt64(req.ToRawID)
	lastOldest := int64(0)
	collected := make([]*Message, 0, historyRangeCapHint(req.FromSeq, req.ToSeq))
	seen := make(map[int64]struct{}, historyRangeCapHint(req.FromSeq, req.ToSeq))
	reachedStart := false
	boundary := false

	for page := range logHistoryRangeMaxPages {
		if err := ctx.Err(); err != nil {
			return historyRangeFilter(collected, req.FromSeq, req.ToSeq), false, false, err
		}
		count := logHistoryRangePageSize
		if page == 0 {
			want := int(req.ToSeq - req.FromSeq)
			if want < 1 {
				want = 1
			}
			if want > logHistoryRangeMaxPageSize {
				want = logHistoryRangeMaxPageSize
			}
			count = want
		}
		params := onebotHistoryParams{GroupID: 0, Count: count}
		if hasAnchor {
			params.MessageID = anchor
			reverse := true
			params.ReverseOrder = &reverse
		}
		pageMsgs, err := fetch(ctx, params)
		if err != nil {
			return historyRangeFilter(collected, req.FromSeq, req.ToSeq), false, false, err
		}
		if len(pageMsgs) == 0 {
			// message_id 方言的空页可能是“平台没有更早历史”，也可能是
			// 服务端瞬时失败后回退到空本地库。这里不把它当成可清除
			// pending 的边界；由调用方保留 pending，交给 seq 路径或重试。
			break
		}

		sortMessagesBySeq(pageMsgs)
		var oldest *Message
		for _, m := range pageMsgs {
			if m == nil || m.Seq <= 0 {
				continue
			}
			if oldest == nil || m.Seq < oldest.Seq {
				oldest = m
			}
			if _, ok := seen[m.Seq]; ok {
				continue
			}
			seen[m.Seq] = struct{}{}
			collected = append(collected, m)
		}
		if oldest == nil {
			break
		}
		if oldest.Seq <= req.FromSeq+1 {
			reachedStart = true
			break
		}
		if lastOldest > 0 && oldest.Seq >= lastOldest {
			break
		}
		lastOldest = oldest.Seq
		next, ok := rawIDToInt64(oldest.RawID)
		if !ok {
			break
		}
		anchor, hasAnchor = next, true
	}
	return historyRangeFilter(collected, req.FromSeq, req.ToSeq), reachedStart, boundary, nil
}

func fetchOnebotRangeBySeq(
	ctx context.Context, req HistoryRangeRequest, fetch onebotHistoryPageFetcher,
) ([]*Message, bool, bool, error) {
	return fetchHistoryBySeqBackward(ctx, req.FromSeq, req.ToSeq,
		func(ctx context.Context, anchor int64, count int) ([]*Message, error) {
			return fetch(ctx, onebotHistoryParams{
				MessageSeq: anchor,
				Count:      count,
			})
		})
}

// fetchOnebotHistoryRange 是 OneBot 区间拉取的策略入口：
//   - 先按 message_id + reverse_order 向旧翻页（SnowLuma/Lagrange）；
//   - 只要 message_id 路径没有完整覆盖起点，就再试 message_seq 向旧翻页
//     （go-cqhttp 及只认 message_seq 的实现）；
//   - 两条路径都未完成时合并各自结果，交给调用方按 fail-closed 处理。
//
// 1119 的旧实现对“message_id 路径返回了非空部分页”直接 return，导致
// go-cqhttp 这类忽略 message_id 的实现永远走不到 seq 回退；1119.fix1 修复。
func fetchOnebotHistoryRange(
	ctx context.Context, req HistoryRangeRequest, fetch onebotHistoryPageFetcher,
) (HistoryRangeResult, error) {
	msgIDMsgs, msgIDReached, msgIDBoundary, msgIDErr := fetchOnebotRangeByMessageID(ctx, req, fetch)
	if msgIDErr == nil && msgIDReached {
		return HistoryRangeResult{Messages: msgIDMsgs, ReachedStart: true, Boundary: msgIDBoundary}, nil
	}

	seqMsgs, seqReached, seqBoundary, seqErr := fetchOnebotRangeBySeq(ctx, req, fetch)
	result := HistoryRangeResult{
		Messages:     mergeHistoryRangeMessages(msgIDMsgs, seqMsgs),
		ReachedStart: msgIDReached || seqReached,
		Boundary:     msgIDBoundary || seqBoundary,
	}
	if seqBoundary {
		// seq 路径的空页不能给 message_id 路径的非空部分页升级边界。
		if len(seqMsgs) == 0 && len(msgIDMsgs) > 0 {
			result.Boundary = msgIDBoundary
		} else if len(seqMsgs) > 0 && len(msgIDMsgs) > 0 &&
			historyRangeOldestSeq(seqMsgs) >= historyRangeOldestSeq(msgIDMsgs) {
			// seq 路径没有比 message_id 路径更靠前，不能仅凭它的一条
			// 空页就宣布平台边界。
			result.Boundary = msgIDBoundary
		}
	}
	if result.ReachedStart || result.Boundary || len(result.Messages) > 0 {
		return result, nil
	}
	if msgIDErr != nil {
		return HistoryRangeResult{}, msgIDErr
	}
	if seqErr != nil {
		return HistoryRangeResult{}, seqErr
	}
	return HistoryRangeResult{}, errLogGapHistoryNoProgress
}

// FetchGroupMsgHistoryRange 实现 HistoryRangeFetcher。
func (p *PlatformAdapterOnebot) FetchGroupMsgHistoryRange(
	ctx context.Context, req HistoryRangeRequest,
) (HistoryRangeResult, error) {
	if p == nil || p.sendEmitter == nil {
		return HistoryRangeResult{}, errors.New("emitter 未初始化")
	}
	gid := ExtractQQEmitterGroupID(req.GroupID)
	if gid == 0 {
		return HistoryRangeResult{}, fmt.Errorf("无效的群ID: %s", req.GroupID)
	}
	if req.ToSeq <= req.FromSeq+1 {
		return HistoryRangeResult{ReachedStart: true}, nil
	}

	// 闭包补上真实 group_id；自由函数只负责翻页策略，便于单测注入方言。
	fetch := func(ctx context.Context, params onebotHistoryParams) ([]*Message, error) {
		params.GroupID = gid
		return p.fetchOnebotHistoryPage(ctx, req.GroupID, gid, params)
	}
	return fetchOnebotHistoryRange(ctx, req, fetch)
}

// FetchLatestHistorySeq 取当前群最新一条历史消息的 seq/raw id。
// SnowLuma 的 message_id=0 表示最新页；只取 1 条。
func (p *PlatformAdapterOnebot) FetchLatestHistorySeq(ctx context.Context, groupID string) (int64, interface{}, error) {
	if p == nil || p.sendEmitter == nil {
		return 0, nil, errors.New("emitter 未初始化")
	}
	gid := ExtractQQEmitterGroupID(groupID)
	if gid == 0 {
		return 0, nil, fmt.Errorf("无效的群ID: %s", groupID)
	}
	msgs, err := p.fetchOnebotHistoryPage(ctx, groupID, gid, onebotHistoryParams{Count: 1})
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
