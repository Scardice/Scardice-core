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
	logHistoryRangeMaxPageSize = 200 // SnowLuma/NapCat 等实现的单页上限
	logHistoryRangeMaxPages    = 200 // 单段最多翻 200 页，避免病态实现死循环
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
) ([]*Message, bool, error) {
	if toSeq <= fromSeq+1 {
		return nil, true, nil
	}
	anchor := toSeq
	lastOldest := int64(0)
	collected := make([]*Message, 0, historyRangeCapHint(fromSeq, toSeq))
	seen := make(map[int64]struct{}, historyRangeCapHint(fromSeq, toSeq))
	complete := false

	for page := 0; page < logHistoryRangeMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return historyRangeFilter(collected, fromSeq, toSeq), false, err
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
			return historyRangeFilter(collected, fromSeq, toSeq), false, err
		}
		if len(pageMsgs) == 0 {
			// 平台明确表示这一段没有更多历史（保留期/已删除/空群）。
			complete = true
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
			complete = true
			break
		}
		if lastOldest > 0 && oldest >= lastOldest {
			// 锚点没有前进，防止实现忽略参数时死循环。
			break
		}
		lastOldest = oldest
		next := oldest - 1
		if next <= fromSeq {
			complete = true
			break
		}
		anchor = next
	}
	return historyRangeFilter(collected, fromSeq, toSeq), complete, nil
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
) ([]*Message, bool, error) {
	anchor, hasAnchor := rawIDToInt64(req.ToRawID)
	lastOldest := int64(0)
	collected := make([]*Message, 0, historyRangeCapHint(req.FromSeq, req.ToSeq))
	seen := make(map[int64]struct{}, historyRangeCapHint(req.FromSeq, req.ToSeq))
	complete := false

	for page := 0; page < logHistoryRangeMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return historyRangeFilter(collected, req.FromSeq, req.ToSeq), false, err
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
			return historyRangeFilter(collected, req.FromSeq, req.ToSeq), false, err
		}
		if len(pageMsgs) == 0 {
			complete = true
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
			complete = true
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
	return historyRangeFilter(collected, req.FromSeq, req.ToSeq), complete, nil
}

func fetchOnebotRangeBySeq(
	ctx context.Context, req HistoryRangeRequest, fetch onebotHistoryPageFetcher,
) ([]*Message, bool, error) {
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
) ([]*Message, bool, error) {
	msgIDMsgs, msgIDComplete, msgIDErr := fetchOnebotRangeByMessageID(ctx, req, fetch)
	if msgIDErr == nil && msgIDComplete {
		return msgIDMsgs, true, nil
	}

	seqMsgs, seqComplete, seqErr := fetchOnebotRangeBySeq(ctx, req, fetch)
	if seqComplete {
		// 1119.fix1: seq 路径空页只能说明“这一页没有数据”，不能反过来
		// 给 message_id 路径的非空部分页升级成“已覆盖整段”。否则平台把
		// 瞬时空页/未知参数返回成空页时，会把部分结果误报为完成。
		if len(seqMsgs) == 0 && len(msgIDMsgs) > 0 {
			return msgIDMsgs, false, nil
		}
		return mergeHistoryRangeMessages(msgIDMsgs, seqMsgs), true, nil
	}

	merged := mergeHistoryRangeMessages(msgIDMsgs, seqMsgs)
	if len(merged) > 0 {
		// 有进展但没覆盖到起点：调用方必须保留 pending，不能把 maxSeq 当覆盖。
		return merged, false, nil
	}
	if msgIDErr != nil {
		return nil, false, msgIDErr
	}
	if seqErr != nil {
		return nil, false, seqErr
	}
	return nil, false, errLogGapHistoryNoProgress
}

// FetchGroupMsgHistoryRange 实现 HistoryRangeFetcher。
func (p *PlatformAdapterOnebot) FetchGroupMsgHistoryRange(
	ctx context.Context, req HistoryRangeRequest,
) ([]*Message, bool, error) {
	if p == nil || p.sendEmitter == nil {
		return nil, false, errors.New("emitter 未初始化")
	}
	gid := ExtractQQEmitterGroupID(req.GroupID)
	if gid == 0 {
		return nil, false, fmt.Errorf("无效的群ID: %s", req.GroupID)
	}
	if req.ToSeq <= req.FromSeq+1 {
		return nil, true, nil
	}

	// 闭包补上真实 group_id；自由函数只负责翻页策略，便于单测注入方言。
	fetch := func(ctx context.Context, params onebotHistoryParams) ([]*Message, error) {
		params.GroupID = gid
		return p.fetchOnebotHistoryPage(ctx, req.GroupID, gid, params)
	}
	return fetchOnebotHistoryRange(ctx, req, fetch)
}
