package dice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/golang-module/carbon"
	"github.com/pilagod/gorm-cursor-paginator/v2/paginator"
	ds "github.com/sealdice/dicescript"
	"github.com/tidwall/gjson"
	"go.uber.org/zap"

	"Scardice-core/dice/service"
	"Scardice-core/dice/storylog"
	"Scardice-core/message"
	"Scardice-core/model"
	"Scardice-core/utils/panicHandler"
)

var ErrGroupCardOverlong = errors.New("群名片长度超过限制")

func getGroupLogState(group *GroupInfo) GroupLogState {
	if group == nil {
		return GroupLogState{}
	}
	return group.GetLogState()
}

func getGroupLogName(group *GroupInfo) string {
	return getGroupLogState(group).Name
}

// suspendLogForBotOff 在 .bot off 让群变为“未激活”时自动执行 .log off：
// 只把 LogOn 置 false（不结束、不上传，LogCurID/LogCurName 保留），
// 并记下“这次关闭是 .bot off 自动造成的”，供 .bot on 自动开启。
// 返回是否真的关闭了（原本日志就是关的则返回 false）。
//
// 暂停时默认取消未完成的补全区间：掉线前的 pending 若留到 .bot on 之后，
// pending floor 会把关闭期间的聊天重新补进日志，违背“关闭段不补录”。
// 例外：如果 pending 正好是本次 .bot off 指令之前触发的掉线窗口，则建立
// off 前窗口授权，让它只补日志、补完即止（见 suspendLogForBotOffAtSeq）。
func (g *GroupInfo) suspendLogForBotOff() bool {
	return g.suspendLogForBotOffAtSeq(0)
}

// suspendLogForBotOffAtSeq 是带指令 seq 的 .bot off 自动暂停入口。
//
// 如果队列里有“窗口完全位于该 .bot off 之前”的在途补全任务，则为它建立
// off 前窗口授权，保留 pending/epoch 让任务补完关闭前的掉线窗口；否则维持
// 原有语义：清 pending、推进 epoch，保证 .bot on 不会补关闭段。
func (g *GroupInfo) suspendLogForBotOffAtSeq(seq int64) bool {
	if g == nil {
		return false
	}
	g.logWriteMu.Lock()
	defer g.logWriteMu.Unlock()

	g.logStateMu.RLock()
	curID, curName, on := g.LogCurID, g.LogCurName, g.LogOn
	g.logStateMu.RUnlock()
	if !on || curName == "" {
		return false
	}

	authorized := false
	if seq > 0 {
		authorized = g.armLogOffGapAuth(curID, curName, g.logEpoch.Load(), seq)
	}

	g.logStateMu.Lock()
	if g.LogCurID != curID || g.LogCurName != curName || !g.LogOn {
		g.logStateMu.Unlock()
		if authorized {
			g.clearLogOffGapAuth()
		}
		return false
	}
	g.LogOn = false
	g.LogPausedByBotOff = true
	g.logStateMu.Unlock()

	seen := seq
	if seen <= 0 {
		seen = g.logLastSeqSnapshot()
	}
	g.clearLogSeenSeq()
	g.setLogSeenSeq(seen)

	if authorized {
		// 保留 pending/epoch，让 off 前任务立即尝试；.bot on 时仍会
		// cancelLogGapFill 清掉未完成的区间。
		g.logGapRetryAt.Store(0)
		return true
	}
	// 注意：必须在释放 logStateMu 之后再取 logSeqMu。
	// MarshalJSON 的顺序是 logSeqMu -> logStateMu，反过来会形成死锁。
	g.cancelLogGapFill()
	return true
}

// resumeLogPausedByBotOff 在群重新激活（.bot on）时按 .log on 的语义
// 自动开启被 .bot off 关闭的日志，并标记“下一条消息只重建基线”，
// 让关闭段不被补录；若期间用户已经 .log on / .log new / .log end，
// 则以用户操作为准。
// 返回值表示本次是否真的把日志重新打开了。
func (g *GroupInfo) resumeLogPausedByBotOff() bool {
	if g == nil {
		return false
	}
	g.logWriteMu.Lock()
	defer g.logWriteMu.Unlock()
	g.logStateMu.Lock()
	if !g.LogPausedByBotOff {
		g.logStateMu.Unlock()
		return false
	}
	g.LogPausedByBotOff = false
	if g.LogOn || g.LogCurName == "" {
		// 用户已经重新开启，或已经 end/new 换了一本日志：不要覆盖用户的操作。
		g.logStateMu.Unlock()
		return false
	}
	g.LogOn = true
	// 只有本次真的自动开启了日志，才需要跳过下一次缺口计算。
	g.LogResumeSkipGap = true
	g.logStateMu.Unlock()
	// 关闭段不补录：清掉暂停前遗留的 pending 区间并取消在途任务。
	// 同样必须在释放 logStateMu 之后再取 logSeqMu，避免与 MarshalJSON 死锁。
	g.cancelLogGapFill()
	g.clearLogOffRequested()
	g.logAutoResumedAt.Store(0)
	return true
}

// isLogPausedByBotOff 报告当前日志关闭是否由 .bot off 自动关闭造成。
func (g *GroupInfo) isLogPausedByBotOff() bool {
	if g == nil {
		return false
	}
	g.logStateMu.RLock()
	defer g.logStateMu.RUnlock()
	return g.LogPausedByBotOff
}

// setLogPausedByBotOff 在“日志本来已关闭，但离线历史确认它应当处于开启”
// 且群已经失活时，补上自动恢复标记：下一次 .bot on 按原语义恢复记录，
// 但当前绝不会把日志重新打开。
func (g *GroupInfo) setLogPausedByBotOff() bool {
	if g == nil {
		return false
	}
	g.logStateMu.Lock()
	defer g.logStateMu.Unlock()
	// 1118: 用户已经明确 .log off 时不要再打“bot off 自动暂停”标记，
	// 否则下一次 .bot on 会把用户刚关的日志重新打开。
	if g.LogOn || g.LogCurName == "" || g.LogPausedByBotOff || g.logOffRequested() {
		return false
	}
	g.LogPausedByBotOff = true
	return true
}

// clearLogPausedByBotOff 在用户显式操作日志（.log on/new/off/end/halt）后清除
// “本次关闭由 .bot off 自动造成”的标记。否则用户已经换了/结束了日志，下一次
// .bot on 仍会被当成“从自动关闭中恢复”，用指令 seq 覆盖刚建立的基线。
func (g *GroupInfo) clearLogPausedByBotOff() {
	if g == nil {
		return
	}
	g.logStateMu.Lock()
	g.LogPausedByBotOff = false
	g.logStateMu.Unlock()
}

// logOffForUser 处理用户显式的 .log off：
//   - 日志开启：关闭，并清除“由 .bot off 自动关闭”的标记；
//   - 日志已由 .bot off 自动关闭：只清标记，让下一次 .bot on 不再自动开启；
//   - 日志本来就没开、或没有日志名：返回 false。
//
// 用 logWriteMu + logStateMu 完成“判断 + 写入”：logWriteMu 让在途补录写入
// 先完成（或被这次 off 看到已关闭而跳过），logStateMu 保护字段本身。
func (g *GroupInfo) logOffForUser() (name string, ok bool) {
	return g.logOffAtSeq(0, true)
}

// logOffForUserAtSeq 是带指令 seq 的 .log off 处理入口。
// 在把 LogOn 置 false 之前，为“窗口完全位于该 .log off 之前”的在途补全任务
// 建立 off 前窗口授权；这样任务可以继续补完 off 之前、掉线期间漏掉的消息，
// 但永远不会写入 off 指令及之后的内容。
func (g *GroupInfo) logOffForUserAtSeq(seq int64) (name string, ok bool) {
	return g.logOffAtSeq(seq, true)
}

// logOffForHistoryAtSeq 是补录任务按历史 .log off 推断关闭 live 日志的入口。
// 1118: 这不是“用户此刻明确要求关闭”，不能留下 logOffRequested 标记；
// 否则之后的离线 .log on 会被这个陈旧标记永久拦住。
func (g *GroupInfo) logOffForHistoryAtSeq(seq int64) (name string, ok bool) {
	return g.logOffAtSeq(seq, false)
}

func (g *GroupInfo) logOffAtSeq(seq int64, userRequested bool) (name string, ok bool) {
	if g == nil {
		return "", false
	}
	// 只有用户显式 .log off 才记录“明确要求关闭”；补录按历史 .log off
	// 关闭 live 日志不能写这个标记。
	if userRequested {
		g.markLogOffRequested(seq)
	}
	g.logAutoResumedAt.Store(0)
	g.logWriteMu.Lock()
	defer g.logWriteMu.Unlock()

	g.logStateMu.RLock()
	curID, curName, on, paused := g.LogCurID, g.LogCurName, g.LogOn, g.LogPausedByBotOff
	g.logStateMu.RUnlock()
	if curName == "" {
		return "", false
	}
	if !on && !paused {
		return curName, false
	}
	// 只有用户显式关闭一个仍在记录的日志才建立新授权；如果日志已被
	// .bot off 自动暂停，沿用之前建立的授权即可。
	if on && seq > 0 {
		if g.armLogOffGapAuth(curID, curName, g.logEpoch.Load(), seq) {
			// off 后没有新消息会再触发 pending floor；清掉旧退避，
			// 让在途/排队任务还能尝试一次。
			g.logGapRetryAt.Store(0)
		}
	}

	g.logStateMu.Lock()
	if g.LogCurID != curID || g.LogCurName != curName || g.LogOn != on {
		g.logStateMu.Unlock()
		g.clearLogOffGapAuth()
		return curName, false
	}
	g.LogOn = false
	g.LogPausedByBotOff = false
	g.logStateMu.Unlock()
	seen := seq
	if seen <= 0 {
		seen = g.logLastSeqSnapshot()
	}
	g.clearLogSeenSeq()
	g.setLogSeenSeq(seen)
	return curName, true
}

// setLogResumeSkipGap 标记“下一次记日志只重建基线、不算缺口”。
// 用于 .bot off → .bot on 的边界：静默期间的消息不属于要补的断层。
func (g *GroupInfo) setLogResumeSkipGap() {
	if g == nil {
		return
	}
	g.logStateMu.Lock()
	g.LogResumeSkipGap = true
	g.logStateMu.Unlock()
}

// consumeLogResumeSkipGap 读取并清除“跳过下一次缺口计算”标记。
func (g *GroupInfo) consumeLogResumeSkipGap() bool {
	if g == nil {
		return false
	}
	g.logStateMu.Lock()
	defer g.logStateMu.Unlock()
	if !g.LogResumeSkipGap {
		return false
	}
	g.LogResumeSkipGap = false
	return true
}

// clearLogResumeSkipGap 清除“跳过下一次缺口”标记。
// .bot on 的指令消息自带 seq 时，调用方应直接用 resetLogSeq 重建基线并清掉本标记：
// 恢复后一条消息都没来就再次掉线/重启时，这个持久标记会把真实的离线窗口吞掉。
func (g *GroupInfo) clearLogResumeSkipGap() {
	if g == nil {
		return
	}
	g.logStateMu.Lock()
	g.LogResumeSkipGap = false
	g.logStateMu.Unlock()
}

// resetLogSeqForNewSegment 在 .log on / .log new 成功时重建日志 seq 基线。
//
// 有 seq 时把基线锚定到当前指令消息（原行为，不变）；没有 seq（部分 OneBot
// 实现或合成消息）时无法锚定本条指令的位置，退化为“下一条带 seq 的消息只
// 重建基线”，避免把 off 段/旧日志段当成缺口补录。该退化只影响没有 seq 的
// 边界情况，正常群消息路径仍走 resetLogSeq。
//
// 只修改基线/恢复标记/epoch，不修改日志开关；调用方负责 MarkDirty。
func (g *GroupInfo) resetLogSeqForNewSegment(seq int64, rawID interface{}) {
	if g == nil {
		return
	}
	if seq > 0 {
		g.clearLogResumeSkipGap()
		g.resetLogSeq(seq, rawID)
		return
	}
	// 没有 seq 时，下一条带 seq 的消息消费该标记后只执行 updateLogSeq，
	// 不再计算缺口。直接 set（不要先 clear）避免并发消息在 clear/set 之间
	// 看到 false 而用旧基线算 gap；resetLogSeqBaseline 同时清掉旧持久基线、
	// 排队区间并推进 epoch，重启后不会拿旧日志基线给新日志补旧段。
	g.setLogResumeSkipGap()
	g.resetLogSeqBaseline()
}

// repairLogIDByName 在持久化 LogCurID 丢失时，按群号+日志名找回现有日志 ID。
//
// 1119.fix1: 旧数据可能只有 LogCurName/LogOn 而没有 LogCurId（升级前从未写过；
// 或 repairPersistedLogState 校验失败后被清成 0）。日志关闭时 ensureGroupLogState
// 不会补 ID，detectOffStateLogGap 又在 ID==0 时直接返回，导致“离线 .log on”
// 永远扫描不到。这里只读查找、不创建日志：日志被删除时保持 0，等 .log on 处理。
func repairLogIDByName(d *Dice, group *GroupInfo, state GroupLogState) bool {
	if d == nil || group == nil || d.DBOperator == nil || state.ID != 0 || state.Name == "" {
		return false
	}
	id, err := service.LogGetIDByName(d.DBOperator, group.GroupID, state.Name)
	if err != nil {
		if !errors.Is(err, service.ErrLogNotFound) && d.Logger != nil {
			d.Logger.Warnf("日志状态自愈失败: 群=%s 名称=%s err=%v", group.GroupID, state.Name, err)
		}
		return false
	}
	if id == 0 {
		return false
	}
	group.SetLogState(id, state.Name, state.On)
	group.MarkDirty(d)
	if d.Logger != nil {
		d.Logger.Infof("日志状态自愈: 群=%s 名称=%s 按名字补全 logID=%d (记录=%v)",
			group.GroupID, state.Name, id, state.On)
	}
	return true
}

// repairPersistedLogState 校验持久化的 LogCurID 是否仍指向 LogCurName。
//
// LogCurID 持久化后不会再像上游那样“重启即为 0、按名字 LogGetOrCreate 自愈”。
// 如果当前日志在 Web UI 被删除，或数据库恢复后同一 ID 指向了同群的另一本日志，
// LogAppendByID 会永久失败/写进错误日志。这里在加载时显式恢复上游的自愈语义：
// 按名字找回（不存在则重建）日志，并清掉属于旧日志的 seq 基线。
func repairPersistedLogState(d *Dice, group *GroupInfo) {
	if d == nil || group == nil {
		return
	}
	state := group.GetLogState()
	if state.ID == 0 {
		// 1119.fix1: 关闭的日志也要补 ID，否则离线 .log on 发现失效。
		repairLogIDByName(d, group, state)
		return
	}
	owner, name, err := service.LogGetOwnerByID(d.DBOperator, state.ID)
	// 除了“日志被删除”，还要校验 ID 仍属于本群：数据库恢复/ID 复用时可能
	// 指向另一个群的同名日志，这种状态在运行期会被 LogAppendByID 拒绝写入。
	if err == nil && owner == group.GroupID && name == state.Name {
		return
	}
	if err != nil && !errors.Is(err, service.ErrLogNotFound) {
		if d.Logger != nil {
			d.Logger.Warnf("日志状态校验失败，暂不处理: 群=%s logID=%d err=%v", group.GroupID, state.ID, err)
		}
		return
	}

	oldID := state.ID
	oldName := state.Name
	if oldName == "" {
		group.ClearLogState()
		group.resetLogSeqBaseline()
		group.MarkDirty(d)
		if d.Logger != nil {
			d.Logger.Warnf("日志状态自愈: 群=%s 旧ID=%d 没有日志名，已清理", group.GroupID, oldID)
		}
		return
	}

	// 先清掉旧 ID，再按名字找回/重建。日志关闭时不主动创建，等 .log on 再处理。
	group.SetLogState(0, oldName, state.On)
	group.resetLogSeqBaseline()
	newID := uint64(0)
	if state.On {
		if id, createErr := service.LogGetOrCreate(d.DBOperator, group.GroupID, oldName); createErr == nil {
			newID = id
			group.SetLogState(id, oldName, true)
		} else if d.Logger != nil {
			d.Logger.Warnf("日志状态修复失败: 群=%s 名称=%s err=%v", group.GroupID, oldName, createErr)
		}
	} else {
		// 1119.fix1: 关闭的日志不创建，但若同名日志仍存在则补回 ID。
		if id, findErr := service.LogGetIDByName(d.DBOperator, group.GroupID, oldName); findErr == nil {
			newID = id
			group.SetLogState(id, oldName, false)
		} else if !errors.Is(findErr, service.ErrLogNotFound) && d.Logger != nil {
			d.Logger.Warnf("日志状态修复失败: 群=%s 名称=%s err=%v", group.GroupID, oldName, findErr)
		}
	}
	group.MarkDirty(d)
	if d.Logger != nil {
		d.Logger.Warnf("日志状态自愈: 群=%s 旧ID=%d(%s) 新ID=%d 记录=%s", group.GroupID, oldID, name, newID, oldName)
	}
}

func ensureGroupLogState(ctx *MsgContext, group *GroupInfo) GroupLogState {
	state := getGroupLogState(group)
	if group == nil || !state.On || state.Name == "" || state.ID > 0 {
		return state
	}

	logID, err := service.LogGetOrCreate(ctx.Dice.DBOperator, group.GroupID, state.Name)
	if err != nil {
		if ctx != nil && ctx.Dice != nil && ctx.Dice.Logger != nil {
			ctx.Dice.Logger.Warnf("日志状态修复失败: 群=%s 名称=%s err=%v", group.GroupID, state.Name, err)
		}
		return state
	}
	group.SetLogState(logID, state.Name, state.On)
	if ctx != nil && ctx.Dice != nil && ctx.Dice.Logger != nil {
		ctx.Dice.Logger.Infof("日志状态修复: 群=%s 记录=%s 补全logID=%d", group.GroupID, state.Name, logID)
	}
	return getGroupLogState(group)
}

// EvalPlayerGroupCardTemplate 只求值 .sn 模板，不调用平台改名接口。
// 求值 panic 转为 error，避免名片异常中断正文回复。
func EvalPlayerGroupCardTemplate(ctx *MsgContext, tmpl string) (result string, err error) {
	if ctx == nil || ctx.Dice == nil {
		return "", errors.New("无法求值名片模板：上下文为空")
	}
	defer func() {
		if r := recover(); r != nil {
			result = ""
			err = fmt.Errorf("名片模板求值异常: %v", r)
			if ctx.Dice.Logger != nil {
				ctx.Dice.Logger.Errorf("%v\n%s", err, debug.Stack())
			}
		}
	}()
	if ctx.SystemTemplate == nil && ctx.Group != nil {
		ctx.SystemTemplate = ctx.Group.GetCharTemplate(ctx.Dice)
	}
	config := ctx.GenDefaultRollVmConfig()
	config.HookValueStore = func(ctx *ds.Context, name string, v *ds.VMValue) (overwrite *ds.VMValue, solved bool) {
		return nil, true
	}
	v := ctx.EvalFString(tmpl, config)
	if v.vm.Error != nil {
		return "", v.vm.Error
	}

	return v.ToString(), nil
}

func SetPlayerGroupCardByTemplate(ctx *MsgContext, tmpl string) (string, error) {
	text, err := EvalPlayerGroupCardTemplate(ctx, tmpl)
	if err != nil {
		if ctx != nil && ctx.Dice != nil && ctx.Dice.Logger != nil {
			ctx.Dice.Logger.Infof("SN指令模板错误: %v", err.Error())
		}
		return "", err
	}

	// 官方 QQ 没有修改群名片的能力，名片改由回复顶部的状态栏承载。
	if ctx.EndPoint == nil || ctx.EndPoint.Adapter == nil || isOfficialQQEndpoint(ctx.EndPoint) {
		return text, nil
	}

	if ctx.EndPoint.Platform == "QQ" && len(text) >= 60 { // Note(Xiangze-Li): 2023-08-09实测群名片长度限制为59个英文字符, 20个中文字符是可行的, 但分别判断过于繁琐
		return text, ErrGroupCardOverlong
	}

	ctx.EndPoint.Adapter.SetGroupCardName(ctx, text)
	return text, nil
}

// {"data":null,"msg":"SEND_MSG_API_ERROR","retcode":100,"status":"failed","wording":"请参考 go-cqhttp 端输出"}

func RegisterBuiltinExtLog(self *Dice) {
	privateCommandListen := map[int64]int64{}
	privateCommandListenMu := sync.RWMutex{}

	// 这个机制作用是记录私聊指令？？忘记了
	privateCommandListenCheck := func() {
		now := time.Now().Unix()
		newMap := map[int64]int64{}
		privateCommandListenMu.Lock()
		for k, v := range privateCommandListen {
			// 30s间隔以上清除
			if now-v < 30 {
				newMap[k] = v
			}
		}
		privateCommandListen = newMap
		privateCommandListenMu.Unlock()
	}

	privateCommandListenHas := func(commandID int64) bool {
		privateCommandListenMu.RLock()
		_, exists := privateCommandListen[commandID]
		privateCommandListenMu.RUnlock()
		return exists
	}

	privateCommandListenSet := func(commandID int64, ts int64) {
		privateCommandListenMu.Lock()
		privateCommandListen[commandID] = ts
		privateCommandListenMu.Unlock()
	}

	// 避免群信息重复记录
	groupMsgInfo := SyncMap[any, int64]{}
	groupMsgInfoLastClean := int64(0)
	groupMsgInfoClean := func() {
		// 清理过久的消息
		now := time.Now().Unix()

		if now-groupMsgInfoLastClean < 60 {
			// 60s清理一次
			return
		}

		groupMsgInfoLastClean = now
		var toDelete []any
		groupMsgInfo.Range(func(key any, t int64) bool {
			if now-t > 5 { // 5秒内如果有此消息，那么不记录
				toDelete = append(toDelete, key)
			}
			return true
		})

		for _, i := range toDelete {
			groupMsgInfo.Delete(i)
		}
	}

	// 检查是否已经记录过 如果记录过则跳过
	groupMsgInfoCheckOk := func(_k interface{}) bool {
		groupMsgInfoClean()
		if _k == nil {
			return false
		}
		t, exists := groupMsgInfo.Load(_k)
		if exists {
			now := time.Now().Unix()
			return now-t > 5 // 5秒内如果有此消息，那么不记录
		}
		return true
	}

	groupMsgInfoSet := func(_k any) {
		if _k != nil {
			groupMsgInfo.Store(_k, time.Now().Unix())
		}
	}

	// 获取logname，第一项是默认名字
	getLogName := func(ctx *MsgContext, _ *Message, cmdArgs *CmdArgs, index int) (string, string) {
		bakLogCurName := getGroupLogName(ctx.Group)
		if newName := cmdArgs.GetArgN(index); newName != "" {
			return bakLogCurName, newName
		}
		return bakLogCurName, bakLogCurName
	}

	const helpLog = `.log new [<日志名>] // 新建日志并开始记录，注意new后跟空格！
.log on [<日志名>]  // 开始记录，不写日志名则开启最近一次日志，注意on后跟空格！
.log off // 暂停记录
.log end // 完成记录并发送日志文件
.log get [<日志名>] // 重新上传日志，并获取链接
.log halt // 强行关闭当前log，不上传日志
.log list // 查看当前群的日志列表
.log del <日志名> // 删除一份日志
.log stat [<日志名>] // 查看统计
.log stat [<日志名>] --all // 查看统计(全团)，--all前必须有空格
.log list <群号> // 查看指定群的日志列表(无法取得日志时，找骰主做这个操作)
.log masterget <群号> <日志名> // 重新上传日志，并获取链接(无法取得日志时，找骰主做这个操作)
.log export <日志名> // 直接取得日志txt(服务出问题或有其他需要时使用)
.log export <日志名> <邮箱地址> // 通过邮件取得日志txt，多个邮箱用空格隔开
注: KOOK、官方 QQ、内置 Lagrange 等渠道不支持掉线日志自动补全，请保持核心在线。`

	// const txtLogTip = "若未出现线上日志地址，可换时间获取，或联系骰主在data/default/log-exports路径下取出日志\n文件名: 群号_日志名_随机数.zip\n注意此文件log end/get后才会生成"

	cmdLog := &CmdItemInfo{
		Name:      "log",
		ShortHelp: helpLog,
		Help:      "日志指令:\n" + helpLog,
		Solve: func(ctx *MsgContext, msg *Message, cmdArgs *CmdArgs) CmdExecuteResult {
			group := ctx.Group
			cmdArgs.ChopPrefixToArgsWith("on", "off", "del", "rm", "masterget",
				"get", "end", "halt", "list", "new", "stat", "export")

			groupNotActiveCheck := func() bool {
				if !group.IsActive(ctx) {
					ReplyToSender(ctx, msg, "未开启时不会记录日志，请先.bot on")
					return true
				}
				return false
			}

			if len(cmdArgs.Args) == 0 {
				onText := "关闭"
				state := getGroupLogState(group)
				if state.On {
					onText = "开启"
				}
				lines, _ := service.LogLinesCountGet(ctx.Dice.DBOperator, group.GroupID, state.Name)
				text := fmt.Sprintf("当前故事: %s\n当前状态: %s\n已记录文本%d条", state.Name, onText, lines)
				ReplyToSender(ctx, msg, text)
				return CmdExecuteResult{Matched: true, Solved: true}
			}

			logNameAliasIndexCache := map[string]*logNameAliasIndex{}
			getLogNameAliasIndex := func(groupID string) (*logNameAliasIndex, error) {
				if index, exists := logNameAliasIndexCache[groupID]; exists {
					return index, nil
				}
				index, err := buildLogNameAliasIndex(ctx.Dice.DBOperator, groupID)
				if err != nil {
					return nil, err
				}
				logNameAliasIndexCache[groupID] = index
				return index, nil
			}

			resolveLogNameWithReply := func(groupID, name string) (string, bool) {
				index, err := getLogNameAliasIndex(groupID)
				if err != nil {
					ReplyToSender(ctx, msg, "获取记录出错: "+err.Error())
					return "", false
				}
				if resolved, ok := index.Resolve(name); ok {
					return resolved, true
				}
				return name, true
			}

			logKeyHintText := func() string {
				return "\n可先使用 .log list 查看对应的【key】: 日志名"
			}

			getAndUpload := func(gid, lname string) {
				if lname != "" {
					var ok bool
					lname, ok = resolveLogNameWithReply(gid, lname)
					if !ok {
						return
					}
				}
				fn, notice, err := logSendToBackend(ctx, gid, lname, true)
				if err != nil {
					reason := strings.TrimPrefix(err.Error(), "#")
					VarSetValueStr(ctx, "$t错误原因", reason)

					tmpl := DiceFormatTmpl(ctx, "日志:记录_上传_失败")
					if strings.Contains(reason, "此log不存在") || strings.Contains(reason, "名字是否正确") {
						tmpl += logKeyHintText()
					}
					ReplyToSenderRaw(ctx, msg, tmpl, "skip")
				} else {
					VarSetValueStr(ctx, "$t日志链接", fn)
					tmpl := DiceFormatTmpl(ctx, "日志:记录_上传_成功")
					if notice != "" {
						tmpl += "\n" + notice
					}
					ReplyToSenderRaw(ctx, msg, tmpl, "skip")
				}
			}

			if cmdArgs.IsArgEqual(1, "on") { //nolint:nestif
				if ctx.IsPrivate {
					ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:提示_私聊不可用"))
					return CmdExecuteResult{Matched: true, Solved: true}
				}

				// 如果日志已经开启，报错返回。但如果刚才是 off 发现任务先一步
				// 把日志恢复（实时 .log on 与异步任务竞态），这条命令其实已经
				// 生效，只补一条说明，不再谎报“已有记录”。
				currentState := getGroupLogState(group)
				if currentState.On {
					// 异步 off 发现任务可能先一步把日志恢复；此时用户的
					// .log on 已经生效，不能回复“已有记录”的失败文案。
					if ts := group.logAutoResumedAt.Load(); ts > 0 && time.Now().Unix()-ts <= 30 {
						group.logAutoResumedAt.Store(0)
						ReplyToSender(ctx, msg, "日志已从离线记录恢复开启。")
						return CmdExecuteResult{Matched: true, Solved: true}
					}
					bfFrom, bfTo, _ := group.pendingLogGapRangeSnapshot()
					if bfFrom <= 0 {
						bfFrom = group.logSeenSeqSnapshot()
					}
					if bfTo <= bfFrom {
						bfTo = msg.Seq
					}
					if group.hasOffDiscoveryContext() &&
						group.enqueueOffDiscoveryBackfill(ctx.Dice, ctx.EndPoint, currentState, group.logEpoch.Load(), bfFrom, bfTo) {
						ReplyToSender(ctx, msg, "日志已开启，离线期间的记录正在补录，完成后会通知。")
						return CmdExecuteResult{Matched: true, Solved: true}
					}
					VarSetValueStr(ctx, "$t记录名称", currentState.Name)
					ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "日志:记录_开启_失败_未结束的记录"))
					return CmdExecuteResult{Matched: true, Solved: true}
				}

				name := cmdArgs.GetArgN(2)
				if name == "" {
					name = currentState.Name
				}
				if name != "" {
					var ok bool
					name, ok = resolveLogNameWithReply(group.GroupID, name)
					if !ok {
						return CmdExecuteResult{Matched: true, Solved: true}
					}
				}

				if name != "" {
					lines, exists := service.LogLinesCountGet(ctx.Dice.DBOperator, group.GroupID, name)

					if exists {
						if groupNotActiveCheck() {
							return CmdExecuteResult{Matched: true, Solved: true}
						}

						logID, err := service.LogGetOrCreate(ctx.Dice.DBOperator, group.GroupID, name)
						if err != nil {
							ReplyToSender(ctx, msg, "日志开启失败: "+err.Error())
							ctx.Dice.Logger.Errorf("日志开启失败: group=%s name=%s err=%v", group.GroupID, name, err)
							return CmdExecuteResult{Matched: true, Solved: true}
						}
						// 实时 .log on 会 reset 基线/epoch，原有的 off 发现任务会被
						// 取消。先把待补录窗口抓下来，reset 之后再挂一个 backfillOnly
						// 任务，避免离线 on 段随 epoch 变化一起丢失。
						bfFrom, bfTo, _ := group.pendingLogGapRangeSnapshot()
						if bfFrom <= 0 {
							bfFrom = group.logSeenSeqSnapshot()
						}
						if bfTo <= bfFrom {
							bfTo = msg.Seq
						}
						needBackfill := group.hasOffDiscoveryContext() && bfFrom > 0 && bfTo > bfFrom
						// .log off 之后立刻 .log on：off 前的 on 窗口任务仍持有授权，
						// reset 会推进 epoch 让它停止。记下窗口，重新挂一个只补日志
						// 的任务（与离线 off 发现窗口分开处理，避免两种模式互相替换）。
						preOffFrom, preOffTo, preOffOK := group.authorizedPreOffGapRange()
						if preOffOK {
							auth := group.logOffGapAuthSnapshot()
							preOffOK = auth != nil && auth.logID == logID && auth.logName == name
						}
						var stateAfter GroupLogState
						var epochAfter uint64
						group.logWriteMu.Lock()
						group.SetLogState(logID, name, true)
						group.resetLogSeqForNewSegment(msg.Seq, msg.RawID)
						group.clearLogPausedByBotOff()
						stateAfter = group.GetLogState()
						epochAfter = group.logEpoch.Load()
						group.logWriteMu.Unlock()
						// 无 seq/不支持补全的平台不应留下永久 LogResumeSkipGap。
						noFillNotice := logGapFillPlatformNotice(ctx.EndPoint)
						if noFillNotice != "" {
							group.clearLogResumeSkipGap()
						}
						group.MarkDirty(ctx.Dice)
						ctx.Dice.Logger.Infof("日志状态切换: 群=%s 开启日志 name=%s id=%d", group.GroupID, name, logID)

						backfillNotice := ""
						if needBackfill {
							if group.enqueueOffDiscoveryBackfill(ctx.Dice, ctx.EndPoint, stateAfter, epochAfter, bfFrom, bfTo) {
								backfillNotice = "\n离线期间的记录正在补录，完成后会通知。"
							} else {
								ctx.Dice.Logger.Warnf("日志开启后未能重建离线补录任务: 群=%s 窗口=%d..%d", group.GroupID, bfFrom, bfTo)
							}
						} else if preOffOK &&
							group.enqueuePreOffBackfillAfterResume(ctx.Dice, ctx.EndPoint, preOffFrom, preOffTo) {
							backfillNotice = "\n关闭前的遗漏记录正在补录，完成后会通知。"
						}

						VarSetValueStr(ctx, "$t记录名称", name)
						VarSetValueInt64(ctx, "$t当前记录条数", lines)
						ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "日志:记录_开启_成功")+backfillNotice+noFillNotice)
					} else {
						VarSetValueStr(ctx, "$t记录名称", name)
						ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "日志:记录_开启_失败_无此记录"))
					}
				} else {
					ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "日志:记录_开启_失败_尚未新建"))
				}
				return CmdExecuteResult{Matched: true, Solved: true}
			} else if cmdArgs.IsArgEqual(1, "off") {
				state := getGroupLogState(group)
				if !state.On && group.hasOffDiscoveryContext() {
					// live 日志已经是 off，但离线发现任务还在补录历史 on 段。
					// 这不是用户“忘记开启”，而是离线期间的 .log on 尚未处理完；
					// 记下明确的关闭请求（阻止任务结束时 adopt），并给出正确提示。
					if _, ok := group.logOffForUserAtSeq(msg.Seq); ok {
						group.MarkDirty(ctx.Dice)
					}
					ReplyToSender(ctx, msg, "当前记录已关闭；离线期间的记录正在补录，完成后会通知。")
					return CmdExecuteResult{Matched: true, Solved: true}
				}
				if _, ok := group.logOffForUserAtSeq(msg.Seq); ok {
					// 显式 .log off 优先于 .bot off 的自动关闭：即使日志已经是
					// 关的，也要清掉“自动开启”标记，避免下一次 .bot on 把它重新打开。
					group.MarkDirty(ctx.Dice)
					ctx.Dice.Logger.Infof("日志状态切换: 群=%s 关闭日志 name=%s id=%d", group.GroupID, state.Name, state.ID)
					lines, _ := service.LogLinesCountGet(ctx.Dice.DBOperator, group.GroupID, state.Name)
					VarSetValueStr(ctx, "$t记录名称", state.Name)
					VarSetValueInt64(ctx, "$t当前记录条数", lines)
					ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "日志:记录_关闭_成功"))
				} else {
					ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "日志:记录_关闭_失败"))
				}
				return CmdExecuteResult{Matched: true, Solved: true}
			} else if cmdArgs.IsArgEqual(1, "del", "rm") {
				name := cmdArgs.GetArgN(2)
				if name == "" {
					return CmdExecuteResult{Matched: true, Solved: true, ShowHelp: true}
				}
				var ok bool
				name, ok = resolveLogNameWithReply(group.GroupID, name)
				if !ok {
					return CmdExecuteResult{Matched: true, Solved: true}
				}

				VarSetValueStr(ctx, "$t记录名称", name)
				if name == getGroupLogName(group) {
					ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "日志:记录_删除_失败_正在进行"))
				} else {
					err := service.LogDelete(ctx.Dice.DBOperator, group.GroupID, name)
					if err == nil {
						ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "日志:记录_删除_成功"))
					} else if errors.Is(err, service.ErrLogNotFound) {
						ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "日志:记录_删除_失败_找不到"))
					} else {
						ReplyToSender(ctx, msg, "日志删除失败: "+err.Error())
					}
				}
				return CmdExecuteResult{Matched: true, Solved: true}
			} else if cmdArgs.IsArgEqual(1, "masterget") {
				groupID, requestForAnotherGroup := getSpecifiedGroupIfMaster(ctx, msg, cmdArgs)
				if requestForAnotherGroup && groupID == "" {
					return CmdExecuteResult{Matched: true, Solved: true}
				}

				logName := cmdArgs.GetArgN(3)
				if logName == "" {
					ReplyToSenderRaw(ctx, msg, "请遵循 .log masterget <群号> <日志名> 格式给出日志名，注意空格\n若不清楚可以.log list <群号>查询", "skip")
					return CmdExecuteResult{Matched: true, Solved: true}
				}

				getAndUpload(groupID, logName)
				return CmdExecuteResult{Matched: true, Solved: true}
			} else if cmdArgs.IsArgEqual(1, "get") {
				// 仿照 log on 为 log get 添加了 IsPrivate 判断
				if ctx.IsPrivate {
					ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:提示_私聊不可用"))
					return CmdExecuteResult{Matched: true, Solved: true}
				}

				logName := getGroupLogName(group)
				if newName := cmdArgs.GetArgN(2); newName != "" {
					logName = newName
				}

				if logName == "" {
					text := DiceFormatTmpl(ctx, "日志:记录_取出_未指定记录")
					ReplyToSenderRaw(ctx, msg, text, "skip")
					return CmdExecuteResult{Matched: true, Solved: true}
				}

				getAndUpload(group.GroupID, logName)
				return CmdExecuteResult{Matched: true, Solved: true}
			} else if cmdArgs.IsArgEqual(1, "end") {
				state := getGroupLogState(group)
				if state.Name == "" {
					ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "日志:记录_关闭_失败"))
					return CmdExecuteResult{Matched: true, Solved: true}
				}
				lines, _ := service.LogLinesCountGet(ctx.Dice.DBOperator, group.GroupID, state.Name)
				VarSetValueInt64(ctx, "$t当前记录条数", lines)
				VarSetValueStr(ctx, "$t记录名称", state.Name)
				text := DiceFormatTmpl(ctx, "日志:记录_结束")
				// Note: 2024-02-28 经过讨论，日志在 off 的情况下 end 属于合理操作，这里不再检查是否开启
				// if !group.LogOn {
				//	 text = strings.TrimRightFunc(DiceFormatTmpl(ctx, "日志:记录_关闭_失败"), unicode.IsSpace) + "\n" + text
				// }
				ReplyToSender(ctx, msg, text)
				group.SetLogOn(false)
				group.clearLogPausedByBotOff()
				group.MarkDirty(ctx.Dice)
				ctx.Dice.Logger.Infof("日志状态切换: 群=%s 结束日志 name=%s id=%d，准备上传", group.GroupID, state.Name, state.ID)

				time.Sleep(time.Duration(0.3 * float64(time.Second)))
				// Note: 2024-10-15 经过简单测试，似乎能缓解#1034的问题，但无法根本解决。
				uploadGroupID := group.GroupID
				uploadName := state.Name
				go getAndUpload(uploadGroupID, uploadName)
				group.ClearLogState()
				group.MarkDirty(ctx.Dice)
				return CmdExecuteResult{Matched: true, Solved: true}
			} else if cmdArgs.IsArgEqual(1, "halt") {
				state := getGroupLogState(group)
				if len(state.Name) > 0 {
					lines, _ := service.LogLinesCountGet(ctx.Dice.DBOperator, group.GroupID, state.Name)
					VarSetValueInt64(ctx, "$t当前记录条数", lines)
					VarSetValueStr(ctx, "$t记录名称", state.Name)
				}
				text := DiceFormatTmpl(ctx, "日志:记录_结束")
				ReplyToSender(ctx, msg, text)
				group.ClearLogState()
				group.clearLogPausedByBotOff()
				group.MarkDirty(ctx.Dice)
				ctx.Dice.Logger.Infof("日志状态切换: 群=%s 强制终止当前日志", group.GroupID)
				return CmdExecuteResult{Matched: true, Solved: true}
			} else if cmdArgs.IsArgEqual(1, "list") {
				groupID, requestForAnotherGroup := getSpecifiedGroupIfMaster(ctx, msg, cmdArgs)
				if requestForAnotherGroup && groupID == "" {
					return CmdExecuteResult{Matched: true, Solved: true}
				}
				if groupID == "" {
					groupID = ctx.Group.GroupID
				}

				var text strings.Builder
				text.WriteString(DiceFormatTmpl(ctx, "日志:记录_列出_导入语"))
				text.WriteString("\n")
				index, err := getLogNameAliasIndex(groupID)
				if err == nil {
					for _, entry := range index.entries {
						text.WriteString(formatLogNameListLine(entry))
						text.WriteString("\n")
					}
					if len(index.entries) == 0 {
						text.WriteString("暂无记录")
					}
				} else {
					text.WriteString("获取记录出错: ")
					text.WriteString(err.Error())
				}
				ReplyToSender(ctx, msg, text.String())
				return CmdExecuteResult{Matched: true, Solved: true}
			} else if cmdArgs.IsArgEqual(1, "new") {
				if ctx.IsPrivate {
					ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:提示_私聊不可用"))
					return CmdExecuteResult{Matched: true, Solved: true}
				}

				name := cmdArgs.GetArgN(2)
				currentState := getGroupLogState(group)
				if currentState.Name != "" && name == "" {
					VarSetValueStr(ctx, "$t记录名称", currentState.Name)
					ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "日志:记录_新建_失败_未结束的记录"))
					return CmdExecuteResult{Matched: true, Solved: true}
				}
				if groupNotActiveCheck() {
					return CmdExecuteResult{Matched: true, Solved: true}
				}

				if name == "" {
					name = time.Now().Format("2006_01_02_15_04_05")
				}
				if currentState.Name != "" {
					VarSetValueInt64(ctx, "$t存在开启记录", 1)
				} else {
					VarSetValueInt64(ctx, "$t存在开启记录", 0)
				}
				VarSetValueStr(ctx, "$t上一记录名称", currentState.Name)
				VarSetValueStr(ctx, "$t记录名称", name)
				logID, err := service.LogGetOrCreate(ctx.Dice.DBOperator, group.GroupID, name)
				if err != nil {
					ReplyToSender(ctx, msg, "日志新建失败: "+err.Error())
					ctx.Dice.Logger.Errorf("日志新建失败: group=%s name=%s err=%v", group.GroupID, name, err)
					return CmdExecuteResult{Matched: true, Solved: true}
				}
				group.logWriteMu.Lock()
				group.SetLogState(logID, name, true)
				group.resetLogSeqForNewSegment(msg.Seq, msg.RawID)
				group.clearLogPausedByBotOff()
				group.logWriteMu.Unlock()
				noFillNotice := logGapFillPlatformNotice(ctx.EndPoint)
				if noFillNotice != "" {
					group.clearLogResumeSkipGap()
				}
				group.MarkDirty(ctx.Dice)
				ctx.Dice.Logger.Infof("日志状态切换: 群=%s 新建并开启日志 name=%s id=%d", group.GroupID, name, logID)

				ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "日志:记录_新建")+noFillNotice)
				return CmdExecuteResult{Matched: true, Solved: true}
			} else if cmdArgs.IsArgEqual(1, "stat") {
				// group := ctx.Group
				_, name := getLogName(ctx, msg, cmdArgs, 2)
				if name != "" {
					var ok bool
					name, ok = resolveLogNameWithReply(group.GroupID, name)
					if !ok {
						return CmdExecuteResult{Matched: true, Solved: true}
					}
				}
				items, err := service.LogGetCommandInfoStrList(ctx.Dice.DBOperator, group.GroupID, name)
				if err == nil && len(items) > 0 {
					// showDetail := cmdArgs.GetKwarg("detail")
					// var showDetail *Kwarg
					showAll := cmdArgs.GetKwarg("all")

					/* if showDetail != nil { //nolint // 故意保留
						results := LogRollBriefDetail(items)

						if len(results) > 0 {
							ReplyToSender(ctx, msg, "统计结果如下:\n"+strings.Join(results, "\n"))
							return CmdExecuteResult{Matched: true, Solved: true}
						}
					} else */{
						isShowAll := showAll != nil
						text := LogRollBriefByPCV2(ctx, items, isShowAll, ctx.Player.Name)
						if text == "" {
							if isShowAll {
								ReplyToSender(ctx, msg, fmt.Sprintf("没有找到故事“%s”的检定记录", name))
							} else {
								ReplyToSender(ctx, msg, fmt.Sprintf("没有找到角色<%s>的任何记录\n若需查看全团，请在指令后加 --all", ctx.Player.Name))
							}
						} else {
							if !isShowAll {
								text += "\n\n若需查看全团，请在指令后加 --all"
							}
							ReplyToSender(ctx, msg, text)
						}
						return CmdExecuteResult{Matched: true, Solved: true}
					}
				}
				ReplyToSender(ctx, msg, "没有发现可供统计的信息，请确保记录名正确，且有进行骰点/检定行为")
				return CmdExecuteResult{Matched: true, Solved: true}
			} else if cmdArgs.IsArgEqual(1, "export") {
				if ctx.IsPrivate {
					// 仿照 log on 为 log get 添加了 IsPrivate 判断
					ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:提示_私聊不可用"))
					return CmdExecuteResult{Matched: true, Solved: true}
				}

				logName := getGroupLogName(group)
				if newName := cmdArgs.GetArgN(2); newName != "" {
					logName = newName
				}
				if logName == "" {
					ReplyToSenderRaw(ctx, msg, DiceFormatTmpl(ctx, "日志:记录_导出_未指定记录"), "skip")
					return CmdExecuteResult{Matched: true, Solved: true}
				}
				var ok bool
				logName, ok = resolveLogNameWithReply(group.GroupID, logName)
				if !ok {
					return CmdExecuteResult{Matched: true, Solved: true}
				}

				now := carbon.Now()
				VarSetValueStr(ctx, "$t记录名", logName)
				VarSetValueStr(ctx, "$t日期", now.ToShortDateString())
				VarSetValueStr(ctx, "$t时间", now.ToShortTimeString())
				logFileNamePrefix := DiceFormatTmpl(ctx, "日志:记录_导出_文件名前缀")
				logFile, notice, err := GetLogTxt(ctx, group.GroupID, logName, logFileNamePrefix)
				if err != nil {
					reply := err.Error()
					if strings.Contains(reply, "此log不存在") || strings.Contains(reply, "名字是否正确") {
						reply += logKeyHintText()
					}
					ReplyToSenderRaw(ctx, msg, reply, "skip")
					return CmdExecuteResult{Matched: true, Solved: true}
				}
				defer os.Remove(logFile)

				var emails []string
				if len(cmdArgs.Args) > 2 {
					emails = cmdArgs.Args[2:]
					// 试图发送邮件
					dice := ctx.Session.Parent
					if dice.CanSendMail() {
						rightEmails := make([]string, 0, len(emails))
						emailExp := regexp.MustCompile(`.*@.*`)
						for _, email := range emails {
							if emailExp.MatchString(email) {
								rightEmails = append(rightEmails, email)
							}
						}
						if len(rightEmails) > 0 {
							emailMsg := DiceFormatTmpl(ctx, "日志:记录_导出_邮件附言")
							dice.SendMailRow(
								fmt.Sprintf("Seal 记录提取: %s", logFileNamePrefix),
								rightEmails,
								emailMsg,
								[]string{logFile},
							)
							text := DiceFormatTmpl(ctx, "日志:记录_导出_邮箱发送前缀") + strings.Join(rightEmails, "\n")
							ReplyToSenderRaw(ctx, msg, text, "skip")
							return CmdExecuteResult{Matched: true, Solved: true}
						}
						ReplyToSenderRaw(ctx, msg, DiceFormatTmpl(ctx, "日志:记录_导出_无格式有效邮箱"), "skip")
					}
					ReplyToSenderRaw(ctx, msg, DiceFormat(ctx, "{核心:骰子名字}未配置邮箱，将直接发送记录文件"), "skip")
				}

				var uri string
				if runtime.GOOS == "windows" {
					uri = "files:///" + logFile
				} else {
					uri = "files://" + logFile
				}
				SendFileToSenderRaw(ctx, msg, uri, "skip")
				VarSetValueStr(ctx, "$t文件名字", logFileNamePrefix)
				reply := DiceFormatTmpl(ctx, "日志:记录_导出_成功")
				if notice != "" {
					reply += "\n" + notice
				}
				ReplyToSenderRaw(ctx, msg, reply, "skip")
				return CmdExecuteResult{Matched: true, Solved: true}
			} else {
				return CmdExecuteResult{Matched: true, Solved: true, ShowHelp: true}
			}
		},
	}

	helpStat := `.stat log [<日志名>] // 查看当前或指定日志的骰点统计
.stat log [<日志名>] --all // 查看全团
.stat help // 帮助
`
	cmdStat := &CmdItemInfo{
		Name:      "stat",
		ShortHelp: helpStat,
		Help:      "查看统计:\n" + helpStat,
		Solve: func(ctx *MsgContext, msg *Message, cmdArgs *CmdArgs) CmdExecuteResult {
			val := cmdArgs.GetArgN(1)
			switch strings.ToLower(val) {
			case "log":
				group := ctx.Group
				_, name := getLogName(ctx, msg, cmdArgs, 2)
				if name != "" {
					resolved, err := resolveLogNameForGroup(ctx.Dice.DBOperator, group.GroupID, name)
					if err != nil {
						ReplyToSender(ctx, msg, "获取记录出错: "+err.Error())
						return CmdExecuteResult{Matched: true, Solved: true}
					}
					name = resolved
				}
				items, err := service.LogGetCommandInfoStrList(ctx.Dice.DBOperator, group.GroupID, name)
				if err == nil && len(items) > 0 {
					// showDetail := cmdArgs.GetKwarg("detail")
					// var showDetail *Kwarg
					showAll := cmdArgs.GetKwarg("all")

					/* if showDetail != nil { //nolint // 故意保留
						results := LogRollBriefDetail(items)

						if len(results) > 0 {
							ReplyToSender(ctx, msg, "统计结果如下:\n"+strings.Join(results, "\n"))
							return CmdExecuteResult{Matched: true, Solved: true}
						}
					} else */{
						isShowAll := showAll != nil
						text := LogRollBriefByPCV2(ctx, items, isShowAll, ctx.Player.Name)
						if text == "" {
							if isShowAll {
								ReplyToSender(ctx, msg, fmt.Sprintf("没有找到故事“%s”的检定记录", name))
							} else {
								ReplyToSender(ctx, msg, fmt.Sprintf("没有找到角色<%s>的任何记录\n若需查看全团，请在指令后加 --all", ctx.Player.Name))
							}
						} else {
							if !isShowAll {
								text += "\n\n若需查看全团，请在指令后加 --all"
							}
							ReplyToSender(ctx, msg, text)
						}
						return CmdExecuteResult{Matched: true, Solved: true}
					}
				}
				if err != nil || len(items) == 0 {
					ReplyToSender(ctx, msg, "没有发现可供统计的信息，请确保记录名正确，且有进行骰点/检定行为")
				}
			default:
				return CmdExecuteResult{Matched: true, Solved: true, ShowHelp: true}
			}
			return CmdExecuteResult{Matched: true, Solved: true}
		},
	}

	helpOb := `.ob // 进入ob模式
.ob exit // 退出ob
`
	cmdOb := &CmdItemInfo{
		Name:          "ob",
		ShortHelp:     helpOb,
		Help:          "观众指令:\n" + helpOb,
		AllowDelegate: true,
		Solve: func(ctx *MsgContext, msg *Message, cmdArgs *CmdArgs) CmdExecuteResult {
			ctx.DelegateText = fmt.Sprintf("由<%s>操作:\n", ctx.Player.Name)
			mctx := GetCtxProxyFirst(ctx, cmdArgs)
			subcommand := cmdArgs.GetArgN(1)

			c := ctx
			if mctx != nil && mctx.Player.UserID != ctx.Player.UserID {
				if ctx.PrivilegeLevel < 50 && subcommand != "help" {
					ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "通用:提示_无权限_非master/管理"))
					return CmdExecuteResult{Matched: true, Solved: true}
				}
				c = mctx
			}

			switch strings.ToLower(subcommand) {
			case "help":
				return CmdExecuteResult{Matched: true, Solved: true, ShowHelp: true}
			case "exit":
				if strings.HasPrefix(strings.ToLower(c.Player.Name), "ob") {
					c.Player.Name = c.Player.Name[len("ob"):]
					c.Player.UpdatedAtTime = time.Now().Unix()
					if c.Group != nil {
						c.Group.MarkDirty(c.Dice)
					}
				}
				c.EndPoint.Adapter.SetGroupCardName(c, c.Player.Name)
				ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "日志:OB_关闭"))
			default:
				if !strings.HasPrefix(strings.ToLower(c.Player.Name), "ob") {
					c.Player.Name = "ob" + c.Player.Name
					c.Player.UpdatedAtTime = time.Now().Unix()
					if c.Group != nil {
						c.Group.MarkDirty(c.Dice)
					}
				}
				c.EndPoint.Adapter.SetGroupCardName(c, c.Player.Name)
				ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "日志:OB_开启"))
			}
			return CmdExecuteResult{Matched: true, Solved: true}
		},
	}

	helpSn := `.sn coc // 自动设置coc名片
.sn dnd // 自动设置dnd名片
.sn none // 设置为空白格式
.sn off // 取消自动设置
`
	cmdSn := &CmdItemInfo{
		Name:               "sn",
		ShortHelp:          helpSn,
		Help:               "跑团名片(需要管理权限):\n" + helpSn,
		CheckCurrentBotOn:  true,
		CheckMentionOthers: true,
		HelpFunc: func(isShort bool) string {
			// 手动添加特定的命令示例到帮助信息的开头
			fixedExamples := ".sn coc // 自动设置coc名片\n" +
				".sn cocL // 自动设置coc名片，小写\n" +
				".sn dnd // 自动设置dnd名片\n"

			text := fixedExamples

			var tempStrList []string

			self.GameSystemMap.Range(func(key string, value *GameSystemTemplate) bool {
				for k, v := range value.NameTemplate {
					if k != "coc" && k != "dnd" && k != "cocL" {
						// 考虑到这里的量级不会太大，所以直接排序已经生成好的提示文本或许更划算
						tempStrList = append(tempStrList, fmt.Sprintf(".sn %s // %s\n", k, v.HelpText))
					}
				}
				return true
			})

			sort.Strings(tempStrList)
			text += strings.Join(tempStrList, "")
			text += ".sn expr {$t玩家_RAW} HP{hp}/{hpmax} // 自设格式\n" +
				".sn none // 设置为空白格式\n" +
				".sn off // 取消自动设置"

			if isShort {
				return text
			}
			return "跑团名片(需要管理权限):\n" + text
		},
		Solve: func(ctx *MsgContext, msg *Message, cmdArgs *CmdArgs) CmdExecuteResult {
			val := cmdArgs.GetArgN(1)
			valLower := strings.ToLower(val)

			handleOverlong := func(ctx *MsgContext, msg *Message, card string) CmdExecuteResult {
				ReplyToSender(ctx, msg, fmt.Sprintf(
					"尝试将群名片修改为 %q 失败，名片长度超过限制。\n请尝试缩短角色名或使用 .sn expr 自定义名片格式。",
					card,
				))
				return CmdExecuteResult{Matched: true, Solved: true}
			}

			// sn 指令(除 help 外)需要骰子具有群管理员权限。提前检测 bot 在群中的角色,
			// 若明确无管理权限则给出明确提示, 由于协议端问题，目前只能做提示。不支持角色检查的适配器
			// 返回 ok=false, 此时保持原有行为(直接尝试设置)不做阻断。
			if valLower != "help" && ctx.Group != nil {
				if detail, ok := checkBotGroupRole(ctx, ctx.Group.GroupID); ok && detail != "owner" && detail != "admin" {
					ReplyToSender(ctx, msg, "【警告】骰子当前可能不具备管理员权限，请检查，若确认具备管理员权限可无视此误报。")
				}
			}

			switch valLower {
			case "help":
				return CmdExecuteResult{Matched: true, Solved: true, ShowHelp: true}
			case "coc", "coc7":
				ctx.Player.AutoSetNameTemplate = "{$t玩家_RAW} SAN{理智} HP{生命值}/{生命值上限} DEX{敏捷}"
				ctx.Player.UpdatedAtTime = time.Now().Unix()
				if ctx.Group != nil {
					ctx.Group.MarkDirty(ctx.Dice)
				}
				text, err := SetPlayerGroupCardByTemplate(ctx, ctx.Player.AutoSetNameTemplate)
				if errors.Is(err, ErrGroupCardOverlong) {
					return handleOverlong(ctx, msg, text)
				}
				VarSetValueStr(ctx, "$t名片格式", val)
				VarSetValueStr(ctx, "$t名片预览", text)
				// 玩家 SAN60 HP10/10 DEX65
				ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "日志:名片_自动设置"))
			case "dnd", "dnd5e":
				// PW{pw}
				ctx.Player.AutoSetNameTemplate = "{$t玩家_RAW} HP{hp}/{hpmax} AC{ac} DC{dc} PP{pp}"
				ctx.Player.UpdatedAtTime = time.Now().Unix()
				if ctx.Group != nil {
					ctx.Group.MarkDirty(ctx.Dice)
				}
				text, err := SetPlayerGroupCardByTemplate(ctx, ctx.Player.AutoSetNameTemplate)
				if errors.Is(err, ErrGroupCardOverlong) {
					return handleOverlong(ctx, msg, text)
				}
				VarSetValueStr(ctx, "$t名片格式", val)
				VarSetValueStr(ctx, "$t名片预览", text)
				// 玩家 HP10/10 AC15 DC15 PW10
				ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "日志:名片_自动设置"))
			case "none":
				ctx.Player.AutoSetNameTemplate = "{$t玩家_RAW}"
				ctx.Player.UpdatedAtTime = time.Now().Unix()
				if ctx.Group != nil {
					ctx.Group.MarkDirty(ctx.Dice)
				}
				text, err := SetPlayerGroupCardByTemplate(ctx, "{$t玩家_RAW}")
				if errors.Is(err, ErrGroupCardOverlong) { // 大约不至于会走到这里，但是为了统一也这样写了
					return handleOverlong(ctx, msg, text)
				}
				VarSetValueStr(ctx, "$t名片格式", "空白")
				VarSetValueStr(ctx, "$t名片预览", text)
				ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "日志:名片_自动设置"))
			case "off", "cancel":
				_, _ = SetPlayerGroupCardByTemplate(ctx, "{$t玩家_RAW}")
				ctx.Player.AutoSetNameTemplate = ""
				ctx.Player.UpdatedAtTime = time.Now().Unix()
				if ctx.Group != nil {
					ctx.Group.MarkDirty(ctx.Dice)
				}
				ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "日志:名片_取消设置"))
			case "expr":
				t := cmdArgs.GetRestArgsFrom(2)
				if len(t) > 80 {
					t = t[:80]
				}
				if t == "" {
					_, _ = SetPlayerGroupCardByTemplate(ctx, "{$t玩家_RAW}")
					ctx.Player.AutoSetNameTemplate = ""
					ctx.Player.UpdatedAtTime = time.Now().Unix()
					if ctx.Group != nil {
						ctx.Group.MarkDirty(ctx.Dice)
					}
					ReplyToSender(ctx, msg, "玩家自设内容为空，已自动关闭此功能")
				} else {
					last := ctx.Player.AutoSetNameTemplate
					ctx.Player.AutoSetNameTemplate = t
					text, err := SetPlayerGroupCardByTemplate(ctx, ctx.Player.AutoSetNameTemplate)
					if err != nil && !errors.Is(err, ErrGroupCardOverlong) {
						ctx.Player.AutoSetNameTemplate = last
						ReplyToSender(ctx, msg, "玩家自设sn格式错误，已自动还原之前模板")
					} else if errors.Is(err, ErrGroupCardOverlong) {
						return handleOverlong(ctx, msg, text)
					} else {
						ctx.Player.UpdatedAtTime = time.Now().Unix()
						if ctx.Group != nil {
							ctx.Group.MarkDirty(ctx.Dice)
						}
						VarSetValueStr(ctx, "$t名片格式", "玩家自设")
						VarSetValueStr(ctx, "$t名片预览", text)
						ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "日志:名片_自动设置"))
					}
				}
			default:
				ok := false
				ctx.Dice.GameSystemMap.Range(func(key string, value *GameSystemTemplate) bool {
					var t NameTemplateItem
					var exists bool

					// 先检查绝对匹配, 不存在则检查小写匹配
					if t, exists = value.NameTemplate[val]; !exists {
						t, exists = value.NameTemplate[strings.ToLower(val)]
					}

					if !exists {
						return true
					}

					// 增加使用sn设置自定义规则的名片模板时的错误反馈
					text, err := SetPlayerGroupCardByTemplate(ctx, t.Template)
					if errors.Is(err, ErrGroupCardOverlong) {
						handleOverlong(ctx, msg, text)
						ok = true
						return false
					} else if err != nil {
						ReplyToSender(ctx, msg, "命名模版错误或不存在，请使用.sn help查看使用说明")
						ok = true
						return false
					}
					ctx.Player.AutoSetNameTemplate = t.Template
					VarSetValueStr(ctx, "$t名片格式", val)
					VarSetValueStr(ctx, "$t名片预览", text)
					ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "日志:名片_自动设置"))
					ok = true
					return false
				})

				if ok {
					return CmdExecuteResult{Matched: true, Solved: true}
				}

				return CmdExecuteResult{Matched: true, Solved: true, ShowHelp: true}
			}
			return CmdExecuteResult{Matched: true, Solved: true}
		},
	}

	self.RegisterExtension(&ExtInfo{
		Name:       "log",
		Version:    "1.0.1",
		Brief:      "跑团辅助扩展，提供日志、染色等功能",
		Author:     "木落",
		AutoActive: true,
		Official:   true,
		OnLoad: func() {
			_ = os.MkdirAll(filepath.Join(self.BaseConfig.DataDir, "log-exports"), 0o755)
		},
		OnMessageSend: func(ctx *MsgContext, msg *Message, flag string) {
			// 无论是否入日志，群内发言都会占用一个seq，故计数要在 skip 之前
			if msg.MessageType == "group" && msg.GroupID != "" {
				if groupInfo, ok := ctx.Session.ServiceAtNew.Load(msg.GroupID); ok {
					groupInfo.noteLogSelfSent()
				}
			}

			// 记录骰子发言
			if flag == "skip" {
				return
			}
			privateCommandListenCheck()
			if msg.MessageType == "private" && ctx.CommandHideFlag != "" {
				if privateCommandListenHas(ctx.CommandID) {
					session := ctx.Session
					groupInfo, ok := session.ServiceAtNew.Load(ctx.CommandHideFlag)
					if !ok {
						ctx.Dice.Logger.Warn("ServiceAtNew ext_log加载groupInfo异常")
						return
					}
					logState := ensureGroupLogState(ctx, groupInfo)
					if !logState.On || logState.Name == "" {
						return
					}
					a := model.LogOneItem{
						Nickname:    ctx.EndPoint.Nickname,
						IMUserID:    UserIDExtract(ctx.EndPoint.UserID),
						UniformID:   ctx.EndPoint.UserID,
						Time:        time.Now().Unix(),
						Message:     msg.Message,
						IsDice:      true,
						CommandID:   ctx.CommandID,
						CommandInfo: ctx.CommandInfo,
						RawMsgID:    msg.RawID,
						// IsDice=true 不参与 raw_msg_id 去重：私聊暗骰回显的
						// 消息 ID 来自私聊会话，与群消息 ID 不是同一命名空间
						// （Telegram 等平台按会话独立编号），同 ID 时两条都要留。
					}

					LogAppend(ctx, groupInfo.GroupID, logState.ID, logState.Name, &a)
				}
			}

			if IsCurGroupBotOnByID(ctx.Session, ctx.EndPoint, msg.MessageType, msg.GroupID) {
				session := ctx.Session
				groupInfo, ok := session.ServiceAtNew.Load(msg.GroupID)
				if !ok {
					ctx.Dice.Logger.Warn("ServiceAtNew ext_log加载groupInfo异常")
					return
				}
				logState := ensureGroupLogState(ctx, groupInfo)
				if logState.On && logState.Name != "" {
					// <2022-02-15 09:54:14.0> [摸鱼king]: 有的 但我不知道
					if ctx.CommandHideFlag != "" {
						// 记录当前指令和时间
						privateCommandListenSet(ctx.CommandID, time.Now().Unix())
					}

					a := model.LogOneItem{
						Nickname:    ctx.EndPoint.Nickname,
						IMUserID:    UserIDExtract(ctx.EndPoint.UserID),
						UniformID:   ctx.EndPoint.UserID,
						Time:        time.Now().Unix(),
						Message:     msg.Message,
						IsDice:      true,
						CommandID:   ctx.CommandID,
						CommandInfo: ctx.CommandInfo,
						RawMsgID:    msg.RawID,
					}
					LogAppend(ctx, groupInfo.GroupID, logState.ID, logState.Name, &a)
				}
			}
		},
		OnMessageReceived: func(ctx *MsgContext, msg *Message) {
			// 处理日志
			if ctx.Group != nil {
				logState := ensureGroupLogState(ctx, ctx.Group)
				if logState.On && logState.Name != "" {
					// 实时 .log on 之后可能还有 off 发现窗口待补录（实时处理器
					// 先执行、或失败后重试）。优先让 backfillOnly 任务补齐历史；
					// 这条消息本身仍然正常写入日志，只是暂不走 on 状态缺口逻辑，
					// 避免 on 任务把 off 起点窗口合并替换掉。
					skipGap := false
					if ctx.Group.hasOffDiscoveryContext() {
						ctx.Group.enqueuePendingOffDiscoveryBackfill(ctx.Dice, ctx.EndPoint, logState)
						skipGap = true
					}
					if msg.Seq > 0 && !skipGap {
						// 只有“日志正在记录”时才会走到这里；off 期间整段不进来，
						// 所以 off 的消息永远不会被算成缺口。
						fromSeq, lastMsgID, gap := logGapFromMessage(ctx.Dice, ctx.Group, logState, msg.Seq, msg.RawID)
						if gap > 0 && endpointSupportsLogGapFill(ctx.EndPoint) {
							task := logGapFillTask{
								dice:      ctx.Dice,
								endpoint:  ctx.EndPoint,
								group:     ctx.Group,
								logID:     logState.ID,
								logName:   logState.Name,
								epoch:     ctx.Group.logEpoch.Load(),
								fromSeq:   fromSeq,
								toSeq:     msg.Seq,
								gap:       gap,
								lastMsgID: lastMsgID,
								trigger:   cloneGapTriggerMessage(msg),
							}
							// 队列化：同一群只跑一个 worker，相邻断层合并，避免抖动时
							// 每个断层一个 goroutine 排队、越补越晚。
							ctx.Group.enqueueLogGapFill(task)
						}
					}

					// 去重，用于同群多骰情况
					if !groupMsgInfoCheckOk(msg.RawID) {
						return
					}
					groupMsgInfoSet(msg.RawID)

					// <2022-02-15 09:54:14.0> [摸鱼king]: 有的 但我不知道
					a := model.LogOneItem{
						Nickname:  ctx.Player.Name,
						IMUserID:  UserIDExtract(ctx.Player.UserID),
						UniformID: ctx.Player.UserID,
						Time:      msg.Time,
						Message:   msg.Message,
						IsDice:    false,
						CommandID: ctx.CommandID,
						RawMsgID:  msg.RawID,
						Seq:       ptrInt64(msg.Seq),
						// 只有落在重放区间内的消息才算补录；重放期间实时到达的
						// 正常消息 seq 在区间之外，不能被标成补录。
						IsGapFill: ctx.Group.isLogGapFillSeq(msg.Seq),
					}

					LogAppend(ctx, ctx.Group.GroupID, logState.ID, logState.Name, &a)
				} else if !logState.On && logState.Name != "" && logState.ID > 0 &&
					msg.Seq > 0 && endpointSupportsLogGapFill(ctx.EndPoint) {
					// live 日志已关闭，但仍要检测“核心离线期间漏掉的消息”：
					// 用已见 seq 游标发现跳号，再从 off 起点扫描历史里的
					// .log on/.log off，补录应该记录的 on 段。
					ctx.Group.detectOffStateLogGap(ctx.Dice, ctx.EndPoint, logState, msg)
				}
			}
		},
		OnMessageDeleted: func(ctx *MsgContext, msg *Message) {
			if ctx.Group != nil {
				// 不按 LogOn 门控：.bot off 会把日志自动关闭，但停用前已记录、
				// 停用期间被撤回的消息仍应从日志删除（找不到行是 no-op）。
				LogDeleteByID(ctx, ctx.Group.GroupID, msg.RawID)
			}
		},
		OnMessageEdit: func(ctx *MsgContext, msg *Message) {
			if ctx.Group == nil {
				return
			}
			// 同上：编辑事件不因日志处于关闭状态而丢失。
			LogEditByID(ctx, ctx.Group.GroupID, msg.Message, msg.RawID)
		},
		GetDescText: GetExtensionDesc,
		CmdMap: CmdMapCls{
			"log":  cmdLog,
			"stat": cmdStat,
			"hiy":  cmdStat,
			"ob":   cmdOb,
			"sn":   cmdSn,
		},
	})
}

func getSpecifiedGroupIfMaster(ctx *MsgContext, msg *Message, cmdArgs *CmdArgs) (groupID string, requestForAnotherGroup bool) {
	if data := cmdArgs.GetArgN(2); data != "" {
		if ctx.PrivilegeLevel < 100 {
			ReplyToSender(ctx, msg, "你并非Master，请检查指令输入是否正确")
			return "", true
		}

		// 已经带平台前缀（QQ-Group:/OpenQQ-Group:/KOOK-CH-Group: 等）时
		// 原样使用，避免官方 QQ 被拼成 QQ-Group:OpenQQ-Group:...。
		if strings.Contains(data, ":") {
			return data, true
		}
		prefix := ""
		switch {
		case isOfficialQQEndpoint(ctx.EndPoint):
			// 1119.fix1: 官方 QQ 频道用的是 OpenQQCH-Channel，
			// 不能统一补成 OpenQQ-Group，否则跨频道查日志会拼错群号。
			if ctx.Group != nil && strings.HasPrefix(ctx.Group.GroupID, "OpenQQCH-Channel:") {
				prefix = "OpenQQCH-Channel"
			} else {
				prefix = "OpenQQ-Group"
			}
		case ctx.EndPoint != nil && ctx.EndPoint.Platform == "QQ":
			prefix = "QQ-Group"
		case ctx.EndPoint != nil && ctx.EndPoint.Platform == "KOOK":
			prefix = "KOOK-CH-Group"
		}
		if prefix != "" {
			data = prefix + ":" + data
		}

		// _newGroup := ctx.Session.ServiceAtNew[data]
		// if _newGroup == nil {
		// 	ReplyToSender(ctx, msg, "找不到指定的群组，请输入正确群号。如在非QQ平台取log，群号请写 QQ-Group:12345")
		// 	return nil, true
		// }
		return data, true
	}
	// 对应的组，是否存在第二个参数
	return "", false
}

func FilenameReplace(name string) string {
	re := regexp.MustCompile(`[/:\*\?"<>\|\\]`)
	return re.ReplaceAllString(name, "")
}

const logAppendFailNoticeInterval = 5 * time.Minute

var (
	logAppendFailMu   sync.Mutex
	logAppendFailLast = map[string]time.Time{}
)

func LogAppend(ctx *MsgContext, groupID string, logID uint64, logName string, logItem *model.LogOneItem) bool {
	ok := false
	if logID > 0 {
		ok = service.LogAppendByID(ctx.Dice.DBOperator, logID, groupID, logItem)
		if !ok && ctx.Group != nil && groupID != "" && logName != "" {
			ok = healLogAppendByID(ctx, groupID, logName, logItem)
		}
	} else if logName != "" {
		ok = service.LogAppend(ctx.Dice.DBOperator, groupID, logName, logItem)
	}
	if !ok {
		// 补录期间任何写入失败都要让任务保留 pending：否则“没写进去”会被
		// 当成“补全完成”而永久丢掉这段缺口。
		if ctx != nil && ctx.Group != nil {
			ctx.Group.markLogGapWriteFailure()
		}
		if ctx == nil || !ctx.SuppressLogAppendFailureNotice {
			reportLogAppendFailure(ctx, groupID, logID, logName)
		}
		return false
	}
	if !ctx.SuppressLogSizeNotice {
		if size, okCount := service.LogLinesCountGet(ctx.Dice.DBOperator, groupID, logName); okCount {
			// 默认每记录500条发出提示
			if ctx.Dice.Config.LogSizeNoticeEnable {
				if ctx.Dice.Config.LogSizeNoticeCount == 0 {
					ctx.Dice.Config.LogSizeNoticeCount = DefaultConfig.LogSizeNoticeCount
				}
				if size > 0 && int(size)%ctx.Dice.Config.LogSizeNoticeCount == 0 {
					VarSetValueInt64(ctx, "$t条数", size)
					text := DiceFormatTmpl(ctx, "日志:记录_条数提醒")
					ReplyToSenderRaw(ctx, &Message{MessageType: "group", GroupID: groupID}, text, "skip")
				}
			}
		}
	}
	return true
}

// healLogAppendByID 在按 ID 写入失败时按名字找回/重建日志并重试一次。
//
// 持久化的 LogCurID 不会像上游运行时字段那样在重启后自动归零：
// Web UI 删除当前日志、数据库恢复导致 ID 失配后，不在这里兜底就会一直写不进日志
// （并且每 5 分钟误报一次“数据库结构未升级”）。
func healLogAppendByID(ctx *MsgContext, groupID, logName string, logItem *model.LogOneItem) bool {
	if ctx == nil || ctx.Dice == nil || ctx.Dice.DBOperator == nil || ctx.Group == nil {
		return false
	}
	state := ctx.Group.GetLogState()
	// 期间用户已经切日志/关日志：不要把手里的旧条目写进别的日志。
	if state.Name != logName || !state.On {
		return false
	}
	newID, err := service.LogGetOrCreate(ctx.Dice.DBOperator, groupID, logName)
	if err != nil || newID == 0 {
		return false
	}
	ctx.Group.SetLogState(newID, logName, state.On)
	ctx.Group.resetLogSeqBaseline()
	ctx.Group.MarkDirty(ctx.Dice)
	if ctx.Dice.Logger != nil {
		ctx.Dice.Logger.Warnf("日志写入自愈: 群=%s 记录=%s 新ID=%d", groupID, logName, newID)
	}
	return service.LogAppendByID(ctx.Dice.DBOperator, newID, groupID, logItem)
}

func reportLogAppendFailure(ctx *MsgContext, groupID string, logID uint64, logName string) {
	if ctx == nil || ctx.Dice == nil {
		return
	}
	if ctx.Dice.Logger != nil {
		ctx.Dice.Logger.Errorf("日志写入失败: group=%s logID=%d name=%s", groupID, logID, logName)
	}
	if groupID == "" {
		return
	}
	now := time.Now()
	logAppendFailMu.Lock()
	last := logAppendFailLast[groupID]
	if !last.IsZero() && now.Sub(last) < logAppendFailNoticeInterval {
		logAppendFailMu.Unlock()
		return
	}
	logAppendFailLast[groupID] = now
	logAppendFailMu.Unlock()
	ReplyToSenderRaw(ctx, &Message{MessageType: "group", GroupID: groupID},
		"日志写入失败，请联系骰主检查后台错误日志", "skip")
}

// 缺失条数不超过该阈值时静默补全并照常执行指令，超过则只补录日志并汇报未执行的指令
const logGapFillSilentThreshold = 5

const (
	// 一次断层补全的总预算：从缺口起点分段扫描，每段最多
	// logGapFillMaxMessages 条、每页 100 条。离线较久时需要多段拉取，
	// 60s 在慢线路/大群上容易只扫到一半，给到 120s。
	logGapFillTimeout      = 120 * time.Second
	logGapFillPageTimeout  = 15 * time.Second // 单页拉取超时，避免一页卡住耗尽总预算
	logGapFillPageSize     = 100              // 单次 get_group_msg_history 的拉取上限
	logGapFillMaxMessages  = 2000             // 单段历史拉取的最大消息数；run() 从缺口起点分段覆盖整个缺口
	logGapFillFetchRetries = 3                // 瞬时网络错误的重试次数
	// logGapFillRetryBackoff 是拉取整体失败后，pending 区间重新触发补全的
	// 最小间隔。pending 会保留到补全完成，没有退避时每条新消息都会重试。
	logGapFillRetryBackoff = 2 * time.Minute
)

// logGapReplayDeniedCommands 是静默重放时不允许执行的管理指令。
// 小断层会重走完整消息流程，若把漏掉的 .log off/.bot off 等指令也重放，
// 会在用户不知情的情况下改变日志/机器人状态；这些指令只补日志，不执行。
//
// 名单必须覆盖所有“改骰子/群配置”的内置指令，漏一个就等于给补录开了后门：
//   - log/bot/master/dismiss/ban/unban：日志与机器人生命周期、封禁
//   - ext：开关扩展（重放 .ext off log 会直接把日志关掉）
//   - set：改全局配置（.set 是 master 指令）
//   - black：黑名单管理
//   - reply：.reply on/off 等价于 .ext reply on/off，可绕过上面的 ext
//   - randalgo：master 修改全局随机算法（.randalgo set）
//
// 跑团类指令（st/ra/draw/name/ch/pc 等）仍然重放，它们是补录的意义所在。
var logGapReplayDeniedCommands = map[string]struct{}{
	"log":      {},
	"bot":      {},
	"master":   {},
	"dismiss":  {},
	"ban":      {},
	"unban":    {}, // 实际由 ban 处理；保留以兼容旧写法
	"ext":      {},
	"set":      {},
	"black":    {},
	"reply":    {},
	"randalgo": {},
}

// logGapFromMessage 记录本条消息的 seq，并返回它与“上一条已记录消息”之间的缺口。
//
// 只在日志开启时调用（OnMessageReceived 里的 Off 分支整段不进来），所以 log off
// 期间的消息永远不会被算成缺口；恢复记录后 .log on/.log new 会把持久基线重置到
// 当次消息，缺口从那一刻重新起算。
//
// 上一条的判定顺序：
//  1. 内存 logLastSeq —— 进程内正常推进的值；
//  2. 持久基线 LogSeqBaseline —— .log on/.log new 的边界，重启后恢复；
//  3. DB MAX(seq) —— 每进程校准一次，用来跨进程重启找回“真正记录到哪”。
//
// gap > 0 才需要补全；返回的 fromSeq 是补全区间起点（不含），toSeq 由调用方补。
func logGapFromMessage(d *Dice, group *GroupInfo, logState GroupLogState, msgSeq int64, rawID interface{}) (fromSeq int64, lastMsgID interface{}, gap int64) {
	// 双重保险：调用方已经在 Off 时跳过整段逻辑，这里再判一次，
	// 保证“off 期间的消息绝不进入缺口计算、也绝不推进 seq 基线”。
	if group == nil || !logState.On || logState.Name == "" {
		return 0, nil, 0
	}
	// .bot off → .bot on 之后的第一次记录：只重建基线，不把静默期间的聊天
	// 当成断层。暂停期间的消息既不补日志，也不重放执行。
	if group.consumeLogResumeSkipGap() {
		group.updateLogSeq(msgSeq, rawID)
		return 0, nil, 0
	}
	// 未校准（或正在退避）时，持久基线可能是很久以前的 .log on，直接算缺口
	// 会把已经落库的历史当成断层重复补录。先校准；失败就本条不补、不推进基线，
	// 等 DB 恢复后由 DB MAX(seq) 一次性对齐。
	if !group.isLogSeqCalibrated() {
		if !group.needLogSeqCalibration() {
			return 0, nil, 0
		}
		baseSeq, baseMsgID := group.logSeqBaselineSnapshot()
		if _, _, ok := calibrateLogSeqBaseline(d, group, logState.ID, baseSeq, baseMsgID); !ok {
			// 校准失败期间消息仍会正常入库；把校准前基线持久化成 pending，
			// 等校准恢复/重启后把基线压回这里，避免 DB MAX 把失败窗口前的
			// 真实断层一起吞掉。
			group.recordLogSeqCalibrationFailure(d)
			return 0, nil, 0
		}
	}
	// 重启前有未完成的补全区间：把内存基线压回区间起点，让这条消息重新
	// 触发补全。只在没有排队/在途任务时生效，正常补全过程不会被反复拉回。
	group.applyLogGapPendingFloor()
	lastSeq, lastMsgID, selfSent := group.updateLogSeq(msgSeq, rawID)
	// 平台 seq 重置（OneBot 实现重装、群迁移等）后 msgSeq 会长期小于旧基线；
	// 连续多条明显回退时重建基线，避免缺口检测永久失效。普通前进/小幅乱序
	// 会清零计数，不会误重置。
	if group.noteLogSeqRegression(msgSeq, lastSeq) {
		group.resetLogSeq(msgSeq, rawID)
		if d != nil {
			group.MarkDirty(d)
			if d.Logger != nil {
				d.Logger.Warnf("检测到平台 seq 重置: 群=%s 旧基线=%d 新seq=%d，已重建基线",
					group.GroupID, lastSeq, msgSeq)
			}
		}
		return 0, nil, 0
	}
	if lastSeq == 0 && logState.ID > 0 {
		// 没有数据库/日志 ID 时校准不适用，持久基线仍是最后一道依据。
		persistedSeq, persistedMsgID := group.logSeqBaselineSnapshot()
		if persistedSeq > lastSeq {
			lastSeq = persistedSeq
			if persistedMsgID != "" {
				lastMsgID = persistedMsgID
			}
		}
	}
	if lastSeq <= 0 {
		return 0, nil, 0
	}
	// 骰子自身发言同样占 seq，扣除后剩下的才是真正遗漏的他人消息。
	gap = msgSeq - lastSeq - 1 - selfSent
	if gap <= 0 {
		return lastSeq, lastMsgID, 0
	}
	return lastSeq, lastMsgID, gap
}

// detectOffStateLogGap 在 live 日志关闭时检测“核心离线期间漏掉的消息”：
// 用已见 seq 游标发现跳号，从 off 起点建立历史扫描任务。
//
// 与 on 状态补录不同，off 状态下不能每来一条消息就更新日志基线：
//   - LogSeenSeq 记录核心最后看到的群消息 seq，用来发现离线窗口；
//   - 缺口任务从 LogSeenSeq 开始，扫描历史 .log on/.log off；
//   - 只有任务成功后才推进/清除 LogSeenSeq，失败会在下一条消息重试。
func (g *GroupInfo) detectOffStateLogGap(d *Dice, ep *EndPointInfo, logState GroupLogState, msg *Message) {
	if g == nil || d == nil || ep == nil || msg == nil || msg.Seq <= 0 {
		return
	}
	if logState.On || logState.Name == "" || logState.ID == 0 {
		return
	}
	seen := g.logSeenSeqSnapshot()
	if seen <= 0 {
		seen = g.logLastSeqSnapshot()
	}
	if seen <= 0 && d.DBOperator != nil {
		if seq, err := service.LogGetLastSeq(d.DBOperator, logState.ID); err == nil && seq > 0 {
			seen = seq
		}
	}
	if seen <= 0 {
		// 没有任何可比较的基线：先把当前位置记为已见，之后的新跳号再扫描。
		g.advanceLogSeenSeq(d, msg.Seq)
		return
	}
	if msg.Seq <= seen {
		// 乱序/重复消息不建立任务。
		return
	}
	gap := msg.Seq - seen - 1
	if gap <= 0 {
		g.advanceLogSeenSeq(d, msg.Seq)
		return
	}
	// 1118: .log off 之前已经有一个持有 off 前窗口授权的任务在排队/运行。
	// 此刻不要用 off 发现任务替换它，否则 1115.fix5 的 off 前窗口会丢。
	// LogSeenSeq 保持不动，等该任务补完后由下一条消息重新建立 off 发现任务，
	// 覆盖当前消息所在的 off 窗口。
	if g.hasAuthorizedPreOffGapTask() {
		if d.Logger != nil {
			d.Logger.Debugf("日志补全等待 off 前窗口任务完成: 群=%s seq=%d", g.GroupID, msg.Seq)
		}
		// worker 已退出但 pending 还在（上次拉取失败），日志又处于关闭状态，
		// 不会再有 on 状态消息触发 pending floor；这里用当前消息重新拉起它。
		if !g.hasAnyLogGapTask() {
			g.retryPendingLogGapTask(d, ep)
		}
		return
	}
	task := logGapFillTask{
		dice:            d,
		endpoint:        ep,
		group:           g,
		logID:           logState.ID,
		logName:         logState.Name,
		epoch:           g.logEpoch.Load(),
		fromSeq:         seen,
		toSeq:           msg.Seq,
		gap:             gap,
		trigger:         cloneGapTriggerMessage(msg),
		discoverFromOff: true,
	}
	// 队列化：worker 运行期间新消息会合并区间；LogSeenSeq 等任务成功后再推进。
	g.enqueueLogGapFill(task)
}

// enqueueOffDiscoveryBackfill 在实时 .log on 已经把 live 日志打开后，
// 为指定的 off 发现窗口创建一个 log-only 历史补录任务。
//
// 实时处理器会 resetLogSeq/epoch++，原来的 off 发现任务因此被取消；
// 这里用 reset 之后的新 epoch 重新挂一个 backfillOnly 任务，确保离线期间
// 已经在历史里确认的 on 段不会丢。
func (g *GroupInfo) enqueueOffDiscoveryBackfill(d *Dice, ep *EndPointInfo, logState GroupLogState, epoch uint64, fromSeq, toSeq int64) bool {
	if g == nil || d == nil || ep == nil || !logState.On || logState.ID == 0 || logState.Name == "" {
		return false
	}
	if fromSeq <= 0 || toSeq <= fromSeq {
		return false
	}
	// 在 logWriteMu 读锁下确认日志没有被并发切换；拿到 epoch 后再入队。
	// 如果入队后用户又 .log new，epoch 变化会让任务自动取消，避免把旧
	// 日志的历史写进新日志。
	g.logWriteMu.RLock()
	current := g.GetLogState()
	currentEpoch := g.logEpoch.Load()
	g.logWriteMu.RUnlock()
	if !current.On || current.ID != logState.ID || current.Name != logState.Name || currentEpoch != epoch {
		return false
	}
	task := logGapFillTask{
		dice:            d,
		endpoint:        ep,
		group:           g,
		logID:           current.ID,
		logName:         current.Name,
		epoch:           currentEpoch,
		fromSeq:         fromSeq,
		toSeq:           toSeq,
		gap:             toSeq - fromSeq - 1,
		discoverFromOff: true,
		backfillOnly:    true,
	}
	g.enqueueLogGapFill(task)
	return true
}

// enqueuePendingOffDiscoveryBackfill 用于失败/重启后的重试：只读持久化的
// off 发现 pending 区间，在没有其它补全任务时重建 log-only 任务。
func (g *GroupInfo) enqueuePendingOffDiscoveryBackfill(d *Dice, ep *EndPointInfo, logState GroupLogState) bool {
	if g == nil || d == nil || ep == nil || !logState.On || logState.ID == 0 || logState.Name == "" {
		return false
	}
	// 与当前日志状态一致才重建；并发 .log new/off 时宁可让下一条消息再试，
	// 也不能把旧日志的 pending 窗口写进新日志。
	g.logWriteMu.RLock()
	current := g.GetLogState()
	currentEpoch := g.logEpoch.Load()
	g.logWriteMu.RUnlock()
	if !current.On || current.ID != logState.ID || current.Name != logState.Name {
		return false
	}
	fromSeq, toSeq, offDiscovery := g.pendingLogGapRangeSnapshot()
	if !offDiscovery || fromSeq <= 0 || toSeq <= fromSeq || g.hasAnyLogGapTask() {
		return false
	}
	task := logGapFillTask{
		dice:            d,
		endpoint:        ep,
		group:           g,
		logID:           current.ID,
		logName:         current.Name,
		epoch:           currentEpoch,
		fromSeq:         fromSeq,
		toSeq:           toSeq,
		gap:             toSeq - fromSeq - 1,
		discoverFromOff: true,
		backfillOnly:    true,
	}
	g.enqueueLogGapFill(task)
	return true
}

// enqueuePreOffBackfillAfterResume 在 .bot on/.log on 取消掉“off 前窗口”
// 授权任务后，用恢复后的新 epoch 重新挂一个只补日志的任务。
//
// .bot on 的 resetLogSeq 和 resume 都会推进 epoch/清 pending，旧任务因此
// 停止；但 off 之前那段消息仍然属于应记录的 on 段，不能随旧任务一起丢。
// 新任务只写日志、不执行历史指令，避免恢复后重放旧命令。
func (g *GroupInfo) enqueuePreOffBackfillAfterResume(d *Dice, ep *EndPointInfo, fromSeq, toSeq int64) bool {
	if g == nil || d == nil || ep == nil || fromSeq <= 0 || toSeq <= fromSeq {
		return false
	}
	// 1119.fix1: 老数据可能在 LogCurID=0 时就被 .bot off 暂停；恢复后
	// ensureGroupLogState 还没机会补 ID，直接返回会导致 off 前窗口不补录。
	// 这里在锁内按名字找回/创建一次，后续任务才能用正确的 logID。
	g.logWriteMu.Lock()
	current := g.GetLogState()
	if current.On && current.ID == 0 && current.Name != "" && d.DBOperator != nil {
		if id, err := service.LogGetOrCreate(d.DBOperator, g.GroupID, current.Name); err == nil && id > 0 {
			g.SetLogState(id, current.Name, true)
			current.ID = id
		} else if d.Logger != nil {
			d.Logger.Warnf("off 前补录无法补全 logID: 群=%s 名称=%s err=%v", g.GroupID, current.Name, err)
		}
	}
	currentEpoch := g.logEpoch.Load()
	g.logWriteMu.Unlock()
	if !current.On || current.ID == 0 || current.Name == "" {
		return false
	}
	task := logGapFillTask{
		dice:         d,
		endpoint:     ep,
		group:        g,
		logID:        current.ID,
		logName:      current.Name,
		epoch:        currentEpoch,
		fromSeq:      fromSeq,
		toSeq:        toSeq,
		gap:          toSeq - fromSeq - 1,
		forceLogOnly: true,
	}
	g.enqueueLogGapFill(task)
	return true
}

// calibrateLogSeqBaseline 在进程内首次记日志时，用数据库里该日志的 MAX(seq)
// 校准 seq 基线，返回校准后的上一条 seq 与 RawID。
//
// 为什么需要：logLastSeq 是运行时字段，重启后只由持久基线（.log on/.log new
// 那一刻的序号）恢复。直接拿它算缺口会把 .log on 之后已经落库的整段历史当成
// 断层（最多拉取 logGapFillMaxMessages 条已记录消息），同时真正的离线缺口
// 因为基线被 updateLogSeq 直接推到最新而永远补不上。
//
// 每个进程只查一次（成功后置 logSeqCalibrated），不会给消息主路径增加常态开销。
func calibrateLogSeqBaseline(d *Dice, group *GroupInfo, logID uint64, lastSeq int64, lastMsgID interface{}) (int64, interface{}, bool) {
	if group == nil {
		return lastSeq, lastMsgID, false
	}
	if d == nil || d.DBOperator == nil || logID == 0 {
		// 没有数据库/日志 ID，校准不适用；标记已校准，避免每条消息重复判断。
		group.markLogSeqCalibrated()
		return lastSeq, lastMsgID, true
	}
	if !group.needLogSeqCalibration() {
		return lastSeq, lastMsgID, true
	}
	seq, err := service.LogGetLastSeq(d.DBOperator, logID)
	if err != nil {
		// 查不到就保持原基线；退避一分钟再试，避免数据库异常时每条消息都查库。
		// 返回 false 让调用方不要用陈旧基线算缺口（否则会重复补录）。
		group.deferLogSeqCalibration(time.Minute)
		return lastSeq, lastMsgID, false
	}
	group.markLogSeqCalibrated()
	if seq <= lastSeq {
		return lastSeq, lastMsgID, true
	}
	group.advanceLogSeq(seq, nil)
	// 数据库里最后一条消息没有携带 RawID，避免断层通知引用错误的消息。
	return seq, nil, true
}

// endpointSupportsLogGapFill 判断平台是否具备“按 seq 拉取群历史”的能力。
//
// 日志断层补全依赖 per-group 的 Message.Seq：只有 OneBot 链路会填充 Seq
// 并实现历史拉取。KOOK、官方 QQ 等平台的 Seq 恒为 0（KOOK 的 sn 是
// per-session 的 WebSocket 序号，不是群消息序号），当前没有接入补全。
// 内置 Lagrange.OneBot 的事件不携带 message_seq，历史接口也只认 message_id，
// 因此显式排除，避免 README/UI 声称支持但实际永远不触发。
// 这里显式挡在入队之前，避免以后给不支持的平台误建补全任务。
func endpointSupportsLogGapFill(ep *EndPointInfo) bool {
	if ep == nil || ep.Adapter == nil {
		return false
	}
	if gocq, ok := ep.Adapter.(*PlatformAdapterGocq); ok && gocq.BuiltinMode == "lagrange" {
		return false
	}
	if _, ok := ep.Adapter.(HistoryRangeFetcher); ok {
		return true
	}
	_, ok := ep.Adapter.(HistoryFetcher)
	return ok
}

// logGapFillPlatformNotice 在日志开启时明确告知用户：当前渠道不支持
// 掉线自动补全。只对已知的无 seq 渠道提示（KOOK、官方 QQ、内置 Lagrange），
// 避免给测试/未知适配器臆造限制。
func logGapFillPlatformNotice(ep *EndPointInfo) string {
	if ep == nil {
		return ""
	}
	knownUnsupported := ep.Platform == "KOOK" || isOfficialQQEndpoint(ep) ||
		func() bool {
			gocq, ok := ep.Adapter.(*PlatformAdapterGocq)
			return ok && gocq.BuiltinMode == "lagrange"
		}()
	if !knownUnsupported || endpointSupportsLogGapFill(ep) {
		return ""
	}
	return "\n当前渠道不支持掉线日志自动补全（KOOK、官方 QQ、内置 Lagrange 等未接入群消息历史序号/历史拉取的渠道），请保持核心在线。"
}

// cloneGapTriggerMessage 复制触发补全任务的实时消息。
// 任务异步执行时，命令处理器/扩展可能继续改写原 msg（如 st 的指令别名替换）；
// 历史状态判断只依赖 trigger 的 Message/Platform/Sender/Seq，复制标量即可避免
// 读到被后续改写的命令文本。
func cloneGapTriggerMessage(msg *Message) *Message {
	if msg == nil {
		return nil
	}
	cp := *msg
	return &cp
}

// logGapFillTask 描述一次 seq 断层补全。
type logGapFillTask struct {
	dice      *Dice
	endpoint  *EndPointInfo
	group     *GroupInfo
	logID     uint64
	logName   string
	epoch     uint64 // 创建时的日志基线代次；epoch 变化说明基线已重建，任务必须取消
	fromSeq   int64
	toSeq     int64
	gap       int64 // 已扣除骰子自身发言的净遗漏条数，仅用于阈值判定，不可当作拉取条数
	lastMsgID interface{}
	// trigger 是触发本任务的实时消息（toSeq 对应它）。历史 .log off/.log on
	// 过滤后，需要用它判断“实时路径是否已经把不该记录的第一条消息写进日志”。
	trigger *Message
	// discoverFromOff 表示这是 live 日志关闭期间的“历史 .log on 发现”任务：
	// 从 LogSeenSeq 开始扫描，起点状态为 off；找到 .log on 后补 on 段，
	// 最终 on 时恢复 live 日志。
	discoverFromOff bool
	// backfillOnly 表示 live 日志已经被实时 .log on 打开，任务只负责把
	// (fromSeq, toSeq) 之间历史记录确认的 on 段补进当前日志：
	// 不写触发消息、不改变 live 状态、不 adopt。用于实时命令先执行、
	// 异步发现任务被 epoch 变化取消时保住离线 on 段。
	backfillOnly bool
	// forceLogOnly 表示任务只补日志、不执行历史指令。用于 .bot on/.log on
	// 在 off 前窗口任务完成前恢复日志：旧任务会因 epoch/LogOn 变化停止，
	// 重新挂的任务沿用同一窗口，但不能再执行旧指令。
	forceLogOnly bool
}

// logStateStillValid 校验补全任务对应的日志仍是该群当前开启的日志。
// 任务可能排在前一个补全后面几十秒，期间用户可能 .log off / .log new 或删除日志。
// 不校验的话：静默重放会在日志关闭后执行指令（OnMessageReceived 不记日志），
// 切换日志后补录内容会写进新日志，删除日志后每条 LogAppend 都会失败并误报
// “数据库结构未升级”。
func (t logGapFillTask) logStateStillValid() bool {
	if t.group == nil {
		return false
	}
	state := t.group.GetLogState()
	if !state.On || state.ID != t.logID || state.Name != t.logName {
		return false
	}
	// epoch 变化说明 .log on/new、.bot on 或日志重建已经重置了 seq 基线：
	// 在途/排队的旧区间不能再写，否则会把 off/静默期间的消息补进日志。
	// 注意：epoch 可能本来就是 0（老群数据首次加载），不能用 0 当“跳过校验”
	// 的哨兵；任务必须携带创建时的真实 epoch。
	if t.group.logEpoch.Load() != t.epoch {
		return false
	}
	return true
}

// logOffGapFillAllowed 判断任务是否持有有效的“off 前窗口”授权。
//
// 条件：日志已经关闭、但仍是同一本日志、epoch 未变，授权端点一致，且任务窗口
// 完全位于 off 指令之前（toSeq <= offSeq）。这样 off 指令之后（含指令本身）
// 永远不会被写入。
func (t logGapFillTask) logOffGapFillAllowed() bool {
	if t.group == nil || t.toSeq <= 0 {
		return false
	}
	state := t.group.GetLogState()
	if state.On || state.ID != t.logID || state.Name != t.logName {
		return false
	}
	if t.group.logEpoch.Load() != t.epoch {
		return false
	}
	auth := t.group.logOffGapAuthSnapshot()
	return auth != nil &&
		auth.logID == t.logID &&
		auth.logName == t.logName &&
		auth.epoch == t.epoch &&
		t.toSeq <= auth.offSeq
}

// logHistoricalDiscoveryAllowed 判断 off 状态下的历史 .log on 发现任务是否
// 仍可继续：live 日志保持关闭、仍是同一本日志、epoch 未变。
// 任务窗口内的 on 段由历史扫描保证，只补日志。
func (t logGapFillTask) logHistoricalDiscoveryAllowed() bool {
	if !t.discoverFromOff || t.group == nil || t.toSeq <= 0 {
		return false
	}
	state := t.group.GetLogState()
	if state.On || state.ID != t.logID || state.Name != t.logName {
		return false
	}
	return t.group.logEpoch.Load() == t.epoch
}

// logOffDiscoveryBackfillAllowed 判断“实时 .log on 已先执行”后的历史补录
// 任务是否仍可继续：只要求仍是同一本日志且 epoch 未变（任务在 reset 之后
// 创建），不要求 LogOn=false。这样实时处理器打开日志后，离线 on 段仍能
// 以 log-only 方式补进来，不会被 epoch 变化一并取消。
func (t logGapFillTask) logOffDiscoveryBackfillAllowed() bool {
	if !t.discoverFromOff || !t.backfillOnly || t.group == nil || t.toSeq <= 0 {
		return false
	}
	state := t.group.GetLogState()
	if state.ID != t.logID || state.Name != t.logName {
		return false
	}
	return t.group.logEpoch.Load() == t.epoch
}

// logFillWritable 是补录写入的统一放行判断：日志正常开启，或持有 off 前窗口
// 授权，或这是 off 状态下的历史 .log on 发现任务。
func (t logGapFillTask) logFillWritable() bool {
	return t.logStateStillValid() || t.logOffGapFillAllowed() ||
		t.logHistoricalDiscoveryAllowed() || t.logOffDiscoveryBackfillAllowed()
}

// forEachMissing 按顺序遍历缺失消息，并在处理每条之前确认日志仍然有效。
//
// 只在任务开始/拉取结束时校验是不够的：缺口可能跨多段、每段最多
// logGapFillMaxMessages 条，静默重放还要执行指令，期间用户完全可能
// .log off / .log new。不逐条校验的话，关掉的日志仍会被继续
// 写入（用户看到的就是“off 之后内容还在进日志”），静默重放还会在日志关闭后
// 继续执行历史指令却不留记录。返回实际处理条数，小于 len(missing) 表示被中止。
//
// 使用 logFillWritable 而不是 logStateStillValid：持有 off 前窗口授权的任务
// 在 LogOn=false 后仍可补完该窗口；无授权时两者行为完全一致。
func (t logGapFillTask) forEachMissing(missing []*Message, fn func(*Message)) int {
	for i, m := range missing {
		if !t.logFillWritable() {
			return i
		}
		fn(m)
	}
	return len(missing)
}

// enqueueLogGapFill 把断层加入队列；相邻/重叠区间会合并，由单 worker 串行补全。
func (g *GroupInfo) enqueueLogGapFill(task logGapFillTask) {
	if g == nil || task.dice == nil {
		return
	}
	if !g.mergeLogGapTask(task) {
		return
	}
	panicHandler.Once(task.dice.Logger, g.runLogGapWorker)
}

// retryPendingLogGapTask 在 worker 已退出、但 persistent pending 仍保留时，
// 用当前 endpoint 重新触发排队任务。用于 off 前窗口任务失败后，日志已关闭、
// 不会再有 on 状态消息来触发 pending floor 的情况。
func (g *GroupInfo) retryPendingLogGapTask(d *Dice, ep *EndPointInfo) bool {
	if g == nil {
		return false
	}
	g.logGapQueueMu.Lock()
	pending := g.logGapPending
	g.logGapQueueMu.Unlock()
	if pending == nil || pending.discoverFromOff {
		return false
	}
	task := *pending
	if d != nil {
		task.dice = d
	}
	if ep != nil {
		task.endpoint = ep
	}
	g.enqueueLogGapFill(task)
	return true
}

// sameLogGapStream 报告两个任务是否属于同一本日志、同一 epoch、同一模式。
// 只有同一流的区间才能安全合并。
func sameLogGapStream(a, b *logGapFillTask) bool {
	return a != nil && b != nil &&
		a.logID == b.logID && a.logName == b.logName &&
		a.epoch == b.epoch && a.discoverFromOff == b.discoverFromOff
}

// mergeLogGapTaskWindow 把 src 的窗口并入 dst，保留更早起点和更晚终点。
func mergeLogGapTaskWindow(dst, src *logGapFillTask) {
	if dst == nil || src == nil {
		return
	}
	if src.fromSeq > 0 && (dst.fromSeq == 0 || src.fromSeq < dst.fromSeq) {
		dst.fromSeq = src.fromSeq
		dst.lastMsgID = src.lastMsgID
	}
	if src.toSeq > dst.toSeq {
		dst.toSeq = src.toSeq
		dst.trigger = src.trigger
	}
	if src.endpoint != nil {
		dst.endpoint = src.endpoint
	}
	if src.dice != nil {
		dst.dice = src.dice
	}
	dst.backfillOnly = dst.backfillOnly || src.backfillOnly
	// 1119.fix1: 只补日志的“off 前窗口”任务被普通任务合并时，限制不能丢；
	// 否则合并后的任务可能重放历史指令或按历史 .log off 再次关闭 live 日志。
	dst.forceLogOnly = dst.forceLogOnly || src.forceLogOnly
	// gap 只用于静默阈值判定，沿用原合并语义累加净遗漏数；
	// 不能用窗口跨度过早放大阈值。
	dst.gap += src.gap
}

// mergeLogGapTask 合并待处理区间，返回是否需要启动 worker。
func (g *GroupInfo) mergeLogGapTask(task logGapFillTask) bool {
	g.logGapQueueMu.Lock()
	defer g.logGapQueueMu.Unlock()

	pending := g.logGapPending
	running := g.logGapRunningTask

	switch {
	case pending == nil && running != nil && sameLogGapStream(running, &task):
		// worker 已经把前一个任务取走（logGapPending=nil），新任务与它同流。
		// 1118: 不能让新任务重置 pending 区间，否则前一个任务失败后它的
		// 区间就永久丢失了。排队任务覆盖两者的并集；前一个任务失败时由
		// 这个并集重试，成功时去重跳过。
		t := *running
		mergeLogGapTaskWindow(&t, &task)
		g.logGapPending = &t
		g.setLogGapPendingRangeMode(t.fromSeq, t.toSeq, t.discoverFromOff)
	case pending == nil:
		t := task
		g.logGapPending = &t
		// 日志切换（ID/名称/epoch/模式变化）时旧区间已无意义，重置 pending。
		g.replaceLogGapPendingRange(t.fromSeq, t.toSeq, t.discoverFromOff)
	case sameLogGapStream(pending, &task):
		mergeLogGapTaskWindow(pending, &task)
		// 运行中任务也属于同一流时，把它的窗口并进排队任务，确保它失败
		// 后排队任务能覆盖整段区间。
		if running != nil && sameLogGapStream(running, &task) {
			mergeLogGapTaskWindow(pending, running)
		}
		g.setLogGapPendingRangeMode(pending.fromSeq, pending.toSeq, pending.discoverFromOff)
	default:
		t := task
		if running != nil && sameLogGapStream(running, &task) {
			mergeLogGapTaskWindow(&t, running)
		}
		g.logGapPending = &t
		// 模式/日志/epoch 不同：旧 pending 已无意义，替换并重置区间。
		g.replaceLogGapPendingRange(t.fromSeq, t.toSeq, t.discoverFromOff)
	}
	if p := g.logGapPending; p != nil {
		if p.discoverFromOff {
			// off 状态发现任务每次都以同一个 LogSeenSeq 为起点，合并时不能累加
			// 各次 gap（会重复计数），直接用最终窗口重算；只用于日志展示。
			p.gap = p.toSeq - p.fromSeq - 1
		}
	}
	if task.dice != nil {
		g.MarkDirty(task.dice)
	}

	if g.logGapWorkerRunning {
		return false
	}
	g.logGapWorkerRunning = true
	return true
}

// runLogGapWorker 串行消费合并后的断层。
// 单个任务 panic 只丢这一段，不能让 worker 标志卡死：CreateTempCtx 在端点
// 尚未就绪时会 panic，而断层补全恰好运行在刚重连之后。
func (g *GroupInfo) runLogGapWorker() {
	for {
		g.logGapQueueMu.Lock()
		task := g.logGapPending
		g.logGapPending = nil
		if task == nil {
			g.logGapRunningTask = nil
			g.logGapWorkerRunning = false
			g.logGapRunningOffDiscovery.Store(false)
			g.logGapQueueMu.Unlock()
			return
		}
		// 在队列锁内标记“正在跑 off 发现”，避免 .log on/.log off 在
		// take 任务与标记之间看到空档。
		g.logGapRunningTask = task
		g.logGapRunningOffDiscovery.Store(task.discoverFromOff)
		g.logGapQueueMu.Unlock()

		func() {
			defer func() {
				if r := recover(); r != nil {
					if task.dice != nil && task.dice.Logger != nil {
						groupID := ""
						if task.group != nil {
							groupID = task.group.GroupID
						}
						task.dice.Logger.Errorf("日志补全任务异常: 群=%s %v\n%s", groupID, r, debug.Stack())
					}
				}
			}()
			task.run()
		}()
		g.logGapQueueMu.Lock()
		if g.logGapRunningTask == task {
			g.logGapRunningTask = nil
		}
		g.logGapQueueMu.Unlock()
		g.logGapRunningOffDiscovery.Store(false)
	}
}

func (t logGapFillTask) run() {
	if t.group == nil || t.dice == nil || t.endpoint == nil {
		return
	}
	if t.discoverFromOff {
		allowed := t.logHistoricalDiscoveryAllowed()
		if t.backfillOnly {
			// live 已被实时 .log on 打开：只要求同一本日志、epoch 未变，
			// 不要求 LogOn=false，否则离线 on 段会被实时处理器一起取消。
			allowed = t.logOffDiscoveryBackfillAllowed()
		}
		if !allowed {
			t.dice.Logger.Infof("日志补全已取消(off 状态历史发现): 群=%s 记录=%s 日志已开启或被切换",
				t.group.GroupID, t.logName)
			t.group.clearLogGapPendingIfIdle(t.dice)
			return
		}
		t.dice.Logger.Infof("日志补全继续(off 状态历史发现): 群=%s 记录=%s 窗口=%d..%d",
			t.group.GroupID, t.logName, t.fromSeq, t.toSeq)
	} else {
		offMode := !t.logStateStillValid()
		if offMode && !t.logOffGapFillAllowed() {
			t.dice.Logger.Infof("日志补全已取消: 群=%s 记录=%s 已关闭或被切换", t.group.GroupID, t.logName)
			t.group.clearLogGapPendingIfIdle(t.dice)
			return
		}
		if offMode {
			t.dice.Logger.Infof("日志补全继续(off 前窗口): 群=%s 记录=%s 窗口=%d..%d",
				t.group.GroupID, t.logName, t.fromSeq, t.toSeq)
		}
	}

	if !endpointSupportsLogGapFill(t.endpoint) {
		t.dice.Logger.Infof("日志补全跳过: 平台不支持按 seq 拉取历史: 群=%s 平台=%s",
			t.group.GroupID, t.endpoint.Platform)
		// 平台永远补不了这段；不要让它每次重启都把基线拉回。
		t.group.clearLogGapPendingIfIdle(t.dice)
		return
	}
	fetcher, ok := t.endpoint.Adapter.(HistoryFetcher)
	if !ok {
		t.dice.Logger.Infof("日志补全跳过: 平台未实现历史消息拉取: 群=%s 平台=%s",
			t.group.GroupID, t.endpoint.Platform)
		t.group.clearLogGapPendingIfIdle(t.dice)
		return
	}

	// 拉取整体失败后的退避期内不再发起历史拉取。pending 区间保留，退避
	// 结束后由下一条消息的 pending floor / 新任务重新触发；这样退避对
	// “已合并任务”和“新产生的断层”同样生效，而不只是挡住 floor。
	if retryAt := t.group.logGapRetryAt.Load(); retryAt > time.Now().Unix() {
		t.dice.Logger.Debugf("日志补全退避中: 群=%s 下次重试=%d", t.group.GroupID, retryAt)
		return
	}

	t.dice.Logger.Infof("检测到日志seq断层: 群=%s 上条seq=%d 本条seq=%d 缺失=%d",
		t.group.GroupID, t.fromSeq, t.toSeq, t.gap)

	fetchCtx, cancel := context.WithTimeout(context.Background(), logGapFillTimeout)
	defer cancel()

	// 从缺口起点向终点分段扫描：每段最多 logGapFillMaxMessages 条，
	// on/off 状态跨段传递。不能只拉最近一段再按 startOn 过滤——如果
	// .log off 在最近窗口之前，窗口内的 off 段会被误当成 on 段补录；
	// 反过来 off 起点任务也会漏掉窗口之前开始的 on 段。
	allMissing := make([]*Message, 0)
	hist := logGapLifecycleInfo{finalOn: !t.discoverFromOff}
	stateOn := !t.discoverFromOff
	// 一旦历史上出现过 .log off/.log on，后续段的状态就不再等于任务的
	// 起始状态；此时不能把 pending 起点前移，否则重试会从段中开始，
	// 用错误的 startOn 把 off 段当 on 段补录。生命周期命令所在段保留在
	// pending 起点，重试会重新扫描它并恢复正确状态。
	stateChanged := false
	totalGap := t.toSeq - t.fromSeq - 1
	multiSegment := totalGap > logGapFillMaxMessages
	if multiSegment {
		t.dice.Logger.Infof("日志缺口较大(共%d条)，按%d条一段分段扫描: 群=%s",
			totalGap, logGapFillMaxMessages, t.group.GroupID)
		// 分段写库前重置写入失败标记；任一段写入失败都会保留 pending。
		t.group.beginLogGapWriteTracking()
	}
	for curFrom := t.fromSeq; curFrom < t.toSeq-1; {
		segTo := curFrom + logGapFillMaxMessages + 1
		if segTo > t.toSeq {
			segTo = t.toSeq
		}
		seg := t
		seg.fromSeq = curFrom
		seg.toSeq = segTo
		msgs, coveredTo, err := seg.fetchHistoryWithCoverage(fetchCtx, fetcher)
		if err != nil {
			t.dice.Logger.Errorf("日志补全拉取历史消息失败: 群=%s 起始seq=%d err=%v",
				t.group.GroupID, seg.fromSeq, err)
			// 保留从当前段开始的 pending 区间以便之后重试，但必须退避：
			// 否则每条新消息都会重新触发一次最长 120s 的拉取。
			t.group.mergeLogGapPendingRangeMode(curFrom, t.toSeq, t.discoverFromOff)
			t.group.MarkDirty(t.dice)
			t.group.deferLogGapRetry(logGapFillRetryBackoff)
			return
		}
		missing := seg.filterMissing(msgs)
		// 先按历史 .log off/.log on 重建 on/off 区间，再做“已落库”去重。
		// 顺序不能反：如果某条 .log off 在之前失败的补录里已经写入数据库，
		// 去重会把它从列表里删掉；但它仍必须参与状态推断，否则后面的 off 段
		// 会被误当成 on 段补进来。
		filtered, info := seg.filterHistoricalLogOffOn(missing, stateOn)
		filtered, dedupeOK := seg.filterAlreadyLogged(filtered)
		if !dedupeOK {
			// 去重查询失败不能当成“没有缺失消息”清掉 pending：否则一次 READ
			// 库抖动就会让这段缺口永久丢失。保留 pending，按 2 分钟退避重试。
			t.group.mergeLogGapPendingRangeMode(curFrom, t.toSeq, t.discoverFromOff)
			t.group.MarkDirty(t.dice)
			t.group.deferLogGapRetry(logGapFillRetryBackoff)
			return
		}

		// 1118: 大缺口分段写库。每段拉完立即写日志并前移 pending 起点，
		// 这样后续段失败/进程重启只重试剩余部分，不会把前几段已拉到的
		// 数据全部丢弃，也不会永远从原始 fromSeq 重扫。
		segmentComplete := true
		if multiSegment && len(msgs) > 0 {
			if len(filtered) > 0 {
				_, segmentComplete = seg.appendSegmentLogOnly(filtered)
			}
			if !t.group.logGapWritesOK() {
				t.group.mergeLogGapPendingRangeMode(curFrom, t.toSeq, t.discoverFromOff)
				t.group.MarkDirty(t.dice)
				t.dice.Logger.Warnf("日志补全分段写入失败，保留 pending 并退避: 群=%s 起始seq=%d",
					t.group.GroupID, curFrom)
				t.group.deferLogGapRetry(logGapFillRetryBackoff)
				return
			}
			if segmentComplete && coveredTo > curFrom && !stateChanged && !info.found {
				if t.group.advanceLogGapPendingStart(coveredTo, t.toSeq, t.discoverFromOff) {
					t.group.MarkDirty(t.dice)
				}
			}
		}

		allMissing = append(allMissing, filtered...)
		hist.found = hist.found || info.found
		if info.found {
			stateChanged = true
		}
		hist.finalOn = info.finalOn
		if info.lastOnSeq > hist.lastOnSeq {
			hist.lastOnSeq = info.lastOnSeq
		}
		stateOn = info.finalOn
		if !segmentComplete {
			// 日志在段内被关闭/切换；停止扫描，由收尾逻辑按取消处理。
			break
		}
		if info.stopped {
			hist.stopped = true
			hist.unsupported = info.unsupported
			break
		}
		if len(msgs) == 0 {
			// 空窗口不等于历史结束：平台可能因保留期/限流只返回空页。
			// 跳过本窗口继续探测后续窗口；如果整段都没有消息，最终会正常清 pending。
			curFrom = segTo - 1
			continue
		}
		if coveredTo < segTo-1 {
			if coveredTo <= curFrom {
				// 平台返回了消息但没有可用 seq（或 seq 不前进），不能假装
				// 扫完了。保留 pending 并退避，避免误报“补全成功”。
				t.group.mergeLogGapPendingRangeMode(curFrom, t.toSeq, t.discoverFromOff)
				t.group.MarkDirty(t.dice)
				t.dice.Logger.Warnf("日志补全无法前进(未覆盖到区间起点或历史消息缺少可用seq): 群=%s 起始seq=%d 已到seq=%d",
					t.group.GroupID, curFrom, coveredTo)
				t.group.deferLogGapRetry(logGapFillRetryBackoff)
				return
			}
			// 段内只拉到一部分：从实际覆盖到的 seq 继续，不能直接跳到段尾。
			curFrom = coveredTo
			continue
		}
		curFrom = segTo - 1
	}
	missing := allMissing

	if t.discoverFromOff {
		if t.backfillOnly {
			t.runOffBackfillOnly(missing, hist)
			return
		}
		t.runOffDiscovery(missing, hist)
		return
	}

	forceLogOnly := t.forceLogOnly
	if hist.found {
		if hist.stopped {
			forceLogOnly = true
			t.dice.Logger.Warnf("日志补全历史状态推断已停止: 群=%s 命令=%s，后续缺口不补",
				t.group.GroupID, hist.unsupported)
		} else if t.logStateStillValid() {
			decision := t.decideHistoricalLogState(hist)
			if decision.stopped {
				forceLogOnly = true
				t.dice.Logger.Warnf("日志补全历史状态推断已停止: 群=%s 命令=%s，后续缺口不补",
					t.group.GroupID, decision.reason)
			} else {
				if decision.deleteTrigger {
					t.deleteTriggerRow()
				}
				// 预恢复补录任务只写日志，不根据历史再改 live 状态：
				// 日志刚刚由 .bot on/.log on 打开，不能被窗口里的旧命令关掉。
				if decision.applyLiveOff && !t.forceLogOnly {
					// 1118: 这是补录按历史 .log off 推断出的关闭，不是用户
					// 此刻的显式命令，不能留下 logOffRequested 标记。
					if _, ok := t.group.logOffForHistoryAtSeq(t.toSeq); ok {
						t.group.MarkDirty(t.dice)
						t.dice.Logger.Infof("日志补全按历史 .log off 关闭当前日志: 群=%s seq=%d",
							t.group.GroupID, t.toSeq)
					}
				}
				forceLogOnly = forceLogOnly || decision.forceLogOnly
			}
		} else {
			// live 已被 .log off/.bot off 关闭，当前任务走 off 前窗口授权；
			// 只需要用过滤后的消息列表，不再改 live 状态。
			forceLogOnly = true
			// 历史缺口已经处于 off，实时再收到的 .log off 只是重复命令：
			// 它不该被记录，但实时路径在本地仍认为 on 时会先写进去。
			if !hist.finalOn {
				if kind, _, ca := t.parseLogLifecycleCommand(t.trigger); kind == "off" &&
					t.lifecycleCommandValid(t.trigger, ca) {
					t.deleteTriggerRow()
				}
			}
		}
	}

	if len(missing) == 0 {
		t.dice.Logger.Infof("日志补全无需处理: 群=%s 缺失区间内没有需要补录的他人发言", t.group.GroupID)
		t.group.clearLogGapPendingIfIdle(t.dice)
		return
	}

	// 拉取历史可能耗时数十秒，写入前必须再确认一次日志状态。
	// 允许“日志已关闭但持有 off 前窗口授权”的任务继续。
	if !t.logFillWritable() {
		t.dice.Logger.Infof("日志补全已取消: 群=%s 记录=%s 在拉取期间已关闭或被切换", t.group.GroupID, t.logName)
		t.group.clearLogGapPendingIfIdle(t.dice)
		return
	}

	// 记录本次补录期间是否发生过日志写入失败。失败不能当成“补全完成”：
	// 写入侧短暂故障（磁盘满、锁超时、只读库）恢复后，这段缺口仍应可重试。
	t.group.beginLogGapWriteTracking()
	done := true
	if forceLogOnly || !t.logStateStillValid() {
		// 拉取/排队期间已经 .log off/.bot off，或历史 .log off/.log on
		// 推断要求只补日志：不执行历史指令，但补录完成后要告知用户。
		appended, backfillDone := t.backfillLogOnlyCount(missing)
		done = backfillDone
		if appended > 0 || hist.found {
			notice := fmt.Sprintf("检测到seq不连贯，已补录 %d 条记录。", appended)
			if !t.logStateStillValid() {
				notice = fmt.Sprintf("日志已关闭，已补录关闭前的 %d 条记录。", appended)
			}
			if hist.stopped {
				notice += fmt.Sprintf("\n遇到 %s 后停止补录。", hist.unsupported)
			}
			t.sendGroupNotice(notice)
		}
	} else if t.gap <= logGapFillSilentThreshold {
		done = t.replaySilently(missing)
	} else {
		t.backfillWithNotice(missing)
	}
	// 日志在补录过程中被关闭/切换是明确取消，pending 不再需要恢复。
	// off 前窗口授权仍有效时继续走完成/写入失败收尾。
	if !t.logFillWritable() {
		t.group.clearLogGapPendingIfIdle(t.dice)
		return
	}
	// 端点会话未绑定（replaySilently 返回 false）是暂时状态，保留 pending
	// 等下次启动/重试，但不能清区间。
	if !done {
		return
	}
	if t.group.logGapWritesOK() {
		t.group.clearLogGapPendingIfIdle(t.dice)
		return
	}
	// 有消息没写进日志：保留 pending 并退避，避免每条新消息都重新拉取历史；
	// 退避到期后由 pending floor / 新任务恢复，已写入的行会由去重跳过。
	t.dice.Logger.Warnf("日志补全写入失败，保留 pending 并退避: 群=%s 记录=%s", t.group.GroupID, t.logName)
	t.group.deferLogGapRetry(logGapFillRetryBackoff)
}

// fetchHistory 按页拉取 (fromSeq, toSeq) 区间，直到覆盖到 toSeq-1 或达到上限。
// 单次 get_group_msg_history 的 count 有实现上限（常见 100），不能一次性传整个断层。
// fetchHistoryWithCoverage 与 fetchHistory 相同，但额外返回本次实际覆盖到的
// 最大 seq。1118: 调用方必须用它判断“这一页/这一段是否真的扫完了”；空页
// 或平台限流返回的部分结果不能被当成历史结束。
func (t logGapFillTask) fetchHistoryWithCoverage(ctx context.Context, fetcher HistoryFetcher) ([]*Message, int64, error) {
	var lastErr error
	for attempt := range logGapFillFetchRetries {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, 0, ctx.Err()
			case <-time.After(time.Duration(1<<uint(attempt-1)) * time.Second):
			}
		}
		msgs, coveredTo, err := t.fetchHistoryOnceWithCoverage(ctx, fetcher)
		if err == nil {
			return msgs, coveredTo, nil
		}
		lastErr = err
		t.dice.Logger.Warnf("日志补全拉取历史消息失败(第%d次): 群=%s err=%v", attempt+1, t.group.GroupID, err)
	}
	return nil, 0, lastErr
}

// logGapFetchWindow 计算一次补全实际要拉取的区间起点与条数。
// total 为 0 表示区间内没有消息；区间过大时只保留最近 logGapFillMaxMessages 条。
// 拉取与“已记录消息”去重查询必须用同一个窗口：否则离线数天时补录只拉最近
// 2000 条，却为整个断层（可能几十万 seq）建去重集合，白查一遍数据库。
func logGapFetchWindow(fromSeq, toSeq int64) (from, total int64) {
	if toSeq <= fromSeq+1 {
		return fromSeq, 0
	}
	total = toSeq - fromSeq - 1
	from = fromSeq
	if total > logGapFillMaxMessages {
		total = logGapFillMaxMessages
		from = toSeq - 1 - total
		if from < fromSeq {
			from = fromSeq
		}
	}
	return from, total
}

func (t logGapFillTask) fetchHistoryOnce(ctx context.Context, fetcher HistoryFetcher) ([]*Message, error) {
	msgs, _, err := t.fetchHistoryOnceWithCoverage(ctx, fetcher)
	return msgs, err
}

func (t logGapFillTask) fetchHistoryOnceWithCoverage(ctx context.Context, fetcher HistoryFetcher) ([]*Message, int64, error) {
	from, total := logGapFetchWindow(t.fromSeq, t.toSeq)
	if total <= 0 {
		return nil, t.fromSeq, nil
	}
	if from > t.fromSeq {
		t.dice.Logger.Warnf("日志补全区间过大(共%d条)，仅补录最近%d条(seq %d-%d): 群=%s 上条seq=%d 本条seq=%d",
			t.toSeq-t.fromSeq-1, total, from, t.toSeq-1, t.group.GroupID, t.fromSeq, t.toSeq)
	}

	// 新接口由适配器自己按平台语义翻页，调用方不再假设“fromSeq 之后”。
	// 这是 1119 的核心修复：SnowLuma 只认 message_id、go-cqhttp 的
	// message_seq 是窗口终点，统一按正向分页必然丢首条/误判覆盖。
	if rangeFetcher, ok := fetcher.(HistoryRangeFetcher); ok {
		req := HistoryRangeRequest{
			GroupID:   t.group.GroupID,
			FromSeq:   from,
			ToSeq:     t.toSeq,
			Count:     int(total),
			FromRawID: t.lastMsgID,
		}
		if t.trigger != nil {
			req.ToRawID = t.trigger.RawID
		}
		msgs, complete, err := rangeFetcher.FetchGroupMsgHistoryRange(ctx, req)
		if err != nil {
			return nil, from, err
		}
		msgs = historyRangeFilter(msgs, from, t.toSeq)
		if complete {
			return msgs, t.toSeq - 1, nil
		}
		if len(msgs) == 0 {
			// 拿到了“最新一页”但没有任何区间内消息，且没有覆盖到起点：
			// 必须保留 pending，不能当成空历史清掉。
			return nil, from, errLogGapHistoryNoProgress
		}
		// 1119.fix1: complete=false 表示还没扫到区间起点。此时绝不能把
		// 已取到消息的最大 seq 当作“已覆盖到段尾”：run() 会据此前移
		// pending 起点并跳过未扫到的前半段，造成静默丢消息。返回起点
		// 表示“本轮没有可前移的覆盖”，由 run() 保留 pending 并退避重试。
		// 已取到的部分消息仍会返回；多段模式下 run() 会先按 on/off 过滤
		// 后写库，单段模式下则等待下一次完整拉取，避免误写 off 段。
		return msgs, from, nil
	}

	all := make([]*Message, 0, total)
	seen := make(map[int64]struct{}, total)
	coveredTo := from
	for int64(len(all)) < total && from < t.toSeq-1 {
		count := int(t.toSeq - from - 1)
		if count > logGapFillPageSize {
			count = logGapFillPageSize
		}
		if remain := int(total) - len(all); count > remain {
			count = remain
		}
		if count <= 0 {
			break
		}

		pageCtx, cancel := context.WithTimeout(ctx, logGapFillPageTimeout)
		page, err := fetcher.FetchGroupMsgHistory(pageCtx, t.group.GroupID, from, count)
		cancel()
		if err != nil {
			return nil, 0, err
		}
		if len(page) == 0 {
			// 空页不等于任务结束：平台可能因历史保留期/限流只返回空。
			// 返回当前覆盖位置，由 run() 决定继续下一窗口还是保留 pending。
			break
		}

		maxSeq := from
		usableSeq := false
		for _, m := range page {
			if m == nil {
				continue
			}
			if m.Seq > from && m.Seq < t.toSeq {
				usableSeq = true
				if _, exists := seen[m.Seq]; !exists {
					seen[m.Seq] = struct{}{}
					all = append(all, m)
				}
			}
			if m.Seq > maxSeq {
				maxSeq = m.Seq
			}
		}
		if maxSeq <= from {
			// 实现没有返回可用的 seq，继续翻页只会死循环。把原始页返回给
			// run() 非空判断，让它走“无法前进”分支保留 pending，而不是
			// 静默当成空历史清掉。
			if !usableSeq {
				all = append(all, page...)
			}
			break
		}
		coveredTo = maxSeq
		from = maxSeq
	}

	if coveredTo > t.toSeq-1 {
		coveredTo = t.toSeq - 1
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].Seq < all[j].Seq })
	return all, coveredTo, nil
}

// filterMissing 保留断层区间内的他人发言。
// isGroupDiceSender 判断历史消息是否由本群的任一骰子端点发出。
// 只比较当前 endpoint 会漏掉同群其他端点：它们的骰子发言已经由各自的
// OnMessageSend 记过日志，补录时再当玩家消息写一遍会造成重复/归属错误。
func (t logGapFillTask) isGroupDiceSender(userID string) bool {
	if userID == "" {
		return false
	}
	if t.endpoint != nil && userID == t.endpoint.UserID {
		return true
	}
	if t.group == nil {
		return false
	}
	if t.group.DiceIDExistsMap != nil {
		if _, ok := t.group.DiceIDExistsMap.Load(userID); ok {
			return true
		}
	}
	if t.group.DiceIDActiveMap != nil {
		if _, ok := t.group.DiceIDActiveMap.Load(userID); ok {
			return true
		}
	}
	return false
}

// filterMissing 保留区间内、且不是本群任一骰子端点的消息。
// 骰子自身发言已由 OnMessageSend 记录，任何端点都不能再当玩家消息补录；
// 自身发言计数可能因重启丢失，所以这里按发送者兜底。
func (t logGapFillTask) filterMissing(msgs []*Message) []*Message {
	missing := make([]*Message, 0, len(msgs))
	for _, m := range msgs {
		if m == nil || m.Seq <= t.fromSeq || m.Seq >= t.toSeq {
			continue
		}
		if t.isGroupDiceSender(m.Sender.UserID) {
			continue
		}
		missing = append(missing, m)
	}
	return missing
}

// isBotSender 判断历史消息是否由机器人发出（含其他骰子）。
func (t logGapFillTask) isBotSender(m *Message) bool {
	if m == nil {
		return false
	}
	return m.Sender.IsRobot || (t.group != nil && t.group.IsBot(m.Sender.UserID, m.Sender.IsRobot))
}

// rawMsgIDKey 返回可用于去重的平台 raw_msg_id；空值/"0"/"<nil>" 都表示
// 平台没有提供可用的消息 ID。
func rawMsgIDKey(v interface{}) string {
	if v == nil {
		return ""
	}
	s := strings.TrimSpace(fmt.Sprintf("%v", v))
	if s == "" || s == "0" || s == "<nil>" {
		return ""
	}
	return s
}

// filterAlreadyLogged 跳过已经写入同一日志的消息。
// 平台重连补发、或补全任务与正常事件并发时，同一条消息可能既走事件路径又被历史拉取到；
// log_items 对 raw_msg_id 没有唯一约束，必须在补录前查一次。
// 返回值 ok=false 表示查询失败：调用方必须保留 pending 并退避重试，
// 不能把“查不到”当成“没有缺失消息”而清掉区间。
func (t logGapFillTask) filterAlreadyLogged(msgs []*Message) ([]*Message, bool) {
	if t.dice == nil || t.dice.DBOperator == nil {
		// 无数据库时无法判断哪些消息已经落库；宁可跳过本次补录，也不能重复写。
		// 无 DB 是永久状态，返回 ok=true 让调用方按“无法补录”收尾，避免无限退避。
		if t.dice != nil && t.dice.Logger != nil {
			t.dice.Logger.Warnf("日志补全跳过: 无法查询已记录消息（数据库不可用）: 群=%s", t.group.GroupID)
		}
		return nil, true
	}
	// 与 fetchHistoryOnce 使用同一窗口：超大断层只补最近 2000 条时，
	// 去重集合也只需覆盖这一段，避免为几十万 seq 建 map。
	windowFrom, _ := logGapFetchWindow(t.fromSeq, t.toSeq)
	existing, err := service.LoggedKeysInSeqRange(t.dice.DBOperator, t.logID, windowFrom, t.toSeq)
	if err != nil {
		// fail-closed：去重查询失败时不能“继续补录”，否则 log_items 没有唯一约束，
		// READ 库故障（读写分离）会直接产生重复日志行。ok=false 让 run() 保留
		// pending 并设置退避，而不是把本次当成“没有缺失消息”清掉区间。
		t.dice.Logger.Warnf("日志补全暂缓: 查询已记录消息失败: 群=%s err=%v", t.group.GroupID, err)
		return nil, false
	}
	if len(existing.RawMsgIDs) == 0 && len(existing.Seqs) == 0 {
		return msgs, true
	}
	filtered := msgs[:0]
	for _, m := range msgs {
		if m == nil {
			continue
		}
		// raw id 存在时它是权威去重键；平台 seq 重置后新消息可能撞上旧行，
		// 不能仅凭 seq 相同就丢掉一条 raw id 不同的消息。
		if rawKey := rawMsgIDKey(m.RawID); rawKey != "" {
			if _, ok := existing.RawMsgIDs[rawKey]; ok {
				continue
			}
		} else if m.Seq > 0 {
			// 平台不返回 raw_msg_id 时才用 seq 去重，避免重试/分段写重复。
			if _, ok := existing.Seqs[m.Seq]; ok {
				continue
			}
		}
		filtered = append(filtered, m)
	}
	return filtered, true
}

// logGapLifecycleInfo 是缺口内历史 .log off/.log on 扫描结果。
type logGapLifecycleInfo struct {
	found       bool
	finalOn     bool
	stopped     bool
	unsupported string
	// lastOnSeq 是扫描到的最晚一次有效 .log on 的 seq（0 表示没有）。
	// 用于判断用户 .log off 标记是否晚于这次 on，避免陈旧标记拦住恢复。
	lastOnSeq int64
}

// historicalCommandText 把历史消息还原成“可解析指令”的文本。
//
// 实时命令解析走 CommandParseNew 的 Segment 路径：引用、图片、表情等
// 第一个文本段之前的非文本元素会被跳过；历史消息的 m.Message 是 CQ 文本，
// 直接 CommandParse 会把这些前导 CQ 当成命令内容，导致引用回复发送的
// .bot/.log 指令识别不到（1119.fix1）。
//
// 这里与实时路径保持一致：
//   - 跳过第一个文本段之前的引用/图片/表情等非文本元素；
//   - 保留前导 @，让 mentionsOtherUser 仍能判断“只 @ 别人”；
//   - 第一个文本段之后的元素按 CQ 文本拼接，参数语义与实时一致。
func historicalCommandText(m *Message) string {
	if m == nil {
		return ""
	}
	if len(m.Segment) == 0 {
		return m.Message
	}
	var b strings.Builder
	started := false
	for _, elem := range m.Segment {
		if elem == nil {
			continue
		}
		if _, ok := elem.(*message.TextElement); ok {
			started = true
		}
		if !started {
			if _, ok := elem.(*message.AtElement); !ok {
				continue
			}
		}
		b.WriteString(message.MessageElementToString(elem))
	}
	return b.String()
}

// parseLogLifecycleCommand 用真实命令解析器识别 .log off/.log on/.log new/
// .log end/.log halt。只解析语法，不执行命令。
func (t logGapFillTask) parseLogLifecycleCommand(m *Message) (kind, name string, cmdArgs *CmdArgs) {
	if t.dice == nil || m == nil {
		return "", "", nil
	}
	ca := CommandParse(historicalCommandText(m), []string{"log"}, t.dice.CommandPrefix, m.Platform, false)
	if ca == nil || !strings.EqualFold(ca.Command, "log") {
		return "", "", nil
	}
	switch strings.ToLower(ca.GetArgN(1)) {
	case "off":
		return "off", "", ca
	case "on":
		return "on", ca.GetArgN(2), ca
	case "new":
		return "new", ca.GetArgN(2), ca
	case "end":
		return "end", "", ca
	case "halt":
		return "halt", "", ca
	}
	return "", "", nil
}

// parseUnsupportedLogLifecycleCommand 识别本轮不模拟、但会影响日志归属/
// 日志扩展状态的命令：.log new/end/halt、.ext off/on log。
//
// 1115.fix7 起不再把 .bot off/.bot on 当作边界：核心离线期间这些命令
// 没有被执行，不可能暂停/恢复日志，也不会改变群激活状态；它们只是发过但
// 未被处理的消息，因此按普通消息处理，不改变日志状态、不停止扫描、不影响
// live。这样本次 2000 条窗口里的 .log off/.log on 都能被看到。
func (t logGapFillTask) parseUnsupportedLogLifecycleCommand(m *Message) (kind string, cmdArgs *CmdArgs, privilegedRequired bool) {
	if t.dice == nil || m == nil {
		return "", nil, false
	}
	if kind, _, ca := t.parseLogLifecycleCommand(m); kind == "new" || kind == "end" || kind == "halt" {
		return "log " + kind, ca, false
	}
	if ca := CommandParse(historicalCommandText(m), []string{"ext"}, t.dice.CommandPrefix, m.Platform, false); ca != nil &&
		strings.EqualFold(ca.Command, "ext") {
		switch strings.ToLower(ca.GetArgN(1)) {
		case "off", "on":
			for _, arg := range ca.Args[1:] {
				name := strings.ToLower(strings.TrimSpace(arg))
				if name == "log" {
					return "ext " + strings.ToLower(ca.GetArgN(1)) + " log", ca, true
				}
				if name == "all" {
					return "ext " + strings.ToLower(ca.GetArgN(1)) + " all", ca, true
				}
			}
			if ca.GetKwarg("all") != nil {
				return "ext " + strings.ToLower(ca.GetArgN(1)) + " all", ca, true
			}
		}
	}
	return "", nil, false
}

// parseBotLifecycleCommand 识别实时触发消息本身是不是 .bot off/.bot on。
// 历史缺口里的 .bot 命令按普通消息忽略；但实时触发消息会由真实 .bot 命令
// 处理器负责，历史补录决策不能抢先删除/关闭它。
func (t logGapFillTask) parseBotLifecycleCommand(m *Message) (kind, botNum string, cmdArgs *CmdArgs) {
	if t.dice == nil || m == nil {
		return "", "", nil
	}
	ca := CommandParse(historicalCommandText(m), []string{"bot"}, t.dice.CommandPrefix, m.Platform, false)
	if ca == nil || !strings.EqualFold(ca.Command, "bot") {
		return "", "", nil
	}
	switch strings.ToLower(ca.GetArgN(1)) {
	case "off":
		return "off", ca.GetArgN(2), ca
	case "on":
		return "on", ca.GetArgN(2), ca
	}
	return "", "", nil
}

// mentionsOtherUser 判断历史消息是否会被真实命令分发拒绝。
//
// 真实语义是 cmd_parse.go 的 SomeoneBeMentionedButNotMe =
// len(At) > 0 && !AmIBeMentioned：只要 @ 了当前骰子，即使同时 @ 了别人，
// commandSolve 也不会拒绝；只有“只 @ 别人、没 @ 骰子”才会拒绝。
// 1119: 旧实现只要看到别人就返回 true，导致“@骰子 + @别人”的 .log off/on
// 实时会执行、历史却当普通消息，on/off 段判断错位。
func (t logGapFillTask) mentionsOtherUser(cmdArgs *CmdArgs) bool {
	if cmdArgs == nil || t.endpoint == nil {
		return false
	}
	botUniform := UserIDExtract(t.endpoint.UserID)
	botMentioned := false
	otherMentioned := false
	for _, at := range cmdArgs.At {
		if at == nil || at.UserID == "" {
			continue
		}
		if at.UserID == t.endpoint.UserID || UserIDExtract(at.UserID) == botUniform {
			botMentioned = true
			continue
		}
		otherMentioned = true
	}
	return otherMentioned && !botMentioned
}

// isHistoricalPrivilegedSender 近似判断历史发送者是否有权执行 .bot/.ext。
// 历史消息没有完整 MsgContext，只能用群角色近似；不确定时宁可停止补录。
func (t logGapFillTask) isHistoricalPrivilegedSender(m *Message) bool {
	if t.dice == nil || t.group == nil || m == nil {
		return false
	}
	if t.dice.Config.BotExtFreeSwitch || isQQChannelPlatform(m.Platform) {
		return true
	}
	if m.Sender.UserID != "" && t.dice.MasterCheck(t.group.GroupID, m.Sender.UserID) {
		return true
	}
	ctx := &MsgContext{
		Dice:        t.dice,
		Group:       t.group,
		MessageType: m.MessageType,
		IsPrivate:   m.MessageType == "private",
	}
	if t.dice.DBOperator != nil && m.Sender.UserID != "" {
		ctx.Player = t.group.PlayerGet(t.dice.DBOperator, m.Sender.UserID)
	}
	// 复用真实权限计算：群主/管理/邀请者/信任/骰主/黑名单。
	return ctx.fillPrivilege(m) >= 40
}

// lifecycleCommandValid 判断历史生命周期命令是否可能是当前骰子执行的那一条。
func (t logGapFillTask) lifecycleCommandValid(m *Message, cmdArgs *CmdArgs) bool {
	if m == nil || t.endpoint == nil {
		return false
	}
	if t.isBotSender(m) {
		return false
	}
	// 1119.fix1: 实时路径在命令分发前会 checkBan；历史扫描没有 MsgContext，
	// 这里至少按骰主黑名单拦住“被 ban 用户”的 .log/.bot 生命周期指令，
	// 避免其离线发言在恢复后改变日志/机器人状态。
	if t.dice != nil && t.dice.Config.BanList != nil && t.dice.Config.BanList.Map != nil {
		if item, ok := t.dice.Config.BanList.GetByID(m.Sender.UserID); ok && item.Rank == BanRankBanned {
			return false
		}
	}
	return !t.mentionsOtherUser(cmdArgs)
}

// historicalLogNameMatches 判断历史 .log on 的目标是否就是当前日志。
// 用户的日志名可能很长，.log list 会展示 hash key，.log on <key> 在实时
// 命令里会先解析成真实名称；历史扫描也必须用同一套解析，否则同一本日志
// 的 key/别名会被误判成“切换到另一本日志”，导致后续 on 段不补或直接停止。
func (t logGapFillTask) historicalLogNameMatches(name string) bool {
	if name == "" || name == t.logName {
		return true
	}
	if t.dice == nil || t.dice.DBOperator == nil || t.group == nil {
		return false
	}
	resolved, err := resolveLogNameForGroup(t.dice.DBOperator, t.group.GroupID, name)
	if err != nil {
		// 无法确认时保守视为不匹配，宁可停止也不猜错日志。
		return false
	}
	return resolved == t.logName
}

// filterHistoricalLogOffOn 按历史 .log off/.log on 重建 on/off 区间，
// 只保留“发送时日志应处于 on”的消息。
//
// startOn=true 用于 live 日志开启时的缺口：起点是最后一条已记录消息之后，
// 那一条是在日志开启时写入的。
// startOn=false 用于 live 日志关闭时的历史 .log on 发现：缺口从已见 seq 开始，
// 当时日志是关闭的，只有遇到有效 .log on 才恢复记录。
func (t logGapFillTask) filterHistoricalLogOffOn(msgs []*Message, startOn bool) ([]*Message, logGapLifecycleInfo) {
	info := logGapLifecycleInfo{finalOn: startOn}
	filtered := make([]*Message, 0, len(msgs))
	stateOn := startOn

	for _, m := range msgs {
		if m == nil {
			continue
		}
		if kind, ca, needPriv := t.parseUnsupportedLogLifecycleCommand(m); kind != "" {
			if needPriv && !t.isHistoricalPrivilegedSender(m) {
				// 没有权限的 .bot/.ext 文本不会改变日志状态，按普通消息处理。
				if stateOn {
					filtered = append(filtered, m)
				}
				continue
			}
			if !t.lifecycleCommandValid(m, ca) {
				if stateOn {
					filtered = append(filtered, m)
				}
				continue
			}
			info.found = true
			info.stopped = true
			info.unsupported = kind
			if stateOn {
				// .log new/end/halt、.bot off 等在实际执行前会先被正常
				// OnMessageReceived 记录；保留这一行。
				filtered = append(filtered, m)
			}
			info.finalOn = stateOn
			return filtered, info
		}

		kind, name, ca := t.parseLogLifecycleCommand(m)
		if kind == "" || !t.lifecycleCommandValid(m, ca) {
			if stateOn {
				filtered = append(filtered, m)
			}
			continue
		}

		info.found = true
		switch kind {
		case "off":
			if stateOn {
				// 实时路径在关闭执行前会记录 .log off 本身。
				filtered = append(filtered, m)
				stateOn = false
			}
		case "on":
			if stateOn {
				// 已经开启时 .log on 失败，但命令消息本身会被记录。
				filtered = append(filtered, m)
				continue
			}
			if name != "" && !t.historicalLogNameMatches(name) {
				// 切换到另一本日志，当前任务无法把后续消息写进正确的日志。
				info.stopped = true
				info.unsupported = "log on " + name
				info.finalOn = false
				return filtered, info
			}
			// 关闭期间的 .log on 本身不会被记录；之后恢复记录。
			stateOn = true
			if m.Seq > info.lastOnSeq {
				info.lastOnSeq = m.Seq
			}
		}
	}

	info.finalOn = stateOn
	return filtered, info
}

// logGapHistoricalDecision 是“历史缺口 + 实时触发消息”合并后的状态决策。
type logGapHistoricalDecision struct {
	finalOn       bool
	forceLogOnly  bool
	applyLiveOff  bool
	deleteTrigger bool
	stopped       bool
	reason        string
}

// decideHistoricalLogState 把缺口扫描结果与实时触发消息合并，决定：
//   - 最终历史状态是否 on；
//   - 是否必须只补日志（不能执行命令）；
//   - 是否要把 live 日志关掉；
//   - 实时路径是否已经把“历史 off 段”的首条消息写进了日志，需要删除。
//
// 只应在 live 日志仍开启、且缺口扫描未 stopped 时调用。
func (t logGapFillTask) decideHistoricalLogState(info logGapLifecycleInfo) logGapHistoricalDecision {
	d := logGapHistoricalDecision{finalOn: info.finalOn, forceLogOnly: !info.finalOn}
	stateBefore := info.finalOn

	triggerKind, triggerName, triggerCA := t.parseLogLifecycleCommand(t.trigger)
	if triggerKind != "" && !t.lifecycleCommandValid(t.trigger, triggerCA) {
		triggerKind, triggerName = "", ""
	}
	if triggerKind == "" {
		if botKind, botNum, botCA := t.parseBotLifecycleCommand(t.trigger); botKind != "" {
			// 实时触发消息是 .bot off/.bot on：由真实命令处理器负责。
			// 历史补录只按 .log off/.log on 过滤缺口，不抢先删行/关日志。
			targetsCurrent := t.endpoint != nil &&
				(len(botNum) < 4 || strings.HasSuffix(t.endpoint.UserID, botNum))
			if targetsCurrent &&
				t.trigger != nil && t.trigger.MessageType != "private" &&
				(t.dice == nil || !t.dice.Config.IgnoreUnaddressedBotCmd || len(botCA.At) > 0) &&
				t.isHistoricalPrivilegedSender(t.trigger) &&
				t.lifecycleCommandValid(t.trigger, botCA) {
				d.stopped = true
				d.reason = "live bot " + botKind
				d.forceLogOnly = true
				return d
			}
		}
		if unsup, ca, needPriv := t.parseUnsupportedLogLifecycleCommand(t.trigger); unsup != "" {
			privileged := !needPriv || t.isHistoricalPrivilegedSender(t.trigger)
			if privileged && t.lifecycleCommandValid(t.trigger, ca) {
				d.stopped = true
				d.reason = unsup
				d.forceLogOnly = true
				return d
			}
		}
	}

	finalOn := stateBefore
	switch triggerKind {
	case "off":
		finalOn = false
	case "on":
		if !stateBefore && triggerName != "" && !t.historicalLogNameMatches(triggerName) {
			d.stopped = true
			d.reason = "log on " + triggerName
			d.forceLogOnly = true
			return d
		}
		finalOn = true
	case "new", "end", "halt":
		d.stopped = true
		d.reason = "log " + triggerKind
		d.forceLogOnly = true
		return d
	}

	d.finalOn = finalOn
	if !stateBefore && t.trigger != nil {
		// 历史状态为 off 时，实时路径本来不应该记录这条触发消息。
		d.deleteTrigger = true
	}
	if !finalOn {
		d.forceLogOnly = true
		// 触发消息本身是 .log off 时交给实时命令处理器关闭日志，
		// 避免我们提前关闭导致命令回复“关闭失败”。
		if triggerKind != "off" {
			d.applyLiveOff = true
		}
	}
	return d
}

// logOffDiscoveryDecision 是 live 日志关闭期间“历史 .log on 发现”任务
// 对缺口 + 触发消息的最终决策。
type logOffDiscoveryDecision struct {
	finalOn          bool
	triggerShouldLog bool
	adoptLiveOn      bool
	stopped          bool
	reason           string
	// lastOnSeq 是最终导致 on 的历史/触发 .log on 的 seq。
	// 用户 .log off 标记只有不早于它时才应阻止 adopt。
	lastOnSeq int64
}

// decideOffDiscovery 在 startOff 的历史扫描结果上合并实时触发消息。
func (t logGapFillTask) decideOffDiscovery(info logGapLifecycleInfo) logOffDiscoveryDecision {
	stateBefore := info.finalOn
	d := logOffDiscoveryDecision{finalOn: stateBefore}
	d.lastOnSeq = info.lastOnSeq
	if info.stopped {
		d.stopped = true
		d.reason = info.unsupported
		return d
	}

	triggerKind, triggerName, triggerCA := t.parseLogLifecycleCommand(t.trigger)
	if triggerKind != "" && !t.lifecycleCommandValid(t.trigger, triggerCA) {
		triggerKind, triggerName = "", ""
	}
	if triggerKind == "" {
		if unsup, ca, needPriv := t.parseUnsupportedLogLifecycleCommand(t.trigger); unsup != "" {
			privileged := !needPriv || t.isHistoricalPrivilegedSender(t.trigger)
			if privileged && t.lifecycleCommandValid(t.trigger, ca) {
				d.stopped = true
				d.reason = unsup
				d.triggerShouldLog = stateBefore
				return d
			}
		}
		// 普通消息（含被忽略的 .bot off/on）：按当前历史状态决定是否补这一条。
		d.finalOn = stateBefore
		d.triggerShouldLog = stateBefore
		d.adoptLiveOn = stateBefore
		return d
	}

	switch triggerKind {
	case "off":
		d.finalOn = false
		d.triggerShouldLog = stateBefore
		d.adoptLiveOn = false
	case "on":
		if !stateBefore && triggerName != "" && !t.historicalLogNameMatches(triggerName) {
			d.stopped = true
			d.reason = "log on " + triggerName
			d.triggerShouldLog = false
			return d
		}
		d.finalOn = true
		// 历史状态已 on 时，.log on 会因“已经开启”失败但消息本身会记录；
		// 历史状态 off 时，这条 .log on 本身不会被记录。
		d.triggerShouldLog = stateBefore
		d.adoptLiveOn = true
		d.lastOnSeq = t.toSeq
	case "new", "end", "halt":
		d.stopped = true
		d.reason = "log " + triggerKind
		d.triggerShouldLog = stateBefore
		d.adoptLiveOn = false
	}
	if d.stopped {
		d.adoptLiveOn = false
	}
	return d
}

// adoptHistoricalLogOn 在 off 状态历史发现任务成功后，把 live 日志重新打开。
// 与实时 .log on 对齐：基线锚定到触发消息 seq；epoch++ 使旧任务失效；
// 清 pending/seen/退避。只在日志仍关闭且日志身份/epoch 未变时执行。
func (t logGapFillTask) adoptHistoricalLogOn() bool {
	g := t.group
	if g == nil || t.toSeq <= 0 || t.dice == nil {
		return false
	}
	// 群已经失活（.bot off）或用户明确 .log off 时绝不能再打开日志。
	// 调用方通常已经拦截；这里作为最后一道防线，防止交接间隙的状态覆盖。
	if !g.IsActiveRaw() || g.logOffRequested() {
		return false
	}
	var rawID interface{}
	msgID := ""
	if t.trigger != nil {
		rawID = t.trigger.RawID
		if rawID != nil {
			msgID = fmt.Sprintf("%v", rawID)
		}
	}
	g.logWriteMu.Lock()
	// 1118: 必须在拿到 logWriteMu 后复查。用户 .log off 也拿这把锁，
	// 如果它在锁外检查之后先完成，这里再置 LogOn=true 就会把用户刚关的
	// 日志重新打开。
	if !g.IsActiveRaw() || g.logOffRequested() {
		g.logWriteMu.Unlock()
		return false
	}
	g.logStateMu.Lock()
	if g.LogOn || g.LogCurID != t.logID || g.LogCurName != t.logName ||
		g.logEpoch.Load() != t.epoch {
		g.logStateMu.Unlock()
		g.logWriteMu.Unlock()
		return false
	}
	g.LogOn = true
	g.LogPausedByBotOff = false
	g.LogResumeSkipGap = false
	g.logStateMu.Unlock()
	g.logSeqMu.Lock()
	g.logLastSeq = t.toSeq
	g.logLastMsgID = rawID
	g.LogSeqBaseline = t.toSeq
	g.LogSeqBaselineMsgID = msgID
	g.LogSeenSeq = 0
	g.LogGapPendingFrom, g.LogGapPendingTo = 0, 0
	g.LogGapPendingOffDiscovery = false
	g.logGapRetryAt.Store(0)
	g.logSelfSent = 0
	g.logSeqRegressCount = 0
	g.logSeqCalibrated = true
	g.logEpoch.Add(1)
	g.logSeqMu.Unlock()
	g.logWriteMu.Unlock()
	g.clearLogOffGapAuth()
	g.clearLogOffRequested()
	g.logAutoResumedAt.Store(time.Now().Unix())
	g.MarkDirty(t.dice)
	return true
}

// sendGroupNotice 向群内补发一条异步任务结果提示。任务可能在重连后运行，
// 发送失败只记日志，不影响补录状态。
func (t logGapFillTask) sendGroupNotice(text string) {
	if text == "" || t.group == nil || t.endpoint == nil || t.dice == nil {
		return
	}
	mctx := &MsgContext{
		Group:    t.group,
		EndPoint: t.endpoint,
		Dice:     t.dice,
		Session:  t.endpoint.Session,
	}
	ReplyToSenderRaw(mctx, &Message{
		MessageType: "group",
		GroupID:     t.group.GroupID,
		Platform:    t.endpoint.Platform,
	}, text, "skip")
}

// offDiscoveryNotice 生成 off 状态历史发现任务的用户提示。
func (t logGapFillTask) offDiscoveryNotice(appended int, finalOn, paused, stopped bool) string {
	var b strings.Builder
	b.WriteString("检测到离线期间的日志记录")
	if appended > 0 {
		_, _ = fmt.Fprintf(&b, "，已补录 %d 条", appended)
	}
	switch {
	case paused:
		b.WriteString("。日志保持关闭，.bot on 后自动恢复记录。")
	case finalOn:
		b.WriteString("。日志已恢复记录。")
	default:
		b.WriteString("。日志保持关闭。")
	}
	if stopped {
		b.WriteString("\n离线期间有 .log new/end/halt 或切换日志，之后未继续补录。")
	}
	return b.String()
}

// runOffDiscovery 处理 live 日志关闭期间的历史 .log on 发现任务：
//   - 只补扫描确认的 on 段（log-only，不执行指令）；
//   - 触发消息按实时语义决定是否补；
//   - 最终历史状态 on 时恢复 live 日志；
//   - 最终 off/无 on 时保持关闭，并推进已见 seq。
func (t logGapFillTask) runOffDiscovery(missing []*Message, hist logGapLifecycleInfo) {
	t.group.beginLogGapWriteTracking()
	d := t.decideOffDiscovery(hist)
	if d.stopped {
		t.dice.Logger.Warnf("日志补全(off 状态历史发现)已停止: 群=%s 命令=%s，后续不补",
			t.group.GroupID, d.reason)
	}

	appended := 0
	if len(missing) > 0 {
		appended, _ = t.backfillLogOnlyCount(missing)
	}
	// 群已经被 .bot off/.log off 关闭时，触发消息本身不应再写进日志：
	// 实时处理器看到的是关闭状态，写进去会制造一条本不该存在的行。
	triggerAppended := false
	if d.triggerShouldLog && t.trigger != nil && t.logFillWritable() && t.group.IsActiveRaw() {
		item := t.logItem(t.trigger)
		mctx := &MsgContext{Group: t.group, EndPoint: t.endpoint, Dice: t.dice}
		mctx.SuppressLogSizeNotice = true
		mctx.SuppressLogAppendFailureNotice = true
		appendedOK := false
		ran := t.group.withLogGapFillWrite(t, func() {
			appendedOK = LogAppend(mctx, t.group.GroupID, t.logID, t.logName, &item)
		})
		if !ran || !appendedOK {
			t.group.markLogGapWriteFailure()
		} else {
			appended++
			triggerAppended = true
		}
	}

	// worker 运行期间有新消息合并：先让后续任务处理更大的窗口，
	// 暂不推进 seen/恢复 live，避免下一段缺口被吞掉。
	if t.group.hasPendingLogGapTask() {
		return
	}
	if !t.group.logGapWritesOK() {
		t.dice.Logger.Warnf("日志补全(off 状态历史发现)写入失败，保留 pending 并退避: 群=%s 记录=%s",
			t.group.GroupID, t.logName)
		t.group.deferLogGapRetry(logGapFillRetryBackoff)
		return
	}
	if d.stopped {
		t.group.advanceLogSeenSeq(t.dice, t.toSeq)
		t.group.clearLogGapPendingIfIdle(t.dice)
		if hist.found || appended > 0 {
			t.sendGroupNotice(t.offDiscoveryNotice(appended, false, false, true))
		}
		return
	}
	// 用户明确 .log off：只有这次 off 不早于最终的历史/触发 .log on 时，
	// 才拒绝恢复。早于 .log on 的标记是上一次关闭残留，不能拦住之后的
	// 离线 .log on。
	if offSeq := t.group.logOffRequestedSeqSnapshot(); offSeq > 0 {
		if d.lastOnSeq <= 0 || offSeq >= d.lastOnSeq {
			t.group.advanceLogSeenSeq(t.dice, t.toSeq)
			t.group.clearLogGapPendingIfIdle(t.dice)
			if hist.found || appended > 0 {
				t.sendGroupNotice(t.offDiscoveryNotice(appended, false, false, false))
			}
			return
		}
		t.group.clearLogOffRequested()
		t.dice.Logger.Infof("日志补全忽略早于历史 .log on 的旧关闭标记: 群=%s offSeq=%d onSeq=%d",
			t.group.GroupID, offSeq, d.lastOnSeq)
	}
	// 群已经失活（典型是 .bot off）：不要重新打开日志，否则 bot off 期间
	// 日志会保持 on，.bot on 后还会把关闭期间的消息当成缺口补进来。
	// 这里保留“由 bot off 暂停”的标记，让下一次 .bot on 按原语义自动恢复。
	if d.finalOn && d.adoptLiveOn && !t.group.IsActiveRaw() {
		paused := t.group.setLogPausedByBotOff()
		if paused {
			t.group.MarkDirty(t.dice)
		}
		t.group.advanceLogSeenSeq(t.dice, t.toSeq)
		t.group.clearLogGapPendingIfIdle(t.dice)
		if hist.found || appended > 0 || paused {
			t.sendGroupNotice(t.offDiscoveryNotice(appended, false, paused, false))
		}
		return
	}
	if d.finalOn && d.adoptLiveOn {
		if t.adoptHistoricalLogOn() {
			t.group.clearLogGapPendingIfIdle(t.dice)
			t.dice.Logger.Infof("日志补全按历史 .log on 恢复记录: 群=%s seq=%d", t.group.GroupID, t.toSeq)
			if hist.found || appended > 0 || triggerAppended {
				t.sendGroupNotice(t.offDiscoveryNotice(appended, true, false, false))
			}
			return
		}
		// adopt 与实时 .log off 的交接间隙：用户已明确要求关闭，按最终 off 收尾。
		if t.group.logOffRequested() {
			t.group.advanceLogSeenSeq(t.dice, t.toSeq)
			t.group.clearLogGapPendingIfIdle(t.dice)
			if hist.found || appended > 0 {
				t.sendGroupNotice(t.offDiscoveryNotice(appended, false, false, false))
			}
			return
		}
		if !t.logHistoricalDiscoveryAllowed() {
			t.group.clearLogGapPendingIfIdle(t.dice)
			return
		}
		t.group.deferLogGapRetry(logGapFillRetryBackoff)
		return
	}
	// 最终 off / 没有有效 .log on：保持关闭，但把已确认处理到的窗口记为已见。
	t.group.advanceLogSeenSeq(t.dice, t.toSeq)
	t.group.clearLogGapPendingIfIdle(t.dice)
	if hist.found || appended > 0 {
		t.sendGroupNotice(t.offDiscoveryNotice(appended, false, false, false))
	}
}

// runOffBackfillOnly 处理“实时 .log on 已经先把 live 日志打开”的历史补录
// 任务：只把 (fromSeq,toSeq) 之间确认的 on 段写进当前日志，不写触发消息、
// 不改变 live 状态、不 adopt。这样实时处理器先执行时，离线 on 段不会
// 因 epoch 变化被一并取消。
func (t logGapFillTask) runOffBackfillOnly(missing []*Message, hist logGapLifecycleInfo) {
	t.group.beginLogGapWriteTracking()
	appended := 0
	if len(missing) > 0 {
		appended, _ = t.backfillLogOnlyCount(missing)
	}
	if t.group.hasPendingLogGapTask() {
		// 后续任务会处理更大的窗口；不在这里清 pending。
		return
	}
	if !t.logOffDiscoveryBackfillAllowed() {
		t.dice.Logger.Infof("日志补全(实时 .log on 后历史补录)已取消: 群=%s 记录=%s 日志已切换", t.group.GroupID, t.logName)
		t.group.clearLogGapPendingIfIdle(t.dice)
		return
	}
	if !t.group.logGapWritesOK() {
		t.dice.Logger.Warnf("日志补全(实时 .log on 后历史补录)写入失败，保留 pending 并退避: 群=%s 记录=%s",
			t.group.GroupID, t.logName)
		t.group.deferLogGapRetry(logGapFillRetryBackoff)
		return
	}
	t.group.clearLogGapPendingIfIdle(t.dice)
	t.dice.Logger.Infof("日志补全完成(实时 .log on 后历史补录): 群=%s 补录=%d条", t.group.GroupID, appended)
	if appended > 0 || hist.found {
		t.sendGroupNotice(fmt.Sprintf("检测到离线期间的 .log on，已补录 %d 条记录。", appended))
	} else {
		// 实时 .log on 的回复已经承诺“完成后会通知”，即使没有可补的
		// on 段也要给一个收尾提示。
		t.sendGroupNotice("离线期间的记录补录完成，没有需要补录的 on 段。")
	}
}

// deleteTriggerRow 删除实时路径已经写入、但按历史状态本不该记录的第一条
// 恢复消息。只按当前 log_id + seq 精确删除，避免跨日志误删。
func (t logGapFillTask) deleteTriggerRow() {
	if t.group == nil || t.logID == 0 || t.toSeq <= 0 || t.dice == nil || t.dice.DBOperator == nil {
		return
	}
	if err := service.LogDeleteByLogIDSeq(t.dice.DBOperator, t.logID, t.toSeq); err != nil {
		if t.dice != nil && t.dice.Logger != nil {
			t.dice.Logger.Warnf("日志补全纠正失败: 删除历史 off 段首条消息: 群=%s logID=%d seq=%d err=%v",
				t.group.GroupID, t.logID, t.toSeq, err)
		}
	}
}

// lookupPlayerName 读取玩家在本群的标注名（角色名/名片）。
// 先查运行时 Players，避免为历史消息逐条访问数据库；未命中再回退到数据库。
func (t logGapFillTask) lookupPlayerName(uid string) string {
	if t.group == nil || uid == "" {
		return ""
	}
	if t.group.Players != nil {
		if p, ok := t.group.Players.Load(uid); ok && p != nil {
			return strings.TrimSpace(p.Name)
		}
	}
	if t.dice != nil && t.dice.DBOperator != nil {
		if p := t.group.PlayerGet(t.dice.DBOperator, uid); p != nil {
			return strings.TrimSpace(p.Name)
		}
	}
	return ""
}

// playerDisplayName 返回玩家标注名，与正常消息路径 OnMessageReceived 使用的
// ctx.Player.Name 保持一致，日志按玩家筛选时才能命中；没有角色卡时用平台昵称兜底。
func (t logGapFillTask) playerDisplayName(uid, fallback string, cache map[string]string) string {
	if name, ok := cache[uid]; ok && name != "" {
		return name
	}
	name := t.lookupPlayerName(uid)
	if name == "" {
		name = fallback
	}
	if uid != "" {
		cache[uid] = name
	}
	return name
}

// replaySilently 让缺失消息重走完整消息流程，日志记录与指令执行都由 ExecuteNew 内部完成。
// 管理指令（log/bot/master/dismiss/ban 等）只补日志、不执行，避免掉线期间的旧指令
// 在恢复后改变骰子状态；普通跑团指令仍然按小断层策略自动补执行。
//
// 返回值表示“这段补全已经结束，可以清除持久化的 pending 区间”。
// 端点会话未绑定是暂时状态，返回 false 让 pending 保留到下次启动/重试。
func (t logGapFillTask) replaySilently(missing []*Message) bool {
	if !t.logStateStillValid() {
		if t.logOffGapFillAllowed() {
			// 日志已关闭但窗口完全在 off 之前：只补日志，不重放命令。
			return t.backfillLogOnly(missing)
		}
		t.dice.Logger.Infof("日志补全已取消(静默重放): 群=%s 日志已关闭或切换", t.group.GroupID)
		return true
	}
	session := t.endpoint.Session
	if session == nil {
		t.dice.Logger.Warnf("日志补全无法重放: 群=%s 端点会话未绑定", t.group.GroupID)
		return false
	}
	endGapFillWindow := t.group.beginLogGapFillWindow(t.fromSeq, t.toSeq)
	defer endGapFillWindow()

	executed, skipped := 0, 0
	logCtx := CreateTempCtx(t.endpoint, &Message{
		MessageType: "group",
		Sender:      SenderBase{UserID: t.endpoint.UserID},
		GroupID:     t.group.GroupID,
		Platform:    t.endpoint.Platform,
	})
	logCtx.SuppressLogSizeNotice = true
	processed := t.forEachMissing(missing, func(m *Message) {
		if t.isBotSender(m) || t.isDeniedReplayCommand(m) {
			// 其他机器人与管理指令只补日志，不执行；日志仍需保持完整。
			// 写入与日志状态在同一把锁里：.log off/new 不会让这条迟到的
			// 写入落进已关闭/已切换的日志。off 前窗口授权下也允许写入。
			item := t.logItem(m)
			appendedOK := false
			if !t.logStateStillValid() {
				logCtx.SuppressLogAppendFailureNotice = true
			}
			ran := t.group.withLogGapFillWrite(t, func() {
				appendedOK = LogAppend(logCtx, t.group.GroupID, t.logID, t.logName, &item)
			})
			if !ran || !appendedOK {
				t.group.markLogGapWriteFailure()
			}
			if ran && appendedOK {
				skipped++
			}
			return
		}
		// 命令执行的临界区无法长期持锁（命令内部可能 .log off），这里在
		// 执行前再做一次最终校验；写入路径已由 withLogGapFillWrite 原子化。
		if !t.logStateStillValid() {
			if !t.logOffGapFillAllowed() {
				return
			}
			// 重放中途日志被关闭：剩余消息只补日志、不再执行命令。
			item := t.logItem(m)
			appendedOK := false
			logCtx.SuppressLogAppendFailureNotice = true
			ran := t.group.withLogGapFillWrite(t, func() {
				appendedOK = LogAppend(logCtx, t.group.GroupID, t.logID, t.logName, &item)
			})
			if !ran || !appendedOK {
				t.group.markLogGapWriteFailure()
			}
			if ran && appendedOK {
				skipped++
			}
			return
		}
		session.ExecuteNew(t.endpoint, m)
		executed++
	})
	if processed < len(missing) {
		t.dice.Logger.Warnf("日志补全中止(静默重放): 群=%s 日志在重放过程中被关闭或切换，已重放=%d条 仅补日志=%d条 剩余=%d条",
			t.group.GroupID, executed, skipped, len(missing)-processed)
		return true
	}
	t.dice.Logger.Infof("日志补全完成(静默重放): 群=%s 重放=%d条 仅补日志=%d条", t.group.GroupID, executed, skipped)
	if len(missing) > 0 {
		// 小缺口过去是静默重放；按“发现掉线并补全要告知用户”的要求，
		// 补完之后补一条简短汇总（重放指令自身的回复仍会单独发出）。
		t.sendGroupNotice(fmt.Sprintf("检测到seq不连贯，已补全 %d 条遗漏消息。", len(missing)))
	}
	return true
}

// appendSegmentLogOnly 把分段扫描的一小段已过滤消息立即写进日志（只写日志，
// 不执行历史指令），用于大缺口的分段进度持久化。返回是否完整处理完本段：
// false 表示日志在写入过程中被关闭/切换，调用方应停止扫描并按取消处理。
func (t logGapFillTask) appendSegmentLogOnly(msgs []*Message) (appended int, complete bool) {
	if len(msgs) == 0 {
		return 0, true
	}
	mctx := &MsgContext{
		Group:    t.group,
		EndPoint: t.endpoint,
		Dice:     t.dice,
	}
	mctx.SuppressLogSizeNotice = true
	mctx.SuppressLogAppendFailureNotice = true

	processed := t.forEachMissing(msgs, func(m *Message) {
		item := t.logItem(m)
		appendedOK := false
		ran := t.group.withLogGapFillWrite(t, func() {
			appendedOK = LogAppend(mctx, t.group.GroupID, t.logID, t.logName, &item)
		})
		if !ran || !appendedOK {
			t.group.markLogGapWriteFailure()
		}
		if appendedOK {
			appended++
		}
	})
	return appended, processed == len(msgs)
}

// backfillLogOnly 只把 off 前窗口的消息写进日志，不执行任何历史指令，
// 也不发“已补全”通知。用于 .log off/.bot off 已经关闭日志、但任务持有
// off 前窗口授权的场景。
func (t logGapFillTask) backfillLogOnly(missing []*Message) bool {
	_, done := t.backfillLogOnlyCount(missing)
	return done
}

// backfillLogOnlyCount 是 backfillLogOnly 的计数版本，供需要向用户汇报
// 补录条数的场景使用。
func (t logGapFillTask) backfillLogOnlyCount(missing []*Message) (appended int, done bool) {
	mctx := &MsgContext{
		Group:    t.group,
		EndPoint: t.endpoint,
		Dice:     t.dice,
	}
	mctx.SuppressLogSizeNotice = true
	mctx.SuppressLogAppendFailureNotice = true

	processed := t.forEachMissing(missing, func(m *Message) {
		item := t.logItem(m)
		appendedOK := false
		ran := t.group.withLogGapFillWrite(t, func() {
			appendedOK = LogAppend(mctx, t.group.GroupID, t.logID, t.logName, &item)
		})
		if !ran || !appendedOK {
			t.group.markLogGapWriteFailure()
		}
		if appendedOK {
			appended++
		}
	})
	if processed < len(missing) {
		t.dice.Logger.Warnf("日志补全中止(off 前窗口): 群=%s 已补录=%d条 剩余=%d条",
			t.group.GroupID, appended, len(missing)-processed)
		return appended, true
	}
	t.dice.Logger.Infof("日志补全完成(off 前窗口，仅补日志): 群=%s 补录=%d条",
		t.group.GroupID, appended)
	return appended, true
}

func (t logGapFillTask) isDeniedReplayCommand(m *Message) bool {
	if m == nil {
		return false
	}
	cmd := extractCommandName(t.dice.CommandPrefix, m.Platform, historicalCommandText(m))
	if cmd == "" {
		return false
	}
	for _, prefix := range t.dice.CommandPrefix {
		if prefix != "" && strings.HasPrefix(cmd, prefix) {
			name := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(cmd, prefix)))
			_, denied := logGapReplayDeniedCommands[name]
			return denied
		}
	}
	return false
}

func (t logGapFillTask) logItem(m *Message) model.LogOneItem {
	nickname := m.Sender.Nickname
	if name := t.lookupPlayerName(m.Sender.UserID); name != "" {
		nickname = name
	}
	return model.LogOneItem{
		Nickname:  nickname,
		IMUserID:  UserIDExtract(m.Sender.UserID),
		UniformID: m.Sender.UserID,
		Time:      m.Time,
		Message:   m.Message,
		IsDice:    false,
		RawMsgID:  m.RawID,
		Seq:       ptrInt64(m.Seq),
		IsGapFill: true,
	}
}

// backfillWithNotice 只补录日志并统计其中的指令，随后引用断层前最后一条消息汇报
func (t logGapFillTask) backfillWithNotice(missing []*Message) {
	mctx := CreateTempCtx(t.endpoint, &Message{
		MessageType: "group",
		Sender:      SenderBase{UserID: t.endpoint.UserID},
		GroupID:     t.group.GroupID,
		Platform:    t.endpoint.Platform,
	})
	mctx.SuppressLogSizeNotice = true

	stats := map[string]map[string]int{}
	nicknames := map[string]string{}
	nameCache := map[string]string{}
	appended := 0

	processed := t.forEachMissing(missing, func(m *Message) {
		item := t.logItem(m)
		appendedOK := false
		if !t.logStateStillValid() {
			mctx.SuppressLogAppendFailureNotice = true
		}
		ran := t.group.withLogGapFillWrite(t, func() {
			appendedOK = LogAppend(mctx, t.group.GroupID, t.logID, t.logName, &item)
		})
		if !ran || !appendedOK {
			t.group.markLogGapWriteFailure()
		}
		if appendedOK {
			appended++
		}

		if t.isBotSender(m) {
			return
		}
		cmd := extractCommandName(t.dice.CommandPrefix, m.Platform, historicalCommandText(m))
		if cmd == "" {
			return
		}
		if stats[m.Sender.UserID] == nil {
			stats[m.Sender.UserID] = map[string]int{}
		}
		stats[m.Sender.UserID][cmd]++
		nicknames[m.Sender.UserID] = t.playerDisplayName(m.Sender.UserID, m.Sender.Nickname, nameCache)
	})

	if processed < len(missing) {
		// 日志在补录过程中被关闭/切换：立刻停手，也不再发“已补全”通知。
		t.dice.Logger.Warnf("日志补全中止(补录): 群=%s 日志在补录过程中被关闭或切换，已补录=%d条 剩余=%d条",
			t.group.GroupID, appended, len(missing)-processed)
		return
	}

	t.dice.Logger.Infof("日志补全完成(指令未执行): 群=%s 补录=%d条 涉及指令用户=%d",
		t.group.GroupID, appended, len(stats))

	if appended == 0 {
		return
	}
	// 补录期间日志被 .log off/.bot off 关闭：不再发“已补全”通知。
	if !t.logStateStillValid() {
		t.dice.Logger.Infof("日志补全完成(off 前窗口，未发通知): 群=%s 补录=%d条",
			t.group.GroupID, appended)
		return
	}
	ReplyToSenderRaw(mctx, &Message{
		MessageType: "group",
		GroupID:     t.group.GroupID,
		Platform:    t.endpoint.Platform,
	}, t.buildNotice(appended, stats, nicknames), "skip")
}

func (t logGapFillTask) buildNotice(appended int, stats map[string]map[string]int, nicknames map[string]string) string {
	var buf strings.Builder
	if t.lastMsgID != nil {
		_, _ = fmt.Fprintf(&buf, "[CQ:reply,id=%v]", t.lastMsgID)
	}
	_, _ = fmt.Fprintf(&buf, "检测到seq不连贯，已异步补全 %d 条遗漏消息，引用的是断层前最后一条有记录的消息。", appended)

	if len(stats) == 0 {
		return buf.String()
	}

	buf.WriteString("\n断层期间出现过以下指令：")
	userIDs := make([]string, 0, len(stats))
	for uid := range stats {
		userIDs = append(userIDs, uid)
	}
	sort.Strings(userIDs)
	for _, uid := range userIDs {
		_, _ = fmt.Fprintf(&buf, "\n%s(%s)", nicknames[uid], UserIDExtract(uid))
		cmds := make([]string, 0, len(stats[uid]))
		for cmd := range stats[uid] {
			cmds = append(cmds, cmd)
		}
		sort.Strings(cmds)
		for _, cmd := range cmds {
			_, _ = fmt.Fprintf(&buf, "\n  |- %s %d次", cmd, stats[uid][cmd])
		}
	}
	buf.WriteString("\n这些指令均未实际执行，如有必要请重新发送。")
	return buf.String()
}

// extractCommandName 提取消息中的指令名用于统计，非指令返回空串。
// 仅做前导符与首个词的粗粒度识别，不解析参数，因此不依赖也不触发指令注册表。
func extractCommandName(prefixes []string, platform string, text string) string {
	rest, _ := AtParse(text, platform)
	rest, _ = SpecialExecuteTimesParse(strings.TrimSpace(rest))

	matched := ""
	for _, p := range prefixes {
		if p != "" && strings.HasPrefix(strings.TrimSpace(rest), p) {
			matched = p
			break
		}
	}
	if matched == "" {
		return ""
	}

	fields := strings.Fields(strings.TrimPrefix(strings.TrimSpace(rest), matched))
	if len(fields) == 0 {
		return ""
	}
	return matched + fields[0]
}

// ptrInt64 把seq转为可空列的值，0表示平台未提供，需要转化成NULL以区分
func ptrInt64(v int64) *int64 {
	if v == 0 {
		return nil
	}
	return &v
}

func LogDeleteByID(ctx *MsgContext, groupID string, messageID interface{}) bool {
	err := service.LogMarkDeleteByRawMsgID(ctx.Dice.DBOperator, groupID, messageID)
	if err != nil {
		ctx.Dice.Logger.Error("LogDeleteById:", zap.Error(err))
		return false
	}
	return true
}

// LogEditByID finds the log item under logName with messageID and replace it with content.
// If the log item cannot be found or an error happens, it returns false.
func LogEditByID(ctx *MsgContext, groupID, content string, messageID interface{}) bool {
	err := service.LogEditByRawMsgID(ctx.Dice.DBOperator, groupID, content, messageID)
	if err != nil {
		ctx.Dice.Logger.Error("LogEditByID:", zap.Error(err))
		return false
	}
	return true
}

func GetLogTxt(ctx *MsgContext, groupID string, logName string, fileNamePrefix string) (string, string, error) {
	// 创建临时文件
	tempPattern, notice := storylog.BuildTempPattern(fileNamePrefix)
	tempLog, err := os.CreateTemp("", tempPattern)
	if err != nil {
		return "", notice, errors.New("log导出出现未知错误")
	}
	defer func() {
		_ = tempLog.Close()
		if err != nil {
			_ = os.Remove(tempLog.Name()) //nolint:gosec
		}
	}()

	counter := 0
	currentCursor := paginator.Cursor{} // 初始游标为空

	// 腾讯元宝: 创建带10秒超时的 context
	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel() // 确保 context 被正确取消

	// 腾讯元宝: 使用 channel 接收 goroutine 的结果
	resultCh := make(chan error, 1)
	go func() {
		defer close(resultCh) // 确保 channel 被关闭

		for {
			select {
			case <-ctxWithTimeout.Done(): // 检查是否超时或被取消
				resultCh <- errors.New("日志导出超时（10秒限制），请尝试减少数据量或联系管理员")
				return
			default:
				// 获取当前游标对应的数据
				cursorLines, cursor, err := service.LogGetCursorLines(ctx.Dice.DBOperator, groupID, logName, currentCursor)
				if err != nil {
					resultCh <- err
					return
				}

				// 写入当前批次的数据
				for _, line := range cursorLines {
					timeTxt := time.Unix(line.Time, 0).Format("2006-01-02 15:04:05")
					text := fmt.Sprintf("%s(%v) %s\n%s\n\n", line.Nickname, line.IMUserID, timeTxt, line.Message)
					if _, err = tempLog.WriteString(text); err != nil {
						resultCh <- fmt.Errorf("写入日志导出临时文件失败: %w", err)
						return
					}
					counter++
				}
				// ========== 新增：每批写入后强制同步 ==========
				if err := tempLog.Sync(); err != nil { // 确保批次数据落盘
					resultCh <- fmt.Errorf("批次同步失败: %w", err)
					return
				}

				// 如果没有下一页，则成功完成
				if cursor.After == nil {
					resultCh <- nil
					return
				}

				// 更新游标，继续获取下一页
				currentCursor.After = cursor.After
			}
		}
	}()

	// 等待 goroutine 完成或超时
	if err := <-resultCh; err != nil {
		return "", notice, err
	}
	// 2. 确保文件指针回到开头
	if _, err := tempLog.Seek(0, 0); err != nil {
		return "", notice, fmt.Errorf("重置文件指针失败: %w", err)
	}

	// 如果没有任何数据，返回错误
	if counter == 0 {
		return "", notice, errors.New("此log不存在，或条目数为空，名字是否正确？")
	}

	return tempLog.Name(), notice, nil
}

func LogSendToBackend(ctx *MsgContext, groupID string, logName string) (string, string, error) {
	return logSendToBackend(ctx, groupID, logName, false)
}

func logSendToBackend(ctx *MsgContext, groupID string, logName string, skipResolve bool) (string, string, error) {
	dice := ctx.Dice
	dirPath := filepath.Join(dice.BaseConfig.DataDir, "log-exports")

	if !skipResolve {
		resolvedName, err := resolveLogNameForGroup(dice.DBOperator, groupID, logName)
		if err != nil {
			return "", "", err
		}
		if resolvedName != "" {
			logName = resolvedName
		}
	}

	var sealBackends []string
	for _, sealBackend := range BackendUrls {
		sealBackends = append(sealBackends, sealBackend+"/dice/api/log")
	}

	uploadCtx := storylog.UploadEnv{
		Dir: dirPath,
		// 原则上说，上传应该都是读的db，但以防万一，还是传Operator
		Db:       dice.DBOperator,
		Log:      dice.Logger,
		Backends: sealBackends,

		LogName:   logName,
		UniformID: ctx.EndPoint.UserID,
		GroupID:   groupID,
	}
	uploadCtx.Version = storylog.StoryVersionV1

	if dice.AdvancedConfig.Enable && dice.AdvancedConfig.StoryLogBackendUrl != "" {
		uploadCtx.Backends = []string{dice.AdvancedConfig.StoryLogBackendUrl}
		uploadCtx.Token = dice.AdvancedConfig.StoryLogBackendToken
	}
	// 原则上1.5支持兼容V1的上传接口，只是需要木落改改代码
	if dice.AdvancedConfig.Enable && dice.AdvancedConfig.StoryLogApiVersion != "" {
		switch dice.AdvancedConfig.StoryLogApiVersion {
		case storylog.StoryVersionV1Str:
			uploadCtx.Version = storylog.StoryVersionV1
		case storylog.StoryVersionV105Str:
			uploadCtx.Version = storylog.StoryVersionV105
		default:
			uploadCtx.Version = storylog.StoryVersionV1
		}
	}

	url, notice, err := storylog.Upload(uploadCtx)
	if err != nil {
		return "", notice, err
	}
	if len(url) == 0 {
		return "", notice, errors.New("上传 log 到服务器失败，未能获取染色器链接")
	}
	return url, notice, nil
}

// LogRollBriefByPCV2 根据log生成骰点简报 采用gjson进行解析 拒绝一次性加载所有数据库数据
func LogRollBriefByPCV2(ctx *MsgContext, items []string, showAll bool, name string) string {
	pcInfo := map[string]map[string]int{}
	// 加载同义词
	tmpl := ctx.Group.GetCharTemplate(ctx.Dice)

	getName := func(s string) string {
		re := regexp.MustCompile(`^([^\d\s]+)(\d+)?$`)
		m := re.FindStringSubmatch(s)
		if len(m) > 0 {
			s = m[1]
		}

		return tmpl.GetAlias(s)
	}

	for _, i := range items {
		// 使用gjson进行解析
		info := gjson.Parse(i)

		setupName := func(name string) {
			if _, exists := pcInfo[name]; !exists {
				pcInfo[name] = map[string]int{}
			}
		}

		if !info.Get("rule").Exists() {
			switch info.Get("cmd").String() {
			case "roll":
				if !info.Get("items").IsArray() {
					continue
				}
				nickname := info.Get("pcName").String()
				setupName(nickname)
				pcInfo[nickname]["骰点"] += len(info.Get("items").Array())
			}
			continue
		}
		if info.Get("rule").String() == "coc7" {
			switch info.Get("cmd").String() {
			case "ra":
				ok2 := info.Get("items").IsArray()
				if !ok2 {
					continue
				}
				nickname := info.Get("pcName").String()
				setupName(nickname)

				for _, j := range info.Get("items").Array() {
					rank := j.Get("rank").Float()
					attr := getName(j.Get("expr2").String())
					if rank > 0 {
						key := fmt.Sprintf("%v:%v", attr, "成功")
						pcInfo[nickname][key]++
					} else if rank < 0 {
						key := fmt.Sprintf("%v:%v", attr, "失败")
						pcInfo[nickname][key]++
					}
				}
				continue
			case "sc":
				ok2 := info.Get("items").IsArray()
				if !ok2 {
					continue
				}
				nickname := info.Get("pcName").String()
				setupName(nickname)

				for _, j := range info.Get("items").Array() {
					rank := j.Get("rank").Float()
					if rank > 0 {
						key := fmt.Sprintf("%v:%v", "理智", "成功")
						pcInfo[nickname][key]++
					} else if rank < 0 {
						key := fmt.Sprintf("%v:%v", "理智", "失败")
						pcInfo[nickname][key]++
					}

					// 如果没有旧值，弄一个
					key := "理智:旧值"
					if pcInfo[nickname][key] == 0 {
						pcInfo[nickname][key] = int(j.Get("sanOld").Int())
					}

					key2 := "理智:新值"
					// if pcInfo[nickname][key2] == 0 {
					pcInfo[nickname][key2] = int(j.Get("sanNew").Int())
					// }
				}
				continue
			case "st":
				ok2 := info.Get("items").IsArray()
				if !ok2 {
					continue
				}
				for _, j := range info.Get("items").Array() {
					nickname := info.Get("pcName").String()
					setupName(nickname)

					if j.Get("type").String() == "mod" {
						readNum := func(item gjson.Result, dataKey, key string) {
							if val := item.Get(dataKey); val.Exists() {
								if val.Type == gjson.Number {
									pcInfo[nickname][key] = int(val.Int()) // 自动处理 float/int/string 数字
								} else {
									// 保存的是 DiceScript 的 IntValue
									if dsVal, dsErr := ds.VMValueFromJSON([]byte(val.Raw)); dsErr == nil {
										if dsInt, dsOK := dsVal.ReadInt(); dsOK {
											pcInfo[nickname][key] = int(dsInt)
										}
									}
								}
							}
							// 如果字段不存在或非数字，pcInfo[nickname][key] 不会被修改
						}

						attr := getName(j.Get("attr").String())
						// 如果没有旧值，弄一个
						key := fmt.Sprintf("%v:旧值", attr)
						if pcInfo[nickname][key] == 0 {
							readNum(j, "valOld", key)
						}

						key2 := fmt.Sprintf("%v:新值", attr)
						// if pcInfo[nickname][key2] == 0 {
						readNum(j, "valNew", key2)
						// }
					}
				}
				continue
			}
		}
	}

	if !showAll {
		pcInfo2 := map[string]map[string]int{}
		if pcInfo[name] != nil {
			pcInfo2[name] = pcInfo[name]
		}
		pcInfo = pcInfo2
	}

	var texts strings.Builder
	for k, v := range pcInfo {
		if len(v) == 0 {
			continue
		}
		fmt.Fprintf(&texts, "<%v>当前团内检定情况:\n", k)
		success := map[string]int{}
		failed := map[string]int{}
		var others []string

		oldVal := map[string]int{}
		newVal := map[string]int{}

		for k2, v2 := range v {
			if strings.HasSuffix(k2, ":成功") {
				success[k2] = v2
			} else if strings.HasSuffix(k2, ":失败") {
				failed[k2] = v2
			} else if strings.HasSuffix(k2, ":旧值") {
				oldVal[k2[:len(k2)-len(":旧值")]] = v2
			} else if strings.HasSuffix(k2, ":新值") {
				newVal[k2[:len(k2)-len(":新值")]] = v2
			} else {
				others = append(others, k2)
			}
		}

		// 排序: 一次挑选一个最大的，直到结束
		doSort := func(m map[string]int) []string {
			var ret []string
			for len(m) > 0 {
				val := -1
				theKey := ""
				for k2, v2 := range m {
					if v2 > val {
						theKey = k2
						val = v2
					}
				}
				ret = append(ret, theKey)
				delete(m, theKey)
			}
			return ret
		}
		successList := doSort(success)
		failedList := doSort(failed)

		if len(successList) > 0 {
			var text strings.Builder
			text.WriteString("成功: ")
			for _, j := range successList {
				fmt.Fprintf(&text, "%v%d ", j[:len(j)-len(":成功")], v[j])
			}
			texts.WriteString(strings.TrimSpace(text.String()))
			texts.WriteString("\n")
		}

		if len(failedList) > 0 {
			var text strings.Builder
			text.WriteString("失败: ")
			for _, j := range failedList {
				fmt.Fprintf(&text, "%v%d ", j[:len(j)-len(":失败")], v[j])
			}
			texts.WriteString(strings.TrimSpace(text.String()))
			texts.WriteString("\n")
		}

		if len(oldVal) > 0 {
			var text strings.Builder
			for k2, v2 := range oldVal {
				fmt.Fprintf(&text, "%v[%v➯%v] ", k2, v2, newVal[k2])
			}
			texts.WriteString("属性: ")
			texts.WriteString(strings.TrimSpace(text.String()))
			texts.WriteString("\n")
		}

		if len(others) > 0 {
			var text strings.Builder
			text.WriteString("其他: ")
			for _, j := range others {
				fmt.Fprintf(&text, "%v%d ", j, v[j])
			}
			texts.WriteString(strings.TrimSpace(text.String()))
			texts.WriteString("\n")
		}
		texts.WriteString("\n")
	}
	return strings.TrimSpace(texts.String())
}

// LogRollBriefByPC 根据log生成骰点简报
func LogRollBriefByPC(ctx *MsgContext, items []*model.LogOneItem, showAll bool, name string) string {
	pcInfo := map[string]map[string]int{}
	// 加载同义词
	tmpl := ctx.Group.GetCharTemplate(ctx.Dice)

	getName := func(s string) string {
		re := regexp.MustCompile(`^([^\d\s]+)(\d+)?$`)
		m := re.FindStringSubmatch(s)
		if len(m) > 0 {
			s = m[1]
		}

		return tmpl.GetAlias(s)
	}

	for _, i := range items {
		if i.CommandInfo != nil { //nolint:nestif
			info, _ := i.CommandInfo.(map[string]interface{})
			// t := time.Unix(i.Time, 0).Format("[04:05]")

			setupName := func(name string) {
				if _, exists := pcInfo[name]; !exists {
					pcInfo[name] = map[string]int{}
				}
			}

			if info["rule"] == nil {
				switch info["cmd"] {
				case "roll":
					items, ok2 := info["items"].([]interface{})
					if !ok2 {
						continue
					}
					nickname := fmt.Sprintf("%v", info["pcName"])
					setupName(nickname)
					pcInfo[nickname]["骰点"] += len(items)
				}
				continue
			}
			if info["rule"] == "coc7" {
				switch info["cmd"] {
				case "ra":
					items, ok2 := info["items"].([]interface{})
					if !ok2 {
						continue
					}
					nickname := fmt.Sprintf("%v", info["pcName"])
					setupName(nickname)

					for _, _j := range items {
						j, ok2 := _j.(map[string]interface{})
						if !ok2 {
							continue
						}

						rank := int(j["rank"].(float64))
						attr := getName(fmt.Sprintf("%v", j["expr2"]))
						if rank > 0 {
							key := fmt.Sprintf("%v:%v", attr, "成功")
							pcInfo[nickname][key]++
						} else if rank < 0 {
							key := fmt.Sprintf("%v:%v", attr, "失败")
							pcInfo[nickname][key]++
						}
					}
					continue
				case "sc":
					items, ok2 := info["items"].([]interface{})
					if !ok2 {
						continue
					}
					nickname := fmt.Sprintf("%v", info["pcName"])
					setupName(nickname)

					for _, _j := range items {
						j, ok2 := _j.(map[string]interface{})
						if !ok2 {
							continue
						}

						rank := int(j["rank"].(float64))
						if rank > 0 {
							key := fmt.Sprintf("%v:%v", "理智", "成功")
							pcInfo[nickname][key]++
						} else if rank < 0 {
							key := fmt.Sprintf("%v:%v", "理智", "失败")
							pcInfo[nickname][key]++
						}

						// 如果没有旧值，弄一个
						key := "理智:旧值"
						if pcInfo[nickname][key] == 0 {
							pcInfo[nickname][key] = int(j["sanOld"].(float64))
						}

						key2 := "理智:新值"
						// if pcInfo[nickname][key2] == 0 {
						pcInfo[nickname][key2] = int(j["sanNew"].(float64))
						// }
					}
					continue
				case "st":
					items, ok2 := info["items"].([]any)
					if !ok2 {
						continue
					}
					for _, _j := range items {
						j, ok2 := _j.(map[string]any)
						if !ok2 {
							continue
						}
						nickname := fmt.Sprintf("%v", info["pcName"])
						setupName(nickname)

						if j["type"] == "mod" {
							readNum := func(dataKey, key string) {
								if val, ok := j[dataKey].(float64); ok {
									// 旧版本兼容，float64是因为json unmarshal默认就是这个
									pcInfo[nickname][key] = int(val)
								} else {
									// TODO: 处理的不是很好，这里后续大段代码依赖了值为int的情况，但是现在实际可以为任何类型，只是不常用
									b, _ := json.Marshal(j[dataKey])
									var v ds.VMValue
									if err := v.UnmarshalJSON(b); err == nil {
										if v.TypeId == ds.VMTypeInt {
											i, _ := v.ReadInt()
											pcInfo[nickname][key] = int(i)
										}
									}
								}
							}

							attr := getName(j["attr"].(string))
							// 如果没有旧值，弄一个
							key := fmt.Sprintf("%v:旧值", attr)
							if pcInfo[nickname][key] == 0 {
								readNum("valOld", key)
							}

							key2 := fmt.Sprintf("%v:新值", attr)
							// if pcInfo[nickname][key2] == 0 {
							readNum("valNew", key2)
							// }
						}
					}
					continue
				}
			}
		}
	}

	if !showAll {
		pcInfo2 := map[string]map[string]int{}
		if pcInfo[name] != nil {
			pcInfo2[name] = pcInfo[name]
		}
		pcInfo = pcInfo2
	}

	var texts strings.Builder
	for k, v := range pcInfo {
		if len(v) == 0 {
			continue
		}
		fmt.Fprintf(&texts, "<%v>当前团内检定情况:\n", k)
		success := map[string]int{}
		failed := map[string]int{}
		var others []string

		oldVal := map[string]int{}
		newVal := map[string]int{}

		for k2, v2 := range v {
			if strings.HasSuffix(k2, ":成功") {
				success[k2] = v2
			} else if strings.HasSuffix(k2, ":失败") {
				failed[k2] = v2
			} else if strings.HasSuffix(k2, ":旧值") {
				oldVal[k2[:len(k2)-len(":旧值")]] = v2
			} else if strings.HasSuffix(k2, ":新值") {
				newVal[k2[:len(k2)-len(":新值")]] = v2
			} else {
				others = append(others, k2)
			}
		}

		// 排序: 一次挑选一个最大的，直到结束
		doSort := func(m map[string]int) []string {
			var ret []string
			for len(m) > 0 {
				val := -1
				theKey := ""
				for k2, v2 := range m {
					if v2 > val {
						theKey = k2
						val = v2
					}
				}
				ret = append(ret, theKey)
				delete(m, theKey)
			}
			return ret
		}
		successList := doSort(success)
		failedList := doSort(failed)

		if len(successList) > 0 {
			var text strings.Builder
			text.WriteString("成功: ")
			for _, j := range successList {
				fmt.Fprintf(&text, "%v%d ", j[:len(j)-len(":成功")], v[j])
			}
			texts.WriteString(strings.TrimSpace(text.String()))
			texts.WriteString("\n")
		}

		if len(failedList) > 0 {
			var text strings.Builder
			text.WriteString("失败: ")
			for _, j := range failedList {
				fmt.Fprintf(&text, "%v%d ", j[:len(j)-len(":失败")], v[j])
			}
			texts.WriteString(strings.TrimSpace(text.String()))
			texts.WriteString("\n")
		}

		if len(oldVal) > 0 {
			var text strings.Builder
			for k2, v2 := range oldVal {
				fmt.Fprintf(&text, "%v[%v➯%v] ", k2, v2, newVal[k2])
			}
			texts.WriteString("属性: ")
			texts.WriteString(strings.TrimSpace(text.String()))
			texts.WriteString("\n")
		}

		if len(others) > 0 {
			var text strings.Builder
			text.WriteString("其他: ")
			for _, j := range others {
				fmt.Fprintf(&text, "%v%d ", j, v[j])
			}
			texts.WriteString(strings.TrimSpace(text.String()))
			texts.WriteString("\n")
		}
		texts.WriteString("\n")
	}
	return strings.TrimSpace(texts.String())
}

// LogRollBriefDetail 根据log生成骰点简报
// TODO：新逻辑下它不可用
func LogRollBriefDetail(items []*model.LogOneItem) []string {
	var texts []string
	for _, i := range items {
		if i.CommandInfo != nil { //nolint:nestif
			info, _ := i.CommandInfo.(map[string]interface{})
			t := time.Unix(i.Time, 0).Format("[04:05]")

			if info["rule"] == nil {
				switch info["cmd"] {
				case "roll":
					// [03分20秒] 木落 骰点d100，出目15
					items, ok2 := info["items"].([]interface{})
					if !ok2 {
						continue
					}
					for _, _j := range items {
						j, ok2 := _j.(map[string]interface{})
						if !ok2 {
							continue
						}

						reasonText := ""
						if j["reason"] != nil {
							reasonText = fmt.Sprintf(" 原因:%v", j["reason"])
						}

						texts = append(texts, fmt.Sprintf("%v %s 骰点%v 出目%v%v", t, info["pcName"], j["expr"], j["result"], reasonText))
					}
				}
				continue
			}
			if info["rule"] == "coc7" {
				switch info["cmd"] {
				case "ra":
					items, ok2 := info["items"].([]interface{})
					if !ok2 {
						continue
					}
					for _, _j := range items {
						j, ok2 := _j.(map[string]interface{})
						if !ok2 {
							continue
						}

						// [18分60秒] 木落 "力量50"检定，出目39/50，成功
						texts = append(texts, fmt.Sprintf("%v %s \"%s\"检定 出目%v/%v，%v", t, info["pcName"], j["expr2"], j["checkVal"], j["attrVal"], SimpleCocSuccessRankToText[int(j["rank"].(float64))]))
					}
					continue
				case "sc":
					items, ok2 := info["items"].([]interface{})
					if !ok2 {
						continue
					}
					for _, _j := range items {
						j, ok2 := _j.(map[string]interface{})
						if !ok2 {
							continue
						}

						// [18分60秒] 木落 理智检定[d100 1 2]，出目15/60，失败。理智39➯38
						texts = append(texts, fmt.Sprintf("%v %s 理智检定%v 出目%v/%v，%v。理智%v➯%v",
							t, info["pcName"], j["exprs"], j["checkVal"], j["sanOld"],
							SimpleCocSuccessRankToText[int(j["rank"].(float64))], j["sanOld"], j["sanNew"]))
					}
					continue
				case "st":
					items, ok2 := info["items"].([]interface{})
					if !ok2 {
						continue
					}
					for _, _j := range items {
						j, ok2 := _j.(map[string]interface{})
						if !ok2 {
							continue
						}

						if j["type"] == "mod" {
							// [18分60秒] 木落 hp变更1d4，39➯38
							texts = append(texts, fmt.Sprintf("%v %s %v变更%v，%v➯%v",
								t, info["pcName"], j["attr"], j["modExpr"], j["valOld"], j["valNew"]))
						}
					}
					continue
				}
			}

			if info["rule"] == "dnd5e" {
				switch info["cmd"] {
				case "rc":
					items, ok2 := info["items"].([]interface{})
					if !ok2 {
						continue
					}
					for _, _j := range items {
						j, ok2 := _j.(map[string]interface{})
						if !ok2 {
							continue
						}

						// [18分60秒] 木落 力量检定，出目24
						texts = append(texts, fmt.Sprintf("%v %s %s检定 出目%v", t, info["pcName"], j["reason"], j["result"]))
					}
					continue
				case "st":
					items, ok2 := info["items"].([]interface{})
					if !ok2 {
						continue
					}
					for _, _j := range items {
						j, ok2 := _j.(map[string]interface{})
						if !ok2 {
							continue
						}

						if j["type"] == "mod" {
							// [18分60秒] 木落 hp变更1d4，39➯38
							texts = append(texts, fmt.Sprintf("%v %s %v变更%v，%v➯%v",
								t, info["pcName"], j["attr"], j["modExpr"], j["valOld"], j["valNew"]))
						}
					}
					continue
				}
			}

			texts = append(texts, fmt.Sprintf("%v\n", i.CommandInfo))
		}
	}
	return texts
}
