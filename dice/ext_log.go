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

func getGroupLogOn(group *GroupInfo) bool {
	state := getGroupLogState(group)
	return state.On && state.Name != ""
}

// suspendLogForBotOff 在 .bot off 让群变为“未激活”时暂停日志记录。
// 只把 LogOn 置 false（不结束、不上传，LogCurID/LogCurName 保留），
// 并记下“这是 .bot off 造成的暂停”，供 .bot on 恢复。
// 返回是否真的暂停了（原本日志就是关的则返回 false）。
func (g *GroupInfo) suspendLogForBotOff() bool {
	if g == nil {
		return false
	}
	g.logStateMu.Lock()
	defer g.logStateMu.Unlock()
	if !g.LogOn || g.LogCurName == "" {
		return false
	}
	g.LogOn = false
	g.LogPausedByBotOff = true
	return true
}

// resumeLogPausedByBotOff 在群重新激活（.bot on）时恢复被 .bot off 暂停的日志。
// 无论是否由本次恢复，都会标记“下一条消息只重建基线”，让静默段不被补录；
// 若期间用户已经 .log on / .log new / .log end，则以用户操作为准。
// 返回值表示本次是否真的把日志重新打开了。
func (g *GroupInfo) resumeLogPausedByBotOff() bool {
	if g == nil {
		return false
	}
	g.logStateMu.Lock()
	defer g.logStateMu.Unlock()
	if !g.LogPausedByBotOff {
		return false
	}
	g.LogPausedByBotOff = false
	g.LogResumeSkipGap = true
	if g.LogOn || g.LogCurName == "" {
		// 用户已经重新开启，或已经 end/new 换了一本日志：不要覆盖用户的操作。
		return false
	}
	g.LogOn = true
	return true
}

// isLogPausedByBotOff 报告当前日志关闭是否由 .bot off 自动暂停造成。
func (g *GroupInfo) isLogPausedByBotOff() bool {
	if g == nil {
		return false
	}
	g.logStateMu.RLock()
	defer g.logStateMu.RUnlock()
	return g.LogPausedByBotOff
}

// clearLogPausedByBotOff 在用户显式操作日志（.log on/new/off/end/halt）后清除
// “暂停由 .bot off 造成”的标记。否则用户已经换了/结束了日志，下一次 .bot on
// 仍会被当成“从暂停中恢复”，用指令 seq 覆盖刚建立的基线。
func (g *GroupInfo) clearLogPausedByBotOff() {
	if g == nil {
		return
	}
	g.logStateMu.Lock()
	g.LogPausedByBotOff = false
	g.logStateMu.Unlock()
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
.log export <日志名> <邮箱地址> // 通过邮件取得日志txt，多个邮箱用空格隔开`

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
				unofficial, fn, notice, err := logSendToBackend(ctx, gid, lname, true)
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
					if unofficial {
						tmpl += "\n[注意：该链接非余烬官方染色器]"
					}
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

				// 如果日志已经开启，报错返回
				currentState := getGroupLogState(group)
				if currentState.On {
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
						group.SetLogState(logID, name, true)
						group.resetLogSeq(msg.Seq, msg.RawID)
						group.clearLogResumeSkipGap()
						group.clearLogPausedByBotOff()
						group.MarkDirty(ctx.Dice)
						ctx.Dice.Logger.Infof("日志状态切换: 群=%s 开启日志 name=%s id=%d", group.GroupID, name, logID)

						VarSetValueStr(ctx, "$t记录名称", name)
						VarSetValueInt64(ctx, "$t当前记录条数", lines)
						ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "日志:记录_开启_成功"))
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
				if state.Name != "" && state.On {
					group.SetLogOn(false)
					group.clearLogPausedByBotOff()
					group.MarkDirty(ctx.Dice)
					ctx.Dice.Logger.Infof("日志状态切换: 群=%s 暂停日志 name=%s id=%d", group.GroupID, state.Name, state.ID)
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
					group.SetLogState(logID, name, true)
					group.resetLogSeq(msg.Seq, msg.RawID)
					group.clearLogResumeSkipGap()
					group.clearLogPausedByBotOff()
					group.MarkDirty(ctx.Dice)
					ctx.Dice.Logger.Infof("日志状态切换: 群=%s 新建并开启日志 name=%s id=%d", group.GroupID, name, logID)

				ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "日志:记录_新建"))
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
					if msg.Seq > 0 {
						// 只有“日志正在记录”时才会走到这里；off 期间整段不进来，
						// 所以 off 的消息永远不会被算成缺口。
						fromSeq, lastMsgID, gap := logGapFromMessage(ctx.Dice, ctx.Group, logState, msg.Seq, msg.RawID)
						if gap > 0 {
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
				}
			}
		},
		OnMessageDeleted: func(ctx *MsgContext, msg *Message) {
			if ctx.Group != nil {
				if getGroupLogOn(ctx.Group) {
					LogDeleteByID(ctx, ctx.Group.GroupID, msg.RawID)
					// ctx.Session.Parent.Logger.Infof("删除日志 %s %s", ctx.Group.GroupId, msg.RawId.(string))
				}
			}
		},
		OnMessageEdit: func(ctx *MsgContext, msg *Message) {
			if ctx.Group == nil {
				return
			}

			if getGroupLogOn(ctx.Group) {
				LogEditByID(ctx, ctx.Group.GroupID, msg.Message, msg.RawID)
			}
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

		var prefix string
		if ctx.EndPoint.Platform == "QQ" {
			prefix = "QQ-Group"
		}
		if !strings.HasPrefix(data, prefix) {
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
		reportLogAppendFailure(ctx, groupID, logID, logName)
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
	// 一次断层补全的总预算：最多 2000 条、每页 100 条，即 20 次接口调用。
	// 30s 在慢线路/大群上不够，给到 60s。
	logGapFillTimeout      = 60 * time.Second
	logGapFillPageTimeout  = 15 * time.Second // 单页拉取超时，避免一页卡住耗尽总预算
	logGapFillPageSize     = 100              // 单次 get_group_msg_history 的拉取上限
	logGapFillMaxMessages  = 2000             // 单次断层最多补录的消息数，避免离线数天时无限拉取
	logGapFillFetchRetries = 3                // 瞬时网络错误的重试次数
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
// 跑团类指令（st/ra/draw/name 等）仍然重放，它们是补录的意义所在。
var logGapReplayDeniedCommands = map[string]struct{}{
	"log":     {},
	"bot":     {},
	"master":  {},
	"dismiss": {},
	"ban":     {},
	"unban":   {},
	"ext":     {},
	"set":     {},
	"black":   {},
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
	lastSeq, lastMsgID, selfSent := group.updateLogSeq(msgSeq, rawID)
	if lastSeq == 0 && logState.ID > 0 {
		// 优先使用持久基线；它记录的是 .log on/.log new 的边界，
		// 比 DB MAX(seq) 更能防止把 log off 期间的消息补进日志。
		persistedSeq, persistedMsgID := group.logSeqBaselineSnapshot()
		if persistedSeq > lastSeq {
			lastSeq = persistedSeq
			if persistedMsgID != "" {
				lastMsgID = persistedMsgID
			}
		}
	}
	// 重启后 logLastSeq 只来自持久基线（.log on 那一刻），可能远旧于数据库里
	// 实际记录的最后一条。每进程首次记日志时用 DB MAX(seq) 校准一次，否则首条
	// 消息会算出巨大假缺口：补的是早已记录的历史，真正的离线缺口反而漏补。
	lastSeq, lastMsgID = calibrateLogSeqBaseline(d, group, logState.ID, lastSeq, lastMsgID)
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

// calibrateLogSeqBaseline 在进程内首次记日志时，用数据库里该日志的 MAX(seq)
// 校准 seq 基线，返回校准后的上一条 seq 与 RawID。
//
// 为什么需要：logLastSeq 是运行时字段，重启后只由持久基线（.log on/.log new
// 那一刻的序号）恢复。直接拿它算缺口会把 .log on 之后已经落库的整段历史当成
// 断层（最多拉取 logGapFillMaxMessages 条已记录消息），同时真正的离线缺口
// 因为基线被 updateLogSeq 直接推到最新而永远补不上。
//
// 每个进程只查一次（成功后置 logSeqCalibrated），不会给消息主路径增加常态开销。
func calibrateLogSeqBaseline(d *Dice, group *GroupInfo, logID uint64, lastSeq int64, lastMsgID interface{}) (int64, interface{}) {
	if d == nil || d.DBOperator == nil || group == nil || logID == 0 {
		return lastSeq, lastMsgID
	}
	if !group.needLogSeqCalibration() {
		return lastSeq, lastMsgID
	}
	seq, err := service.LogGetLastSeq(d.DBOperator, logID)
	if err != nil {
		// 查不到就保持原基线；退避一分钟再试，避免数据库异常时每条消息都查库。
		group.deferLogSeqCalibration(time.Minute)
		return lastSeq, lastMsgID
	}
	group.markLogSeqCalibrated()
	if seq <= lastSeq {
		return lastSeq, lastMsgID
	}
	group.advanceLogSeq(seq, nil)
	// 数据库里最后一条消息没有携带 RawID，避免断层通知引用错误的消息。
	return seq, nil
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
	// epoch==0 兼容测试里手工构造的任务。
	if t.epoch != 0 && t.group.logEpoch.Load() != t.epoch {
		return false
	}
	return true
}

// forEachMissing 按顺序遍历缺失消息，并在处理每条之前确认日志仍然有效。
//
// 只在任务开始/拉取结束时校验是不够的：补录最多 2000 条、静默重放还要执行指令，
// 期间用户完全可能 .log off / .log new。不逐条校验的话，关掉的日志仍会被继续
// 写入（用户看到的就是“off 之后内容还在进日志”），静默重放还会在日志关闭后
// 继续执行历史指令却不留记录。返回实际处理条数，小于 len(missing) 表示被中止。
func (t logGapFillTask) forEachMissing(missing []*Message, fn func(*Message)) int {
	for i, m := range missing {
		if !t.logStateStillValid() {
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

// mergeLogGapTask 合并待处理区间，返回是否需要启动 worker。
func (g *GroupInfo) mergeLogGapTask(task logGapFillTask) bool {
	g.logGapQueueMu.Lock()
	defer g.logGapQueueMu.Unlock()

	pending := g.logGapPending
	// 日志切换（ID/名称变化）或基线重建（epoch 变化）时旧区间已无意义：
	// 用新任务替换，避免把新日志/新基线的断层合并进旧任务后一起取消，
	// 也避免把 off/静默段合并进旧任务补进日志。
	if pending == nil || pending.logID != task.logID || pending.logName != task.logName || pending.epoch != task.epoch {
		t := task
		g.logGapPending = &t
	} else {
		if task.fromSeq < pending.fromSeq {
			pending.fromSeq = task.fromSeq
			pending.lastMsgID = task.lastMsgID
		}
		if task.toSeq > pending.toSeq {
			pending.toSeq = task.toSeq
			pending.gap += task.gap
		}
		// 重连后 endpoint 可能已更换，总是使用最新任务的状态。
		pending.endpoint = task.endpoint
		pending.dice = task.dice
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
			g.logGapWorkerRunning = false
			g.logGapQueueMu.Unlock()
			return
		}
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
	}
}

func (t logGapFillTask) run() {
	if t.group == nil || t.dice == nil || t.endpoint == nil {
		return
	}
	if !t.logStateStillValid() {
		t.dice.Logger.Infof("日志补全已取消: 群=%s 记录=%s 已关闭或被切换", t.group.GroupID, t.logName)
		return
	}

	fetcher, ok := t.endpoint.Adapter.(HistoryFetcher)
	if !ok {
		t.dice.Logger.Infof("日志补全跳过: 平台未实现历史消息拉取: 群=%s 平台=%s",
			t.group.GroupID, t.endpoint.Platform)
		return
	}

	t.dice.Logger.Infof("检测到日志seq断层: 群=%s 上条seq=%d 本条seq=%d 缺失=%d",
		t.group.GroupID, t.fromSeq, t.toSeq, t.gap)

	fetchCtx, cancel := context.WithTimeout(context.Background(), logGapFillTimeout)
	defer cancel()

	msgs, err := t.fetchHistory(fetchCtx, fetcher)
	if err != nil {
		t.dice.Logger.Errorf("日志补全拉取历史消息失败: 群=%s 起始seq=%d err=%v", t.group.GroupID, t.fromSeq, err)
		return
	}

	missing := t.filterMissing(msgs)
	missing = t.filterAlreadyLogged(missing)
	if len(missing) == 0 {
		t.dice.Logger.Infof("日志补全无需处理: 群=%s 缺失区间内没有需要补录的他人发言", t.group.GroupID)
		return
	}

	// 拉取历史可能耗时数十秒，写入前必须再确认一次日志状态。
	if !t.logStateStillValid() {
		t.dice.Logger.Infof("日志补全已取消: 群=%s 记录=%s 在拉取期间已关闭或被切换", t.group.GroupID, t.logName)
		return
	}

	if t.gap <= logGapFillSilentThreshold {
		t.replaySilently(missing)
		return
	}
	t.backfillWithNotice(missing)
}

// fetchHistory 按页拉取 (fromSeq, toSeq) 区间，直到覆盖到 toSeq-1 或达到上限。
// 单次 get_group_msg_history 的 count 有实现上限（常见 100），不能一次性传整个断层。
func (t logGapFillTask) fetchHistory(ctx context.Context, fetcher HistoryFetcher) ([]*Message, error) {
	var lastErr error
	for attempt := 0; attempt < logGapFillFetchRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(1<<uint(attempt-1)) * time.Second):
			}
		}
		msgs, err := t.fetchHistoryOnce(ctx, fetcher)
		if err == nil {
			return msgs, nil
		}
		lastErr = err
		t.dice.Logger.Warnf("日志补全拉取历史消息失败(第%d次): 群=%s err=%v", attempt+1, t.group.GroupID, err)
	}
	return nil, lastErr
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
	from, total := logGapFetchWindow(t.fromSeq, t.toSeq)
	if total <= 0 {
		return nil, nil
	}
	if from > t.fromSeq {
		t.dice.Logger.Warnf("日志补全区间过大(共%d条)，仅补录最近%d条(seq %d-%d): 群=%s 上条seq=%d 本条seq=%d",
			t.toSeq-t.fromSeq-1, total, from, t.toSeq-1, t.group.GroupID, t.fromSeq, t.toSeq)
	}

	all := make([]*Message, 0, total)
	seen := make(map[int64]struct{}, total)
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
			return nil, err
		}
		if len(page) == 0 {
			break
		}

		maxSeq := from
		for _, m := range page {
			if m == nil {
				continue
			}
			if m.Seq > from && m.Seq < t.toSeq {
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
			// 实现没有返回可用的 seq，继续翻页只会死循环。
			break
		}
		from = maxSeq
	}

	sort.SliceStable(all, func(i, j int) bool { return all[i].Seq < all[j].Seq })
	return all, nil
}

// filterMissing 保留断层区间内的他人发言。
// 骰子自身发言已由 OnMessageSend 记录，重复入库或被当成玩家指令执行都是错的；
// 自身发言计数虽已在断层估算时扣除，但计数可能因重启丢失，故这里仍按发送者兜底剔除。
// 其他机器人同样剔除：历史消息里的 bot 指令不应在本群重新执行。
func (t logGapFillTask) filterMissing(msgs []*Message) []*Message {
	missing := make([]*Message, 0, len(msgs))
	for _, m := range msgs {
		if m == nil || m.Seq <= t.fromSeq || m.Seq >= t.toSeq {
			continue
		}
		if t.endpoint != nil && m.Sender.UserID == t.endpoint.UserID {
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

// filterAlreadyLogged 跳过已经写入同一日志的消息。
// 平台重连补发、或补全任务与正常事件并发时，同一条消息可能既走事件路径又被历史拉取到；
// log_items 对 raw_msg_id 没有唯一约束，必须在补录前查一次。
func (t logGapFillTask) filterAlreadyLogged(msgs []*Message) []*Message {
	if t.dice == nil || t.dice.DBOperator == nil {
		return msgs
	}
	// 与 fetchHistoryOnce 使用同一窗口：超大断层只补最近 2000 条时，
	// 去重集合也只需覆盖这一段，避免为几十万 seq 建 map。
	windowFrom, _ := logGapFetchWindow(t.fromSeq, t.toSeq)
	existing, err := service.LogRawMsgIDsInSeqRange(t.dice.DBOperator, t.logID, windowFrom, t.toSeq)
	if err != nil {
		t.dice.Logger.Warnf("日志补全查询已记录消息失败，继续补录: 群=%s err=%v", t.group.GroupID, err)
		return msgs
	}
	if len(existing) == 0 {
		return msgs
	}
	filtered := msgs[:0]
	for _, m := range msgs {
		if m == nil {
			continue
		}
		if _, ok := existing[fmt.Sprintf("%v", m.RawID)]; ok {
			continue
		}
		filtered = append(filtered, m)
	}
	return filtered
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
func (t logGapFillTask) replaySilently(missing []*Message) {
	session := t.endpoint.Session
	if session == nil {
		t.dice.Logger.Warnf("日志补全无法重放: 群=%s 端点会话未绑定", t.group.GroupID)
		return
	}
	if !t.logStateStillValid() {
		t.dice.Logger.Infof("日志补全已取消(静默重放): 群=%s 日志已关闭或切换", t.group.GroupID)
		return
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
			item := t.logItem(m)
			LogAppend(logCtx, t.group.GroupID, t.logID, t.logName, &item)
			skipped++
			return
		}
		session.ExecuteNew(t.endpoint, m)
		executed++
	})
	if processed < len(missing) {
		t.dice.Logger.Warnf("日志补全中止(静默重放): 群=%s 日志在重放过程中被关闭或切换，已重放=%d条 仅补日志=%d条 剩余=%d条",
			t.group.GroupID, executed, skipped, len(missing)-processed)
		return
	}
	t.dice.Logger.Infof("日志补全完成(静默重放): 群=%s 重放=%d条 仅补日志=%d条", t.group.GroupID, executed, skipped)
}

func (t logGapFillTask) isDeniedReplayCommand(m *Message) bool {
	if m == nil {
		return false
	}
	cmd := extractCommandName(t.dice.CommandPrefix, m.Platform, m.Message)
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
		if LogAppend(mctx, t.group.GroupID, t.logID, t.logName, &item) {
			appended++
		}

		if t.isBotSender(m) {
			return
		}
		cmd := extractCommandName(t.dice.CommandPrefix, m.Platform, m.Message)
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
					marker := ""
					if line.IsGapFill {
						marker = "[补录] "
					}
					text := fmt.Sprintf("%s%s(%v) %s\n%s\n\n", marker, line.Nickname, line.IMUserID, timeTxt, line.Message)
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

func LogSendToBackend(ctx *MsgContext, groupID string, logName string) (bool, string, string, error) {
	return logSendToBackend(ctx, groupID, logName, false)
}

func logSendToBackend(ctx *MsgContext, groupID string, logName string, skipResolve bool) (bool, string, string, error) {
	dice := ctx.Dice
	dirPath := filepath.Join(dice.BaseConfig.DataDir, "log-exports")

	if !skipResolve {
		resolvedName, err := resolveLogNameForGroup(dice.DBOperator, groupID, logName)
		if err != nil {
			return false, "", "", err
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

	var unofficial bool
	if dice.AdvancedConfig.Enable && dice.AdvancedConfig.StoryLogBackendUrl != "" {
		unofficial = true
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
		return unofficial, "", notice, err
	}
	if len(url) == 0 {
		return unofficial, "", notice, errors.New("上传 log 到服务器失败，未能获取染色器链接")
	}
	return unofficial, url, notice, nil
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
