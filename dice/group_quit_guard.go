package dice

import (
	"sync"

	"Scardice-core/logger"
)

// botGroupRoleChecker 允许测试替换群内身份查询；生产路径固定为 checkBotGroupRole。
// 自动退群会在独立 goroutine 中读取，测试替换时必须加锁，避免 race。
var (
	botGroupRoleCheckerMu sync.RWMutex
	botGroupRoleChecker   = checkBotGroupRole
)

func getBotGroupRoleChecker() func(*MsgContext, string) (string, bool) {
	botGroupRoleCheckerMu.RLock()
	defer botGroupRoleCheckerMu.RUnlock()
	return botGroupRoleChecker
}

func setBotGroupRoleChecker(checker func(*MsgContext, string) (string, bool)) {
	botGroupRoleCheckerMu.Lock()
	defer botGroupRoleCheckerMu.Unlock()
	botGroupRoleChecker = checker
}

// groupQuitNeedsRoleCheck 判断当前平台是否需要退群前的群主保护。
// QQ 系平台退群可能直接解散群聊，必须在自动退群前确认骰子账号不是群主。
func groupQuitNeedsRoleCheck(ctx *MsgContext) bool {
	if ctx == nil || ctx.EndPoint == nil {
		return false
	}
	return ctx.EndPoint.Platform == "QQ" || ctx.EndPoint.ProtocolType == "onebot"
}

// canAutoQuitGroup 是自动退群的统一闸门。
// 身份查询失败或当前账号是群主时返回 false；无法查询身份的旧适配器保持原行为。
func canAutoQuitGroup(ctx *MsgContext, groupID string) bool {
	if ctx == nil || ctx.EndPoint == nil || ctx.EndPoint.Adapter == nil {
		return false
	}
	if !groupQuitNeedsRoleCheck(ctx) {
		return true
	}

	checker := getBotGroupRoleChecker()
	role, ok := checker(ctx, groupID)
	if !ok {
		if role == errGroupRoleCheckUnsupported {
			// WalleQ/官方 QQ 等适配器没有可靠的群角色查询，保持原有自动退群行为。
			logGroupQuitRoleCheckSkipped(ctx, groupID, role)
			return true
		}
		logGroupQuitBlocked(ctx, groupID, role)
		return false
	}
	if role == "owner" {
		logGroupQuitBlocked(ctx, groupID, "当前账号为本群群主，自动退群会解散群聊")
		return false
	}
	return true
}

// quitGroupSafely 在真正发送退群请求前再核对一次身份，避免查询后身份发生变化。
// 自动退群永远不带群主确认，因此群主会被拦下。
func quitGroupSafely(ctx *MsgContext, groupID string) bool {
	if !canAutoQuitGroup(ctx, groupID) {
		return false
	}
	ctx.EndPoint.Adapter.QuitGroup(ctx, groupID)
	return true
}

// autoQuitGroup 同步执行自动退群：先校验身份，再执行告别/通告，最后退群。
// 返回 false 表示已取消，beforeQuit 不会执行。
func autoQuitGroup(ctx *MsgContext, groupID string, beforeQuit func(*MsgContext)) bool {
	if !canAutoQuitGroup(ctx, groupID) {
		return false
	}
	if beforeQuit != nil {
		beforeQuit(ctx)
	}
	return quitGroupSafely(ctx, groupID)
}

// autoQuitGroupAsync 在独立任务中执行自动退群。
// 黑名单处理位于消息/事件处理路径，身份查询需要等待平台 API 回复，
// 放到独立 goroutine 可以避免阻塞事件循环；panic 由 ErrorLogAndContinue 兜底。
func autoQuitGroupAsync(ctx *MsgContext, groupID string, beforeQuit func(*MsgContext)) {
	if ctx == nil || ctx.Dice == nil {
		return
	}
	quitCtx := ctx.ShallowCopy()
	go func() {
		defer ErrorLogAndContinue(quitCtx.Dice)
		autoQuitGroup(quitCtx, groupID, beforeQuit)
	}()
}

func logGroupQuitBlocked(ctx *MsgContext, groupID string, detail string) {
	log := logger.M()
	botID := ""
	if ctx != nil {
		if ctx.Dice != nil && ctx.Dice.Logger != nil {
			log = ctx.Dice.Logger
		}
		if ctx.EndPoint != nil {
			botID = ctx.EndPoint.UserID
		}
	}
	log.Warnf("自动退群已取消: 群组<%s>，账号<%s>，身份检查结果: %s", groupID, botID, detail)
}

func logGroupQuitRoleCheckSkipped(ctx *MsgContext, groupID string, detail string) {
	log := logger.M()
	botID := ""
	if ctx != nil {
		if ctx.Dice != nil && ctx.Dice.Logger != nil {
			log = ctx.Dice.Logger
		}
		if ctx.EndPoint != nil {
			botID = ctx.EndPoint.UserID
		}
	}
	log.Warnf("自动退群未做群主校验: 群组<%s>，账号<%s>，原因: %s", groupID, botID, detail)
}
