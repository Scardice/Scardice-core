package dice

import (
	"runtime/debug"
	"time"
)

// setOutboundDelay makes every durable effect submitted through ctx wait at
// least delay before the outbox hands it to the provider. A zero or negative
// delay restores immediate delivery. Callback handlers use it instead of
// sleeping, because a sleeping handler would hold the callback lease.
func (ctx *MsgContext) setOutboundDelay(delay time.Duration) {
	if delay < 0 {
		delay = 0
	}
	ctx.outboundDelay = delay
}

// noticeInTransaction delivers a notice from inside a durable callback. The
// goroutine used outside callbacks would race the transaction's finalization
// and its sends would be refused once the callback closes, so the notice is
// staged synchronously and the legacy one-second pause between targets becomes
// a delay on each effect.
func (ctx *MsgContext) noticeInTransaction(txt string, noticeType NoticeType) {
	defer func() {
		if r := recover(); r != nil {
			ctx.Dice.Logger.Errorf("发送通知异常: %v 堆栈: %v", r, string(debug.Stack()))
		}
	}()

	sent := false
	if ctx.EndPoint != nil && ctx.EndPoint.Enable {
		base := ctx.outboundDelay
		for index, target := range filterNoticeTargetsForEndpoint(ctx.Dice.Config.NoticeIDs, noticeType, ctx.EndPoint) {
			ctx.setOutboundDelay(base + time.Duration(index)*time.Second)
			sendNoticeToTarget(ctx, target, txt)
			sent = true
		}
		ctx.setOutboundDelay(base)
	}
	if sent {
		return
	}
	platform := "<未知平台>"
	if ctx.EndPoint != nil {
		platform = ctx.EndPoint.Platform
	}
	if len(filterNoticeTargets(ctx.Dice.Config.NoticeIDs, noticeType)) != 0 {
		ctx.Dice.Logger.Errorf("未能发送来自%s的通知：%s", platform, txt)
	} else {
		ctx.Dice.Logger.Warnf("因为没有启用接收 %s 分类的通知目标，无法发送来自%s的通知：%s", noticeType, platform, txt)
	}
}
