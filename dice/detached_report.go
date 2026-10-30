package dice

import "runtime/debug"

// detach lets background work speak for a command after the command returned.
//
// A command's MsgContext is released as soon as the command returns: VarSetValue
// then panics, which takes the whole process down when it happens in a
// goroutine, and replies are silently dropped. The returned function therefore
// builds a fresh context for the same endpoint and sender, from a snapshot of
// msg, on every call and runs speak with it. A failure, including a panic, is
// logged and only loses that one report, so it can never stop the work that
// produced it.
func (ctx *MsgContext) detach(msg *Message) func(speak func(reportCtx *MsgContext, reportMsg *Message)) {
	endpoint, snapshot, logger := ctx.EndPoint, *msg, ctx.Dice.Logger
	return func(speak func(reportCtx *MsgContext, reportMsg *Message)) {
		defer func() {
			if r := recover(); r != nil {
				logger.Errorf("命令的延迟汇报异常: %v\n%s", r, debug.Stack())
			}
		}()
		reportMsg := snapshot
		reportCtx := CreateTempCtx(endpoint, &reportMsg)
		reportCtx.standaloneSendScope = true
		defer reportCtx.releaseExecutionState()
		speak(reportCtx, &reportMsg)
	}
}

// detachReply is detach for the common case of sending one text back to the
// sender of msg.
func (ctx *MsgContext) detachReply(msg *Message) func(text string) {
	report := ctx.detach(msg)
	return func(text string) {
		report(func(reportCtx *MsgContext, reportMsg *Message) { ReplyToSender(reportCtx, reportMsg, text) })
	}
}
