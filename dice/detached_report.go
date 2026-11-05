package dice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime/debug"
	"slices"
	"strconv"
	"sync/atomic"

	"Scardice-core/core/execution"
	"Scardice-core/eventstore"
	"Scardice-core/logger"
)

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
	var log = logger.M()
	if ctx != nil && ctx.Dice != nil && ctx.Dice.Logger != nil {
		log = ctx.Dice.Logger
	}
	if ctx == nil || ctx.Dice == nil || ctx.EndPoint == nil || ctx.Session == nil ||
		ctx.EndPoint.Session == nil || ctx.Session != ctx.EndPoint.Session || msg == nil {
		return func(func(*MsgContext, *Message)) {
			log.Error("命令的延迟汇报失败: 上下文不完整")
		}
	}
	origin, d, session, endpoint := ctx, ctx.Dice, ctx.Session, ctx.EndPoint
	snapshot := *msg
	snapshot.Segment = slices.Clone(msg.Segment)
	baseID, identityErr := (eventstore.UUIDGenerator{}).NewID()
	local := struct {
		commandID       int64
		currentCommand  string
		commandHideFlag string
		privilegeLevel  int
		groupRoleLevel  int
	}{
		commandID: ctx.CommandID, currentCommand: ctx.CurrentCommand,
		commandHideFlag: ctx.CommandHideFlag, privilegeLevel: ctx.PrivilegeLevel,
		groupRoleLevel: ctx.GroupRoleLevel,
	}
	var sequence atomic.Uint64
	return func(speak func(reportCtx *MsgContext, reportMsg *Message)) {
		if identityErr != nil {
			log.Errorf("命令的延迟汇报失败: %v", identityErr)
			return
		}
		if speak == nil {
			log.Error("命令的延迟汇报失败: 汇报函数为空")
			return
		}
		if endpoint.Session == nil || endpoint.Session != session || d.ImSession != session {
			log.Error("命令的延迟汇报失败: endpoint 会话已失效")
			return
		}
		call := sequence.Add(1)
		canonical, err := json.Marshal(struct {
			BaseID      string `json:"baseId"`
			Call        uint64 `json:"call"`
			EndpointID  string `json:"endpointId"`
			MessageType string `json:"messageType"`
			GroupID     string `json:"groupId,omitempty"`
			UserID      string `json:"userId,omitempty"`
		}{
			BaseID: baseID, Call: call, EndpointID: endpoint.ID, MessageType: snapshot.MessageType,
			GroupID: snapshot.GroupID, UserID: snapshot.Sender.UserID,
		})
		if err != nil {
			log.Errorf("命令的延迟汇报失败: %v", err)
			return
		}
		identity := d.DomainExecutionIdentity("detached-report", baseID+":"+strconv.FormatUint(call, 10))
		execute := func(transaction *DurableCallbackTransaction) error {
			reportMsg := snapshot
			reportCtx, buildErr := NewDomainMsgContext(transaction, d, session, endpoint, &reportMsg)
			if buildErr != nil {
				return buildErr
			}
			reportCtx.callbackMetadata = transaction.metadata
			reportCtx.executionContext = transaction.executionContext
			reportCtx.CommandID = local.commandID
			reportCtx.CurrentCommand = local.currentCommand
			reportCtx.CommandHideFlag = local.commandHideFlag
			reportCtx.PrivilegeLevel = local.privilegeLevel
			reportCtx.GroupRoleLevel = local.groupRoleLevel
			return runDetachedReport(reportCtx, &reportMsg, speak)
		}
		// A live origin root is joined only while it still accepts work; a
		// report launched as the command returns may find the root already
		// sealed, in which case it speaks from a root of its own.
		if origin.callbackTransaction != nil && !origin.executionReleased.Load() &&
			origin.callbackTransaction.Domain().CheckOpen() == nil {
			err := execute(origin.callbackTransaction)
			if err == nil {
				return
			}
			if !errors.Is(err, execution.ErrDomainTxClosed) {
				origin.setExecutionError(err)
				log.Errorf("命令的延迟汇报失败: %v", err)
				return
			}
		}
		err = d.WithDomainExecution(context.Background(), identity, canonical, execute)
		if err != nil {
			log.Errorf("命令的延迟汇报失败: %v", err)
		}
	}
}

func runDetachedReport(
	reportCtx *MsgContext,
	reportMsg *Message,
	speak func(reportCtx *MsgContext, reportMsg *Message),
) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("命令的延迟汇报异常: %v\n%s", recovered, debug.Stack())
		}
	}()
	if err = reportCtx.runStandaloneMessageScope(func() { speak(reportCtx, reportMsg) }); err != nil {
		return err
	}
	if err = reportCtx.getExecutionError(); err != nil {
		return err
	}
	return reportCtx.callbackTransaction.Domain().Err()
}

// detachReply is detach for the common case of sending one text back to the
// sender of msg.
func (ctx *MsgContext) detachReply(msg *Message) func(text string) {
	report := ctx.detach(msg)
	return func(text string) {
		report(func(reportCtx *MsgContext, reportMsg *Message) { ReplyToSender(reportCtx, reportMsg, text) })
	}
}
