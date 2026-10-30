package dice

import (
	"context"
	"fmt"

	"Scardice-core/adapterapi"
	"Scardice-core/core/messageflow"
	"Scardice-core/endpoint"
	"Scardice-core/logger"
)

// bindAdapterEventConversation supplies the already-projected compatibility
// scope used to select extensions. It never creates a group or player.
func (h *DurableCallbackHost) bindAdapterEventConversation(mctx *MsgContext, scope messageflow.CallbackScope) {
	if h == nil || h.dice == nil || h.dice.ImSession == nil || mctx == nil {
		return
	}
	if mctx.Group == nil {
		mctx.Group, _ = h.dice.ImSession.ServiceAtNew.Load(scope.GroupID)
	}
	if mctx.Player == nil && mctx.Group != nil {
		mctx.Player, _ = mctx.Group.Players.Load(scope.UserID)
	}
	mctx.IsCurGroupBotOn = mctx.MessageType == "group" && mctx.Group != nil && mctx.Group.IsActive(mctx)
}

// HandleAdapterEvent delivers a conversation-free event without manufacturing
// compatibility group/player state. Admission serializes it with durable
// callbacks, while the worker context bounds every awaited JavaScript task.
func (h *DurableCallbackHost) HandleAdapterEvent(ctx context.Context, fenced endpoint.FencedAdapterEvent) (adapterapi.IngressReceipt, error) {
	if h == nil || h.dice == nil || h.dice.ImSession == nil {
		return adapterapi.IngressReceipt{}, messageflow.ErrCallbackUnavailable
	}
	if !fenced.EndpointID.Valid() || fenced.Generation == 0 || fenced.DesiredVersion == 0 {
		return adapterapi.IngressReceipt{}, fmt.Errorf("%w: invalid adapter event fence", adapterapi.ErrInvalidContract)
	}
	if err := fenced.Event.Validate(); err != nil {
		return adapterapi.IngressReceipt{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	callbackCtx, releaseAdmission, err := h.BeginCallback(ctx)
	if err != nil {
		return adapterapi.IngressReceipt{}, err
	}
	defer releaseAdmission()

	h.mu.Lock()
	defer h.mu.Unlock()
	if err := callbackCtx.Err(); err != nil {
		return adapterapi.IngressReceipt{}, err
	}

	endpointInfo := compatibilityAdapterEventEndpoint(h.dice.ImSession, string(fenced.EndpointID))
	carrier := &MsgContext{
		Dice: h.dice, Session: h.dice.ImSession, EndPoint: endpointInfo,
		executionContext: callbackCtx,
	}
	defer carrier.releaseExecutionState()
	dispatchErr := safeDispatchGlobalAdapterEvent(h.dice, carrier, fenced.Event, endpointInfo)
	if stopErr := carrier.stopJSExecution(); dispatchErr == nil {
		dispatchErr = stopErr
	}
	if dispatchErr != nil {
		log := h.dice.Logger
		if log == nil {
			log = logger.M()
		}
		log.Errorf("全局适配器事件回调失败: %v", dispatchErr)
		return adapterapi.IngressReceipt{Outcome: adapterapi.IngressRejected}, nil
	}
	return adapterapi.IngressReceipt{Outcome: adapterapi.IngressAccepted}, nil
}

func safeDispatchGlobalAdapterEvent(d *Dice, carrier *MsgContext, event adapterapi.AdapterEvent, endpointInfo *EndPointInfo) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("adapter event callback panic: %v", recovered)
		}
	}()
	return d.dispatchAdapterEvent(carrier, nil, event, endpointInfo)
}

func compatibilityAdapterEventEndpoint(session *IMSession, endpointID string) *EndPointInfo {
	if session != nil {
		for _, endpointInfo := range session.EndPointsReadOnly() {
			if endpointInfo != nil && endpointInfo.ID == endpointID {
				endpointInfo.Session = session
				return endpointInfo
			}
		}
	}
	return &EndPointInfo{EndPointInfoBase: EndPointInfoBase{
		ID: endpointID, Enable: true, State: StateConnected, Session: session,
	}}
}

var _ endpoint.AdapterEventSink = (*DurableCallbackHost)(nil)
