package dice

import (
	"context"
	"encoding/json"
	"fmt"

	"Scardice-core/adapterapi"
	"Scardice-core/core/messageflow"
	"Scardice-core/endpoint"
	"Scardice-core/eventstore"
	"Scardice-core/logger"
)

// bindAdapterEventConversation resolves only existing canonical owners. A
// protocol event cannot manufacture a conversation merely to select hooks.
func (h *DurableCallbackHost) bindAdapterEventConversation(mctx *MsgContext, scope messageflow.CallbackScope) error {
	if h == nil || h.dice == nil || h.dice.ImSession == nil || mctx == nil {
		return messageflow.ErrCallbackUnavailable
	}
	if err := mctx.ResolveExistingDomainConversation(scope.GroupID, scope.UserID); err != nil {
		return err
	}
	mctx.IsCurGroupBotOn = mctx.MessageType == "group" && mctx.Group != nil && mctx.Group.IsActive(mctx)
	return nil
}

// HandleAdapterEvent gives an endpoint-only event its own durable invocation;
// it has no fabricated group/player and does not hold an execution-wide lock.
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
	request, err := json.Marshal(fenced)
	if err != nil {
		return adapterapi.IngressReceipt{}, err
	}
	invocation, err := (eventstore.UUIDGenerator{}).NewID()
	if err != nil {
		return adapterapi.IngressReceipt{}, err
	}
	dispatchErr := h.dice.WithDomainExecution(ctx, h.dice.DomainExecutionIdentity("adapter-event", invocation), request, func(transaction *DurableCallbackTransaction) error {
		if err := transaction.checkEndpointFence(transaction.executionContext, fenced.EndpointID, fenced.Generation, fenced.DesiredVersion); err != nil {
			return err
		}
		endpointInfo := compatibilityAdapterEventEndpoint(h.dice.ImSession, string(fenced.EndpointID))
		carrier := &MsgContext{
			Dice: h.dice, Session: h.dice.ImSession, EndPoint: endpointInfo,
			executionContext:    transaction.executionContext,
			callbackTransaction: transaction, callbackMetadata: transaction.metadata,
		}
		defer carrier.releaseExecutionState()
		if err := safeDispatchGlobalAdapterEvent(h.dice, carrier, fenced.Event, endpointInfo); err != nil {
			return err
		}
		return carrier.stopJSExecution()
	})
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
				return endpointInfo
			}
		}
	}
	return &EndPointInfo{EndPointInfoBase: EndPointInfoBase{
		ID: endpointID, Enable: true, State: StateConnected, Session: session,
	}}
}

var _ endpoint.AdapterEventSink = (*DurableCallbackHost)(nil)
