package dice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"Scardice-core/adapterapi"
)

var ErrPureOnebotInboundUnavailable = errors.New("pureonebot inbound core is unavailable")

// ExecutePureOnebotInbound forwards the provider-neutral contract through the
// injected durable ingress seam. It never invokes a legacy Execute wrapper.
func (s *IMSession) ExecutePureOnebotInbound(ctx context.Context, ep *EndPointInfo, inbound adapterapi.InboundMessage) (adapterapi.IngressReceipt, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := inbound.Validate(); err != nil {
		return adapterapi.IngressReceipt{}, err
	}
	if s == nil || s.Parent == nil || ep == nil {
		return adapterapi.IngressReceipt{}, ErrPureOnebotInboundUnavailable
	}
	if inbound.Kind != adapterapi.InboundKindMessage {
		return adapterapi.IngressReceipt{Outcome: adapterapi.IngressRejected}, nil
	}
	executor := s.PureOnebotInboundExecutor
	if executor == nil {
		return adapterapi.IngressReceipt{}, ErrPureOnebotInboundUnavailable
	}
	receipt, err := executor.HandleInbound(ctx, inbound)
	if err != nil {
		return adapterapi.IngressReceipt{}, err
	}
	if err := receipt.Validate(); err != nil {
		return adapterapi.IngressReceipt{}, err
	}
	if (receipt.Outcome == adapterapi.IngressAccepted || receipt.Outcome == adapterapi.IngressDuplicate) && receipt.InboxID == "" {
		return adapterapi.IngressReceipt{}, fmt.Errorf("%w: durable receipt missing inbox id", adapterapi.ErrInvalidContract)
	}
	return receipt, nil
}

// NewPureOnebotReadEndpoint derives the minimal legacy EndPointInfo view
// required by compatibility ingress callers without attaching an adapter.
func NewPureOnebotReadEndpoint(id adapterapi.EndpointID, config adapterapi.ValidatedConfig) *EndPointInfo {
	var canonical OnebotConfig
	_ = json.Unmarshal(config.Canonical, &canonical)
	userID := strings.TrimSpace(canonical.AccountHint)
	if userID == "" {
		userID = string(id)
	}
	return &EndPointInfo{EndPointInfoBase: EndPointInfoBase{ID: string(id), UserID: userID, Platform: "QQ", ProtocolType: "pureonebot", Enable: true, State: StateConnected}}
}
