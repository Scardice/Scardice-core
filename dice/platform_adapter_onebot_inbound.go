package dice

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"Scardice-core/adapterapi"
)

var ErrPureOnebotInboundUnavailable = errors.New("pureonebot inbound core is unavailable")

func pureOnebotCoreMessage(ep *EndPointInfo, inbound adapterapi.InboundMessage) *Message {
	message := &Message{
		Time:        inbound.OccurredAt.Unix(),
		MessageType: "private",
		Message:     inbound.Text,
		Platform:    ep.Platform,
		Sender:      SenderBase{UserID: string(inbound.Sender)},
		RawID:       string(inbound.MessageID),
	}
	if message.Time <= 0 {
		message.Time = time.Now().Unix()
	}
	conversation := string(inbound.Conversation)
	if strings.HasPrefix(conversation, "QQ:group:") {
		message.GroupID = "QQ-Group:" + strings.TrimPrefix(conversation, "QQ:group:")
		message.MessageType = "group"
		message.GroupName = message.GroupID
	}
	if inbound.MessageID != "" {
		message.RawID = string(inbound.MessageID)
	}
	if message.Message == "" && len(inbound.Segments) > 0 {
		for _, segment := range inbound.Segments {
			if segment.Text != "" {
				message.Message += segment.Text
			}
		}
	}
	return message
}

// ExecutePureOnebotInbound forwards the provider-neutral contract through the
// injected durable ingress seam. It never invokes a legacy Execute wrapper.
func (s *IMSession) ExecutePureOnebotInbound(ctx context.Context, ep *EndPointInfo, inbound adapterapi.InboundMessage) (adapterapi.IngressReceipt, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := inbound.Validate(); err != nil {
		return adapterapi.IngressReceipt{}, err
	}
	if s == nil || s.Parent == nil || ep == nil || !inbound.ProviderEventID.Valid() {
		return adapterapi.IngressReceipt{}, ErrPureOnebotInboundUnavailable
	}
	if inbound.Kind != adapterapi.InboundKindMessage {
		return adapterapi.IngressReceipt{Outcome: adapterapi.IngressRejected, InboxID: string(inbound.ProviderEventID)}, nil
	}
	executor := s.PureOnebotInboundExecutor
	if executor == nil {
		return adapterapi.IngressReceipt{}, ErrPureOnebotInboundUnavailable
	}
	receipt, err := executor.HandleInbound(ctx, inbound)
	if err != nil {
		return adapterapi.IngressReceipt{}, err
	}
	if receipt.InboxID == "" {
		receipt.InboxID = string(inbound.ProviderEventID)
	}
	if err := receipt.Validate(); err != nil {
		return adapterapi.IngressReceipt{}, err
	}
	return receipt, nil
}

// NewPureOnebotReadEndpoint derives the minimal legacy EndPointInfo view
// required by ExecuteNew from the endpoint projection. It does not attach an
// adapter or mutate IMSession.EndPoints.
func NewPureOnebotReadEndpoint(id adapterapi.EndpointID, config adapterapi.ValidatedConfig) *EndPointInfo {
	var canonical OnebotConfig
	_ = json.Unmarshal(config.Canonical, &canonical)
	userID := strings.TrimSpace(canonical.AccountHint)
	if userID == "" {
		userID = string(id)
	}
	return &EndPointInfo{EndPointInfoBase: EndPointInfoBase{ID: string(id), UserID: userID, Platform: "QQ", ProtocolType: "pureonebot", Enable: true, State: StateConnected}}
}
