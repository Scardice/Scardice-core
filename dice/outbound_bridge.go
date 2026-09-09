package dice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/messageflow"
	"Scardice-core/eventstore"
	"Scardice-core/message"
)

type durableOutboundSubmitter interface {
	Submit(context.Context, messageflow.SubmitRequest) (messageflow.SubmitResult, error)
}

var ErrDurableOutboundUnsupported = errors.New("durable outbound: unsupported")

func isPureOnebotEndpoint(ep *EndPointInfo) bool {
	return ep != nil && ep.Platform == "QQ" && ep.ProtocolType == string(PureOnebotAdapterKey)
}

// OutboundBridgePort is the small Core seam used by reply helpers. It accepts
// an effect only after the durable outbound service has committed it.
type OutboundBridgePort interface {
	SubmitText(ctx *MsgContext, msg *Message, text, flag string, group bool) error
}

type durableOutboundActionPort interface {
	SubmitAction(ctx *MsgContext, payload adapterapi.EffectPayload) error
}

type outboundSuccessNotification struct {
	callbackCtx *MsgContext
	session     *IMSession
	msg         Message
	text        string
	flag        string
	group       bool
}

// submits them through messageflow. It intentionally has no provider access.
type DurableOutboundBridge struct {
	submitter durableOutboundSubmitter
	resolver  messageflow.EndpointResolver
	ids       messageflow.IDGenerator
	now       func() time.Time
	mu        sync.Mutex
	// submitMu fences pending registration/reconciliation against terminal
	// notifications. The notifier waits for Submit to reconcile the committed
	// effect ID before consuming the callback record.
	submitMu sync.Mutex
	pending  map[string]outboundSuccessNotification
}

func NewDurableOutboundBridge(submitter durableOutboundSubmitter, resolver messageflow.EndpointResolver, ids messageflow.IDGenerator) *DurableOutboundBridge {
	if ids == nil {
		ids = eventstore.UUIDGenerator{}
	}
	return &DurableOutboundBridge{submitter: submitter, resolver: resolver, ids: ids, now: func() time.Time { return time.Now().UTC() }, pending: make(map[string]outboundSuccessNotification)}
}

func (b *DurableOutboundBridge) SubmitText(ctx *MsgContext, msg *Message, text, flag string, group bool) error {
	if group {
		if msg == nil || msg.GroupID == "" {
			return ErrDurableOutboundUnsupported
		}
	} else if msg == nil || msg.Sender.UserID == "" {
		return ErrDurableOutboundUnsupported
	}
	if strings.TrimSpace(text) == "" || ctx == nil || ctx.EndPoint == nil {
		return ErrDurableOutboundUnsupported
	}
	target := adapterapi.EffectTarget{Kind: adapterapi.TargetPerson, Conversation: adapterapi.ConversationID(canonicalOnebotUserID(msg.Sender.UserID))}
	if group {
		target = adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: adapterapi.ConversationID(canonicalOnebotGroupID(msg.GroupID))}
	}
	if (group && ExtractQQEmitterGroupID(string(target.Conversation)) <= 0) || (!group && ExtractQQEmitterUserID(string(target.Conversation)) <= 0) {
		return ErrDurableOutboundUnsupported
	}
	payloadKind := adapterapi.EffectPayloadPersonText
	if group {
		payloadKind = adapterapi.EffectPayloadGroupText
	}
	return b.submit(ctx, msg, adapterapi.EffectPayload{Kind: payloadKind, Target: target, Text: text}, flag, group, text)
}

// SubmitSegments is reserved until the Core hook can snapshot outgoing
// segments for post-success notification. Rejecting here avoids reporting an
// incoming message as the successful outgoing content.
func (b *DurableOutboundBridge) SubmitSegments(_ *MsgContext, _ *Message, _ []message.IMessageElement, _ string, _ bool) error {
	return ErrDurableOutboundUnsupported
}

func (b *DurableOutboundBridge) SubmitAction(ctx *MsgContext, payload adapterapi.EffectPayload) error {
	if ctx == nil || ctx.EndPoint == nil || b == nil {
		return ErrDurableOutboundUnsupported
	}
	return b.submit(ctx, nil, payload, "", payload.Target.Kind == adapterapi.TargetGroup, "")
}

func (b *DurableOutboundBridge) submit(ctx *MsgContext, msg *Message, payload adapterapi.EffectPayload, flag string, group bool, text string) error {
	if b == nil || b.submitter == nil || b.resolver == nil || b.ids == nil || ctx == nil || ctx.EndPoint == nil {
		return ErrDurableOutboundUnsupported
	}
	endpointID, err := adapterapi.NewEndpointID(ctx.EndPoint.ID)
	if err != nil {
		return ErrDurableOutboundUnsupported
	}
	snapshot, err := b.resolver.Resolve(context.Background(), endpointID)
	if err != nil || snapshot.IndexSigner == nil || snapshot.IndexRootID == "" {
		return ErrDurableOutboundUnsupported
	}
	lane, err := adapterapi.NewLaneMetadataWithSigner(endpointID, payload.Target, 1, func(label string, covered []byte) ([]byte, error) {
		digest, keyID, signErr := snapshot.IndexSigner.KeyedDigest(context.Background(), label, string(covered))
		if signErr != nil || keyID != snapshot.IndexRootID {
			return nil, ErrDurableOutboundUnsupported
		}
		return digest, nil
	})
	if err != nil {
		return err
	}
	newID := func() (string, error) { return b.ids.NewID() }
	effectID, err := newID()
	if err != nil {
		return err
	}
	opID, err := newID()
	if err != nil {
		return err
	}
	commandID := durableOutboundCommandID(ctx, msg, payload, text, flag)
	correlation := durableOutboundRelatedID(commandID, "correlation")
	causation := durableOutboundRelatedID(commandID, "causation")
	kind := adapterapi.EffectKindMessage
	action := adapterapi.ActionKindSendMessage
	retry := adapterapi.EffectRetryNonIdempotent
	risk := adapterapi.EffectRiskNormal
	caps := adapterapi.CapabilityOutbound
	if payload.Kind == adapterapi.EffectPayloadSegments {
		caps |= adapterapi.CapabilityRichMessages
	} else if payload.Kind != adapterapi.EffectPayloadPersonText && payload.Kind != adapterapi.EffectPayloadGroupText {
		kind = adapterapi.EffectKindAction
		caps, action, retry, risk = actionContract(payload.Kind)
	}
	now := b.now().UTC()
	effect := adapterapi.OutboundEffect{Version: adapterapi.EffectVersionOne, ID: adapterapi.EffectID(effectID), EndpointID: endpointID, OperationID: adapterapi.OperationID(opID), CorrelationID: adapterapi.CorrelationID(correlation), CausationID: adapterapi.CausationID(causation), Lane: lane, Deadline: now.Add(5 * time.Minute), Risk: risk, RetryClass: retry, RequiredCapabilities: caps, RequiredAction: action, Kind: kind, Payload: payload}
	if err := effect.Validate(); err != nil {
		return err
	}
	principal := strings.TrimSpace(ctx.EndPoint.UserID)
	if principal == "" {
		principal = string(endpointID)
	}
	request := messageflow.SubmitRequest{Effect: effect, CommandID: commandID, PrincipalID: adapterapi.PrincipalID(principal)}
	notification := outboundSuccessNotification{}
	registered := false
	if msg != nil {
		notification = snapshotOutboundNotification(ctx, msg, text, flag, group)
		b.submitMu.Lock()
		b.mu.Lock()
		if _, exists := b.pending[effectID]; !exists {
			b.pending[effectID] = notification
			registered = true
		}
		b.mu.Unlock()
		defer b.submitMu.Unlock()
	}
	result, err := b.submitter.Submit(context.Background(), request)
	if err != nil {
		if msg != nil && registered {
			b.mu.Lock()
			delete(b.pending, effectID)
			b.mu.Unlock()
		}
		return err
	}
	id := result.EffectID
	if id == "" {
		id = effectID
	}
	if msg != nil && result.Deduplicated && id != effectID {
		b.mu.Lock()
		_, alreadyPending := b.pending[id]
		if registered {
			delete(b.pending, effectID)
		}
		b.mu.Unlock()
		if !alreadyPending {
			return nil
		}
	} else if msg != nil && !result.Deduplicated && id != effectID && registered {
		b.mu.Lock()
		if _, stillPending := b.pending[effectID]; stillPending {
			delete(b.pending, effectID)
			if _, alreadyPending := b.pending[id]; !alreadyPending {
				b.pending[id] = notification
			}
		}
		b.mu.Unlock()
	}
	if msg != nil && result.Deduplicated && id == effectID && registered {
		b.mu.Lock()
		delete(b.pending, effectID)
		b.mu.Unlock()
	}
	return nil
}
func durableOutboundCommandID(ctx *MsgContext, msg *Message, payload adapterapi.EffectPayload, text, flag string) string {
	type identity struct {
		EndpointID   string
		CommandID    int64
		Current      string
		RawMessageID string
		Target       adapterapi.EffectTarget
		Payload      adapterapi.EffectPayloadKind
		Text         string
		Flag         string
	}
	rawID := ""
	if msg != nil {
		rawID = fmt.Sprintf("%v", msg.RawID)
	}
	endpointID, commandID, current := "", int64(0), ""
	if ctx != nil {
		commandID, current = ctx.CommandID, ctx.CurrentCommand
		if ctx.EndPoint != nil {
			endpointID = ctx.EndPoint.ID
		}
	}
	encoded, _ := json.Marshal(identity{endpointID, commandID, current, rawID, payload.Target, payload.Kind, text, flag})
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
func durableOutboundRelatedID(commandID, relation string) string {
	sum := sha256.Sum256([]byte(relation + ":" + commandID))
	return hex.EncodeToString(sum[:])
}

func actionContract(kind adapterapi.EffectPayloadKind) (adapterapi.CapabilitySet, adapterapi.ActionKind, adapterapi.EffectRetryClass, adapterapi.EffectRisk) {
	switch kind {
	case adapterapi.EffectPayloadRecall:
		return adapterapi.CapabilityOutbound | adapterapi.CapabilityActions, adapterapi.ActionKindRecallMessage, adapterapi.EffectRetryProviderIdempotent, adapterapi.EffectRiskNormal
	case adapterapi.EffectPayloadSetGroupCard:
		return adapterapi.CapabilityOutbound | adapterapi.CapabilityActions, adapterapi.ActionKindSetGroupCard, adapterapi.EffectRetryNonIdempotent, adapterapi.EffectRiskHigh
	case adapterapi.EffectPayloadQuit:
		return adapterapi.CapabilityOutbound | adapterapi.CapabilityActions, adapterapi.ActionKindQuit, adapterapi.EffectRetryNonIdempotent, adapterapi.EffectRiskHigh
	case adapterapi.EffectPayloadBan:
		return adapterapi.CapabilityOutbound | adapterapi.CapabilityActions, adapterapi.ActionKindBan, adapterapi.EffectRetryNonIdempotent, adapterapi.EffectRiskHigh
	case adapterapi.EffectPayloadKick:
		return adapterapi.CapabilityOutbound | adapterapi.CapabilityActions, adapterapi.ActionKindKick, adapterapi.EffectRetryNonIdempotent, adapterapi.EffectRiskHigh
	case adapterapi.EffectPayloadGroupInfoRefresh:
		return adapterapi.CapabilityOutbound | adapterapi.CapabilityActions, adapterapi.ActionKindGroupInfoRefresh, adapterapi.EffectRetryProviderIdempotent, adapterapi.EffectRiskNormal
	case adapterapi.EffectPayloadEdit:
		return adapterapi.CapabilityOutbound | adapterapi.CapabilityActions, adapterapi.ActionKindEditMessage, adapterapi.EffectRetryProviderIdempotent, adapterapi.EffectRiskNormal
	default:
		return 0, 0, 0, 0
	}
}

// NotifyOutboundEffectResult is installed as the dispatcher's post-commit
// notifier. Every terminal outcome consumes the in-memory acceptance record;
// only a committed success schedules the user hook. Production dispatchers
// invoke this asynchronously, and submitMu fences it behind Submit's durable
// result reconciliation.
func (b *DurableOutboundBridge) NotifyOutboundEffectResult(_ context.Context, effect adapterapi.OutboundEffect, result adapterapi.EffectResult) {
	if b == nil {
		return
	}
	b.submitMu.Lock()
	defer b.submitMu.Unlock()
	b.mu.Lock()
	notification, ok := b.pending[string(effect.ID)]
	if ok {
		delete(b.pending, string(effect.ID))
	}
	b.mu.Unlock()
	if !ok || result.Outcome != adapterapi.EffectSucceeded || notification.session == nil {
		return
	}
	sent := notification.msg
	sent.Platform = "QQ"
	sent.Message = notification.text
	sent.RawID = result.ProviderID
	if notification.group {
		sent.MessageType = "group"
	} else {
		sent.MessageType = "private"
	}
	if notification.callbackCtx != nil && notification.callbackCtx.EndPoint != nil {
		sent.Sender = SenderBase{UserID: notification.callbackCtx.EndPoint.UserID, Nickname: notification.callbackCtx.EndPoint.Nickname}
	}
	callbackCtx := notification.callbackCtx
	session := notification.session
	flag := notification.flag
	go func() {
		defer func() { _ = recover() }()
		session.OnMessageSend(callbackCtx, &sent, flag)
	}()
}
func snapshotOutboundNotification(ctx *MsgContext, msg *Message, text, flag string, group bool) outboundSuccessNotification {
	session := ctx.Session
	if session == nil && ctx.EndPoint != nil {
		session = ctx.EndPoint.Session
	}
	endpoint := &EndPointInfo{}
	if ctx.EndPoint != nil {
		endpoint.EndPointInfoBase = EndPointInfoBase{
			ID: ctx.EndPoint.ID, Nickname: ctx.EndPoint.Nickname, UserID: ctx.EndPoint.UserID,
			Platform: ctx.EndPoint.Platform, ProtocolType: ctx.EndPoint.ProtocolType, Session: session,
		}
	}
	callbackCtx := &MsgContext{
		MessageType: ctx.MessageType, Group: ctx.Group, Player: ctx.Player,
		EndPoint: endpoint, Session: session, Dice: ctx.Dice,
		IsCurGroupBotOn: ctx.IsCurGroupBotOn, IsPrivate: ctx.IsPrivate,
		CommandID: ctx.CommandID, CurrentCommand: ctx.CurrentCommand,
		CommandHideFlag: ctx.CommandHideFlag, PrivilegeLevel: ctx.PrivilegeLevel,
		GroupRoleLevel: ctx.GroupRoleLevel,
	}
	return outboundSuccessNotification{callbackCtx: callbackCtx, session: session, msg: *msg, text: text, flag: flag, group: group}
}

// NotifyOutboundEffectSucceeded retains compatibility with the success-only
// dispatcher hook while sharing terminal cleanup with the all-outcome hook.
func (b *DurableOutboundBridge) NotifyOutboundEffectSucceeded(ctx context.Context, effect adapterapi.OutboundEffect, result adapterapi.EffectResult) {
	b.NotifyOutboundEffectResult(ctx, effect, result)
}
