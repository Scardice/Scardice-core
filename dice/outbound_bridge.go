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
	"Scardice-core/logger"
	"Scardice-core/message"
)

type durableOutboundSubmitter interface {
	Submit(ctx context.Context, request messageflow.SubmitRequest) (messageflow.SubmitResult, error)
}

type durableOutboundPreparer interface {
	Prepare(ctx context.Context, request messageflow.SubmitRequest) (messageflow.PreparedOutbound, error)
}

type durableOutboundIDAllocator func() (string, error)

var ErrDurableOutboundUnsupported = errors.New("durable outbound: unsupported")

// AdapterAPIOperation is the synchronous durable-admission result exposed to
// plugin hosts. Staged operations exist only in the current callback collector.
type AdapterAPIOperation struct {
	ID     string `jsbind:"id" json:"id"`
	Status string `jsbind:"status" json:"status"`
}

func isPureOnebotEndpoint(ep *EndPointInfo) bool {
	return ep != nil && ep.Platform == "QQ" && ep.ProtocolType == string(PureOnebotAdapterKey)
}

// OutboundBridgePort is the small Core seam used by reply helpers. It accepts
// an effect only after the durable outbound service has committed it.
type OutboundBridgePort interface {
	SubmitText(ctx *MsgContext, msg *Message, text, flag string, group bool) error
}

type durableOutboundForwardPort interface {
	submitForward(ctx *MsgContext, msg *Message, nodes []message.ForwardNode, flag string, group bool) error
}

type durableOutboundActionPort interface {
	SubmitAction(ctx *MsgContext, payload adapterapi.EffectPayload) error
}

// FailClosedOutboundBridge prevents event-sourced endpoints from bypassing
// the outbox while the production bridge is still being assembled.
type FailClosedOutboundBridge struct{}

func NewFailClosedOutboundBridge() *FailClosedOutboundBridge {
	return &FailClosedOutboundBridge{}
}

func (*FailClosedOutboundBridge) SubmitText(*MsgContext, *Message, string, string, bool) error {
	return ErrDurableOutboundUnsupported
}

func (*FailClosedOutboundBridge) SubmitAction(*MsgContext, adapterapi.EffectPayload) error {
	return ErrDurableOutboundUnsupported
}

type outboundSuccessNotification struct {
	dice     *Dice
	session  *IMSession
	endpoint *EndPointInfo

	sourceGroupID    string
	sourcePlayerID   string
	expectedEndpoint adapterapi.EndpointID
	expectedTarget   adapterapi.EffectTarget
	expectedKind     adapterapi.EffectPayloadKind
	messageType      string

	msg   Message
	text  string
	flag  string
	group bool

	isCurGroupBotOn bool
	isPrivate       bool
	commandID       int64
	currentCommand  string
	commandHideFlag string
	privilegeLevel  int
	groupRoleLevel  int
	logReplyTime    int64
	logReplySeq     int64
	skipLogArchive  bool
}

// OutboundNotificationOwner admits completion work under a runtime lifetime.
// Its shutdown boundary must cancel and join every admitted function.
type OutboundNotificationOwner interface {
	Go(run func(ctx context.Context)) bool
}

const outboundSuccessNotificationTimeout = 30 * time.Second

// submits them through messageflow. It intentionally has no provider access.
type DurableOutboundBridge struct {
	notifications OutboundNotificationOwner
	submitter     durableOutboundSubmitter
	resolver      messageflow.EndpointResolver
	ids           messageflow.IDGenerator
	now           func() time.Time
	mu            sync.Mutex
	// submitMu fences pending registration/reconciliation against terminal
	// notifications. The notifier waits for Submit to reconcile the committed
	// effect ID before consuming the callback record.
	submitMu sync.Mutex
	pending  map[string]outboundSuccessNotification
}

func NewDurableOutboundBridge(submitter durableOutboundSubmitter, resolver messageflow.EndpointResolver, ids messageflow.IDGenerator, notifications OutboundNotificationOwner) *DurableOutboundBridge {
	if ids == nil {
		ids = eventstore.UUIDGenerator{}
	}
	return &DurableOutboundBridge{
		notifications: notifications, submitter: submitter, resolver: resolver, ids: ids,
		now: func() time.Time { return time.Now().UTC() }, pending: make(map[string]outboundSuccessNotification),
	}
}

func (b *DurableOutboundBridge) SubmitText(ctx *MsgContext, msg *Message, text, flag string, group bool) error {
	return b.submitText(context.Background(), ctx, msg, text, flag, group, nil)
}

func (b *DurableOutboundBridge) submitText(requestCtx context.Context, ctx *MsgContext, msg *Message, text, flag string, group bool, ids durableOutboundIDAllocator) error {
	if group {
		if msg == nil || strings.TrimSpace(msg.GroupID) == "" {
			return ErrDurableOutboundUnsupported
		}
	} else if msg == nil || strings.TrimSpace(msg.Sender.UserID) == "" {
		return ErrDurableOutboundUnsupported
	}
	if strings.TrimSpace(text) == "" || ctx == nil || ctx.EndPoint == nil {
		return ErrDurableOutboundUnsupported
	}
	endpointID, snapshot, err := b.resolveEndpoint(requestCtx, ctx)
	if err != nil {
		return err
	}
	target, err := outboundTextTarget(snapshot.AdapterKey, ctx.EndPoint, msg, group)
	if err != nil {
		return err
	}
	payloadKind := adapterapi.EffectPayloadPersonText
	if group {
		payloadKind = adapterapi.EffectPayloadGroupText
	}
	return b.submitResolved(requestCtx, ctx, msg, adapterapi.EffectPayload{Kind: payloadKind, Target: target, Text: text}, flag, group, text, endpointID, ids, nil)
}

func (b *DurableOutboundBridge) submitForward(ctx *MsgContext, msg *Message, nodes []message.ForwardNode, flag string, group bool) error {
	if b == nil || ctx == nil || ctx.EndPoint == nil || len(nodes) == 0 {
		return ErrDurableOutboundUnsupported
	}
	payloadNodes := durableForwardPayloadNodes(nodes)
	if len(payloadNodes) == 0 {
		return ErrDurableOutboundUnsupported
	}
	requestCtx := context.Background()
	endpointID, snapshot, err := b.resolveEndpoint(requestCtx, ctx)
	if err != nil {
		return err
	}
	target, err := outboundTextTarget(snapshot.AdapterKey, ctx.EndPoint, msg, group)
	if err != nil {
		return err
	}
	payload := adapterapi.EffectPayload{
		Kind:         adapterapi.EffectPayloadForward,
		Target:       target,
		ForwardNodes: payloadNodes,
	}
	return b.submitResolved(requestCtx, ctx, msg, payload, flag, group, forwardNodesToText(nodes), endpointID, nil, nil)
}

func outboundTextTarget(adapterKey adapterapi.AdapterKey, endpoint *EndPointInfo, msg *Message, group bool) (adapterapi.EffectTarget, error) {
	if msg == nil {
		return adapterapi.EffectTarget{}, ErrDurableOutboundUnsupported
	}
	if adapterKey == "" && endpoint != nil {
		adapterKey = adapterapi.AdapterKey(strings.TrimSpace(endpoint.ProtocolType))
	}
	conversation := strings.TrimSpace(msg.Sender.UserID)
	kind := adapterapi.TargetPerson
	if group {
		conversation = strings.TrimSpace(msg.GroupID)
		kind = adapterapi.TargetGroup
	}
	switch adapterKey {
	case OnebotAdapterKey, GocqAdapterKey, LagrangeAdapterKey, WalleQAdapterKey, RedAdapterKey, MilkyAdapterKey:
		if group {
			conversation = canonicalOnebotGroupID(conversation)
			if ExtractQQEmitterGroupID(conversation) <= 0 {
				return adapterapi.EffectTarget{}, ErrDurableOutboundUnsupported
			}
		} else {
			conversation = canonicalOnebotUserID(conversation)
			if ExtractQQEmitterUserID(conversation) <= 0 {
				return adapterapi.EffectTarget{}, ErrDurableOutboundUnsupported
			}
		}
	}
	target := adapterapi.EffectTarget{Kind: kind, Conversation: adapterapi.ConversationID(conversation)}
	if err := target.Validate(); err != nil {
		return adapterapi.EffectTarget{}, ErrDurableOutboundUnsupported
	}
	return target, nil
}

// SubmitSegments is reserved until the Core hook can snapshot outgoing
// segments for post-success notification. Rejecting here avoids reporting an
// incoming message as the successful outgoing content.
func (b *DurableOutboundBridge) SubmitSegments(_ *MsgContext, _ *Message, _ []message.IMessageElement, _ string, _ bool) error {
	return ErrDurableOutboundUnsupported
}

func (b *DurableOutboundBridge) SubmitAction(ctx *MsgContext, payload adapterapi.EffectPayload) error {
	return b.submitAction(context.Background(), ctx, payload, nil)
}

func (b *DurableOutboundBridge) submitAction(requestCtx context.Context, ctx *MsgContext, payload adapterapi.EffectPayload, ids durableOutboundIDAllocator) error {
	if ctx == nil || ctx.EndPoint == nil || b == nil {
		return ErrDurableOutboundUnsupported
	}
	return b.submit(requestCtx, ctx, nil, payload, "", payload.Target.Kind == adapterapi.TargetGroup, "", ids)
}

func (b *DurableOutboundBridge) submit(requestCtx context.Context, ctx *MsgContext, msg *Message, payload adapterapi.EffectPayload, flag string, group bool, text string, ids durableOutboundIDAllocator) error {
	endpointID, _, err := b.resolveEndpoint(requestCtx, ctx)
	if err != nil {
		return err
	}
	return b.submitResolved(requestCtx, ctx, msg, payload, flag, group, text, endpointID, ids, nil)
}

func (b *DurableOutboundBridge) resolveEndpoint(requestCtx context.Context, ctx *MsgContext) (adapterapi.EndpointID, messageflow.EndpointSnapshot, error) {
	if ctx == nil || ctx.EndPoint == nil {
		return "", messageflow.EndpointSnapshot{}, ErrDurableOutboundUnsupported
	}
	endpointID, err := adapterapi.NewEndpointID(ctx.EndPoint.ID)
	if err != nil {
		return "", messageflow.EndpointSnapshot{}, ErrDurableOutboundUnsupported
	}
	return b.resolveExplicitEndpoint(requestCtx, ctx, endpointID)
}

func (b *DurableOutboundBridge) resolveExplicitEndpoint(requestCtx context.Context, ctx *MsgContext, endpointID adapterapi.EndpointID) (adapterapi.EndpointID, messageflow.EndpointSnapshot, error) {
	if requestCtx == nil || b == nil || b.submitter == nil || b.resolver == nil || b.ids == nil || !endpointID.Valid() {
		return "", messageflow.EndpointSnapshot{}, ErrDurableOutboundUnsupported
	}
	if ctx != nil {
		if err := ctx.checkExecution(); err != nil {
			return "", messageflow.EndpointSnapshot{}, err
		}
	}
	if err := requestCtx.Err(); err != nil {
		return "", messageflow.EndpointSnapshot{}, err
	}
	snapshot, err := b.resolver.Resolve(requestCtx, endpointID)
	if err != nil {
		return "", messageflow.EndpointSnapshot{}, err
	}
	if snapshot.EndpointID != endpointID {
		return "", messageflow.EndpointSnapshot{}, ErrDurableOutboundUnsupported
	}
	return endpointID, snapshot, nil
}

// EnqueueAdapterAPI durably admits an exact native adapter request. Callback
// invocations stage into their existing collector; standalone calls commit the
// same durable Prepare/Submit shape immediately.
func (b *DurableOutboundBridge) EnqueueAdapterAPI(requestCtx context.Context, ctx *MsgContext, endpointID adapterapi.EndpointID, rawJSON string) (AdapterAPIOperation, error) {
	if err := adapterapi.ValidateProtocolJSON(rawJSON); err != nil {
		return AdapterAPIOperation{}, err
	}
	endpointID, _, err := b.resolveExplicitEndpoint(requestCtx, ctx, endpointID)
	if err != nil {
		return AdapterAPIOperation{}, err
	}
	result := messageflow.SubmitResult{}
	err = b.submitResolved(
		requestCtx,
		ctx,
		nil,
		adapterapi.EffectPayload{
			Kind:        adapterapi.EffectPayloadAdapterAPI,
			Target:      adapterapi.EffectTarget{Kind: adapterapi.TargetRaw, Raw: "adapter-api"},
			RequestJSON: rawJSON,
		},
		"",
		false,
		"",
		endpointID,
		nil,
		&result,
	)
	if err != nil {
		return AdapterAPIOperation{}, err
	}
	if !adapterapi.OperationID(result.OperationID).Valid() {
		return AdapterAPIOperation{}, ErrDurableOutboundUnsupported
	}
	operation := AdapterAPIOperation{ID: result.OperationID, Status: "pending"}
	if staged, ok := b.StagedAdapterAPIOperation(ctx, result.OperationID); ok {
		return staged, nil
	}
	return operation, nil
}

// StagedAdapterAPIOperation resolves only operations owned by the caller's
// current callback collector. Committed operation lookup remains store-backed.
func (*DurableOutboundBridge) StagedAdapterAPIOperation(ctx *MsgContext, operationID string) (AdapterAPIOperation, bool) {
	if ctx == nil || ctx.callbackTransaction == nil || ctx.callbackTransaction.collector == nil ||
		!ctx.callbackTransaction.collector.HasPreparedOutboundOperation(operationID) {
		return AdapterAPIOperation{}, false
	}
	return AdapterAPIOperation{ID: operationID, Status: "staged"}, true
}

func (b *DurableOutboundBridge) submitResolved(
	requestCtx context.Context,
	ctx *MsgContext,
	msg *Message,
	payload adapterapi.EffectPayload,
	flag string,
	group bool,
	text string,
	endpointID adapterapi.EndpointID,
	newID durableOutboundIDAllocator,
	resultOut *messageflow.SubmitResult,
) error {
	if requestCtx == nil {
		return ErrDurableOutboundUnsupported
	}
	if err := requestCtx.Err(); err != nil {
		return err
	}
	switch payload.Kind {
	case adapterapi.EffectPayloadAdapterAPI:
		if ctx == nil || ctx.Dice == nil {
			return ErrDurableOutboundUnsupported
		}
		if err := adapterapi.ValidateProtocolJSON(payload.RequestJSON); err != nil {
			return err
		}
		if err := ctx.Dice.checkAdapterOutboundCensor(ctx, payload.RequestJSON); err != nil {
			return err
		}
	case adapterapi.EffectPayloadForward:
		if ctx == nil || ctx.Dice == nil {
			return ErrDurableOutboundUnsupported
		}
		requestJSON, err := onebotForwardRequestJSON(payload)
		if err != nil {
			return err
		}
		if err := ctx.Dice.checkAdapterOutboundCensor(ctx, string(requestJSON)); err != nil {
			return err
		}
	default:
		// Typed payloads have no raw protocol request to pass through the censor.
	}
	lane, err := adapterapi.NewLaneMetadata(endpointID, payload.Target, 1)
	if err != nil {
		return err
	}
	if newID == nil {
		newID = b.ids.NewID
	}
	effectID, err := newID()
	if err != nil {
		return err
	}
	opID, err := newID()
	if err != nil {
		return err
	}
	// Each invocation is a new emission, even when its payload is identical.
	// Retrying an already prepared request retains this effect-bound identity.
	commandID := durableOutboundRelatedID(effectID, "emission")
	if payload.Kind == adapterapi.EffectPayloadGroupInfoRefresh {
		commandID = durableGroupInfoRefreshCommandID(ctx, effectID, payload)
	}
	correlation := durableOutboundRelatedID(commandID, "correlation")
	causation := durableOutboundRelatedID(commandID, "causation")
	kind := adapterapi.EffectKindMessage
	action := adapterapi.ActionKindSendMessage
	retry := adapterapi.EffectRetryNonIdempotent
	risk := adapterapi.EffectRiskNormal
	caps := adapterapi.CapabilityOutbound
	if payload.Kind == adapterapi.EffectPayloadSegments || payload.Kind == adapterapi.EffectPayloadForward {
		caps |= adapterapi.CapabilityRichMessages
	} else if payload.Kind != adapterapi.EffectPayloadPersonText && payload.Kind != adapterapi.EffectPayloadGroupText {
		kind = adapterapi.EffectKindAction
		caps, action, retry, risk = actionContract(payload.Kind)
	}
	now := b.now().UTC()
	effect := adapterapi.OutboundEffect{Version: adapterapi.EffectVersionOne, ID: adapterapi.EffectID(effectID), EndpointID: endpointID, OperationID: adapterapi.OperationID(opID), CorrelationID: adapterapi.CorrelationID(correlation), CausationID: adapterapi.CausationID(causation), Lane: lane, Deadline: now.Add(5 * time.Minute), Risk: risk, RetryClass: retry, RequiredCapabilities: caps, RequiredAction: action, Kind: kind, Payload: payload}
	if ctx != nil {
		if delay := ctx.outboundDelay; delay > 0 {
			// Keep the delayed effect well inside its deadline so a long delay can
			// never turn into an expired send.
			if limit := effect.Deadline.Sub(now) / 2; delay > limit {
				delay = limit
			}
			effect.NotBefore = now.Add(delay)
		}
	}
	if validateErr := effect.Validate(); validateErr != nil {
		return validateErr
	}
	principal := ""
	if ctx != nil && ctx.EndPoint != nil {
		principal = strings.TrimSpace(ctx.EndPoint.UserID)
	}
	if principal == "" {
		principal = string(endpointID)
	}
	request := messageflow.SubmitRequest{Effect: effect, CommandID: commandID, PrincipalID: adapterapi.PrincipalID(principal)}
	if ctx != nil && ctx.callbackTransaction != nil {
		preparer, ok := b.submitter.(durableOutboundPreparer)
		if !ok {
			return ErrDurableOutboundUnsupported
		}
		prepared, err := preparer.Prepare(requestCtx, request)
		if err != nil {
			return fmt.Errorf("prepare outbound effect: %w", err)
		}
		if resultOut != nil {
			*resultOut = prepared.Result
		}
		if prepared.Result.Deduplicated {
			return nil
		}
		effectID := prepared.Work.Effects[0].EffectID
		var notification outboundSuccessNotification
		if msg != nil {
			notification = snapshotOutboundNotification(ctx, msg, text, flag, group)
			notification.expectedEndpoint, notification.expectedTarget, notification.expectedKind = endpointID, payload.Target, payload.Kind
		}
		intentUpdate, hasIntent, err := outboundStoryLogIntentUpdate(ctx, msg, payload, text, effectID, b.now())
		if err != nil {
			return fmt.Errorf("story log intent: %w", err)
		}
		if hasIntent {
			if err := ctx.callbackTransaction.collector.AddPreparedOutboundWithLog(prepared.OwnedWork(), intentUpdate); err != nil {
				return fmt.Errorf("stage outbound effect with log intent: %w", err)
			}
			if notification.dice != nil {
				notification.skipLogArchive = true
			}
		} else if err := ctx.callbackTransaction.collector.AddPreparedOutbound(prepared.OwnedWork()); err != nil {
			return fmt.Errorf("stage outbound effect: %w", err)
		}
		if msg != nil {
			ctx.callbackTransaction.callbackCommitFence = &b.submitMu
			if err := ctx.callbackTransaction.AfterCommitPublication(func() {
				b.mu.Lock()
				if _, exists := b.pending[effectID]; !exists {
					b.pending[effectID] = notification
				}
				b.mu.Unlock()
			}); err != nil {
				return fmt.Errorf("register outbound completion: %w", err)
			}
		}
		return nil
	}
	notification := outboundSuccessNotification{}
	registered := false
	if msg != nil {
		notification = snapshotOutboundNotification(ctx, msg, text, flag, group)
		notification.expectedEndpoint, notification.expectedTarget, notification.expectedKind = endpointID, payload.Target, payload.Kind
		b.submitMu.Lock()
		b.mu.Lock()
		if _, exists := b.pending[effectID]; !exists {
			b.pending[effectID] = notification
			registered = true
		}
		b.mu.Unlock()
		defer b.submitMu.Unlock()
	}
	result, err := b.submitter.Submit(requestCtx, request)
	if err != nil {
		if msg != nil && registered {
			b.mu.Lock()
			delete(b.pending, effectID)
			b.mu.Unlock()
		}
		return err
	}
	if resultOut != nil {
		*resultOut = result
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

func prepareStandaloneGroupFarewell(ctx *MsgContext, msg *Message, text string) string {
	if ctx == nil || ctx.Dice == nil || msg == nil {
		return ""
	}
	d := ctx.Dice
	visibleText := visibleReplyText(ctx, text)
	d.Logger.Infof("发给(群%s): %s", msg.GroupID, visibleText)
	config := d.Config()
	if config != nil && config.EnableCensor && config.CensorMode == OnlyOutputReply {
		checkText := sealCodeRe.ReplaceAllString(visibleText, "")
		checkText = cqCodeRe.ReplaceAllString(checkText, "")
		hit, words, terminate, _ := d.CensorMsg(ctx, msg, checkText, text)
		if terminate {
			return ""
		}
		if hit {
			d.Logger.Infof(
				"拒绝回复命中敏感词「%s」的内容「%s」，原消息「%s」- 来自群(%s)内<%s>(%s)",
				strings.Join(words, "|"),
				text, msg.Message,
				msg.GroupID,
				msg.Sender.Nickname,
				msg.Sender.UserID,
			)
			text = DiceFormatTmpl(ctx, "核心:拦截_完全拦截_发出的消息")
		}
	}
	if lenWithoutBase64(text) > 15000 {
		text = "要发送的文本过长"
	}
	return strings.TrimSpace(text)
}

func standaloneGroupFarewellParts(ctx *MsgContext, text string) []string {
	parts := make([]string, 0, 1)
	for _, item := range ctx.compileReplyPlan(text) {
		if item.Forward {
			part := strings.TrimSpace(stripForwardSplitMarkers(item.Text, ctx.getSplitKey()))
			if part != "" {
				parts = append(parts, part)
			}
			continue
		}
		for _, part := range ctx.SplitText(item.Text) {
			if part = strings.TrimSpace(part); part != "" {
				parts = append(parts, part)
			}
		}
	}
	return parts
}

// SubmitDurableGroupQuit atomically stages an optional farewell, endpoint
// membership removal, and the provider quit action. An active callback keeps
// its root; an independent management invocation receives a durable root.
func SubmitDurableGroupQuit(requestCtx context.Context, mctx *MsgContext, groupID, farewell string) error {
	if requestCtx == nil || mctx == nil || mctx.Dice == nil || mctx.EndPoint == nil ||
		mctx.Session == nil || mctx.Dice.DurableStore == nil || strings.TrimSpace(groupID) == "" {
		return adapterapi.ErrInvalidContract
	}
	if err := requestCtx.Err(); err != nil {
		return err
	}
	if err := mctx.checkExecution(); err != nil {
		return err
	}
	bridge, ok := mctx.Dice.OutboundBridge.(*DurableOutboundBridge)
	if !ok || bridge == nil {
		return ErrDurableOutboundUnsupported
	}
	groupID = strings.TrimSpace(groupID)
	stage := func(transaction *DurableCallbackTransaction) error {
		return bridge.stageDurableGroupQuit(requestCtx, mctx, transaction, groupID, farewell)
	}
	if transaction := mctx.callbackTransaction; transaction != nil {
		return stage(transaction)
	}
	if mctx.CommandID <= 0 {
		return adapterapi.ErrInvalidContract
	}
	canonical, err := json.Marshal(struct {
		EndpointID string `json:"endpointId"`
		GroupID    string `json:"groupId"`
		Farewell   string `json:"farewell,omitempty"`
		CommandID  int64  `json:"commandId"`
		Command    string `json:"command,omitempty"`
	}{
		EndpointID: mctx.EndPoint.ID, GroupID: groupID, Farewell: farewell,
		CommandID: mctx.CommandID, Command: strings.TrimSpace(mctx.CurrentCommand),
	})
	if err != nil {
		return err
	}
	invocation := fmt.Sprintf("%s:%s:%d:%s", mctx.EndPoint.ID, groupID, mctx.CommandID, strings.TrimSpace(mctx.CurrentCommand))
	identity := mctx.Dice.DomainExecutionIdentity("standalone-group-quit", invocation)
	return mctx.Dice.WithDomainExecution(requestCtx, identity, canonical, stage)
}

func (b *DurableOutboundBridge) stageDurableGroupQuit(
	requestCtx context.Context,
	source *MsgContext,
	transaction *DurableCallbackTransaction,
	groupID, farewell string,
) error {
	if transaction == nil || transaction.Domain() == nil {
		return ErrDomainExecutionUnavailable
	}
	staged := &MsgContext{
		MessageType: "group", Dice: source.Dice, Session: source.Session, EndPoint: source.EndPoint,
		IsCurGroupBotOn: source.IsCurGroupBotOn, IsPrivate: false,
		CommandID: source.CommandID, CurrentCommand: source.CurrentCommand,
		CommandHideFlag: source.CommandHideFlag, PrivilegeLevel: source.PrivilegeLevel,
		GroupRoleLevel: source.GroupRoleLevel, DelegateText: source.DelegateText,
		callbackTransaction: transaction, callbackMetadata: transaction.metadata,
		executionContext: transaction.executionContext,
	}
	staged.SetSplitKey(source.getSplitKey())
	sourcePlayerID := ""
	if source.Group != nil && source.Group.GroupID() == groupID && source.Player != nil {
		sourcePlayerID = source.Player.UserID()
	}
	if err := staged.ResolveExistingDomainConversation(groupID, sourcePlayerID); err != nil {
		return err
	}
	if staged.Group == nil {
		return fmt.Errorf("group %s does not exist", groupID)
	}
	msg := &Message{
		MessageType: "group", GroupID: groupID,
		Sender: SenderBase{UserID: source.EndPoint.UserID, Nickname: source.EndPoint.Nickname},
	}
	endpointID, snapshot, err := b.resolveEndpoint(requestCtx, staged)
	if err != nil {
		return err
	}
	target, err := outboundTextTarget(snapshot.AdapterKey, staged.EndPoint, msg, true)
	if err != nil {
		return err
	}
	var farewellParts []string
	if farewell != "" {
		if prepared := prepareStandaloneGroupFarewell(staged, msg, farewell); prepared != "" {
			farewellParts = standaloneGroupFarewellParts(staged, prepared)
		}
	}
	effectBase, err := b.ids.NewID()
	if err != nil {
		return err
	}
	operationBase, err := b.ids.NewID()
	if err != nil {
		return err
	}
	var idIndex uint64
	nextID := func() (string, error) {
		base := effectBase
		if idIndex%2 == 1 {
			base = operationBase
		}
		id := fmt.Sprintf("%s-%016x", base, idIndex/2)
		idIndex++
		return id, nil
	}
	identityBase := strings.TrimSpace(staged.CurrentCommand)
	if identityBase == "" {
		identityBase = fmt.Sprintf("standalone-group-quit:%d", staged.CommandID)
	}
	for index, part := range farewellParts {
		staged.CurrentCommand = fmt.Sprintf("%s:farewell:%016x", identityBase, index)
		if err = b.submitResolved(requestCtx, staged, msg, adapterapi.EffectPayload{
			Kind: adapterapi.EffectPayloadGroupText, Target: target, Text: part,
		}, "", true, part, endpointID, nextID, nil); err != nil {
			return err
		}
	}
	staged.CurrentCommand = identityBase + ":quit"
	if err = b.submitResolved(requestCtx, staged, nil, adapterapi.EffectPayload{
		Kind: adapterapi.EffectPayloadQuit, Target: target,
	}, "", true, "", endpointID, nextID, nil); err != nil {
		return err
	}
	if err := staged.Group.SetActivation(staged.EndPoint.UserID, false, false); err != nil {
		return err
	}
	return transaction.Domain().Err()
}

func outboundStoryLogIntentUpdate(ctx *MsgContext, msg *Message, payload adapterapi.EffectPayload, text, effectID string, createdAt time.Time) (eventstore.LogUpdate, bool, error) {
	if ctx == nil || ctx.Dice == nil || ctx.Group == nil {
		return eventstore.LogUpdate{}, false, nil
	}
	privateHiddenReply := (payload.Kind == adapterapi.EffectPayloadPersonText || payload.Kind == adapterapi.EffectPayloadForward) &&
		payload.Target.Kind == adapterapi.TargetPerson && ctx.CommandHideFlag != ""
	groupReply := (payload.Kind == adapterapi.EffectPayloadGroupText || payload.Kind == adapterapi.EffectPayloadForward) &&
		payload.Target.Kind == adapterapi.TargetGroup
	if !privateHiddenReply && !groupReply {
		return eventstore.LogUpdate{}, false, nil
	}
	groupID := ctx.Group.GroupID()
	if msg == nil {
		return eventstore.LogUpdate{}, false, ErrDurableOutboundUnsupported
	}
	if canonicalOnebotGroupID(msg.GroupID) != canonicalOnebotGroupID(groupID) {
		if groupReply && msg.MessageType == "group" &&
			strings.TrimSpace(payload.Target.Conversation.String()) == strings.TrimSpace(msg.GroupID) {
			// A send to another group is not part of this group's story log.
			return eventstore.LogUpdate{}, false, nil
		}
		return eventstore.LogUpdate{}, false, ErrDurableOutboundUnsupported
	}
	if privateHiddenReply {
		if msg.MessageType != "group" ||
			canonicalOnebotGroupID(ctx.CommandHideFlag) != canonicalOnebotGroupID(groupID) ||
			strings.TrimSpace(payload.Target.Conversation.String()) != strings.TrimSpace(msg.Sender.UserID) {
			return eventstore.LogUpdate{}, false, ErrDurableOutboundUnsupported
		}
	} else if strings.TrimSpace(payload.Target.Conversation.String()) != strings.TrimSpace(msg.GroupID) {
		return eventstore.LogUpdate{}, false, ErrDurableOutboundUnsupported
	}
	if ctx.callbackTransaction == nil || !ctx.callbackTransaction.HasStoryLogStateUpdate(ctx.Dice.BaseConfig.Name, groupID) {
		if _, err := loadGroupLogState(ctx, ctx.Group); err != nil {
			return eventstore.LogUpdate{}, false, err
		}
	}
	state, err := ctx.Group.GetLogState()
	if err != nil {
		return eventstore.LogUpdate{}, false, err
	}
	if !state.On || state.Name == "" {
		return eventstore.LogUpdate{}, false, nil
	}
	repository := logRepositoryForDice(ctx.Dice)
	if repository == nil {
		return eventstore.LogUpdate{}, false, ErrDurableOutboundUnsupported
	}
	commandInfo, err := storyLogCommandInfo(ctx.CommandInfo)
	if err != nil {
		return eventstore.LogUpdate{}, false, err
	}
	entry := eventstore.StoryLogEntry{
		DiceID: repository.DiceID(), GroupID: groupID, LogName: state.Name,
		Nickname: ctx.EndPoint.Nickname, IMUserID: UserIDExtract(ctx.EndPoint.UserID),
		Time: ctx.replyLogTime(createdAt), Message: text, IsDice: true, CommandID: ctx.CommandID,
		CommandInfo: commandInfo, UniformID: ctx.EndPoint.UserID,
		Seq: ptrInt64(ctx.logReplySeq),
	}
	return eventstore.NewStoryLogIntentPutUpdate(eventstore.StoryLogIntent{EffectID: effectID, Entry: entry}), true, nil
}

func durableGroupInfoRefreshCommandID(ctx *MsgContext, effectID string, payload adapterapi.EffectPayload) string {
	seed := effectID
	endpointID := ""
	if ctx != nil {
		if ctx.callbackMetadata.CommandID != "" {
			seed = ctx.callbackMetadata.CommandID
		}
		if ctx.EndPoint != nil {
			endpointID = ctx.EndPoint.ID
		}
	}
	relation := "group-info-refresh:" + endpointID + ":" + payload.Target.Conversation.String()
	return durableOutboundRelatedID(seed, relation)
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
	case adapterapi.EffectPayloadAnswerRequest:
		return adapterapi.CapabilityOutbound | adapterapi.CapabilityActions, adapterapi.ActionKindAnswerRequest, adapterapi.EffectRetryNonIdempotent, adapterapi.EffectRiskNormal
	case adapterapi.EffectPayloadAdapterAPI:
		return adapterapi.CapabilityOutbound | adapterapi.CapabilityActions, adapterapi.ActionKindAdapterAPI, adapterapi.EffectRetryNonIdempotent, adapterapi.EffectRiskNormal
	default:
		return 0, 0, 0, 0
	}
}

// NotifyOutboundEffectResult is installed as the dispatcher's post-commit
// notifier. Every terminal outcome consumes the in-memory acceptance record;
// only a committed success schedules the user hook on its runtime owner.
// submitMu fences notification admission behind Submit's durable result
// reconciliation.
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
	if !ok {
		return
	}
	if err := result.Validate(); err != nil {
		b.logOutboundSuccessNotificationError(effect.ID, fmt.Errorf("invalid provider completion: %w", err), notification)
		return
	}
	if err := effect.Validate(); err != nil {
		b.logOutboundSuccessNotificationError(effect.ID, fmt.Errorf("invalid completed effect: %w", err), notification)
		return
	}
	if effect.EndpointID != notification.expectedEndpoint ||
		effect.Payload.Target != notification.expectedTarget ||
		effect.Payload.Kind != notification.expectedKind ||
		result.Artifact != nil || result.GroupInfo != nil {
		b.logOutboundSuccessNotificationError(effect.ID, errors.New("provider completion does not match accepted effect"), notification)
		return
	}
	if result.Outcome != adapterapi.EffectSucceeded || notification.dice == nil ||
		notification.session == nil || notification.endpoint == nil {
		return
	}
	sent := notification.msg
	sent.Platform = notification.endpoint.Platform
	sent.Message = notification.text
	sent.RawID = result.ProviderID
	if notification.group {
		sent.MessageType = "group"
		sent.GroupID = effect.Payload.Target.Conversation.String()
	} else {
		sent.MessageType = "private"
		sent.GroupID = ""
	}
	if notification.endpoint != nil {
		sent.Sender = SenderBase{UserID: notification.endpoint.UserID, Nickname: notification.endpoint.Nickname}
	}
	if !b.notifications.Go(func(ownerCtx context.Context) {
		ctx, cancel := context.WithTimeout(ownerCtx, outboundSuccessNotificationTimeout)
		defer cancel()
		b.runOutboundSuccessNotification(ctx, effect, result, notification, sent)
	}) {
		b.logOutboundSuccessNotificationError(effect.ID, errors.New("outbound notification owner stopped"), notification)
	}
}

func (b *DurableOutboundBridge) runOutboundSuccessNotification(
	ctx context.Context,
	effect adapterapi.OutboundEffect,
	result adapterapi.EffectResult,
	notification outboundSuccessNotification,
	sent Message,
) {
	canonical, err := json.Marshal(struct {
		EffectID     adapterapi.EffectID     `json:"effectId"`
		EndpointID   adapterapi.EndpointID   `json:"endpointId"`
		Target       adapterapi.EffectTarget `json:"target"`
		ProviderID   string                  `json:"providerId"`
		SourceGroup  string                  `json:"sourceGroup,omitempty"`
		SourcePlayer string                  `json:"sourcePlayer,omitempty"`
		MessageType  string                  `json:"messageType"`
		MessageText  string                  `json:"messageText"`
		Notification string                  `json:"notification"`
	}{
		EffectID: effect.ID, EndpointID: effect.EndpointID, Target: effect.Payload.Target,
		ProviderID: result.ProviderID, SourceGroup: notification.sourceGroupID,
		SourcePlayer: notification.sourcePlayerID, MessageType: sent.MessageType,
		MessageText: sent.Message, Notification: notification.flag,
	})
	if err != nil {
		b.logOutboundSuccessNotificationError(effect.ID, err, notification)
		return
	}
	identity := notification.dice.DomainExecutionIdentity("outbound-provider-completion", string(effect.ID))
	err = notification.dice.WithDomainExecution(ctx, identity, canonical, func(transaction *DurableCallbackTransaction) error {
		callbackCtx, buildErr := notification.newContext(transaction)
		if buildErr != nil {
			return buildErr
		}
		return runOutboundSuccessHooks(callbackCtx, transaction, notification.session, &sent, notification.flag)
	})
	if err != nil {
		b.logOutboundSuccessNotificationError(effect.ID, err, notification)
	}
}

func (*DurableOutboundBridge) logOutboundSuccessNotificationError(effectID adapterapi.EffectID, err error, notification outboundSuccessNotification) {
	log := logger.M()
	if notification.dice != nil && notification.dice.Logger != nil {
		log = notification.dice.Logger
	}
	log.Errorf("出站成功回调失败: effect=%s err=%v", effectID, err)
}

func (notification outboundSuccessNotification) newContext(transaction *DurableCallbackTransaction) (*MsgContext, error) {
	if transaction == nil || notification.dice == nil || notification.session == nil || notification.endpoint == nil {
		return nil, ErrDomainExecutionUnavailable
	}
	callbackCtx := &MsgContext{
		MessageType: notification.messageType, EndPoint: notification.endpoint,
		Session: notification.session, Dice: notification.dice,
		IsCurGroupBotOn: notification.isCurGroupBotOn, IsPrivate: notification.isPrivate,
		CommandID: notification.commandID, CurrentCommand: notification.currentCommand,
		CommandHideFlag: notification.commandHideFlag, PrivilegeLevel: notification.privilegeLevel,
		GroupRoleLevel: notification.groupRoleLevel,
		logReplyTime:   notification.logReplyTime, logReplySeq: notification.logReplySeq,
		skipLogArchive:      notification.skipLogArchive,
		callbackTransaction: transaction, callbackMetadata: transaction.metadata,
		executionContext: transaction.executionContext,
	}
	if notification.sourceGroupID != "" {
		if err := callbackCtx.ResolveExistingDomainConversation(notification.sourceGroupID, notification.sourcePlayerID); err != nil {
			return nil, err
		}
		if callbackCtx.Group == nil || (notification.sourcePlayerID != "" && callbackCtx.Player == nil) {
			return nil, fmt.Errorf("outbound completion source no longer exists: group=%s player=%s", notification.sourceGroupID, notification.sourcePlayerID)
		}
	}
	return callbackCtx, nil
}

func runOutboundSuccessHooks(
	callbackCtx *MsgContext,
	transaction *DurableCallbackTransaction,
	session *IMSession,
	sent *Message,
	flag string,
) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("outbound completion hook panic: %v", recovered)
		}
	}()
	if err = callbackCtx.runStandaloneMessageScope(func() {
		session.OnMessageSend(callbackCtx, sent, flag)
	}); err != nil {
		return err
	}
	if err = callbackCtx.getExecutionError(); err != nil {
		return err
	}
	return transaction.Domain().Err()
}

func snapshotOutboundNotification(ctx *MsgContext, msg *Message, text, flag string, group bool) outboundSuccessNotification {
	if ctx == nil || msg == nil {
		return outboundSuccessNotification{}
	}
	session := ctx.Session
	if session == nil && ctx.EndPoint != nil {
		session = ctx.EndPoint.Session
	}
	snapshot := *msg
	if msg.Segment != nil {
		snapshot.Segment = append([]message.IMessageElement(nil), msg.Segment...)
	}
	notification := outboundSuccessNotification{
		dice: ctx.Dice, session: session, endpoint: ctx.EndPoint,
		messageType: ctx.MessageType, msg: snapshot, text: text, flag: flag, group: group,
		isCurGroupBotOn: ctx.IsCurGroupBotOn, isPrivate: ctx.IsPrivate,
		commandID: ctx.CommandID, currentCommand: ctx.CurrentCommand,
		commandHideFlag: ctx.CommandHideFlag, privilegeLevel: ctx.PrivilegeLevel,
		groupRoleLevel: ctx.GroupRoleLevel, logReplyTime: ctx.logReplyTime, logReplySeq: ctx.logReplySeq,
	}
	if ctx.Group != nil {
		notification.sourceGroupID = ctx.Group.GroupID()
	}
	if ctx.Player != nil {
		notification.sourcePlayerID = ctx.Player.UserID()
	}
	return notification
}

// NotifyOutboundEffectSucceeded retains compatibility with the success-only
// dispatcher hook while sharing terminal cleanup with the all-outcome hook.
func (b *DurableOutboundBridge) NotifyOutboundEffectSucceeded(ctx context.Context, effect adapterapi.OutboundEffect, result adapterapi.EffectResult) {
	b.NotifyOutboundEffectResult(ctx, effect, result)
}
