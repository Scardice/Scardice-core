package dice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	return b.submitResolved(requestCtx, ctx, msg, adapterapi.EffectPayload{Kind: payloadKind, Target: target, Text: text}, flag, group, text, endpointID, snapshot, ids, nil)
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
	return b.submitResolved(requestCtx, ctx, msg, payload, flag, group, forwardNodesToText(nodes), endpointID, snapshot, nil, nil)
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
	endpointID, snapshot, err := b.resolveEndpoint(requestCtx, ctx)
	if err != nil {
		return err
	}
	return b.submitResolved(requestCtx, ctx, msg, payload, flag, group, text, endpointID, snapshot, ids, nil)
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
	if snapshot.IndexSigner == nil || snapshot.IndexRootID == "" || snapshot.EndpointID != endpointID {
		return "", messageflow.EndpointSnapshot{}, ErrDurableOutboundUnsupported
	}
	return endpointID, snapshot, nil
}

// EnqueueAdapterAPI durably admits an exact native adapter request. Callback
// invocations stage into their existing collector; standalone calls commit the
// same encrypted Prepare/Submit shape immediately.
func (b *DurableOutboundBridge) EnqueueAdapterAPI(requestCtx context.Context, ctx *MsgContext, endpointID adapterapi.EndpointID, rawJSON string) (AdapterAPIOperation, error) {
	if err := adapterapi.ValidateProtocolJSON(rawJSON); err != nil {
		return AdapterAPIOperation{}, err
	}
	endpointID, snapshot, err := b.resolveExplicitEndpoint(requestCtx, ctx, endpointID)
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
		snapshot,
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
	snapshot messageflow.EndpointSnapshot,
	newID durableOutboundIDAllocator,
	resultOut *messageflow.SubmitResult,
) error {
	if requestCtx == nil {
		return ErrDurableOutboundUnsupported
	}
	if err := requestCtx.Err(); err != nil {
		return err
	}
	if payload.Kind == adapterapi.EffectPayloadAdapterAPI {
		if ctx == nil || ctx.Dice == nil {
			return ErrDurableOutboundUnsupported
		}
		if err := adapterapi.ValidateProtocolJSON(payload.RequestJSON); err != nil {
			return err
		}
		if err := ctx.Dice.checkAdapterOutboundCensor(ctx, payload.RequestJSON); err != nil {
			return err
		}
	} else if payload.Kind == adapterapi.EffectPayloadForward {
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
	}
	lane, err := adapterapi.NewLaneMetadataWithSigner(endpointID, payload.Target, 1, func(label string, covered []byte) ([]byte, error) {
		digest, keyID, signErr := snapshot.IndexSigner.KeyedDigest(requestCtx, label, string(covered))
		if signErr != nil {
			return nil, signErr
		}
		if keyID != snapshot.IndexRootID {
			return nil, ErrDurableOutboundUnsupported
		}
		return digest, nil
	})
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
		}
		intentUpdate, hasIntent, err := outboundStoryLogIntentUpdate(ctx, msg, payload, text, effectID, b.now())
		if err != nil {
			return fmt.Errorf("story log intent: %w", err)
		}
		if hasIntent {
			if err := ctx.callbackTransaction.collector.AddPreparedOutboundWithLog(prepared, intentUpdate); err != nil {
				return fmt.Errorf("stage outbound effect with log intent: %w", err)
			}
			if notification.callbackCtx != nil {
				notification.callbackCtx.skipLogArchive = true
			}
		} else if err := ctx.callbackTransaction.collector.AddPreparedOutbound(prepared); err != nil {
			return fmt.Errorf("stage outbound effect: %w", err)
		}
		if msg != nil {
			ctx.callbackTransaction.callbackCommitFence = &b.submitMu
			ctx.callbackTransaction.callbackAfterCommit = append(ctx.callbackTransaction.callbackAfterCommit, func() {
				b.mu.Lock()
				if _, exists := b.pending[effectID]; !exists {
					b.pending[effectID] = notification
				}
				b.mu.Unlock()
			})
		}
		return nil
	}
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
	if d.Config.EnableCensor && d.Config.CensorMode == OnlyOutputReply {
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

// SubmitDurableGroupQuit atomically accepts an optional farewell followed by a
// group-quit action. It is only for standalone management requests; callback
// handlers already own a wider transaction and must stage into that transaction.
func SubmitDurableGroupQuit(requestCtx context.Context, mctx *MsgContext, groupID, farewell string) error {
	if requestCtx == nil || mctx == nil || mctx.Dice == nil || mctx.EndPoint == nil || mctx.Dice.DurableStore == nil || strings.TrimSpace(groupID) == "" || mctx.CommandID <= 0 {
		return adapterapi.ErrInvalidContract
	}
	if err := requestCtx.Err(); err != nil {
		return err
	}
	if mctx.callbackTransaction != nil {
		return ErrDurableOutboundUnsupported
	}
	bridge, ok := mctx.Dice.OutboundBridge.(*DurableOutboundBridge)
	if !ok || bridge == nil {
		return ErrDurableOutboundUnsupported
	}

	groupID = strings.TrimSpace(groupID)
	msg := &Message{MessageType: "group", GroupID: groupID}
	endpointID, snapshot, err := bridge.resolveEndpoint(requestCtx, mctx)
	if err != nil {
		return err
	}
	target, err := outboundTextTarget(snapshot.AdapterKey, mctx.EndPoint, msg, true)
	if err != nil {
		return err
	}
	var farewellParts []string
	if farewell != "" {
		if prepared := prepareStandaloneGroupFarewell(mctx, msg, farewell); prepared != "" {
			farewellParts = standaloneGroupFarewellParts(mctx, prepared)
		}
	}

	collector := messageflow.NewMutationCollector(eventstore.EventFactory{})
	transaction, err := NewDurableCallbackTransaction(mctx.Dice.DurableStore, collector)
	if err != nil {
		return err
	}
	staged := mctx.ShallowCopy()
	staged.CurrentCommand = mctx.CurrentCommand
	staged.callbackTransaction = transaction
	metadataID := fmt.Sprintf("standalone-group-quit:%d", staged.CommandID)
	if current := strings.TrimSpace(staged.CurrentCommand); current != "" {
		metadataID += ":" + current
	}
	staged.callbackMetadata = eventstore.Metadata{
		CommandID: metadataID, CorrelationID: metadataID,
		Producer: "dice/standalone-group-quit", OccurredAt: bridge.now().UTC(),
	}

	effectBase, err := bridge.ids.NewID()
	if err != nil {
		return err
	}
	operationBase, err := bridge.ids.NewID()
	if err != nil {
		return err
	}
	// 为本次退群操作分配独立身份；分段告别与退群顺序由 collector 的追加顺序保证。
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
		identityBase = metadataID
	}
	for index, part := range farewellParts {
		staged.CurrentCommand = fmt.Sprintf("%s:farewell:%016x", identityBase, index)
		if err = bridge.submitResolved(requestCtx, staged, msg, adapterapi.EffectPayload{
			Kind: adapterapi.EffectPayloadGroupText, Target: target, Text: part,
		}, "", true, part, endpointID, snapshot, nextID, nil); err != nil {
			return err
		}
	}
	staged.CurrentCommand = identityBase + ":quit"
	if err = bridge.submitResolved(requestCtx, staged, nil, adapterapi.EffectPayload{
		Kind: adapterapi.EffectPayloadQuit, Target: target,
	}, "", true, "", endpointID, snapshot, nextID, nil); err != nil {
		return err
	}
	if err = transaction.Finalize(requestCtx); err != nil {
		return err
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		return err
	}
	if err = eventstore.ValidateUnitOfWork(work); err != nil {
		if errors.Is(err, eventstore.ErrEmptyUnitOfWork) {
			return nil
		}
		return err
	}

	unlock, err := acquireDurableOutboundCommitFence(requestCtx, transaction.callbackCommitFence)
	if err != nil {
		return err
	}
	defer unlock()
	if _, err = mctx.Dice.DurableStore.Commit(requestCtx, work); err != nil {
		return err
	}
	for _, afterCommit := range transaction.callbackAfterCommit {
		afterCommit()
	}
	return nil
}

func acquireDurableOutboundCommitFence(ctx context.Context, fence callbackCommitFence) (func(), error) {
	if fence == nil {
		return func() {}, nil
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if fence.TryLock() {
			if err := ctx.Err(); err != nil {
				fence.Unlock()
				return nil, err
			}
			return fence.Unlock, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
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
	if msg == nil || canonicalOnebotGroupID(msg.GroupID) != canonicalOnebotGroupID(ctx.Group.GroupID) {
		return eventstore.LogUpdate{}, false, ErrDurableOutboundUnsupported
	}
	if privateHiddenReply {
		if msg.MessageType != "group" ||
			canonicalOnebotGroupID(ctx.CommandHideFlag) != canonicalOnebotGroupID(ctx.Group.GroupID) ||
			strings.TrimSpace(payload.Target.Conversation.String()) != strings.TrimSpace(msg.Sender.UserID) {
			return eventstore.LogUpdate{}, false, ErrDurableOutboundUnsupported
		}
	} else if strings.TrimSpace(payload.Target.Conversation.String()) != strings.TrimSpace(msg.GroupID) {
		return eventstore.LogUpdate{}, false, ErrDurableOutboundUnsupported
	}
	if ctx.callbackTransaction == nil || !ctx.callbackTransaction.HasStoryLogStateUpdate(ctx.Dice.BaseConfig.Name, ctx.Group.GroupID) {
		if _, err := loadGroupLogState(ctx, ctx.Group); err != nil {
			return eventstore.LogUpdate{}, false, err
		}
	}
	state := getGroupLogState(ctx.Group)
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
		DiceID: repository.DiceID(), GroupID: ctx.Group.GroupID, LogName: state.Name,
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
		_ = callbackCtx.runStandaloneMessageScope(func() {
			session.OnMessageSend(callbackCtx, &sent, flag)
		})
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
		logReplyTime:   ctx.logReplyTime, logReplySeq: ctx.logReplySeq,
	}
	return outboundSuccessNotification{callbackCtx: callbackCtx, session: session, msg: *msg, text: text, flag: flag, group: group}
}

// NotifyOutboundEffectSucceeded retains compatibility with the success-only
// dispatcher hook while sharing terminal cleanup with the all-outcome hook.
func (b *DurableOutboundBridge) NotifyOutboundEffectSucceeded(ctx context.Context, effect adapterapi.OutboundEffect, result adapterapi.EffectResult) {
	b.NotifyOutboundEffectResult(ctx, effect, result)
}
