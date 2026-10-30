package dice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	dingtalk "github.com/Szzrain/DingTalk-go"
	"github.com/open-dingtalk/dingtalk-stream-sdk-go/chatbot"

	"Scardice-core/adapterapi"
)

const DingTalkAdapterKey adapterapi.AdapterKey = "dingtalk"

type DingTalkDescriptor struct{}

type dingTalkConfigInput struct {
	ClientID    string          `json:"clientId"`
	RobotCode   string          `json:"robotCode"`
	CoolAppCode string          `json:"coolAppCode"`
	Stream      *bool           `json:"stream"`
	Token       json.RawMessage `json:"token"`
}

type dingTalkCanonicalConfig struct {
	ClientID    string                  `json:"clientId"`
	RobotCode   string                  `json:"robotCode"`
	CoolAppCode string                  `json:"coolAppCode"`
	Stream      bool                    `json:"stream"`
	Token       providerCanonicalSecret `json:"token"`
}

type dingTalkSession interface {
	AddEventHandler(handler interface{}) func()
	Open() error
	Close() error
	MessagePrivateSend(conversationID, robotCode string, message dingtalk.Message) (string, error)
	MessageGroupSend(conversationID, robotCode, coolAppCode string, message dingtalk.Message) (string, error)
}

type dingTalkRuntime struct {
	config     dingTalkCanonicalConfig
	tokenRef   adapterapi.SecretRef
	resolver   adapterapi.SecretResolver
	newSession func(string, string) dingTalkSession

	mu      sync.RWMutex
	cancel  context.CancelFunc
	running bool
	token   string
	session dingTalkSession
}

func NewDingTalkDescriptor() adapterapi.Descriptor { return DingTalkDescriptor{} }

func (DingTalkDescriptor) Key() adapterapi.AdapterKey { return DingTalkAdapterKey }

func (DingTalkDescriptor) ConfigVersion() uint16 { return 1 }
func FormatDiceIDDingTalk(id string) string {
	return fmt.Sprintf("DINGTALK:%s", id)
}

func FormatDiceIDDingTalkGroup(id string) string {
	return fmt.Sprintf("DINGTALK-Group:%s", id)
}

func ExtractDingTalkUserID(id string) string {
	return strings.TrimPrefix(id, "DINGTALK:")
}

func ExtractDingTalkGroupID(id string) string {
	return strings.TrimPrefix(id, "DINGTALK-Group:")
}

func (DingTalkDescriptor) SupportedActions(adapterapi.ValidatedConfig) adapterapi.ActionSet {
	return adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage)
}

func (DingTalkDescriptor) Capabilities(adapterapi.ValidatedConfig) adapterapi.CapabilitySet {
	return adapterapi.CapabilityLifecycle | adapterapi.CapabilityInbound | adapterapi.CapabilityOutbound
}

func (DingTalkDescriptor) ValidateConfig(ctx context.Context, raw json.RawMessage) (adapterapi.ValidatedConfig, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	var input dingTalkConfigInput
	if err := decodeStrictProviderJSON(raw, &input); err != nil {
		return adapterapi.ValidatedConfig{}, fmt.Errorf("dingtalk: invalid config: %w", err)
	}
	input.ClientID = strings.TrimSpace(input.ClientID)
	input.RobotCode = strings.TrimSpace(input.RobotCode)
	input.CoolAppCode = strings.TrimSpace(input.CoolAppCode)
	if input.ClientID == "" || input.RobotCode == "" || input.Stream == nil || !*input.Stream {
		return adapterapi.ValidatedConfig{}, errors.New("dingtalk: clientId, robotCode, and stream mode are required")
	}
	var token providerCanonicalSecret
	if err := decodeStrictProviderJSON(input.Token, &token); err != nil || token.Version == 0 {
		return adapterapi.ValidatedConfig{}, errors.New("dingtalk: invalid token reference")
	}
	ref := adapterapi.SecretRef{Ref: token.SecretRef, Version: token.Version}
	if err := ref.Validate(); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	encoded, err := json.Marshal(dingTalkCanonicalConfig{ClientID: input.ClientID, RobotCode: input.RobotCode, CoolAppCode: input.CoolAppCode, Stream: true, Token: token})
	if err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	canonical, err := adapterapi.CanonicalizeJSON(encoded)
	if err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	validated := adapterapi.ValidatedConfig{Version: 1, Canonical: canonical, SecretRefs: []adapterapi.SecretRef{ref}}
	if err := validated.Validate(); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	return validated, nil
}

func (descriptor DingTalkDescriptor) NewRuntime(init adapterapi.RuntimeInit) (adapterapi.AdapterRuntime, error) {
	if !init.EndpointID.Valid() || init.Generation == 0 || init.DesiredVersion == 0 {
		return nil, errors.New("dingtalk: runtime identity is incomplete")
	}
	if err := init.Config.Validate(); err != nil {
		return nil, err
	}
	validated, err := descriptor.ValidateConfig(context.Background(), init.Config.Canonical)
	if err != nil || validated.Version != init.Config.Version || !bytes.Equal(validated.Canonical, init.Config.Canonical) || len(validated.SecretRefs) != len(init.Config.SecretRefs) {
		return nil, errors.New("dingtalk: runtime config was not validated by descriptor")
	}
	for index := range validated.SecretRefs {
		if validated.SecretRefs[index] != init.Config.SecretRefs[index] {
			return nil, errors.New("dingtalk: runtime secret references do not match")
		}
	}
	var config dingTalkCanonicalConfig
	if err := json.Unmarshal(init.Config.Canonical, &config); err != nil {
		return nil, errors.New("dingtalk: invalid canonical runtime config")
	}
	return &dingTalkRuntime{config: config, tokenRef: validated.SecretRefs[0], resolver: init.Secrets, newSession: func(clientID, token string) dingTalkSession { return dingtalk.New(clientID, token) }}, nil
}

func (*dingTalkRuntime) OwnedResources() adapterapi.OwnedResourceManifest {
	return adapterapi.OwnedResourceManifest{}
}

func (*dingTalkRuntime) Capabilities() adapterapi.CapabilitySet {
	return adapterapi.CapabilityLifecycle | adapterapi.CapabilityInbound | adapterapi.CapabilityOutbound
}

func (*dingTalkRuntime) Diagnostics(context.Context) adapterapi.DiagnosticReport {
	return adapterapi.DiagnosticReport{}
}

func (runtime *dingTalkRuntime) Execute(_ context.Context, effect adapterapi.OutboundEffect) adapterapi.EffectResult {
	if effect.Version != adapterapi.EffectVersionOne {
		return adapterapi.UnsupportedResult("dingtalk_invalid_effect_version")
	}
	if err := effect.ValidateForCapabilities(runtime.Capabilities(), adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage)); err != nil {
		return adapterapi.UnsupportedResult("dingtalk_effect_not_supported")
	}
	payload := effect.Payload
	conversation := payload.Target.Conversation.String()
	message := &dingtalk.MessageSampleText{Content: payload.Text}
	runtime.mu.RLock()
	defer runtime.mu.RUnlock()
	if runtime.session == nil || runtime.token == "" {
		return adapterapi.TerminalResult("dingtalk_provider_unavailable", "provider unavailable")
	}
	var providerID string
	var err error
	switch payload.Kind {
	case adapterapi.EffectPayloadGroupText:
		groupID := strings.TrimPrefix(conversation, "DINGTALK-Group:")
		if payload.Target.Kind != adapterapi.TargetGroup || groupID == conversation || groupID == "" {
			return adapterapi.UnsupportedResult("dingtalk_invalid_target")
		}
		providerID, err = runtime.session.MessageGroupSend(groupID, runtime.config.RobotCode, runtime.config.CoolAppCode, message)
	case adapterapi.EffectPayloadPersonText:
		userID := strings.TrimPrefix(conversation, "DINGTALK:")
		if payload.Target.Kind != adapterapi.TargetPerson || userID == conversation || userID == "" {
			return adapterapi.UnsupportedResult("dingtalk_invalid_target")
		}
		providerID, err = runtime.session.MessagePrivateSend(userID, runtime.config.RobotCode, message)
	default:
		return adapterapi.UnsupportedResult("dingtalk_effect_not_supported")
	}
	if err != nil {
		return adapterapi.AmbiguousResult("dingtalk_provider_ambiguous", "provider dispatch outcome is unknown")
	}
	if providerID == "" {
		return adapterapi.TerminalResult("dingtalk_invalid_response", "provider returned an invalid response")
	}
	return adapterapi.SucceededResult(providerID)
}

func (runtime *dingTalkRuntime) resolveToken(ctx context.Context) (string, error) {
	if runtime == nil || runtime.resolver == nil {
		return "", errors.New("dingtalk: token resolver is unavailable")
	}
	value, err := runtime.resolver.Resolve(ctx, runtime.tokenRef)
	if err != nil {
		return "", err
	}
	if value.Version != runtime.tokenRef.Version || len(value.Bytes) == 0 {
		return "", errors.New("dingtalk: token resolution is invalid")
	}
	return string(value.Bytes), nil
}

func (runtime *dingTalkRuntime) Run(ctx context.Context, core adapterapi.CorePort) (runErr error) {
	if runtime == nil || core == nil {
		return errors.New("dingtalk: runtime or core is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithCancel(ctx)
	runtime.mu.Lock()
	if runtime.cancel != nil {
		runtime.mu.Unlock()
		cancel()
		return errors.New("dingtalk: runtime already started")
	}
	runtime.cancel, runtime.running = cancel, true
	runtime.mu.Unlock()
	defer func() {
		if runErr != nil && !errors.Is(runErr, context.Canceled) {
			_ = core.ReportObservation(context.Background(), adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateFailed, Code: "runtime_failed", Detail: "DingTalk runtime failed", Retryable: true, OccurredAt: time.Now().UTC()})
		}
		_ = runtime.Stop(context.Background())
	}()
	if err := core.ReportObservation(runCtx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateStarting, Code: "starting", Detail: "DingTalk runtime starting", OccurredAt: time.Now().UTC()}); err != nil {
		return err
	}
	token, err := runtime.resolveToken(runCtx)
	if err != nil {
		return err
	}
	session := runtime.newSession(runtime.config.ClientID, token)
	if session == nil {
		return errors.New("dingtalk: session factory returned nil")
	}
	callbackErrors := make(chan error, 1)
	remove := session.AddEventHandler(func(_ *dingtalk.Session, data *chatbot.BotCallbackDataModel) {
		if handleErr := dingTalkHandleMessage(runCtx, core, data); handleErr != nil {
			select {
			case callbackErrors <- handleErr:
			default:
			}
		}
	})
	defer remove()
	if openErr := session.Open(); openErr != nil {
		return openErr
	}
	runtime.mu.Lock()
	if !runtime.running {
		runtime.mu.Unlock()
		_ = session.Close()
		return nil
	}
	runtime.session, runtime.token = session, token
	runtime.mu.Unlock()
	if reportErr := core.ReportObservation(runCtx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateConnected, Code: "connected", Detail: "DingTalk Stream established", OccurredAt: time.Now().UTC()}); reportErr != nil {
		return reportErr
	}
	providerID, err := adapterapi.NewPrincipalID(FormatDiceIDDingTalk(runtime.config.RobotCode))
	if err != nil {
		return err
	}
	if err := core.ReportObservation(runCtx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationIdentity, State: adapterapi.ObservedStateConnected, ProviderID: providerID, Code: "identity", OccurredAt: time.Now().UTC()}); err != nil {
		return err
	}
	select {
	case <-runCtx.Done():
		return nil
	case err := <-callbackErrors:
		return err
	}
}

func dingTalkHandleMessage(ctx context.Context, core adapterapi.CorePort, data *chatbot.BotCallbackDataModel) error {
	if data == nil || data.MsgId == "" || data.SenderStaffId == "" || data.ConversationId == "" {
		return nil
	}
	conversation := FormatDiceIDDingTalk(data.SenderStaffId)
	conversationKind := adapterapi.ConversationKindDirect
	if data.ConversationType == "2" {
		conversationKind = adapterapi.ConversationKindGroup
		conversation = FormatDiceIDDingTalkGroup(data.ConversationId)
	}
	inbound := adapterapi.InboundMessage{ProviderEventID: adapterapi.ProviderEventID("dingtalk-message:" + data.MsgId), MessageID: adapterapi.MessageID(data.MsgId), Platform: "DINGTALK", Sender: adapterapi.PrincipalID(FormatDiceIDDingTalk(data.SenderStaffId)), Conversation: adapterapi.ConversationID(conversation), ConversationKind: conversationKind, Target: conversation, Kind: adapterapi.InboundKindMessage, Text: data.Text.Content}
	if data.IsAdmin {
		inbound.SenderRole = "admin"
	}
	if data.Text.Content != "" {
		inbound.Segments = []adapterapi.InboundSegment{{Kind: "text", Text: data.Text.Content}}
	}
	if data.CreateAt > 0 {
		inbound.OccurredAt = time.UnixMilli(data.CreateAt).UTC()
	}
	if err := inbound.Validate(); err != nil {
		return err
	}
	receipt, err := core.HandleInbound(ctx, inbound)
	if err != nil {
		return err
	}
	if err := receipt.Validate(); err != nil {
		return err
	}
	if receipt.Outcome == adapterapi.IngressRejected {
		return errors.New("dingtalk: ingress rejected")
	}
	return nil
}

func (runtime *dingTalkRuntime) Stop(context.Context) error {
	if runtime == nil {
		return nil
	}
	runtime.mu.Lock()
	cancel := runtime.cancel
	runtime.cancel = nil
	runtime.running = false
	session := runtime.session
	runtime.session = nil
	runtime.token = ""
	if cancel != nil {
		cancel()
	}
	var err error
	if session != nil {
		err = session.Close()
	}
	runtime.mu.Unlock()
	return err
}
