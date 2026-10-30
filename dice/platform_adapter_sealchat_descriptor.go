package dice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/time/rate"

	"Scardice-core/adapterapi"
	sealsatori "Scardice-core/utils/satori"
)

const SealChatAdapterKey adapterapi.AdapterKey = "sealchat"

var errSealChatInvalidGatewayPayload = errors.New("sealchat: invalid gateway payload")

type SealChatDescriptor struct{}

type sealChatConfigInput struct {
	Version    string          `json:"version"`
	AppID      string          `json:"appId"`
	Tenant     string          `json:"tenant"`
	ConnectURL string          `json:"connectUrl"`
	Token      json.RawMessage `json:"token"`
}

type sealChatCanonicalConfig struct {
	Version    string                  `json:"version"`
	AppID      string                  `json:"appId"`
	Tenant     string                  `json:"tenant"`
	ConnectURL string                  `json:"connectUrl"`
	Token      providerCanonicalSecret `json:"token"`
}

type sealChatRuntime struct {
	config   sealChatCanonicalConfig
	tokenRef adapterapi.SecretRef
	resolver adapterapi.SecretResolver
	dialer   *websocket.Dialer

	mu        sync.Mutex
	writeMu   sync.Mutex
	pendingMu sync.Mutex
	cancel    context.CancelFunc
	runCtx    context.Context
	conn      *websocket.Conn
	pending   map[string]chan json.RawMessage
	wg        sync.WaitGroup
	running   bool
	connected bool
	selfID    string
	sequence  atomic.Uint64
	lastPong  atomic.Int64

	// characterLimiter bounds provider character writes per runtime generation,
	// preserving the legacy 60-writes-per-minute (burst 5) adapter limit.
	characterLimiter *rate.Limiter
}

type sealChatReadResult struct {
	messageType int
	data        []byte
	err         error
}

type sealChatGatewayFrame struct {
	Op   *sealsatori.Opcode `json:"op"`
	Body json.RawMessage    `json:"body"`
	API  string             `json:"api"`
	Echo string             `json:"echo"`
	Data json.RawMessage    `json:"data"`
}

type sealChatReady struct {
	ErrorMessage string          `json:"errorMsg"`
	User         sealsatori.User `json:"user"`
	Logins       []sealChatLogin `json:"logins"`
}

type sealChatLogin struct {
	SelfID string          `json:"self_id"`
	User   sealsatori.User `json:"user"`
}

func NewSealChatDescriptor() adapterapi.Descriptor { return SealChatDescriptor{} }

func (SealChatDescriptor) Key() adapterapi.AdapterKey { return SealChatAdapterKey }

func (SealChatDescriptor) ConfigVersion() uint16 { return 1 }
func FormatDiceIDSealChat(id string) string {
	if strings.HasPrefix(id, "SEALCHAT:") {
		return id
	}
	return fmt.Sprintf("SEALCHAT:%s", id)
}

func FormatDiceIDSealChatPrivate(id string) string {
	if strings.HasPrefix(id, "PG-SEALCHAT:") {
		return id
	}
	return fmt.Sprintf("PG-SEALCHAT:%s", id)
}

func FormatDiceIDSealChatGroup(id string) string {
	if strings.HasPrefix(id, "SEALCHAT-Group:") {
		return id
	}
	return fmt.Sprintf("SEALCHAT-Group:%s", id)
}

func ExtractSealChatPrivateChatID(id string, userID string) string {
	if strings.HasPrefix(id, "SEALCHAT:") {
		left := strings.TrimPrefix(id, "SEALCHAT:")
		right := strings.TrimPrefix(userID, "SEALCHAT:")
		if left > right {
			left, right = right, left
		}
		return fmt.Sprintf("%s:%s", left, right)
	}
	return id
}

func ExtractSealChatUserID(id string) string {
	if strings.HasPrefix(id, "SEALCHAT:") {
		return strings.TrimPrefix(id, "SEALCHAT:")
	}
	if strings.HasPrefix(id, "SEALCHAT-Group:") {
		return strings.TrimPrefix(id, "SEALCHAT-Group:")
	}
	return id
}
func sealChatSupportedActions() adapterapi.ActionSet {
	return adapterapi.ActionSet(0).With(
		adapterapi.ActionKindSendMessage,
		adapterapi.ActionKindSetGroupCard,
	)
}

func (SealChatDescriptor) SupportedActions(adapterapi.ValidatedConfig) adapterapi.ActionSet {
	return sealChatSupportedActions()
}

func (SealChatDescriptor) Capabilities(adapterapi.ValidatedConfig) adapterapi.CapabilitySet {
	return adapterapi.CapabilityLifecycle | adapterapi.CapabilityInbound | adapterapi.CapabilityOutbound | adapterapi.CapabilityActions | adapterapi.CapabilityRichMessages
}

func (*sealChatRuntime) Capabilities() adapterapi.CapabilitySet {
	return adapterapi.CapabilityLifecycle | adapterapi.CapabilityInbound | adapterapi.CapabilityOutbound | adapterapi.CapabilityActions | adapterapi.CapabilityRichMessages
}

func (runtime *sealChatRuntime) Execute(ctx context.Context, effect adapterapi.OutboundEffect) adapterapi.EffectResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return adapterapi.TerminalResult("sealchat_context_canceled", "dispatch context canceled")
	}
	if effect.Version != adapterapi.EffectVersionOne {
		return adapterapi.UnsupportedResult("sealchat_invalid_effect_version")
	}
	if err := effect.ValidateForCapabilities(runtime.Capabilities(), sealChatSupportedActions()); err != nil {
		return adapterapi.UnsupportedResult("sealchat_effect_not_supported")
	}
	payload := effect.Payload
	switch payload.Kind {
	case adapterapi.EffectPayloadGroupText, adapterapi.EffectPayloadPersonText, adapterapi.EffectPayloadSegments:
		channelID, err := runtime.outboundChannel(ctx, payload)
		if err != nil {
			return adapterapi.UnsupportedResult("sealchat_invalid_target")
		}
		content, err := sealChatOutboundContent(payload)
		if err != nil {
			return adapterapi.UnsupportedResult(err.Error())
		}
		data, wrote, err := runtime.callAPI(ctx, "message.create", map[string]any{"channel_id": channelID, "content": content})
		if err != nil {
			return sealChatDispatchFailure(wrote)
		}
		providerID := sealChatResponseID(data)
		if providerID == "" {
			return adapterapi.TerminalResult("sealchat_invalid_response", "provider returned an invalid response")
		}
		return adapterapi.SucceededResult(providerID)
	case adapterapi.EffectPayloadSetGroupCard:
		if payload.Target.Kind != adapterapi.TargetGroup {
			return adapterapi.UnsupportedResult("sealchat_invalid_target")
		}
		channelID := strings.TrimPrefix(payload.Target.Conversation.String(), "SEALCHAT-Group:")
		memberID := ExtractSealChatUserID(string(payload.Target.Member))
		if channelID == payload.Target.Conversation.String() || channelID == "" || memberID == "" {
			return adapterapi.UnsupportedResult("sealchat_invalid_target")
		}
		_, wrote, err := runtime.callAPI(ctx, "bot.channel_member.set_name", map[string]string{
			"user_id":    memberID,
			"channel_id": channelID,
			"name":       payload.Card,
		})
		if err != nil {
			return sealChatDispatchFailure(wrote)
		}
		return adapterapi.SucceededResult("")
	default:
		return adapterapi.UnsupportedResult("sealchat_effect_not_supported")
	}
}

func (runtime *sealChatRuntime) outboundChannel(ctx context.Context, payload adapterapi.EffectPayload) (string, error) {
	conversation := payload.Target.Conversation.String()
	switch payload.Kind {
	case adapterapi.EffectPayloadGroupText:
		if payload.Target.Kind != adapterapi.TargetGroup {
			return "", errors.New("invalid group target")
		}
		channelID := strings.TrimPrefix(conversation, "SEALCHAT-Group:")
		if channelID == conversation || channelID == "" {
			return "", errors.New("invalid group target")
		}
		return channelID, nil
	case adapterapi.EffectPayloadPersonText, adapterapi.EffectPayloadSegments:
		if payload.Target.Kind != adapterapi.TargetPerson {
			return "", errors.New("invalid person target")
		}
		userID := strings.TrimPrefix(conversation, "SEALCHAT:")
		if userID == conversation || userID == "" {
			return "", errors.New("invalid person target")
		}
		data, wrote, err := runtime.callAPI(ctx, "channel.private.create", map[string]string{"user_id": userID})
		if err != nil {
			if wrote {
				return "", err
			}
			return "", err
		}
		channelID := sealChatResponseID(data)
		if channelID == "" {
			runtime.mu.Lock()
			selfID := runtime.selfID
			runtime.mu.Unlock()
			channelID = ExtractSealChatPrivateChatID(conversation, FormatDiceIDSealChat(selfID))
		}
		if channelID == "" {
			return "", errors.New("private channel is unavailable")
		}
		return channelID, nil
	default:
		return "", errors.New("unsupported outbound payload")
	}
}

func sealChatOutboundContent(payload adapterapi.EffectPayload) (string, error) {
	switch payload.Kind {
	case adapterapi.EffectPayloadGroupText, adapterapi.EffectPayloadPersonText:
		return sealsatori.ContentEscape(payload.Text), nil
	case adapterapi.EffectPayloadSegments:
		var content strings.Builder
		for _, segment := range payload.Segments {
			switch segment.Kind {
			case adapterapi.SegmentKindText:
				content.WriteString(sealsatori.ContentEscape(segment.Text))
			case adapterapi.SegmentKindMention:
				if segment.Text == "all" || segment.Text == "SEALCHAT:all" {
					content.WriteString(`<at type="all"/>`)
					continue
				}
				userID := ExtractSealChatUserID(segment.Text)
				if userID == "" {
					return "", errors.New("sealchat_invalid_mention")
				}
				_, _ = fmt.Fprintf(&content, `<at id="%s"/>`, sealsatori.ContentEscape(userID))
			case adapterapi.SegmentKindImage, adapterapi.SegmentKindFile:
				return "", errors.New("sealchat_artifact_reader_unavailable")
			default:
				return "", errors.New("sealchat_unknown_segment")
			}
		}
		if content.Len() == 0 {
			return "", errors.New("sealchat_empty_segments")
		}
		return content.String(), nil
	default:
		return "", errors.New("sealchat_unknown_payload")
	}
}

func (SealChatDescriptor) ValidateConfig(ctx context.Context, raw json.RawMessage) (adapterapi.ValidatedConfig, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	var input sealChatConfigInput
	if err := decodeStrictProviderJSON(raw, &input); err != nil {
		return adapterapi.ValidatedConfig{}, fmt.Errorf("sealchat: invalid config: %w", err)
	}
	if input.Version != "1" {
		return adapterapi.ValidatedConfig{}, errors.New("sealchat: unsupported config version")
	}
	var secret providerCanonicalSecret
	if err := decodeStrictProviderJSON(input.Token, &secret); err != nil || secret.Version == 0 {
		return adapterapi.ValidatedConfig{}, errors.New("sealchat: invalid token reference")
	}
	tokenRef := adapterapi.SecretRef{Ref: secret.SecretRef, Version: secret.Version}
	if err := tokenRef.Validate(); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	connectURL, err := normalizeSealChatURL(input.ConnectURL)
	if err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	encoded, err := json.Marshal(sealChatCanonicalConfig{Version: input.Version, AppID: strings.TrimSpace(input.AppID), Tenant: strings.TrimSpace(input.Tenant), ConnectURL: connectURL, Token: secret})
	if err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	canonical, err := adapterapi.CanonicalizeJSON(encoded)
	if err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	validated := adapterapi.ValidatedConfig{Version: 1, Canonical: canonical, SecretRefs: []adapterapi.SecretRef{tokenRef}}
	if err := validated.Validate(); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	return validated, nil
}

func normalizeSealChatURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "ws" && parsed.Scheme != "wss") || parsed.User != nil || parsed.Fragment != "" {
		return "", errors.New("sealchat: connectUrl must be an absolute ws or wss URL without credentials or fragment")
	}
	return parsed.String(), nil
}

func (descriptor SealChatDescriptor) NewRuntime(init adapterapi.RuntimeInit) (adapterapi.AdapterRuntime, error) {
	if !init.EndpointID.Valid() || init.Generation == 0 || init.DesiredVersion == 0 {
		return nil, errors.New("sealchat: runtime identity is incomplete")
	}
	if err := init.Config.Validate(); err != nil {
		return nil, err
	}
	validated, err := descriptor.ValidateConfig(context.Background(), init.Config.Canonical)
	if err != nil || validated.Version != init.Config.Version || !bytes.Equal(validated.Canonical, init.Config.Canonical) || len(validated.SecretRefs) != 1 || len(init.Config.SecretRefs) != 1 || validated.SecretRefs[0] != init.Config.SecretRefs[0] {
		return nil, errors.New("sealchat: runtime config was not validated by descriptor")
	}
	var config sealChatCanonicalConfig
	if err := json.Unmarshal(init.Config.Canonical, &config); err != nil {
		return nil, errors.New("sealchat: invalid canonical runtime config")
	}
	return &sealChatRuntime{config: config, tokenRef: validated.SecretRefs[0], resolver: init.Secrets, dialer: websocket.DefaultDialer, pending: make(map[string]chan json.RawMessage), characterLimiter: rate.NewLimiter(rate.Every(time.Minute/60), 5)}, nil
}

func (*sealChatRuntime) OwnedResources() adapterapi.OwnedResourceManifest {
	return adapterapi.OwnedResourceManifest{}
}

func (*sealChatRuntime) Diagnostics(context.Context) adapterapi.DiagnosticReport {
	return adapterapi.DiagnosticReport{}
}

func (runtime *sealChatRuntime) resolveToken(ctx context.Context) (string, error) {
	if runtime == nil || runtime.resolver == nil {
		return "", errors.New("sealchat: token resolver is unavailable")
	}
	value, err := runtime.resolver.Resolve(ctx, runtime.tokenRef)
	if err != nil {
		return "", err
	}
	if value.Version != runtime.tokenRef.Version || len(value.Bytes) == 0 {
		return "", errors.New("sealchat: token resolution is invalid")
	}
	return string(value.Bytes), nil
}

func sealChatDispatchFailure(wrote bool) adapterapi.EffectResult {
	if wrote {
		return adapterapi.AmbiguousResult("sealchat_provider_ambiguous", "provider dispatch outcome is unknown")
	}
	return adapterapi.TerminalResult("sealchat_provider_unavailable", "provider unavailable")
}

func sealChatResponseID(data json.RawMessage) string {
	var object struct {
		ID        string `json:"id"`
		MessageID string `json:"message_id"`
	}
	if json.Unmarshal(data, &object) == nil {
		if object.ID != "" {
			return object.ID
		}
		if object.MessageID != "" {
			return object.MessageID
		}
	}
	var objects []struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(data, &objects) == nil && len(objects) != 0 {
		return objects[0].ID
	}
	return ""
}

func (runtime *sealChatRuntime) callAPI(ctx context.Context, name string, data any) (json.RawMessage, bool, error) {
	runtime.mu.Lock()
	connection, runCtx, connected := runtime.conn, runtime.runCtx, runtime.connected
	runtime.mu.Unlock()
	if connection == nil || runCtx == nil || !connected {
		return nil, false, errors.New("sealchat: provider unavailable")
	}
	echo := "scardice-" + strconv.FormatUint(runtime.sequence.Add(1), 10)
	response := make(chan json.RawMessage, 1)
	runtime.pendingMu.Lock()
	runtime.pending[echo] = response
	runtime.pendingMu.Unlock()
	defer func() {
		runtime.pendingMu.Lock()
		delete(runtime.pending, echo)
		runtime.pendingMu.Unlock()
	}()
	runtime.writeMu.Lock()
	err := connection.WriteJSON(sealsatori.ScApiMsgPayload{Api: name, Echo: echo, Data: data})
	runtime.writeMu.Unlock()
	if err != nil {
		return nil, true, err
	}
	select {
	case payload := <-response:
		return payload, true, nil
	case <-ctx.Done():
		return nil, true, ctx.Err()
	case <-runCtx.Done():
		return nil, true, runCtx.Err()
	}
}

func (runtime *sealChatRuntime) Run(ctx context.Context, core adapterapi.CorePort) (runErr error) {
	if runtime == nil || core == nil {
		return errors.New("sealchat: runtime or core is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithCancel(ctx)
	runtime.mu.Lock()
	if runtime.cancel != nil {
		runtime.mu.Unlock()
		cancel()
		return errors.New("sealchat: runtime already started")
	}
	runtime.cancel, runtime.runCtx, runtime.running = cancel, runCtx, true
	runtime.mu.Unlock()
	defer func() {
		if runErr != nil && !errors.Is(runErr, context.Canceled) {
			_ = core.ReportObservation(context.Background(), adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateFailed, Code: "runtime_failed", Detail: "SealChat runtime failed", Retryable: true, OccurredAt: time.Now().UTC()})
		}
		_ = runtime.Stop(context.Background())
	}()
	if err := core.ReportObservation(runCtx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateStarting, Code: "starting", Detail: "SealChat runtime starting", OccurredAt: time.Now().UTC()}); err != nil {
		return err
	}
	token, err := runtime.resolveToken(runCtx)
	if err != nil {
		return err
	}
	connection, response, err := runtime.dialer.DialContext(runCtx, runtime.config.ConnectURL, nil)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		return err
	}
	connection.SetReadLimit(adapterapi.MaxInboundTextBytes + 64*1024)
	reads := make(chan sealChatReadResult, 1)
	runtime.mu.Lock()
	if !runtime.running {
		runtime.mu.Unlock()
		_ = connection.Close()
		return nil
	}
	runtime.conn = connection
	runtime.wg.Add(1)
	go runtime.readLoop(runCtx, connection, reads)
	runtime.mu.Unlock()
	runtime.writeMu.Lock()
	err = connection.WriteJSON(sealsatori.GatewayPayloadStructure{Op: sealsatori.OpIdentify, Body: map[string]string{"token": token}})
	runtime.writeMu.Unlock()
	if err != nil {
		return err
	}
	runtime.lastPong.Store(time.Now().Unix())
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-runCtx.Done():
			return nil
		case result := <-reads:
			if result.err != nil {
				if runCtx.Err() != nil {
					return nil
				}
				return result.err
			}
			if result.messageType != websocket.TextMessage {
				continue
			}
			if err := runtime.handleFrame(runCtx, core, result.data); err != nil {
				return err
			}
		case <-heartbeat.C:
			if time.Now().Unix()-runtime.lastPong.Load() > 45 {
				return errors.New("sealchat: heartbeat timed out")
			}
			runtime.writeMu.Lock()
			err := connection.WriteJSON(sealsatori.GatewayPayloadStructure{Op: sealsatori.OpPing, Body: map[string]any{}})
			runtime.writeMu.Unlock()
			if err != nil {
				return err
			}
		}
	}
}

func (runtime *sealChatRuntime) handleFrame(ctx context.Context, core adapterapi.CorePort, data []byte) error {
	var frame sealChatGatewayFrame
	if decodeErr := json.Unmarshal(data, &frame); decodeErr != nil {
		return fmt.Errorf("%w: %w", errSealChatInvalidGatewayPayload, decodeErr)
	}
	if frame.Echo != "" && len(frame.Data) != 0 {
		runtime.pendingMu.Lock()
		pending := runtime.pending[frame.Echo]
		runtime.pendingMu.Unlock()
		if pending != nil {
			select {
			case pending <- frame.Data:
			default:
			}
			return nil
		}
	}
	if frame.Op == nil {
		// A frame with an api name and an echo is an inbound provider request
		// (for example the SealChat character-card API); without an echo it is a
		// response to one of our own outbound requests.
		if frame.API != "" && frame.Echo != "" {
			return runtime.handleAPIRequest(ctx, core, frame.API, frame.Echo, frame.Data)
		}
		return nil
	}
	switch *frame.Op {
	case sealsatori.OpReady:
		return runtime.handleReady(ctx, core, frame.Body)
	case sealsatori.OpPing:
		runtime.mu.Lock()
		connection := runtime.conn
		runtime.mu.Unlock()
		if connection == nil {
			return nil
		}
		runtime.writeMu.Lock()
		err := connection.WriteJSON(sealsatori.GatewayPayloadStructure{Op: sealsatori.OpPong, Body: map[string]any{}})
		runtime.writeMu.Unlock()
		return err
	case sealsatori.OpPong:
		runtime.lastPong.Store(time.Now().Unix())
		return nil
	case sealsatori.OpEvent:
		return runtime.handleEvent(ctx, core, frame.Body)
	default:
		return nil
	}
}

func (runtime *sealChatRuntime) handleReady(ctx context.Context, core adapterapi.CorePort, body json.RawMessage) error {
	var ready sealChatReady
	if err := json.Unmarshal(body, &ready); err != nil {
		return err
	}
	if ready.ErrorMessage != "" {
		return fmt.Errorf("sealchat: provider rejected identity: %s", ready.ErrorMessage)
	}
	user := ready.User
	if user.ID == "" && len(ready.Logins) != 0 {
		user = ready.Logins[0].User
		if user.ID == "" {
			user.ID = ready.Logins[0].SelfID
		}
	}
	if user.ID == "" {
		return errors.New("sealchat: ready payload has no identity")
	}
	runtime.mu.Lock()
	if runtime.connected {
		runtime.mu.Unlock()
		return nil
	}
	runtime.connected, runtime.selfID = true, user.ID
	runtime.mu.Unlock()
	if err := core.ReportObservation(ctx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateConnected, Code: "connected", Detail: "SealChat gateway established", OccurredAt: time.Now().UTC()}); err != nil {
		return err
	}
	providerID, err := adapterapi.NewPrincipalID(FormatDiceIDSealChat(user.ID))
	if err != nil {
		return err
	}
	return core.ReportObservation(ctx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationIdentity, State: adapterapi.ObservedStateConnected, ProviderID: providerID, Code: "identity", OccurredAt: time.Now().UTC()})
}

func (runtime *sealChatRuntime) handleEvent(ctx context.Context, core adapterapi.CorePort, body json.RawMessage) error {
	var event sealsatori.Event
	if decodeErr := json.Unmarshal(body, &event); decodeErr != nil {
		return fmt.Errorf("%w: %w", errSealChatInvalidGatewayPayload, decodeErr)
	}
	if event.Message == nil {
		return nil
	}
	runtime.mu.Lock()
	selfID := runtime.selfID
	runtime.mu.Unlock()
	if event.Message.User != nil && event.Message.User.ID == selfID {
		return nil
	}
	inbound, err := sealChatInbound(&event)
	if err != nil {
		return fmt.Errorf("%w: %w", errSealChatInvalidGatewayPayload, err)
	}
	receipt, err := core.HandleInbound(ctx, inbound)
	if err != nil {
		return err
	}
	if err := receipt.Validate(); err != nil {
		return err
	}
	if receipt.Outcome == adapterapi.IngressRejected {
		return errors.New("sealchat: ingress rejected")
	}
	return nil
}

// sealChatCharacterAPINames maps SealChat's native character API names to the
// closed set of Core character operations.
var sealChatCharacterAPINames = map[string]adapterapi.CharacterOperation{
	"character.get":      adapterapi.CharacterOperationGet,
	"character.set":      adapterapi.CharacterOperationSet,
	"character.list":     adapterapi.CharacterOperationList,
	"character.new":      adapterapi.CharacterOperationNew,
	"character.save":     adapterapi.CharacterOperationSave,
	"character.tag":      adapterapi.CharacterOperationTag,
	"character.untagAll": adapterapi.CharacterOperationUntagAll,
	"character.load":     adapterapi.CharacterOperationLoad,
	"character.delete":   adapterapi.CharacterOperationDelete,
}

// sealChatCharacterWrite reports whether an operation mutates stored state and
// therefore consumes the legacy write rate limit. Reads (get/list) do not.
func sealChatCharacterWrite(operation adapterapi.CharacterOperation) bool {
	switch operation {
	case adapterapi.CharacterOperationGet, adapterapi.CharacterOperationList:
		return false
	default:
		return true
	}
}

// handleAPIRequest dispatches an inbound provider API request. Unknown API
// names are answered with an explicit failure so the provider is never left
// waiting for a response.
func (runtime *sealChatRuntime) handleAPIRequest(ctx context.Context, core adapterapi.CorePort, name string, echo string, data json.RawMessage) error {
	operation, known := sealChatCharacterAPINames[name]
	if !known {
		return runtime.sendAPIResponse(echo, map[string]any{"ok": false, "error": "unknown api: " + name})
	}
	// Writes are rate limited per runtime generation, matching the legacy
	// adapter's 60-writes-per-minute (burst 5) limiter.
	if sealChatCharacterWrite(operation) && runtime.characterLimiter != nil && !runtime.characterLimiter.Allow() {
		return runtime.sendAPIResponse(echo, map[string]any{"ok": false, "error": "rate limit exceeded: max 60 writes per minute"})
	}
	characterPort, ok := core.(adapterapi.CharacterCorePort)
	if !ok {
		return runtime.sendAPIResponse(echo, map[string]any{"ok": false, "error": "character api is unavailable"})
	}
	request, err := sealChatCharacterRequest(operation, data)
	if err != nil {
		return runtime.sendAPIResponse(echo, map[string]any{"ok": false, "error": err.Error()})
	}
	response, err := characterPort.HandleCharacter(ctx, request)
	if err != nil {
		return runtime.sendAPIResponse(echo, map[string]any{"ok": false, "error": err.Error()})
	}
	return runtime.sendAPIResponse(echo, sealChatCharacterResponsePayload(operation, response))
}

// sealChatCharacterRequest decodes a provider character request body into the
// closed, bounded Core DTO.
func sealChatCharacterRequest(operation adapterapi.CharacterOperation, data json.RawMessage) (adapterapi.CharacterRequest, error) {
	var payload struct {
		GroupID    string         `json:"group_id"`
		UserID     string         `json:"user_id"`
		ID         string         `json:"id"`
		Name       *string        `json:"name"`
		SheetType  *string        `json:"sheet_type"`
		Attributes map[string]any `json:"attrs"`
	}
	if len(data) != 0 {
		if err := json.Unmarshal(data, &payload); err != nil {
			return adapterapi.CharacterRequest{}, errors.New("invalid data format")
		}
	}
	request := adapterapi.CharacterRequest{
		Operation:  operation,
		UserID:     payload.UserID,
		GroupID:    payload.GroupID,
		Character:  payload.ID,
		Attributes: payload.Attributes,
		AttrsSet:   payload.Attributes != nil,
	}
	if payload.Name != nil {
		request.Name, request.NameSet = strings.TrimSpace(*payload.Name), true
	}
	if payload.SheetType != nil {
		request.SheetType, request.SheetSet = strings.TrimSpace(*payload.SheetType), true
	}
	return request, nil
}

// sealChatCharacterResponsePayload renders a Core character response back into
// the SealChat JSON shape expected by the provider client.
func sealChatCharacterResponsePayload(operation adapterapi.CharacterOperation, response adapterapi.CharacterResponse) map[string]any {
	if !response.OK {
		payload := map[string]any{"ok": false, "error": response.Error}
		if len(response.UnboundGroups) != 0 {
			payload["binding_groups"] = response.UnboundGroups
		}
		return payload
	}
	payload := map[string]any{"ok": true}
	if response.ID != "" {
		payload["id"] = response.ID
	}
	if response.Name != "" {
		payload["name"] = response.Name
	}
	if response.SheetType != "" {
		payload["sheet_type"] = response.SheetType
	}
	if response.AttributesSet {
		payload["data"] = response.Attributes
		payload["type"] = response.SheetType
	}
	if response.Action != "" {
		payload["action"] = response.Action
	}
	if response.BoundGroupID != "" {
		payload["bound_group_id"] = response.BoundGroupID
	}
	if len(response.UnboundGroups) != 0 || operation == adapterapi.CharacterOperationUntagAll {
		groups := response.UnboundGroups
		if groups == nil {
			groups = []string{}
		}
		payload["unbound_groups"] = groups
		payload["unbound_count"] = len(groups)
	}
	if response.List != nil {
		list := make([]map[string]any, 0, len(response.List))
		for _, item := range response.List {
			list = append(list, map[string]any{
				"id":         item.ID,
				"name":       item.Name,
				"sheet_type": item.SheetType,
				"updated_at": item.UpdatedAt,
			})
		}
		payload["list"] = list
	}
	return payload
}

func (runtime *sealChatRuntime) sendAPIResponse(echo string, data any) error {
	runtime.mu.Lock()
	connection, runCtx := runtime.conn, runtime.runCtx
	runtime.mu.Unlock()
	if connection == nil || runCtx == nil {
		return errors.New("sealchat: gateway is disconnected")
	}
	runtime.writeMu.Lock()
	defer runtime.writeMu.Unlock()
	return connection.WriteJSON(sealsatori.ScApiMsgPayload{Api: "", Echo: echo, Data: data})
}

func sealChatInbound(event *sealsatori.Event) (adapterapi.InboundMessage, error) {
	if event == nil || event.Message == nil || event.Message.ID == "" || event.Message.Channel == nil {
		return adapterapi.InboundMessage{}, errors.New("sealchat: incomplete message event")
	}
	var kind adapterapi.InboundKind
	switch event.Type {
	case sealsatori.EventMessageCreated:
		kind = adapterapi.InboundKindMessage
	case sealsatori.EventMessageUpdated:
		kind = adapterapi.InboundKindMessageUpdated
	case sealsatori.EventMessageDeleted:
		kind = adapterapi.InboundKindMessageDeleted
	default:
		return adapterapi.InboundMessage{}, errors.New("sealchat: unsupported message event")
	}
	message := event.Message
	conversation := FormatDiceIDSealChatGroup(message.Channel.ID)
	conversationKind := adapterapi.ConversationKindGroup
	if message.Channel.Type == sealsatori.DirectChannelType {
		conversationKind = adapterapi.ConversationKindDirect
		conversation = FormatDiceIDSealChatPrivate(message.Channel.ID)
	}
	providerEventID := fmt.Sprint(event.ID)
	if providerEventID == "<nil>" || providerEventID == "" {
		providerEventID = string(event.Type) + ":" + message.ID
	}
	inbound := adapterapi.InboundMessage{ProviderEventID: adapterapi.ProviderEventID(providerEventID), MessageID: adapterapi.MessageID(message.ID), Platform: "SEALCHAT", Conversation: adapterapi.ConversationID(conversation), ConversationKind: conversationKind, Target: conversation, Kind: kind, Text: sealChatDecodeContent(message.Content)}
	if message.User != nil && message.User.ID != "" {
		inbound.Sender = adapterapi.PrincipalID(FormatDiceIDSealChat(message.User.ID))
	}
	if message.Member != nil {
		inbound.SenderRole = sealChatSenderRole(message.Member.Roles)
	}
	if inbound.Text != "" {
		inbound.Segments = []adapterapi.InboundSegment{{Kind: "text", Text: inbound.Text}}
	}
	timestamp := message.Timestamp
	if timestamp == 0 {
		timestamp = int64(event.Timestamp)
	}
	if timestamp > 1_000_000_000_000 {
		inbound.OccurredAt = time.UnixMilli(timestamp).UTC()
	} else if timestamp > 0 {
		inbound.OccurredAt = time.Unix(timestamp, 0).UTC()
	}
	if err := inbound.Validate(); err != nil {
		return adapterapi.InboundMessage{}, err
	}
	return inbound, nil
}

// sealChatSenderRole maps provider member roles to the normalized inbound
// sender role, preserving the legacy role-name aliases. A present member with
// no recognized role is a plain member, matching the legacy adapter.
func sealChatSenderRole(roles []string) string {
	for _, role := range roles {
		switch strings.ToLower(strings.TrimSpace(role)) {
		case "owner", "群主", "creator":
			return "owner"
		case "admin", "管理员", "administrator", "moderator":
			return "admin"
		}
	}
	return "member"
}

func sealChatDecodeContent(content string) string {
	root := sealsatori.ElementParse(content)
	var output strings.Builder
	root.Traverse(func(element *sealsatori.Element) {
		switch element.Type {
		case "at":
			if element.Attrs["role"] != "all" {
				_, _ = fmt.Fprintf(&output, "<@%s>", element.Attrs["id"])
			}
		case "root":
		default:
			output.WriteString(element.ToString())
		}
	})
	return strings.TrimSpace(output.String())
}

func (runtime *sealChatRuntime) readLoop(ctx context.Context, connection *websocket.Conn, results chan<- sealChatReadResult) {
	defer runtime.wg.Done()
	for {
		messageType, data, err := connection.ReadMessage()
		select {
		case results <- sealChatReadResult{messageType: messageType, data: data, err: err}:
		case <-ctx.Done():
			return
		}
		if err != nil {
			return
		}
	}
}

func (runtime *sealChatRuntime) Stop(context.Context) error {
	if runtime == nil {
		return nil
	}
	runtime.mu.Lock()
	cancel := runtime.cancel
	runtime.cancel = nil
	runtime.runCtx = nil
	runtime.running = false
	runtime.connected = false
	connection := runtime.conn
	runtime.conn = nil
	runtime.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if connection != nil {
		runtime.writeMu.Lock()
		_ = connection.Close()
		runtime.writeMu.Unlock()
	}
	runtime.wg.Wait()
	return nil
}
