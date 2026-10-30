package dice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	milky "github.com/Szzrain/Milky-go-sdk"
	"github.com/gorilla/websocket"

	"Scardice-core/adapterapi"
)

const MilkyAdapterKey adapterapi.AdapterKey = "milky"

const maxMilkyWebSocketMessageBytes = adapterapi.MaxInboundTextBytes + 32*1024

type MilkyDescriptor struct{}

type milkyConfigInput struct {
	Version             json.RawMessage `json:"version"`
	WSGateway           string          `json:"ws_gateway"`
	RESTGateway         string          `json:"rest_gateway"`
	Token               json.RawMessage `json:"token"`
	BuiltInMode         string          `json:"built_in_mode"`
	Account             string          `json:"account"`
	AccountHint         string          `json:"account_hint"`
	SignServerURL       string          `json:"sign_server_url"`
	IgnoreFriendRequest bool            `json:"ignore_friend_request"`
}

type milkyCanonicalSecret struct {
	SecretRef string `json:"secretRef"`
	Version   uint64 `json:"version"`
}

type milkyCanonicalConfig struct {
	Version             string               `json:"version"`
	WSGateway           string               `json:"ws_gateway"`
	RESTGateway         string               `json:"rest_gateway"`
	Token               milkyCanonicalSecret `json:"token"`
	BuiltInMode         string               `json:"built_in_mode"`
	IgnoreFriendRequest bool                 `json:"ignore_friend_request"`
}

func NewMilkyDescriptor() adapterapi.Descriptor { return MilkyDescriptor{} }

func (MilkyDescriptor) Key() adapterapi.AdapterKey { return MilkyAdapterKey }

func (MilkyDescriptor) ConfigVersion() uint16 { return 1 }

func (MilkyDescriptor) SupportedActions(config adapterapi.ValidatedConfig) adapterapi.ActionSet {
	actions := adapterapi.ActionSet(0).With(
		adapterapi.ActionKindSendMessage,
		adapterapi.ActionKindSetGroupCard,
		adapterapi.ActionKindQuit,
		adapterapi.ActionKindGroupInfoRefresh,
	)
	if isBuiltinMilkyConfig(config) {
		actions = actions.With(adapterapi.ActionKindRequestQRCode)
	}
	return actions
}

func (MilkyDescriptor) Capabilities(config adapterapi.ValidatedConfig) adapterapi.CapabilitySet {
	capabilities := adapterapi.CapabilityLifecycle |
		adapterapi.CapabilityInbound |
		adapterapi.CapabilityOutbound |
		adapterapi.CapabilityActions |
		adapterapi.CapabilityRichMessages
	if isBuiltinMilkyConfig(config) {
		capabilities |= adapterapi.CapabilityArtifacts
	}
	return capabilities
}

func (MilkyDescriptor) ValidateConfig(ctx context.Context, raw json.RawMessage) (adapterapi.ValidatedConfig, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	var input milkyConfigInput
	if err := decodeStrictMilkyJSON(raw, &input); err != nil {
		return adapterapi.ValidatedConfig{}, fmt.Errorf("milky: invalid config: %w", err)
	}
	version, err := normalizeMilkyVersion(input.Version)
	if err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	if input.BuiltInMode != "" {
		return validateBuiltinMilkyConfig(ctx, input)
	}
	wsGateway, err := normalizeMilkyGateway(input.WSGateway, "ws", "wss")
	if err != nil {
		return adapterapi.ValidatedConfig{}, fmt.Errorf("milky: invalid websocket gateway: %w", err)
	}
	restGateway, err := normalizeMilkyGateway(input.RESTGateway, "http", "https")
	if err != nil {
		return adapterapi.ValidatedConfig{}, fmt.Errorf("milky: invalid REST gateway: %w", err)
	}
	var token milkyCanonicalSecret
	if decodeErr := decodeStrictMilkyJSON(input.Token, &token); decodeErr != nil || token.Version == 0 {
		return adapterapi.ValidatedConfig{}, errors.New("milky: invalid token reference")
	}
	ref := adapterapi.SecretRef{Ref: token.SecretRef, Version: token.Version}
	if validateErr := ref.Validate(); validateErr != nil {
		return adapterapi.ValidatedConfig{}, validateErr
	}
	encoded, err := json.Marshal(milkyCanonicalConfig{Version: version, WSGateway: wsGateway, RESTGateway: restGateway, Token: token, BuiltInMode: "", IgnoreFriendRequest: input.IgnoreFriendRequest})
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

func decodeStrictMilkyJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func normalizeMilkyVersion(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return "1.0", nil
	}
	var text string
	if json.Unmarshal(raw, &text) == nil && (text == "1" || text == "1.0") {
		return "1.0", nil
	}
	var number json.Number
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&number) == nil && (number.String() == "1" || number.String() == "1.0") {
		return "1.0", nil
	}
	return "", errors.New("milky: unsupported protocol version")
}

func normalizeMilkyGateway(raw string, allowed ...string) (string, error) {
	if raw == "" || strings.TrimSpace(raw) != raw {
		return "", errors.New("missing gateway")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return "", errors.New("malformed gateway")
	}
	validScheme := false
	for _, scheme := range allowed {
		validScheme = validScheme || parsed.Scheme == scheme
	}
	if !validScheme {
		return "", errors.New("unsupported gateway scheme")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	return parsed.String(), nil
}

func (descriptor MilkyDescriptor) NewRuntime(init adapterapi.RuntimeInit) (adapterapi.AdapterRuntime, error) {
	if !init.EndpointID.Valid() || init.Generation == 0 || init.DesiredVersion == 0 {
		return nil, errors.New("milky: runtime identity is incomplete")
	}
	if err := init.Config.Validate(); err != nil {
		return nil, err
	}
	validated, err := descriptor.ValidateConfig(context.Background(), init.Config.Canonical)
	if err != nil || validated.Version != init.Config.Version || !bytes.Equal(validated.Canonical, init.Config.Canonical) || len(validated.SecretRefs) != len(init.Config.SecretRefs) {
		return nil, errors.New("milky: runtime config was not validated by descriptor")
	}
	for index := range validated.SecretRefs {
		if validated.SecretRefs[index] != init.Config.SecretRefs[index] {
			return nil, errors.New("milky: runtime secret references do not match")
		}
	}
	var config milkyCanonicalConfig
	if err := json.Unmarshal(init.Config.Canonical, &config); err != nil {
		return nil, errors.New("milky: invalid canonical runtime config")
	}
	if builtin, builtinErr := decodeBuiltinMilkyCanonical(init.Config); builtinErr == nil {
		return newBuiltinMilkyRuntime(init, builtin), nil
	}
	return &milkyRuntime{
		config:     config,
		tokenRef:   adapterapi.SecretRef{Ref: config.Token.SecretRef, Version: config.Token.Version},
		resolver:   init.Secrets,
		httpClient: &http.Client{Timeout: 20 * time.Second},
		dialer:     websocket.DefaultDialer,
	}, nil
}

type milkyRuntime struct {
	config     milkyCanonicalConfig
	tokenRef   adapterapi.SecretRef
	resolver   adapterapi.SecretResolver
	httpClient *http.Client
	dialer     *websocket.Dialer

	mu      sync.Mutex
	cancel  context.CancelFunc
	conn    *websocket.Conn
	wg      sync.WaitGroup
	running bool
	token   string
	selfID  int64
}

type milkyReadResult struct {
	messageType int
	data        []byte
	err         error
}

type milkyGroupInfoResult struct {
	GroupID        int64  `json:"group_id"`
	Name           string `json:"group_name"`
	MemberCount    *int32 `json:"member_count"`
	MaxMemberCount *int32 `json:"max_member_count"`
}

func (*milkyRuntime) OwnedResources() adapterapi.OwnedResourceManifest {
	return adapterapi.OwnedResourceManifest{}
}

func (*milkyRuntime) Capabilities() adapterapi.CapabilitySet {
	return adapterapi.CapabilityLifecycle |
		adapterapi.CapabilityInbound |
		adapterapi.CapabilityOutbound |
		adapterapi.CapabilityActions |
		adapterapi.CapabilityRichMessages
}

func milkyRuntimeSupportedActions() adapterapi.ActionSet {
	return adapterapi.ActionSet(0).With(
		adapterapi.ActionKindSendMessage,
		adapterapi.ActionKindSetGroupCard,
		adapterapi.ActionKindQuit,
		adapterapi.ActionKindGroupInfoRefresh,
	)
}

func (runtime *milkyRuntime) Execute(ctx context.Context, effect adapterapi.OutboundEffect) adapterapi.EffectResult {
	if runtime == nil {
		return adapterapi.TerminalResult("milky_provider_unavailable", "provider unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if effect.Version != adapterapi.EffectVersionOne {
		return adapterapi.UnsupportedResult("milky_invalid_effect_version")
	}
	if err := effect.ValidateForCapabilities(runtime.Capabilities(), milkyRuntimeSupportedActions()); err != nil {
		return adapterapi.UnsupportedResult("milky_effect_not_supported")
	}
	for _, segment := range effect.Payload.Segments {
		if segment.Artifact != nil {
			return adapterapi.UnsupportedResult("milky_artifact_reader_unavailable")
		}
	}
	runtime.mu.Lock()
	token := runtime.token
	connected := runtime.selfID > 0
	runtime.mu.Unlock()
	if !connected {
		return adapterapi.TerminalResult("milky_provider_unavailable", "provider unavailable")
	}
	payload := effect.Payload
	switch payload.Kind {
	case adapterapi.EffectPayloadPersonText, adapterapi.EffectPayloadGroupText, adapterapi.EffectPayloadSegments:
		group := payload.Target.Kind == adapterapi.TargetGroup
		target, err := milkyTargetID(payload.Target, group)
		if err != nil {
			return adapterapi.UnsupportedResult("milky_invalid_target")
		}
		message, err := milkyOutboundSegments(payload)
		if err != nil {
			return adapterapi.UnsupportedResult("milky_unsupported_segment")
		}
		path := "send_private_message"
		body := map[string]any{"user_id": target, "message": message}
		if group {
			path = "send_group_message"
			body = map[string]any{"group_id": target, "message": message}
		}
		data, err := runtime.request(ctx, token, path, body)
		if err != nil {
			return adapterapi.AmbiguousResult("milky_provider_ambiguous", "provider dispatch outcome is unknown")
		}
		var result milky.MessageRet
		if err := json.Unmarshal(data, &result); err != nil || result.MessageSeq <= 0 {
			return adapterapi.TerminalResult("milky_invalid_response", "provider returned an invalid response")
		}
		return adapterapi.SucceededResult(strconv.FormatInt(result.MessageSeq, 10))
	case adapterapi.EffectPayloadSetGroupCard:
		groupID, err := milkyTargetID(payload.Target, true)
		if err != nil {
			return adapterapi.UnsupportedResult("milky_invalid_target")
		}
		memberID, err := milkyTargetID(adapterapi.EffectTarget{
			Kind:         adapterapi.TargetPerson,
			Conversation: adapterapi.ConversationID(payload.Target.Member),
		}, false)
		if err != nil {
			return adapterapi.UnsupportedResult("milky_invalid_member")
		}
		_, err = runtime.request(ctx, token, "set_group_member_card", map[string]any{
			"group_id": groupID,
			"user_id":  memberID,
			"card":     payload.Card,
		})
		if err != nil {
			return adapterapi.AmbiguousResult("milky_provider_ambiguous", "provider dispatch outcome is unknown")
		}
		return adapterapi.SucceededResult("")
	case adapterapi.EffectPayloadQuit:
		groupID, err := milkyTargetID(payload.Target, true)
		if err != nil {
			return adapterapi.UnsupportedResult("milky_invalid_target")
		}
		_, err = runtime.request(ctx, token, "quit_group", map[string]any{"group_id": groupID})
		if err != nil {
			return adapterapi.AmbiguousResult("milky_provider_ambiguous", "provider dispatch outcome is unknown")
		}
		return adapterapi.SucceededResult("")
	case adapterapi.EffectPayloadGroupInfoRefresh:
		groupID, err := milkyTargetID(payload.Target, true)
		if err != nil {
			return adapterapi.UnsupportedResult("milky_invalid_target")
		}
		data, err := runtime.request(ctx, token, "get_group_info", map[string]any{
			"group_id": groupID,
			"no_cache": true,
		})
		if err != nil {
			return adapterapi.RetryableResult("milky_group_info_refresh_failed", "provider group info refresh failed")
		}
		var info milkyGroupInfoResult
		if err := json.Unmarshal(data, &info); err != nil || info.GroupID != groupID ||
			(info.MemberCount != nil && *info.MemberCount < 0) ||
			(info.MaxMemberCount != nil && *info.MaxMemberCount < 0) {
			return adapterapi.TerminalResult("milky_invalid_response", "provider returned invalid group info")
		}
		observation := adapterapi.GroupInfoResult{
			Conversation:        payload.Target.Conversation,
			Name:                info.Name,
			MemberCountKnown:    info.MemberCount != nil,
			MaxMemberCountKnown: info.MaxMemberCount != nil,
		}
		if info.MemberCount != nil {
			observation.MemberCount = uint32(*info.MemberCount)
		}
		if info.MaxMemberCount != nil {
			observation.MaxMemberCount = uint32(*info.MaxMemberCount)
		}
		if err := observation.ValidateForTarget(payload.Target); err != nil {
			return adapterapi.TerminalResult("milky_invalid_response", "provider returned invalid group info")
		}
		return adapterapi.SucceededGroupInfoResult(observation)
	default:
		return adapterapi.UnsupportedResult("milky_effect_not_supported")
	}
}

func milkyOutboundSegments(payload adapterapi.EffectPayload) ([]milky.IMessageElement, error) {
	if payload.Kind == adapterapi.EffectPayloadPersonText || payload.Kind == adapterapi.EffectPayloadGroupText {
		return []milky.IMessageElement{&milky.TextElement{Text: payload.Text}}, nil
	}
	segments := make([]milky.IMessageElement, 0, len(payload.Segments))
	for _, segment := range payload.Segments {
		switch segment.Kind {
		case adapterapi.SegmentKindText:
			segments = append(segments, &milky.TextElement{Text: segment.Text})
		case adapterapi.SegmentKindMention:
			if segment.Text == "all" || segment.Text == "QQ:all" {
				segments = append(segments, &milky.AtAllElement{})
				continue
			}
			userID, err := onebotPersonID(segment.Text)
			if err != nil {
				return nil, err
			}
			segments = append(segments, &milky.AtElement{UserID: userID})
		case adapterapi.SegmentKindImage, adapterapi.SegmentKindFile:
			return nil, errors.New("milky: artifact segment cannot be resolved")
		default:
			return nil, errors.New("milky: unsupported message segment")
		}
	}
	if len(segments) == 0 {
		return nil, errors.New("milky: empty message")
	}
	return segments, nil
}

func (*milkyRuntime) Diagnostics(context.Context) adapterapi.DiagnosticReport {
	return adapterapi.DiagnosticReport{}
}

func milkyTargetID(target adapterapi.EffectTarget, group bool) (int64, error) {
	if group {
		if target.Kind != adapterapi.TargetGroup {
			return 0, errors.New("milky: group target kind mismatch")
		}
		return onebotNumericID(target.Conversation.String(), true)
	}
	if target.Kind != adapterapi.TargetPerson {
		return 0, errors.New("milky: person target kind mismatch")
	}
	return onebotPersonID(target.Conversation.String())
}

func (runtime *milkyRuntime) resolveToken(ctx context.Context) (string, error) {
	if runtime == nil {
		return "", errors.New("milky: runtime is unavailable")
	}
	if runtime.tokenRef.Ref == "" {
		return "", nil
	}
	if runtime.resolver == nil {
		return "", errors.New("milky: token resolver is unavailable")
	}
	value, err := runtime.resolver.Resolve(ctx, runtime.tokenRef)
	if err != nil {
		return "", err
	}
	if value.Version != runtime.tokenRef.Version || len(value.Bytes) == 0 {
		return "", errors.New("milky: token resolution is invalid")
	}
	return string(value.Bytes), nil
}

func (runtime *milkyRuntime) Run(ctx context.Context, core adapterapi.CorePort) (runErr error) {
	if runtime == nil || core == nil {
		return errors.New("milky: runtime or core is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithCancel(ctx)
	runtime.mu.Lock()
	if runtime.running {
		runtime.mu.Unlock()
		cancel()
		return errors.New("milky: runtime already started")
	}
	runtime.running = true
	runtime.cancel = cancel
	runtime.mu.Unlock()
	defer func() {
		if runErr != nil && !errors.Is(runErr, context.Canceled) {
			_ = core.ReportObservation(context.Background(), adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateFailed, Code: "runtime_failed", Detail: "Milky runtime failed", Retryable: true, OccurredAt: time.Now().UTC()})
		}
		_ = runtime.Stop(context.Background())
	}()
	if err := core.ReportObservation(runCtx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateStarting, Code: "starting", Detail: "Milky runtime starting", OccurredAt: time.Now().UTC()}); err != nil {
		return err
	}
	token, err := runtime.resolveToken(runCtx)
	if err != nil {
		return err
	}
	gateway, err := url.Parse(runtime.config.WSGateway)
	if err != nil {
		return err
	}
	query := gateway.Query()
	query.Set("access_token", token)
	gateway.RawQuery = query.Encode()
	connection, response, err := runtime.dialer.DialContext(runCtx, gateway.String(), nil)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		return err
	}
	connection.SetReadLimit(maxMilkyWebSocketMessageBytes)
	runtime.mu.Lock()
	if !runtime.running {
		runtime.mu.Unlock()
		_ = connection.Close()
		return nil
	}
	runtime.conn = connection
	runtime.token = token
	runtime.mu.Unlock()
	login, err := runtime.getLoginInfo(runCtx, token)
	if err != nil {
		return err
	}
	reads := make(chan milkyReadResult, 1)
	runtime.mu.Lock()
	if !runtime.running {
		runtime.mu.Unlock()
		return nil
	}
	runtime.selfID = login.UIN
	runtime.wg.Add(1)
	runtime.mu.Unlock()
	go runtime.readLoop(runCtx, connection, reads)
	if reportErr := core.ReportObservation(runCtx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateConnected, Code: "connected", Detail: "Milky connection established", OccurredAt: time.Now().UTC()}); reportErr != nil {
		return reportErr
	}
	providerID, err := adapterapi.NewPrincipalID(FormatDiceIDQQ(strconv.FormatInt(login.UIN, 10)))
	if err != nil {
		return err
	}
	if err := core.ReportObservation(runCtx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationIdentity, State: adapterapi.ObservedStateConnected, ProviderID: providerID, Code: "identity", Detail: login.Nickname, OccurredAt: time.Now().UTC()}); err != nil {
		return err
	}
	heartbeat := time.NewTicker(40 * time.Second)
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
			if result.messageType != websocket.TextMessage && result.messageType != websocket.BinaryMessage {
				continue
			}
			if err := runtime.handleWireEvent(runCtx, core, result.data); err != nil {
				return err
			}
		case <-heartbeat.C:
			if err := connection.WriteJSON(map[string]any{"op": 1, "d": 0}); err != nil {
				return err
			}
		}
	}
}

func (runtime *milkyRuntime) getLoginInfo(ctx context.Context, token string) (*milky.LoginInfo, error) {
	data, err := runtime.request(ctx, token, "get_login_info", struct{}{})
	if err != nil {
		return nil, err
	}
	var login milky.LoginInfo
	if err := json.Unmarshal(data, &login); err != nil || login.UIN <= 0 {
		return nil, errors.New("milky: invalid login response")
	}
	return &login, nil
}

func (runtime *milkyRuntime) request(ctx context.Context, token, path string, body any) (json.RawMessage, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, runtime.config.RESTGateway+"/"+path, bytes.NewReader(encoded))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := runtime.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("milky: provider HTTP status %d", response.StatusCode)
	}
	var envelope struct {
		Status  string          `json:"status"`
		RetCode int             `json:"retcode"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&envelope); err != nil {
		return nil, err
	}
	if envelope.Status != "ok" || envelope.RetCode != 0 {
		return nil, errors.New("milky: provider rejected request")
	}
	return envelope.Data, nil
}

func (runtime *milkyRuntime) readLoop(ctx context.Context, connection *websocket.Conn, results chan<- milkyReadResult) {
	defer runtime.wg.Done()
	for {
		messageType, data, err := connection.ReadMessage()
		select {
		case results <- milkyReadResult{messageType: messageType, data: data, err: err}:
		case <-ctx.Done():
			return
		}
		if err != nil {
			return
		}
	}
}

func (*milkyRuntime) handleWireEvent(ctx context.Context, core adapterapi.CorePort, data []byte) error {
	var event struct {
		Type string          `json:"event_type"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(data, &event); err != nil {
		return err
	}
	var inbound adapterapi.InboundMessage
	var err error
	switch event.Type {
	case "message_receive":
		var message milky.ReceiveMessage
		if decodeErr := json.Unmarshal(event.Data, &message); decodeErr != nil {
			return decodeErr
		}
		inbound, err = milkyMessageInbound(&message)
	case "message_recall":
		var recall milky.MessageRecall
		if decodeErr := json.Unmarshal(event.Data, &recall); decodeErr != nil {
			return decodeErr
		}
		inbound, err = milkyRecallInbound(&recall)
	default:
		return nil
	}
	if err != nil {
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
		return errors.New("milky: ingress rejected")
	}
	return nil
}

func (runtime *milkyRuntime) Stop(context.Context) error {
	if runtime == nil {
		return nil
	}
	runtime.mu.Lock()
	cancel := runtime.cancel
	runtime.cancel = nil
	runtime.running = false
	connection := runtime.conn
	runtime.conn = nil
	runtime.token = ""
	runtime.selfID = 0
	runtime.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if connection != nil {
		_ = connection.Close()
	}
	runtime.wg.Wait()
	return nil
}

func milkyMessageInbound(message *milky.ReceiveMessage) (adapterapi.InboundMessage, error) {
	if message == nil || message.PeerId <= 0 || message.SenderId <= 0 || message.MessageSeq <= 0 {
		return adapterapi.InboundMessage{}, errors.New("milky: incomplete message event")
	}
	var conversation string
	conversationKind := adapterapi.ConversationKindDirect
	switch message.MessageScene {
	case "group":
		conversationKind = adapterapi.ConversationKindGroup
		conversation = FormatDiceIDQQGroup(strconv.FormatInt(message.PeerId, 10))
	case "friend":
		conversation = FormatDiceIDQQ(strconv.FormatInt(message.PeerId, 10))
	default:
		return adapterapi.InboundMessage{}, errors.New("milky: unsupported message scene")
	}
	segments := make([]adapterapi.InboundSegment, 0, len(message.Segments))
	var text strings.Builder
	for _, element := range message.Segments {
		switch segment := element.(type) {
		case *milky.TextElement:
			if segment == nil || segment.Text == "" {
				continue
			}
			text.WriteString(segment.Text)
			segments = append(segments, adapterapi.InboundSegment{Kind: "text", Text: segment.Text})
		case *milky.AtElement:
			if segment != nil && segment.UserID > 0 {
				segments = append(segments, adapterapi.InboundSegment{Kind: "mention", ProviderID: FormatDiceIDQQ(strconv.FormatInt(segment.UserID, 10))})
			}
		case *milky.AtAllElement:
			segments = append(segments, adapterapi.InboundSegment{Kind: "mention_all"})
		case *milky.ImageElement:
			if segment != nil && segment.TempURL != "" {
				segments = append(segments, adapterapi.InboundSegment{Kind: "image", URL: segment.TempURL})
			}
		case *milky.ReplyElement:
			if segment != nil && segment.MessageSeq > 0 {
				segments = append(segments, adapterapi.InboundSegment{Kind: "reply", ProviderID: strconv.FormatInt(segment.MessageSeq, 10)})
			}
		}
	}
	sequence := strconv.FormatInt(message.MessageSeq, 10)
	inbound := adapterapi.InboundMessage{
		ProviderEventID:  adapterapi.ProviderEventID("milky-message:" + message.MessageScene + ":" + strconv.FormatInt(message.PeerId, 10) + ":" + sequence),
		MessageID:        adapterapi.MessageID(sequence),
		Platform:         "QQ",
		Sender:           adapterapi.PrincipalID(FormatDiceIDQQ(strconv.FormatInt(message.SenderId, 10))),
		Conversation:     adapterapi.ConversationID(conversation),
		ConversationKind: conversationKind,
		Target:           conversation,
		Kind:             adapterapi.InboundKindMessage,
		Text:             text.String(),
		Segments:         segments,
	}
	// Group role is a member-of-group fact; it is only meaningful for group
	// scenes, matching the legacy adapter which read GroupMember.Role solely
	// under the "group" branch.
	if conversationKind == adapterapi.ConversationKindGroup && message.GroupMember != nil {
		inbound.SenderRole = normalizeGroupSenderRole(message.GroupMember.Role)
	}
	if message.Time > 0 {
		inbound.OccurredAt = time.Unix(message.Time, 0).UTC()
	}
	if err := inbound.Validate(); err != nil {
		return adapterapi.InboundMessage{}, err
	}
	return inbound, nil
}

func milkyRecallInbound(recall *milky.MessageRecall) (adapterapi.InboundMessage, error) {
	if recall == nil || recall.PeerID <= 0 || recall.MessageSeq <= 0 || recall.SenderID <= 0 {
		return adapterapi.InboundMessage{}, errors.New("milky: incomplete message recall event")
	}
	var conversation string
	conversationKind := adapterapi.ConversationKindDirect
	switch recall.MessageScene {
	case "group":
		conversationKind = adapterapi.ConversationKindGroup
		conversation = FormatDiceIDQQGroup(strconv.FormatInt(recall.PeerID, 10))
	case "friend":
		conversation = FormatDiceIDQQ(strconv.FormatInt(recall.PeerID, 10))
	default:
		return adapterapi.InboundMessage{}, errors.New("milky: unsupported recall scene")
	}
	sequence := strconv.FormatInt(recall.MessageSeq, 10)
	inbound := adapterapi.InboundMessage{
		ProviderEventID:  adapterapi.ProviderEventID("milky-recall:" + recall.MessageScene + ":" + strconv.FormatInt(recall.PeerID, 10) + ":" + sequence),
		MessageID:        adapterapi.MessageID(sequence),
		Platform:         "QQ",
		Sender:           adapterapi.PrincipalID(FormatDiceIDQQ(strconv.FormatInt(recall.SenderID, 10))),
		Conversation:     adapterapi.ConversationID(conversation),
		ConversationKind: conversationKind,
		Target:           conversation,
		Kind:             adapterapi.InboundKindMessageDeleted,
	}
	if err := inbound.Validate(); err != nil {
		return adapterapi.InboundMessage{}, err
	}
	return inbound, nil
}
