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
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"Scardice-core/adapterapi"
)

const DodoAdapterKey adapterapi.AdapterKey = "dodo"

type DodoDescriptor struct{}

type dodoConfigInput struct {
	IslandID   string          `json:"islandId"`
	BotID      string          `json:"botId"`
	ClientID   string          `json:"clientID"`
	APIBaseURL string          `json:"apiBaseURL"`
	Token      json.RawMessage `json:"token"`
}

type dodoCanonicalConfig struct {
	IslandID   string                  `json:"islandId"`
	BotID      string                  `json:"botId"`
	ClientID   string                  `json:"clientID"`
	APIBaseURL string                  `json:"apiBaseURL"`
	Token      providerCanonicalSecret `json:"token"`
}

type dodoRuntime struct {
	config   dodoCanonicalConfig
	tokenRef adapterapi.SecretRef
	resolver adapterapi.SecretResolver

	mu         sync.Mutex
	cancel     context.CancelFunc
	conn       *websocket.Conn
	wg         sync.WaitGroup
	running    bool
	token      string
	selfID     string
	httpClient *http.Client
	dialer     *websocket.Dialer
}

type dodoReadResult struct {
	messageType int
	data        []byte
	err         error
}

type dodoEnvelope struct {
	Status  int             `json:"status"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

type dodoWireMessage struct {
	Type int             `json:"type"`
	Data json.RawMessage `json:"data"`
}

type dodoEvent struct {
	EventID   string          `json:"eventId"`
	EventType string          `json:"eventType"`
	EventBody json.RawMessage `json:"eventBody"`
	Timestamp int64           `json:"timestamp"`
}

type dodoMessageBody struct {
	IslandID    string          `json:"islandSourceId"`
	ChannelID   string          `json:"channelId"`
	UserID      string          `json:"dodoSourceId"`
	MessageID   string          `json:"messageId"`
	MessageType int             `json:"messageType"`
	MessageBody json.RawMessage `json:"messageBody"`
}
type dodoCardMessage struct {
	Content string       `json:"content,omitempty"`
	Card    dodoCardBody `json:"card"`
}

type dodoCardBody struct {
	Type       string        `json:"type"`
	Components []interface{} `json:"components"`
	Theme      string        `json:"theme"`
	Title      string        `json:"title,omitempty"`
}

type dodoCardTextComponent struct {
	Type string           `json:"type"`
	Text dodoCardTextBody `json:"text"`
}

type dodoCardTextBody struct {
	Content string `json:"content"`
	Type    string `json:"type"`
}

var dodoURLPattern = regexp.MustCompile(`\b(http://www\.|https://www\.|http://|https://)?[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,5}(:[0-9]{1,5})?(/[a-zA-Z0-9#]+[\w\-./?%&=]*)?\b`)

func dodoConvertLinksToMarkdown(text string) string {
	return dodoURLPattern.ReplaceAllStringFunc(text, func(match string) string {
		return "[" + match + "](" + match + ")"
	})
}

func dodoCardFromText(text string) dodoCardMessage {
	return dodoCardMessage{
		Card: dodoCardBody{
			Type:  "card",
			Theme: "default",
			Components: []interface{}{
				dodoCardTextComponent{
					Type: "section",
					Text: dodoCardTextBody{Content: dodoConvertLinksToMarkdown(text), Type: "dodo-md"},
				},
			},
		},
	}
}

func dodoCardFromSegments(segments []adapterapi.MessageSegment) (dodoCardMessage, error) {
	components := make([]interface{}, 0, len(segments))
	for _, segment := range segments {
		var text string
		switch segment.Kind {
		case adapterapi.SegmentKindText:
			text = dodoConvertLinksToMarkdown(segment.Text)
		case adapterapi.SegmentKindMention:
			text = "<@!" + ExtractDodoUserID(segment.Text) + ">"
		case adapterapi.SegmentKindImage, adapterapi.SegmentKindFile:
			return dodoCardMessage{}, errors.New("dodo_artifact_reader_unavailable")
		default:
			return dodoCardMessage{}, errors.New("dodo_unknown_segment")
		}
		components = append(components, dodoCardTextComponent{
			Type: "section",
			Text: dodoCardTextBody{Content: text, Type: "dodo-md"},
		})
	}
	if len(components) == 0 {
		return dodoCardMessage{}, errors.New("dodo_empty_segments")
	}
	return dodoCardMessage{Card: dodoCardBody{Type: "card", Theme: "default", Components: components}}, nil
}

func NewDodoDescriptor() adapterapi.Descriptor { return DodoDescriptor{} }

func (DodoDescriptor) Key() adapterapi.AdapterKey { return DodoAdapterKey }

func (DodoDescriptor) ConfigVersion() uint16 { return 1 }
func FormatDiceIDDodo(id string) string {
	return fmt.Sprintf("DODO:%s", id)
}

func FormatDiceIDDodoGroup(id string) string {
	return fmt.Sprintf("DODO-Group:%s", id)
}

func ExtractDodoUserID(id string) string {
	return strings.TrimPrefix(id, "DODO:")
}

func ExtractDodoGroupID(id string) string {
	return strings.TrimPrefix(id, "DODO-Group:")
}

func dodoSupportedActions() adapterapi.ActionSet {
	return adapterapi.ActionSet(0).With(
		adapterapi.ActionKindSendMessage,
		adapterapi.ActionKindSetGroupCard,
		adapterapi.ActionKindQuit,
		adapterapi.ActionKindGroupInfoRefresh,
	)
}

func (DodoDescriptor) SupportedActions(adapterapi.ValidatedConfig) adapterapi.ActionSet {
	return dodoSupportedActions()
}

func (DodoDescriptor) Capabilities(adapterapi.ValidatedConfig) adapterapi.CapabilitySet {
	return adapterapi.CapabilityLifecycle | adapterapi.CapabilityInbound | adapterapi.CapabilityOutbound | adapterapi.CapabilityActions | adapterapi.CapabilityRichMessages
}

func (DodoDescriptor) ValidateConfig(ctx context.Context, raw json.RawMessage) (adapterapi.ValidatedConfig, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	var input dodoConfigInput
	if err := decodeStrictProviderJSON(raw, &input); err != nil {
		return adapterapi.ValidatedConfig{}, fmt.Errorf("dodo: invalid config: %w", err)
	}
	input.ClientID = strings.TrimSpace(input.ClientID)
	if input.ClientID == "" {
		return adapterapi.ValidatedConfig{}, errors.New("dodo: clientID is required")
	}
	var token providerCanonicalSecret
	if err := decodeStrictProviderJSON(input.Token, &token); err != nil || token.Version == 0 {
		return adapterapi.ValidatedConfig{}, errors.New("dodo: invalid token reference")
	}
	ref := adapterapi.SecretRef{Ref: token.SecretRef, Version: token.Version}
	if err := ref.Validate(); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	apiBaseURL, err := normalizeProviderHTTPURL(input.APIBaseURL, true)
	if err != nil {
		return adapterapi.ValidatedConfig{}, fmt.Errorf("dodo: invalid apiBaseURL: %w", err)
	}
	encoded, err := json.Marshal(dodoCanonicalConfig{IslandID: strings.TrimSpace(input.IslandID), BotID: strings.TrimSpace(input.BotID), ClientID: input.ClientID, APIBaseURL: apiBaseURL, Token: token})
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

func (descriptor DodoDescriptor) NewRuntime(init adapterapi.RuntimeInit) (adapterapi.AdapterRuntime, error) {
	if !init.EndpointID.Valid() || init.Generation == 0 || init.DesiredVersion == 0 {
		return nil, errors.New("dodo: runtime identity is incomplete")
	}
	if err := init.Config.Validate(); err != nil {
		return nil, err
	}
	validated, err := descriptor.ValidateConfig(context.Background(), init.Config.Canonical)
	if err != nil || validated.Version != init.Config.Version || !bytes.Equal(validated.Canonical, init.Config.Canonical) || len(validated.SecretRefs) != len(init.Config.SecretRefs) {
		return nil, errors.New("dodo: runtime config was not validated by descriptor")
	}
	for index := range validated.SecretRefs {
		if validated.SecretRefs[index] != init.Config.SecretRefs[index] {
			return nil, errors.New("dodo: runtime secret references do not match")
		}
	}
	var config dodoCanonicalConfig
	if err := json.Unmarshal(init.Config.Canonical, &config); err != nil {
		return nil, errors.New("dodo: invalid canonical runtime config")
	}
	return &dodoRuntime{config: config, tokenRef: validated.SecretRefs[0], resolver: init.Secrets, httpClient: &http.Client{Timeout: 20 * time.Second}, dialer: websocket.DefaultDialer}, nil
}

func (*dodoRuntime) OwnedResources() adapterapi.OwnedResourceManifest {
	return adapterapi.OwnedResourceManifest{}
}

func (*dodoRuntime) Capabilities() adapterapi.CapabilitySet {
	return adapterapi.CapabilityLifecycle | adapterapi.CapabilityInbound | adapterapi.CapabilityOutbound | adapterapi.CapabilityActions | adapterapi.CapabilityRichMessages
}

func (*dodoRuntime) Diagnostics(context.Context) adapterapi.DiagnosticReport {
	return adapterapi.DiagnosticReport{}
}

func (runtime *dodoRuntime) Execute(ctx context.Context, effect adapterapi.OutboundEffect) adapterapi.EffectResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if effect.Version != adapterapi.EffectVersionOne {
		return adapterapi.UnsupportedResult("dodo_invalid_effect_version")
	}
	if err := effect.ValidateForCapabilities(runtime.Capabilities(), dodoSupportedActions()); err != nil {
		return adapterapi.UnsupportedResult("dodo_effect_not_supported")
	}
	runtime.mu.Lock()
	token, selfID := runtime.token, runtime.selfID
	runtime.mu.Unlock()
	if token == "" || selfID == "" {
		return adapterapi.TerminalResult("dodo_provider_unavailable", "provider unavailable")
	}
	payload := effect.Payload
	switch payload.Kind {
	case adapterapi.EffectPayloadSetGroupCard, adapterapi.EffectPayloadQuit, adapterapi.EffectPayloadGroupInfoRefresh:
		if payload.Target.Kind != adapterapi.TargetGroup {
			return adapterapi.UnsupportedResult("dodo_invalid_target")
		}
		channelID := strings.TrimPrefix(payload.Target.Conversation.String(), "DODO-Group:")
		if channelID == payload.Target.Conversation.String() || channelID == "" {
			return adapterapi.UnsupportedResult("dodo_invalid_target")
		}
		info, err := runtime.channelInfo(ctx, token, channelID)
		if err != nil {
			return adapterapi.AmbiguousResult("dodo_provider_ambiguous", "provider dispatch outcome is unknown")
		}
		switch payload.Kind {
		case adapterapi.EffectPayloadGroupInfoRefresh:
			if info.ChannelID == "" {
				return adapterapi.TerminalResult("dodo_invalid_response", "provider returned an invalid response")
			}
			return adapterapi.SucceededResult(info.ChannelID)
		case adapterapi.EffectPayloadQuit:
			islandID := info.IslandID
			if islandID == "" {
				islandID = runtime.config.IslandID
			}
			if islandID == "" {
				return adapterapi.TerminalResult("dodo_invalid_response", "provider returned an invalid channel response")
			}
			if _, err := runtime.request(ctx, token, "/api/v2/bot/island/leave", map[string]string{"islandSourceId": islandID}); err != nil {
				return adapterapi.AmbiguousResult("dodo_provider_ambiguous", "provider dispatch outcome is unknown")
			}
			return adapterapi.SucceededResult("")
		case adapterapi.EffectPayloadSetGroupCard:
			memberID := ExtractDodoUserID(string(payload.Target.Member))
			islandID := info.IslandID
			if islandID == "" {
				islandID = runtime.config.IslandID
			}
			if memberID == "" || islandID == "" {
				return adapterapi.UnsupportedResult("dodo_invalid_target")
			}
			if _, err := runtime.request(ctx, token, "/api/v2/member/nickname/edit", map[string]string{"islandSourceId": islandID, "dodoSourceId": memberID, "nickName": payload.Card}); err != nil {
				return adapterapi.AmbiguousResult("dodo_provider_ambiguous", "provider dispatch outcome is unknown")
			}
			return adapterapi.SucceededResult("")
		default:
			return adapterapi.UnsupportedResult("dodo_effect_not_supported")
		}
	case adapterapi.EffectPayloadGroupText:
		if payload.Target.Kind != adapterapi.TargetGroup {
			return adapterapi.UnsupportedResult("dodo_invalid_target")
		}
		channelID := strings.TrimPrefix(payload.Target.Conversation.String(), "DODO-Group:")
		if channelID == payload.Target.Conversation.String() || channelID == "" {
			return adapterapi.UnsupportedResult("dodo_invalid_target")
		}
		card := dodoCardFromText(payload.Text)
		data, err := runtime.request(ctx, token, "/api/v2/channel/message/send", map[string]any{"channelId": channelID, "messageType": 6, "messageBody": card})
		if err != nil {
			return adapterapi.AmbiguousResult("dodo_provider_ambiguous", "provider dispatch outcome is unknown")
		}
		return dodoMessageResult(data)
	case adapterapi.EffectPayloadSegments:
		if payload.Target.Kind != adapterapi.TargetGroup {
			return adapterapi.UnsupportedResult("dodo_invalid_target")
		}
		channelID := strings.TrimPrefix(payload.Target.Conversation.String(), "DODO-Group:")
		if channelID == payload.Target.Conversation.String() || channelID == "" {
			return adapterapi.UnsupportedResult("dodo_invalid_target")
		}
		card, err := dodoCardFromSegments(payload.Segments)
		if err != nil {
			return adapterapi.UnsupportedResult(err.Error())
		}
		data, err := runtime.request(ctx, token, "/api/v2/channel/message/send", map[string]any{"channelId": channelID, "messageType": 6, "messageBody": card})
		if err != nil {
			return adapterapi.AmbiguousResult("dodo_provider_ambiguous", "provider dispatch outcome is unknown")
		}
		return dodoMessageResult(data)
	case adapterapi.EffectPayloadPersonText:
		if payload.Target.Kind != adapterapi.TargetPerson {
			return adapterapi.UnsupportedResult("dodo_invalid_target")
		}
		userID := strings.TrimPrefix(payload.Target.Conversation.String(), "DODO:")
		if userID == payload.Target.Conversation.String() || userID == "" || runtime.config.IslandID == "" {
			return adapterapi.UnsupportedResult("dodo_invalid_target")
		}
		data, err := runtime.request(ctx, token, "/api/v2/personal/message/send", map[string]any{"islandSourceId": runtime.config.IslandID, "dodoSourceId": userID, "messageType": 1, "messageBody": map[string]string{"content": payload.Text}})
		if err != nil {
			return adapterapi.AmbiguousResult("dodo_provider_ambiguous", "provider dispatch outcome is unknown")
		}
		return dodoMessageResult(data)
	default:
		return adapterapi.UnsupportedResult("dodo_effect_not_supported")
	}
}

type dodoChannelInfo struct {
	ChannelID string `json:"channelId"`
	IslandID  string `json:"islandSourceId"`
}

func (runtime *dodoRuntime) channelInfo(ctx context.Context, token, channelID string) (dodoChannelInfo, error) {
	data, err := runtime.request(ctx, token, "/api/v2/channel/info", map[string]string{"channelId": channelID})
	if err != nil {
		return dodoChannelInfo{}, err
	}
	var info dodoChannelInfo
	if err := json.Unmarshal(data, &info); err != nil || info.ChannelID == "" {
		return dodoChannelInfo{}, errors.New("dodo: invalid channel info response")
	}
	return info, nil
}

func dodoMessageResult(data json.RawMessage) adapterapi.EffectResult {
	var result struct {
		MessageID string `json:"messageId"`
	}
	if err := json.Unmarshal(data, &result); err != nil || result.MessageID == "" {
		return adapterapi.TerminalResult("dodo_invalid_response", "provider returned an invalid response")
	}
	return adapterapi.SucceededResult(result.MessageID)
}

func (runtime *dodoRuntime) request(ctx context.Context, token, path string, body any) (json.RawMessage, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	base := runtime.config.APIBaseURL
	if base == "" {
		base = "https://botopen.imdodo.com"
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(encoded))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bot "+runtime.config.ClientID+"."+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := runtime.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("dodo: provider returned %s", response.Status)
	}
	var envelope dodoEnvelope
	if err := json.NewDecoder(io.LimitReader(response.Body, adapterapi.MaxInboundTextBytes+64*1024)).Decode(&envelope); err != nil {
		return nil, err
	}
	if envelope.Status != 0 {
		return nil, fmt.Errorf("dodo: provider rejected request: %s", envelope.Message)
	}
	return envelope.Data, nil
}

// senderRole mirrors the legacy Dodo check: the island owner is owner; members
// whose aggregated role permissions include ADMIN or MANAGE_MEMBER are admin.
// A failed lookup resolves to no role instead of granting elevated rights.
func (runtime *dodoRuntime) senderRole(ctx context.Context, token, islandID, userID string) string {
	if token == "" || islandID == "" || userID == "" {
		return ""
	}
	role, err := runtime.lookupIslandRole(ctx, token, islandID, userID)
	if err != nil {
		return ""
	}
	return role
}

func (runtime *dodoRuntime) lookupIslandRole(ctx context.Context, token, islandID, userID string) (string, error) {
	if runtime.httpClient == nil {
		return "", errors.New("dodo: http client is unavailable")
	}
	islandData, err := runtime.request(ctx, token, "/api/v1/island/info", map[string]string{"islandSourceId": islandID})
	if err != nil {
		return "", err
	}
	var island struct {
		OwnerDodoSourceID string `json:"ownerDodoSourceId"`
	}
	if err := json.Unmarshal(islandData, &island); err != nil {
		return "", err
	}
	if island.OwnerDodoSourceID != "" && userID == island.OwnerDodoSourceID {
		return "owner", nil
	}
	roleData, err := runtime.request(ctx, token, "/api/v1/guild/role/member/get", map[string]string{"islandSourceId": islandID, "dodoSourceId": userID})
	if err != nil {
		return "", err
	}
	var roles []struct {
		Permission string `json:"permission"`
	}
	if err := json.Unmarshal(roleData, &roles); err != nil {
		return "", err
	}
	var permissions int64
	for _, role := range roles {
		value, err := strconv.ParseInt(role.Permission, 16, 64)
		if err != nil {
			continue
		}
		permissions |= value
	}
	if permissions&(dodoPermissionAdmin|dodoPermissionManageMember) > 0 {
		return "admin", nil
	}
	return "", nil
}

const (
	dodoPermissionManageMember = 1 << 2
	dodoPermissionAdmin        = 1 << 3
)

func (runtime *dodoRuntime) resolveToken(ctx context.Context) (string, error) {
	if runtime == nil || runtime.resolver == nil {
		return "", errors.New("dodo: token resolver is unavailable")
	}
	value, err := runtime.resolver.Resolve(ctx, runtime.tokenRef)
	if err != nil {
		return "", err
	}
	if value.Version != runtime.tokenRef.Version || len(value.Bytes) == 0 {
		return "", errors.New("dodo: token resolution is invalid")
	}
	return string(value.Bytes), nil
}

func (runtime *dodoRuntime) Run(ctx context.Context, core adapterapi.CorePort) (runErr error) {
	if runtime == nil || core == nil {
		return errors.New("dodo: runtime or core is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithCancel(ctx)
	runtime.mu.Lock()
	if runtime.cancel != nil {
		runtime.mu.Unlock()
		cancel()
		return errors.New("dodo: runtime already started")
	}
	runtime.cancel, runtime.running = cancel, true
	runtime.mu.Unlock()
	defer func() {
		if runErr != nil && !errors.Is(runErr, context.Canceled) {
			_ = core.ReportObservation(context.Background(), adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateFailed, Code: "runtime_failed", Detail: "Dodo runtime failed", Retryable: true, OccurredAt: time.Now().UTC()})
		}
		_ = runtime.Stop(context.Background())
	}()
	if err := core.ReportObservation(runCtx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateStarting, Code: "starting", Detail: "Dodo runtime starting", OccurredAt: time.Now().UTC()}); err != nil {
		return err
	}
	token, err := runtime.resolveToken(runCtx)
	if err != nil {
		return err
	}
	selfData, err := runtime.request(runCtx, token, "/api/v2/bot/info", map[string]any{})
	if err != nil {
		return err
	}
	var self struct {
		UserID string `json:"dodoSourceId"`
	}
	if decodeErr := json.Unmarshal(selfData, &self); decodeErr != nil || self.UserID == "" {
		return errors.New("dodo: invalid self identity")
	}
	gatewayData, err := runtime.request(runCtx, token, "/api/v2/websocket/connection", map[string]any{})
	if err != nil {
		return err
	}
	var gateway struct {
		Endpoint string `json:"endpoint"`
	}
	if decodeErr := json.Unmarshal(gatewayData, &gateway); decodeErr != nil {
		return decodeErr
	}
	endpoint, err := url.Parse(gateway.Endpoint)
	if err != nil || endpoint.Host == "" || (endpoint.Scheme != "ws" && endpoint.Scheme != "wss") || endpoint.User != nil || endpoint.Fragment != "" {
		return errors.New("dodo: invalid websocket endpoint")
	}
	headers := http.Header{"Authorization": []string{"Bot " + runtime.config.ClientID + "." + token}}
	connection, response, err := runtime.dialer.DialContext(runCtx, endpoint.String(), headers)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		return err
	}
	connection.SetReadLimit(adapterapi.MaxInboundTextBytes + 64*1024)
	reads := make(chan dodoReadResult, 1)
	runtime.mu.Lock()
	if !runtime.running {
		runtime.mu.Unlock()
		_ = connection.Close()
		return nil
	}
	runtime.conn, runtime.token, runtime.selfID = connection, token, self.UserID
	runtime.wg.Add(1)
	runtime.mu.Unlock()
	go runtime.readLoop(runCtx, connection, reads)
	if reportErr := core.ReportObservation(runCtx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateConnected, Code: "connected", Detail: "Dodo websocket established", OccurredAt: time.Now().UTC()}); reportErr != nil {
		return reportErr
	}
	providerID, err := adapterapi.NewPrincipalID(FormatDiceIDDodo(self.UserID))
	if err != nil {
		return err
	}
	if err := core.ReportObservation(runCtx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationIdentity, State: adapterapi.ObservedStateConnected, ProviderID: providerID, Code: "identity", OccurredAt: time.Now().UTC()}); err != nil {
		return err
	}
	heartbeat := time.NewTicker(25 * time.Second)
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
			if err := runtime.handleWireEvent(runCtx, core, result.data, self.UserID); err != nil {
				return err
			}
		case <-heartbeat.C:
			if err := connection.WriteJSON(map[string]int{"type": 1}); err != nil {
				return err
			}
		}
	}
}

func (runtime *dodoRuntime) handleWireEvent(ctx context.Context, core adapterapi.CorePort, data []byte, selfID string) error {
	var wire dodoWireMessage
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if wire.Type != 0 {
		return nil
	}
	var event dodoEvent
	if err := json.Unmarshal(wire.Data, &event); err != nil {
		return err
	}
	if event.EventType != "1001" && event.EventType != "2001" {
		return nil
	}
	var message dodoMessageBody
	if err := json.Unmarshal(event.EventBody, &message); err != nil {
		return err
	}
	if event.EventID == "" || message.MessageID == "" || message.UserID == "" || message.UserID == selfID {
		return nil
	}
	var content struct {
		Content string `json:"content"`
		URL     string `json:"url"`
	}
	if err := json.Unmarshal(message.MessageBody, &content); err != nil {
		return err
	}
	conversation := FormatDiceIDDodo(message.UserID)
	conversationKind := adapterapi.ConversationKindDirect
	if event.EventType == "2001" {
		conversationKind = adapterapi.ConversationKindGroup
		if message.ChannelID == "" {
			return errors.New("dodo: channel message missing channel id")
		}
		conversation = FormatDiceIDDodoGroup(message.ChannelID)
	}

	content.Content = normalizeDodoInboundText(content.Content)
	inbound := adapterapi.InboundMessage{ProviderEventID: adapterapi.ProviderEventID(event.EventID), MessageID: adapterapi.MessageID(message.MessageID), Platform: "DODO", Sender: adapterapi.PrincipalID(FormatDiceIDDodo(message.UserID)), Conversation: adapterapi.ConversationID(conversation), ConversationKind: conversationKind, Target: conversation, Kind: adapterapi.InboundKindMessage, Text: content.Content}
	if conversationKind == adapterapi.ConversationKindGroup {
		runtime.mu.Lock()
		token := runtime.token
		runtime.mu.Unlock()
		inbound.SenderRole = runtime.senderRole(ctx, token, message.IslandID, message.UserID)
	}
	if content.Content != "" {
		inbound.Segments = []adapterapi.InboundSegment{{Kind: "text", Text: content.Content}}
	} else if content.URL != "" {
		inbound.Segments = []adapterapi.InboundSegment{{Kind: "image", URL: content.URL}}
	}
	if event.Timestamp > 0 {
		inbound.OccurredAt = time.UnixMilli(event.Timestamp).UTC()
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
		return errors.New("dodo: ingress rejected")
	}
	return nil
}
func normalizeDodoInboundText(text string) string {
	return strings.ReplaceAll(text, "<@!", "<@")
}

func (runtime *dodoRuntime) readLoop(ctx context.Context, connection *websocket.Conn, results chan<- dodoReadResult) {
	defer runtime.wg.Done()
	for {
		messageType, data, err := connection.ReadMessage()
		select {
		case results <- dodoReadResult{messageType: messageType, data: data, err: err}:
		case <-ctx.Done():
			return
		}
		if err != nil {
			return
		}
	}
}

func (runtime *dodoRuntime) Stop(context.Context) error {
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
	runtime.selfID = ""
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
