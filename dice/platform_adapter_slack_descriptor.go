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

	"github.com/gorilla/websocket"

	"Scardice-core/adapterapi"
)

const SlackAdapterKey adapterapi.AdapterKey = "slack"

type SlackDescriptor struct{}

type slackConfigInput struct {
	Version    string          `json:"version"`
	Channel    string          `json:"channel"`
	APIBaseURL string          `json:"apiBaseURL"`
	AppToken   json.RawMessage `json:"appToken"`
	BotToken   json.RawMessage `json:"botToken"`
}

type slackCanonicalConfig struct {
	Version    string                  `json:"version"`
	Channel    string                  `json:"channel"`
	APIBaseURL string                  `json:"apiBaseURL"`
	AppToken   providerCanonicalSecret `json:"appToken"`
	BotToken   providerCanonicalSecret `json:"botToken"`
}

type slackRuntime struct {
	config      slackCanonicalConfig
	appTokenRef adapterapi.SecretRef
	botTokenRef adapterapi.SecretRef
	resolver    adapterapi.SecretResolver

	mu         sync.Mutex
	cancel     context.CancelFunc
	conn       *websocket.Conn
	wg         sync.WaitGroup
	running    bool
	appToken   string
	botToken   string
	selfID     string
	httpClient *http.Client
	dialer     *websocket.Dialer
}

type slackReadResult struct {
	messageType int
	data        []byte
	err         error
}

type slackAPIResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

type slackSocketEnvelope struct {
	Type       string          `json:"type"`
	EnvelopeID string          `json:"envelope_id"`
	Payload    json.RawMessage `json:"payload"`
}

type slackEventsPayload struct {
	TeamID  string            `json:"team_id"`
	EventID string            `json:"event_id"`
	Event   slackMessageEvent `json:"event"`
}

type slackMessageEvent struct {
	Type        string `json:"type"`
	Subtype     string `json:"subtype"`
	User        string `json:"user"`
	BotID       string `json:"bot_id"`
	Text        string `json:"text"`
	Channel     string `json:"channel"`
	ChannelType string `json:"channel_type"`
	ClientMsgID string `json:"client_msg_id"`
	Timestamp   string `json:"ts"`
}

func NewSlackDescriptor() adapterapi.Descriptor { return SlackDescriptor{} }

func (SlackDescriptor) Key() adapterapi.AdapterKey { return SlackAdapterKey }

func (SlackDescriptor) ConfigVersion() uint16 { return 1 }
func FormatDiceIDSlack(id string) string {
	return fmt.Sprintf("SLACK:%s", id)
}

func FormatDiceIDSlackChannel(id string) string {
	return fmt.Sprintf("SLACK-CH-Group:%s", id)
}

func FormatDiceIDSlackGuild(id string) string {
	return fmt.Sprintf("SLACK-Guild:%s", id)
}

func ExtractSlackUserID(id string) string {
	return strings.TrimPrefix(id, "SLACK:")
}

func ExtractSlackChannelID(id string) string {
	return strings.TrimPrefix(id, "SLACK-CH-Group:")
}

func (SlackDescriptor) SupportedActions(adapterapi.ValidatedConfig) adapterapi.ActionSet {
	return adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage)
}

func (SlackDescriptor) Capabilities(adapterapi.ValidatedConfig) adapterapi.CapabilitySet {
	return adapterapi.CapabilityLifecycle | adapterapi.CapabilityInbound | adapterapi.CapabilityOutbound
}

func (SlackDescriptor) ValidateConfig(ctx context.Context, raw json.RawMessage) (adapterapi.ValidatedConfig, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	var input slackConfigInput
	if err := decodeStrictProviderJSON(raw, &input); err != nil {
		return adapterapi.ValidatedConfig{}, fmt.Errorf("slack: invalid config: %w", err)
	}
	if input.Version != "1" {
		return adapterapi.ValidatedConfig{}, errors.New("slack: unsupported config version")
	}
	appToken, appRef, err := slackSecretRef(input.AppToken, "appToken")
	if err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	botToken, botRef, err := slackSecretRef(input.BotToken, "botToken")
	if err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	apiBaseURL, err := normalizeProviderHTTPURL(input.APIBaseURL, true)
	if err != nil {
		return adapterapi.ValidatedConfig{}, fmt.Errorf("slack: invalid apiBaseURL: %w", err)
	}
	encoded, err := json.Marshal(slackCanonicalConfig{Version: input.Version, Channel: strings.TrimSpace(input.Channel), APIBaseURL: apiBaseURL, AppToken: appToken, BotToken: botToken})
	if err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	canonical, err := adapterapi.CanonicalizeJSON(encoded)
	if err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	validated := adapterapi.ValidatedConfig{Version: 1, Canonical: canonical, SecretRefs: []adapterapi.SecretRef{appRef, botRef}}
	if err := validated.Validate(); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	return validated, nil
}

func slackSecretRef(raw json.RawMessage, name string) (providerCanonicalSecret, adapterapi.SecretRef, error) {
	var secret providerCanonicalSecret
	if err := decodeStrictProviderJSON(raw, &secret); err != nil || secret.Version == 0 {
		return providerCanonicalSecret{}, adapterapi.SecretRef{}, fmt.Errorf("slack: invalid %s reference", name)
	}
	ref := adapterapi.SecretRef{Ref: secret.SecretRef, Version: secret.Version}
	if err := ref.Validate(); err != nil {
		return providerCanonicalSecret{}, adapterapi.SecretRef{}, err
	}
	return secret, ref, nil
}

func (descriptor SlackDescriptor) NewRuntime(init adapterapi.RuntimeInit) (adapterapi.AdapterRuntime, error) {
	if !init.EndpointID.Valid() || init.Generation == 0 || init.DesiredVersion == 0 {
		return nil, errors.New("slack: runtime identity is incomplete")
	}
	if err := init.Config.Validate(); err != nil {
		return nil, err
	}
	validated, err := descriptor.ValidateConfig(context.Background(), init.Config.Canonical)
	if err != nil || validated.Version != init.Config.Version || !bytes.Equal(validated.Canonical, init.Config.Canonical) || len(validated.SecretRefs) != len(init.Config.SecretRefs) {
		return nil, errors.New("slack: runtime config was not validated by descriptor")
	}
	for index := range validated.SecretRefs {
		if validated.SecretRefs[index] != init.Config.SecretRefs[index] {
			return nil, errors.New("slack: runtime secret references do not match")
		}
	}
	var config slackCanonicalConfig
	if err := json.Unmarshal(init.Config.Canonical, &config); err != nil {
		return nil, errors.New("slack: invalid canonical runtime config")
	}
	return &slackRuntime{config: config, appTokenRef: validated.SecretRefs[0], botTokenRef: validated.SecretRefs[1], resolver: init.Secrets, httpClient: &http.Client{Timeout: 20 * time.Second}, dialer: websocket.DefaultDialer}, nil
}

func (*slackRuntime) OwnedResources() adapterapi.OwnedResourceManifest {
	return adapterapi.OwnedResourceManifest{}
}

func (*slackRuntime) Capabilities() adapterapi.CapabilitySet {
	return adapterapi.CapabilityLifecycle | adapterapi.CapabilityInbound | adapterapi.CapabilityOutbound
}

func (*slackRuntime) Diagnostics(context.Context) adapterapi.DiagnosticReport {
	return adapterapi.DiagnosticReport{}
}

func (runtime *slackRuntime) Execute(ctx context.Context, effect adapterapi.OutboundEffect) adapterapi.EffectResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if effect.Version != adapterapi.EffectVersionOne {
		return adapterapi.UnsupportedResult("slack_invalid_effect_version")
	}
	if err := effect.ValidateForCapabilities(runtime.Capabilities(), adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage)); err != nil {
		return adapterapi.UnsupportedResult("slack_effect_not_supported")
	}
	payload := effect.Payload
	var prefix string
	switch payload.Kind {
	case adapterapi.EffectPayloadGroupText:
		if payload.Target.Kind != adapterapi.TargetGroup {
			return adapterapi.UnsupportedResult("slack_invalid_target")
		}
		prefix = "SLACK-CH-Group:"
	case adapterapi.EffectPayloadPersonText:
		if payload.Target.Kind != adapterapi.TargetPerson {
			return adapterapi.UnsupportedResult("slack_invalid_target")
		}
		prefix = "SLACK:"
	default:
		return adapterapi.UnsupportedResult("slack_effect_not_supported")
	}
	conversation := payload.Target.Conversation.String()
	channel := strings.TrimPrefix(conversation, prefix)
	if channel == conversation || channel == "" {
		return adapterapi.UnsupportedResult("slack_invalid_target")
	}
	runtime.mu.Lock()
	botToken, selfID := runtime.botToken, runtime.selfID
	runtime.mu.Unlock()
	if botToken == "" || selfID == "" {
		return adapterapi.TerminalResult("slack_provider_unavailable", "provider unavailable")
	}
	response, err := runtime.api(ctx, botToken, "chat.postMessage", map[string]string{"channel": channel, "text": payload.Text})
	if err != nil {
		return adapterapi.AmbiguousResult("slack_provider_ambiguous", "provider dispatch outcome is unknown")
	}
	var result struct {
		Timestamp string `json:"ts"`
	}
	if err := json.Unmarshal(response, &result); err != nil || result.Timestamp == "" {
		return adapterapi.TerminalResult("slack_invalid_response", "provider returned an invalid response")
	}
	return adapterapi.SucceededResult(result.Timestamp)
}

func (runtime *slackRuntime) api(ctx context.Context, token, method string, body any) (json.RawMessage, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	base := runtime.config.APIBaseURL
	if base == "" {
		base = "https://slack.com/api"
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/"+method, bytes.NewReader(encoded))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	response, err := runtime.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("slack: provider returned %s", response.Status)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, adapterapi.MaxInboundTextBytes+64*1024))
	if err != nil {
		return nil, err
	}
	var status slackAPIResponse
	if err := json.Unmarshal(data, &status); err != nil {
		return nil, err
	}
	if !status.OK {
		return nil, fmt.Errorf("slack: provider rejected request: %s", status.Error)
	}
	return data, nil
}

func (runtime *slackRuntime) resolveSecret(ctx context.Context, ref adapterapi.SecretRef) (string, error) {
	if runtime == nil || runtime.resolver == nil {
		return "", errors.New("slack: secret resolver is unavailable")
	}
	value, err := runtime.resolver.Resolve(ctx, ref)
	if err != nil {
		return "", err
	}
	if value.Version != ref.Version || len(value.Bytes) == 0 {
		return "", errors.New("slack: secret resolution is invalid")
	}
	return string(value.Bytes), nil
}

func (runtime *slackRuntime) Run(ctx context.Context, core adapterapi.CorePort) (runErr error) {
	if runtime == nil || core == nil {
		return errors.New("slack: runtime or core is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithCancel(ctx)
	runtime.mu.Lock()
	if runtime.cancel != nil {
		runtime.mu.Unlock()
		cancel()
		return errors.New("slack: runtime already started")
	}
	runtime.cancel, runtime.running = cancel, true
	runtime.mu.Unlock()
	defer func() {
		if runErr != nil && !errors.Is(runErr, context.Canceled) {
			_ = core.ReportObservation(context.Background(), adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateFailed, Code: "runtime_failed", Detail: "Slack runtime failed", Retryable: true, OccurredAt: time.Now().UTC()})
		}
		_ = runtime.Stop(context.Background())
	}()
	if err := core.ReportObservation(runCtx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateStarting, Code: "starting", Detail: "Slack runtime starting", OccurredAt: time.Now().UTC()}); err != nil {
		return err
	}
	appToken, err := runtime.resolveSecret(runCtx, runtime.appTokenRef)
	if err != nil {
		return err
	}
	botToken, err := runtime.resolveSecret(runCtx, runtime.botTokenRef)
	if err != nil {
		return err
	}
	authData, err := runtime.api(runCtx, botToken, "auth.test", map[string]any{})
	if err != nil {
		return err
	}
	var auth struct {
		UserID string `json:"user_id"`
	}
	if decodeErr := json.Unmarshal(authData, &auth); decodeErr != nil || auth.UserID == "" {
		return errors.New("slack: invalid self identity")
	}
	connectionData, err := runtime.api(runCtx, appToken, "apps.connections.open", map[string]any{})
	if err != nil {
		return err
	}
	var connectionResult struct {
		URL string `json:"url"`
	}
	if decodeErr := json.Unmarshal(connectionData, &connectionResult); decodeErr != nil {
		return decodeErr
	}
	socketURL, err := url.Parse(connectionResult.URL)
	if err != nil || socketURL.Host == "" || (socketURL.Scheme != "ws" && socketURL.Scheme != "wss") || socketURL.User != nil || socketURL.Fragment != "" {
		return errors.New("slack: invalid socket URL")
	}
	connection, response, err := runtime.dialer.DialContext(runCtx, socketURL.String(), nil)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		return err
	}
	connection.SetReadLimit(adapterapi.MaxInboundTextBytes + 64*1024)
	runtime.mu.Lock()
	runtime.conn = connection
	runtime.mu.Unlock()
	var hello slackSocketEnvelope
	if readErr := connection.ReadJSON(&hello); readErr != nil || hello.Type != "hello" {
		return errors.New("slack: socket did not send hello")
	}
	reads := make(chan slackReadResult, 1)
	runtime.mu.Lock()
	if !runtime.running {
		runtime.mu.Unlock()
		return nil
	}
	runtime.appToken, runtime.botToken, runtime.selfID = appToken, botToken, auth.UserID
	runtime.wg.Add(1)
	runtime.mu.Unlock()
	go runtime.readLoop(runCtx, connection, reads)
	if reportErr := core.ReportObservation(runCtx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateConnected, Code: "connected", Detail: "Slack Socket Mode established", OccurredAt: time.Now().UTC()}); reportErr != nil {
		return reportErr
	}
	providerID, err := adapterapi.NewPrincipalID(FormatDiceIDSlack(auth.UserID))
	if err != nil {
		return err
	}
	if err := core.ReportObservation(runCtx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationIdentity, State: adapterapi.ObservedStateConnected, ProviderID: providerID, Code: "identity", OccurredAt: time.Now().UTC()}); err != nil {
		return err
	}
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
			var envelope slackSocketEnvelope
			if err := json.Unmarshal(result.data, &envelope); err != nil {
				return err
			}
			if envelope.Type == "disconnect" {
				return errors.New("slack: socket requested reconnect")
			}
			if envelope.Type == "events_api" {
				if err := runtime.handleEnvelope(runCtx, core, envelope); err != nil {
					return err
				}
			}
			if envelope.EnvelopeID != "" {
				if err := connection.WriteJSON(map[string]string{"envelope_id": envelope.EnvelopeID}); err != nil {
					return err
				}
			}
		}
	}
}

func (runtime *slackRuntime) handleEnvelope(ctx context.Context, core adapterapi.CorePort, envelope slackSocketEnvelope) error {
	var payload slackEventsPayload
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		return err
	}
	event := payload.Event
	if (event.Type != "message" && event.Type != "app_mention") || event.Subtype != "" || event.BotID != "" || event.User == "" || event.Channel == "" {
		return nil
	}
	messageID := event.ClientMsgID
	if messageID == "" {
		messageID = event.Timestamp
	}
	if messageID == "" || envelope.EnvelopeID == "" {
		return errors.New("slack: incomplete message event")
	}
	conversation := FormatDiceIDSlackChannel(event.Channel)
	conversationKind := adapterapi.ConversationKindGroup
	if event.ChannelType == "im" {
		conversationKind = adapterapi.ConversationKindDirect
		conversation = FormatDiceIDSlack(event.User)
	}
	inbound := adapterapi.InboundMessage{ProviderEventID: adapterapi.ProviderEventID("slack-envelope:" + envelope.EnvelopeID), MessageID: adapterapi.MessageID(messageID), Platform: "SLACK", Sender: adapterapi.PrincipalID(FormatDiceIDSlack(event.User)), Conversation: adapterapi.ConversationID(conversation), ConversationKind: conversationKind, Target: conversation, Kind: adapterapi.InboundKindMessage, Text: event.Text}
	if conversationKind == adapterapi.ConversationKindGroup {
		runtime.mu.Lock()
		token := runtime.botToken
		runtime.mu.Unlock()
		inbound.SenderRole = runtime.senderRole(ctx, token, event.User)
	}
	if event.Text != "" {
		inbound.Segments = []adapterapi.InboundSegment{{Kind: "text", Text: event.Text}}
	}
	if timestamp, err := strconv.ParseFloat(event.Timestamp, 64); err == nil {
		seconds := int64(timestamp)
		inbound.OccurredAt = time.Unix(seconds, int64((timestamp-float64(seconds))*1e9)).UTC()
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
		return errors.New("slack: ingress rejected")
	}
	return nil
}

// senderRole mirrors the legacy Slack check: users.info owner/admin flags map
// to owner/admin. A failed lookup resolves to no role instead of granting
// elevated rights.
func (runtime *slackRuntime) senderRole(ctx context.Context, token, userID string) string {
	if token == "" || userID == "" {
		return ""
	}
	role, err := runtime.lookupUserRole(ctx, token, userID)
	if err != nil {
		return ""
	}
	return role
}

func (runtime *slackRuntime) lookupUserRole(ctx context.Context, token, userID string) (string, error) {
	if runtime.httpClient == nil {
		return "", errors.New("slack: http client is unavailable")
	}
	data, err := runtime.api(ctx, token, "users.info", map[string]any{"user": userID})
	if err != nil {
		return "", err
	}
	var result struct {
		User struct {
			IsOwner bool `json:"is_owner"`
			IsAdmin bool `json:"is_admin"`
		} `json:"user"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return "", err
	}
	switch {
	case result.User.IsOwner:
		return "owner", nil
	case result.User.IsAdmin:
		return "admin", nil
	default:
		return "", nil
	}
}

func (runtime *slackRuntime) readLoop(ctx context.Context, connection *websocket.Conn, results chan<- slackReadResult) {
	defer runtime.wg.Done()
	for {
		messageType, data, err := connection.ReadMessage()
		select {
		case results <- slackReadResult{messageType: messageType, data: data, err: err}:
		case <-ctx.Done():
			return
		}
		if err != nil {
			return
		}
	}
}

func (runtime *slackRuntime) Stop(context.Context) error {
	if runtime == nil {
		return nil
	}
	runtime.mu.Lock()
	cancel := runtime.cancel
	runtime.cancel = nil
	runtime.running = false
	connection := runtime.conn
	runtime.conn = nil
	runtime.appToken = ""
	runtime.botToken = ""
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
