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
	"unicode/utf16"

	"Scardice-core/adapterapi"
)

const TelegramAdapterKey adapterapi.AdapterKey = "telegram"

type TelegramDescriptor struct{}

type telegramConfigInput struct {
	ChatID     string          `json:"chatId"`
	WebhookURL string          `json:"webhookUrl"`
	ProxyURL   string          `json:"proxyURL"`
	APIBaseURL string          `json:"apiBaseURL"`
	Token      json.RawMessage `json:"token"`
}

type telegramCanonicalConfig struct {
	ChatID     string                  `json:"chatId"`
	WebhookURL string                  `json:"webhookUrl"`
	ProxyURL   string                  `json:"proxyURL"`
	APIBaseURL string                  `json:"apiBaseURL"`
	Token      providerCanonicalSecret `json:"token"`
}

type telegramRuntime struct {
	config   telegramCanonicalConfig
	tokenRef adapterapi.SecretRef
	resolver adapterapi.SecretResolver

	mu         sync.Mutex
	cancel     context.CancelFunc
	running    bool
	token      string
	selfID     int64
	selfName   string
	usernames  map[string]int64
	httpClient *http.Client
}

type telegramEnvelope struct {
	OK          bool            `json:"ok"`
	Result      json.RawMessage `json:"result"`
	Description string          `json:"description"`
}

type telegramUser struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	FirstName string `json:"first_name"`
	IsBot     bool   `json:"is_bot"`
}

type telegramChat struct {
	ID   int64  `json:"id"`
	Type string `json:"type"`
}

// telegramEntity mirrors Telegram's MessageEntity offsets, which are measured
// in UTF-16 code units over the raw message text.
type telegramEntity struct {
	Type   string        `json:"type"`
	Offset int           `json:"offset"`
	Length int           `json:"length"`
	User   *telegramUser `json:"user"`
}

type telegramMessage struct {
	MessageID     int64            `json:"message_id"`
	Date          int64            `json:"date"`
	Text          string           `json:"text"`
	Caption       string           `json:"caption"`
	From          telegramUser     `json:"from"`
	Chat          telegramChat     `json:"chat"`
	Entities      []telegramEntity `json:"entities"`
	CaptionEntity []telegramEntity `json:"caption_entities"`
}

type telegramUpdate struct {
	UpdateID      int64            `json:"update_id"`
	Message       *telegramMessage `json:"message"`
	EditedMessage *telegramMessage `json:"edited_message"`
}

func NewTelegramDescriptor() adapterapi.Descriptor { return TelegramDescriptor{} }

func (TelegramDescriptor) Key() adapterapi.AdapterKey { return TelegramAdapterKey }

func (TelegramDescriptor) ConfigVersion() uint16 { return 1 }
func FormatDiceIDTelegram(id string) string {
	return fmt.Sprintf("TG:%s", id)
}

func FormatDiceIDTelegramGroup(id string) string {
	return fmt.Sprintf("TG-Group:%s", id)
}

func ExtractTelegramUserID(id string) string {
	return strings.TrimPrefix(id, "TG:")
}

func ExtractTelegramGroupID(id string) string {
	return strings.TrimPrefix(id, "TG-Group:")
}

func telegramSupportedActions() adapterapi.ActionSet {
	return adapterapi.ActionSet(0).With(
		adapterapi.ActionKindSendMessage,
		adapterapi.ActionKindQuit,
		adapterapi.ActionKindGroupInfoRefresh,
	)
}

func (TelegramDescriptor) SupportedActions(adapterapi.ValidatedConfig) adapterapi.ActionSet {
	return telegramSupportedActions()
}

func (TelegramDescriptor) Capabilities(adapterapi.ValidatedConfig) adapterapi.CapabilitySet {
	return adapterapi.CapabilityLifecycle |
		adapterapi.CapabilityInbound |
		adapterapi.CapabilityOutbound |
		adapterapi.CapabilityActions |
		adapterapi.CapabilityRichMessages
}

func (*telegramRuntime) Capabilities() adapterapi.CapabilitySet {
	return adapterapi.CapabilityLifecycle |
		adapterapi.CapabilityInbound |
		adapterapi.CapabilityOutbound |
		adapterapi.CapabilityActions |
		adapterapi.CapabilityRichMessages
}

func (runtime *telegramRuntime) Execute(ctx context.Context, effect adapterapi.OutboundEffect) adapterapi.EffectResult {
	if runtime == nil {
		return adapterapi.TerminalResult("telegram_provider_unavailable", "provider unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if effect.Version != adapterapi.EffectVersionOne {
		return adapterapi.UnsupportedResult("telegram_invalid_effect_version")
	}
	if err := effect.ValidateForCapabilities(runtime.Capabilities(), telegramSupportedActions()); err != nil {
		return adapterapi.UnsupportedResult("telegram_effect_not_supported")
	}
	payload := effect.Payload
	if payload.Kind == adapterapi.EffectPayloadQuit || payload.Kind == adapterapi.EffectPayloadGroupInfoRefresh {
		chatID, err := telegramGroupTarget(payload)
		if err != nil {
			return adapterapi.UnsupportedResult("telegram_invalid_target")
		}
		runtime.mu.Lock()
		token, selfID := runtime.token, runtime.selfID
		runtime.mu.Unlock()
		if token == "" || selfID == 0 {
			return adapterapi.TerminalResult("telegram_provider_unavailable", "provider unavailable")
		}
		method := "getChat"
		if payload.Kind == adapterapi.EffectPayloadQuit {
			method = "leaveChat"
		}
		result, err := runtime.request(ctx, token, method, map[string]any{"chat_id": chatID})
		if err != nil {
			return adapterapi.AmbiguousResult("telegram_provider_ambiguous", "provider dispatch outcome is unknown")
		}
		if payload.Kind == adapterapi.EffectPayloadQuit {
			var succeeded bool
			if err := json.Unmarshal(result, &succeeded); err != nil || !succeeded {
				return adapterapi.TerminalResult("telegram_invalid_response", "provider returned an invalid response")
			}
			return adapterapi.SucceededResult("")
		}
		var chat telegramChat
		if err := json.Unmarshal(result, &chat); err != nil || chat.ID == 0 {
			return adapterapi.TerminalResult("telegram_invalid_response", "provider returned an invalid response")
		}
		return adapterapi.SucceededResult(strconv.FormatInt(chat.ID, 10))
	}
	chatID, err := telegramMessageTarget(payload)
	if err != nil {
		return adapterapi.UnsupportedResult("telegram_invalid_target")
	}
	runtime.mu.Lock()
	token, selfID := runtime.token, runtime.selfID
	runtime.mu.Unlock()
	if token == "" || selfID == 0 {
		return adapterapi.TerminalResult("telegram_provider_unavailable", "provider unavailable")
	}
	body, err := telegramOutboundBody(payload, chatID)
	if err != nil {
		return adapterapi.UnsupportedResult(err.Error())
	}
	result, err := runtime.request(ctx, token, "sendMessage", body)
	if err != nil {
		return adapterapi.AmbiguousResult("telegram_provider_ambiguous", "provider dispatch outcome is unknown")
	}
	var message telegramMessage
	if err := json.Unmarshal(result, &message); err != nil || message.MessageID == 0 {
		return adapterapi.TerminalResult("telegram_invalid_response", "provider returned an invalid response")
	}
	return adapterapi.SucceededResult(strconv.FormatInt(message.MessageID, 10))
}

func telegramMessageTarget(payload adapterapi.EffectPayload) (int64, error) {
	var prefix string
	switch payload.Kind {
	case adapterapi.EffectPayloadGroupText:
		if payload.Target.Kind != adapterapi.TargetGroup {
			return 0, errors.New("telegram: target is not a group")
		}
		prefix = "TG-Group:"
	case adapterapi.EffectPayloadPersonText:
		if payload.Target.Kind != adapterapi.TargetPerson {
			return 0, errors.New("telegram: target is not a person")
		}
		prefix = "TG:"
	case adapterapi.EffectPayloadSegments:
		switch payload.Target.Kind {
		case adapterapi.TargetGroup:
			prefix = "TG-Group:"
		case adapterapi.TargetPerson:
			prefix = "TG:"
		default:
			return 0, errors.New("telegram: target is not a person or group")
		}
	default:
		return 0, errors.New("telegram: unsupported message payload")
	}
	conversation := payload.Target.Conversation.String()
	chatIDText := strings.TrimPrefix(conversation, prefix)
	if chatIDText == conversation || chatIDText == "" {
		return 0, errors.New("telegram: invalid message target")
	}
	chatID, err := strconv.ParseInt(chatIDText, 10, 64)
	if err != nil || chatID == 0 {
		return 0, errors.New("telegram: invalid message target")
	}
	return chatID, nil
}

type telegramOutboundEntity struct {
	Type   string              `json:"type"`
	Offset int                 `json:"offset"`
	Length int                 `json:"length"`
	User   *telegramEntityUser `json:"user,omitempty"`
}

type telegramEntityUser struct {
	ID int64 `json:"id"`
}

type telegramOutboundMessage struct {
	ChatID   int64                    `json:"chat_id"`
	Text     string                   `json:"text"`
	Entities []telegramOutboundEntity `json:"entities,omitempty"`
}

func telegramOutboundBody(payload adapterapi.EffectPayload, chatID int64) (telegramOutboundMessage, error) {
	body := telegramOutboundMessage{ChatID: chatID}
	if payload.Kind == adapterapi.EffectPayloadPersonText || payload.Kind == adapterapi.EffectPayloadGroupText {
		if payload.Text == "" {
			return telegramOutboundMessage{}, errors.New("telegram_empty_message")
		}
		body.Text = payload.Text
		return body, nil
	}
	if payload.Kind != adapterapi.EffectPayloadSegments {
		return telegramOutboundMessage{}, errors.New("telegram_effect_not_supported")
	}
	for _, segment := range payload.Segments {
		switch segment.Kind {
		case adapterapi.SegmentKindText:
			body.Text += segment.Text
		case adapterapi.SegmentKindMention:
			if segment.Text == "all" || segment.Text == "TG:all" {
				body.Text += "@all "
				continue
			}
			userIDText := strings.TrimPrefix(segment.Text, "TG:")
			userID, err := strconv.ParseInt(userIDText, 10, 64)
			if err != nil || userID == 0 {
				return telegramOutboundMessage{}, errors.New("telegram_invalid_mention")
			}
			offset := len(utf16.Encode([]rune(body.Text)))
			display := "@" + userIDText + " "
			body.Text += display
			body.Entities = append(body.Entities, telegramOutboundEntity{
				Type:   "text_mention",
				Offset: offset,
				Length: len(utf16.Encode([]rune(display))),
				User:   &telegramEntityUser{ID: userID},
			})
		case adapterapi.SegmentKindImage, adapterapi.SegmentKindFile:
			return telegramOutboundMessage{}, errors.New("telegram_artifact_reader_unavailable")
		default:
			return telegramOutboundMessage{}, errors.New("telegram_unknown_segment")
		}
	}
	if body.Text == "" {
		return telegramOutboundMessage{}, errors.New("telegram_empty_segments")
	}
	return body, nil
}

func telegramGroupTarget(payload adapterapi.EffectPayload) (int64, error) {
	if payload.Target.Kind != adapterapi.TargetGroup {
		return 0, errors.New("telegram: target is not a group")
	}
	conversation := payload.Target.Conversation.String()
	chatIDText := strings.TrimPrefix(conversation, "TG-Group:")
	if chatIDText == conversation || chatIDText == "" {
		return 0, errors.New("telegram: invalid group target")
	}
	chatID, err := strconv.ParseInt(chatIDText, 10, 64)
	if err != nil || chatID == 0 {
		return 0, errors.New("telegram: invalid group target")
	}
	return chatID, nil
}

func (TelegramDescriptor) ValidateConfig(ctx context.Context, raw json.RawMessage) (adapterapi.ValidatedConfig, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	var input telegramConfigInput
	if err := decodeStrictProviderJSON(raw, &input); err != nil {
		return adapterapi.ValidatedConfig{}, fmt.Errorf("telegram: invalid config: %w", err)
	}
	if strings.TrimSpace(input.WebhookURL) != "" {
		return adapterapi.ValidatedConfig{}, errors.New("telegram: webhook mode requires an HTTP-listener runtime")
	}
	var token providerCanonicalSecret
	if err := decodeStrictProviderJSON(input.Token, &token); err != nil || token.Version == 0 {
		return adapterapi.ValidatedConfig{}, errors.New("telegram: invalid token reference")
	}
	ref := adapterapi.SecretRef{Ref: token.SecretRef, Version: token.Version}
	if err := ref.Validate(); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	proxyURL, err := normalizeProviderHTTPURL(input.ProxyURL, true)
	if err != nil {
		return adapterapi.ValidatedConfig{}, fmt.Errorf("telegram: invalid proxyURL: %w", err)
	}
	apiBaseURL, err := normalizeProviderHTTPURL(input.APIBaseURL, true)
	if err != nil {
		return adapterapi.ValidatedConfig{}, fmt.Errorf("telegram: invalid apiBaseURL: %w", err)
	}
	encoded, err := json.Marshal(telegramCanonicalConfig{ChatID: strings.TrimSpace(input.ChatID), WebhookURL: "", ProxyURL: proxyURL, APIBaseURL: apiBaseURL, Token: token})
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

func (descriptor TelegramDescriptor) NewRuntime(init adapterapi.RuntimeInit) (adapterapi.AdapterRuntime, error) {
	if !init.EndpointID.Valid() || init.Generation == 0 || init.DesiredVersion == 0 {
		return nil, errors.New("telegram: runtime identity is incomplete")
	}
	if err := init.Config.Validate(); err != nil {
		return nil, err
	}
	validated, err := descriptor.ValidateConfig(context.Background(), init.Config.Canonical)
	if err != nil || validated.Version != init.Config.Version || !bytes.Equal(validated.Canonical, init.Config.Canonical) || len(validated.SecretRefs) != len(init.Config.SecretRefs) {
		return nil, errors.New("telegram: runtime config was not validated by descriptor")
	}
	for index := range validated.SecretRefs {
		if validated.SecretRefs[index] != init.Config.SecretRefs[index] {
			return nil, errors.New("telegram: runtime secret references do not match")
		}
	}
	var config telegramCanonicalConfig
	if decodeErr := json.Unmarshal(init.Config.Canonical, &config); decodeErr != nil {
		return nil, errors.New("telegram: invalid canonical runtime config")
	}
	client, err := telegramHTTPClient(config.ProxyURL)
	if err != nil {
		return nil, err
	}
	return &telegramRuntime{config: config, tokenRef: adapterapi.SecretRef{Ref: config.Token.SecretRef, Version: config.Token.Version}, resolver: init.Secrets, usernames: make(map[string]int64), httpClient: client}, nil
}

func (*telegramRuntime) OwnedResources() adapterapi.OwnedResourceManifest {
	return adapterapi.OwnedResourceManifest{}
}

func (*telegramRuntime) Diagnostics(context.Context) adapterapi.DiagnosticReport {
	return adapterapi.DiagnosticReport{}
}

func telegramHTTPClient(proxy string) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if proxy != "" {
		parsed, err := url.Parse(proxy)
		if err != nil {
			return nil, err
		}
		transport.Proxy = http.ProxyURL(parsed)
	}
	return &http.Client{Transport: transport, Timeout: 40 * time.Second}, nil
}

func (runtime *telegramRuntime) request(ctx context.Context, token, method string, body any) (json.RawMessage, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	base := runtime.config.APIBaseURL
	if base == "" {
		base = "https://api.telegram.org"
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/bot"+token+"/"+method, bytes.NewReader(encoded))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := runtime.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("telegram: provider returned %s", response.Status)
	}
	var envelope telegramEnvelope
	if err := json.NewDecoder(io.LimitReader(response.Body, adapterapi.MaxInboundTextBytes+64*1024)).Decode(&envelope); err != nil {
		return nil, err
	}
	if !envelope.OK {
		return nil, fmt.Errorf("telegram: provider rejected request: %s", envelope.Description)
	}
	return envelope.Result, nil
}

func (runtime *telegramRuntime) resolveToken(ctx context.Context) (string, error) {
	if runtime == nil || runtime.resolver == nil {
		return "", errors.New("telegram: token resolver is unavailable")
	}
	value, err := runtime.resolver.Resolve(ctx, runtime.tokenRef)
	if err != nil {
		return "", err
	}
	if value.Version != runtime.tokenRef.Version || len(value.Bytes) == 0 {
		return "", errors.New("telegram: token resolution is invalid")
	}
	return string(value.Bytes), nil
}

func (runtime *telegramRuntime) Run(ctx context.Context, core adapterapi.CorePort) (runErr error) {
	if runtime == nil || core == nil {
		return errors.New("telegram: runtime or core is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithCancel(ctx)
	runtime.mu.Lock()
	if runtime.cancel != nil {
		runtime.mu.Unlock()
		cancel()
		return errors.New("telegram: runtime already started")
	}
	runtime.cancel, runtime.running = cancel, true
	runtime.mu.Unlock()
	defer func() {
		if runErr != nil && !errors.Is(runErr, context.Canceled) {
			_ = core.ReportObservation(context.Background(), adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateFailed, Code: "runtime_failed", Detail: "Telegram runtime failed", Retryable: true, OccurredAt: time.Now().UTC()})
		}
		_ = runtime.Stop(context.Background())
	}()
	if err := core.ReportObservation(runCtx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateStarting, Code: "starting", Detail: "Telegram runtime starting", OccurredAt: time.Now().UTC()}); err != nil {
		return err
	}
	token, err := runtime.resolveToken(runCtx)
	if err != nil {
		return err
	}
	selfData, err := runtime.request(runCtx, token, "getMe", map[string]any{})
	if err != nil {
		return err
	}
	var self telegramUser
	if decodeErr := json.Unmarshal(selfData, &self); decodeErr != nil || self.ID == 0 || !self.IsBot {
		return errors.New("telegram: invalid self identity")
	}
	runtime.mu.Lock()
	if !runtime.running {
		runtime.mu.Unlock()
		return nil
	}
	runtime.token, runtime.selfID, runtime.selfName = token, self.ID, self.Username
	runtime.mu.Unlock()
	if reportErr := core.ReportObservation(runCtx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateConnected, Code: "connected", Detail: "Telegram polling established", OccurredAt: time.Now().UTC()}); reportErr != nil {
		return reportErr
	}
	providerID, err := adapterapi.NewPrincipalID(FormatDiceIDTelegram(strconv.FormatInt(self.ID, 10)))
	if err != nil {
		return err
	}
	if err := core.ReportObservation(runCtx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationIdentity, State: adapterapi.ObservedStateConnected, ProviderID: providerID, Code: "identity", OccurredAt: time.Now().UTC()}); err != nil {
		return err
	}
	var offset int64
	for runCtx.Err() == nil {
		updatesData, err := runtime.request(runCtx, token, "getUpdates", map[string]any{"offset": offset, "timeout": 30, "allowed_updates": []string{"message", "edited_message"}})
		if err != nil {
			if runCtx.Err() != nil {
				return nil
			}
			return err
		}
		var updates []telegramUpdate
		if err := json.Unmarshal(updatesData, &updates); err != nil {
			return err
		}
		for _, update := range updates {
			if update.UpdateID >= offset {
				offset = update.UpdateID + 1
			}
			if err := runtime.handleUpdate(runCtx, core, update); err != nil {
				return err
			}
		}
	}
	return nil
}

func (runtime *telegramRuntime) handleUpdate(ctx context.Context, core adapterapi.CorePort, update telegramUpdate) error {
	message := update.Message
	kind := adapterapi.InboundKindMessage
	if message == nil {
		message = update.EditedMessage
		kind = adapterapi.InboundKindMessageUpdated
	}
	if message == nil || message.MessageID == 0 || message.Chat.ID == 0 || message.From.ID == 0 || message.From.IsBot {
		return nil
	}
	text := message.Text
	entities := message.Entities
	if text == "" {
		text = message.Caption
		entities = message.CaptionEntity
	}
	runtime.mu.Lock()
	selfID, selfName, token := runtime.selfID, runtime.selfName, runtime.token
	runtime.rememberUsername(message.From.Username, message.From.ID)
	segments := telegramInboundSegments(text, entities, selfID, selfName, runtime.usernames)
	runtime.mu.Unlock()

	conversation := FormatDiceIDTelegram(strconv.FormatInt(message.From.ID, 10))
	conversationKind := adapterapi.ConversationKindDirect
	if message.Chat.Type != "private" {
		conversationKind = adapterapi.ConversationKindGroup
		conversation = FormatDiceIDTelegramGroup(strconv.FormatInt(message.Chat.ID, 10))
	}
	inbound := adapterapi.InboundMessage{ProviderEventID: adapterapi.ProviderEventID("telegram-update:" + strconv.FormatInt(update.UpdateID, 10)), MessageID: adapterapi.MessageID(strconv.FormatInt(message.MessageID, 10)), Platform: "TG", Sender: adapterapi.PrincipalID(FormatDiceIDTelegram(strconv.FormatInt(message.From.ID, 10))), Conversation: adapterapi.ConversationID(conversation), ConversationKind: conversationKind, Target: conversation, Kind: kind, Segments: segments}
	if conversationKind == adapterapi.ConversationKindGroup {
		inbound.SenderRole = runtime.senderRole(ctx, token, message.Chat.ID, message.From.ID)
	}
	if len(segments) != 0 {
		inbound.Text = telegramSegmentsText(segments)
	}
	if message.Date > 0 {
		inbound.OccurredAt = time.Unix(message.Date, 0).UTC()
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
		return errors.New("telegram: ingress rejected")
	}
	return nil
}

// rememberUsername retains the first observed identity, matching the legacy
// cache. The caller holds runtime.mu.
func (runtime *telegramRuntime) rememberUsername(username string, id int64) {
	username = strings.TrimSpace(username)
	if username == "" || id == 0 {
		return
	}
	key := strings.ToLower(username)
	if runtime.usernames == nil {
		runtime.usernames = make(map[string]int64)
	}
	if _, exists := runtime.usernames[key]; exists {
		return
	}
	runtime.usernames[key] = id
}

// telegramInboundSegments converts Telegram text and UTF-16 entity offsets
// into structured mentions, preserving unresolved usernames as plain text.
func telegramInboundSegments(text string, entities []telegramEntity, selfID int64, selfName string, known map[string]int64) []adapterapi.InboundSegment {
	if text == "" {
		return nil
	}
	units := utf16.Encode([]rune(text))
	segments := make([]adapterapi.InboundSegment, 0, len(entities)+1)
	appendText := func(start, end int) {
		if start >= end || start < 0 || end > len(units) {
			return
		}
		if content := normalizeTelegramInboundText(string(utf16.Decode(units[start:end]))); content != "" {
			segments = append(segments, adapterapi.InboundSegment{Kind: "text", Text: content})
		}
	}
	index := 0
	for _, entity := range entities {
		if entity.Offset < index || entity.Offset+entity.Length > len(units) || entity.Length <= 0 {
			continue
		}
		appendText(index, entity.Offset)
		if target, ok := telegramEntityMentionID(entity, units, selfID, selfName, known); ok {
			segments = append(segments, adapterapi.InboundSegment{Kind: "mention", ProviderID: FormatDiceIDTelegram(strconv.FormatInt(target, 10))})
		} else {
			appendText(entity.Offset, entity.Offset+entity.Length)
		}
		index = entity.Offset + entity.Length
	}
	appendText(index, len(units))
	if len(segments) == 0 {
		return []adapterapi.InboundSegment{{Kind: "text", Text: normalizeTelegramInboundText(text)}}
	}
	return segments
}

// telegramEntityMentionID resolves an entity that denotes a concrete Telegram
// user. A non-nil result means the entity carries a resolvable identity;
// otherwise its original text must be preserved verbatim.
func telegramEntityMentionID(entity telegramEntity, units []uint16, selfID int64, selfName string, known map[string]int64) (int64, bool) {
	switch entity.Type {
	case "text_mention":
		if entity.User != nil && entity.User.ID != 0 {
			return entity.User.ID, true
		}
	case "mention":
		name := strings.TrimPrefix(string(utf16.Decode(units[entity.Offset:entity.Offset+entity.Length])), "@")
		if name == "" {
			return 0, false
		}
		if selfName != "" && strings.EqualFold(name, selfName) && selfID != 0 {
			return selfID, true
		}
		if id, ok := known[strings.ToLower(name)]; ok && id != 0 {
			return id, true
		}
	}
	return 0, false
}

// telegramSegmentsText renders segments back to the canonical text form so text
// only consumers still observe normalized <@provider-id> mentions.
func telegramSegmentsText(segments []adapterapi.InboundSegment) string {
	var builder strings.Builder
	for _, segment := range segments {
		switch segment.Kind {
		case "text":
			builder.WriteString(segment.Text)
		case "mention":
			_, _ = fmt.Fprintf(&builder, "<@%s>", ExtractTelegramUserID(segment.ProviderID))
		}
	}
	return builder.String()
}

// senderRole resolves the provider-declared group role for one sender, matching
// the legacy adapter semantics: creator -> owner, administrator -> admin, and
// every other status (or a failed lookup) -> no role. Lookups must never block
// ingestion into a false admin.
func (runtime *telegramRuntime) senderRole(ctx context.Context, token string, chatID, userID int64) string {
	role, err := runtime.lookupChatRole(ctx, token, chatID, userID)
	if err != nil {
		return ""
	}
	return role
}

func (runtime *telegramRuntime) lookupChatRole(ctx context.Context, token string, chatID, userID int64) (string, error) {
	if runtime.httpClient == nil {
		return "", errors.New("telegram: http client is unavailable")
	}
	data, err := runtime.request(ctx, token, "getChatMember", map[string]any{"chat_id": chatID, "user_id": userID})
	if err != nil {
		return "", err
	}
	var member struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(data, &member); err != nil {
		return "", err
	}
	switch member.Status {
	case "creator":
		return "owner", nil
	case "administrator":
		return "admin", nil
	default:
		return "", nil
	}
}

var telegramMentionPattern = regexp.MustCompile(`tg://user\?id=(\d+)`)

func normalizeTelegramInboundText(text string) string {
	return telegramMentionPattern.ReplaceAllString(text, `<@$1>`)
}

func (runtime *telegramRuntime) Stop(context.Context) error {
	if runtime == nil {
		return nil
	}
	runtime.mu.Lock()
	cancel := runtime.cancel
	runtime.cancel = nil
	runtime.running = false
	runtime.token = ""
	runtime.selfID = 0
	runtime.selfName = ""
	runtime.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return nil
}
