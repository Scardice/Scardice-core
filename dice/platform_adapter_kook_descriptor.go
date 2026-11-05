package dice

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"

	"Scardice-core/adapterapi"
	"Scardice-core/logger"
)

const KookAdapterKey adapterapi.AdapterKey = "kook"

type KookDescriptor struct{}

type kookConfigInput struct {
	Version    string          `json:"version"`
	Guild      string          `json:"guild"`
	Channel    string          `json:"channel"`
	APIBaseURL string          `json:"apiBaseURL"`
	Token      json.RawMessage `json:"token"`
}

type kookCanonicalConfig struct {
	Version    string                  `json:"version"`
	Guild      string                  `json:"guild"`
	Channel    string                  `json:"channel"`
	APIBaseURL string                  `json:"apiBaseURL"`
	Token      providerCanonicalSecret `json:"token"`
}

type kookRuntime struct {
	config   kookCanonicalConfig
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
	// timing overrides the protocol timers; the zero value selects the
	// documented defaults.
	timing kookTiming
}

// KOOK websocket timers, https://developer.kookapp.cn/doc/websocket: a ping
// every 30s, a pong within 6s, a hello within 6s, and an exponential redial
// backoff that starts at 2s and is capped at 60s.
const (
	defaultKookHeartbeatInterval = 30 * time.Second
	defaultKookPongTimeout       = 6 * time.Second
	defaultKookHelloTimeout      = 6 * time.Second
	defaultKookReconnectBase     = 2 * time.Second
	defaultKookReconnectMax      = 60 * time.Second
	// A gateway-directed reconnect that arrives sooner than this after the
	// connection was established counts as a loop, not an instruction.
	defaultKookReconnectLoopWindow = 5 * time.Second
	defaultKookInboundRetryDelay   = 200 * time.Millisecond
	kookInboundQueueSize           = 512
	maxKookInboundRetries          = 2
)

type kookTiming struct {
	heartbeatInterval time.Duration
	pongTimeout       time.Duration
	helloTimeout      time.Duration
	reconnectBase     time.Duration
	reconnectMax      time.Duration
	inboundRetryDelay time.Duration
	// reconnectLoopWindow is how long a session must have lived for a
	// gateway-directed reconnect to be redialed at once.
	reconnectLoopWindow time.Duration
}

type kookReadResult struct {
	messageType int
	data        []byte
	err         error
}

type kookEnvelope struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

type kookGatewayPayload struct {
	Signal   int             `json:"s"`
	Sequence int64           `json:"sn"`
	Data     json.RawMessage `json:"d"`
}

type kookGatewayUser struct {
	ID       string `json:"id"`
	Nickname string `json:"nickname"`
	Bot      bool   `json:"bot"`
}

type kookGatewayMessage struct {
	ChannelType string          `json:"channel_type"`
	Type        int             `json:"type"`
	TargetID    string          `json:"target_id"`
	AuthorID    string          `json:"author_id"`
	Content     string          `json:"content"`
	MessageID   string          `json:"msg_id"`
	Timestamp   int64           `json:"msg_timestamp"`
	Extra       json.RawMessage `json:"extra"`
}
type kookCard struct {
	Type    string        `json:"type"`
	Modules []interface{} `json:"modules"`
	Theme   string        `json:"theme"`
	Size    string        `json:"size"`
}

type kookCardTextModule struct {
	Type string              `json:"type"`
	Text kookCardTextContent `json:"text"`
}

type kookCardTextContent struct {
	Content string `json:"content"`
	Type    string `json:"type"`
}

func kookCardContent(segments []adapterapi.MessageSegment, plainText string) (string, error) {
	modules := make([]interface{}, 0, len(segments))
	if plainText != "" {
		modules = append(modules, kookCardTextModule{Type: "section", Text: kookCardTextContent{Content: plainText, Type: "plain-text"}})
	}
	for _, segment := range segments {
		switch segment.Kind {
		case adapterapi.SegmentKindText:
			modules = append(modules, kookCardTextModule{Type: "section", Text: kookCardTextContent{Content: segment.Text, Type: "plain-text"}})
		case adapterapi.SegmentKindMention:
			modules = append(modules, kookCardTextModule{Type: "section", Text: kookCardTextContent{Content: "(met)" + strings.TrimPrefix(segment.Text, "KOOK:") + "(met)", Type: "kmarkdown"}})
		case adapterapi.SegmentKindImage, adapterapi.SegmentKindFile:
			return "", errors.New("kook_artifact_reader_unavailable")
		default:
			return "", errors.New("kook_unknown_segment")
		}
	}
	if len(modules) == 0 {
		return "", errors.New("kook_empty_message")
	}
	content, err := json.Marshal([]kookCard{{Type: "card", Modules: modules, Theme: "primary", Size: "lg"}})
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func NewKookDescriptor() adapterapi.Descriptor { return KookDescriptor{} }

func (KookDescriptor) Key() adapterapi.AdapterKey { return KookAdapterKey }

func (KookDescriptor) ConfigVersion() uint16 { return 1 }
func FormatDiceIDKook(id string) string {
	return fmt.Sprintf("KOOK:%s", id)
}

func FormatDiceIDKookGuild(id string) string {
	return fmt.Sprintf("KOOK-Guild:%s", id)
}

func FormatDiceIDKookChannel(id string) string {
	return fmt.Sprintf("KOOK-CH-Group:%s", id)
}

func ExtractKookUserID(id string) string {
	return strings.TrimPrefix(id, "KOOK:")
}

func ExtractKookChannelID(id string) string {
	return strings.TrimPrefix(id, "KOOK-CH-Group:")
}

func ExtractKookGuildID(id string) string {
	return strings.TrimPrefix(id, "KOOK-Guild:")
}

func kookSupportedActions() adapterapi.ActionSet {
	return adapterapi.ActionSet(0).With(
		adapterapi.ActionKindSendMessage,
		adapterapi.ActionKindRecallMessage,
		adapterapi.ActionKindEditMessage,
		adapterapi.ActionKindSetGroupCard,
		adapterapi.ActionKindQuit,
		adapterapi.ActionKindGroupInfoRefresh,
	)
}

func (KookDescriptor) SupportedActions(adapterapi.ValidatedConfig) adapterapi.ActionSet {
	return kookSupportedActions()
}

func (KookDescriptor) Capabilities(adapterapi.ValidatedConfig) adapterapi.CapabilitySet {
	return adapterapi.CapabilityLifecycle | adapterapi.CapabilityInbound | adapterapi.CapabilityOutbound | adapterapi.CapabilityActions | adapterapi.CapabilityRichMessages
}

func (KookDescriptor) ValidateConfig(ctx context.Context, raw json.RawMessage) (adapterapi.ValidatedConfig, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	var input kookConfigInput
	if err := decodeStrictProviderJSON(raw, &input); err != nil {
		return adapterapi.ValidatedConfig{}, fmt.Errorf("kook: invalid config: %w", err)
	}
	if input.Version != "1" {
		return adapterapi.ValidatedConfig{}, errors.New("kook: unsupported config version")
	}
	var token providerCanonicalSecret
	if err := decodeStrictProviderJSON(input.Token, &token); err != nil || token.Version == 0 {
		return adapterapi.ValidatedConfig{}, errors.New("kook: invalid token reference")
	}
	ref := adapterapi.SecretRef{Ref: token.SecretRef, Version: token.Version}
	if err := ref.Validate(); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	apiBaseURL, err := normalizeProviderHTTPURL(input.APIBaseURL, true)
	if err != nil {
		return adapterapi.ValidatedConfig{}, fmt.Errorf("kook: invalid apiBaseURL: %w", err)
	}
	encoded, err := json.Marshal(kookCanonicalConfig{Version: input.Version, Guild: strings.TrimSpace(input.Guild), Channel: strings.TrimSpace(input.Channel), APIBaseURL: apiBaseURL, Token: token})
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

func (descriptor KookDescriptor) NewRuntime(init adapterapi.RuntimeInit) (adapterapi.AdapterRuntime, error) {
	if !init.EndpointID.Valid() || init.Generation == 0 || init.DesiredVersion == 0 {
		return nil, errors.New("kook: runtime identity is incomplete")
	}
	if err := init.Config.Validate(); err != nil {
		return nil, err
	}
	validated, err := descriptor.ValidateConfig(context.Background(), init.Config.Canonical)
	if err != nil || validated.Version != init.Config.Version || !bytes.Equal(validated.Canonical, init.Config.Canonical) || len(validated.SecretRefs) != len(init.Config.SecretRefs) {
		return nil, errors.New("kook: runtime config was not validated by descriptor")
	}
	for index := range validated.SecretRefs {
		if validated.SecretRefs[index] != init.Config.SecretRefs[index] {
			return nil, errors.New("kook: runtime secret references do not match")
		}
	}
	var config kookCanonicalConfig
	if err := json.Unmarshal(init.Config.Canonical, &config); err != nil {
		return nil, errors.New("kook: invalid canonical runtime config")
	}
	return &kookRuntime{config: config, tokenRef: adapterapi.SecretRef{Ref: config.Token.SecretRef, Version: config.Token.Version}, resolver: init.Secrets, httpClient: &http.Client{Timeout: 20 * time.Second}, dialer: websocket.DefaultDialer}, nil
}

func (*kookRuntime) OwnedResources() adapterapi.OwnedResourceManifest {
	return adapterapi.OwnedResourceManifest{}
}

func (*kookRuntime) Capabilities() adapterapi.CapabilitySet {
	return adapterapi.CapabilityLifecycle | adapterapi.CapabilityInbound | adapterapi.CapabilityOutbound | adapterapi.CapabilityActions | adapterapi.CapabilityRichMessages
}

func (*kookRuntime) Diagnostics(context.Context) adapterapi.DiagnosticReport {
	return adapterapi.DiagnosticReport{}
}

func (runtime *kookRuntime) Execute(ctx context.Context, effect adapterapi.OutboundEffect) adapterapi.EffectResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if effect.Version != adapterapi.EffectVersionOne {
		return adapterapi.UnsupportedResult("kook_invalid_effect_version")
	}
	if err := effect.ValidateForCapabilities(runtime.Capabilities(), kookSupportedActions()); err != nil {
		return adapterapi.UnsupportedResult("kook_effect_not_supported")
	}
	runtime.mu.Lock()
	token, selfID := runtime.token, runtime.selfID
	runtime.mu.Unlock()
	if token == "" || selfID == "" {
		return adapterapi.TerminalResult("kook_provider_unavailable", "provider unavailable")
	}
	payload := effect.Payload
	switch payload.Kind {
	case adapterapi.EffectPayloadEdit, adapterapi.EffectPayloadRecall:
		if payload.Target.Kind != adapterapi.TargetGroup && payload.Target.Kind != adapterapi.TargetPerson {
			return adapterapi.UnsupportedResult("kook_invalid_target")
		}
		private := payload.Target.Kind == adapterapi.TargetPerson
		path := "/message/delete"
		body := map[string]any{"msg_id": string(payload.MessageID)}
		if payload.Kind == adapterapi.EffectPayloadEdit {
			path = "/message/update"
			body["content"] = payload.Text
		}
		if private {
			userID := strings.TrimPrefix(payload.Target.Conversation.String(), "KOOK:")
			if userID == payload.Target.Conversation.String() || userID == "" {
				return adapterapi.UnsupportedResult("kook_invalid_target")
			}
			chatCode, err := runtime.privateChatCode(ctx, token, userID)
			if err != nil {
				return adapterapi.AmbiguousResult("kook_provider_ambiguous", "provider dispatch outcome is unknown")
			}
			if payload.Kind == adapterapi.EffectPayloadEdit {
				path = "/direct-message/update"
			} else {
				path = "/direct-message/delete"
			}
			body["chat_code"] = chatCode
		} else {
			channelID := strings.TrimPrefix(payload.Target.Conversation.String(), "KOOK-CH-Group:")
			if channelID == payload.Target.Conversation.String() || channelID == "" {
				return adapterapi.UnsupportedResult("kook_invalid_target")
			}
		}
		if _, err := runtime.request(ctx, token, http.MethodPost, path, body); err != nil {
			return adapterapi.AmbiguousResult("kook_provider_ambiguous", "provider dispatch outcome is unknown")
		}
		return adapterapi.SucceededResult(string(payload.MessageID))
	case adapterapi.EffectPayloadSetGroupCard, adapterapi.EffectPayloadQuit, adapterapi.EffectPayloadGroupInfoRefresh:
		if payload.Target.Kind != adapterapi.TargetGroup {
			return adapterapi.UnsupportedResult("kook_invalid_target")
		}
		channelID := strings.TrimPrefix(payload.Target.Conversation.String(), "KOOK-CH-Group:")
		if channelID == payload.Target.Conversation.String() || channelID == "" {
			return adapterapi.UnsupportedResult("kook_invalid_target")
		}
		info, err := runtime.channelInfo(ctx, token, channelID)
		if err != nil {
			return adapterapi.AmbiguousResult("kook_provider_ambiguous", "provider dispatch outcome is unknown")
		}
		switch payload.Kind {
		case adapterapi.EffectPayloadGroupInfoRefresh:
			return adapterapi.SucceededResult(info.ID)
		case adapterapi.EffectPayloadQuit:
			if info.GuildID == "" {
				return adapterapi.UnsupportedResult("kook_invalid_response")
			}
			if _, err := runtime.request(ctx, token, http.MethodPost, "/guild/leave", map[string]string{"guild_id": info.GuildID}); err != nil {
				return adapterapi.AmbiguousResult("kook_provider_ambiguous", "provider dispatch outcome is unknown")
			}
			return adapterapi.SucceededResult("")
		case adapterapi.EffectPayloadSetGroupCard:
			guildID := info.GuildID
			if guildID == "" {
				guildID = ExtractKookGuildID(runtime.config.Guild)
			}
			memberID := ExtractKookUserID(string(payload.Target.Member))
			if guildID == "" || memberID == "" {
				return adapterapi.UnsupportedResult("kook_invalid_target")
			}
			if _, err := runtime.request(ctx, token, http.MethodPost, "/guild/nickname", map[string]string{"guild_id": guildID, "user_id": memberID, "nickname": payload.Card}); err != nil {
				return adapterapi.AmbiguousResult("kook_provider_ambiguous", "provider dispatch outcome is unknown")
			}
			return adapterapi.SucceededResult("")
		default:
			return adapterapi.UnsupportedResult("kook_effect_not_supported")
		}
	case adapterapi.EffectPayloadGroupText, adapterapi.EffectPayloadPersonText, adapterapi.EffectPayloadSegments:
		private := payload.Target.Kind == adapterapi.TargetPerson
		if !private && payload.Target.Kind != adapterapi.TargetGroup {
			return adapterapi.UnsupportedResult("kook_invalid_target")
		}
		cardText, err := kookCardContent(payload.Segments, payload.Text)
		if err != nil {
			return adapterapi.UnsupportedResult(err.Error())
		}
		path := "/message/create"
		targetID := strings.TrimPrefix(payload.Target.Conversation.String(), "KOOK-CH-Group:")
		body := map[string]any{"type": 7, "target_id": targetID, "content": cardText}
		if private {
			targetID = strings.TrimPrefix(payload.Target.Conversation.String(), "KOOK:")
			if targetID == payload.Target.Conversation.String() || targetID == "" {
				return adapterapi.UnsupportedResult("kook_invalid_target")
			}
			chatCode, err := runtime.privateChatCode(ctx, token, targetID)
			if err != nil {
				return adapterapi.AmbiguousResult("kook_provider_ambiguous", "provider dispatch outcome is unknown")
			}
			path = "/direct-message/create"
			body = map[string]any{"type": 7, "chat_code": chatCode, "content": cardText}
		} else if targetID == payload.Target.Conversation.String() || targetID == "" {
			return adapterapi.UnsupportedResult("kook_invalid_target")
		}
		data, err := runtime.request(ctx, token, http.MethodPost, path, body)
		if err != nil {
			return adapterapi.AmbiguousResult("kook_provider_ambiguous", "provider dispatch outcome is unknown")
		}
		var result struct {
			MessageID string `json:"msg_id"`
		}
		if err := json.Unmarshal(data, &result); err != nil || result.MessageID == "" {
			return adapterapi.TerminalResult("kook_invalid_response", "provider returned an invalid response")
		}
		return adapterapi.SucceededResult(result.MessageID)
	default:
		return adapterapi.UnsupportedResult("kook_effect_not_supported")
	}
}

func (runtime *kookRuntime) privateChatCode(ctx context.Context, token, userID string) (string, error) {
	chatData, err := runtime.request(ctx, token, http.MethodPost, "/user-chat/create", map[string]string{"target_id": userID})
	if err != nil {
		return "", err
	}
	var chat struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(chatData, &chat); err != nil || chat.Code == "" {
		return "", errors.New("kook: invalid private chat response")
	}
	return chat.Code, nil
}

type kookChannelInfo struct {
	ID      string `json:"id"`
	GuildID string `json:"guild_id"`
}

func (runtime *kookRuntime) channelInfo(ctx context.Context, token, channelID string) (kookChannelInfo, error) {
	path := "/channel/view?target_id=" + url.QueryEscape(channelID)
	data, err := runtime.request(ctx, token, http.MethodGet, path, nil)
	if err != nil {
		return kookChannelInfo{}, err
	}
	var info kookChannelInfo
	if err := json.Unmarshal(data, &info); err != nil || info.ID == "" {
		return kookChannelInfo{}, errors.New("kook: invalid channel response")
	}
	return info, nil
}

func (runtime *kookRuntime) apiBase() string {
	if runtime.config.APIBaseURL != "" {
		return runtime.config.APIBaseURL + "/api/v3"
	}
	return "https://www.kookapp.cn/api/v3"
}

func (runtime *kookRuntime) request(ctx context.Context, token, method, path string, body any) (json.RawMessage, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, runtime.apiBase()+path, reader)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bot "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := runtime.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("kook: provider returned %s", response.Status)
	}
	var envelope kookEnvelope
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&envelope); err != nil {
		return nil, err
	}
	if envelope.Code != 0 {
		return nil, fmt.Errorf("kook: provider rejected request: %s", envelope.Message)
	}
	return envelope.Data, nil
}

// senderRole mirrors the legacy Kook check: the guild master, or a member whose
// aggregated role permissions include ADMINISTRATOR, KICK_USER or BAN_USER.
// A failed lookup resolves to no role instead of granting elevated rights.
func (runtime *kookRuntime) senderRole(ctx context.Context, token, guildID, userID string) string {
	if token == "" || guildID == "" || userID == "" {
		return ""
	}
	role, err := runtime.lookupGuildRole(ctx, token, guildID, userID)
	if err != nil {
		return ""
	}
	return role
}

func (runtime *kookRuntime) lookupGuildRole(ctx context.Context, token, guildID, userID string) (string, error) {
	if runtime.httpClient == nil {
		return "", errors.New("kook: http client is unavailable")
	}
	userData, err := runtime.request(ctx, token, http.MethodGet, "/user/view?user_id="+url.QueryEscape(userID)+"&guild_id="+url.QueryEscape(guildID), nil)
	if err != nil {
		return "", err
	}
	var user struct {
		Roles []int64 `json:"roles"`
	}
	if err := json.Unmarshal(userData, &user); err != nil {
		return "", err
	}
	guildData, err := runtime.request(ctx, token, http.MethodGet, "/guild/view?guild_id="+url.QueryEscape(guildID), nil)
	if err != nil {
		return "", err
	}
	var guild struct {
		MasterID string `json:"master_id"`
		Roles    []struct {
			RoleID      int64 `json:"role_id"`
			Permissions int64 `json:"permissions"`
		} `json:"roles"`
	}
	if err := json.Unmarshal(guildData, &guild); err != nil {
		return "", err
	}
	if userID == guild.MasterID {
		return "admin", nil
	}
	assigned := make(map[int64]struct{}, len(user.Roles))
	for _, role := range user.Roles {
		assigned[role] = struct{}{}
	}
	for _, role := range guild.Roles {
		if _, ok := assigned[role.RoleID]; !ok {
			continue
		}
		if role.Permissions&(kookPermissionAdmin|kookPermissionKickUser|kookPermissionBanUser) > 0 {
			return "admin", nil
		}
	}
	return "", nil
}

const (
	kookPermissionAdmin    = 1 << 0
	kookPermissionKickUser = 1 << 6
	kookPermissionBanUser  = 1 << 7
)

func (runtime *kookRuntime) resolveToken(ctx context.Context) (string, error) {
	if runtime == nil || runtime.resolver == nil {
		return "", errors.New("kook: token resolver is unavailable")
	}
	value, err := runtime.resolver.Resolve(ctx, runtime.tokenRef)
	if err != nil {
		return "", err
	}
	if value.Version != runtime.tokenRef.Version || len(value.Bytes) == 0 {
		return "", errors.New("kook: token resolution is invalid")
	}
	return string(value.Bytes), nil
}

// kookSessionError is the failure of one gateway session. Run redials after
// it; any other error ends Run. A directed error is the gateway telling a
// healthy client to reconnect (signal 5): Run redials at once and does not
// report an outage.
type kookSessionError struct {
	code     string
	err      error
	directed bool
}

func (e *kookSessionError) Error() string { return e.code + ": " + e.err.Error() }
func (e *kookSessionError) Unwrap() error { return e.err }

func kookSessionFailure(code string, err error) error { return &kookSessionError{code: code, err: err} }

// kookReconnectReason describes the reconnect codes the gateway documents.
func kookReconnectReason(code int64) string {
	switch code {
	case 40106:
		return "resume failed: missing parameters"
	case 40107:
		return "session expired"
	case 40108:
		return "invalid or expired sn"
	}
	return ""
}

// kookReconnectRequest reads the code and message of a signal-5 payload. The
// documented code is a number; a string, a missing or a malformed payload must
// not stop the client from reconnecting, so every failure yields zero values.
func kookReconnectRequest(data json.RawMessage) (code int64, message string) {
	var payload struct {
		Code json.Number `json:"code"`
		Err  string      `json:"err"`
	}
	_ = json.Unmarshal(data, &payload)
	code, _ = payload.Code.Int64()
	return code, payload.Err
}

func (timing kookTiming) withDefaults() kookTiming {
	if timing.heartbeatInterval <= 0 {
		timing.heartbeatInterval = defaultKookHeartbeatInterval
	}
	if timing.pongTimeout <= 0 {
		timing.pongTimeout = defaultKookPongTimeout
	}
	if timing.helloTimeout <= 0 {
		timing.helloTimeout = defaultKookHelloTimeout
	}
	if timing.reconnectBase <= 0 {
		timing.reconnectBase = defaultKookReconnectBase
	}
	if timing.reconnectLoopWindow <= 0 {
		timing.reconnectLoopWindow = defaultKookReconnectLoopWindow
	}
	if timing.reconnectMax <= 0 {
		timing.reconnectMax = defaultKookReconnectMax
	}
	if timing.inboundRetryDelay <= 0 {
		timing.inboundRetryDelay = defaultKookInboundRetryDelay
	}
	return timing
}

// redialDelay is the wait before redial number attempt (0-based): the base,
// doubled per consecutive failure, capped at the maximum.
func (timing kookTiming) redialDelay(attempt int) time.Duration {
	if attempt >= 30 {
		return timing.reconnectMax
	}
	if delay := timing.reconnectBase << attempt; delay > 0 && delay < timing.reconnectMax {
		return delay
	}
	return timing.reconnectMax
}

func kookRuntimeLogger() *zap.SugaredLogger { return zap.S().Named(logger.LogKeyAdapter) }

// Run keeps one gateway session open until Stop. A session that fails (gateway
// unreachable, no hello, no pong, reconnect signal, closed transport) is
// reported once as failed per outage, then redialed with exponential backoff;
// only a local, non-retryable fault ends Run.
func (runtime *kookRuntime) Run(ctx context.Context, core adapterapi.CorePort) (runErr error) {
	if runtime == nil || core == nil {
		return errors.New("kook: runtime or core is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithCancel(ctx)
	runtime.mu.Lock()
	if runtime.cancel != nil {
		runtime.mu.Unlock()
		cancel()
		return errors.New("kook: runtime already started")
	}
	runtime.cancel, runtime.running = cancel, true
	runtime.mu.Unlock()
	defer func() {
		if runErr != nil && !errors.Is(runErr, context.Canceled) {
			_ = core.ReportObservation(context.Background(), adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateFailed, Code: "runtime_failed", Detail: "Kook runtime failed", Retryable: true, OccurredAt: time.Now().UTC()})
		}
		_ = runtime.Stop(context.Background())
	}()
	if err := core.ReportObservation(runCtx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateStarting, Code: "starting", Detail: "Kook runtime starting", OccurredAt: time.Now().UTC()}); err != nil {
		return err
	}
	token, err := runtime.resolveToken(runCtx)
	if err != nil {
		return err
	}
	timing := runtime.timing.withDefaults()
	// One worker serves every session of this Run, so events reach Core in
	// arrival order and a slow Core never stalls the socket.
	jobs := make(chan json.RawMessage, kookInboundQueueSize)
	runtime.mu.Lock()
	if !runtime.running {
		runtime.mu.Unlock()
		return nil
	}
	runtime.wg.Add(1)
	runtime.mu.Unlock()
	go runtime.inboundWorker(runCtx, core, jobs, timing)
	log := kookRuntimeLogger()
	outage, attempts := false, 0
	var connectedAt time.Time
	onConnected := func() {
		if outage {
			log.Infof("Kook 连接已恢复")
		}
		outage, attempts = false, 0
		connectedAt = time.Now()
	}
	for {
		connectedAt = time.Time{}
		err := runtime.runSession(runCtx, core, token, timing, jobs, onConnected)
		if runCtx.Err() != nil || errors.Is(err, context.Canceled) {
			return nil
		}
		var failure *kookSessionError
		if !errors.As(err, &failure) {
			return err
		}
		cause := sanitizeOnebotProviderCause(failure.err.Error())
		if failure.directed && !connectedAt.IsZero() && time.Since(connectedAt) >= timing.reconnectLoopWindow {
			// The gateway told a healthy session to reconnect. Events still
			// queued from it are real messages (Core de-duplicates by provider
			// message ID) and stay queued; only the sequence is discarded, with
			// the session.
			log.Infof("Kook 网关要求重新连接（%s）：%s；正在重新连接", failure.code, cause)
			attempts = 0
			continue
		}
		if !outage {
			outage = true
			_ = core.ReportObservation(runCtx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateFailed, Code: failure.code, Detail: cause, Retryable: true, OccurredAt: time.Now().UTC()})
			log.Warnf("Kook 连接中断（%s）：%s；将自动重连", failure.code, cause)
		} else {
			log.Debugf("Kook 重连失败（%s）：%s", failure.code, cause)
		}
		redial := time.NewTimer(timing.redialDelay(attempts))
		attempts++
		select {
		case <-runCtx.Done():
			redial.Stop()
			return nil
		case <-redial.C:
		}
	}
}

// runSession fetches a fresh gateway, connects and serves it until it fails.
// Each session starts from sn 0: a new gateway session numbers its events
// afresh, and after a reconnect signal the local sequence must not survive.
func (runtime *kookRuntime) runSession(ctx context.Context, core adapterapi.CorePort, token string, timing kookTiming, jobs chan<- json.RawMessage, onConnected func()) error {
	gatewayData, err := runtime.request(ctx, token, http.MethodGet, "/gateway/index?compress=0", nil)
	if err != nil {
		return kookSessionFailure("connect_failed", err)
	}
	var gatewayResult struct {
		URL string `json:"url"`
	}
	if decodeErr := json.Unmarshal(gatewayData, &gatewayResult); decodeErr != nil {
		return kookSessionFailure("connect_failed", decodeErr)
	}
	gatewayURL, err := url.Parse(gatewayResult.URL)
	if err != nil || gatewayURL.Host == "" || (gatewayURL.Scheme != "ws" && gatewayURL.Scheme != "wss") || gatewayURL.User != nil || gatewayURL.Fragment != "" {
		return kookSessionFailure("connect_failed", errors.New("kook: invalid gateway URL"))
	}
	selfData, err := runtime.request(ctx, token, http.MethodGet, "/user/me", nil)
	if err != nil {
		return kookSessionFailure("connect_failed", err)
	}
	var self kookGatewayUser
	if decodeErr := json.Unmarshal(selfData, &self); decodeErr != nil || self.ID == "" {
		return kookSessionFailure("connect_failed", errors.New("kook: invalid self identity"))
	}
	headers := http.Header{"Authorization": []string{"Bot " + token}}
	connection, response, err := runtime.dialer.DialContext(ctx, gatewayURL.String(), headers)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		return kookSessionFailure("connect_failed", err)
	}
	defer connection.Close()
	connection.SetReadLimit(adapterapi.MaxInboundTextBytes + 64*1024)
	runtime.mu.Lock()
	if !runtime.running {
		runtime.mu.Unlock()
		return context.Canceled
	}
	runtime.conn = connection
	runtime.mu.Unlock()
	defer func() {
		runtime.mu.Lock()
		if runtime.conn == connection {
			runtime.conn = nil
		}
		runtime.mu.Unlock()
	}()

	_ = connection.SetReadDeadline(time.Now().Add(timing.helloTimeout))
	messageType, helloBytes, err := connection.ReadMessage()
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return kookSessionFailure("hello_timeout", errors.New("kook: gateway did not send hello in time"))
		}
		return kookSessionFailure("remote_closed", err)
	}
	_ = connection.SetReadDeadline(time.Time{})
	helloBytes, err = decodeKookFrame(messageType, helloBytes)
	if err != nil {
		return kookSessionFailure("hello_failed", err)
	}
	var hello kookGatewayPayload
	if decodeErr := json.Unmarshal(helloBytes, &hello); decodeErr != nil || hello.Signal != 1 {
		return kookSessionFailure("hello_failed", errors.New("kook: gateway did not send hello"))
	}
	var helloData struct {
		Code int `json:"code"`
	}
	if decodeErr := json.Unmarshal(hello.Data, &helloData); decodeErr != nil || helloData.Code != 0 {
		return kookSessionFailure("hello_failed", fmt.Errorf("kook: invalid gateway hello (code %d)", helloData.Code))
	}
	reads := make(chan kookReadResult, 1)
	runtime.mu.Lock()
	if !runtime.running {
		runtime.mu.Unlock()
		return context.Canceled
	}
	runtime.token, runtime.selfID = token, self.ID
	runtime.wg.Add(1)
	runtime.mu.Unlock()
	sessionCtx, cancelSession := context.WithCancel(ctx)
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		runtime.readLoop(sessionCtx, connection, reads)
	}()
	defer func() {
		cancelSession()
		_ = connection.Close()
		<-readerDone
	}()
	// The first ping is due one interval after the hello, not after the
	// observations below have been published.
	heartbeat := time.NewTimer(timing.heartbeatInterval)
	defer heartbeat.Stop()
	if reportErr := core.ReportObservation(ctx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateConnected, Code: "connected", Detail: "Kook connection established", OccurredAt: time.Now().UTC()}); reportErr != nil {
		return reportErr
	}
	onConnected()
	providerID, err := adapterapi.NewPrincipalID(FormatDiceIDKook(self.ID))
	if err != nil {
		return err
	}
	if err := core.ReportObservation(ctx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationIdentity, State: adapterapi.ObservedStateConnected, ProviderID: providerID, Code: "identity", OccurredAt: time.Now().UTC()}); err != nil {
		return err
	}

	// A ping goes out every heartbeat interval; the gateway must answer it
	// with a pong (s=3) within the pong timeout, or the session is dead.
	var pongTimer *time.Timer
	var pongDeadline <-chan time.Time
	defer func() {
		if pongTimer != nil {
			pongTimer.Stop()
		}
	}()
	var sequence int64
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case result := <-reads:
			if result.err != nil {
				return kookSessionFailure("remote_closed", result.err)
			}
			payloadBytes, err := decodeKookFrame(result.messageType, result.data)
			if err != nil {
				return kookSessionFailure("frame_invalid", err)
			}
			var payload kookGatewayPayload
			if err := json.Unmarshal(payloadBytes, &payload); err != nil {
				return kookSessionFailure("frame_invalid", err)
			}
			switch payload.Signal {
			case 0:
				// An sn at or below the processed maximum was handled already.
				if payload.Sequence > 0 && payload.Sequence <= sequence {
					continue
				}
				select {
				case jobs <- payload.Data:
				default:
					kookRuntimeLogger().Warnf("Kook 消息队列已满，丢弃一条消息（sn=%d）", payload.Sequence)
				}
				if payload.Sequence > sequence {
					sequence = payload.Sequence
				}
			case 3:
				if pongTimer != nil {
					pongTimer.Stop()
					pongTimer, pongDeadline = nil, nil
				}
			case 5:
				code, message := kookReconnectRequest(payload.Data)
				detail := fmt.Sprintf("kook: gateway requested reconnect (code %d", code)
				if reason := kookReconnectReason(code); reason != "" {
					detail += ": " + reason
				}
				if message != "" {
					detail += "; " + message
				}
				return &kookSessionError{code: "reconnect_requested", err: errors.New(detail + ")"), directed: true}
			}
		case <-heartbeat.C:
			_ = connection.SetWriteDeadline(time.Now().Add(timing.pongTimeout))
			if err := connection.WriteJSON(map[string]any{"s": 2, "sn": sequence}); err != nil {
				return kookSessionFailure("heartbeat_failed", err)
			}
			if pongTimer == nil {
				pongTimer = time.NewTimer(timing.pongTimeout)
				pongDeadline = pongTimer.C
			}
			heartbeat.Reset(timing.heartbeatInterval)
		case <-pongDeadline:
			return kookSessionFailure("heartbeat_timeout", errors.New("kook: gateway did not answer the heartbeat"))
		}
	}
}

func decodeKookFrame(messageType int, data []byte) ([]byte, error) {
	if messageType != websocket.BinaryMessage {
		return data, nil
	}
	reader, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(io.LimitReader(reader, adapterapi.MaxInboundTextBytes+64*1024))
}

func (runtime *kookRuntime) handleEvent(ctx context.Context, core adapterapi.CorePort, data json.RawMessage) error {
	var message kookGatewayMessage
	if err := json.Unmarshal(data, &message); err != nil {
		return err
	}
	if message.Type != 1 && message.Type != 2 && message.Type != 9 {
		return nil
	}
	var extra struct {
		GuildID    string          `json:"guild_id"`
		Author     kookGatewayUser `json:"author"`
		RawContent string          `json:"raw_content"`
	}
	if err := json.Unmarshal(message.Extra, &extra); err != nil {
		return err
	}
	if extra.Author.Bot || message.AuthorID == "" || message.MessageID == "" || message.TargetID == "" {
		return nil
	}
	text := message.Content
	if message.Type == 9 && extra.RawContent != "" {
		text = extra.RawContent
	}
	text = normalizeKookInboundText(text)

	conversation := FormatDiceIDKook(message.AuthorID)
	conversationKind := adapterapi.ConversationKindDirect
	if message.ChannelType != "PERSON" {
		conversationKind = adapterapi.ConversationKindGroup
		conversation = FormatDiceIDKookChannel(message.TargetID)
	}
	inbound := adapterapi.InboundMessage{ProviderEventID: adapterapi.ProviderEventID("kook-message-created:" + message.MessageID), MessageID: adapterapi.MessageID(message.MessageID), Platform: "KOOK", Sender: adapterapi.PrincipalID(FormatDiceIDKook(message.AuthorID)), Conversation: adapterapi.ConversationID(conversation), ConversationKind: conversationKind, Target: conversation, Kind: adapterapi.InboundKindMessage, Text: text}
	if conversationKind == adapterapi.ConversationKindGroup {
		runtime.mu.Lock()
		token := runtime.token
		runtime.mu.Unlock()
		inbound.SenderRole = runtime.senderRole(ctx, token, extra.GuildID, message.AuthorID)
	}
	if text != "" {
		inbound.Segments = []adapterapi.InboundSegment{{Kind: "text", Text: text}}
	}
	if message.Type == 2 && message.Content != "" {
		inbound.Segments = []adapterapi.InboundSegment{{Kind: "image", URL: message.Content}}
	}
	if message.Timestamp > 0 {
		inbound.OccurredAt = time.UnixMilli(message.Timestamp).UTC()
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
		return errKookIngressRejected
	}
	return nil
}

var errKookIngressRejected = errors.New("kook: ingress rejected")

// inboundWorker hands queued gateway events to Core one at a time. A message
// Core refuses is a fact about that message, not about the connection: it is
// retried when Core reports a transient condition, then dropped and logged,
// and never ends the session.
func (runtime *kookRuntime) inboundWorker(ctx context.Context, core adapterapi.CorePort, jobs <-chan json.RawMessage, timing kookTiming) {
	defer runtime.wg.Done()
	log := kookRuntimeLogger()
	for {
		select {
		case <-ctx.Done():
			return
		case data := <-jobs:
			err := runtime.handleEvent(ctx, core, data)
			for attempt := 0; err != nil && isRetryableInboundError(err) && attempt < maxKookInboundRetries; attempt++ {
				retry := time.NewTimer(timing.inboundRetryDelay)
				select {
				case <-ctx.Done():
					retry.Stop()
					return
				case <-retry.C:
				}
				err = runtime.handleEvent(ctx, core, data)
			}
			if err != nil && ctx.Err() == nil {
				log.Warnf("Kook 消息未能交给核心，已丢弃：%s", sanitizeOnebotProviderCause(err.Error()))
			}
		}
	}
}
func normalizeKookInboundText(text string) string {
	for {
		start := strings.Index(text, "(met)")
		if start < 0 {
			return text
		}
		idStart := start + len("(met)")
		endOffset := strings.Index(text[idStart:], "(met)")
		if endOffset < 0 {
			return text
		}
		end := idStart + endOffset
		if end == idStart {
			return text
		}
		text = text[:start] + "<@" + text[idStart:end] + ">" + text[end+len("(met)"):]
	}
}

func (runtime *kookRuntime) readLoop(ctx context.Context, connection *websocket.Conn, results chan<- kookReadResult) {
	defer runtime.wg.Done()
	for {
		messageType, data, err := connection.ReadMessage()
		select {
		case results <- kookReadResult{messageType: messageType, data: data, err: err}:
		case <-ctx.Done():
			return
		}
		if err != nil {
			return
		}
	}
}

func (runtime *kookRuntime) Stop(context.Context) error {
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
