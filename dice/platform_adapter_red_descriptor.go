package dice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/gorilla/websocket"

	"Scardice-core/adapterapi"
)

const RedAdapterKey adapterapi.AdapterKey = "red"

const redDispatchTimeout = 15 * time.Second
const redMaxHTTPResponseBytes = 4 << 20

// redMemberCacheTTL bounds how long one group's member list is reused before it
// is re-fetched. The provider exposes member permissions only through the
// group/getMemberList API, so every group message needs a lookup; caching keeps
// that to at most one request per group per TTL instead of one per message.
const redMemberCacheTTL = 60 * time.Second

// redMaxCachedGroups bounds the member cache so a hostile or very large account
// cannot grow it without limit.
const redMaxCachedGroups = 256

// redMemberLookupTimeout bounds one member-list request. The lookup happens
// inline in the gateway read loop, so it is deliberately shorter than a
// dispatch timeout: an unresponsive provider delays that group's role
// resolution but never stalls inbound handling for long.
const redMemberLookupTimeout = 5 * time.Second

var redMemberHTTPClient = &http.Client{
	Timeout: redMemberLookupTimeout,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

var errRedMalformedGatewayPayload = errors.New("red: malformed gateway payload")

type RedDescriptor struct{}

type redConfigInput struct {
	Version    string          `json:"version"`
	Device     string          `json:"device"`
	Protocol   string          `json:"protocol"`
	AppID      string          `json:"appId"`
	Host       string          `json:"host"`
	Port       int             `json:"port"`
	RedVersion string          `json:"redVersion"`
	Token      json.RawMessage `json:"token"`
}

type redCanonicalConfig struct {
	Version    string                  `json:"version"`
	Device     string                  `json:"device"`
	Protocol   string                  `json:"protocol"`
	AppID      string                  `json:"appId"`
	Host       string                  `json:"host"`
	Port       int                     `json:"port"`
	RedVersion string                  `json:"redVersion"`
	Token      providerCanonicalSecret `json:"token"`
}

type redRuntime struct {
	config          redCanonicalConfig
	tokenRef        adapterapi.SecretRef
	resolver        adapterapi.SecretResolver
	dialer          *websocket.Dialer
	dispatchTimeout time.Duration

	mu         sync.Mutex
	writeMu    sync.Mutex
	dispatchMu sync.Mutex
	cancel     context.CancelFunc
	runCtx     context.Context
	conn       *websocket.Conn
	replies    chan json.RawMessage
	wg         sync.WaitGroup
	running    bool
	connected  bool
	uncertain  bool

	// memberMu guards the per-group member-role cache. Entries are populated
	// lazily from group/getMemberList and expire after redMemberCacheTTL.
	memberMu    sync.Mutex
	memberCache map[string]redMemberCacheEntry
}

// redMemberCacheEntry is one group's cached member roles keyed by dice user ID
// (QQ:<uin>), together with the fetch time used for TTL expiry.
type redMemberCacheEntry struct {
	roles     map[string]string
	fetchedAt time.Time
}

type redReadResult struct {
	messageType int
	data        []byte
	err         error
}

type redGatewayFrame struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

func NewRedDescriptor() adapterapi.Descriptor { return RedDescriptor{} }

func (RedDescriptor) Key() adapterapi.AdapterKey { return RedAdapterKey }

func (RedDescriptor) ConfigVersion() uint16 { return 1 }

func (RedDescriptor) SupportedActions(adapterapi.ValidatedConfig) adapterapi.ActionSet {
	return adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage)
}

func (RedDescriptor) Capabilities(adapterapi.ValidatedConfig) adapterapi.CapabilitySet {
	return adapterapi.CapabilityLifecycle | adapterapi.CapabilityInbound | adapterapi.CapabilityOutbound
}

func (RedDescriptor) ValidateConfig(ctx context.Context, raw json.RawMessage) (adapterapi.ValidatedConfig, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	var input redConfigInput
	if err := decodeStrictProviderJSON(raw, &input); err != nil {
		return adapterapi.ValidatedConfig{}, fmt.Errorf("red: invalid config: %w", err)
	}
	if input.Version != "1" {
		return adapterapi.ValidatedConfig{}, errors.New("red: unsupported config version")
	}
	host, err := normalizeRedHost(input.Host)
	if err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	if input.Port < 1 || input.Port > 65535 {
		return adapterapi.ValidatedConfig{}, errors.New("red: port must be between 1 and 65535")
	}
	var secret providerCanonicalSecret
	if decodeErr := decodeStrictProviderJSON(input.Token, &secret); decodeErr != nil || secret.Version == 0 {
		return adapterapi.ValidatedConfig{}, errors.New("red: invalid token reference")
	}
	tokenRef := adapterapi.SecretRef{Ref: secret.SecretRef, Version: secret.Version}
	if validateErr := tokenRef.Validate(); validateErr != nil {
		return adapterapi.ValidatedConfig{}, validateErr
	}
	encoded, err := json.Marshal(redCanonicalConfig{
		Version:    input.Version,
		Device:     strings.TrimSpace(input.Device),
		Protocol:   strings.TrimSpace(input.Protocol),
		AppID:      strings.TrimSpace(input.AppID),
		Host:       host,
		Port:       input.Port,
		RedVersion: strings.TrimSpace(input.RedVersion),
		Token:      secret,
	})
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

func normalizeRedHost(raw string) (string, error) {
	host := strings.TrimSpace(raw)
	if host == "" || host != raw || len(host) > 253 || strings.ContainsAny(host, "/\\@?#") {
		return "", errors.New("red: host must be a hostname or IP address without scheme, credentials, path, query, or fragment")
	}
	for _, character := range host {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return "", errors.New("red: host contains whitespace or control characters")
		}
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}
	if strings.Contains(host, ":") && net.ParseIP(host) == nil {
		return "", errors.New("red: host contains an invalid port or IPv6 address")
	}
	parsed, err := url.Parse("http://" + net.JoinHostPort(host, "1"))
	if err != nil || parsed.Hostname() != host {
		return "", errors.New("red: invalid host")
	}
	return host, nil
}

func (descriptor RedDescriptor) NewRuntime(init adapterapi.RuntimeInit) (adapterapi.AdapterRuntime, error) {
	if !init.EndpointID.Valid() || init.Generation == 0 || init.DesiredVersion == 0 {
		return nil, errors.New("red: runtime identity is incomplete")
	}
	if err := init.Config.Validate(); err != nil {
		return nil, err
	}
	validated, err := descriptor.ValidateConfig(context.Background(), init.Config.Canonical)
	if err != nil || validated.Version != init.Config.Version || !bytes.Equal(validated.Canonical, init.Config.Canonical) || len(validated.SecretRefs) != 1 || len(init.Config.SecretRefs) != 1 || validated.SecretRefs[0] != init.Config.SecretRefs[0] {
		return nil, errors.New("red: runtime config was not validated by descriptor")
	}
	var config redCanonicalConfig
	if err := json.Unmarshal(init.Config.Canonical, &config); err != nil {
		return nil, errors.New("red: invalid canonical runtime config")
	}
	return &redRuntime{config: config, tokenRef: validated.SecretRefs[0], resolver: init.Secrets, dialer: websocket.DefaultDialer, replies: make(chan json.RawMessage, 1), dispatchTimeout: redDispatchTimeout, memberCache: make(map[string]redMemberCacheEntry)}, nil
}

func (*redRuntime) OwnedResources() adapterapi.OwnedResourceManifest {
	return adapterapi.OwnedResourceManifest{}
}

func (*redRuntime) Capabilities() adapterapi.CapabilitySet {
	return adapterapi.CapabilityLifecycle | adapterapi.CapabilityInbound | adapterapi.CapabilityOutbound
}

func (*redRuntime) Diagnostics(context.Context) adapterapi.DiagnosticReport {
	return adapterapi.DiagnosticReport{}
}

func (runtime *redRuntime) resolveToken(ctx context.Context) (string, error) {
	if runtime == nil || runtime.resolver == nil {
		return "", errors.New("red: token resolver is unavailable")
	}
	value, err := runtime.resolver.Resolve(ctx, runtime.tokenRef)
	if err != nil {
		return "", err
	}
	if value.Version != runtime.tokenRef.Version || len(value.Bytes) == 0 {
		return "", errors.New("red: token resolution is invalid")
	}
	return string(value.Bytes), nil
}

func (runtime *redRuntime) Execute(ctx context.Context, effect adapterapi.OutboundEffect) adapterapi.EffectResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return adapterapi.TerminalResult("red_context_canceled", "dispatch context canceled")
	}
	if effect.Version != adapterapi.EffectVersionOne {
		return adapterapi.UnsupportedResult("red_invalid_effect_version")
	}
	if err := effect.ValidateForCapabilities(runtime.Capabilities(), adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage)); err != nil {
		return adapterapi.UnsupportedResult("red_effect_not_supported")
	}
	payload := effect.Payload
	peer := &RedPeer{}
	switch payload.Kind {
	case adapterapi.EffectPayloadGroupText:
		if payload.Target.Kind != adapterapi.TargetGroup {
			return adapterapi.UnsupportedResult("red_invalid_target")
		}
		conversation := payload.Target.Conversation.String()
		peer.ChatType = GroupChat
		peer.PeerUin = strings.TrimPrefix(conversation, "QQ-Group:")
		if peer.PeerUin == conversation || peer.PeerUin == "" {
			return adapterapi.UnsupportedResult("red_invalid_target")
		}
	case adapterapi.EffectPayloadPersonText:
		if payload.Target.Kind != adapterapi.TargetPerson {
			return adapterapi.UnsupportedResult("red_invalid_target")
		}
		conversation := payload.Target.Conversation.String()
		peer.ChatType = PersonChat
		peer.PeerUin = strings.TrimPrefix(conversation, "QQ:")
		if peer.PeerUin == conversation || peer.PeerUin == "" {
			return adapterapi.UnsupportedResult("red_invalid_target")
		}
	default:
		return adapterapi.UnsupportedResult("red_effect_not_supported")
	}
	outbound := RedPack[RedMessageSend]{Type: "message::send", Payload: &RedMessageSend{Peer: peer, Elements: []*RedElement{{ElementType: 1, TextElement: &RedTextElement{Content: payload.Text}}}}}
	return runtime.dispatch(ctx, outbound)
}

func (runtime *redRuntime) dispatch(ctx context.Context, outbound RedPack[RedMessageSend]) adapterapi.EffectResult {
	runtime.dispatchMu.Lock()
	defer runtime.dispatchMu.Unlock()
	if runtime.uncertain {
		return adapterapi.AmbiguousResult("red_reconnect_required", "a prior dispatch outcome is unknown; reconnect before sending again")
	}
	runtime.mu.Lock()
	connection, runCtx, connected := runtime.conn, runtime.runCtx, runtime.connected
	runtime.mu.Unlock()
	if connection == nil || runCtx == nil || !connected {
		return adapterapi.TerminalResult("red_provider_unavailable", "provider unavailable")
	}
	select {
	case <-runtime.replies:
	default:
	}
	runtime.writeMu.Lock()
	err := connection.WriteJSON(outbound)
	runtime.writeMu.Unlock()
	if err != nil {
		runtime.uncertain = true
		return adapterapi.AmbiguousResult("red_provider_ambiguous", "provider dispatch outcome is unknown")
	}
	waitCtx, cancel := context.WithTimeout(ctx, runtime.dispatchTimeout)
	defer cancel()
	select {
	case data := <-runtime.replies:
		providerID, acknowledged := redReplyResult(data)
		if !acknowledged {
			runtime.uncertain = true
			return adapterapi.AmbiguousResult("red_invalid_reply", "provider returned an unrecognized dispatch reply")
		}
		return adapterapi.SucceededResult(providerID)
	case <-waitCtx.Done():
		runtime.uncertain = true
		return adapterapi.AmbiguousResult("red_provider_ambiguous", "provider dispatch outcome is unknown")
	case <-runCtx.Done():
		runtime.uncertain = true
		return adapterapi.AmbiguousResult("red_provider_ambiguous", "provider disconnected before acknowledging dispatch")
	}
}

func redReplyResult(data json.RawMessage) (string, bool) {
	var payload struct {
		MsgID     string `json:"msgId"`
		MessageID string `json:"messageId"`
		Success   *bool  `json:"success"`
		Code      *int   `json:"code"`
	}
	if json.Unmarshal(data, &payload) == nil {
		if payload.Success != nil && !*payload.Success || payload.Code != nil && *payload.Code != 0 {
			return "", false
		}
		if payload.MsgID != "" {
			return payload.MsgID, true
		}
		if payload.MessageID != "" {
			return payload.MessageID, true
		}
		if payload.Success != nil && *payload.Success || payload.Code != nil && *payload.Code == 0 {
			return "", true
		}
	}
	var messages []RedMessage
	if json.Unmarshal(data, &messages) == nil && len(messages) != 0 && messages[0].MsgID != "" {
		return messages[0].MsgID, true
	}
	return "", false
}

func (runtime *redRuntime) Run(ctx context.Context, core adapterapi.CorePort) (runErr error) {
	if runtime == nil || core == nil {
		return errors.New("red: runtime or core is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	runCtx, cancel := context.WithCancel(ctx)
	runtime.mu.Lock()
	if runtime.cancel != nil {
		runtime.mu.Unlock()
		cancel()
		return errors.New("red: runtime already started")
	}
	runtime.cancel, runtime.runCtx, runtime.running = cancel, runCtx, true
	runtime.mu.Unlock()
	defer func() {
		if runErr != nil && !errors.Is(runErr, context.Canceled) {
			_ = core.ReportObservation(context.Background(), adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateFailed, Code: "runtime_failed", Detail: "Red runtime failed", Retryable: true, OccurredAt: time.Now().UTC()})
		}
		_ = runtime.Stop(context.Background())
	}()
	if err := core.ReportObservation(runCtx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateStarting, Code: "starting", Detail: "Red runtime starting", OccurredAt: time.Now().UTC()}); err != nil {
		return err
	}
	token, err := runtime.resolveToken(runCtx)
	if err != nil {
		return err
	}
	address := net.JoinHostPort(runtime.config.Host, strconv.Itoa(runtime.config.Port))
	connectURL := url.URL{Scheme: "ws", Host: address}
	connection, response, err := runtime.dialer.DialContext(runCtx, connectURL.String(), nil)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		return err
	}
	connection.SetReadLimit(adapterapi.MaxInboundTextBytes + 256*1024)
	runtime.mu.Lock()
	if !runtime.running {
		runtime.mu.Unlock()
		_ = connection.Close()
		return nil
	}
	runtime.conn = connection
	runtime.mu.Unlock()
	go func() {
		<-runCtx.Done()
		_ = connection.Close()
	}()
	deadline := time.Now().Add(redDispatchTimeout)
	_ = connection.SetWriteDeadline(deadline)
	runtime.writeMu.Lock()
	err = connection.WriteJSON(RedPack[RedConnectReq]{Type: "meta::connect", Payload: &RedConnectReq{Token: token}})
	runtime.writeMu.Unlock()
	if err != nil {
		return err
	}
	_ = connection.SetReadDeadline(deadline)
	var auth RedPack[RedConnectResp]
	if readErr := connection.ReadJSON(&auth); readErr != nil {
		return readErr
	}
	_ = connection.SetReadDeadline(time.Time{})
	_ = connection.SetWriteDeadline(time.Time{})
	if auth.Payload == nil {
		return errors.New("red: authentication response is invalid")
	}
	selfID, nickname := "", ""
	if auth.Payload.AuthData != nil {
		selfID, nickname = auth.Payload.AuthData.Uin, auth.Payload.AuthData.NickName
	}
	if selfID == "" {
		selfID, nickname, err = runtime.fetchSelfProfile(runCtx, token, address)
		if err != nil {
			return err
		}
	}
	reads := make(chan redReadResult, 1)
	runtime.mu.Lock()
	if !runtime.running {
		runtime.mu.Unlock()
		_ = connection.Close()
		return nil
	}
	runtime.connected = true
	runtime.wg.Add(1)
	go runtime.readLoop(runCtx, connection, reads)
	runtime.mu.Unlock()
	if reportErr := core.ReportObservation(runCtx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateConnected, Code: "connected", Detail: "Red websocket authenticated", OccurredAt: time.Now().UTC()}); reportErr != nil {
		return reportErr
	}
	providerID, err := adapterapi.NewPrincipalID(formatDiceIDRed(selfID))
	if err != nil {
		return err
	}
	if err := core.ReportObservation(runCtx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationIdentity, State: adapterapi.ObservedStateConnected, ProviderID: providerID, Code: "identity", Detail: nickname, OccurredAt: time.Now().UTC()}); err != nil {
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
			if err := runtime.handleFrame(runCtx, core, result.data); err != nil {
				return err
			}
		}
	}
}

func (runtime *redRuntime) fetchSelfProfile(ctx context.Context, token, address string) (string, string, error) {
	profileURL := url.URL{Scheme: "http", Host: address, Path: "/api/getSelfProfile"}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL.String(), nil)
	if err != nil {
		return "", "", err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{
		Timeout: redDispatchTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return "", "", err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", "", fmt.Errorf("red: getSelfProfile returned HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, redMaxHTTPResponseBytes+1))
	if err != nil || len(data) > redMaxHTTPResponseBytes {
		return "", "", errors.New("red: getSelfProfile response is invalid or oversized")
	}
	var profile struct {
		Uin  string `json:"uin"`
		Nick string `json:"nick"`
	}
	if err := json.Unmarshal(data, &profile); err != nil || profile.Uin == "" {
		return "", "", errors.New("red: getSelfProfile returned an invalid response")
	}
	return profile.Uin, profile.Nick, nil
}

func (runtime *redRuntime) handleFrame(ctx context.Context, core adapterapi.CorePort, data []byte) error {
	var frame redGatewayFrame
	if decodeErr := json.Unmarshal(data, &frame); decodeErr != nil {
		return fmt.Errorf("%w: %w", errRedMalformedGatewayPayload, decodeErr)
	}
	if frame.Type == "message::send::reply" {
		select {
		case runtime.replies <- append(json.RawMessage(nil), frame.Payload...):
		default:
		}
		return nil
	}
	var messages RedMessageRecv
	if decodeErr := json.Unmarshal(frame.Payload, &messages); decodeErr != nil {
		return fmt.Errorf("%w: %w", errRedMalformedGatewayPayload, decodeErr)
	}
	for _, message := range messages {
		inbound, ok := normalizeRedInbound(message)
		if !ok {
			continue
		}
		// The Red protocol carries group permission only in the member-list
		// API, never on the message event, so the runtime resolves it here and
		// attaches it to the normalized facts. A failed lookup leaves the role
		// empty: unknown permission must never be promoted to admin/owner.
		if inbound.ConversationKind == adapterapi.ConversationKindGroup {
			inbound.SenderRole = runtime.resolveGroupSenderRole(ctx, message, string(inbound.Sender))
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
			return errors.New("red: ingress rejected")
		}
	}
	return nil
}

// resolveGroupSenderRole returns the closed-set role for one group message
// sender, fetching and caching the group's member list when needed. It returns
// "" whenever the provider cannot be reached, the member is absent, or the
// provider reports an unrecognized role; callers treat "" as "no known
// permission" and Core then applies its unprivileged default.
func (runtime *redRuntime) resolveGroupSenderRole(ctx context.Context, message *RedMessage, sender string) string {
	if runtime == nil || message == nil || sender == "" {
		return ""
	}
	group := message.PeerUin
	if group == "" {
		group = message.PeerUid
	}
	if group == "" {
		return ""
	}
	roles, ok := runtime.cachedMemberRoles(group)
	if !ok {
		roles = runtime.fetchMemberRoles(ctx, group)
	}
	return roles[sender]
}

// cachedMemberRoles returns the cached role map for a group when it is still
// within redMemberCacheTTL.
func (runtime *redRuntime) cachedMemberRoles(group string) (map[string]string, bool) {
	runtime.memberMu.Lock()
	defer runtime.memberMu.Unlock()
	entry, ok := runtime.memberCache[group]
	if !ok || time.Since(entry.fetchedAt) > redMemberCacheTTL {
		return nil, false
	}
	return entry.roles, true
}

// storeMemberRoles records a fresh role map for a group, dropping the whole
// cache if it would grow past redMaxCachedGroups.
func (runtime *redRuntime) storeMemberRoles(group string, roles map[string]string) {
	runtime.memberMu.Lock()
	defer runtime.memberMu.Unlock()
	if runtime.memberCache == nil || len(runtime.memberCache) >= redMaxCachedGroups {
		runtime.memberCache = make(map[string]redMemberCacheEntry, redMaxCachedGroups)
	}
	runtime.memberCache[group] = redMemberCacheEntry{roles: roles, fetchedAt: time.Now()}
}

// fetchMemberRoles queries the provider's group/getMemberList endpoint and maps
// each member onto the closed role vocabulary. Any transport, status, or decode
// failure yields no roles so the caller degrades to "no known permission". The
// (possibly empty) result is cached regardless so a persistently failing
// provider is retried once per TTL rather than once per message.
func (runtime *redRuntime) fetchMemberRoles(ctx context.Context, group string) map[string]string {
	token, err := runtime.resolveToken(ctx)
	if err != nil {
		return nil
	}
	groupID, err := strconv.ParseInt(group, 10, 64)
	if err != nil {
		return nil
	}
	count, err := runtime.fetchMemberCount(ctx, token, group)
	if err != nil {
		runtime.storeMemberRoles(group, nil)
		return nil
	}
	body, err := json.Marshal(struct {
		Group int64 `json:"group"`
		Size  int   `json:"size"`
	}{Group: groupID, Size: count})
	if err != nil {
		return nil
	}
	roles, err := runtime.fetchMemberList(ctx, token, body)
	if err != nil {
		// Cache the empty result so the failure is not retried per message.
		runtime.storeMemberRoles(group, nil)
		return nil
	}
	runtime.storeMemberRoles(group, roles)
	return roles
}

func (runtime *redRuntime) fetchMemberCount(ctx context.Context, token, group string) (int, error) {
	data, err := runtime.memberRequest(ctx, token, http.MethodGet, "/api/bot/groups", nil)
	if err != nil {
		return 0, err
	}
	var groups []struct {
		Code  string `json:"groupCode"`
		Count int    `json:"memberCount"`
	}
	if err := json.Unmarshal(data, &groups); err != nil {
		return 0, err
	}
	for _, item := range groups {
		if item.Code == group && item.Count > 0 {
			return item.Count, nil
		}
	}
	return 0, errors.New("red: group member count unavailable")
}

func (runtime *redRuntime) memberRequest(ctx context.Context, token, method, path string, body []byte) ([]byte, error) {
	address := net.JoinHostPort(runtime.config.Host, strconv.Itoa(runtime.config.Port))
	endpoint := url.URL{Scheme: "http", Host: address, Path: path}
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := redMemberHTTPClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("red: member lookup returned HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, redMaxHTTPResponseBytes+1))
	if err != nil || len(data) > redMaxHTTPResponseBytes {
		return nil, errors.New("red: member lookup response is invalid or oversized")
	}
	return data, nil
}

func (runtime *redRuntime) fetchMemberList(ctx context.Context, token string, body []byte) (map[string]string, error) {
	data, err := runtime.memberRequest(ctx, token, http.MethodPost, "/api/group/getMemberList", body)
	if err != nil {
		return nil, err
	}
	var page []struct {
		Detail *RedGroupMember `json:"detail"`
	}
	if err := json.Unmarshal(data, &page); err != nil {
		return nil, errors.New("red: getMemberList returned an invalid response")
	}
	roles := make(map[string]string, len(page))
	for _, entry := range page {
		member := entry.Detail
		if member == nil {
			continue
		}
		id := member.Uin
		if id == "" {
			id = member.Uid
		}
		if id == "" {
			continue
		}
		if role := normalizeRedGroupRole(member.Role); role != "" {
			roles[formatDiceIDRed(id)] = role
		}
	}
	return roles, nil
}

// normalizeRedGroupRole maps the provider's numeric member role onto the closed
// SenderRole vocabulary: 4=群主, 3=管理, 2=普通成员. Anything else is unknown.
func normalizeRedGroupRole(role int) string {
	switch role {
	case 4:
		return "owner"
	case 3:
		return "admin"
	case 2:
		return "member"
	default:
		return ""
	}
}

func normalizeRedInbound(message *RedMessage) (adapterapi.InboundMessage, bool) {
	if message == nil || message.MsgID == "" {
		return adapterapi.InboundMessage{}, false
	}
	sender := message.SenderUin
	if sender == "" {
		sender = message.SenderUid
	}
	if sender == "" {
		return adapterapi.InboundMessage{}, false
	}
	conversation := formatDiceIDRed(sender)
	conversationKind := adapterapi.ConversationKindDirect
	if message.ChatType == int(GroupChat) {
		conversationKind = adapterapi.ConversationKindGroup
		group := message.PeerUin
		if group == "" {
			group = message.PeerUid
		}
		if group == "" {
			return adapterapi.InboundMessage{}, false
		}
		conversation = formatDiceIDRedGroup(group)
	} else if message.ChatType != int(PersonChat) {
		return adapterapi.InboundMessage{}, false
	}
	text, segments := normalizeRedElements(message.Elements)
	occurredAt := time.Now().UTC()
	if timestamp, err := strconv.ParseInt(message.MsgTime, 10, 64); err == nil && timestamp > 0 {
		occurredAt = time.Unix(timestamp, 0).UTC()
	}
	return adapterapi.InboundMessage{
		ProviderEventID:  adapterapi.ProviderEventID("red-message:" + message.MsgID),
		MessageID:        adapterapi.MessageID(message.MsgID),
		Platform:         "QQ",
		Sender:           adapterapi.PrincipalID(formatDiceIDRed(sender)),
		Conversation:     adapterapi.ConversationID(conversation),
		ConversationKind: conversationKind,
		Target:           conversation,
		Kind:             adapterapi.InboundKindMessage,
		Text:             text,
		Segments:         segments,
		OccurredAt:       occurredAt,
	}, true
}

func normalizeRedElements(elements []*RedElement) (string, []adapterapi.InboundSegment) {
	var text strings.Builder
	segments := make([]adapterapi.InboundSegment, 0, len(elements))
	for _, element := range elements {
		if element == nil {
			continue
		}
		switch element.ElementType {
		case 1:
			if element.TextElement == nil {
				continue
			}
			content := element.TextElement.Content
			switch element.TextElement.AtType {
			case 1:
				content = "[CQ:at,qq=all]"
			case 2:
				target := element.TextElement.AtNtUin
				if target == "" {
					target = element.TextElement.AtUid
				}
				if target != "" {
					content = "[CQ:at,qq=" + target + "]"
				}
			}
			text.WriteString(content)
			if content != "" {
				segments = append(segments, adapterapi.InboundSegment{Kind: "text", Text: content})
			}
		case 2:
			if element.PicElement == nil || element.PicElement.OriginImageUrl == "" {
				continue
			}
			content := "[CQ:image,url=" + element.PicElement.OriginImageUrl + "]"
			text.WriteString(content)
			segments = append(segments, adapterapi.InboundSegment{Kind: "image", ProviderID: element.ElementId, URL: element.PicElement.OriginImageUrl})
		}
	}
	return text.String(), segments
}

func (runtime *redRuntime) readLoop(ctx context.Context, connection *websocket.Conn, results chan<- redReadResult) {
	defer runtime.wg.Done()
	for {
		messageType, data, err := connection.ReadMessage()
		select {
		case results <- redReadResult{messageType: messageType, data: data, err: err}:
		case <-ctx.Done():
			return
		}
		if err != nil {
			return
		}
	}
}

func (runtime *redRuntime) Stop(context.Context) error {
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
