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
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"Scardice-core/adapterapi"
)

const DiscordAdapterKey adapterapi.AdapterKey = "discord"

type DiscordDescriptor struct{}

type discordConfigInput struct {
	Version            string          `json:"version"`
	Guild              string          `json:"guild"`
	Channel            string          `json:"channel"`
	Token              json.RawMessage `json:"token"`
	ProxyURL           string          `json:"proxyURL"`
	ReverseProxyURL    string          `json:"reverseProxyUrl"`
	ReverseProxyCDNURL string          `json:"reverseProxyCDNUrl"`
}

type discordCanonicalConfig struct {
	Version            string                  `json:"version"`
	Guild              string                  `json:"guild"`
	Channel            string                  `json:"channel"`
	Token              providerCanonicalSecret `json:"token"`
	ProxyURL           string                  `json:"proxyURL"`
	ReverseProxyURL    string                  `json:"reverseProxyUrl"`
	ReverseProxyCDNURL string                  `json:"reverseProxyCDNUrl"`
}

func discordAntiMarkdownFormat(text string) string {
	for _, value := range []struct{ old, new string }{
		{`\`, `\\`},
		{`~`, `\~`},
		{"`", "\\`"},
		{"!", "\\!"},
		{"(", "\\("},
		{")", "\\)"},
		{"[", "\\["},
		{"]", "\\]"},
		{"*", "\\*"},
	} {
		text = strings.ReplaceAll(text, value.old, value.new)
	}
	return text
}

func discordOutboundBody(payload adapterapi.EffectPayload) (map[string]any, error) {
	var description strings.Builder
	if payload.Text != "" {
		description.WriteString(discordAntiMarkdownFormat(payload.Text))
	}
	for _, segment := range payload.Segments {
		switch segment.Kind {
		case adapterapi.SegmentKindText:
			description.WriteString(discordAntiMarkdownFormat(segment.Text))
		case adapterapi.SegmentKindMention:
			if segment.Text == "all" || segment.Text == "DISCORD:all" {
				description.WriteString("@everyone ")
			} else {
				description.WriteString("<@" + strings.TrimPrefix(segment.Text, "DISCORD:") + ">")
			}
		case adapterapi.SegmentKindImage, adapterapi.SegmentKindFile:
			return nil, errors.New("discord_artifact_reader_unavailable")
		default:
			return nil, errors.New("discord_unknown_segment")
		}
	}
	if description.Len() == 0 {
		return nil, errors.New("discord_empty_message")
	}
	return map[string]any{"embeds": []map[string]string{{"description": description.String(), "type": "article"}}}, nil
}

func (DiscordDescriptor) Key() adapterapi.AdapterKey { return DiscordAdapterKey }

func (DiscordDescriptor) ConfigVersion() uint16 { return 1 }
func FormatDiceIDDiscord(id string) string {
	return fmt.Sprintf("DISCORD:%s", id)
}

func FormatDiceIDDiscordChannel(id string) string {
	return fmt.Sprintf("DISCORD-CH-Group:%s", id)
}

func FormatDiceIDDiscordGuild(id string) string {
	return fmt.Sprintf("DISCORD-Guild:%s", id)
}

func ExtractDiscordUserID(id string) string {
	return strings.TrimPrefix(id, "DISCORD:")
}

func ExtractDiscordChannelID(id string) string {
	return strings.TrimPrefix(id, "DISCORD-CH-Group:")
}

func discordSupportedActions() adapterapi.ActionSet {
	return adapterapi.ActionSet(0).With(
		adapterapi.ActionKindSendMessage,
		adapterapi.ActionKindRecallMessage,
		adapterapi.ActionKindEditMessage,
		adapterapi.ActionKindSetGroupCard,
		adapterapi.ActionKindQuit,
		adapterapi.ActionKindGroupInfoRefresh,
	)
}

func (DiscordDescriptor) SupportedActions(adapterapi.ValidatedConfig) adapterapi.ActionSet {
	return discordSupportedActions()
}

func (DiscordDescriptor) Capabilities(adapterapi.ValidatedConfig) adapterapi.CapabilitySet {
	return adapterapi.CapabilityLifecycle | adapterapi.CapabilityInbound | adapterapi.CapabilityOutbound | adapterapi.CapabilityActions | adapterapi.CapabilityRichMessages
}

func (DiscordDescriptor) ValidateConfig(ctx context.Context, raw json.RawMessage) (adapterapi.ValidatedConfig, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	var input discordConfigInput
	if err := decodeStrictProviderJSON(raw, &input); err != nil {
		return adapterapi.ValidatedConfig{}, fmt.Errorf("discord: invalid config: %w", err)
	}
	if input.Version != "1" {
		return adapterapi.ValidatedConfig{}, errors.New("discord: unsupported config version")
	}
	var token providerCanonicalSecret
	if err := decodeStrictProviderJSON(input.Token, &token); err != nil || token.Version == 0 {
		return adapterapi.ValidatedConfig{}, errors.New("discord: invalid token reference")
	}
	ref := adapterapi.SecretRef{Ref: token.SecretRef, Version: token.Version}
	if err := ref.Validate(); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	proxyURL, err := normalizeProviderHTTPURL(input.ProxyURL, true)
	if err != nil {
		return adapterapi.ValidatedConfig{}, fmt.Errorf("discord: invalid proxyURL: %w", err)
	}
	reverseProxyURL, err := normalizeProviderHTTPURL(input.ReverseProxyURL, true)
	if err != nil {
		return adapterapi.ValidatedConfig{}, fmt.Errorf("discord: invalid reverseProxyUrl: %w", err)
	}
	reverseProxyCDNURL, err := normalizeProviderHTTPURL(input.ReverseProxyCDNURL, true)
	if err != nil {
		return adapterapi.ValidatedConfig{}, fmt.Errorf("discord: invalid reverseProxyCDNUrl: %w", err)
	}
	encoded, err := json.Marshal(discordCanonicalConfig{
		Version:            input.Version,
		Guild:              strings.TrimSpace(input.Guild),
		Channel:            strings.TrimSpace(input.Channel),
		Token:              token,
		ProxyURL:           proxyURL,
		ReverseProxyURL:    reverseProxyURL,
		ReverseProxyCDNURL: reverseProxyCDNURL,
	})
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

type discordGatewayUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Bot      bool   `json:"bot"`
	System   bool   `json:"system"`
}

type discordGatewayMessage struct {
	ID        string             `json:"id"`
	ChannelID string             `json:"channel_id"`
	GuildID   string             `json:"guild_id"`
	Content   string             `json:"content"`
	Timestamp string             `json:"timestamp"`
	Author    discordGatewayUser `json:"author"`
}

func discordMessageInbound(eventType string, message discordGatewayMessage) (adapterapi.InboundMessage, error) {
	if message.ID == "" || message.ChannelID == "" {
		return adapterapi.InboundMessage{}, errors.New("discord: incomplete message event")
	}
	var kind adapterapi.InboundKind
	var eventName string
	switch eventType {
	case "MESSAGE_CREATE":
		kind, eventName = adapterapi.InboundKindMessage, "created"
	case "MESSAGE_UPDATE":
		kind, eventName = adapterapi.InboundKindMessageUpdated, "updated"
	case "MESSAGE_DELETE":
		kind, eventName = adapterapi.InboundKindMessageDeleted, "deleted"
	default:
		return adapterapi.InboundMessage{}, errors.New("discord: unsupported message event")
	}
	if kind != adapterapi.InboundKindMessageDeleted && message.Author.ID == "" {
		return adapterapi.InboundMessage{}, errors.New("discord: message author is missing")
	}
	conversation := FormatDiceIDDiscord(message.Author.ID)
	conversationKind := adapterapi.ConversationKindDirect
	if message.GuildID != "" {
		conversationKind = adapterapi.ConversationKindGroup
		conversation = FormatDiceIDDiscordChannel(message.ChannelID)
	}
	inbound := adapterapi.InboundMessage{
		ProviderEventID:  adapterapi.ProviderEventID("discord-message-" + eventName + ":" + message.ID),
		MessageID:        adapterapi.MessageID(message.ID),
		Platform:         "DISCORD",
		Conversation:     adapterapi.ConversationID(conversation),
		ConversationKind: conversationKind,
		Target:           conversation,
		Kind:             kind,
		Text:             message.Content,
	}
	if message.Author.ID != "" {
		inbound.Sender = adapterapi.PrincipalID(FormatDiceIDDiscord(message.Author.ID))
	}
	if message.Content != "" {
		inbound.Segments = []adapterapi.InboundSegment{{Kind: "text", Text: message.Content}}
	}
	if message.Timestamp != "" {
		occurredAt, err := time.Parse(time.RFC3339Nano, message.Timestamp)
		if err != nil {
			return adapterapi.InboundMessage{}, fmt.Errorf("discord: invalid message timestamp: %w", err)
		}
		inbound.OccurredAt = occurredAt.UTC()
	}
	if err := inbound.Validate(); err != nil {
		return adapterapi.InboundMessage{}, err
	}
	return inbound, nil
}

func NewDiscordDescriptor() adapterapi.Descriptor { return DiscordDescriptor{} }

func (descriptor DiscordDescriptor) NewRuntime(init adapterapi.RuntimeInit) (adapterapi.AdapterRuntime, error) {
	if !init.EndpointID.Valid() || init.Generation == 0 || init.DesiredVersion == 0 {
		return nil, errors.New("discord: runtime identity is incomplete")
	}
	if err := init.Config.Validate(); err != nil {
		return nil, err
	}
	validated, err := descriptor.ValidateConfig(context.Background(), init.Config.Canonical)
	if err != nil || validated.Version != init.Config.Version || !bytes.Equal(validated.Canonical, init.Config.Canonical) || len(validated.SecretRefs) != len(init.Config.SecretRefs) {
		return nil, errors.New("discord: runtime config was not validated by descriptor")
	}
	for index := range validated.SecretRefs {
		if validated.SecretRefs[index] != init.Config.SecretRefs[index] {
			return nil, errors.New("discord: runtime secret references do not match")
		}
	}
	var config discordCanonicalConfig
	if decodeErr := json.Unmarshal(init.Config.Canonical, &config); decodeErr != nil {
		return nil, errors.New("discord: invalid canonical runtime config")
	}
	client, dialer, err := discordTransports(config.ProxyURL)
	if err != nil {
		return nil, err
	}
	return &discordRuntime{
		config:     config,
		tokenRef:   adapterapi.SecretRef{Ref: config.Token.SecretRef, Version: config.Token.Version},
		resolver:   init.Secrets,
		httpClient: client,
		dialer:     dialer,
	}, nil
}

type discordRuntime struct {
	config   discordCanonicalConfig
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

type discordReadResult struct {
	messageType int
	data        []byte
	err         error
}

type discordGatewayPayload struct {
	Op       int             `json:"op"`
	Data     json.RawMessage `json:"d"`
	Sequence *int64          `json:"s"`
	Type     string          `json:"t"`
}

func (*discordRuntime) OwnedResources() adapterapi.OwnedResourceManifest {
	return adapterapi.OwnedResourceManifest{}
}

func (*discordRuntime) Capabilities() adapterapi.CapabilitySet {
	return adapterapi.CapabilityLifecycle | adapterapi.CapabilityInbound | adapterapi.CapabilityOutbound | adapterapi.CapabilityActions | adapterapi.CapabilityRichMessages
}

func (*discordRuntime) Diagnostics(context.Context) adapterapi.DiagnosticReport {
	return adapterapi.DiagnosticReport{}
}

func (runtime *discordRuntime) Execute(ctx context.Context, effect adapterapi.OutboundEffect) adapterapi.EffectResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if effect.Version != adapterapi.EffectVersionOne {
		return adapterapi.UnsupportedResult("discord_invalid_effect_version")
	}
	if err := effect.ValidateForCapabilities(runtime.Capabilities(), discordSupportedActions()); err != nil {
		return adapterapi.UnsupportedResult("discord_effect_not_supported")
	}
	runtime.mu.Lock()
	token, selfID := runtime.token, runtime.selfID
	client := runtime.httpClient
	config := runtime.config
	runtime.mu.Unlock()
	if token == "" || selfID == "" {
		return adapterapi.TerminalResult("discord_provider_unavailable", "provider unavailable")
	}
	if client == nil {
		client = http.DefaultClient
	}
	payload := effect.Payload
	switch payload.Kind {
	case adapterapi.EffectPayloadEdit, adapterapi.EffectPayloadRecall:
		channelID, err := discordEffectChannel(ctx, client, config, token, payload.Target)
		if err != nil {
			return adapterapi.UnsupportedResult("discord_invalid_target")
		}
		path := "/channels/" + channelID + "/messages/" + string(payload.MessageID)
		method := http.MethodDelete
		var body any
		if payload.Kind == adapterapi.EffectPayloadEdit {
			method = http.MethodPatch
			body = map[string]string{"content": payload.Text}
		}
		_, status, err := discordRequest(ctx, client, config, token, method, path, body)
		if err != nil {
			if status >= http.StatusInternalServerError || status == 0 {
				return adapterapi.AmbiguousResult("discord_provider_ambiguous", "provider dispatch outcome is unknown")
			}
			return adapterapi.TerminalResult("discord_provider_rejected", "provider rejected the request")
		}
		return adapterapi.SucceededResult(string(payload.MessageID))
	case adapterapi.EffectPayloadSetGroupCard, adapterapi.EffectPayloadQuit, adapterapi.EffectPayloadGroupInfoRefresh:
		if payload.Target.Kind != adapterapi.TargetGroup {
			return adapterapi.UnsupportedResult("discord_invalid_target")
		}
		channelID := strings.TrimPrefix(payload.Target.Conversation.String(), "DISCORD-CH-Group:")
		if channelID == payload.Target.Conversation.String() {
			return adapterapi.UnsupportedResult("discord_invalid_target")
		}
		if _, err := parseDiscordSnowflake(channelID); err != nil {
			return adapterapi.UnsupportedResult("discord_invalid_target")
		}
		channel, err := discordChannelInfo(ctx, client, config, token, channelID)
		if err != nil {
			return adapterapi.AmbiguousResult("discord_provider_ambiguous", "provider dispatch outcome is unknown")
		}
		switch payload.Kind {
		case adapterapi.EffectPayloadGroupInfoRefresh:
			return adapterapi.SucceededResult(channel.ID)
		case adapterapi.EffectPayloadQuit:
			guildID := channel.GuildID
			if guildID == "" {
				guildID = strings.TrimPrefix(config.Guild, "DISCORD-Guild:")
			}
			if guildID == "" {
				return adapterapi.UnsupportedResult("discord_invalid_target")
			}
			_, status, err := discordRequest(ctx, client, config, token, http.MethodDelete, "/guilds/"+guildID, nil)
			if err != nil {
				if status >= http.StatusInternalServerError || status == 0 {
					return adapterapi.AmbiguousResult("discord_provider_ambiguous", "provider dispatch outcome is unknown")
				}
				return adapterapi.TerminalResult("discord_provider_rejected", "provider rejected the request")
			}
			return adapterapi.SucceededResult("")
		case adapterapi.EffectPayloadSetGroupCard:
			guildID := channel.GuildID
			if guildID == "" {
				guildID = strings.TrimPrefix(config.Guild, "DISCORD-Guild:")
			}
			memberID := strings.TrimPrefix(string(payload.Target.Member), "DISCORD:")
			if guildID == "" || memberID == "" {
				return adapterapi.UnsupportedResult("discord_invalid_target")
			}
			_, status, err := discordRequest(ctx, client, config, token, http.MethodPatch, "/guilds/"+guildID+"/members/"+memberID, map[string]string{"nick": payload.Card})
			if err != nil {
				if status >= http.StatusInternalServerError || status == 0 {
					return adapterapi.AmbiguousResult("discord_provider_ambiguous", "provider dispatch outcome is unknown")
				}
				return adapterapi.TerminalResult("discord_provider_rejected", "provider rejected the request")
			}
			return adapterapi.SucceededResult("")
		default:
			return adapterapi.UnsupportedResult("discord_effect_not_supported")
		}
	case adapterapi.EffectPayloadGroupText, adapterapi.EffectPayloadPersonText, adapterapi.EffectPayloadSegments:
		channelID, err := discordEffectChannel(ctx, client, config, token, payload.Target)
		if err != nil {
			return adapterapi.UnsupportedResult("discord_invalid_target")
		}
		body, err := discordOutboundBody(payload)
		if err != nil {
			return adapterapi.UnsupportedResult(err.Error())
		}
		data, status, err := discordRequest(ctx, client, config, token, http.MethodPost, "/channels/"+channelID+"/messages", body)
		if err != nil {
			if status >= http.StatusInternalServerError || status == 0 {
				return adapterapi.AmbiguousResult("discord_provider_ambiguous", "provider dispatch outcome is unknown")
			}
			return adapterapi.TerminalResult("discord_provider_rejected", "provider rejected the request")
		}
		var result struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(data, &result); err != nil || result.ID == "" {
			return adapterapi.TerminalResult("discord_invalid_response", "provider returned an invalid response")
		}
		return adapterapi.SucceededResult(result.ID)
	default:
		return adapterapi.UnsupportedResult("discord_effect_not_supported")
	}
}

func discordEffectChannel(ctx context.Context, client *http.Client, config discordCanonicalConfig, token string, target adapterapi.EffectTarget) (string, error) {
	conversation := target.Conversation.String()
	if target.Kind == adapterapi.TargetGroup {
		channelID := strings.TrimPrefix(conversation, "DISCORD-CH-Group:")
		if channelID == conversation {
			return "", errors.New("discord: invalid group target")
		}
		if _, err := parseDiscordSnowflake(channelID); err != nil {
			return "", err
		}
		return channelID, nil
	}
	if target.Kind != adapterapi.TargetPerson {
		return "", errors.New("discord: invalid target kind")
	}
	userID := strings.TrimPrefix(conversation, "DISCORD:")
	if userID == conversation {
		return "", errors.New("discord: invalid person target")
	}
	if _, err := parseDiscordSnowflake(userID); err != nil {
		return "", err
	}
	return discordCreateDMChannel(ctx, client, config, token, userID)
}

type discordChannel struct {
	ID      string `json:"id"`
	GuildID string `json:"guild_id"`
}

func discordChannelInfo(ctx context.Context, client *http.Client, config discordCanonicalConfig, token, channelID string) (discordChannel, error) {
	data, _, err := discordRequest(ctx, client, config, token, http.MethodGet, "/channels/"+channelID, nil)
	if err != nil {
		return discordChannel{}, err
	}
	var channel discordChannel
	if err := json.Unmarshal(data, &channel); err != nil || channel.ID == "" {
		return discordChannel{}, errors.New("discord: invalid channel response")
	}
	return channel, nil
}

func discordRequest(ctx context.Context, client *http.Client, config discordCanonicalConfig, token, method, path string, body any) (json.RawMessage, int, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, discordAPIBase(config)+path, reader)
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("Authorization", "Bot "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, response.StatusCode, err
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return data, response.StatusCode, fmt.Errorf("discord: provider returned %s", response.Status)
	}
	return data, response.StatusCode, nil
}

// senderRole mirrors the legacy Discord check: KICK_MEMBERS, BAN_MEMBERS or
// ADMINISTRATOR grants admin. A failed lookup resolves to no role instead of
// blocking ingestion or granting elevated rights.
func (runtime *discordRuntime) senderRole(ctx context.Context, token, guildID, channelID, userID string) string {
	if token == "" || guildID == "" || channelID == "" || userID == "" {
		return ""
	}
	role, err := runtime.lookupGuildRole(ctx, token, guildID, channelID, userID)
	if err != nil {
		return ""
	}
	return role
}

func (runtime *discordRuntime) lookupGuildRole(ctx context.Context, token, guildID, channelID, userID string) (string, error) {
	if runtime.httpClient == nil {
		return "", errors.New("discord: http client is unavailable")
	}
	guildData, _, err := discordRequest(ctx, runtime.httpClient, runtime.config, token, http.MethodGet, "/guilds/"+guildID, nil)
	if err != nil {
		return "", err
	}
	var guild struct {
		OwnerID string `json:"owner_id"`
		Roles   []struct {
			ID          string `json:"id"`
			Permissions uint64 `json:"permissions,string"`
		} `json:"roles"`
	}
	if err := json.Unmarshal(guildData, &guild); err != nil {
		return "", err
	}
	if guild.OwnerID == userID {
		return "admin", nil
	}
	memberData, _, err := discordRequest(ctx, runtime.httpClient, runtime.config, token, http.MethodGet, "/guilds/"+guildID+"/members/"+userID, nil)
	if err != nil {
		return "", err
	}
	var member struct {
		Roles []string `json:"roles"`
	}
	if err := json.Unmarshal(memberData, &member); err != nil {
		return "", err
	}
	assigned := make(map[string]struct{}, len(member.Roles))
	for _, role := range member.Roles {
		assigned[role] = struct{}{}
	}
	var permissions uint64
	for _, role := range guild.Roles {
		_, memberRole := assigned[role.ID]
		if role.ID == guildID || memberRole {
			permissions |= role.Permissions
		}
	}
	const adminPermissions = discordPermissionKickMembers | discordPermissionBanMembers | discordPermissionAdministrator
	if permissions&discordPermissionAdministrator != 0 {
		permissions |= adminPermissions
	}
	channelData, _, err := discordRequest(ctx, runtime.httpClient, runtime.config, token, http.MethodGet, "/channels/"+channelID, nil)
	if err != nil {
		return "", err
	}
	var channel struct {
		Overwrites []struct {
			ID    string `json:"id"`
			Type  int    `json:"type"`
			Allow uint64 `json:"allow,string"`
			Deny  uint64 `json:"deny,string"`
		} `json:"permission_overwrites"`
	}
	if err := json.Unmarshal(channelData, &channel); err != nil {
		return "", err
	}
	// Preserve discordgo's legacy precedence: everyone, assigned roles, member.
	for _, overwrite := range channel.Overwrites {
		if overwrite.ID == guildID {
			permissions = permissions&^overwrite.Deny | overwrite.Allow
			break
		}
	}
	var deny, allow uint64
	for _, overwrite := range channel.Overwrites {
		if _, ok := assigned[overwrite.ID]; ok && overwrite.Type == 0 {
			deny |= overwrite.Deny
			allow |= overwrite.Allow
		}
	}
	permissions = permissions&^deny | allow
	for _, overwrite := range channel.Overwrites {
		if overwrite.ID == userID && overwrite.Type == 1 {
			permissions = permissions&^overwrite.Deny | overwrite.Allow
			break
		}
	}
	if permissions&adminPermissions != 0 {
		return "admin", nil
	}
	return "", nil
}

const (
	discordPermissionKickMembers   = 1 << 1
	discordPermissionBanMembers    = 1 << 2
	discordPermissionAdministrator = 1 << 3
)

func discordCreateDMChannel(ctx context.Context, client *http.Client, config discordCanonicalConfig, token, userID string) (string, error) {
	body, err := json.Marshal(map[string]string{"recipient_id": userID})
	if err != nil {
		return "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, discordAPIBase(config)+"/users/@me/channels", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	request.Header.Set("Authorization", "Bot "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("discord: create DM channel returned %s", response.Status)
	}
	var result struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&result); err != nil {
		return "", err
	}
	if _, err := parseDiscordSnowflake(result.ID); err != nil {
		return "", fmt.Errorf("discord: invalid DM channel id: %w", err)
	}
	return result.ID, nil
}

func parseDiscordSnowflake(value string) (uint64, error) {
	var parsed uint64
	if value == "" {
		return 0, errors.New("empty snowflake")
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return 0, errors.New("invalid snowflake")
		}
		next := parsed*10 + uint64(digit-'0')
		if next < parsed {
			return 0, errors.New("snowflake overflow")
		}
		parsed = next
	}
	if parsed == 0 {
		return 0, errors.New("zero snowflake")
	}
	return parsed, nil
}

func discordAPIBase(config discordCanonicalConfig) string {
	base := config.ReverseProxyURL
	if base == "" {
		base = "https://discord.com"
	}
	return strings.TrimRight(base, "/") + "/api/v10"
}

func discordTransports(proxy string) (*http.Client, *websocket.Dialer, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	dialer := *websocket.DefaultDialer
	dialer.HandshakeTimeout = 45 * time.Second
	if proxy != "" {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			return nil, nil, fmt.Errorf("discord: invalid proxy transport: %w", err)
		}
		proxyFunc := http.ProxyURL(proxyURL)
		transport.Proxy = proxyFunc
		dialer.Proxy = proxyFunc
	}
	return &http.Client{Transport: transport, Timeout: 20 * time.Second}, &dialer, nil
}

func (runtime *discordRuntime) resolveToken(ctx context.Context) (string, error) {
	if runtime == nil || runtime.resolver == nil {
		return "", errors.New("discord: token resolver is unavailable")
	}
	value, err := runtime.resolver.Resolve(ctx, runtime.tokenRef)
	if err != nil {
		return "", err
	}
	if value.Version != runtime.tokenRef.Version || len(value.Bytes) == 0 {
		return "", errors.New("discord: token resolution is invalid")
	}
	return string(value.Bytes), nil
}

func (runtime *discordRuntime) discoverGateway(ctx context.Context, token string) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, discordAPIBase(runtime.config)+"/gateway", nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Authorization", "Bot "+token)
	response, err := runtime.httpClient.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("discord: gateway discovery returned %s", response.Status)
	}
	var result struct {
		URL string `json:"url"`
	}
	if decodeErr := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&result); decodeErr != nil {
		return "", decodeErr
	}
	gateway, err := url.Parse(result.URL)
	if err != nil || gateway.Host == "" || (gateway.Scheme != "ws" && gateway.Scheme != "wss") || gateway.User != nil || gateway.Fragment != "" {
		return "", errors.New("discord: invalid gateway URL")
	}
	query := gateway.Query()
	query.Set("v", "10")
	query.Set("encoding", "json")
	gateway.RawQuery = query.Encode()
	return gateway.String(), nil
}

func (runtime *discordRuntime) Run(ctx context.Context, core adapterapi.CorePort) (runErr error) {
	if runtime == nil || core == nil {
		return errors.New("discord: runtime or core is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithCancel(ctx)
	runtime.mu.Lock()
	if runtime.cancel != nil {
		runtime.mu.Unlock()
		cancel()
		return errors.New("discord: runtime already started")
	}
	runtime.cancel = cancel
	runtime.running = true
	runtime.mu.Unlock()
	defer func() {
		if runErr != nil && !errors.Is(runErr, context.Canceled) {
			_ = core.ReportObservation(context.Background(), adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateFailed, Code: "runtime_failed", Detail: "Discord runtime failed", Retryable: true, OccurredAt: time.Now().UTC()})
		}
		_ = runtime.Stop(context.Background())
	}()
	if err := core.ReportObservation(runCtx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateStarting, Code: "starting", Detail: "Discord runtime starting", OccurredAt: time.Now().UTC()}); err != nil {
		return err
	}
	token, err := runtime.resolveToken(runCtx)
	if err != nil {
		return err
	}
	gateway, err := runtime.discoverGateway(runCtx, token)
	if err != nil {
		return err
	}
	connection, response, err := runtime.dialer.DialContext(runCtx, gateway, nil)
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
	var hello discordGatewayPayload
	if err := connection.ReadJSON(&hello); err != nil {
		return err
	}
	if hello.Op != 10 {
		return errors.New("discord: gateway did not send hello")
	}
	var helloData struct {
		HeartbeatInterval float64 `json:"heartbeat_interval"`
	}
	if err := json.Unmarshal(hello.Data, &helloData); err != nil || helloData.HeartbeatInterval <= 0 {
		return errors.New("discord: invalid heartbeat interval")
	}
	identify := map[string]any{
		"op": 2,
		"d": map[string]any{
			"token":   token,
			"intents": (1 << 9) | (1 << 12) | (1 << 15),
			"properties": map[string]string{
				"os":      "linux",
				"browser": "Scardice",
				"device":  "Scardice",
			},
		},
	}
	if err := connection.WriteJSON(identify); err != nil {
		return err
	}
	reads := make(chan discordReadResult, 1)
	runtime.mu.Lock()
	if !runtime.running {
		runtime.mu.Unlock()
		return nil
	}
	runtime.wg.Add(1)
	runtime.mu.Unlock()
	go runtime.readLoop(runCtx, connection, reads)
	heartbeat := time.NewTicker(time.Duration(helloData.HeartbeatInterval * float64(time.Millisecond)))
	defer heartbeat.Stop()
	var sequence int64
	connected := false
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
			var payload discordGatewayPayload
			if err := json.Unmarshal(result.data, &payload); err != nil {
				return err
			}
			if payload.Sequence != nil {
				sequence = *payload.Sequence
			}
			if payload.Op == 7 || payload.Op == 9 {
				return errors.New("discord: gateway requested reconnect")
			}
			if payload.Op != 0 {
				continue
			}
			if payload.Type == "READY" {
				if connected {
					continue
				}
				if err := runtime.handleReady(runCtx, core, token, payload.Data); err != nil {
					return err
				}
				connected = true
				continue
			}
			if err := runtime.handleDispatch(runCtx, core, payload.Type, payload.Data); err != nil {
				return err
			}
		case <-heartbeat.C:
			if err := connection.WriteJSON(map[string]any{"op": 1, "d": sequence}); err != nil {
				return err
			}
		}
	}
}

func (runtime *discordRuntime) handleReady(ctx context.Context, core adapterapi.CorePort, token string, data json.RawMessage) error {
	var ready struct {
		User discordGatewayUser `json:"user"`
	}
	if err := json.Unmarshal(data, &ready); err != nil || ready.User.ID == "" {
		return errors.New("discord: invalid ready payload")
	}
	runtime.mu.Lock()
	runtime.token = token
	runtime.selfID = ready.User.ID
	runtime.mu.Unlock()
	if err := core.ReportObservation(ctx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateConnected, Code: "connected", Detail: "Discord connection established", OccurredAt: time.Now().UTC()}); err != nil {
		return err
	}
	providerID, err := adapterapi.NewPrincipalID(FormatDiceIDDiscord(ready.User.ID))
	if err != nil {
		return err
	}
	return core.ReportObservation(ctx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationIdentity, State: adapterapi.ObservedStateConnected, ProviderID: providerID, Code: "identity", OccurredAt: time.Now().UTC()})
}

func (runtime *discordRuntime) handleDispatch(ctx context.Context, core adapterapi.CorePort, eventType string, data json.RawMessage) error {
	if eventType != "MESSAGE_CREATE" && eventType != "MESSAGE_UPDATE" && eventType != "MESSAGE_DELETE" {
		return nil
	}
	var message discordGatewayMessage
	if err := json.Unmarshal(data, &message); err != nil {
		return err
	}
	if eventType == "MESSAGE_CREATE" && (message.Author.Bot || message.Author.System) {
		return nil
	}
	inbound, err := discordMessageInbound(eventType, message)
	if err != nil {
		return err
	}
	if inbound.ConversationKind == adapterapi.ConversationKindGroup && inbound.Kind == adapterapi.InboundKindMessage {
		runtime.mu.Lock()
		token := runtime.token
		runtime.mu.Unlock()
		inbound.SenderRole = runtime.senderRole(ctx, token, message.GuildID, message.ChannelID, message.Author.ID)
	}
	receipt, err := core.HandleInbound(ctx, inbound)
	if err != nil {
		return err
	}
	if err := receipt.Validate(); err != nil {
		return err
	}
	if receipt.Outcome == adapterapi.IngressRejected {
		return errors.New("discord: ingress rejected")
	}
	return nil
}

func (runtime *discordRuntime) readLoop(ctx context.Context, connection *websocket.Conn, results chan<- discordReadResult) {
	defer runtime.wg.Done()
	for {
		messageType, data, err := connection.ReadMessage()
		select {
		case results <- discordReadResult{messageType: messageType, data: data, err: err}:
		case <-ctx.Done():
			return
		}
		if err != nil {
			return
		}
	}
}

func (runtime *discordRuntime) Stop(context.Context) error {
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
