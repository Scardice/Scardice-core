package dice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"Scardice-core/adapterapi"
)

const MinecraftAdapterKey adapterapi.AdapterKey = "minecraft"

type MinecraftDescriptor struct{}

type minecraftConfig struct {
	ServerAddress string `json:"serverAddress"`
	Username      string `json:"username"`
	AuthMode      string `json:"authMode"`
	ConnectURL    string `json:"connectUrl"`
}
type MessageMinecraft struct {
	Event *MessageEvent `json:"event"`
	Type  string        `json:"type"`
}

type MessageEvent struct {
	Content     string `json:"content"`
	IsAdmin     bool   `json:"isAdmin"`
	Name        string `json:"name"`
	UUID        string `json:"uuid"`
	MessageType string `json:"messageType"`
}

type SendMessageMinecraft struct {
	Content     string `json:"content"`
	Name        string `json:"name"`
	UUID        string `json:"uuid"`
	MessageType string `json:"messageType"`
}

type minecraftRuntime struct {
	config minecraftConfig
	dialer *websocket.Dialer

	mu      sync.Mutex
	writeMu sync.Mutex
	cancel  context.CancelFunc
	conn    *websocket.Conn
	wg      sync.WaitGroup
	running bool
}

type minecraftReadResult struct {
	messageType int
	data        []byte
	err         error
}

func NewMinecraftDescriptor() adapterapi.Descriptor { return MinecraftDescriptor{} }

func (MinecraftDescriptor) Key() adapterapi.AdapterKey { return MinecraftAdapterKey }

func (MinecraftDescriptor) ConfigVersion() uint16 { return 1 }
func FormatDiceIDMC(id string) string {
	return fmt.Sprintf("MC:%s", id)
}

func ExtractMCUserID(id string) string {
	return strings.TrimPrefix(id, "MC:")
}

func (MinecraftDescriptor) SupportedActions(adapterapi.ValidatedConfig) adapterapi.ActionSet {
	return adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage)
}

func (MinecraftDescriptor) Capabilities(adapterapi.ValidatedConfig) adapterapi.CapabilitySet {
	return adapterapi.CapabilityLifecycle | adapterapi.CapabilityInbound | adapterapi.CapabilityOutbound
}

func (MinecraftDescriptor) ValidateConfig(ctx context.Context, raw json.RawMessage) (adapterapi.ValidatedConfig, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	var input minecraftConfig
	if err := decodeStrictProviderJSON(raw, &input); err != nil {
		return adapterapi.ValidatedConfig{}, fmt.Errorf("minecraft: invalid config: %w", err)
	}
	input.ServerAddress = strings.TrimSpace(input.ServerAddress)
	input.Username = strings.TrimSpace(input.Username)
	input.AuthMode = strings.TrimSpace(input.AuthMode)
	input.ConnectURL = strings.TrimSpace(input.ConnectURL)
	parsed, err := url.Parse(input.ConnectURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "ws" && parsed.Scheme != "wss") || parsed.User != nil || parsed.Fragment != "" {
		return adapterapi.ValidatedConfig{}, errors.New("minecraft: connectUrl must be an absolute ws or wss URL without credentials or fragment")
	}
	input.ConnectURL = parsed.String()
	encoded, err := json.Marshal(input)
	if err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	canonical, err := adapterapi.CanonicalizeJSON(encoded)
	if err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	validated := adapterapi.ValidatedConfig{Version: 1, Canonical: canonical}
	if err := validated.Validate(); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	return validated, nil
}

func (descriptor MinecraftDescriptor) NewRuntime(init adapterapi.RuntimeInit) (adapterapi.AdapterRuntime, error) {
	if !init.EndpointID.Valid() || init.Generation == 0 || init.DesiredVersion == 0 {
		return nil, errors.New("minecraft: runtime identity is incomplete")
	}
	if err := init.Config.Validate(); err != nil {
		return nil, err
	}
	validated, err := descriptor.ValidateConfig(context.Background(), init.Config.Canonical)
	if err != nil || validated.Version != init.Config.Version || !bytes.Equal(validated.Canonical, init.Config.Canonical) || len(init.Config.SecretRefs) != 0 {
		return nil, errors.New("minecraft: runtime config was not validated by descriptor")
	}
	var config minecraftConfig
	if err := json.Unmarshal(init.Config.Canonical, &config); err != nil {
		return nil, errors.New("minecraft: invalid canonical runtime config")
	}
	return &minecraftRuntime{config: config, dialer: websocket.DefaultDialer}, nil
}

func (*minecraftRuntime) OwnedResources() adapterapi.OwnedResourceManifest {
	return adapterapi.OwnedResourceManifest{}
}

func (*minecraftRuntime) Capabilities() adapterapi.CapabilitySet {
	return adapterapi.CapabilityLifecycle | adapterapi.CapabilityInbound | adapterapi.CapabilityOutbound
}

func (*minecraftRuntime) Diagnostics(context.Context) adapterapi.DiagnosticReport {
	return adapterapi.DiagnosticReport{}
}

func (runtime *minecraftRuntime) Execute(ctx context.Context, effect adapterapi.OutboundEffect) adapterapi.EffectResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return adapterapi.TerminalResult("minecraft_context_canceled", "dispatch context canceled")
	}
	if effect.Version != adapterapi.EffectVersionOne {
		return adapterapi.UnsupportedResult("minecraft_invalid_effect_version")
	}
	if err := effect.ValidateForCapabilities(runtime.Capabilities(), adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage)); err != nil {
		return adapterapi.UnsupportedResult("minecraft_effect_not_supported")
	}
	payload := effect.Payload
	message := SendMessageMinecraft{Content: payload.Text}
	switch payload.Kind {
	case adapterapi.EffectPayloadGroupText:
		if payload.Target.Kind != adapterapi.TargetGroup || payload.Target.Conversation != "MC:server" {
			return adapterapi.UnsupportedResult("minecraft_invalid_target")
		}
		message.MessageType = "group"
	case adapterapi.EffectPayloadPersonText:
		if payload.Target.Kind != adapterapi.TargetPerson {
			return adapterapi.UnsupportedResult("minecraft_invalid_target")
		}
		conversation := payload.Target.Conversation.String()
		message.UUID = strings.TrimPrefix(conversation, "MC:")
		if message.UUID == conversation || message.UUID == "" || message.UUID == "server" {
			return adapterapi.UnsupportedResult("minecraft_invalid_target")
		}
		message.MessageType = "private"
	default:
		return adapterapi.UnsupportedResult("minecraft_effect_not_supported")
	}
	runtime.mu.Lock()
	connection := runtime.conn
	running := runtime.running
	runtime.mu.Unlock()
	if !running || connection == nil {
		return adapterapi.TerminalResult("minecraft_provider_unavailable", "provider unavailable")
	}
	runtime.writeMu.Lock()
	err := connection.WriteJSON(message)
	runtime.writeMu.Unlock()
	if err != nil {
		return adapterapi.AmbiguousResult("minecraft_provider_ambiguous", "provider dispatch outcome is unknown")
	}
	return adapterapi.AmbiguousResult("minecraft_unacknowledged", "provider protocol has no delivery acknowledgement")
}

func (runtime *minecraftRuntime) Run(ctx context.Context, core adapterapi.CorePort) (runErr error) {
	if runtime == nil || core == nil {
		return errors.New("minecraft: runtime or core is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithCancel(ctx)
	runtime.mu.Lock()
	if runtime.cancel != nil {
		runtime.mu.Unlock()
		cancel()
		return errors.New("minecraft: runtime already started")
	}
	runtime.cancel, runtime.running = cancel, true
	runtime.mu.Unlock()
	defer func() {
		if runErr != nil && !errors.Is(runErr, context.Canceled) {
			_ = core.ReportObservation(context.Background(), adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateFailed, Code: "runtime_failed", Detail: "Minecraft runtime failed", Retryable: true, OccurredAt: time.Now().UTC()})
		}
		_ = runtime.Stop(context.Background())
	}()
	if err := core.ReportObservation(runCtx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateStarting, Code: "starting", Detail: "Minecraft runtime starting", OccurredAt: time.Now().UTC()}); err != nil {
		return err
	}
	connection, response, err := runtime.dialer.DialContext(runCtx, runtime.config.ConnectURL, nil)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		return err
	}
	connection.SetReadLimit(adapterapi.MaxInboundTextBytes + 32*1024)
	reads := make(chan minecraftReadResult, 1)
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
	if reportErr := core.ReportObservation(runCtx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateConnected, Code: "connected", Detail: "Minecraft websocket established", OccurredAt: time.Now().UTC()}); reportErr != nil {
		return reportErr
	}
	providerID, err := adapterapi.NewPrincipalID("MC:WebSocket")
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
			if err := minecraftHandleMessage(runCtx, core, result.data); err != nil {
				return err
			}
		}
	}
}

func minecraftHandleMessage(ctx context.Context, core adapterapi.CorePort, data []byte) error {
	var message MessageMinecraft
	if err := json.Unmarshal(data, &message); err != nil {
		return err
	}
	if message.Event == nil || message.Event.UUID == "" || message.Event.Content == "" {
		return nil
	}
	conversation := FormatDiceIDMC(message.Event.UUID)
	conversationKind := adapterapi.ConversationKindDirect
	if message.Event.MessageType == "group" {
		conversationKind = adapterapi.ConversationKindGroup
		conversation = "MC:server"
	} else if message.Event.MessageType != "private" {
		return nil
	}
	inbound := adapterapi.InboundMessage{Platform: "MC", Sender: adapterapi.PrincipalID(FormatDiceIDMC(message.Event.UUID)), Conversation: adapterapi.ConversationID(conversation), ConversationKind: conversationKind, Target: conversation, Kind: adapterapi.InboundKindMessage, Text: message.Event.Content, Segments: []adapterapi.InboundSegment{{Kind: "text", Text: message.Event.Content}}, OccurredAt: time.Now().UTC()}
	if message.Event.IsAdmin {
		inbound.SenderRole = "admin"
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
		return errors.New("minecraft: ingress rejected")
	}
	return nil
}

func (runtime *minecraftRuntime) readLoop(ctx context.Context, connection *websocket.Conn, results chan<- minecraftReadResult) {
	defer runtime.wg.Done()
	for {
		messageType, data, err := connection.ReadMessage()
		select {
		case results <- minecraftReadResult{messageType: messageType, data: data, err: err}:
		case <-ctx.Done():
			return
		}
		if err != nil {
			return
		}
	}
}

func (runtime *minecraftRuntime) Stop(context.Context) error {
	if runtime == nil {
		return nil
	}
	runtime.mu.Lock()
	cancel := runtime.cancel
	runtime.cancel = nil
	runtime.running = false
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
