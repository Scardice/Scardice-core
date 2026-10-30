package dice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"Scardice-core/adapterapi"
	satoriutil "Scardice-core/utils/satori"
)

const SatoriAdapterKey adapterapi.AdapterKey = "satori"

const maxSatoriWebSocketMessageBytes = adapterapi.MaxInboundTextBytes + 32*1024

type SatoriDescriptor struct{}

type satoriConfigInput struct {
	Version  string          `json:"version"`
	Platform string          `json:"platform"`
	Host     string          `json:"host"`
	Port     int             `json:"port"`
	Token    json.RawMessage `json:"token"`
}

type satoriCanonicalSecret struct {
	SecretRef string `json:"secretRef"`
	Version   uint64 `json:"version"`
}

type satoriCanonicalConfig struct {
	Version  string                `json:"version"`
	Platform string                `json:"platform"`
	Host     string                `json:"host"`
	Port     int                   `json:"port"`
	Token    satoriCanonicalSecret `json:"token"`
}

func NewSatoriDescriptor() adapterapi.Descriptor { return SatoriDescriptor{} }

func (SatoriDescriptor) Key() adapterapi.AdapterKey { return SatoriAdapterKey }

func (SatoriDescriptor) ConfigVersion() uint16 { return 1 }

func (SatoriDescriptor) SupportedActions(adapterapi.ValidatedConfig) adapterapi.ActionSet {
	return adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage)
}

func (SatoriDescriptor) Capabilities(adapterapi.ValidatedConfig) adapterapi.CapabilitySet {
	return adapterapi.CapabilityLifecycle | adapterapi.CapabilityInbound | adapterapi.CapabilityOutbound
}

func (SatoriDescriptor) ValidateConfig(ctx context.Context, raw json.RawMessage) (adapterapi.ValidatedConfig, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	var input satoriConfigInput
	if err := decodeStrictSatoriJSON(raw, &input); err != nil {
		return adapterapi.ValidatedConfig{}, fmt.Errorf("satori: invalid config: %w", err)
	}
	if input.Version != SatoriProtocolVersion || input.Platform == "" || input.Host == "" {
		return adapterapi.ValidatedConfig{}, errors.New("satori: incomplete config")
	}
	if _, _, err := satoriEndpoints(input.Version, input.Host, input.Port); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	if _, err := adapterapi.NewAdapterKey(input.Platform); err != nil {
		return adapterapi.ValidatedConfig{}, fmt.Errorf("satori: invalid platform: %w", err)
	}
	var token satoriCanonicalSecret
	if err := decodeStrictSatoriJSON(input.Token, &token); err != nil || token.Version == 0 {
		return adapterapi.ValidatedConfig{}, errors.New("satori: invalid token reference")
	}
	ref := adapterapi.SecretRef{Ref: token.SecretRef, Version: token.Version}
	if err := ref.Validate(); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	encoded, err := json.Marshal(satoriCanonicalConfig{Version: input.Version, Platform: input.Platform, Host: input.Host, Port: input.Port, Token: token})
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

func decodeStrictSatoriJSON(raw []byte, target any) error {
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

func (descriptor SatoriDescriptor) NewRuntime(init adapterapi.RuntimeInit) (adapterapi.AdapterRuntime, error) {
	if !init.EndpointID.Valid() || init.Generation == 0 || init.DesiredVersion == 0 {
		return nil, errors.New("satori: runtime identity is incomplete")
	}
	if err := init.Config.Validate(); err != nil {
		return nil, err
	}
	validated, err := descriptor.ValidateConfig(context.Background(), init.Config.Canonical)
	if err != nil || validated.Version != init.Config.Version || !bytes.Equal(validated.Canonical, init.Config.Canonical) || len(validated.SecretRefs) != len(init.Config.SecretRefs) {
		return nil, errors.New("satori: runtime config was not validated by descriptor")
	}
	for index := range validated.SecretRefs {
		if validated.SecretRefs[index] != init.Config.SecretRefs[index] {
			return nil, errors.New("satori: runtime secret references do not match")
		}
	}
	var config satoriCanonicalConfig
	if err := json.Unmarshal(init.Config.Canonical, &config); err != nil {
		return nil, errors.New("satori: invalid canonical runtime config")
	}
	return &satoriRuntime{
		config:     config,
		tokenRef:   adapterapi.SecretRef{Ref: config.Token.SecretRef, Version: config.Token.Version},
		resolver:   init.Secrets,
		httpClient: http.DefaultClient,
	}, nil
}

type satoriRuntime struct {
	config   satoriCanonicalConfig
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
}

type satoriReadResult struct {
	messageType int
	data        []byte
	err         error
}

func (*satoriRuntime) OwnedResources() adapterapi.OwnedResourceManifest {
	return adapterapi.OwnedResourceManifest{}
}

func (*satoriRuntime) Capabilities() adapterapi.CapabilitySet {
	return adapterapi.CapabilityLifecycle | adapterapi.CapabilityInbound | adapterapi.CapabilityOutbound
}

func (runtime *satoriRuntime) Execute(ctx context.Context, effect adapterapi.OutboundEffect) adapterapi.EffectResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if effect.Version != adapterapi.EffectVersionOne {
		return adapterapi.UnsupportedResult("satori_invalid_effect_version")
	}
	if err := effect.ValidateForCapabilities(runtime.Capabilities(), adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage)); err != nil {
		return adapterapi.UnsupportedResult("satori_effect_not_supported")
	}
	payload := effect.Payload
	if payload.Kind != adapterapi.EffectPayloadPersonText && payload.Kind != adapterapi.EffectPayloadGroupText {
		return adapterapi.UnsupportedResult("satori_effect_not_supported")
	}
	runtime.mu.Lock()
	token, selfID := runtime.token, runtime.selfID
	client := runtime.httpClient
	config := runtime.config
	runtime.mu.Unlock()
	if token == "" || selfID == "" {
		return adapterapi.TerminalResult("satori_provider_unavailable", "provider unavailable")
	}
	if client == nil {
		client = http.DefaultClient
	}
	channelID := UserIDExtract(payload.Target.Conversation.String())
	if channelID == "" {
		return adapterapi.UnsupportedResult("satori_invalid_target")
	}
	if payload.Kind == adapterapi.EffectPayloadPersonText {
		if config.Platform != "qq" {
			return adapterapi.UnsupportedResult("satori_private_message_not_supported")
		}
		channelID = "private:" + channelID
	}
	requestBody, err := json.Marshal(map[string]string{
		"channel_id": channelID,
		"content":    satoriutil.ContentEscape(payload.Text),
	})
	if err != nil {
		return adapterapi.TerminalResult("satori_invalid_message", "message encoding failed")
	}
	_, httpURL, err := satoriEndpoints(config.Version, config.Host, config.Port)
	if err != nil {
		return adapterapi.TerminalResult("satori_invalid_config", "provider configuration is invalid")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, httpURL.String()+"/message.create", bytes.NewReader(requestBody))
	if err != nil {
		return adapterapi.TerminalResult("satori_invalid_request", "provider request is invalid")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-Platform", config.Platform)
	request.Header.Set("X-Self-Id", selfID)
	response, err := client.Do(request)
	if err != nil {
		return adapterapi.AmbiguousResult("satori_provider_ambiguous", "provider dispatch outcome is unknown")
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		if response.StatusCode >= http.StatusInternalServerError {
			return adapterapi.AmbiguousResult("satori_provider_ambiguous", "provider dispatch outcome is unknown")
		}
		return adapterapi.TerminalResult("satori_provider_rejected", "provider rejected the request")
	}
	var messages []SatoriMessage
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&messages); err != nil || len(messages) == 0 || messages[0].ID == "" {
		return adapterapi.TerminalResult("satori_invalid_response", "provider returned an invalid response")
	}
	return adapterapi.SucceededResult(messages[0].ID)
}

func (*satoriRuntime) Diagnostics(context.Context) adapterapi.DiagnosticReport {
	return adapterapi.DiagnosticReport{}
}

func (runtime *satoriRuntime) resolveToken(ctx context.Context) (string, error) {
	if runtime == nil || runtime.resolver == nil {
		return "", errors.New("satori: token resolver is unavailable")
	}
	value, err := runtime.resolver.Resolve(ctx, runtime.tokenRef)
	if err != nil {
		return "", err
	}
	if value.Version != runtime.tokenRef.Version || len(value.Bytes) == 0 {
		return "", errors.New("satori: token resolution is invalid")
	}
	return string(value.Bytes), nil
}

func (runtime *satoriRuntime) Run(ctx context.Context, core adapterapi.CorePort) (runErr error) {
	if runtime == nil || core == nil {
		return errors.New("satori: runtime or core is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithCancel(ctx)
	runtime.mu.Lock()
	if runtime.cancel != nil {
		runtime.mu.Unlock()
		cancel()
		return errors.New("satori: runtime already started")
	}
	runtime.cancel = cancel
	runtime.running = true
	runtime.mu.Unlock()
	defer func() {
		if runErr != nil && !errors.Is(runErr, context.Canceled) {
			_ = core.ReportObservation(context.Background(), adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateFailed, Code: "runtime_failed", Detail: "Satori runtime failed", Retryable: true, OccurredAt: time.Now().UTC()})
		}
		_ = runtime.Stop(context.Background())
	}()
	if err := core.ReportObservation(runCtx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateStarting, Code: "starting", Detail: "Satori runtime starting", OccurredAt: time.Now().UTC()}); err != nil {
		return err
	}
	token, err := runtime.resolveToken(runCtx)
	if err != nil {
		return err
	}
	wsURL, _, err := satoriEndpoints(runtime.config.Version, runtime.config.Host, runtime.config.Port)
	if err != nil {
		return err
	}
	connection, response, err := websocket.DefaultDialer.DialContext(runCtx, wsURL.String(), nil)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		return err
	}
	connection.SetReadLimit(maxSatoriWebSocketMessageBytes)
	runtime.mu.Lock()
	runtime.conn = connection
	runtime.mu.Unlock()
	if writeErr := connection.WriteJSON(SatoriPayload[SatoriIdentify]{Op: SatoriOpIdentify, Body: &SatoriIdentify{Token: token}}); writeErr != nil {
		return writeErr
	}
	var ready SatoriPayload[SatoriReady]
	if readErr := connection.ReadJSON(&ready); readErr != nil {
		return readErr
	}
	login, err := selectSatoriLogin(runtime.config.Platform, ready.Body)
	if err != nil {
		return err
	}
	reads := make(chan satoriReadResult, 1)
	runtime.mu.Lock()
	if !runtime.running {
		runtime.mu.Unlock()
		return nil
	}
	runtime.token = token
	runtime.selfID = login.SelfID
	runtime.wg.Add(1)
	runtime.mu.Unlock()
	go runtime.readLoop(runCtx, connection, reads)
	if reportErr := core.ReportObservation(runCtx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateConnected, Code: "connected", Detail: "Satori connection established", OccurredAt: time.Now().UTC()}); reportErr != nil {
		return reportErr
	}
	providerID, err := adapterapi.NewPrincipalID(formatDiceIDSatori(runtime.config.Platform, login.SelfID))
	if err != nil {
		return err
	}
	if err := core.ReportObservation(runCtx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationIdentity, State: adapterapi.ObservedStateConnected, ProviderID: providerID, Code: "identity", OccurredAt: time.Now().UTC()}); err != nil {
		return err
	}

	heartbeat := time.NewTicker(10 * time.Second)
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
			if err := runtime.handleWireEvent(runCtx, core, result.data); err != nil {
				return err
			}
		case <-heartbeat.C:
			if err := connection.WriteJSON(SatoriPayload[any]{Op: SatoriOpPing}); err != nil {
				return err
			}
		}
	}
}

func selectSatoriLogin(platform string, ready *SatoriReady) (*SatoriLogin, error) {
	if ready == nil {
		return nil, errors.New("satori: missing ready payload")
	}
	for _, login := range ready.Logins {
		if login != nil && login.Platform == platform && login.SelfID != "" {
			return login, nil
		}
	}
	return nil, errors.New("satori: ready payload has no matching login")
}

func (runtime *satoriRuntime) readLoop(ctx context.Context, connection *websocket.Conn, results chan<- satoriReadResult) {
	defer runtime.wg.Done()
	for {
		messageType, data, err := connection.ReadMessage()
		select {
		case results <- satoriReadResult{messageType: messageType, data: data, err: err}:
		case <-ctx.Done():
			return
		}
		if err != nil {
			return
		}
	}
}

func (runtime *satoriRuntime) handleWireEvent(ctx context.Context, core adapterapi.CorePort, data []byte) error {
	var payload struct {
		Op   SatoriOpCode    `json:"op"`
		Body json.RawMessage `json:"body"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}
	if payload.Op != SatoriOpEvent {
		return nil
	}
	var event SatoriEvent
	if err := json.Unmarshal(payload.Body, &event); err != nil {
		return err
	}
	var inbound adapterapi.InboundMessage
	var err error
	switch event.Type {
	case "message-created":
		inbound, err = satoriMessageCreatedInbound(runtime.config.Platform, &event)
	case "message-updated", "message-deleted":
		inbound, err = satoriMessageMutationInbound(runtime.config.Platform, &event)
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
		return errors.New("satori: ingress rejected")
	}
	return nil
}

func (runtime *satoriRuntime) Stop(context.Context) error {
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
