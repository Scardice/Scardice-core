package dice

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"Scardice-core/adapterapi"
)

const WalleQAdapterKey adapterapi.AdapterKey = "walleq"

type WalleQDescriptor struct{}

func NewWalleQDescriptor() adapterapi.Descriptor { return WalleQDescriptor{} }
func (WalleQDescriptor) Key() adapterapi.AdapterKey {
	return WalleQAdapterKey
}
func (WalleQDescriptor) ConfigVersion() uint16 { return 1 }
func (WalleQDescriptor) SupportedActions(adapterapi.ValidatedConfig) adapterapi.ActionSet {
	return walleqSupportedActions()
}

func (WalleQDescriptor) Capabilities(adapterapi.ValidatedConfig) adapterapi.CapabilitySet {
	return adapterapi.CapabilityLifecycle |
		adapterapi.CapabilityInbound |
		adapterapi.CapabilityOutbound |
		adapterapi.CapabilityActions |
		adapterapi.CapabilityRichMessages
}

type walleqEndpointConfig struct {
	ConnectURL         string `json:"connectUrl"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

func (WalleQDescriptor) ValidateConfig(ctx context.Context, raw json.RawMessage) (adapterapi.ValidatedConfig, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	var input struct {
		ConnectURL         string `json:"connectUrl"`
		URL                string `json:"url"`
		UseInPackWalleQ    *bool  `json:"useInPackWalleQ"`
		InsecureSkipVerify bool   `json:"insecureSkipVerify"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return adapterapi.ValidatedConfig{}, fmt.Errorf("walleq: invalid configuration: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return adapterapi.ValidatedConfig{}, errors.New("walleq: multiple JSON values")
		}
		return adapterapi.ValidatedConfig{}, fmt.Errorf("walleq: invalid trailing JSON: %w", err)
	}
	if input.UseInPackWalleQ != nil && *input.UseInPackWalleQ {
		return adapterapi.ValidatedConfig{}, errors.New("walleq: built-in process mode is not migrated")
	}
	connectURL := strings.TrimSpace(input.ConnectURL)
	if connectURL == "" {
		connectURL = strings.TrimSpace(input.URL)
	}
	if input.ConnectURL != "" && input.URL != "" && strings.TrimSpace(input.ConnectURL) != strings.TrimSpace(input.URL) {
		return adapterapi.ValidatedConfig{}, errors.New("walleq: connect URL aliases conflict")
	}
	parsed, err := url.Parse(connectURL)
	if err != nil || parsed.Scheme == "" || (parsed.Scheme != "ws" && parsed.Scheme != "wss") || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return adapterapi.ValidatedConfig{}, errors.New("walleq: connectUrl must be an absolute ws or wss URL without credentials or fragment")
	}
	canonical, err := json.Marshal(walleqEndpointConfig{ConnectURL: parsed.String(), InsecureSkipVerify: input.InsecureSkipVerify})
	if err != nil {
		return adapterapi.ValidatedConfig{}, fmt.Errorf("walleq: canonical configuration: %w", err)
	}
	canonical, err = adapterapi.CanonicalizeJSON(canonical)
	if err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	return adapterapi.ValidatedConfig{Version: 1, Canonical: canonical}, nil
}

func (WalleQDescriptor) NewRuntime(init adapterapi.RuntimeInit) (adapterapi.AdapterRuntime, error) {
	if !init.EndpointID.Valid() || init.Generation == 0 || init.DesiredVersion == 0 {
		return nil, errors.New("walleq: runtime identity is incomplete")
	}
	if err := init.Config.Validate(); err != nil || init.Config.Version != 1 {
		return nil, errors.New("walleq: runtime configuration was not validated")
	}
	var config walleqEndpointConfig
	if err := json.Unmarshal(init.Config.Canonical, &config); err != nil {
		return nil, errors.New("walleq: invalid canonical configuration")
	}
	validated, err := (WalleQDescriptor{}).ValidateConfig(context.Background(), init.Config.Canonical)
	if err != nil || !bytes.Equal(validated.Canonical, init.Config.Canonical) {
		return nil, errors.New("walleq: runtime configuration was not canonical")
	}
	return &walleqRuntime{config: config}, nil
}

type walleqRuntime struct {
	config walleqEndpointConfig

	mu      sync.Mutex
	writeMu sync.Mutex
	conn    *websocket.Conn
	cancel  context.CancelFunc
	stopped bool
}

func walleqSupportedActions() adapterapi.ActionSet {
	return adapterapi.ActionSet(0).With(
		adapterapi.ActionKindSendMessage,
		adapterapi.ActionKindQuit,
		adapterapi.ActionKindBan,
		adapterapi.ActionKindKick,
		adapterapi.ActionKindGroupInfoRefresh,
	)
}

func (*walleqRuntime) Capabilities() adapterapi.CapabilitySet {
	return adapterapi.CapabilityLifecycle |
		adapterapi.CapabilityInbound |
		adapterapi.CapabilityOutbound |
		adapterapi.CapabilityActions |
		adapterapi.CapabilityRichMessages
}

func (runtime *walleqRuntime) Execute(ctx context.Context, effect adapterapi.OutboundEffect) adapterapi.EffectResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if effect.Version != adapterapi.EffectVersionOne {
		return adapterapi.UnsupportedResult("walleq_invalid_effect_version")
	}
	if err := effect.ValidateForCapabilities(runtime.Capabilities(), walleqSupportedActions()); err != nil {
		return adapterapi.UnsupportedResult("walleq_effect_not_supported")
	}

	payload := effect.Payload
	command := walleqCommand{Echo: effect.ID.String()}
	switch payload.Kind {
	case adapterapi.EffectPayloadPersonText, adapterapi.EffectPayloadGroupText, adapterapi.EffectPayloadSegments:
		group := payload.Kind == adapterapi.EffectPayloadGroupText ||
			(payload.Kind == adapterapi.EffectPayloadSegments && payload.Target.Kind == adapterapi.TargetGroup)
		target, err := walleqOutboundTarget(payload.Target, group)
		if err != nil {
			return adapterapi.UnsupportedResult("walleq_invalid_target")
		}
		segments, err := walleqOutboundSegments(payload)
		if err != nil {
			return adapterapi.UnsupportedResult("walleq_unsupported_segment")
		}
		params := struct {
			DetailType string                  `json:"detail_type"`
			UserID     string                  `json:"user_id,omitempty"`
			GroupID    string                  `json:"group_id,omitempty"`
			Message    []walleqOutboundSegment `json:"message"`
		}{Message: segments}
		if group {
			params.DetailType = "group"
			params.GroupID = target
		} else {
			params.DetailType = "private"
			params.UserID = target
		}
		command.Action = "send_message"
		command.Params = params
	case adapterapi.EffectPayloadQuit, adapterapi.EffectPayloadGroupInfoRefresh:
		groupID, err := walleqOutboundTarget(payload.Target, true)
		if err != nil {
			return adapterapi.UnsupportedResult("walleq_invalid_target")
		}
		command.Params = struct {
			GroupID string `json:"group_id"`
		}{GroupID: groupID}
		if payload.Kind == adapterapi.EffectPayloadQuit {
			command.Action = "leave_group"
		} else {
			command.Action = "get_group_info"
		}
	case adapterapi.EffectPayloadBan, adapterapi.EffectPayloadKick:
		groupID, err := walleqOutboundTarget(payload.Target, true)
		if err != nil || payload.Target.Member == "" {
			return adapterapi.UnsupportedResult("walleq_invalid_target")
		}
		memberID, err := walleqOutboundTarget(adapterapi.EffectTarget{
			Kind:         adapterapi.TargetPerson,
			Conversation: adapterapi.ConversationID(payload.Target.Member),
		}, false)
		if err != nil {
			return adapterapi.UnsupportedResult("walleq_invalid_target")
		}
		params := struct {
			GroupID  string `json:"groupId"`
			UserID   string `json:"userId"`
			Duration uint32 `json:"duration,omitempty"`
		}{GroupID: groupID, UserID: memberID}
		if payload.Kind == adapterapi.EffectPayloadBan {
			command.Action = "ban_group_member"
			params.Duration = payload.DurationSeconds
		} else {
			command.Action = "kick_group_member"
		}
		command.Params = params
	default:
		return adapterapi.UnsupportedResult("walleq_effect_not_supported")
	}
	if err := runtime.writeJSONContext(ctx, command); err != nil {
		return adapterapi.TerminalResult("walleq_provider_unavailable", "provider connection is unavailable")
	}
	return adapterapi.SucceededResult("")
}

func (*walleqRuntime) Diagnostics(context.Context) adapterapi.DiagnosticReport {
	return adapterapi.DiagnosticReport{}
}

func (*walleqRuntime) OwnedResources() adapterapi.OwnedResourceManifest {
	return adapterapi.OwnedResourceManifest{}
}

func (runtime *walleqRuntime) Run(ctx context.Context, core adapterapi.CorePort) (runErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if core == nil {
		return errors.New("walleq: CorePort is required")
	}
	if err := runtime.report(ctx, core, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateStarting, Code: "starting", Detail: "WalleQ runtime starting", OccurredAt: time.Now().UTC()}); err != nil {
		return err
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer func() {
		_ = runtime.report(context.Background(), core, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateStopping, Code: "stopping", Detail: "runtime stopping", OccurredAt: time.Now().UTC()})
		runtime.close()
		_ = runtime.report(context.Background(), core, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateStopped, Code: "stopped", Detail: "runtime stopped", OccurredAt: time.Now().UTC()})
	}()

	dialer := websocket.Dialer{}
	if strings.HasPrefix(runtime.config.ConnectURL, "wss://") {
		dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: runtime.config.InsecureSkipVerify} //nolint:gosec // explicit configuration opt-in
	}
	connection, response, err := dialer.DialContext(runCtx, runtime.config.ConnectURL, nil)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		_ = runtime.report(context.Background(), core, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateFailed, Code: "connect_failed", Detail: "WalleQ connection failed", Retryable: true, OccurredAt: time.Now().UTC()})
		return err
	}
	runtime.mu.Lock()
	if runtime.stopped {
		runtime.mu.Unlock()
		_ = connection.Close()
		return nil
	}
	runtime.conn, runtime.cancel = connection, cancel
	runtime.mu.Unlock()
	if err := runtime.writeJSON(walleqCommand{Action: "get_self_info", Echo: "walleq-identity"}); err != nil {
		return err
	}

	for {
		_, payload, err := connection.ReadMessage()
		if err != nil {
			if runCtx.Err() != nil || runtime.isStopped() {
				return nil
			}
			_ = runtime.report(context.Background(), core, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateFailed, Code: "read_failed", Detail: "WalleQ connection closed", Retryable: true, OccurredAt: time.Now().UTC()})
			return err
		}
		if err := runtime.handleFrame(runCtx, core, payload); err != nil {
			return err
		}
	}
}

func (runtime *walleqRuntime) Stop(context.Context) error {
	runtime.mu.Lock()
	runtime.stopped = true
	cancel, connection := runtime.cancel, runtime.conn
	runtime.cancel, runtime.conn = nil, nil
	runtime.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if connection != nil {
		return connection.Close()
	}
	return nil
}

func (runtime *walleqRuntime) close() {
	_ = runtime.Stop(context.Background())
}

func (runtime *walleqRuntime) isStopped() bool {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.stopped
}

func (runtime *walleqRuntime) writeJSON(value any) error {
	return runtime.writeJSONContext(context.Background(), value)
}

func (runtime *walleqRuntime) writeJSONContext(ctx context.Context, value any) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	runtime.writeMu.Lock()
	defer runtime.writeMu.Unlock()
	runtime.mu.Lock()
	connection := runtime.conn
	runtime.mu.Unlock()
	if connection == nil {
		return errors.New("walleq: connection is not available")
	}
	return connection.WriteJSON(value)
}

type walleqCommand struct {
	Action string `json:"action"`
	Params any    `json:"params,omitempty"`
	Echo   string `json:"echo,omitempty"`
}

type walleqOutboundSegment struct {
	Type string                    `json:"type"`
	Data walleqOutboundSegmentData `json:"data,omitempty"`
}

type walleqOutboundSegmentData struct {
	Text   string `json:"text,omitempty"`
	UserID string `json:"user_id,omitempty"`
}

func walleqOutboundTarget(target adapterapi.EffectTarget, group bool) (string, error) {
	if group {
		if target.Kind != adapterapi.TargetGroup {
			return "", errors.New("walleq: target is not a group")
		}
		value := target.Conversation.String()
		switch {
		case strings.HasPrefix(value, "QQ-Group:"):
			value = strings.TrimPrefix(value, "QQ-Group:")
		case strings.HasPrefix(value, "QQ:group:"):
			value = strings.TrimPrefix(value, "QQ:group:")
		default:
			return "", errors.New("walleq: invalid group target")
		}
		if _, err := strconv.ParseUint(value, 10, 64); err != nil {
			return "", err
		}
		return value, nil
	}
	if target.Kind != adapterapi.TargetPerson {
		return "", errors.New("walleq: target is not a person")
	}
	value := target.Conversation.String()
	switch {
	case strings.HasPrefix(value, "QQ:"):
		value = strings.TrimPrefix(value, "QQ:")
	case strings.HasPrefix(value, "PG-QQ:"):
		value = strings.TrimPrefix(value, "PG-QQ:")
	default:
		return "", errors.New("walleq: invalid person target")
	}
	if _, err := strconv.ParseUint(value, 10, 64); err != nil {
		return "", err
	}
	return value, nil
}

func walleqOutboundSegments(payload adapterapi.EffectPayload) ([]walleqOutboundSegment, error) {
	if payload.Kind == adapterapi.EffectPayloadPersonText || payload.Kind == adapterapi.EffectPayloadGroupText {
		return []walleqOutboundSegment{{Type: "text", Data: walleqOutboundSegmentData{Text: payload.Text}}}, nil
	}
	segments := make([]walleqOutboundSegment, 0, len(payload.Segments))
	for _, segment := range payload.Segments {
		switch segment.Kind {
		case adapterapi.SegmentKindText:
			segments = append(segments, walleqOutboundSegment{Type: "text", Data: walleqOutboundSegmentData{Text: segment.Text}})
		case adapterapi.SegmentKindMention:
			if segment.Text == "all" || segment.Text == "QQ:all" {
				segments = append(segments, walleqOutboundSegment{Type: "mention_all"})
				continue
			}
			userID, err := walleqOutboundTarget(adapterapi.EffectTarget{
				Kind:         adapterapi.TargetPerson,
				Conversation: adapterapi.ConversationID(segment.Text),
			}, false)
			if err != nil {
				return nil, err
			}
			segments = append(segments, walleqOutboundSegment{Type: "mention", Data: walleqOutboundSegmentData{UserID: userID}})
		default:
			return nil, errors.New("walleq: artifact segment is unavailable")
		}
	}
	if len(segments) == 0 {
		return nil, errors.New("walleq: message has no segments")
	}
	return segments, nil
}

func (runtime *walleqRuntime) handleFrame(ctx context.Context, core adapterapi.CorePort, payload []byte) error {
	var envelope struct {
		Type       string          `json:"type"`
		DetailType string          `json:"detail_type"`
		Echo       string          `json:"echo"`
		Data       json.RawMessage `json:"data"`
		ID         string          `json:"id"`
		MessageID  string          `json:"message_id"`
		Time       int64           `json:"time"`
		UserID     string          `json:"user_id"`
		UserName   string          `json:"user_name"`
		UserCard   string          `json:"user_card"`
		GroupID    string          `json:"group_id"`
		AltMessage string          `json:"alt_message"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return fmt.Errorf("walleq: decode frame: %w", err)
	}
	if envelope.Echo == "walleq-identity" {
		var identity struct {
			UserID   string `json:"user_id"`
			UserName string `json:"user_name"`
		}
		if err := json.Unmarshal(envelope.Data, &identity); err != nil || identity.UserID == "" {
			return errors.New("walleq: identity response is invalid")
		}
		return runtime.report(ctx, core, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationIdentity, State: adapterapi.ObservedStateConnected, ProviderID: adapterapi.PrincipalID("QQ:" + identity.UserID), Code: "identity", Detail: identity.UserName, OccurredAt: time.Now().UTC()})
	}
	if envelope.Type != "message" {
		return nil
	}
	message, err := walleqInboundMessage(envelope)
	if err != nil {
		return err
	}
	if validateErr := message.Validate(); validateErr != nil {
		return validateErr
	}
	receipt, err := core.HandleInbound(ctx, message)
	if err != nil {
		return err
	}
	if err := receipt.Validate(); err != nil || receipt.Outcome == adapterapi.IngressRejected {
		return errors.New("walleq: durable ingress rejected")
	}
	return nil
}

func walleqInboundMessage(frame struct {
	Type       string          `json:"type"`
	DetailType string          `json:"detail_type"`
	Echo       string          `json:"echo"`
	Data       json.RawMessage `json:"data"`
	ID         string          `json:"id"`
	MessageID  string          `json:"message_id"`
	Time       int64           `json:"time"`
	UserID     string          `json:"user_id"`
	UserName   string          `json:"user_name"`
	UserCard   string          `json:"user_card"`
	GroupID    string          `json:"group_id"`
	AltMessage string          `json:"alt_message"`
}) (adapterapi.InboundMessage, error) {
	if frame.ID == "" || frame.MessageID == "" || frame.UserID == "" {
		return adapterapi.InboundMessage{}, errors.New("walleq: message identity is incomplete")
	}
	var conversation string
	conversationKind := adapterapi.ConversationKindDirect
	switch frame.DetailType {
	case "private":
		conversation = "PG-QQ:" + frame.UserID
	case "group":
		conversationKind = adapterapi.ConversationKindGroup
		if frame.GroupID == "" {
			return adapterapi.InboundMessage{}, errors.New("walleq: group message has no group ID")
		}
		conversation = "QQ-Group:" + frame.GroupID
	default:
		return adapterapi.InboundMessage{}, errors.New("walleq: unsupported message detail type")
	}
	occurredAt := time.Time{}
	if frame.Time > 0 {
		occurredAt = time.Unix(frame.Time, 0).UTC()
	}
	return adapterapi.InboundMessage{ProviderEventID: adapterapi.ProviderEventID(frame.ID), MessageID: adapterapi.MessageID(frame.MessageID), Platform: "QQ", Sender: adapterapi.PrincipalID("QQ:" + frame.UserID), Conversation: adapterapi.ConversationID(conversation), ConversationKind: conversationKind, Kind: adapterapi.InboundKindMessage, Text: frame.AltMessage, OccurredAt: occurredAt}, nil
}

func (runtime *walleqRuntime) report(ctx context.Context, core adapterapi.CorePort, observation adapterapi.LifecycleObservation) error {
	if err := observation.Validate(); err != nil {
		return err
	}
	return core.ReportObservation(ctx, observation)
}
