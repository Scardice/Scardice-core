package dice

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	socketio "github.com/PaienNate/pineutil/evsocket/v2"
	"github.com/bytedance/sonic"

	"Scardice-core/adapterapi"
	"Scardice-core/core/messageflow"
	emitter "Scardice-core/dice/imsdk/onebot"
	"Scardice-core/dice/imsdk/onebot/schema"
	emitterTypes "Scardice-core/dice/imsdk/onebot/types"
	"Scardice-core/eventstore"
)

const maxOnebotInboundBytes = adapterapi.MaxInboundTextBytes

var ErrOnebotInboundPayloadTooLarge = errors.New("onebot: inbound payload exceeds bound")

// onebotRuntime is a generation-scoped owner of the protocol transport. It
// deliberately has no Dice, IMSession, endpoint, or persistence dependency.
type onebotListenerFactory func(network, address string) (net.Listener, error)

// onebotOutboundEmitter is deliberately narrower than emitter.Emitter. The
// runtime retains the full emitter for lifecycle echo/login handling, while
// this seam keeps outbound translation independently testable.
type onebotOutboundEmitter interface {
	SendPvtMsg(context.Context, int64, schema.MessageChain) (*emitterTypes.SendMsgRes, error)
	SendGrMsg(context.Context, int64, schema.MessageChain) (*emitterTypes.SendMsgRes, error)
	DelMsg(context.Context, int64) error
	SetGroupCard(context.Context, int64, int64, string) error
	QuitGroup(context.Context, int64) error
	GetGroupInfo(context.Context, int64, bool) (*emitterTypes.GroupInfo, error)
	Raw(context.Context, emitter.Action, any) ([]byte, error)
}
type onebotRuntime struct {
	config   OnebotConfig
	resolver adapterapi.SecretResolver
	listenerFactory onebotListenerFactory

	mu       sync.Mutex
	started  bool
	cancel   context.CancelFunc
	manager  *socketio.SocketInstance
	conn     *socketio.WebsocketWrapper
	server   *http.Server
	listener net.Listener
	core     adapterapi.CorePort
	emitter  emitter.Emitter
	outbound onebotOutboundEmitter
	tokenRef *string

	stopOnce sync.Once
	doneOnce sync.Once
	stopCh   chan struct{}
	doneCh   chan struct{}
	events   chan onebotRuntimeEvent
	fenced   atomic.Bool
	stopReq  atomic.Bool
	callbackMu sync.Mutex
	callbackWG sync.WaitGroup
	wg         sync.WaitGroup
	handlerMu  sync.Mutex
	handlerWG  sync.WaitGroup
	connectionMu sync.Mutex
	connections map[*socketio.WebsocketWrapper]chan struct{}
	inboundRejected atomic.Uint64
	inboundBackpressure atomic.Uint64
}
type onebotRuntimeEvent struct {
	kind string
	kws  *socketio.WebsocketWrapper
	err  error
	raw  []byte
}

func (r *onebotRuntime) admitCallback(fn func()) {
	r.callbackMu.Lock()
	if r.fenced.Load() {
		r.callbackMu.Unlock()
		return
	}
	r.callbackWG.Add(1)
	r.callbackMu.Unlock()
	defer r.callbackWG.Done()
	fn()
}
func (r *onebotRuntime) trackConnection(conn *socketio.WebsocketWrapper) {
	if conn == nil {
		return
	}
	r.callbackMu.Lock()
	if r.fenced.Load() {
		r.callbackMu.Unlock()
		return
	}
	r.connectionMu.Lock()
	if _, ok := r.connections[conn]; !ok {
		r.connections[conn] = make(chan struct{})
	}
	r.connectionMu.Unlock()
	r.callbackMu.Unlock()
}

func (r *onebotRuntime) completeConnection(conn *socketio.WebsocketWrapper) {
	if conn == nil {
		return
	}
	r.connectionMu.Lock()
	if done, ok := r.connections[conn]; ok {
		delete(r.connections, conn)
		close(done)
	}
	r.connectionMu.Unlock()
}

func newOnebotRuntime(config OnebotConfig, resolver adapterapi.SecretResolver, listenerFactories ...onebotListenerFactory) *onebotRuntime {
	var listenerFactory onebotListenerFactory
	if len(listenerFactories) > 0 { listenerFactory = listenerFactories[0] }
	return &onebotRuntime{
		config: config, resolver: resolver, listenerFactory: listenerFactory,
		stopCh: make(chan struct{}), doneCh: make(chan struct{}),
		events: make(chan onebotRuntimeEvent, 32),
		connections: make(map[*socketio.WebsocketWrapper]chan struct{}),
	}
}

func (r *onebotRuntime) RejectedInboundCount() uint64 {
	if r == nil { return 0 }
	return r.inboundRejected.Load()
}

func (r *onebotRuntime) BackpressureInboundCount() uint64 {
	if r == nil { return 0 }
	return r.inboundBackpressure.Load()
}

func (r *onebotRuntime) Capabilities() adapterapi.CapabilitySet {
	return adapterapi.CapabilityLifecycle |
		adapterapi.CapabilityInbound |
		adapterapi.CapabilityOutbound |
		adapterapi.CapabilityActions |
		adapterapi.CapabilityRichMessages
}

func (r *onebotRuntime) Execute(ctx context.Context, effect adapterapi.OutboundEffect) adapterapi.EffectResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if effect.Version != adapterapi.EffectVersionOne {
		return adapterapi.UnsupportedResult("onebot_invalid_effect_version")
	}
	if err := effect.Validate(); err != nil {
		return adapterapi.UnsupportedResult("onebot_invalid_effect")
	}
	if effect.Payload.Kind == adapterapi.EffectPayloadFile {
		return adapterapi.UnsupportedResult("onebot_artifact_reader_unavailable")
	}
	for _, segment := range effect.Payload.Segments {
		if segment.Artifact != nil {
			return adapterapi.UnsupportedResult("onebot_artifact_reader_unavailable")
		}
	}
	r.mu.Lock()
	outbound := r.outbound
	if outbound == nil {
		outbound = r.emitter
	}
	r.mu.Unlock()
	if err := effect.ValidateForCapabilities(r.Capabilities(), onebotSupportedActions()); err != nil {
		return adapterapi.UnsupportedResult("onebot_effect_not_supported")
	}
	if outbound == nil {
		return adapterapi.TerminalResult("onebot_provider_unavailable", "provider unavailable")
	}

	payload := effect.Payload
	switch payload.Kind {
	case adapterapi.EffectPayloadPersonText, adapterapi.EffectPayloadGroupText, adapterapi.EffectPayloadSegments:
		target, err := onebotTargetID(payload.Target, payload.Target.Kind == adapterapi.TargetGroup)
		if err != nil {
			return adapterapi.UnsupportedResult("onebot_invalid_target")
		}
		chain, err := onebotMessageChain(payload)
		if err != nil {
			return adapterapi.UnsupportedResult("onebot_unsupported_segment")
		}
		var response *emitterTypes.SendMsgRes
		if payload.Target.Kind == adapterapi.TargetPerson {
			response, err = outbound.SendPvtMsg(ctx, target, chain)
		} else {
			response, err = outbound.SendGrMsg(ctx, target, chain)
		}
		if err != nil {
			return onebotProviderErrorResult(err)
		}
		if response == nil || response.MessageId <= 0 {
			return adapterapi.TerminalResult("onebot_invalid_response", "provider returned no message id")
		}
		return adapterapi.SucceededResult(strconv.FormatInt(response.MessageId, 10))
	case adapterapi.EffectPayloadRecall:
		messageID, err := onebotNumericID(string(payload.MessageID), false)
		if err != nil {
			return adapterapi.UnsupportedResult("onebot_invalid_message_id")
		}
		if err := outbound.DelMsg(ctx, messageID); err != nil {
			return onebotProviderErrorResult(err)
		}
		return adapterapi.SucceededResult("")
	case adapterapi.EffectPayloadSetGroupCard:
		groupID, memberID, err := onebotGroupAndMember(payload.Target)
		if err != nil {
			return adapterapi.UnsupportedResult("onebot_invalid_target")
		}
		if err := outbound.SetGroupCard(ctx, groupID, memberID, payload.Card); err != nil {
			return onebotProviderErrorResult(err)
		}
		return adapterapi.SucceededResult("")
	case adapterapi.EffectPayloadQuit:
		groupID, err := onebotTargetID(payload.Target, true)
		if err != nil {
			return adapterapi.UnsupportedResult("onebot_invalid_target")
		}
		if err := outbound.QuitGroup(ctx, groupID); err != nil {
			return onebotProviderErrorResult(err)
		}
		return adapterapi.SucceededResult("")
	case adapterapi.EffectPayloadGroupInfoRefresh:
		groupID, err := onebotTargetID(payload.Target, true)
		if err != nil {
			return adapterapi.UnsupportedResult("onebot_invalid_target")
		}
		info, err := outbound.GetGroupInfo(ctx, groupID, true)
		if err != nil {
			return onebotProviderErrorResult(err)
		}
		if info == nil {
			return adapterapi.TerminalResult("onebot_invalid_response", "provider returned no group info")
		}
		return adapterapi.SucceededResult("")
	case adapterapi.EffectPayloadEdit:
		messageID, err := onebotNumericID(string(payload.MessageID), false)
		if err != nil {
			return adapterapi.UnsupportedResult("onebot_invalid_message_id")
		}
		raw, err := outbound.Raw(ctx, emitter.Action("set_msg"), map[string]any{
			"message_id": messageID,
			"message":    onebotTextChain(payload.Text),
		})
		if err != nil {
			return onebotProviderErrorResult(err)
		}
		return onebotRawResult(raw)
	case adapterapi.EffectPayloadBan, adapterapi.EffectPayloadKick:
		groupID, memberID, err := onebotGroupAndMember(payload.Target)
		if err != nil {
			return adapterapi.UnsupportedResult("onebot_invalid_target")
		}
		action := emitter.Action("set_group_kick")
		params := map[string]any{"group_id": groupID, "user_id": memberID}
		if payload.Kind == adapterapi.EffectPayloadBan {
			action = emitter.Action("set_group_ban")
			params["duration"] = payload.DurationSeconds
		}
		raw, err := outbound.Raw(ctx, action, params)
		if err != nil {
			return onebotProviderErrorResult(err)
		}
		return onebotRawResult(raw)
	default:
		return adapterapi.UnsupportedResult("onebot_action_not_supported")
	}
}

func onebotSupportedActions() adapterapi.ActionSet {
	return adapterapi.ActionSet(0).With(
		adapterapi.ActionKindSendMessage,
		adapterapi.ActionKindRecallMessage,
		adapterapi.ActionKindEditMessage,
		adapterapi.ActionKindSetGroupCard,
		adapterapi.ActionKindQuit,
		adapterapi.ActionKindBan,
		adapterapi.ActionKindKick,
		adapterapi.ActionKindGroupInfoRefresh,
	)
}

func onebotProviderErrorResult(err error) adapterapi.EffectResult {
	var networkErr net.Error
	if errors.Is(err, context.DeadlineExceeded) ||
		(errors.As(err, &networkErr) && (networkErr.Timeout() || networkErr.Temporary())) {
		return adapterapi.RetryableResult("onebot_provider_transient", "provider request is transient")
	}
	return adapterapi.TerminalResult("onebot_provider_failed", "provider request failed")
}

func onebotRawResult(raw []byte) adapterapi.EffectResult {
	var fields map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &fields) != nil {
		return adapterapi.TerminalResult("onebot_provider_failed", "provider returned an invalid response")
	}
	statusRaw, statusOK := fields["status"]
	retRaw, retOK := fields["retcode"]
	if !retOK {
		retRaw, retOK = fields["retCode"]
	}
	if !statusOK || !retOK {
		return adapterapi.TerminalResult("onebot_provider_failed", "provider returned an incomplete response")
	}
	var status string
	var retcode int
	if json.Unmarshal(statusRaw, &status) != nil || json.Unmarshal(retRaw, &retcode) != nil || !strings.EqualFold(status, "ok") || retcode != 0 {
		return adapterapi.TerminalResult("onebot_provider_failed", "provider returned a failed response")
	}
	return adapterapi.SucceededResult("")
}

func onebotNumericID(value string, prefixedGroup bool) (int64, error) {
	value = strings.TrimSpace(value)
	if prefixedGroup {
		switch {
		case strings.HasPrefix(value, "QQ-Group:"):
			value = strings.TrimPrefix(value, "QQ-Group:")
		case strings.HasPrefix(value, "QQ:group:"):
			value = strings.TrimPrefix(value, "QQ:group:")
		default:
			return 0, errors.New("invalid OneBot group id")
		}
	} else if strings.HasPrefix(value, "QQ:") {
		value = strings.TrimPrefix(value, "QQ:")
	}
	if value == "" || strings.Contains(value, ":") {
		return 0, errors.New("invalid OneBot numeric id")
	}
	id, err := strconv.ParseInt(value, 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("invalid OneBot numeric id")
	}
	return id, nil
}

func onebotPersonID(value string) (int64, error) {
	if value != strings.TrimSpace(value) || !strings.HasPrefix(value, "QQ:") {
		return 0, errors.New("invalid OneBot person id")
	}
	return onebotNumericID(value, false)
}

func onebotTargetID(target adapterapi.EffectTarget, group bool) (int64, error) {
	if (group && target.Kind != adapterapi.TargetGroup) || (!group && target.Kind != adapterapi.TargetPerson) {
		return 0, errors.New("target kind mismatch")
	}
	if group {
		return onebotNumericID(string(target.Conversation), true)
	}
	return onebotPersonID(string(target.Conversation))
}

func onebotGroupAndMember(target adapterapi.EffectTarget) (int64, int64, error) {
	groupID, err := onebotTargetID(target, true)
	if err != nil || target.Member == "" {
		return 0, 0, errors.New("invalid group member target")
	}
	memberID, err := onebotPersonID(string(target.Member))
	return groupID, memberID, err
}

func onebotTextChain(text string) schema.MessageChain {
	return schema.MessageChain(nil).Text(text)
}

func onebotMessageChain(payload adapterapi.EffectPayload) (schema.MessageChain, error) {
	if payload.Kind == adapterapi.EffectPayloadPersonText || payload.Kind == adapterapi.EffectPayloadGroupText {
		return onebotTextChain(payload.Text), nil
	}
	var chain schema.MessageChain
	for _, segment := range payload.Segments {
		switch segment.Kind {
		case adapterapi.SegmentKindText:
			chain = chain.Text(segment.Text)
		case adapterapi.SegmentKindMention:
			id, err := onebotPersonID(segment.Text)
			if err != nil {
				return nil, err
			}
			chain = chain.At(strconv.FormatInt(id, 10))
		default:
			return nil, errors.New("unsupported OneBot segment")
		}
	}
	return chain, nil
}

func (*onebotRuntime) Diagnostics(context.Context) adapterapi.DiagnosticReport {
	return adapterapi.DiagnosticReport{}
}

func (r *onebotRuntime) Run(ctx context.Context, core adapterapi.CorePort) (runErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	r.mu.Lock()
	if r.started {
		r.mu.Unlock()
		return errors.New("onebot: runtime already started")
	}
	r.started = true
	r.core = core
	if r.fenced.Load() {
		r.mu.Unlock()
		r.finish()
		return nil
	}
	runCtx, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	r.mu.Unlock()

	defer func() {
		_ = r.reportState(context.Background(), adapterapi.ObservedStateStopping, "stopping", "runtime stopping", true)
		r.cleanup()
		_ = r.reportState(context.Background(), adapterapi.ObservedStateStopped, "stopped", "runtime stopped", true)
		r.mu.Lock()
		r.core = nil
		r.mu.Unlock()
		r.finish()
	}()

	if err := r.reportState(runCtx, adapterapi.ObservedStateStarting, "starting", "OneBot runtime starting", false); err != nil {
		return err
	}
	token, err := r.resolveToken(runCtx)
	if err != nil {
		_ = r.reportFailure(runCtx, "secret_resolve_failed", err)
		return err
	}
	if r.fenced.Load() {
		return nil
	}
	r.mu.Lock()
	r.tokenRef = &token
	r.mu.Unlock()
	manager := socketio.NewSocketInstance()
	r.mu.Lock()
	r.manager = manager
	r.mu.Unlock()
	r.installCallbacks(manager, &token)

	if r.config.Mode == "server" {
		if err := r.startServer(manager); err != nil {
			_ = r.reportFailure(runCtx, "listener_start_failed", err)
			return err
		}
	} else {
		if err := r.startClient(manager, token, runCtx); err != nil {
			if r.fenced.Load() || errors.Is(runCtx.Err(), context.Canceled) {
				return nil
			}
			_ = r.reportFailure(runCtx, "connect_failed", err)
			return err
		}
	}

	for {
		select {
		case <-r.stopCh:
			return nil
		case <-runCtx.Done():
			if r.stopReq.Load() {
				return nil
			}
			return runCtx.Err()
		case event := <-r.events:
			if r.fenced.Load() {
				continue
			}
			switch event.kind {
			case "connect":
				if err := r.handleConnected(runCtx, event.kws); err != nil {
					_ = r.reportFailure(runCtx, "login_info_failed", err)
					return err
				}
			case "disconnect":
				if event.err == nil {
					event.err = errors.New("remote WebSocket closed")
				}
				_ = r.reportFailure(runCtx, "remote_closed", event.err)
				return event.err
			case "auth_failed":
				err := event.err
				if err == nil {
					err = errors.New("OneBot authorization failed")
				}
				_ = r.reportFailure(runCtx, "auth_failed", err)
				return err
			case "inbound":
				if err := r.handleInbound(runCtx, event.raw); err != nil {
					if isRetryableOnebotInboundError(err) {
						r.inboundRejected.Add(1)
						continue
					}
					_ = r.reportFailure(runCtx, "inbound_failed", err)
					return err
				}
			}
		}
	}
}

func isRetryableOnebotInboundError(err error) bool {
	return errors.Is(err, messageflow.ErrIngressBackpressure) ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, eventstore.ErrReadinessQuarantined) ||
		errors.Is(err, eventstore.ErrKeySourceUnavailable) ||
		errors.Is(err, eventstore.ErrEncryptionUnavailable) ||
		errors.Is(err, eventstore.ErrParticipantFailure)
}

func (r *onebotRuntime) Stop(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	r.stopOnce.Do(func() {
		r.stopReq.Store(true)
		r.fenced.Store(true)
		close(r.stopCh)
		r.mu.Lock()
		cancel, server, listener, manager, conn, started := r.cancel, r.server, r.listener, r.manager, r.conn, r.started
		r.mu.Unlock()
		if server != nil {
			_ = server.Close()
		}
		if listener != nil {
			_ = listener.Close()
		}
		if conn != nil {
			conn.Close()
		}
		if manager != nil {
			_ = manager.ShutdownWait(ctx)
		}
		if cancel != nil {
			cancel()
		}
		if !started {
			r.finish()
		}
	})
	select {
	case <-r.doneCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *onebotRuntime) finish() { r.doneOnce.Do(func() { close(r.doneCh) }) }

func (r *onebotRuntime) resolveToken(ctx context.Context) (string, error) {
	if r.config.Token.Ref == "" {
		return "", nil
	}
	if r.resolver == nil {
		return "", errors.New("onebot: token resolver is unavailable")
	}
	secret, err := r.resolver.Resolve(ctx, r.config.Token)
	if err != nil {
		return "", err
	}
	if secret.Version != 0 && secret.Version != r.config.Token.Version {
		for i := range secret.Bytes {
			secret.Bytes[i] = 0
		}
		return "", fmt.Errorf("onebot: resolved token version %d does not match %d", secret.Version, r.config.Token.Version)
	}
	copyBytes := append([]byte(nil), secret.Bytes...)
	for i := range secret.Bytes {
		secret.Bytes[i] = 0
	}
	token := string(copyBytes)
	for i := range copyBytes {
		copyBytes[i] = 0
	}
	return token, nil
}

func (r *onebotRuntime) installCallbacks(manager *socketio.SocketInstance, tokenRef *string) {
	manager.On(socketio.EventConnect, func(payload *socketio.EventPayload) {
		var kws *socketio.WebsocketWrapper
		if payload != nil {
			kws = payload.Kws
		}
		r.trackConnection(kws)
		r.admitCallback(func() {
			token := ""
			if tokenRef != nil {
				token = *tokenRef
			}
			if token != "" && (kws == nil || !onebotAuthorizationMatches(token, kws.GetRequestHeader("Authorization"))) {
				r.enqueue(onebotRuntimeEvent{kind: "auth_failed", err: errors.New("OneBot token verification failed")})
				if kws != nil {
					kws.Emit([]byte(`{"status":"failed","retcode":1403,"data":null,"message":"token验证失败","wording":"token验证失败","echo":null}`))
					kws.Close()
				}
				return
			}
			r.enqueue(onebotRuntimeEvent{kind: "connect", kws: kws})
		})
	})
	manager.On(socketio.EventDisconnect, func(payload *socketio.EventPayload) {
		if payload != nil {
			r.completeConnection(payload.Kws)
		}
		r.admitCallback(func() {
			var err error
			if payload != nil {
				err = payload.Error
			}
			r.enqueue(onebotRuntimeEvent{kind: "disconnect", err: err})
		})
	})
	manager.On(socketio.EventMessage, func(payload *socketio.EventPayload) {
		r.admitCallback(func() {
			if payload == nil || len(payload.Data) == 0 {
				return
			}
			if len(payload.Data) > maxOnebotInboundBytes {
				r.inboundRejected.Add(1)
				return
			}
			var response emitter.Response[sonic.NoCopyRawMessage]
			if err := sonic.Unmarshal(payload.Data, &response); err == nil && response.Echo != "" {
				r.mu.Lock()
				e := r.emitter
				r.mu.Unlock()
				if e != nil {
					e.HandleEcho(response)
				}
				return
			}
			var envelope struct {
				PostType string `json:"post_type"`
			}
			if json.Unmarshal(payload.Data, &envelope) == nil && envelope.PostType != "" {
				r.enqueue(onebotRuntimeEvent{kind: "inbound", raw: append([]byte(nil), payload.Data...)})
			}
		})
	})
}


func (r *onebotRuntime) enqueue(event onebotRuntimeEvent) bool {
	select {
	case r.events <- event:
		return true
	case <-r.stopCh:
		if event.kind == "inbound" {
			r.inboundBackpressure.Add(1)
		}
		return false
	}
}

func (r *onebotRuntime) startClient(manager *socketio.SocketInstance, token string, ctx context.Context) error {
	options := socketio.ClientOptions{RequestHeader: make(http.Header)}
	if token != "" {
		options.RequestHeader.Set("Authorization", token)
	}
	if strings.HasPrefix(r.config.URL, "wss://") {
		options.TLSConfig = &tls.Config{InsecureSkipVerify: r.config.InsecureSkipVerify} //nolint:gosec // explicit config opt-in
	}
	conn := manager.NewClient(r.config.URL, options)
	r.mu.Lock()
	r.conn = conn
	r.mu.Unlock()
	connected := make(chan error, 1)
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		connected <- conn.Connect()
	}()
	select {
	case err := <-connected:
		return err
	case <-ctx.Done():
		conn.Close()
		return ctx.Err()
	}
}

func (r *onebotRuntime) startServer(manager *socketio.SocketInstance) error {
	var listener net.Listener
	var err error
	if r.listenerFactory != nil {
		listener, err = r.listenerFactory("tcp", r.config.ListenAddress)
	} else {
		listener, err = net.Listen("tcp", r.config.ListenAddress)
	}
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle(r.config.ReverseSuffix, r.wrapHTTPHandler(manager.New()))
	server := &http.Server{Handler: mux}
	r.mu.Lock()
	r.listener, r.server = listener, server
	r.mu.Unlock()
	r.wg.Add(1)

	go func() {
		defer r.wg.Done()
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			r.enqueue(onebotRuntimeEvent{kind: "disconnect", err: err})
		}
	}()
	return nil
}
func (r *onebotRuntime) wrapHTTPHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.handlerMu.Lock()
		if r.fenced.Load() {
			r.handlerMu.Unlock()
			http.Error(w, "runtime is shutting down", http.StatusServiceUnavailable)
			return
		}
		r.handlerWG.Add(1)
		r.handlerMu.Unlock()
		defer r.handlerWG.Done()
		next.ServeHTTP(w, req)
	})
}

func (r *onebotRuntime) handleInbound(ctx context.Context, raw []byte) error {
	if len(raw) > maxOnebotInboundBytes {
		r.inboundRejected.Add(1)
		return ErrOnebotInboundPayloadTooLarge
	}
	var envelope struct {
		PostType  string          `json:"post_type"`
		Time      int64           `json:"time"`
		UserID    json.RawMessage `json:"user_id"`
		GroupID   json.RawMessage `json:"group_id"`
		MessageID json.RawMessage `json:"message_id"`
		Message   json.RawMessage `json:"message"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return err
	}
	if envelope.PostType != "message" {
		return nil
	}
	var eventID adapterapi.ProviderEventID
	if id, ok := onebotInboundInt(envelope.MessageID); ok {
		var eventErr error
		eventID, eventErr = adapterapi.NewProviderEventID(fmt.Sprintf("onebot-message-%d", id))
		if eventErr != nil {
			return eventErr
		}
	}
	message := adapterapi.InboundMessage{
		ProviderEventID: eventID,
		Kind:            adapterapi.InboundKindMessage,
		Platform:        "QQ",
		Text:            onebotInboundText(envelope.Message),
		Segments:        onebotInboundSegments(envelope.Message),
		OccurredAt:      time.Now(),
	}
	if envelope.Time > 0 {
		message.OccurredAt = time.Unix(envelope.Time, 0)
	}
	if id, ok := onebotInboundInt(envelope.MessageID); ok {
		message.MessageID, _ = adapterapi.NewMessageID(fmt.Sprintf("%d", id))
	}
	if id, ok := onebotInboundInt(envelope.UserID); ok {
		message.Sender, _ = adapterapi.NewPrincipalID(fmt.Sprintf("QQ:%d", id))
	}
	if id, ok := onebotInboundInt(envelope.GroupID); ok {
		message.Conversation, _ = adapterapi.NewConversationID(fmt.Sprintf("QQ:group:%d", id))
	} else if message.Sender != "" {
		message.Conversation, _ = adapterapi.NewConversationID(string(message.Sender))
	}
	message.Target = string(message.Conversation)
	message.CausationID, _ = adapterapi.NewCausationID(string(message.ProviderEventID))
	if err := message.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	core := r.core
	r.mu.Unlock()
	if core == nil {
		return nil
	}
	receipt, err := core.HandleInbound(ctx, message)
	if err != nil {
		return err
	}
	return receipt.Validate()
}

func onebotInboundInt(raw json.RawMessage) (int64, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return 0, false
	}
	var number int64
	if json.Unmarshal(raw, &number) == nil {
		return number, true
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		var err error
		number, err = strconv.ParseInt(text, 10, 64)
		return number, err == nil
	}
	return 0, false
}

func onebotInboundText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text
	}
	var segments []struct {
		Type string `json:"type"`
		Data struct {
			Text string `json:"text"`
		} `json:"data"`
	}
	if json.Unmarshal(raw, &segments) != nil {
		return ""
	}
	var builder strings.Builder
	for _, segment := range segments {
		if segment.Type == "text" {
			builder.WriteString(segment.Data.Text)
		}
	}
	return builder.String()
}

func onebotInboundSegments(raw json.RawMessage) []adapterapi.InboundSegment {
	var wire []struct {
		Type string `json:"type"`
		Data map[string]json.RawMessage `json:"data"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &wire) != nil {
		return nil
	}
	segments := make([]adapterapi.InboundSegment, 0, len(wire))
	for _, item := range wire {
		if item.Type == "" {
			continue
		}
		segment := adapterapi.InboundSegment{Kind: item.Type}
		if value, ok := item.Data["text"]; ok {
			_ = json.Unmarshal(value, &segment.Text)
		}
		if value, ok := item.Data["id"]; ok {
			_ = json.Unmarshal(value, &segment.ProviderID)
		}
		if value, ok := item.Data["file"]; ok && segment.ProviderID == "" {
			_ = json.Unmarshal(value, &segment.ProviderID)
		}
		if value, ok := item.Data["url"]; ok {
			_ = json.Unmarshal(value, &segment.URL)
		}
		segments = append(segments, segment)
	}
	return segments
}

func (r *onebotRuntime) handleConnected(ctx context.Context, conn *socketio.WebsocketWrapper) error {
	if conn == nil || r.fenced.Load() {
		return errors.New("onebot: connection was fenced")
	}
	e := emitter.NewEVEmitter(conn)
	r.mu.Lock()
	r.emitter = e
	r.mu.Unlock()
	info, err := e.GetLoginInfo(ctx)
	if err != nil {
		conn.Close()
		return err
	}
	if info == nil {
		return errors.New("onebot: get_login_info returned no data")
	}
	if r.fenced.Load() {
		return errors.New("onebot: connection was fenced")
	}
	providerID, err := adapterapi.NewPrincipalID(fmt.Sprintf("QQ:%d", info.UserId))
	if err != nil {
		return err
	}
	if err := r.reportState(ctx, adapterapi.ObservedStateConnected, "connected", "OneBot connection established", false); err != nil {
		return err
	}
	return r.reportObservation(ctx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationIdentity, State: adapterapi.ObservedStateConnected, ProviderID: providerID, Code: "identity", Detail: info.NickName, OccurredAt: time.Now()}, false)
}

func (r *onebotRuntime) reportFailure(ctx context.Context, code string, cause error) error {
	detail := ""
	if cause != nil {
		detail = cause.Error()
	}
	return r.reportObservation(ctx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateFailed, Code: code, Detail: detail, Retryable: true, OccurredAt: time.Now()}, true)
}

func (r *onebotRuntime) reportState(ctx context.Context, state adapterapi.ObservedState, code, detail string, allowFenced bool) error {
	return r.reportObservation(ctx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: state, Code: code, Detail: detail, OccurredAt: time.Now()}, allowFenced)
}

func (r *onebotRuntime) reportObservation(ctx context.Context, observation adapterapi.LifecycleObservation, allowFenced bool) error {
	if !allowFenced && r.fenced.Load() {
		return context.Canceled
	}
	r.mu.Lock()
	core := r.core
	r.mu.Unlock()
	if core == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return core.ReportObservation(ctx, observation)
}

func (r *onebotRuntime) cleanup() {
	r.stopOnce.Do(func() {
		r.stopReq.Store(true)
		close(r.stopCh)
	})
	r.callbackMu.Lock()
	r.fenced.Store(true)
	r.callbackMu.Unlock()
	r.handlerMu.Lock()
	r.handlerMu.Unlock()
	r.mu.Lock()
	cancel, conn, manager, server, listener := r.cancel, r.conn, r.manager, r.server, r.listener
	tokenRef := r.tokenRef
	r.mu.Unlock()
	if server != nil {
		_ = server.Close()
	}
	if listener != nil {
		_ = listener.Close()
	}
	r.handlerWG.Wait()
	if conn != nil {
		conn.Close()
	}
	if manager != nil {
		_ = manager.ShutdownWait(context.Background())
	}
	if cancel != nil {
		cancel()
	}
	r.callbackWG.Wait()
	r.wg.Wait()
	r.connectionMu.Lock()
	waits := make([]chan struct{}, 0, len(r.connections))
	for _, done := range r.connections {
		waits = append(waits, done)
	}
	r.connectionMu.Unlock()
	for _, done := range waits {
		<-done
	}
	r.connectionMu.Lock()
	r.connections = make(map[*socketio.WebsocketWrapper]chan struct{})
	r.connectionMu.Unlock()
	if tokenRef != nil {
		*tokenRef = ""
	}
	r.mu.Lock()
	r.cancel = nil
	r.manager = nil
	r.conn = nil
	r.server = nil
	r.listener = nil
	r.emitter = nil
	r.outbound = nil
	r.tokenRef = nil
	r.mu.Unlock()
}

