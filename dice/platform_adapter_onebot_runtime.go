package dice

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	socketio "github.com/PaienNate/pineutil/evsocket/v2"
	"github.com/bytedance/sonic"
	"go.uber.org/zap"

	"Scardice-core/adapterapi"
	emitter "Scardice-core/dice/imsdk/onebot"
	"Scardice-core/dice/imsdk/onebot/schema"
	emitterTypes "Scardice-core/dice/imsdk/onebot/types"
	"Scardice-core/eventstore"
	"Scardice-core/logger"
	"Scardice-core/message"
)

const maxOnebotInboundBytes = adapterapi.MaxInboundTextBytes
const maxOnebotInboundRetries uint8 = 2
const maxOnebotPendingRecalls = 64
const onebotRecallTimeout = 30 * time.Second
const maxOnebotProviderDiagnosticBytes = adapterapi.MaxDiagnosticMessageBytes

var ErrOnebotInboundPayloadTooLarge = errors.New("onebot: inbound payload exceeds bound")
var ErrOnebotUnsupportedInboundEvent = errors.New("onebot: unsupported inbound event")
var ErrOnebotRecallQueueFull = errors.New("onebot: delayed recall queue is full")
var ErrOnebotRuntimeStopped = errors.New("onebot: runtime is stopped")

var onebotOutboundCodePattern = regexp.MustCompile(`\[(img|图|文本|text|语音|voice|视频|video):(.+?)]|\[CQ:([A-Za-z0-9_.-]+)(,[^]]*)?]`)
var onebotURLCredentialsPattern = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://[^/\s:@]+:)[^@\s]+@`)
var onebotMySQLCredentialsPattern = regexp.MustCompile(`(?i)(\b[^\s:/@]+:)[^@\s]+(@(tcp|unix)\()`)
var onebotSensitiveDiagnosticPattern = regexp.MustCompile(`(?i)(["']?(authorization|access[_-]?token|api[_-]?key|token|password|passwd|secret|cookie|body|content|request|params|payload|message|text|chat|card|reason|remark|file|url)["']?\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,;&]+)`)
var onebotBearerDiagnosticPattern = regexp.MustCompile(`(?i)\bBearer\s+[^\s,;]+`)
var onebotRuntimeAssetLogger = zap.NewNop().Sugar()

// onebotRuntime is a generation-scoped owner of the protocol transport. It
// deliberately has no Dice, IMSession, endpoint, or persistence dependency.
type onebotListenerFactory func(network, address string) (net.Listener, error)

// onebotOutboundEmitter is deliberately narrower than emitter.Emitter. The
// runtime retains the full emitter for lifecycle echo/login handling, while
// this seam keeps outbound translation independently testable.
type onebotOutboundEmitter interface {
	SendPvtMsg(ctx context.Context, userID int64, message schema.MessageChain) (*emitterTypes.SendMsgRes, error)
	SendGrMsg(ctx context.Context, groupID int64, message schema.MessageChain) (*emitterTypes.SendMsgRes, error)
	DelMsg(ctx context.Context, messageID int64) error
	SetGroupCard(ctx context.Context, groupID, userID int64, card string) error
	QuitGroup(ctx context.Context, groupID int64) error
	Raw(ctx context.Context, action emitter.Action, params any) ([]byte, error)
}
type onebotRuntime struct {
	config          OnebotConfig
	resolver        adapterapi.SecretResolver
	listenerFactory onebotListenerFactory

	mu            sync.Mutex
	started       bool
	cancel        context.CancelFunc
	manager       *socketio.SocketInstance
	conn          *socketio.WebsocketWrapper
	server        *http.Server
	listener      net.Listener
	core          adapterapi.CorePort
	emitter       emitter.Emitter
	emitterConn   *socketio.WebsocketWrapper
	outbound      onebotOutboundEmitter
	tokenRef      *string
	assetResolver *onebotAssetResolver
	// lookupBudget bounds the provider lookups made for one inbound event; zero
	// selects the default.
	lookupBudget time.Duration
	// reconnectBase and reconnectMax bound the client's redial backoff; zero
	// selects the defaults.
	reconnectBase time.Duration
	reconnectMax  time.Duration

	recallMu       sync.Mutex
	recallCtx      context.Context
	recallCancel   context.CancelFunc
	recallPending  int
	recallRejected atomic.Uint64
	recallFailed   atomic.Uint64

	stopOnce           sync.Once
	doneOnce           sync.Once
	stopCh             chan struct{}
	doneCh             chan struct{}
	priorityConnect    chan onebotRuntimeEvent
	priorityDisconnect chan onebotRuntimeEvent
	listenerFailed     chan onebotRuntimeEvent
	events             chan onebotRuntimeEvent
	fenced             atomic.Bool
	stopReq            atomic.Bool
	callbackMu         sync.Mutex
	callbackWG         sync.WaitGroup
	wg                 sync.WaitGroup
	handlerMu          sync.Mutex
	handlerWG          sync.WaitGroup
	connectionMu       sync.Mutex
	connections        map[*socketio.WebsocketWrapper]uint64

	// Conversation-free adapter events use one bounded sequential worker so
	// plugin latency cannot occupy the protocol event loop.
	globalEventMu           sync.Mutex
	globalEventCtx          context.Context
	globalEventCancel       context.CancelFunc
	globalEventEvents       chan adapterapi.AdapterEvent
	globalEventWG           sync.WaitGroup
	globalEventEnqueued     atomic.Uint64
	globalEventAccepted     atomic.Uint64
	globalEventDuplicate    atomic.Uint64
	globalEventRejected     atomic.Uint64
	globalEventBackpressure atomic.Uint64
	globalEventFailed       atomic.Uint64

	inboundRejected     atomic.Uint64
	inboundBackpressure atomic.Uint64
	inboundCollisions   atomic.Uint64
	inboundRetries      atomic.Uint64
	transportDropped    atomic.Uint64
	priorityDropped     atomic.Uint64
	reconnectAttempts   atomic.Uint64
	authRejected        atomic.Uint64
	transportDropMu     sync.Mutex

	// Owned by the Run goroutine: the pending client redial, how many redials
	// in a row have been scheduled, whether the current outage was reported,
	// and whether a logged-in session is up.
	redialTimer    *time.Timer
	redialC        <-chan time.Time
	redialStreak   int
	outageReported bool
	sessionUp      bool
}

// A client redials a lost protocol end with exponential backoff between these
// bounds; a server keeps listening for it to connect again.
const (
	defaultOnebotReconnectBase = time.Second
	defaultOnebotReconnectMax  = time.Minute
)

// OwnedResources is empty because Pure OneBot owns only in-memory and network
// resources; it never creates generation-local filesystem paths.
func (*onebotRuntime) OwnedResources() adapterapi.OwnedResourceManifest {
	return adapterapi.OwnedResourceManifest{}
}

type onebotRuntimeEvent struct {
	kind    string
	kws     *socketio.WebsocketWrapper
	err     error
	raw     []byte
	attempt uint8
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
	if !conn.IsAlive() {
		r.connectionMu.Unlock()
		r.callbackMu.Unlock()
		return
	}
	if _, ok := r.connections[conn]; !ok {
		r.connections[conn] = conn.TransportDropBaseline()
	}
	r.connectionMu.Unlock()
	r.callbackMu.Unlock()
}

func (r *onebotRuntime) completeConnection(conn *socketio.WebsocketWrapper) {
	if conn == nil {
		return
	}
	r.mu.Lock()
	var disconnected emitter.Emitter
	if r.emitterConn == conn {
		disconnected = r.emitter
		r.emitter, r.emitterConn = nil, nil
	}
	r.mu.Unlock()
	if disconnected != nil {
		disconnected.Close()
	}
	r.connectionMu.Lock()
	if baseline, ok := r.connections[conn]; ok {
		current := conn.DroppedEventCount()
		r.transportDropMu.Lock()
		if current > baseline {
			r.transportDropped.Add(current - baseline)
		}
		r.transportDropMu.Unlock()
		delete(r.connections, conn)
	}
	r.connectionMu.Unlock()
}

func newOnebotRuntime(config OnebotConfig, resolver adapterapi.SecretResolver, listenerFactories ...onebotListenerFactory) *onebotRuntime {
	return newOnebotRuntimeWithResources(config, resolver, "", "", "", listenerFactories...)
}

func newOnebotRuntimeWithResources(
	config OnebotConfig,
	resolver adapterapi.SecretResolver,
	resourceRoot string,
	resourceAccessToken string,
	resourceServeAddress string,
	listenerFactories ...onebotListenerFactory,
) *onebotRuntime {
	var listenerFactory onebotListenerFactory
	if len(listenerFactories) > 0 {
		listenerFactory = listenerFactories[0]
	}
	assetRoot := ""
	if strings.TrimSpace(resourceRoot) != "" {
		// ResourceRoot is the instance directory (for example data/default);
		// message assets live in its shared parent data directory.
		assetRoot = filepath.Dir(filepath.Clean(resourceRoot))
	}
	return &onebotRuntime{
		config: config, resolver: resolver, listenerFactory: listenerFactory,
		assetResolver: &onebotAssetResolver{
			ImageAssetBaseURL: config.ImageAssetBaseURL,
			assetRoot:         assetRoot,
			assetImageToken:   resourceAccessToken,
			assetServeAddress: resourceServeAddress,
			logger:            onebotRuntimeAssetLogger,
		},
		stopCh: make(chan struct{}), doneCh: make(chan struct{}),
		priorityConnect:    make(chan onebotRuntimeEvent, 1),
		priorityDisconnect: make(chan onebotRuntimeEvent, 1),
		listenerFailed:     make(chan onebotRuntimeEvent, 1),
		events:             make(chan onebotRuntimeEvent, 32),
		connections:        make(map[*socketio.WebsocketWrapper]uint64),
	}
}

func (r *onebotRuntime) RejectedInboundCount() uint64 {
	if r == nil {
		return 0
	}
	return r.inboundRejected.Load()
}

func (r *onebotRuntime) BackpressureInboundCount() uint64 {
	if r == nil {
		return 0
	}
	return r.inboundBackpressure.Load()
}

func (r *onebotRuntime) InboundConflictCount() uint64 {
	if r == nil {
		return 0
	}
	return r.inboundCollisions.Load()
}

func (r *onebotRuntime) InboundRetryCount() uint64 {
	if r == nil {
		return 0
	}
	return r.inboundRetries.Load()
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
	case adapterapi.EffectPayloadAdapterAPI:
		response, err := r.CallAPI(ctx, adapterapi.AdapterCallRequest{EndpointID: effect.EndpointID, RawJSON: payload.RequestJSON})
		if err != nil {
			if errors.Is(err, emitter.ErrInvalidRawRequest) {
				return adapterapi.TerminalResult("onebot_invalid_request", err.Error())
			}
			return onebotProviderErrorResult("adapter_api", effect.RetryClass, err)
		}
		return onebotRawResult("adapter_api", effect.RetryClass, []byte(response.RawJSON))
	case adapterapi.EffectPayloadForward:
		raw, err := onebotForwardRequestJSON(payload)
		if err != nil {
			return adapterapi.UnsupportedResult("onebot_invalid_forward")
		}
		action := emitter.Action("send_private_forward_msg")
		if payload.Target.Kind == adapterapi.TargetGroup {
			action = "send_group_forward_msg"
		}
		response, err := r.CallAPI(ctx, adapterapi.AdapterCallRequest{EndpointID: effect.EndpointID, RawJSON: string(raw)})
		if err != nil {
			if errors.Is(err, emitter.ErrInvalidRawRequest) {
				return adapterapi.TerminalResult("onebot_invalid_request", err.Error())
			}
			return onebotProviderErrorResult(action, effect.RetryClass, err)
		}
		return onebotForwardResult(action, effect.RetryClass, []byte(response.RawJSON))
	case adapterapi.EffectPayloadPersonText, adapterapi.EffectPayloadGroupText, adapterapi.EffectPayloadSegments:
		target, err := onebotTargetID(payload.Target, payload.Target.Kind == adapterapi.TargetGroup)
		if err != nil {
			return adapterapi.UnsupportedResult("onebot_invalid_target")
		}
		chain, recalls, err := r.onebotMessageChain(payload)
		if err != nil {
			return adapterapi.UnsupportedResult("onebot_unsupported_segment")
		}
		reservedRecalls := countOnebotDelayedRecalls(recalls, len(chain) > 0)
		if err := r.reserveOnebotMessageRecalls(reservedRecalls); err != nil {
			return adapterapi.TerminalResult("onebot_recall_queue_full", err.Error())
		}
		defer func() {
			r.releaseOnebotRecallReservations(reservedRecalls)
		}()
		if len(chain) == 0 {
			handled, recallErr := r.dispatchOnebotMessageRecalls(ctx, outbound, recalls, 0, true, &reservedRecalls)
			if recallErr != nil {
				return onebotProviderErrorResult(emitter.ACTION_DELETE_MSG, effect.RetryClass, recallErr)
			}
			if !handled {
				return adapterapi.UnsupportedResult("onebot_recall_target_missing")
			}
			return adapterapi.SucceededResult("")
		}
		var response *emitterTypes.SendMsgRes
		action := emitter.ACTION_SEND_GROUP_MSG
		if payload.Target.Kind == adapterapi.TargetPerson {
			action = emitter.ACTION_SEND_PRIVATE_MSG
			response, err = outbound.SendPvtMsg(ctx, target, chain)
		} else {
			response, err = outbound.SendGrMsg(ctx, target, chain)
		}
		if err != nil {
			return onebotProviderErrorResult(action, effect.RetryClass, err)
		}
		if response == nil || response.MessageId == 0 {
			diagnostic := onebotProviderDiagnostic{action: safeOnebotDiagnosticLabel(action, "unknown")}
			return onebotUncertainResult(effect.RetryClass, "onebot_response_uncertain", diagnostic.message("provider returned no message id"))
		}
		if _, recallErr := r.dispatchOnebotMessageRecalls(ctx, outbound, recalls, response.MessageId, false, &reservedRecalls); recallErr != nil {
			result := adapterapi.AmbiguousResult("onebot_recall_schedule_failed", "message was sent but recall scheduling failed")
			result.ProviderID = strconv.FormatInt(response.MessageId, 10)
			return result
		}
		return adapterapi.SucceededResult(strconv.FormatInt(response.MessageId, 10))
	case adapterapi.EffectPayloadRecall:
		messageID, err := parseOnebotMessageID(string(payload.MessageID))
		if err != nil {
			return adapterapi.UnsupportedResult("onebot_invalid_message_id")
		}
		if err := outbound.DelMsg(ctx, messageID); err != nil {
			return onebotProviderErrorResult(emitter.ACTION_DELETE_MSG, effect.RetryClass, err)
		}
		return adapterapi.SucceededResult("")
	case adapterapi.EffectPayloadSetGroupCard:
		groupID, memberID, err := onebotGroupAndMember(payload.Target)
		if err != nil {
			return adapterapi.UnsupportedResult("onebot_invalid_target")
		}
		if err := outbound.SetGroupCard(ctx, groupID, memberID, payload.Card); err != nil {
			return onebotProviderErrorResult(emitter.ACTION_SET_GROUP_CARD, effect.RetryClass, err)
		}
		return adapterapi.SucceededResult("")
	case adapterapi.EffectPayloadQuit:
		groupID, err := onebotTargetID(payload.Target, true)
		if err != nil {
			return adapterapi.UnsupportedResult("onebot_invalid_target")
		}
		if err := outbound.QuitGroup(ctx, groupID); err != nil {
			return onebotProviderErrorResult(emitter.ACTION_QUIT_GROUP, effect.RetryClass, err)
		}
		return adapterapi.SucceededResult("")
	case adapterapi.EffectPayloadGroupInfoRefresh:
		groupID, err := onebotTargetID(payload.Target, true)
		if err != nil {
			return adapterapi.UnsupportedResult("onebot_invalid_target")
		}
		raw, err := outbound.Raw(ctx, emitter.ACTION_GET_GROUP_INFO, emitterTypes.GetGroupInfoReq{
			GroupId: groupID,
			NoCache: true,
		})
		if err != nil {
			return onebotProviderErrorResult(emitter.ACTION_GET_GROUP_INFO, effect.RetryClass, err)
		}
		return onebotGroupInfoRefreshResult(effect.RetryClass, raw, payload.Target, groupID)
	case adapterapi.EffectPayloadEdit:
		messageID, err := parseOnebotMessageID(string(payload.MessageID))
		if err != nil {
			return adapterapi.UnsupportedResult("onebot_invalid_message_id")
		}
		action := emitter.Action("set_msg")
		raw, err := outbound.Raw(ctx, action, map[string]any{
			"message_id": messageID,
			"message":    onebotTextChain(payload.Text),
		})
		if err != nil {
			return onebotProviderErrorResult(action, effect.RetryClass, err)
		}
		return onebotRawResult(action, effect.RetryClass, raw)
	case adapterapi.EffectPayloadAnswerRequest:
		// The provider addresses a request by its flag; the target only routes
		// the lane, so it is validated but not sent.
		group := payload.Target.Kind == adapterapi.TargetGroup
		if _, err := onebotTargetID(payload.Target, group); err != nil {
			return adapterapi.UnsupportedResult("onebot_invalid_target")
		}
		action := emitter.ACTION_SET_FRIEND_ADD_REQUEST
		var params any = emitterTypes.FriendAddReq{Flag: payload.RequestID, Approve: payload.Approve}
		if group {
			// Only invitations to the bot are surfaced as group requests.
			action = emitter.ACTION_SET_GROUP_ADD_REQUEST
			params = emitterTypes.GroupAddReq{Flag: payload.RequestID, SubType: "invite", Approve: payload.Approve, Reason: payload.Reason}
		}
		raw, err := outbound.Raw(ctx, action, params)
		if err != nil {
			return onebotProviderErrorResult(action, effect.RetryClass, err)
		}
		return onebotRawResult(action, effect.RetryClass, raw)
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
			return onebotProviderErrorResult(action, effect.RetryClass, err)
		}
		return onebotRawResult(action, effect.RetryClass, raw)
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
		adapterapi.ActionKindAnswerRequest,
		adapterapi.ActionKindGroupInfoRefresh,
		adapterapi.ActionKindAdapterAPI,
	)
}

type onebotProviderDiagnostic struct {
	action     string
	status     string
	retcode    int
	retcodeSet bool
	cause      string
}

type onebotResponseEnvelope struct {
	Status       string          `json:"status"`
	RetCode      *int            `json:"retcode"`
	RetCodeCamel *int            `json:"retCode"`
	Message      string          `json:"message"`
	Wording      string          `json:"wording"`
	Msg          string          `json:"msg"`
	Data         json.RawMessage `json:"data"`
}

func onebotProviderErrorResult(action emitter.Action, retryClass adapterapi.EffectRetryClass, err error) adapterapi.EffectResult {
	diagnostic := onebotProviderDiagnostic{action: safeOnebotDiagnosticLabel(action, "unknown")}
	var rejected interface{ IsActionRejected() }
	if errors.As(err, &rejected) {
		if responseDiagnostic, ok := onebotDiagnosticFromSDKError(action, err); ok {
			diagnostic = responseDiagnostic
		}
		return adapterapi.TerminalResult("onebot_provider_rejected", diagnostic.message("provider rejected action"))
	}

	var networkErr net.Error
	var temporaryErr interface{ Temporary() bool }
	switch {
	case errors.Is(err, context.Canceled):
		return onebotUncertainResult(retryClass, "onebot_transport_canceled", diagnostic.message("provider request canceled before acknowledgement"))
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &networkErr) && networkErr.Timeout()):
		return onebotUncertainResult(retryClass, "onebot_transport_timeout", diagnostic.message("provider acknowledgement timed out"))
	case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF):
		return onebotUncertainResult(retryClass, "onebot_transport_eof", diagnostic.message("provider connection ended before acknowledgement"))
	case errors.As(err, &temporaryErr) && temporaryErr.Temporary():
		return onebotUncertainResult(retryClass, "onebot_provider_transient", diagnostic.message("provider reported a transient failure"))
	}
	if responseDiagnostic, ok := onebotDiagnosticFromSDKError(action, err); ok {
		return onebotUncertainResult(retryClass, "onebot_response_uncertain", responseDiagnostic.message("provider response could not be decoded"))
	}
	return onebotUncertainResult(retryClass, "onebot_transport_unknown", diagnostic.message("provider transport outcome is unknown"))
}

func onebotRawResult(action emitter.Action, retryClass adapterapi.EffectRetryClass, raw []byte) adapterapi.EffectResult {
	diagnostic, ok := decodeOnebotProviderDiagnostic(action, raw)
	if !ok {
		diagnostic = onebotProviderDiagnostic{action: safeOnebotDiagnosticLabel(action, "unknown")}
		return onebotUncertainResult(retryClass, "onebot_response_uncertain", diagnostic.message("provider returned an invalid response"))
	}
	if strings.EqualFold(diagnostic.status, "async") && diagnostic.retcodeSet && diagnostic.retcode == 1 {
		return onebotUncertainResult(retryClass, "onebot_provider_async", diagnostic.message("provider accepted asynchronous action; final outcome is unknown"))
	}
	if strings.EqualFold(diagnostic.status, "failed") || (diagnostic.retcodeSet && diagnostic.retcode != 0) {
		return adapterapi.TerminalResult("onebot_provider_rejected", diagnostic.message("provider rejected action"))
	}
	if diagnostic.status == "" || !diagnostic.retcodeSet {
		return onebotUncertainResult(retryClass, "onebot_response_uncertain", diagnostic.message("provider returned an incomplete response"))
	}
	if strings.EqualFold(diagnostic.status, "ok") {
		return adapterapi.SucceededResult("")
	}
	return onebotUncertainResult(retryClass, "onebot_response_uncertain", diagnostic.message("provider response status is uncertain"))
}
func onebotForwardResult(action emitter.Action, retryClass adapterapi.EffectRetryClass, raw []byte) adapterapi.EffectResult {
	result := onebotRawResult(action, retryClass, raw)
	if result.Outcome != adapterapi.EffectSucceeded {
		return result
	}
	var envelope onebotResponseEnvelope
	if json.Unmarshal(raw, &envelope) != nil || len(envelope.Data) == 0 || string(envelope.Data) == "null" {
		return result
	}
	var data struct {
		MessageID json.RawMessage `json:"message_id"`
	}
	if json.Unmarshal(envelope.Data, &data) != nil || len(data.MessageID) == 0 {
		return result
	}
	var messageID int64
	if err := json.Unmarshal(data.MessageID, &messageID); err != nil {
		var stringID string
		if json.Unmarshal(data.MessageID, &stringID) != nil {
			return result
		}
		messageID, err = parseOnebotMessageID(stringID)
		if err != nil {
			return result
		}
	} else if messageID == 0 {
		return result
	}
	result.ProviderID = strconv.FormatInt(messageID, 10)
	return result
}

type onebotGroupInfoResponse struct {
	GroupID        *int64  `json:"group_id"`
	GroupName      *string `json:"group_name"`
	MemberCount    *int64  `json:"member_count"`
	MaxMemberCount *int64  `json:"max_member_count"`
}

func onebotGroupInfoRefreshResult(retryClass adapterapi.EffectRetryClass, raw []byte, target adapterapi.EffectTarget, groupID int64) adapterapi.EffectResult {
	var envelope onebotResponseEnvelope
	if len(raw) == 0 || json.Unmarshal(raw, &envelope) != nil {
		return onebotRawResult(emitter.ACTION_GET_GROUP_INFO, retryClass, raw)
	}
	diagnostic := onebotDiagnosticFromEnvelope(emitter.ACTION_GET_GROUP_INFO, envelope)
	if !strings.EqualFold(diagnostic.status, "ok") || !diagnostic.retcodeSet || diagnostic.retcode != 0 {
		return onebotRawResult(emitter.ACTION_GET_GROUP_INFO, retryClass, raw)
	}
	var info onebotGroupInfoResponse
	if len(envelope.Data) == 0 || string(envelope.Data) == "null" ||
		json.Unmarshal(envelope.Data, &info) != nil ||
		info.GroupID == nil || *info.GroupID != groupID || info.GroupName == nil ||
		(info.MemberCount != nil && (*info.MemberCount < 0 || uint64(*info.MemberCount) > uint64(^uint32(0)))) ||
		(info.MaxMemberCount != nil && (*info.MaxMemberCount < 0 || uint64(*info.MaxMemberCount) > uint64(^uint32(0)))) {
		return adapterapi.TerminalResult("onebot_invalid_response", "provider returned invalid group info")
	}
	observation := adapterapi.GroupInfoResult{
		Conversation:        target.Conversation,
		Name:                *info.GroupName,
		MemberCountKnown:    info.MemberCount != nil,
		MaxMemberCountKnown: info.MaxMemberCount != nil,
	}
	if info.MemberCount != nil {
		observation.MemberCount = uint32(*info.MemberCount)
	}
	if info.MaxMemberCount != nil {
		observation.MaxMemberCount = uint32(*info.MaxMemberCount)
	}
	if err := observation.ValidateForTarget(target); err != nil {
		return adapterapi.TerminalResult("onebot_invalid_response", "provider returned invalid group info")
	}
	return adapterapi.SucceededGroupInfoResult(observation)
}

// Execute runs after the durable dispatch marker. Only provider-idempotent
// effects may turn an unacknowledged provider outcome into a retry;
// pre-dispatch-only and non-idempotent effects must remain ambiguous.
func onebotUncertainResult(retryClass adapterapi.EffectRetryClass, code, message string) adapterapi.EffectResult {
	if retryClass == adapterapi.EffectRetryProviderIdempotent {
		return adapterapi.RetryableResult(code, message)
	}
	return adapterapi.AmbiguousResult(code, message)
}

// The bundled SDK exposes rejection as a marker error whose safe structured
// response follows " response=". Deliberately ignore the earlier params/echo
// text because it can contain message bodies and other request data.
func onebotDiagnosticFromSDKError(action emitter.Action, err error) (onebotProviderDiagnostic, bool) {
	if err == nil {
		return onebotProviderDiagnostic{}, false
	}
	const marker = " response="
	text := err.Error()
	for searchEnd := len(text); searchEnd > 0; {
		index := strings.LastIndex(text[:searchEnd], marker)
		if index < 0 {
			break
		}
		start := index + len(marker)
		decoder := json.NewDecoder(strings.NewReader(text[start:]))
		var envelope onebotResponseEnvelope
		if decoder.Decode(&envelope) == nil {
			diagnostic := onebotDiagnosticFromEnvelope(action, envelope)
			if diagnostic.status != "" || diagnostic.retcodeSet {
				return diagnostic, true
			}
		}
		searchEnd = index
	}
	return onebotProviderDiagnostic{}, false
}

func decodeOnebotProviderDiagnostic(action emitter.Action, raw []byte) (onebotProviderDiagnostic, bool) {
	if len(raw) == 0 {
		return onebotProviderDiagnostic{}, false
	}
	var envelope onebotResponseEnvelope
	if json.Unmarshal(raw, &envelope) != nil {
		return onebotProviderDiagnostic{}, false
	}
	return onebotDiagnosticFromEnvelope(action, envelope), true
}

func onebotDiagnosticFromEnvelope(action emitter.Action, envelope onebotResponseEnvelope) onebotProviderDiagnostic {
	diagnostic := onebotProviderDiagnostic{
		action: safeOnebotDiagnosticLabel(action, "unknown"),
		status: safeOnebotDiagnosticLabel(strings.ToLower(strings.TrimSpace(envelope.Status)), ""),
	}
	switch {
	case envelope.RetCode != nil:
		diagnostic.retcode, diagnostic.retcodeSet = *envelope.RetCode, true
	case envelope.RetCodeCamel != nil:
		diagnostic.retcode, diagnostic.retcodeSet = *envelope.RetCodeCamel, true
	}
	if !diagnostic.retcodeSet || diagnostic.retcode != 0 || !strings.EqualFold(diagnostic.status, "ok") {
		diagnostic.cause = sanitizeOnebotProviderCause(firstNonemptyOnebotCause(envelope.Message, envelope.Wording, envelope.Msg, onebotDataCause(envelope.Data)))
	}
	return diagnostic
}

func onebotDataCause(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text
	}
	var fields struct {
		Message string `json:"message"`
		Wording string `json:"wording"`
		Msg     string `json:"msg"`
		Error   string `json:"error"`
	}
	if json.Unmarshal(raw, &fields) != nil {
		return ""
	}
	return firstNonemptyOnebotCause(fields.Message, fields.Wording, fields.Msg, fields.Error)
}

func firstNonemptyOnebotCause(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func safeOnebotDiagnosticLabel(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	if len(value) > 128 {
		return fallback
	}
	for _, char := range value {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '_' && char != '-' && char != '.' && char != ':' {
			return fallback
		}
	}
	return value
}

func sanitizeOnebotProviderCause(value string) string {
	if len(value) > maxOnebotProviderDiagnosticBytes*2 {
		value = truncateOnebotDiagnostic(value, maxOnebotProviderDiagnosticBytes*2)
	}
	value = strings.ToValidUTF8(value, "\uFFFD")
	value = onebotURLCredentialsPattern.ReplaceAllString(value, "${1}[REDACTED]@")
	value = onebotMySQLCredentialsPattern.ReplaceAllString(value, "${1}[REDACTED]${2}")
	value = onebotBearerDiagnosticPattern.ReplaceAllString(value, "Bearer [REDACTED]")
	value = onebotSensitiveDiagnosticPattern.ReplaceAllString(value, "${1}[REDACTED]")
	value = strings.Join(strings.Fields(value), " ")
	return truncateOnebotDiagnostic(value, maxOnebotProviderDiagnosticBytes)
}

func truncateOnebotDiagnostic(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if len(value) <= limit {
		return value
	}
	const ellipsis = "…"
	end := limit - len(ellipsis)
	for end > 0 && value[end]&0xc0 == 0x80 {
		end--
	}
	return strings.TrimSpace(value[:end]) + ellipsis
}

func (diagnostic onebotProviderDiagnostic) message(category string) string {
	var text strings.Builder
	text.Grow(128 + len(diagnostic.cause))
	text.WriteString("action=")
	text.WriteString(diagnostic.action)
	if diagnostic.status != "" {
		text.WriteString(" status=")
		text.WriteString(diagnostic.status)
	}
	if diagnostic.retcodeSet {
		text.WriteString(" retcode=")
		text.WriteString(strconv.Itoa(diagnostic.retcode))
	}
	text.WriteString(" category=")
	text.WriteString(category)
	if diagnostic.cause != "" {
		text.WriteString(" cause=")
		text.WriteString(diagnostic.cause)
	}
	return truncateOnebotDiagnostic(text.String(), maxOnebotProviderDiagnosticBytes)
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

type onebotRecallDirective struct {
	messageID int64
	delay     time.Duration
}

func (r *onebotRuntime) onebotMessageChain(payload adapterapi.EffectPayload) (schema.MessageChain, []onebotRecallDirective, error) {
	if payload.Kind == adapterapi.EffectPayloadPersonText || payload.Kind == adapterapi.EffectPayloadGroupText {
		chain, recalls := r.onebotTextMessageChain(payload.Text)
		return chain, recalls, nil
	}
	var chain schema.MessageChain
	var recalls []onebotRecallDirective
	for _, segment := range payload.Segments {
		switch segment.Kind {
		case adapterapi.SegmentKindText:
			textChain, textRecalls := r.onebotTextMessageChain(segment.Text)
			chain = append(chain, textChain...)
			recalls = append(recalls, textRecalls...)
		case adapterapi.SegmentKindMention:
			id, err := onebotPersonID(segment.Text)
			if err != nil {
				return nil, nil, err
			}
			chain = chain.At(strconv.FormatInt(id, 10))
		default:
			return nil, nil, errors.New("unsupported OneBot segment")
		}
	}
	return chain, recalls, nil
}

func (r *onebotRuntime) onebotTextMessageChain(text string) (schema.MessageChain, []onebotRecallDirective) {
	if strings.IndexByte(text, '[') < 0 {
		return onebotTextChain(text), nil
	}
	matches := onebotOutboundCodePattern.FindAllStringSubmatchIndex(text, -1)
	if len(matches) == 0 {
		return onebotTextChain(text), nil
	}

	resolver := r.assetResolver
	if resolver == nil {
		resolver = &onebotAssetResolver{
			ImageAssetBaseURL: r.config.ImageAssetBaseURL,
			logger:            onebotRuntimeAssetLogger,
		}
	}
	var chain schema.MessageChain
	var recalls []onebotRecallDirective
	cursor := 0
	for _, match := range matches {
		if match[0] > cursor {
			chain = chain.Text(text[cursor:match[0]])
		}
		segment, recall, ok := r.onebotOutboundCodeSegment(text, match, resolver)
		switch {
		case !ok:
			chain = chain.Text(text[match[0]:match[1]])
		case recall != nil:
			recalls = append(recalls, *recall)
		default:
			chain = chain.Append(segment)
		}
		cursor = match[1]
	}
	if cursor < len(text) {
		chain = chain.Text(text[cursor:])
	}
	return chain, recalls
}

func (r *onebotRuntime) onebotOutboundCodeSegment(text string, match []int, resolver *onebotAssetResolver) (schema.Message, *onebotRecallDirective, bool) {
	var (
		codeType       string
		normalizedType string
		args           map[string]string
		sealCode       bool
	)
	if match[2] >= 0 {
		sealCode = true
		codeType = onebotSealResourceType(text[match[2]:match[3]])
		normalizedType = codeType
		args = map[string]string{"file": strings.TrimSpace(text[match[4]:match[5]])}
	} else {
		codeType = text[match[6]:match[7]]
		normalizedType = strings.ToLower(codeType)
		var ok bool
		args, ok = parseOnebotCQArgs(text, match[8], match[9])
		if !ok {
			return schema.Message{}, nil, false
		}
	}
	if codeType == "" {
		return schema.Message{}, nil, false
	}
	if normalizedType == "recall" {
		recall, ok := parseOnebotRecallDirective(args)
		return schema.Message{}, recall, ok
	}

	switch normalizedType {
	case "image", "file", "record", "video":
		codeType = normalizedType
		fileReference := strings.TrimSpace(args["file"])
		resourceURL := strings.TrimSpace(args["url"])
		if fileReference == "" && resourceURL == "" {
			return schema.Message{}, nil, false
		}
		fileResolved := false
		if fileReference != "" {
			resolved, err := resolveOnebotOutboundResource(resolver, fileReference, sealCode)
			if err == nil {
				args["file"] = resolved
				fileResolved = true
			} else if resourceURL == "" {
				placeholder, marshalErr := sonic.Marshal(map[string]string{"text": "[找不到图片/文件]"})
				if marshalErr != nil {
					return schema.Message{}, nil, false
				}
				return schema.Message{Type: "text", Data: placeholder}, nil, true
			}
		}
		if resourceURL != "" {
			resolved, err := resolveOnebotOutboundResource(resolver, resourceURL, false)
			if err != nil {
				if !fileResolved {
					placeholder, marshalErr := sonic.Marshal(map[string]string{"text": "[找不到图片/文件]"})
					if marshalErr != nil {
						return schema.Message{}, nil, false
					}
					return schema.Message{Type: "text", Data: placeholder}, nil, true
				}
			} else {
				args["url"] = resolved
				if fileReference == "" {
					args["file"] = resolved
				}
			}
		}
	}

	data, err := sonic.Marshal(args)
	if err != nil {
		return schema.Message{}, nil, false
	}
	return schema.Message{Type: codeType, Data: data}, nil, true
}

func onebotSealResourceType(code string) string {
	switch strings.ToLower(code) {
	case "图", "img", "文本", "text":
		// 文本/text 是历史兼容拼写；既有海豹码语义一直将其映射为图片。
		return "image"
	case "语音", "voice":
		return "record"
	case "视频", "video":
		return "video"
	default:
		return ""
	}
}

func parseOnebotCQArgs(text string, start, end int) (map[string]string, bool) {
	args := make(map[string]string)
	if start < 0 || end < 0 {
		return args, true
	}
	raw := strings.TrimPrefix(text[start:end], ",")
	if raw == "" {
		return args, true
	}
	for _, item := range strings.Split(raw, ",") {
		pair := strings.SplitN(item, "=", 2)
		if len(pair) != 2 || strings.TrimSpace(pair[0]) == "" {
			return nil, false
		}
		args[strings.TrimSpace(pair[0])] = message.UnescapeCQParam(pair[1])
	}
	return args, true
}

func parseOnebotRecallDirective(args map[string]string) (*onebotRecallDirective, bool) {
	recall := &onebotRecallDirective{}
	if rawID := strings.TrimSpace(args["id"]); rawID != "" {
		messageID, err := parseOnebotMessageID(rawID)
		if err != nil {
			return nil, false
		}
		recall.messageID = messageID
	}
	if rawDelay := strings.TrimSpace(args["delay"]); rawDelay != "" {
		delayMS, err := strconv.ParseInt(rawDelay, 10, 64)
		const maxDelayMS = int64((1<<63 - 1) / 1_000_000)
		if err != nil || delayMS < 0 || delayMS > maxDelayMS {
			return nil, false
		}
		recall.delay = time.Duration(delayMS) * time.Millisecond
	}
	return recall, true
}

func resolveOnebotOutboundResource(resolver *onebotAssetResolver, reference string, sealCode bool) (string, error) {
	reference = strings.TrimSpace(reference)
	if reference == "" {
		return "", errors.New("empty OneBot resource")
	}
	lowerReference := strings.ToLower(reference)
	if strings.HasPrefix(lowerReference, "http://") ||
		strings.HasPrefix(lowerReference, "https://") ||
		strings.HasPrefix(lowerReference, "base64://") {
		return reference, nil
	}
	resolved, err := resolver.resolveLocalAsset(reference)
	if err == nil {
		return resolved, nil
	}
	if !sealCode &&
		!strings.HasPrefix(lowerReference, "file://") &&
		!strings.ContainsAny(reference, `/\`) {
		// OneBot providers also accept opaque uploaded-resource IDs in file.
		return reference, nil
	}
	return "", err
}

func countOnebotDelayedRecalls(recalls []onebotRecallDirective, fallbackAvailable bool) int {
	count := 0
	for _, recall := range recalls {
		if recall.delay > 0 && (recall.messageID != 0 || fallbackAvailable) {
			count++
		}
	}
	return count
}

func (r *onebotRuntime) reserveOnebotMessageRecalls(count int) error {
	if count <= 0 {
		return nil
	}
	r.recallMu.Lock()
	defer r.recallMu.Unlock()
	if r.fenced.Load() {
		r.recallRejected.Add(1)
		return ErrOnebotRuntimeStopped
	}
	if count > maxOnebotPendingRecalls-r.recallPending {
		r.recallRejected.Add(1)
		return ErrOnebotRecallQueueFull
	}
	r.recallPending += count
	return nil
}

func (r *onebotRuntime) releaseOnebotRecallReservations(count int) {
	if count <= 0 {
		return
	}
	r.recallMu.Lock()
	if count >= r.recallPending {
		r.recallPending = 0
	} else {
		r.recallPending -= count
	}
	r.recallMu.Unlock()
}

func (r *onebotRuntime) dispatchOnebotMessageRecalls(
	ctx context.Context,
	outbound onebotOutboundEmitter,
	recalls []onebotRecallDirective,
	fallbackMessageID int64,
	strict bool,
	reserved *int,
) (bool, error) {
	handled := false
	for _, recall := range recalls {
		messageID := recall.messageID
		if messageID == 0 {
			messageID = fallbackMessageID
		}
		if messageID == 0 {
			continue
		}
		handled = true
		if recall.delay <= 0 {
			if err := outbound.DelMsg(ctx, messageID); err != nil {
				r.recallFailed.Add(1)
				if strict {
					return handled, err
				}
			}
			continue
		}
		if reserved == nil || *reserved <= 0 {
			r.recallRejected.Add(1)
			return handled, errors.New("onebot: delayed recall reservation is unavailable")
		}
		if err := r.scheduleReservedOnebotMessageRecall(outbound, messageID, recall.delay); err != nil {
			return handled, err
		}
		*reserved--
	}
	return handled, nil
}

func (r *onebotRuntime) scheduleOnebotMessageRecall(outbound onebotOutboundEmitter, messageID int64, delay time.Duration) error {
	if outbound == nil || messageID == 0 || delay <= 0 {
		return errors.New("onebot: invalid delayed recall")
	}
	if err := r.reserveOnebotMessageRecalls(1); err != nil {
		return err
	}
	if err := r.scheduleReservedOnebotMessageRecall(outbound, messageID, delay); err != nil {
		r.releaseOnebotRecallReservations(1)
		return err
	}
	return nil
}

func (r *onebotRuntime) scheduleReservedOnebotMessageRecall(outbound onebotOutboundEmitter, messageID int64, delay time.Duration) error {
	r.recallMu.Lock()
	if r.fenced.Load() {
		r.recallMu.Unlock()
		r.recallRejected.Add(1)
		return ErrOnebotRuntimeStopped
	}
	root := r.recallCtx
	if root == nil {
		root, r.recallCancel = context.WithCancel(context.Background())
		r.recallCtx = root
	}
	timerCtx, cancelTimer := context.WithTimeout(root, delay)
	r.recallMu.Unlock()

	context.AfterFunc(timerCtx, func() {
		defer r.releaseOnebotRecallReservations(1)
		defer cancelTimer()
		timerErr := timerCtx.Err()
		if !errors.Is(timerErr, context.DeadlineExceeded) || root.Err() != nil || r.fenced.Load() {
			return
		}
		recallCtx, cancelRecall := context.WithTimeout(root, onebotRecallTimeout)
		defer cancelRecall()
		if err := outbound.DelMsg(recallCtx, messageID); err != nil {
			r.recallFailed.Add(1)
		}
	})
	return nil
}

func (r *onebotRuntime) cancelOnebotMessageRecalls() {
	r.recallMu.Lock()
	cancel := r.recallCancel
	r.recallCancel = nil
	r.recallCtx = nil
	r.recallMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (r *onebotRuntime) Diagnostics(context.Context) adapterapi.DiagnosticReport {
	if r == nil {
		return adapterapi.DiagnosticReport{}
	}
	r.connectionMu.Lock()
	r.transportDropMu.Lock()
	dropped := r.transportDropped.Load()
	for wrapper, baseline := range r.connections {
		if wrapper != nil {
			current := wrapper.DroppedEventCount()
			if current > baseline {
				dropped += current - baseline
			}
		}
	}
	r.transportDropMu.Unlock()
	r.connectionMu.Unlock()
	count := func(code, message string, value uint64) adapterapi.DiagnosticEntry {
		return adapterapi.DiagnosticEntry{
			Severity: adapterapi.DiagnosticInfo,
			Code:     code,
			Message:  message + ": " + strconv.FormatUint(value, 10),
		}
	}
	return adapterapi.DiagnosticReport{Entries: []adapterapi.DiagnosticEntry{
		count("inbound.rejected", "Rejected inbound events", r.inboundRejected.Load()),
		count("inbound.backpressure", "Inbound backpressure events", r.inboundBackpressure.Load()),
		count("inbound.conflicts", "Inbound identity conflicts", r.inboundCollisions.Load()),
		count("inbound.retries", "Inbound bounded rehandoffs", r.inboundRetries.Load()),
		count("priority.coalesced", "Coalesced duplicate priority events", r.priorityDropped.Load()),
		count("adapter_event.enqueued", "Global adapter events admitted to delivery", r.globalEventEnqueued.Load()),
		count("adapter_event.accepted", "Accepted global adapter event receipts", r.globalEventAccepted.Load()),
		count("adapter_event.duplicate", "Duplicate global adapter event receipts", r.globalEventDuplicate.Load()),
		count("adapter_event.rejected", "Rejected global adapter event receipts", r.globalEventRejected.Load()),
		count("adapter_event.backpressure", "Global adapter events dropped at delivery-lane backpressure (no retry)", r.globalEventBackpressure.Load()),
		count("adapter_event.failed", "Failed global adapter event deliveries", r.globalEventFailed.Load()),
		count("transport.dropped_events", "Transport callback events dropped at queue admission", dropped),
		count("outbound.recall_rejected", "Rejected delayed recalls", r.recallRejected.Load()),
		count("outbound.recall_failed", "Failed recalls", r.recallFailed.Load()),
		count("transport.reconnect_attempts", "Client reconnect attempts", r.reconnectAttempts.Load()),
		count("transport.auth_rejected", "Unauthorized connections rejected", r.authRejected.Load()),
	}}
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
	r.startGlobalOnebotEventDelivery(runCtx, core)

	defer func() {
		if r.redialTimer != nil {
			r.redialTimer.Stop()
		}
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
	} else if err := r.startClient(manager, token, runCtx); err != nil {
		if r.fenced.Load() || errors.Is(runCtx.Err(), context.Canceled) {
			return nil
		}
		// The protocol end may simply not be up yet, as after a host reboot.
		r.connectionLost(runCtx, "connect_failed", err)
	}

	for {
		if err := r.drainPriorityEvents(runCtx); err != nil {
			return err
		}
		select {
		case <-r.stopCh:
			return nil
		case <-runCtx.Done():
			if r.stopReq.Load() {
				return nil
			}
			return runCtx.Err()
		case event := <-r.priorityConnect:
			if err := r.processRuntimeEvent(runCtx, event); err != nil {
				return err
			}
		case event := <-r.priorityDisconnect:
			if err := r.processRuntimeEvent(runCtx, event); err != nil {
				return err
			}
		case event := <-r.listenerFailed:
			if err := r.processRuntimeEvent(runCtx, event); err != nil {
				return err
			}
		case event := <-r.events:
			if err := r.processRuntimeEvent(runCtx, event); err != nil {
				return err
			}
		case <-r.redialC:
			r.redialTimer, r.redialC = nil, nil
			if err := r.redial(runCtx); err != nil && !r.fenced.Load() && runCtx.Err() == nil {
				r.connectionLost(runCtx, "connect_failed", err)
			}
		}
	}
}

func (r *onebotRuntime) drainPriorityEvents(ctx context.Context) error {
	for {
		select {
		case event := <-r.priorityConnect:
			if err := r.processRuntimeEvent(ctx, event); err != nil {
				return err
			}
		case event := <-r.priorityDisconnect:
			if err := r.processRuntimeEvent(ctx, event); err != nil {
				return err
			}
		case event := <-r.listenerFailed:
			if err := r.processRuntimeEvent(ctx, event); err != nil {
				return err
			}
		default:
			return nil
		}
	}
}

func (r *onebotRuntime) processRuntimeEvent(runCtx context.Context, event onebotRuntimeEvent) error {
	if r.fenced.Load() {
		return nil
	}
	switch event.kind {
	case "connect":
		if err := r.handleConnected(runCtx, event.kws); err != nil {
			if r.fenced.Load() {
				return nil
			}
			r.connectionLost(runCtx, "login_info_failed", err)
			return nil
		}
		r.connectionRestored()
	case "disconnect":
		// A connection that never logged in, such as an unauthorized one, ends
		// no session, and a newer live connection makes an older one's late
		// disconnect irrelevant.
		if !r.sessionUp || r.hasLiveConnection() {
			return nil
		}
		r.sessionUp = false
		if event.err == nil {
			event.err = errors.New("remote WebSocket closed")
		}
		r.connectionLost(runCtx, "remote_closed", event.err)
	case "listener_failed":
		_ = r.reportFailure(runCtx, "listener_failed", event.err)
		return event.err
	case "inbound":
		if err := r.handleInbound(runCtx, event.raw); err != nil {
			if errors.Is(err, ErrOnebotUnsupportedInboundEvent) {
				r.inboundRejected.Add(1)
				return nil
			}
			if errors.Is(err, eventstore.ErrConflict) {
				r.inboundCollisions.Add(1)
				r.inboundRejected.Add(1)
				return nil
			}
			if isRetryableInboundError(err) {
				if rehandoffOnebotInbound(&event) {
					r.inboundRetries.Add(1)
					if r.enqueue(event) {
						return nil
					}
				}
				r.inboundRejected.Add(1)
				return nil
			}
			_ = r.reportFailure(runCtx, "inbound_failed", err)
			return err
		}
	}
	return nil
}

// connectionLost reports an outage once, however many redials it takes, and
// as a client schedules the next redial. A server keeps listening for the
// protocol end to connect again. It runs on the Run goroutine.
func (r *onebotRuntime) connectionLost(ctx context.Context, code string, cause error) {
	if !r.outageReported {
		r.outageReported = true
		_ = r.reportFailure(ctx, code, cause)
		detail := ""
		if cause != nil {
			detail = sanitizeOnebotProviderCause(cause.Error())
		}
		if r.config.Mode == "server" {
			onebotRuntimeLogger().Warnf("OneBot 连接中断（%s）：%s；等待协议端重新连接", code, detail)
		} else {
			onebotRuntimeLogger().Warnf("OneBot 连接中断（%s）：%s；将自动重连", code, detail)
		}
	}
	if r.config.Mode != "server" {
		r.scheduleRedial()
	}
}

// connectionRestored marks a logged-in session and resets the backoff.
func (r *onebotRuntime) connectionRestored() {
	r.sessionUp = true
	if r.outageReported {
		onebotRuntimeLogger().Infof("OneBot 连接已恢复")
	}
	r.outageReported = false
	r.redialStreak = 0
	if r.redialTimer != nil {
		r.redialTimer.Stop()
		r.redialTimer, r.redialC = nil, nil
	}
}

func (r *onebotRuntime) scheduleRedial() {
	if r.redialC != nil {
		return
	}
	base, limit := r.reconnectBase, r.reconnectMax
	if base <= 0 {
		base = defaultOnebotReconnectBase
	}
	if limit <= 0 {
		limit = defaultOnebotReconnectMax
	}
	delay := limit
	if r.redialStreak < 30 {
		if backoff := base << r.redialStreak; backoff > 0 && backoff < limit {
			delay = backoff
		}
	}
	r.redialStreak++
	r.redialTimer = time.NewTimer(delay)
	r.redialC = r.redialTimer.C
}

// redial opens a new transport on the client facade, which keeps its event
// bindings: success arrives as a connect event like the first connection.
func (r *onebotRuntime) redial(ctx context.Context) error {
	r.mu.Lock()
	conn := r.conn
	r.mu.Unlock()
	if conn == nil {
		return errors.New("onebot: client connection is unavailable")
	}
	r.reconnectAttempts.Add(1)
	dialed := make(chan error, 1)
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		dialed <- conn.Reconnect()
	}()
	select {
	case err := <-dialed:
		return err
	case <-ctx.Done():
		conn.Close()
		return ctx.Err()
	}
}

func (r *onebotRuntime) hasLiveConnection() bool {
	r.connectionMu.Lock()
	defer r.connectionMu.Unlock()
	for connection := range r.connections {
		if connection.IsAlive() {
			return true
		}
	}
	return false
}

func onebotRuntimeLogger() *zap.SugaredLogger { return zap.S().Named(logger.LogKeyAdapter) }

func rehandoffOnebotInbound(event *onebotRuntimeEvent) bool {
	if event == nil || event.attempt >= maxOnebotInboundRetries {
		return false
	}
	event.attempt++
	return true
}

func (r *onebotRuntime) Stop(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	r.stopOnce.Do(func() {
		r.stopReq.Store(true)
		r.fenced.Store(true)
		r.cancelOnebotMessageRecalls()
		r.stopGlobalOnebotEventDelivery()
		close(r.stopCh)
		r.mu.Lock()
		cancel, server, listener, manager, conn, started := r.cancel, r.server, r.listener, r.manager, r.conn, r.started
		activeEmitter := r.emitter
		r.mu.Unlock()
		if activeEmitter != nil {
			activeEmitter.Close()
		}
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
			r.waitGlobalOnebotEventDelivery()
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
				// Refuse only this connection: anyone who can reach the listener
				// must not be able to take the endpoint down with a wrong token.
				r.authRejected.Add(1)
				onebotRuntimeLogger().Warnf("OneBot 反向连接 token 验证失败，已拒绝该连接（%s）", r.config.ListenAddress)
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
			var envelope struct {
				PostType json.RawMessage `json:"post_type"`
				Echo     json.RawMessage `json:"echo"`
			}
			if json.Unmarshal(payload.Data, &envelope) != nil {
				r.inboundRejected.Add(1)
				return
			}
			var echo string
			_ = json.Unmarshal(envelope.Echo, &echo)
			if echo != "" {
				r.mu.Lock()
				e, connection := r.emitter, r.emitterConn
				r.mu.Unlock()
				if e != nil && (payload.Kws == nil || payload.Kws == connection) {
					e.HandleEcho(echo, payload.Data)
				}
				return
			}
			var postType string
			if json.Unmarshal(envelope.PostType, &postType) == nil && postType != "" {
				r.enqueue(onebotRuntimeEvent{kind: "inbound", raw: append([]byte(nil), payload.Data...)})
			}
		})
	})
}

func priorityChannel(r *onebotRuntime, kind string) chan onebotRuntimeEvent {
	switch kind {
	case "connect":
		return r.priorityConnect
	case "disconnect":
		return r.priorityDisconnect
	case "listener_failed":
		return r.listenerFailed
	default:
		return nil
	}
}

func (r *onebotRuntime) enqueue(event onebotRuntimeEvent) bool {
	if channel := priorityChannel(r, event.kind); channel != nil {
		select {
		case channel <- event:
			return true
		default:
			r.priorityDropped.Add(1)
			return true
		}
	}
	select {
	case r.events <- event:
		return true
	default:
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
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	r.mu.Lock()
	r.listener, r.server = listener, server
	r.mu.Unlock()
	r.wg.Add(1)

	go func() {
		defer r.wg.Done()
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			r.enqueue(onebotRuntimeEvent{kind: "listener_failed", err: err})
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
	return r.handleProtocolInbound(ctx, raw)
}

// newOnebotInbound starts the inbound for one provider event. The fields that
// depend on what kind of event it is are filled in by the caller.
func newOnebotInbound(envelope *onebotInboundEnvelope) adapterapi.InboundMessage {
	message := adapterapi.InboundMessage{
		ConversationKind: adapterapi.ConversationKindDirect,
		Platform:         "QQ",
	}
	if envelope.Time > 0 {
		message.OccurredAt = time.Unix(envelope.Time, 0)
	}
	return message
}

// fillOnebotMessage translates a provider message into the inbound contract.
// A message received live and the same message read back from the provider's
// history both come through here, so they are the same fact either way.
func fillOnebotMessage(message *adapterapi.InboundMessage, envelope *onebotInboundEnvelope) error {
	message.Kind = adapterapi.InboundKindMessage
	messageID, hasMessageID := onebotInboundID(envelope.MessageID)
	if !hasMessageID {
		return fmt.Errorf("%w: missing message_id", ErrOnebotUnsupportedInboundEvent)
	}
	messageIDValue, err := adapterapi.NewMessageID(messageID)
	if err != nil {
		return fmt.Errorf("%w: invalid message_id", ErrOnebotUnsupportedInboundEvent)
	}
	providerEventID, err := adapterapi.NewProviderEventID("onebot-message-" + messageID)
	if err != nil {
		return fmt.Errorf("%w: invalid message_id", ErrOnebotUnsupportedInboundEvent)
	}
	userID, hasUserID := onebotInboundID(envelope.UserID)
	if !hasUserID {
		return fmt.Errorf("%w: missing user_id", ErrOnebotUnsupportedInboundEvent)
	}
	sender, err := adapterapi.NewPrincipalID("QQ:" + userID)
	if err != nil {
		return fmt.Errorf("%w: invalid user_id", ErrOnebotUnsupportedInboundEvent)
	}
	message.MessageID = messageIDValue
	message.ProviderEventID = providerEventID
	message.Sender = sender
	message.Sequence, _ = onebotInboundSequence(envelope.MessageSeq)
	message.Text = onebotInboundText(envelope.Message)
	message.Segments = onebotInboundSegments(envelope.Message)
	if envelope.MessageType == "guild" {
		guildID, hasGuildID := onebotInboundID(envelope.GuildID)
		channelID, hasChannelID := onebotInboundID(envelope.ChannelID)
		if !hasGuildID || !hasChannelID {
			return fmt.Errorf("%w: incomplete guild conversation", ErrOnebotUnsupportedInboundEvent)
		}
		message.ConversationKind = adapterapi.ConversationKindGroup
		message.Conversation, _ = adapterapi.NewConversationID(fmt.Sprintf("QQ-CH-Group:%s-%s", guildID, channelID))
		if !message.Conversation.Valid() {
			return fmt.Errorf("%w: invalid guild conversation", ErrOnebotUnsupportedInboundEvent)
		}
	} else if id, ok := onebotInboundID(envelope.GroupID); ok {
		message.ConversationKind = adapterapi.ConversationKindGroup
		message.Conversation, _ = adapterapi.NewConversationID("QQ-Group:" + id)
		if !message.Conversation.Valid() {
			return fmt.Errorf("%w: invalid group conversation", ErrOnebotUnsupportedInboundEvent)
		}
	} else if envelope.MessageType == "group" {
		return fmt.Errorf("%w: incomplete group conversation", ErrOnebotUnsupportedInboundEvent)
	} else if message.Sender != "" {
		message.Conversation, _ = adapterapi.NewConversationID(string(message.Sender))
	}
	if message.ConversationKind == adapterapi.ConversationKindGroup {
		message.SenderRole = normalizeGroupSenderRole(envelope.Sender.Role)
	}
	// The payload already names its sender; a group card wins over the nickname.
	message.SenderName = onebotDisplayName(envelope.Sender.Card)
	if message.SenderName == "" {
		message.SenderName = onebotDisplayName(envelope.Sender.Nickname)
	}
	return nil
}

// onebotInboundSequence reads a provider message sequence number. Anything that
// is not a positive integer is reported as absent.
func onebotInboundSequence(raw json.RawMessage) (int64, bool) {
	id, ok := onebotInboundID(raw)
	if !ok {
		return 0, false
	}
	sequence, err := strconv.ParseInt(id, 10, 64)
	if err != nil || sequence <= 0 {
		return 0, false
	}
	return sequence, true
}

// sealOnebotInbound completes an inbound once its kind specific fields are
// filled in and checks it against the contract.
func sealOnebotInbound(message *adapterapi.InboundMessage) error {
	message.Target = string(message.Conversation)
	if message.ProviderEventID != "" {
		message.CausationID, _ = adapterapi.NewCausationID(string(message.ProviderEventID))
		if !message.CausationID.Valid() {
			return adapterapi.ErrInvalidContract
		}
	}
	if err := message.Validate(); err != nil {
		return fmt.Errorf("%w: invalid inbound contract", ErrOnebotUnsupportedInboundEvent)
	}
	return nil
}

// onebotHistoryInbound turns one entry of a provider's group history into the
// inbound the same message produced when it arrived live. group is the group
// that was asked about; an entry that is not a placeable message of that group,
// or has no time or sequence, is rejected rather than guessed at.
func onebotHistoryInbound(raw []byte, group adapterapi.ConversationID) (adapterapi.InboundMessage, error) {
	var envelope onebotInboundEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return adapterapi.InboundMessage{}, onebotEventRejected("malformed history entry")
	}
	groupID := ExtractQQEmitterGroupID(string(group))
	if envelope.PostType != "message" || envelope.MessageType != "group" || groupID <= 0 || envelope.Time <= 0 {
		return adapterapi.InboundMessage{}, onebotEventRejected("history entry is not a timed group message")
	}
	if _, hasSequence := onebotInboundSequence(envelope.MessageSeq); !hasSequence {
		return adapterapi.InboundMessage{}, onebotEventRejected("history entry has no sequence")
	}
	// Some providers leave the group out of history entries.
	if len(envelope.GroupID) == 0 || string(envelope.GroupID) == "null" {
		envelope.GroupID = json.RawMessage(strconv.FormatInt(groupID, 10))
	}
	message := newOnebotInbound(&envelope)
	if err := fillOnebotMessage(&message, &envelope); err != nil {
		return adapterapi.InboundMessage{}, err
	}
	if message.Conversation != group {
		return adapterapi.InboundMessage{}, onebotEventRejected("history entry belongs to another group")
	}
	event := adapterapi.AdapterEvent{
		Protocol: onebotAdapterEventProtocol,
		Type:     envelope.PostType,
		RawJSON:  string(raw),
	}
	message.AdapterEvent = &event
	if err := sealOnebotInbound(&message); err != nil {
		return adapterapi.InboundMessage{}, err
	}
	return message, nil
}

// normalizeGroupSenderRole maps a provider-supplied group member role onto the
// closed set adapterapi.InboundMessage accepts: "", "member", "admin", "owner".
// Provider vocabularies differ (OneBot/Milky use owner/admin/member, OfficialQQ
// uses the same three, Red uses numeric codes), and some providers emit custom
// titles for the same permission. Anything unrecognized is dropped rather than
// forwarded, because an unexpected value would fail InboundMessage.Validate and
// reject the whole message.
func normalizeGroupSenderRole(role string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "owner":
		return "owner"
	case "admin", "administrator":
		return "admin"
	case "member", "normal":
		return "member"
	default:
		return ""
	}
}
func onebotInboundID(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", false
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text, text != ""
	}
	if number, ok := onebotInboundInt(raw); ok {
		return strconv.FormatInt(number, 10), true
	}
	return "", false
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

// onebotInboundAtTarget resolves the mention target carried by an OneBot `at`
// segment. OneBot v11 sends the target under `qq` as either a JSON number or a
// JSON string; some implementations emit `user_id` instead. The raw provider ID
// is preserved (no `QQ:` prefix) so Core can compare it against the bot's own
// account after prefixing the platform. `all` is preserved verbatim: it is the
// provider's mention-everyone marker rather than a member identity.
func onebotInboundAtTarget(data map[string]json.RawMessage) string {
	for _, key := range []string{"qq", "user_id"} {
		value, ok := data[key]
		if !ok {
			continue
		}
		var text string
		if json.Unmarshal(value, &text) == nil {
			if text = strings.TrimSpace(text); text != "" {
				return text
			}
			continue
		}
		var number int64
		if json.Unmarshal(value, &number) == nil {
			return strconv.FormatInt(number, 10)
		}
	}
	return ""
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
		Type string                     `json:"type"`
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
		if item.Type == "at" && segment.ProviderID == "" {
			segment.ProviderID = onebotInboundAtTarget(item.Data)
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
	previous := r.emitter
	r.emitter, r.emitterConn = e, conn
	r.mu.Unlock()
	if previous != nil {
		previous.Close()
	}
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
	r.handlerMu.Lock()
	r.fenced.Store(true)
	r.handlerMu.Unlock()
	r.callbackMu.Unlock()
	r.cancelOnebotMessageRecalls()
	r.stopGlobalOnebotEventDelivery()
	r.mu.Lock()
	cancel, conn, manager, server, listener := r.cancel, r.conn, r.manager, r.server, r.listener
	tokenRef := r.tokenRef
	activeEmitter := r.emitter
	r.mu.Unlock()
	if activeEmitter != nil {
		activeEmitter.Close()
	}
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
	r.waitGlobalOnebotEventDelivery()
	r.callbackWG.Wait()
	r.wg.Wait()
	r.connectionMu.Lock()
	for connection, baseline := range r.connections {
		current := connection.DroppedEventCount()
		r.transportDropMu.Lock()
		if current > baseline {
			r.transportDropped.Add(current - baseline)
		}
		r.transportDropMu.Unlock()
		delete(r.connections, connection)
	}
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
	r.emitterConn = nil
	r.outbound = nil
	r.tokenRef = nil
	r.mu.Unlock()
}
