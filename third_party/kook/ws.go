package kook

import (
	"bytes"
	"compress/zlib"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"runtime/debug"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// ErrWSAlreadyOpen is the error when connecting with connected websocket.
var ErrWSAlreadyOpen = errors.New("websocket is already opened")

// errSessionClosed 表示用户主动关闭了会话，自动重连不应把它重新拉起来。
var errSessionClosed = errors.New("websocket session is closed")

// ErrSessionClosed 暴露给适配器，用于区分“用户已关闭”和可重试的网络错误。
var ErrSessionClosed = errSessionClosed

// errResumeUnavailable 表示当前没有可用于恢复的 session/gateway。
var errResumeUnavailable = errors.New("websocket resume state is unavailable")

// helloStatusError 保留 KOOK HELLO 的状态码，供重连逻辑区分永久失败和网络抖动。
type helloStatusError struct {
	code EventStatusCode
}

func (e *helloStatusError) Error() string {
	return fmt.Sprintf("expecting status ok, received %d", e.code)
}

func permanentAuthStatusCode(code EventStatusCode) bool {
	switch code {
	case EventStatusMissingArgument,
		EventStatusInvalidToken,
		EventStatusTokenAuthFailed,
		EventStatusTokenExpired:
		return true
	default:
		return false
	}
}

func permanentResumeStatusCode(code EventStatusCode) bool {
	if permanentAuthStatusCode(code) {
		return true
	}
	switch code {
	case EventStatusResumeFailed,
		EventStatusSessionExpired,
		EventStatusInvalidSequenceNumber:
		return true
	default:
		return false
	}
}

// eventStatusErrorCode 从 HELLO 或 REST 错误中提取 KOOK 状态码。
// 获取 gateway 失败时错误来自 REST 层，KOOK 使用同一组 401xx 码；
// 这里同时兼容 *RestError 和值类型 RestError。
func eventStatusErrorCode(err error) (EventStatusCode, bool) {
	var helloErr *helloStatusError
	if errors.As(err, &helloErr) {
		return helloErr.code, true
	}
	var restErr *RestError
	if errors.As(err, &restErr) {
		return EventStatusCode(restErr.Code), true
	}
	var restValue RestError
	if errors.As(err, &restValue) {
		return EventStatusCode(restValue.Code), true
	}
	return 0, false
}

func isPermanentResumeError(err error) bool {
	code, ok := eventStatusErrorCode(err)
	return ok && permanentResumeStatusCode(code)
}

// isPermanentAuthError 只把明确的凭据/握手错误视为不可恢复；
// 网络抖动、网关 5xx 等仍交给指数退避处理。
func isPermanentAuthError(err error) bool {
	code, ok := eventStatusErrorCode(err)
	return ok && permanentAuthStatusCode(code)
}

// ResumeState 是进程重启后恢复 KOOK 连接所需的最小状态。
type ResumeState struct {
	Gateway   string `json:"gateway"`
	SessionID string `json:"session_id"`
	SN        int64  `json:"sn"`
}

// ResumeState 返回当前可持久化的 resume 快照。
func (s *Session) ResumeState() ResumeState {
	s.RLock()
	defer s.RUnlock()
	var sn int64
	if s.sequence != nil {
		sn = atomic.LoadInt64(s.sequence)
	}
	return ResumeState{
		Gateway:   s.gateway,
		SessionID: s.sessionID,
		SN:        sn,
	}
}

// RestoreResumeState 在建立新连接前恢复 session_id/gateway/sn。
// Gateway 允许为空：调用方可能出于安全考虑不持久化带 token 的网关地址，
// 此时 Open 会通过 REST 重新获取 gateway 后再附加 resume 参数。
// 已有活动连接时拒绝覆盖，避免把在线会话改成旧状态。
func (s *Session) RestoreResumeState(state ResumeState) bool {
	if state.SessionID == "" {
		return false
	}
	s.Lock()
	defer s.Unlock()
	if s.wsConn != nil {
		return false
	}
	s.gateway = state.Gateway
	s.sessionID = state.SessionID
	if s.sequence == nil {
		s.sequence = new(int64)
	}
	sn := state.SN
	if sn < 0 {
		sn = 0
	}
	atomic.StoreInt64(s.sequence, sn)
	return true
}

// IsPermanentAuthError 判断错误是否属于凭据/握手类的永久失败。
// 适配器可据此决定是禁用端点还是保留会话继续重连。
func IsPermanentAuthError(err error) bool {
	return isPermanentAuthError(err)
}

// ReconnectAsync 在 Open 遇到瞬时错误后启动后台重连。
// 会话仍保留 session_id/gateway/sn，因此会优先 resume。
func (s *Session) ReconnectAsync() {
	if s == nil || s.isClosed() {
		return
	}
	go s.reconnect()
}

// IsClosed 返回用户是否已经主动关闭会话。
func (s *Session) IsClosed() bool {
	return s.isClosed()
}

// IsOpen 返回当前是否持有一个活动 WebSocket 连接。
func (s *Session) IsOpen() bool {
	s.RLock()
	defer s.RUnlock()
	return s.wsConn != nil
}

// SetFatalHandler 设置不可恢复错误回调。必须在下一次 Open 前调用。
func (s *Session) SetFatalHandler(h func(error)) {
	s.Lock()
	s.FatalHandler = h
	s.Unlock()
}

func (s *Session) reportFatal(err error) {
	s.RLock()
	h := s.FatalHandler
	s.RUnlock()
	if h != nil {
		h(err)
	}
}

// SetReconnectHandler 设置后台重连成功回调。必须在下一次 Open 前调用。
func (s *Session) SetReconnectHandler(h func()) {
	s.Lock()
	s.ReconnectHandler = h
	s.Unlock()
}

func (s *Session) reportReconnected() {
	s.RLock()
	h := s.ReconnectHandler
	s.RUnlock()
	if h == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			addCaller(s.Logger.Error()).Interface("panic", r).Msg("reconnect handler panicked")
		}
	}()
	h()
}

const (
	// reconnectMaxBackoff 是网关重连退避上限，KOOK 文档建议最大 60 秒。
	reconnectMaxBackoff = 60 * time.Second
	// heartbeatWriteTTL 防止底层连接阻塞时一直持有 wsMutex。
	heartbeatWriteTTL = 10 * time.Second
	// forcedResyncCooldown 限制强制重同步的频率，避免 handler 卡死时反复断线。
	forcedResyncCooldown = 10 * time.Second
)

// 心跳时序保持为 var 以便测试缩短；生产默认值来自 KOOK 文档。
// 测试会修改这些值，读写都必须经过 heartbeatTimingMu，
// 否则旧连接的 heartbeat goroutine 会与下一个测试形成数据竞争。
var (
	heartbeatTimingMu         sync.RWMutex
	heartbeatAckTimeout       = 6 * time.Second
	heartbeatRetryFirstDelay  = 2 * time.Second
	heartbeatRetrySecondDelay = 4 * time.Second
)

func getHeartbeatTiming() (ack, first, second time.Duration) {
	heartbeatTimingMu.RLock()
	defer heartbeatTimingMu.RUnlock()
	return heartbeatAckTimeout, heartbeatRetryFirstDelay, heartbeatRetrySecondDelay
}

func setHeartbeatTiming(ack, first, second time.Duration) {
	heartbeatTimingMu.Lock()
	heartbeatAckTimeout = ack
	heartbeatRetryFirstDelay = first
	heartbeatRetrySecondDelay = second
	heartbeatTimingMu.Unlock()
}

// gapResyncTimeout 是 sn 空洞等待补发的上限；超时后强制 resume/reconnect。
// 保持为 var 以便测试缩短，生产默认 15 秒。
var gapResyncTimeout = 15 * time.Second

// resumeRetryDelays 是 resume 失败后的重试间隔。文档要求前两次为 8/16 秒；
// 之后对纯网络故障使用更长的退避继续保留 session_id/sn，
// 等网络恢复后仍能 resume 补发离线事件，而不是过早转全新 session。
var resumeRetryDelays = []time.Duration{
	8 * time.Second,
	16 * time.Second,
	30 * time.Second,
	60 * time.Second,
}

// maxAmbiguousResumeAttempts 是“未收到明确永久错误”（拨号失败、握手后立即断开等）
// 时的 resume 重试上限，超过后认为会话已不可恢复，转全新 session。
// 服务端明确拒绝 resume（40106/40107/40108 等）不消耗该预算，立即转新 session。
// 默认间隔下总时长约 6 分钟，与 KOOK 会话在服务端的存活时间同数量级。
const maxAmbiguousResumeAttempts = 8

// Open starts a websocket connection. It does not block the function.
// 如果当前仍持有可 resume 的 session（例如正处于自动重连退避期），
// 用户主动 Open 会优先 resume，避免直接 resetSessionState 丢掉离线事件。
func (s *Session) Open() (err error) {
	s.RLock()
	// gateway 允许为空：从持久化快照恢复的会话不保存带 token 的旧地址，
	// open 会先通过 REST 重新获取 gateway 再附加 resume 参数。
	canResume := s.sessionID != ""
	s.RUnlock()
	if !canResume {
		return s.open(true, false)
	}

	err = s.open(true, true)
	if err == nil || err == ErrWSAlreadyOpen || err == errSessionClosed {
		return err
	}
	if err == errResumeUnavailable || isPermanentResumeError(err) {
		addCaller(s.Logger.Warn()).Err("err", err).Msg("resume unavailable on Open, starting a new session")
		s.flushResumeState()
		return s.open(true, false)
	}
	// 网络类错误保留 resume 状态，交给调用方/下一次重连继续尝试。
	return err
}

// open 建立连接。resetClosed 为 true 表示这是用户主动 Open，允许清除关闭标记；
// resume 为 true 时在旧 gateway 上追加 resume 参数，保留 sn 和已处理记录。
// 自动重连使用 false，避免在用户关闭会话后复活连接。
func (s *Session) open(resetClosed bool, resume bool) (err error) {
	// 同一时刻只允许一个建连过程；否则两个 Open 会互相执行
	// resetSessionState，把对方刚建立的 sn/session 状态清掉。
	s.openMu.Lock()
	defer s.openMu.Unlock()

	s.Lock()
	if resetClosed && s.closed {
		s.closed = false
		s.closedCh = make(chan struct{})
	}
	if s.closed {
		s.Unlock()
		return errSessionClosed
	}
	if s.wsConn != nil {
		s.Unlock()
		addCaller(s.Logger.Error()).Msg("websocket is already open")
		return ErrWSAlreadyOpen
	}
	gateway := s.gateway
	sessionID := s.sessionID
	sn := atomic.LoadInt64(s.sequence)
	if resume && sessionID == "" {
		s.Unlock()
		return errResumeUnavailable
	}
	s.Unlock()

	if !resume {
		// 新 session 不能沿用旧 session 的 sn/去重记录，并让旧 handler 的迟到结果失效。
		s.resetSessionState(false)
	}

	if gateway == "" {
		gateway, err = s.Gateway()
		if err != nil {
			addCaller(s.Logger.Error()).Err("err", err).Msg("unable to get ws gateway")
			return
		}
		s.Lock()
		if s.gateway == "" {
			s.gateway = gateway
		} else {
			gateway = s.gateway
		}
		s.Unlock()
	}

	if resume {
		// 保留 base gateway，只在实际连接 URL 上追加 resume 参数。
		resumeURL, resumeErr := resumeGatewayURL(gateway, sn, sessionID)
		if resumeErr != nil {
			addCaller(s.Logger.Error()).Err("err", resumeErr).Msg("invalid resume gateway, starting a new session")
			return errResumeUnavailable
		}
		gateway = resumeURL
	}

	addCaller(s.Logger.Info()).Str("gateway_url", gateway).Msg("connecting to gateway")
	dialer := *websocket.DefaultDialer
	dialer.HandshakeTimeout = 15 * time.Second
	wsConn, _, err := dialer.Dial(gateway, http.Header{})
	if err != nil {
		addCaller(s.Logger.Error()).
			Str("gateway_url", gateway).
			Err("err", err).
			Msg("error connecting to gateway")
		s.Lock()
		if !resume && s.wsConn == nil {
			s.gateway = ""
		}
		s.Unlock()
		return
	}
	wsConn.SetCloseHandler(func(code int, text string) error {
		return nil
	})

	// KOOK 要求 6 秒内收到 hello，否则视为握手超时。
	_ = wsConn.SetReadDeadline(time.Now().Add(6 * time.Second))
	mt, m, err := wsConn.ReadMessage()
	if err != nil {
		addCaller(s.Logger.Error()).Err("err", err).Msg("error reading message from websocket")
		_ = wsConn.Close()
		s.Lock()
		if !resume && s.wsConn == nil {
			s.gateway = ""
		}
		s.Unlock()
		return
	}
	e, err := s.onEvent(wsConn, mt, m)
	if err != nil {
		addCaller(s.Logger.Error()).Err("err", err).Msg("error parsing event")
		_ = wsConn.Close()
		s.Lock()
		if !resume && s.wsConn == nil {
			s.gateway = ""
		}
		s.Unlock()
		return
	}
	if e == nil {
		_ = wsConn.Close()
		s.Lock()
		if !resume {
			s.gateway = ""
		}
		s.Unlock()
		return fmt.Errorf("expecting signal hello, got empty event")
	}
	if e.Signal != EventSignalHello {
		_ = wsConn.Close()
		s.Lock()
		if !resume {
			s.gateway = ""
		}
		s.Unlock()
		err = fmt.Errorf("expecting signal hello, got singal %d", e.Signal)
		return err
	}

	var h EventDataHello
	if err = json.Unmarshal(e.Data, &h); err != nil {
		addCaller(s.Logger.Error()).Err("err", err).Msg("error unmarshalling hello")
		_ = wsConn.Close()
		s.Lock()
		if !resume {
			s.gateway = ""
		}
		s.Unlock()
		err = fmt.Errorf("error unmarshalling hello, %s", err.Error())
		return
	}
	if h.Code != EventStatusOk {
		_ = wsConn.Close()
		s.Lock()
		if !resume {
			s.gateway = ""
		}
		s.Unlock()
		addCaller(s.Logger.Error()).Int("code", int(h.Code)).Msg("error status is not ok")
		err = &helloStatusError{code: h.Code}
		return
	}
	addCaller(s.Logger.Info()).Msg("signal hello received")
	_ = wsConn.SetReadDeadline(time.Time{})

	listening := make(chan interface{})

	// 服务器可能忽略 resume 参数并直接建立一个全新 session。
	// 新 session 的 sn 从 1 开始；如果继续沿用旧 sequence，所有新事件都会被当成重复丢弃。
	sessionChanged := resume && h.SessionID != "" && sessionID != "" && h.SessionID != sessionID
	if resume && sessionID != "" && h.SessionID == "" {
		// HELLO 成功但缺少 session_id：无法判断服务端是否真的恢复了旧 session。
		// 保守地按新 session 处理并清空 sn，避免新事件被旧 sequence 当重复丢弃。
		addCaller(s.Logger.Warn()).
			Str("old_session_id", sessionID).
			Msg("resume hello is missing session_id, resetting sn state")
		s.resetSessionState(false)
		sessionChanged = true
	} else if sessionChanged {
		addCaller(s.Logger.Warn()).
			Str("old_session_id", sessionID).
			Str("new_session_id", h.SessionID).
			Msg("resume returned a new session, resetting sn state")
		s.resetSessionState(false)
	}
	newSession := !resume || sessionChanged

	// 提交连接状态；期间用户可能已经 Close，或另一个 Open 抢先成功。
	s.Lock()
	if s.closed {
		s.Unlock()
		_ = wsConn.Close()
		return errSessionClosed
	}
	if s.wsConn != nil {
		s.Unlock()
		_ = wsConn.Close()
		return ErrWSAlreadyOpen
	}
	s.wsConn = wsConn
	s.listening = listening
	s.lastConnectAt = time.Now()
	if h.SessionID != "" {
		s.sessionID = h.SessionID
	}
	// 首个 PONG 必须真实到达；不能用建连时间伪装成 ACK。
	s.LastHeartbeatAck = time.Time{}
	dispatcher := s.dispatcher
	var oldDispatcher *eventDispatcher
	startDispatcher := false
	// 新 session 必须换一个新的 dispatcher：旧 dispatcher 可能仍卡在旧 handler 上，
	// 继续复用它会让新会话的事件排在旧 handler 后面，表现为心跳正常但命令不响应。
	if dispatcher == nil || newSession {
		oldDispatcher = dispatcher
		dispatcher = newEventDispatcher()
		s.dispatcher = dispatcher
		startDispatcher = true
	}
	s.Unlock()

	if oldDispatcher != nil {
		oldDispatcher.close()
		// 给旧 handler 一个有限完成窗口，减少旧/新会话命令并发执行；
		// 若 handler 永久阻塞，不能无限等待，否则重连无法完成。
		if !oldDispatcher.waitForExit(2 * time.Second) {
			addCaller(s.Logger.Warn()).Msg("old event handler did not stop within 2s; starting new dispatcher")
		}
	}
	if startDispatcher {
		go s.dispatchEvents(dispatcher)
	}
	go s.heartbeat(wsConn, listening)
	go s.listen(wsConn, listening)

	addCaller(s.Logger.Info()).Msg("exiting")
	return
}

// resumeGatewayURL 在旧 gateway 上追加 KOOK 文档要求的 resume 参数。
// 只用于本次连接，不写回 s.gateway，避免后续重连重复拼接。
// 解析失败必须返回 error：静默连接一个不带 resume 参数的 URL 会被误判成 resume 成功。
func resumeGatewayURL(gateway string, sn int64, sessionID string) (string, error) {
	parsed, err := url.Parse(gateway)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	query.Set("resume", "1")
	query.Set("sn", strconv.FormatInt(sn, 10))
	query.Set("session_id", sessionID)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func (s *Session) onEvent(wsConn *websocket.Conn, messageType int, message []byte) (e *Event, err error) {
	var reader io.Reader
	reader = bytes.NewBuffer(message)

	if messageType == websocket.BinaryMessage {
		z, err2 := zlib.NewReader(reader)
		if err2 != nil {
			addCaller(s.Logger.Error()).Err("err", err2).Msg("error decompressing websocket message")
			return nil, err2
		}
		defer func() {
			err3 := z.Close()
			if err3 != nil {
				addCaller(s.Logger.Warn()).Err("err", err3).Msg("error closing zlib")
			}
		}()

		reader = z
	}

	jsonDecoder := json.NewDecoder(reader)
	if err = jsonDecoder.Decode(&e); err != nil {
		addCaller(s.Logger.Error()).Err("err", err).Msg("error decoding websocket message")
		return
	}
	if e == nil {
		// JSON null decodes into a nil *Event without an error.  Treat it as a
		// malformed frame instead of dereferencing it in the read loop.
		return nil, errors.New("empty websocket event")
	}

	addCaller(s.Logger.Debug()).Int("signal", int(e.Signal)).Int64("seq", e.SequenceNumber).Bytes("data", e.Data).Msg("received event")

	if e.Signal == EventSignalHello {
		return
	}

	if e.Signal == EventSignalPong {
		if wsConn != nil {
			s.RLock()
			current := s.wsConn == wsConn
			s.RUnlock()
			if !current {
				return
			}
		}
		s.Lock()
		s.LastHeartbeatAck = time.Now().UTC()
		s.Unlock()
		addCaller(s.Logger.Debug()).Msg("got heartbeat ACK")
		return
	}

	if e.Signal == EventSignalReconnect {
		addCaller(s.Logger.Info()).Msg("closing current ws and reconnecting in response to Reconnect signal")
		closed := true
		if wsConn != nil {
			closed, _ = s.closeConnIf(wsConn, websocket.CloseServiceRestart)
		} else {
			_ = s.closeConn(websocket.CloseServiceRestart)
		}
		if !closed {
			return
		}
		// s=5 是服务端要求重新建 session，必须清空旧 sn/session/gateway。
		s.resetSessionState(true)
		s.reconnect()
		return
	}

	if e.Signal == EventSignalResumeAck {
		var ack EventDataResumeAck
		if err := json.Unmarshal(e.Data, &ack); err != nil {
			addCaller(s.Logger.Warn()).Err("err", err).Msg("error unmarshalling resume ack")
		} else {
			s.applyResumeAckSessionID(wsConn, ack.SessionID)
		}
		addCaller(s.Logger.Info()).Msg("all missing message are sent, received Resume Ack signal")
		return
	}

	if e.Signal != EventSignalEvent {
		addCaller(s.Logger.Error()).Int("signal", int(e.Signal)).Int64("seq", e.SequenceNumber).Bytes("data", e.Data).Msg("unknown signal")
		return
	}

	epoch := s.sessionEpoch.Load()
	data := EventData{}
	if err = json.Unmarshal(e.Data, &data); err != nil {
		addCaller(s.Logger.Error()).Int("signal", int(e.Signal)).Int64("seq", e.SequenceNumber).Bytes("data", e.Data).Err("err", err).Msg("unmarshal event data error")
		if wsConn == nil {
			s.skipEvent(epoch, e.SequenceNumber, "event data parse failed")
		} else {
			s.queueSkipEvent(wsConn, e, epoch, "event data parse failed")
		}
		return nil, nil
	}
	if data.EventDataGeneral == nil {
		// d 为空对象或 null 时内嵌指针保持 nil；直接访问 data.Type 会 panic。
		addCaller(s.Logger.Error()).Int("signal", int(e.Signal)).Int64("seq", e.SequenceNumber).Bytes("data", e.Data).Msg("event data missing general fields")
		if wsConn == nil {
			s.skipEvent(epoch, e.SequenceNumber, "event data missing general fields")
		} else {
			s.queueSkipEvent(wsConn, e, epoch, "event data missing general fields")
		}
		return nil, nil
	}
	if wsConn == nil && data.Type == MessageTypeSystem && data.ChannelType == "WEBHOOK_CHALLENGE" {
		return e, errWebhookVerify
	}

	if wsConn == nil {
		// Webhook 没有 WebSocket 读循环，保持同步处理。
		s.handleEventNow(e, &data, epoch)
		return nil, nil
	}

	s.RLock()
	current := s.wsConn == wsConn
	dispatcher := s.dispatcher
	s.RUnlock()
	if !current || dispatcher == nil {
		return nil, nil
	}

	q := &queuedEvent{conn: wsConn, epoch: epoch, event: e, data: data}
	if !dispatcher.push(q) {
		addCaller(s.Logger.Error()).Int64("seq", e.SequenceNumber).Msg("event queue is full or closed, forcing resync")
		s.requestResyncThrottled(wsConn, "event queue is full")
	}
	return nil, nil
}

// queueSkipEvent 把一个无法解析的事件放入分发队列。
// 它不执行 handler，只推进 sn；否则该 sn 会永久堵住后续事件。
func (s *Session) queueSkipEvent(wsConn *websocket.Conn, e *Event, epoch uint64, reason string) {
	if e == nil || e.SequenceNumber == 0 {
		return
	}
	s.RLock()
	current := s.wsConn == wsConn
	dispatcher := s.dispatcher
	s.RUnlock()
	if !current || dispatcher == nil {
		return
	}
	q := &queuedEvent{conn: wsConn, epoch: epoch, event: e, skip: true}
	if !dispatcher.push(q) {
		s.requestResyncThrottled(wsConn, reason+": event queue is full")
	}
}

// handleEventNow 用于 webhook 路径，保持同步语义。
func (s *Session) handleEventNow(e *Event, data *EventData, epoch uint64) {
	sn := e.SequenceNumber
	if sn != 0 && !s.beginEvent(epoch, sn) {
		return
	}
	success := s.runEventHandlerChecked(e, data, epoch)
	s.finishEvent(epoch, sn, success)
	if !success {
		s.skipEvent(epoch, sn, "event handler failed")
	}
}

// dispatchEvents 在独立协程按 sn 顺序处理事件，读循环只负责收包和控制信号。
// 整个 Session 只有一个分发协程；重连期间旧 handler 未结束时，新连接事件会排队等待，
// 从根上避免旧/新连接同时执行同一个 sn。
func (s *Session) dispatchEvents(dispatcher *eventDispatcher) {
	defer close(dispatcher.done)
	pending := make(map[int64]*queuedEvent)
	var lastConn *websocket.Conn
	lastGapExpected := int64(-1)
	var gapFilled chan struct{}
	closeGap := func() {
		if gapFilled != nil {
			close(gapFilled)
			gapFilled = nil
		}
	}
	defer closeGap()

	for {
		q, ok := dispatcher.pop()
		if !ok {
			return
		}
		epoch := s.sessionEpoch.Load()
		if q.epoch != epoch {
			pending = make(map[int64]*queuedEvent)
			closeGap()
			lastGapExpected = -1
			continue
		}
		s.RLock()
		currentConn := s.wsConn
		s.RUnlock()
		if currentConn == nil || q.conn != currentConn {
			// 旧连接事件交给 resume 重放，不能在这里执行。
			pending = make(map[int64]*queuedEvent)
			lastConn = currentConn
			lastGapExpected = -1
			closeGap()
			continue
		}
		if currentConn != lastConn {
			// 新连接：旧连接的 pending 项不能参与新连接的 sn 判定，
			// 否则会吞掉新连接重放的同一 sn。
			pending = make(map[int64]*queuedEvent)
			lastConn = currentConn
			lastGapExpected = -1
			closeGap()
		}

		sn := q.event.SequenceNumber
		if sn == 0 {
			s.processQueuedEvent(q, epoch)
			continue
		}

		seq := atomic.LoadInt64(s.sequence)
		if sn <= seq {
			delete(pending, sn)
			if lastGapExpected >= 0 && seq >= lastGapExpected {
				closeGap()
				lastGapExpected = -1
			}
			continue
		}
		if _, exists := pending[sn]; exists {
			continue
		}
		// 缺口事件已经收到：在进入可能很慢的 handler 之前解除超时，
		// 避免“命令耗时 > 15s”被误判为链路丢包而强制重连。
		if lastGapExpected >= 0 && sn == lastGapExpected {
			closeGap()
			lastGapExpected = -1
		}
		// 首个事件允许建立基线；之后只处理连续 sn。
		if seq == 0 || sn == seq+1 {
			s.processQueuedEvent(q, epoch)
			s.drainPending(epoch, pending)
			continue
		}
		if len(pending) >= maxQueuedEvents {
			addCaller(s.Logger.Error()).Int64("seq", sn).Msg("reorder buffer is full, forcing resync")
			closeGap()
			lastGapExpected = -1
			s.requestResyncThrottled(q.conn, "reorder buffer is full")
			continue
		}
		if lastGapExpected != seq+1 {
			// 链路仍正常时先按文档发 s=4 请求补发；超时仍不前进则强制 resync。
			// seq 是最后已处理的事件，缺失的是 seq+1。watcher 必须等待
			// seq+1，使用 seq 会让 sequence < expected 永远为 false。
			closeGap()
			gapFilled = make(chan struct{})
			lastGapExpected = seq + 1
			if err := s.sendResumeSignal(q.conn, seq); err != nil {
				closeGap()
				lastGapExpected = -1
				s.requestResyncThrottled(q.conn, "resume signal write failed")
				continue
			}
			go s.watchGap(q.conn, lastGapExpected, epoch, gapFilled)
		}
		pending[sn] = q
	}
}

func (s *Session) drainPending(epoch uint64, pending map[int64]*queuedEvent) {
	for {
		if s.sessionEpoch.Load() != epoch {
			return
		}
		next := atomic.LoadInt64(s.sequence) + 1
		q, ok := pending[next]
		if !ok {
			return
		}
		s.RLock()
		currentConn := s.wsConn
		s.RUnlock()
		if currentConn == nil || q.conn != currentConn {
			delete(pending, next)
			return
		}
		delete(pending, next)
		s.processQueuedEvent(q, epoch)
	}
}

func (s *Session) processQueuedEvent(q *queuedEvent, epoch uint64) {
	sn := q.event.SequenceNumber
	if q.skip {
		s.skipEvent(epoch, sn, "event data parse failed")
		return
	}
	if sn != 0 && !s.beginEvent(epoch, sn) {
		return
	}
	success := s.runEventHandlerChecked(q.event, &q.data, epoch)
	s.finishEvent(epoch, sn, success)
	if !success {
		s.skipEvent(epoch, sn, "event handler failed")
	}
}

// runEventHandler 在当前 epoch 下执行 handler，供测试和 webhook 同步路径使用。
func (s *Session) runEventHandler(e *Event, data *EventData) (success bool) {
	return s.runEventHandlerChecked(e, data, s.sessionEpoch.Load())
}

// runEventHandlerChecked 在 event 所属 epoch 下执行 handler。
// 获取 handler 锁后必须重新校验 epoch：旧会话的事件可能在等锁期间被新会话替换，
// 此时不能再执行，否则旧命令的副作用会落到新会话上。
func (s *Session) runEventHandlerChecked(e *Event, data *EventData, epoch uint64) (success bool) {
	success = true
	defer func() {
		if r := recover(); r != nil {
			success = false
			addCaller(s.Logger.Error()).Int("signal", int(e.Signal)).Int64("seq", e.SequenceNumber).Interface("panic", r).Bytes("stack", debug.Stack()).Msg("event handler panicked")
		}
	}()

	// 重连/Close 时旧 dispatcher 与新 dispatcher 可能短暂共存。
	// 在 Session（或适配器注入的共享锁）级别串行化 handler，避免两个长命令同时修改骰子状态。
	s.lockHandler()
	defer s.unlockHandler()

	if s.sessionEpoch.Load() != epoch {
		addCaller(s.Logger.Warn()).Int64("seq", e.SequenceNumber).Msg("dropping stale event from a replaced session")
		return false
	}

	if data.Type == MessageTypeSystem {
		sys := EventDataSystem{}
		if err := json.Unmarshal(data.Extra, &sys); err != nil {
			addCaller(s.Logger.Error()).Int("signal", int(e.Signal)).Int64("seq", e.SequenceNumber).Bytes("data", e.Data).Err("err", err).Msg("unmarshal system event extra.body error")
			return false
		}
		if eh, ok := registeredEventHandler[sys.Type]; ok {
			t := eh.New()
			ex := t.GetExtra()
			if err := json.Unmarshal(sys.Body, ex); err != nil {
				addCaller(s.Logger.Error()).Int("signal", int(e.Signal)).Int64("seq", e.SequenceNumber).Bytes("data", e.Data).Err("err", err).Msg("unmarshal extra error")
				return false
			}
			s.handleEvent(eh.Type(), data.EventDataGeneral, t)
		} else {
			addCaller(s.Logger.Warn()).Int("signal", int(e.Signal)).Int64("seq", e.SequenceNumber).Bytes("data", e.Data).Msg("unknown system message event")
		}
		return
	}

	if eh, ok := registeredEventHandler[strconv.Itoa(int(data.Type))]; ok {
		t := eh.New()
		ex := t.GetExtra()
		if err := json.Unmarshal(data.Extra, ex); err != nil {
			addCaller(s.Logger.Error()).Int("signal", int(e.Signal)).Int64("seq", e.SequenceNumber).Bytes("data", e.Data).Err("err", err).Msg("unmarshal extra error")
			return false
		}
		s.handleEvent(eh.Type(), data.EventDataGeneral, t)
	} else {
		addCaller(s.Logger.Warn()).Int("signal", int(e.Signal)).Int64("seq", e.SequenceNumber).Bytes("data", e.Data).Msg("unknown message event")
	}
	return true
}

// SetHandlerLock 注入适配器级的 handler 串行锁。
// 禁用后立即启用会创建新的 Session，Session 内部的 handlerMu 无法覆盖旧 Session；
// 由适配器持有一把跨 Session 的锁，才能真正避免旧/新连接的命令并发修改数据。
// 必须在 Open 前调用。
func (s *Session) SetHandlerLock(mu *sync.Mutex) {
	s.Lock()
	s.externalHandlerMu = mu
	s.Unlock()
}

func (s *Session) lockHandler() {
	s.RLock()
	mu := s.externalHandlerMu
	s.RUnlock()
	if mu != nil {
		mu.Lock()
		return
	}
	s.handlerMu.Lock()
}

func (s *Session) unlockHandler() {
	s.RLock()
	mu := s.externalHandlerMu
	s.RUnlock()
	if mu != nil {
		mu.Unlock()
		return
	}
	s.handlerMu.Unlock()
}

// beginEvent 在 handler 执行前占位，阻止同一 sn 被旧/新连接并发重复处理。
// sequence 和 inFlight 是精确判据；不要用布隆过滤器拒绝事件，
// 否则一次假阳性就会让该 sn 永久无法推进。
func (s *Session) beginEvent(epoch uint64, sn int64) bool {
	s.eventMu.Lock()
	defer s.eventMu.Unlock()
	if s.sessionEpoch.Load() != epoch {
		return false
	}
	if atomic.LoadInt64(s.sequence) >= sn {
		return false
	}
	if _, exists := s.inFlight[sn]; exists {
		return false
	}
	s.inFlight[sn] = struct{}{}
	return true
}

// finishEvent 只在 handler 完成后记录 sn；解析失败的事件不会推进 sequence。
func (s *Session) finishEvent(epoch uint64, sn int64, success bool) {
	if sn == 0 {
		return
	}
	advanced := false
	s.eventMu.Lock()
	if s.sessionEpoch.Load() != epoch {
		// 旧会话的 handler 不能删除新会话的 inFlight 标记。
		s.eventMu.Unlock()
		return
	}
	delete(s.inFlight, sn)
	if success && sn > atomic.LoadInt64(s.sequence) {
		atomic.StoreInt64(s.sequence, sn)
		advanced = true
	}
	s.eventMu.Unlock()
	if advanced {
		// 每处理完一个 sn 就把 resume 快照落盘，避免进程退出后从旧快照
		// 重放已执行过的事件。
		s.notifySnPersist()
	}
}

// skipEvent 用于无法解析或 handler 失败的事件：记录日志并推进 sn，
// 避免一个坏包把整个 session 永久堵在同一个 sn 上。
func (s *Session) skipEvent(epoch uint64, sn int64, reason string) {
	if sn == 0 {
		return
	}
	advanced := false
	s.eventMu.Lock()
	if s.sessionEpoch.Load() != epoch {
		s.eventMu.Unlock()
		return
	}
	delete(s.inFlight, sn)
	if atomic.LoadInt64(s.sequence) < sn {
		atomic.StoreInt64(s.sequence, sn)
		advanced = true
	}
	s.eventMu.Unlock()
	if !advanced {
		return
	}
	addCaller(s.Logger.Warn()).Int64("seq", sn).Str("reason", reason).Msg("skipping event to keep sn stream moving")
	s.notifySnPersist()
}

// SetSnPersistHandler 设置 sn 前进后的持久化回调。必须在下一次 Open 前设置。
func (s *Session) SetSnPersistHandler(handler func()) {
	s.snPersistMu.Lock()
	s.snPersist = handler
	s.snPersistMu.Unlock()
}

func (s *Session) notifySnPersist() {
	s.snPersistMu.RLock()
	handler := s.snPersist
	s.snPersistMu.RUnlock()
	if handler != nil {
		handler()
	}
}

// requestResync 关闭指定连接并触发 resume；用于队列溢出等无法在本地恢复的情况。
func (s *Session) requestResync(conn *websocket.Conn, reason string) {
	if conn == nil {
		return
	}
	addCaller(s.Logger.Warn()).Str("reason", reason).Msg("forcing gateway resync")
	if closed, _ := s.closeConnIf(conn, websocket.CloseTryAgainLater); closed {
		go s.reconnectAfterDisconnect()
	}
}

// requestResyncThrottled 用于队列满/重排满：连续触发通常意味着 handler 长时间阻塞，
// 节流避免形成 5 秒一次的连接风暴。gap 超时不走节流，保证真正丢包时能恢复。
func (s *Session) requestResyncThrottled(conn *websocket.Conn, reason string) {
	if conn == nil {
		return
	}
	s.resyncMu.Lock()
	if !s.lastForcedResync.IsZero() && time.Since(s.lastForcedResync) < forcedResyncCooldown {
		s.resyncMu.Unlock()
		addCaller(s.Logger.Warn()).Str("reason", reason).Msg("forced resync suppressed by cooldown")
		return
	}
	s.lastForcedResync = time.Now()
	s.resyncMu.Unlock()
	s.requestResync(conn, reason)
}

// resetSessionState 丢弃旧 session 的 resume/sn/事件状态。
// clearGateway 为 true 时会强制下次重新获取 gateway。
func (s *Session) resetSessionState(clearGateway bool) {
	s.Lock()
	if clearGateway {
		s.gateway = ""
	}
	s.sessionID = ""
	atomic.StoreInt64(s.sequence, 0)
	resetEpoch := s.sessionEpoch.Add(1)
	s.Unlock()

	s.eventMu.Lock()
	// 另一个 Open/Close 可能已经进入下一次状态重置；不要清掉它的 inFlight。
	if s.sessionEpoch.Load() == resetEpoch {
		s.inFlight = make(map[int64]struct{})
	}
	s.eventMu.Unlock()
}

func (s *Session) listen(wsConn *websocket.Conn, listening <-chan interface{}) {
	addCaller(s.Logger.Info()).Msg("called")
	defer func() {
		if r := recover(); r != nil {
			// 最后一道保险：任何未预期的解析/状态错误只断当前连接，不能让整个进程退出。
			addCaller(s.Logger.Error()).Interface("panic", r).Bytes("stack", debug.Stack()).Msg("gateway read loop panicked")
			if closed, _ := s.closeConnIf(wsConn, websocket.CloseGoingAway); closed {
				s.reconnectAfterDisconnect()
			}
		}
	}()

	for {
		messageType, message, err := wsConn.ReadMessage()
		if err != nil {
			s.RLock()
			sameConnection := s.wsConn == wsConn
			s.RUnlock()

			if sameConnection {
				addCaller(s.Logger.Warn()).Str("gateway_url", s.gatewayURL()).Err("err", err).Msg("error reading from gateway")
				if closed, _ := s.closeConnIf(wsConn, websocket.CloseGoingAway); closed {
					addCaller(s.Logger.Info()).Msg("calling reconnect")
					s.reconnectAfterDisconnect()
				}
			}
			return
		}
		select {
		case <-listening:
			return
		default:
		}
		if _, err := s.onEvent(wsConn, messageType, message); err != nil {
			if errors.Is(err, errWebhookVerify) {
				// WS 上不应出现 webhook challenge；忽略即可，不能影响后续 sn。
				continue
			}
			addCaller(s.Logger.Error()).Err("err", err).Msg("error handling gateway event")
			// 外层 JSON 解析失败时仍尽量提取 sn，避免一个坏帧卡住整个事件流。
			if sn, ok := extractEventSequence(messageType, message); ok {
				s.queueSkipEvent(wsConn, &Event{Signal: EventSignalEvent, SequenceNumber: sn}, s.sessionEpoch.Load(), "malformed event frame skipped")
				continue
			}
			if closed, _ := s.closeConnIf(wsConn, websocket.CloseGoingAway); closed {
				s.reconnectAfterDisconnect()
			}
			return
		}
	}
}

// extractEventSequence 从无法完整解析的帧里尽量提取事件 sn。
// 只接受 s=0（事件）的帧，控制信令的 sn 不能推进事件序列。
func extractEventSequence(messageType int, message []byte) (int64, bool) {
	var reader io.Reader = bytes.NewBuffer(message)
	if messageType == websocket.BinaryMessage {
		z, err := zlib.NewReader(reader)
		if err != nil {
			return 0, false
		}
		defer func() { _ = z.Close() }()
		reader = z
	}
	var probe struct {
		Signal interface{} `json:"s"`
		Sn     interface{} `json:"sn"`
	}
	if err := json.NewDecoder(reader).Decode(&probe); err != nil {
		return 0, false
	}
	if probe.Signal != nil {
		signal, ok := probe.Signal.(float64)
		if !ok || signal != 0 {
			return 0, false
		}
	}
	switch sn := probe.Sn.(type) {
	case float64:
		if sn <= 0 || sn != float64(int64(sn)) {
			return 0, false
		}
		return int64(sn), true
	case string:
		value, err := strconv.ParseInt(sn, 10, 64)
		if err == nil && value > 0 {
			return value, true
		}
	}
	return 0, false
}

type pingSignal struct {
	Signal         EventSignal `json:"s"`
	SequenceNumber int64       `json:"sn"`
}

type resumeSignal struct {
	Signal         EventSignal `json:"s"`
	SequenceNumber int64       `json:"sn"`
}

// sendResumeSignal 在链路仍正常但 sn 出现空洞时，按文档发送 s=4 请求补发。
// 调用方必须处理返回错误并触发 resync，否则会留下无法恢复的 pending 空洞。
func (s *Session) sendResumeSignal(wsConn *websocket.Conn, sn int64) error {
	if wsConn == nil || wsConn.UnderlyingConn() == nil {
		// 测试/构造的 Session 可能没有底层 net.Conn；没有可写的链路时
		// 不需要触发重连，watcher 也会因为 UnderlyingConn 为空而直接退出。
		return nil
	}
	if !s.connectionCurrent(wsConn) {
		return errors.New("resume signal connection is unavailable")
	}
	s.wsMutex.Lock()
	_ = wsConn.SetWriteDeadline(time.Now().Add(heartbeatWriteTTL))
	err := wsConn.WriteJSON(resumeSignal{
		Signal:         EventSignalResume,
		SequenceNumber: sn,
	})
	s.wsMutex.Unlock()
	if err != nil {
		addCaller(s.Logger.Error()).Err("err", err).Int64("seq", sn).Msg("error sending resume signal")
		return err
	}
	addCaller(s.Logger.Info()).Int64("seq", sn).Msg("sent resume signal to fill sn gap")
	return nil
}

// watchGap 在 sn 空洞持续存在时强制一次 resync，避免丢包导致永久等待。
// filled 在缺口事件到达时关闭，避免慢 handler 被误判为链路故障。
func (s *Session) watchGap(wsConn *websocket.Conn, expected int64, epoch uint64, filled <-chan struct{}) {
	if wsConn == nil || wsConn.UnderlyingConn() == nil {
		return
	}
	s.RLock()
	done := s.closedCh
	s.RUnlock()
	timer := time.NewTimer(gapResyncTimeout)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-done:
		return
	case <-filled:
		return
	}
	if s.sessionEpoch.Load() != epoch || !s.connectionCurrent(wsConn) {
		return
	}
	if atomic.LoadInt64(s.sequence) < expected {
		addCaller(s.Logger.Error()).Int64("expected", expected).Int64("seq", atomic.LoadInt64(s.sequence)).Msg("sn gap timeout, forcing resync")
		s.requestResync(wsConn, "sn gap timeout")
	}
}

func (s *Session) heartbeat(wsConn *websocket.Conn, listening <-chan interface{}) {
	addCaller(s.Logger.Info()).Msg("called")
	if listening == nil || wsConn == nil {
		return
	}
	ackTimeout, _, _ := getHeartbeatTiming()
	for {
		sequence := atomic.LoadInt64(s.sequence)
		sentAt, err := s.sendHeartbeat(wsConn, sequence)
		if err != nil {
			addCaller(s.Logger.Error()).Str("gateway_url", s.gatewayURL()).Err("err", err).Msg("error sending heartbeat to gateway")
			if closed, _ := s.closeConnIf(wsConn, websocket.CloseGoingAway); closed {
				s.reconnectAfterDisconnect()
			}
			return
		}
		// KOOK 要求 6 秒内收到 pong；读循环现在不再执行 handler，PONG 不会被慢命令堵住。
		if !s.waitForHeartbeatAck(sentAt, ackTimeout, listening) {
			if s.isClosed() {
				return
			}
			if !s.connectionCurrent(wsConn) {
				return
			}
			addCaller(s.Logger.Warn()).Dur("latency", time.Since(sentAt)).Msg("ACK not received, retrying heartbeat")
			// 文档要求 PONG 超时后先补两次 PING（间隔 2、4 秒），再进入 resume。
			if !s.retryHeartbeat(wsConn, listening, sentAt) {
				if s.isClosed() {
					return
				}
				if !s.connectionCurrent(wsConn) {
					return
				}
				addCaller(s.Logger.Error()).Dur("latency", time.Since(sentAt)).Msg("ACK not received after retries, reconnect")
				if closed, _ := s.closeConnIf(wsConn, websocket.CloseGoingAway); closed {
					s.reconnectAfterDisconnect()
				}
				// reconnect 会建立新连接，旧的 heartbeat 协程必须退出，
				// 否则它会继续向已关闭的连接发心跳并误关新连接。
				return
			}
			// 补发 PING 成功后，从当前时间重新计算下一次正常心跳。
			sentAt = time.Now().UTC()
		}

		// 下一次心跳保持在 30s ± 5s，而不是固定 30s。
		interval := heartbeatInterval
		if heartbeatJitter > 0 {
			interval += time.Duration(rand.Int63n(int64(2*heartbeatJitter)+1)) - heartbeatJitter
		}
		nextAt := sentAt.Add(interval)
		timer := time.NewTimer(time.Until(nextAt))
		select {
		case <-timer.C:
		case <-listening:
			timer.Stop()
			return
		}
	}
}

// sendHeartbeat 发送一次 PING，并返回发送时间。
func (s *Session) sendHeartbeat(wsConn *websocket.Conn, sequence int64) (time.Time, error) {
	sentAt := time.Now().UTC()
	s.wsMutex.Lock()
	s.LastHeartbeatSent = sentAt
	// 写超时防止底层连接阻塞时一直持有 wsMutex，导致关闭流程卡死。
	_ = wsConn.SetWriteDeadline(time.Now().Add(heartbeatWriteTTL))
	err := wsConn.WriteJSON(pingSignal{
		Signal:         EventSignalPing,
		SequenceNumber: sequence,
	})
	s.wsMutex.Unlock()
	return sentAt, err
}

// retryHeartbeat 按 KOOK 文档在 PONG 超时后补发两次 PING（间隔 2 秒、4 秒）。
// 两次补发之间只用精确计时器等待，不能再等满一个 6 秒 ACK 超时；
// 第二包发出后仍按 6 秒等待 PONG，失败才进入 resume/reconnect。
func (s *Session) retryHeartbeat(wsConn *websocket.Conn, listening <-chan interface{}, lastSentAt time.Time) bool {
	ackTimeout, firstDelay, secondDelay := getHeartbeatTiming()
	if s.isClosed() || !s.connectionCurrent(wsConn) {
		return false
	}
	// 文档：6 秒超时后先等 2 秒补发第一包。
	if !s.waitListening(firstDelay, listening) {
		return false
	}
	if s.isClosed() || !s.connectionCurrent(wsConn) {
		return false
	}
	// 这 2 秒内迟到的 PONG 仍然有效，直接恢复。
	s.RLock()
	ack := s.LastHeartbeatAck
	s.RUnlock()
	if !ack.Before(lastSentAt) {
		return true
	}
	addCaller(s.Logger.Info()).Dur("delay", firstDelay).Msg("sending retry heartbeat")
	sentAt, err := s.sendHeartbeat(wsConn, atomic.LoadInt64(s.sequence))
	if err != nil {
		addCaller(s.Logger.Error()).Str("gateway_url", s.gatewayURL()).Err("err", err).Msg("error sending retry heartbeat")
		return false
	}
	// 文档：两次补发 ping 的间隔为 2、4 秒。第一个补发包之后只等 4 秒。
	if !s.waitListening(secondDelay, listening) {
		return false
	}
	if s.isClosed() || !s.connectionCurrent(wsConn) {
		return false
	}
	s.RLock()
	ack = s.LastHeartbeatAck
	s.RUnlock()
	if !ack.Before(sentAt) {
		return true
	}
	addCaller(s.Logger.Info()).Dur("delay", secondDelay).Msg("sending second retry heartbeat")
	sentAt, err = s.sendHeartbeat(wsConn, atomic.LoadInt64(s.sequence))
	if err != nil {
		addCaller(s.Logger.Error()).Str("gateway_url", s.gatewayURL()).Err("err", err).Msg("error sending second retry heartbeat")
		return false
	}
	// 最后一包仍按文档的 6 秒 ACK 超时判断连接是否恢复。
	return s.waitForHeartbeatAck(sentAt, ackTimeout, listening)
}

func (s *Session) connectionCurrent(wsConn *websocket.Conn) bool {
	s.RLock()
	defer s.RUnlock()
	return s.wsConn == wsConn
}

// applyResumeAckSessionID 应用 s=6 RESUME ACK 携带的 session_id。
// 只在当前连接上生效，避免旧连接的迟到 ACK 覆盖新会话。
func (s *Session) applyResumeAckSessionID(wsConn *websocket.Conn, sessionID string) {
	if wsConn == nil || sessionID == "" {
		return
	}
	s.Lock()
	defer s.Unlock()
	if s.wsConn != wsConn {
		return
	}
	if s.sessionID != "" && s.sessionID != sessionID {
		addCaller(s.Logger.Warn()).
			Str("old_session_id", s.sessionID).
			Str("new_session_id", sessionID).
			Msg("resume ack changed session_id")
	}
	s.sessionID = sessionID
}

func (s *Session) waitListening(d time.Duration, listening <-chan interface{}) bool {
	if listening == nil {
		time.Sleep(d)
		return true
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-listening:
		return false
	}
}

// waitForHeartbeatAck 等待 sentAt 之后到达的 pong；listening 关闭时立即退出。
func (s *Session) waitForHeartbeatAck(sentAt time.Time, timeout time.Duration, listening <-chan interface{}) bool {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		s.RLock()
		ack := s.LastHeartbeatAck
		s.RUnlock()
		if !ack.Before(sentAt) {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		select {
		case <-ticker.C:
		case <-listening:
			return false
		}
	}
}

// reconnectAfterDisconnect 在连接断开后调用。短命连接先补足最小存活时间，
// 避免网关反复“接受握手后立即关闭”时形成无退避的重连风暴。
func (s *Session) reconnectAfterDisconnect() {
	s.RLock()
	startedAt := s.lastConnectAt
	closed := s.closed
	conn := s.wsConn
	done := s.closedCh
	s.RUnlock()
	if closed || conn != nil {
		return
	}
	if !startedAt.IsZero() {
		if elapsed := time.Since(startedAt); elapsed < minStableConnection {
			if !s.waitReconnect(minStableConnection-elapsed, done) {
				return
			}
		}
	}
	s.RLock()
	closed = s.closed
	conn = s.wsConn
	s.RUnlock()
	if closed || conn != nil {
		return
	}
	s.reconnect()
}

func (s *Session) reconnect() {
	s.Lock()
	if s.closed || s.reconnecting {
		s.Unlock()
		return
	}
	s.reconnecting = true
	s.reconnectSeq++
	mySeq := s.reconnectSeq
	done := s.closedCh
	// gateway 允许为空：open 会通过 REST 重新获取，不能因此放弃 resume。
	canResume := s.sessionID != ""
	s.Unlock()
	defer func() {
		s.Lock()
		// 只清理自己这一轮；finishReconnect 可能已经放行下一轮重连。
		if s.reconnectSeq == mySeq {
			s.reconnecting = false
		}
		s.Unlock()
	}()

	// 断线后先尝试 resume，保留未确认的 sn，便于服务端补发离线事件。
	// 网络错误使用文档要求的 8/16 秒退避；只有明确的永久错误才立即转新 session。
	if canResume {
		for attempt := 0; ; attempt++ {
			if s.isClosed() {
				return
			}
			addCaller(s.Logger.Info()).Msg("trying to resume gateway connection")
			err := s.open(false, true)
			if err == nil {
				if s.finishReconnect() {
					addCaller(s.Logger.Info()).Msg("successfully resumed gateway connection")
					s.reportReconnected()
					return
				}
				// 握手成功后立刻断开，继续重试；不要丢掉 resume 状态。
			} else {
				if err == ErrWSAlreadyOpen {
					addCaller(s.Logger.Info()).Msg("websocket already exists, no need to reconnect")
					return
				}
				if err == errSessionClosed {
					return
				}
				if err == errResumeUnavailable || isPermanentResumeError(err) {
					addCaller(s.Logger.Error()).Err("err", err).Msg("resume cannot continue, starting a new session")
					break
				}
				addCaller(s.Logger.Error()).Err("err", err).Msg("error resuming gateway connection, will retry")
			}

			s.RLock()
			stillCanResume := s.sessionID != ""
			s.RUnlock()
			if !stillCanResume {
				break
			}
			if attempt+1 >= maxAmbiguousResumeAttempts {
				addCaller(s.Logger.Error()).Msg("resume retry budget exhausted, starting a new session")
				break
			}
			delay := resumeRetryDelays[len(resumeRetryDelays)-1]
			if attempt < len(resumeRetryDelays) {
				delay = resumeRetryDelays[attempt]
			}
			if !s.waitReconnect(delay, done) {
				return
			}
		}
		// resume 不可用或永久失败：转全新 session，必须清空旧 sn/session。
		s.flushResumeState()
	}

	wait := time.Second
	for {
		if s.isClosed() {
			return
		}
		addCaller(s.Logger.Info()).Msg("trying to reconnect to gateway")
		err := s.open(false, false)
		if err == nil {
			if s.finishReconnect() {
				addCaller(s.Logger.Info()).Msg("successfully reconnected to gateway")
				s.reportReconnected()
				return
			}
			// 握手成功后立刻断开也视为一次失败的重连，必须退避后再试。
			if !s.waitReconnect(wait, done) {
				return
			}
			wait *= 2
			if wait > reconnectMaxBackoff {
				wait = reconnectMaxBackoff
			}
			continue
		}
		if err == ErrWSAlreadyOpen {
			addCaller(s.Logger.Info()).Msg("websocket already exists, no need to reconnect")
			return
		}
		if err == errSessionClosed {
			return
		}
		if isPermanentAuthError(err) {
			// token 失效等错误重试没有意义；通知上层回置为失败态，避免 UI 永远显示在线。
			addCaller(s.Logger.Error()).Err("err", err).Msg("permanent authentication error, stopping reconnect")
			s.reportFatal(err)
			return
		}

		addCaller(s.Logger.Error()).Err("err", err).Msg("error reconnecting to gateway")
		if !s.waitReconnect(wait, done) {
			return
		}
		wait *= 2
		if wait > reconnectMaxBackoff {
			wait = reconnectMaxBackoff
		}
	}
}

// finishReconnect 在启动新连接的 goroutine 之前清除重连标志；
// 若连接已立刻断开则返回 false，让调用方继续重试。
func (s *Session) finishReconnect() bool {
	s.Lock()
	alive := s.wsConn != nil
	if alive {
		s.reconnecting = false
	}
	s.Unlock()
	return alive
}

func (s *Session) waitReconnect(d time.Duration, done <-chan struct{}) bool {
	if done == nil {
		time.Sleep(d)
		return true
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-done:
		return false
	}
}

// flushResumeState 丢弃旧 session 的 resume/sn 状态，准备建立全新连接。
func (s *Session) flushResumeState() {
	s.resetSessionState(true)
}

func (s *Session) isClosed() bool {
	s.RLock()
	defer s.RUnlock()
	return s.closed
}

// gatewayURL 返回当前 gateway 的快照，避免日志读取与 open/flush 写入并发。
func (s *Session) gatewayURL() string {
	s.RLock()
	defer s.RUnlock()
	return s.gateway
}

// closeConn 只关闭当前底层连接，不设置用户关闭标记，供自动重连路径使用。
func (s *Session) closeConn(code int) error {
	_, err := s.closeConnIf(nil, code)
	return err
}

// detachConn 在锁内摘除当前连接，返回被摘除的连接和 listening 通道。
// 之后的新 Open 不受影响；关闭动作在锁外执行，避免阻塞其他状态操作。
func (s *Session) detachConn(expected *websocket.Conn) (*websocket.Conn, chan interface{}, bool) {
	s.Lock()
	if expected != nil && s.wsConn != expected {
		s.Unlock()
		return nil, nil, false
	}
	conn := s.wsConn
	listening := s.listening
	s.listening = nil
	s.wsConn = nil
	s.Unlock()
	return conn, listening, true
}

func (s *Session) closeDetached(conn *websocket.Conn, listening chan interface{}, code int) error {
	if listening != nil {
		close(listening)
	}
	if conn == nil {
		return nil
	}
	// 测试中可能存在没有底层 net.Conn 的零值 websocket.Conn；避免 WriteMessage panic。
	if conn.UnderlyingConn() != nil {
		s.wsMutex.Lock()
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(code, ""))
		s.wsMutex.Unlock()
	}
	return conn.Close()
}

// closeConnIf 只在 expected 仍是当前连接时关闭它，避免旧协程误关重连后的新连接。
func (s *Session) closeConnIf(expected *websocket.Conn, code int) (bool, error) {
	conn, listening, ok := s.detachConn(expected)
	if !ok {
		return false, nil
	}
	return true, s.closeDetached(conn, listening, code)
}

// Close closes a websocket connection.
func (s *Session) Close() error {
	return s.CloseWithCode(websocket.CloseNormalClosure)
}

// CloseWithCode closes a websocket connection with custom websocket closing code.
func (s *Session) CloseWithCode(code int) error {
	s.Lock()
	if !s.closed {
		s.closed = true
		if s.closedCh != nil {
			close(s.closedCh)
		}
	}
	// 让正在执行的 handler 在返回后不要污染下一次 Open 的 sn 状态。
	s.sessionEpoch.Add(1)
	closeEpoch := s.sessionEpoch.Load()
	dispatcher := s.dispatcher
	s.dispatcher = nil
	// 和摘除连接放在同一把锁里：解锁后即使另一个 Open 装上新连接，
	// 这里也只会关闭本次 Close 摘到的旧连接。
	conn := s.wsConn
	listening := s.listening
	s.wsConn = nil
	s.listening = nil
	// 真正建立过 session 时，下次 Open 必须重新获取 gateway；缓存旧 gateway
	// 在长时间禁用后可能已失效。没有 session_id 的测试/异常连接保留 gateway。
	if s.sessionID != "" {
		s.gateway = ""
	}
	s.sessionID = ""
	s.Unlock()
	if dispatcher != nil {
		dispatcher.close()
		// Close/DoRelogin 之后马上 Open 时会新建 dispatcher；如果旧 handler 仍在执行，
		// 新旧会话的命令会并发修改同一份状态。给旧 handler 一个有限的完成窗口，
		// 卡死时不能无限等待，否则禁用/重登会被永久阻塞。
		if !dispatcher.waitForExit(2 * time.Second) {
			addCaller(s.Logger.Warn()).Msg("event handler did not stop within 2s during close")
		}
	}
	s.eventMu.Lock()
	// 如果 Close 解锁后另一个 goroutine 已经 Open 并重置了 epoch，
	// 不要清掉新 session 的 inFlight。
	if s.sessionEpoch.Load() == closeEpoch {
		s.inFlight = make(map[int64]struct{})
	}
	s.eventMu.Unlock()
	return s.closeDetached(conn, listening, code)
}
