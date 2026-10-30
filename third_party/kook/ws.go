package kook

import (
	"bytes"
	"compress/zlib"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// ErrWSAlreadyOpen is the error when connecting with connected websocket.
var ErrWSAlreadyOpen = errors.New("websocket is already opened")

// errSessionClosed 表示用户主动关闭了会话，自动重连不应把它重新拉起来。
var errSessionClosed = errors.New("websocket session is closed")

// Open starts a websocket connection. It does not block the function.
func (s *Session) Open() (err error) {
	return s.open(true)
}

// open 建立连接。resetClosed 为 true 表示这是用户主动 Open，允许清除关闭标记；
// 自动重连使用 false，避免在用户关闭会话后复活连接。
func (s *Session) open(resetClosed bool) (err error) {
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
	s.Unlock()

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
		if s.wsConn == nil {
			s.gateway = ""
		}
		s.Unlock()
		return
	}
	wsConn.SetCloseHandler(func(code int, text string) error {
		return nil
	})

	// 握手阶段必须有超时，否则半开连接会让 Open 永久阻塞。
	_ = wsConn.SetReadDeadline(time.Now().Add(15 * time.Second))
	mt, m, err := wsConn.ReadMessage()
	if err != nil {
		addCaller(s.Logger.Error()).Err("err", err).Msg("error reading message from websocket")
		_ = wsConn.Close()
		s.Lock()
		if s.wsConn == nil {
			s.gateway = ""
		}
		s.Unlock()
		return
	}
	e, err := s.onEvent(mt, m)
	if err != nil {
		addCaller(s.Logger.Error()).Err("err", err).Msg("error parsing event")
		_ = wsConn.Close()
		s.Lock()
		if s.wsConn == nil {
			s.gateway = ""
		}
		s.Unlock()
		return
	}
	if e.Signal != EventSignalHello {
		_ = wsConn.Close()
		s.Lock()
		s.gateway = ""
		s.Unlock()
		err = fmt.Errorf("expecting signal hello, got singal %d", e.Signal)
		return err
	}
	addCaller(s.Logger.Info()).Msg("signal hello received")

	var h EventDataHello
	if err = json.Unmarshal(e.Data, &h); err != nil {
		addCaller(s.Logger.Error()).Err("err", err).Msg("error unmarshalling hello")
		_ = wsConn.Close()
		s.Lock()
		s.gateway = ""
		s.Unlock()
		err = fmt.Errorf("error unmarshalling hello, %s", err.Error())
		return
	}
	if h.Code != EventStatusOk {
		_ = wsConn.Close()
		s.Lock()
		s.gateway = ""
		s.Unlock()
		addCaller(s.Logger.Error()).Int("code", int(h.Code)).Msg("error status is not ok")
		err = fmt.Errorf("expecting status ok, received %d", h.Code)
		return
	}
	_ = wsConn.SetReadDeadline(time.Time{})

	listening := make(chan interface{})

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
	s.LastHeartbeatAck = time.Now().UTC()
	s.Unlock()

	go s.heartbeat(wsConn, listening)
	go s.listen(wsConn, listening)

	addCaller(s.Logger.Info()).Msg("exiting")
	return
}

func (s *Session) onEvent(messageType int, message []byte) (e *Event, err error) {
	var reader io.Reader
	reader = bytes.NewBuffer(message)

	if messageType == websocket.BinaryMessage {
		z, err2 := zlib.NewReader(reader)
		if err2 != nil {
			addCaller(s.Logger.Error()).Err("err", err).Msg("error decompressing websocket message")
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

	addCaller(s.Logger.Debug()).Int("signal", int(e.Signal)).Int64("seq", e.SequenceNumber).Bytes("data", e.Data).Msg("received event")

	if e.Signal == EventSignalHello {
		return
	}

	if e.Signal == EventSignalPong {
		s.Lock()
		s.LastHeartbeatAck = time.Now().UTC()
		s.Unlock()
		addCaller(s.Logger.Debug()).Msg("got heartbeat ACK")
		return
	}

	if e.Signal == EventSignalReconnect {
		addCaller(s.Logger.Info()).Msg("closing current ws and reconnecting in response to Reconnect signal")
		_ = s.closeConn(websocket.CloseServiceRestart)
		s.Lock()
		s.gateway = ""
		atomic.StoreInt64(s.sequence, 0)
		s.snStore.Clear()
		s.Unlock()
		s.reconnect()
		return
	}

	if e.Signal == EventSignalResumeAck {
		addCaller(s.Logger.Info()).Msg("all missing message are sent, received Resume Ack signal")
		return
	}

	if e.Signal != EventSignalEvent {
		addCaller(s.Logger.Error()).Int("signal", int(e.Signal)).Int64("seq", e.SequenceNumber).Bytes("data", e.Data).Msg("unknown signal")
		return
	}

	atomic.AddInt64(s.sequence, 1)
	var exist bool
	func() {
		s.snStore.Lock()
		defer s.snStore.Unlock()
		exist = s.snStore.TestAndInsert(e.SequenceNumber)
	}()
	if exist && e.SequenceNumber != 0 {
		return nil, nil
	}
	data := EventData{}

	if err = json.Unmarshal(e.Data, &data); err != nil {
		addCaller(s.Logger.Error()).Int("signal", int(e.Signal)).Int64("seq", e.SequenceNumber).Bytes("data", e.Data).Err("err", err).Msg("unmarshal event data error")
		return
	}
	if data.Type == MessageTypeSystem {
		if data.ChannelType == "WEBHOOK_CHALLENGE" {
			return e, errWebhookVerify
		}
		sys := EventDataSystem{}
		if err = json.Unmarshal(data.Extra, &sys); err != nil {
			addCaller(s.Logger.Error()).Int("signal", int(e.Signal)).Int64("seq", e.SequenceNumber).Bytes("data", e.Data).Err("err", err).Msg("unmarshal system event extra.body error")
			return
		}
		if eh, ok := registeredEventHandler[sys.Type]; ok {
			t := eh.New()
			ex := t.GetExtra()
			if err = json.Unmarshal(sys.Body, ex); err != nil {
				addCaller(s.Logger.Error()).Int("signal", int(e.Signal)).Int64("seq", e.SequenceNumber).Bytes("data", e.Data).Err("err", err).Msg("unmarshal extra error")
			}
			s.handleEvent(eh.Type(), data.EventDataGeneral, t)
		} else {
			addCaller(s.Logger.Warn()).Int("signal", int(e.Signal)).Int64("seq", e.SequenceNumber).Bytes("data", e.Data).Msg("unknown system message event")
		}
	} else {
		if eh, ok := registeredEventHandler[strconv.Itoa(int(data.Type))]; ok {
			t := eh.New()
			ex := t.GetExtra()
			if err = json.Unmarshal(data.Extra, ex); err != nil {
				addCaller(s.Logger.Error()).Int("signal", int(e.Signal)).Int64("seq", e.SequenceNumber).Bytes("data", e.Data).Err("err", err).Msg("unmarshal extra error")
			}
			s.handleEvent(eh.Type(), data.EventDataGeneral, t)
		} else {
			addCaller(s.Logger.Warn()).Int("signal", int(e.Signal)).Int64("seq", e.SequenceNumber).Bytes("data", e.Data).Msg("unknown message event")
		}
	}

	return nil, err
}

func (s *Session) listen(wsConn *websocket.Conn, listening <-chan interface{}) {
	addCaller(s.Logger.Info()).Msg("called")

	for {
		messageType, message, err := wsConn.ReadMessage()
		if err != nil {
			s.RLock()
			sameConnection := s.wsConn == wsConn
			s.RUnlock()

			if sameConnection {
				addCaller(s.Logger.Warn()).Str("gateway_url", s.gateway).Err("err", err).Msg("error reading from gateway")
				_ = s.closeConn(websocket.CloseAbnormalClosure)
				addCaller(s.Logger.Info()).Msg("calling reconnect")
				s.reconnect()
			}
			return
		}
		select {
		case <-listening:
			return
		default:
			s.onEvent(messageType, message)
		}
	}
}

type pingSignal struct {
	Signal         EventSignal `json:"s"`
	SequenceNumber int64       `json:"sn"`
}

func (s *Session) heartbeat(wsConn *websocket.Conn, listening <-chan interface{}) {
	addCaller(s.Logger.Info()).Msg("called")
	if listening == nil || wsConn == nil {
		return
	}
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	for {
		s.RLock()
		last := s.LastHeartbeatAck
		s.RUnlock()
		sequence := atomic.LoadInt64(s.sequence)
		addCaller(s.Logger.Debug()).Int64("seq", sequence).Msg("sending gateway websocket heartbeat")

		s.wsMutex.Lock()
		s.LastHeartbeatSent = time.Now().UTC()
		// 写超时防止底层连接阻塞时一直持有 wsMutex，导致关闭流程卡死。
		_ = wsConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		err := wsConn.WriteJSON(pingSignal{
			Signal:         EventSignalPing,
			SequenceNumber: sequence,
		})
		s.wsMutex.Unlock()
		if err != nil || time.Since(last) > 36*time.Second {
			if err != nil {
				addCaller(s.Logger.Error()).Str("gateway_url", s.gateway).Err("err", err).Msg("error sending heartbeat to gateway")
			} else {
				addCaller(s.Logger.Error()).Dur("latency", time.Since(last)).Msg("ACK not received, reconnect")
			}
			_ = s.closeConn(websocket.CloseAbnormalClosure)
			s.reconnect()
			// reconnect 会建立新连接，旧的 heartbeat 协程必须退出，
			// 否则它会继续向已关闭的连接发心跳并误关新连接。
			return
		}
		select {
		case <-ticker.C:
		case <-listening:
			return
		}
	}
}

func (s *Session) reconnect() {
	s.Lock()
	if s.closed || s.reconnecting {
		s.Unlock()
		return
	}
	s.reconnecting = true
	done := s.closedCh
	s.Unlock()
	defer func() {
		s.Lock()
		s.reconnecting = false
		s.Unlock()
	}()

	var err error
	wait := time.Second
	for {
		if s.isClosed() {
			return
		}
		addCaller(s.Logger.Info()).Msg("trying to reconnect to gateway")
		err = s.open(false)
		if err == nil {
			addCaller(s.Logger.Info()).Msg("successfully reconnected to gateway")
			return
		}
		if err == ErrWSAlreadyOpen {
			addCaller(s.Logger.Info()).Msg("websocket already exists, no need to reconnect")
			return
		}
		if err == errSessionClosed {
			return
		}

		addCaller(s.Logger.Error()).Err("err", err).Msg("error reconnecting to gateway")
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-done:
			timer.Stop()
			return
		}
		wait *= 2
		if wait > 10*time.Minute {
			wait = 10 * time.Minute
		}
	}
}

func (s *Session) isClosed() bool {
	s.RLock()
	defer s.RUnlock()
	return s.closed
}

// closeConn 只关闭当前底层连接，不设置用户关闭标记，供自动重连路径使用。
func (s *Session) closeConn(code int) error {
	s.Lock()
	listening := s.listening
	conn := s.wsConn
	s.listening = nil
	s.wsConn = nil
	s.Unlock()

	if listening != nil {
		close(listening)
	}
	if conn == nil {
		return nil
	}
	s.wsMutex.Lock()
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(code, ""))
	s.wsMutex.Unlock()
	return conn.Close()
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
	s.Unlock()
	return s.closeConn(code)
}
