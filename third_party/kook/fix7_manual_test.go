package kook

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// TestRequestPreservesRestErrorForNon2xxJSON 锁定非 2xx + JSON 业务码的错误保真：
// KOOK 可能用 401 + {"code":40103} 表示 token 过期，丢掉 RestError 会让
// IsPermanentAuthError 无法识别，端点会一直重连而不是明确失败。
func TestRequestPreservesRestErrorForNon2xxJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":40103,"message":"token expired"}`))
	}))
	defer server.Close()

	s := New("token", nopLogger{})
	s.Client = server.Client()

	_, err := s.Request(http.MethodGet, server.URL, nil)
	if err == nil {
		t.Fatal("Request should fail on HTTP 401")
	}
	var restErr *RestError
	if !errors.As(err, &restErr) {
		t.Fatalf("error type = %T (%v), want *RestError", err, err)
	}
	if restErr.Code != int(EventStatusTokenExpired) {
		t.Fatalf("RestError.Code = %d, want %d", restErr.Code, EventStatusTokenExpired)
	}
}

// TestRequestDoesNotRetryNonIdempotentTransportError 锁定“非幂等请求不重试”：
// 服务端已经处理、响应丢失时重试 POST 会产生重复消息/重复上传。
func TestRequestDoesNotRetryNonIdempotentTransportError(t *testing.T) {
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Errorf("ResponseWriter does not implement Hijacker")
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			return
		}
		_ = conn.Close()
	}))
	defer server.Close()

	s := New("token", nopLogger{})
	s.Client = server.Client()
	s.MaxRetry = 3
	s.RetryTimeout = 2 * time.Second

	if _, err := s.Request(http.MethodPost, server.URL, map[string]string{"content": "hi"}); err == nil {
		t.Fatal("POST with a dropped response should return an error")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("POST attempts = %d, want 1 (must not retry non-idempotent request)", got)
	}
}

// TestRequestDoesNotRetryNonIdempotentRateLimit 锁定 429 时非幂等请求直接返回，
// 不在调用方协程里睡眠重试（否则会堵住唯一的事件分发协程）。
func TestRequestDoesNotRetryNonIdempotentRateLimit(t *testing.T) {
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("X-Rate-Limit-Reset", "0.01")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"code":0}`))
	}))
	defer server.Close()

	s := New("token", nopLogger{})
	s.Client = server.Client()
	s.MaxRetry = 3
	s.RetryTimeout = time.Second

	_, err := s.Request(http.MethodPost, server.URL, map[string]string{"content": "hi"})
	if err == nil || !strings.Contains(err.Error(), "retry after") {
		t.Fatalf("POST 429 error = %v, want a retry-after error", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("POST attempts = %d, want 1", got)
	}
}

func newPreAckTestEvent(conn *websocket.Conn, epoch uint64, sn int64, content string) *queuedEvent {
	return &queuedEvent{
		conn:  conn,
		epoch: epoch,
		event: &Event{Signal: EventSignalEvent, SequenceNumber: sn},
		data: EventData{
			EventDataGeneral: &EventDataGeneral{Type: 251, Content: content},
			Extra:            []byte(`{}`),
		},
	}
}

// TestPreAckEventsDispatchedOnceAfterSessionChange 锁定换 session 时：
// ACK 前的事件一律不执行；ACK 后按 sn 顺序、以新 epoch 各执行一次。
func TestPreAckEventsDispatchedOnceAfterSessionChange(t *testing.T) {
	s, conn, h := newDispatchTestSession(t)
	s.sessionID = "sess-1"
	atomic.StoreInt64(s.sequence, 5)

	s.Lock()
	s.resumePending = true
	for sn := int64(1); sn <= 7; sn++ {
		s.preAck = append(s.preAck, newPreAckTestEvent(conn, s.sessionEpoch.Load(), sn, fmt.Sprintf("new-%d", sn)))
	}
	s.Unlock()

	// ACK 之前不得执行任何 preAck 事件。
	select {
	case got := <-h.events:
		t.Fatalf("pre-ack event executed before RESUME ACK: %q", got)
	case <-time.After(100 * time.Millisecond):
	}

	s.applyResumeAckSessionID(conn, "sess-2")

	for sn := int64(1); sn <= 7; sn++ {
		want := fmt.Sprintf("new-%d", sn)
		select {
		case got := <-h.events:
			if got != want {
				t.Fatalf("event order = %q, want %q", got, want)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("timed out waiting for %q; sequence=%d", want, atomic.LoadInt64(s.sequence))
		}
	}
	select {
	case got := <-h.events:
		t.Fatalf("pre-ack event executed twice: %q", got)
	case <-time.After(100 * time.Millisecond):
	}
	if got := atomic.LoadInt64(s.sequence); got != 7 {
		t.Fatalf("sequence = %d, want 7", got)
	}
}

// TestResumeAckSameSessionDropsDuplicatePreAck 锁定同 session 的 ACK：
// sn<=已处理高水位的是重复补发，丢掉；sn>高水位的是 resume 期间的新事件，按序补投。
func TestResumeAckSameSessionDropsDuplicatePreAck(t *testing.T) {
	s, conn, h := newDispatchTestSession(t)
	s.sessionID = "sess-1"
	atomic.StoreInt64(s.sequence, 5)

	s.Lock()
	s.resumePending = true
	for sn := int64(4); sn <= 7; sn++ {
		s.preAck = append(s.preAck, newPreAckTestEvent(conn, s.sessionEpoch.Load(), sn, fmt.Sprintf("ev-%d", sn)))
	}
	s.Unlock()

	s.applyResumeAckSessionID(conn, "sess-1")

	for _, want := range []string{"ev-6", "ev-7"} {
		select {
		case got := <-h.events:
			if got != want {
				t.Fatalf("event = %q, want %q", got, want)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("timed out waiting for %q; sequence=%d", want, atomic.LoadInt64(s.sequence))
		}
	}
	select {
	case got := <-h.events:
		t.Fatalf("duplicate pre-ack event executed: %q", got)
	case <-time.After(100 * time.Millisecond):
	}
	if got := atomic.LoadInt64(s.sequence); got != 7 {
		t.Fatalf("sequence = %d, want 7", got)
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	for _, content := range h.order {
		if content == "ev-4" || content == "ev-5" {
			t.Fatalf("duplicate sn executed after same-session ack: %v", h.order)
		}
	}
}

// TestPreAckBufferFullDropsEvent 锁定缓冲区满时丢弃新事件而不是乱序执行；
// 缺失的 sn 会在 ACK 后由 s=4 补发。
func TestPreAckBufferFullDropsEvent(t *testing.T) {
	s, conn, h := newDispatchTestSession(t)
	s.sessionID = "sess-1"

	s.Lock()
	s.resumePending = true
	for i := 0; i < maxPreAckEvents; i++ {
		s.preAck = append(s.preAck, newPreAckTestEvent(conn, s.sessionEpoch.Load(), int64(i+1), "old"))
	}
	s.Unlock()

	payload := []byte(`{"s":0,"sn":99999,"d":{"type":251,"content":"overflow","extra":{}}}`)
	if _, err := s.onEvent(conn, websocket.TextMessage, payload); err != nil {
		t.Fatalf("onEvent: %v", err)
	}
	s.RLock()
	got := len(s.preAck)
	s.RUnlock()
	if got != maxPreAckEvents {
		t.Fatalf("preAck len = %d, want %d (overflow event must be dropped)", got, maxPreAckEvents)
	}
	select {
	case content := <-h.events:
		t.Fatalf("overflow event executed instead of buffered/dropped: %q", content)
	case <-time.After(100 * time.Millisecond):
	}
}

// TestManualComplianceConstants 把 KOOK 手册的关键数值锁进测试，防止后续
// 又出现“为了抗断网把 resume 预算改回 8 次”这类超出手册的改动。
func TestManualComplianceConstants(t *testing.T) {
	if heartbeatInterval != 30*time.Second {
		t.Fatalf("heartbeat interval = %s, manual says 30s", heartbeatInterval)
	}
	if heartbeatJitter != 5*time.Second {
		t.Fatalf("heartbeat jitter = %s, manual says ±5s", heartbeatJitter)
	}
	if heartbeatAckTimeout != 6*time.Second {
		t.Fatalf("pong timeout = %s, manual says 6s", heartbeatAckTimeout)
	}
	if heartbeatRetryFirstDelay != 2*time.Second || heartbeatRetrySecondDelay != 4*time.Second {
		t.Fatalf("heartbeat retry spacing = %s/%s, manual says 2s/4s", heartbeatRetryFirstDelay, heartbeatRetrySecondDelay)
	}
	if len(resumeRetryDelays) != 2 || resumeRetryDelays[0] != 8*time.Second || resumeRetryDelays[1] != 16*time.Second {
		t.Fatalf("resume delays = %v, manual says 8s/16s", resumeRetryDelays)
	}
	if maxAmbiguousResumeAttempts != 3 {
		t.Fatalf("resume attempts = %d, manual says first + 8s/16s retries = 3", maxAmbiguousResumeAttempts)
	}
	if reconnectMaxBackoff != 60*time.Second {
		t.Fatalf("gateway backoff cap = %s, manual says 60s", reconnectMaxBackoff)
	}
	// ACK 超时是本地兜底（手册未规定），锁定 60s，避免大积压补发时被误改短。
	if resumeAckTimeout != 60*time.Second {
		t.Fatalf("resume ack timeout = %s, want 60s local guard", resumeAckTimeout)
	}
	if !permanentAuthStatusCode(EventStatusMissingArgument) ||
		!permanentAuthStatusCode(EventStatusInvalidToken) ||
		!permanentAuthStatusCode(EventStatusTokenAuthFailed) ||
		permanentAuthStatusCode(EventStatusTokenExpired) {
		t.Fatal("HELLO 40100/40101/40102 must be permanent, 40103 must reconnect")
	}
	for _, code := range []EventStatusCode{
		EventStatusTokenExpired,
		EventStatusResumeFailed,
		EventStatusSessionExpired,
		EventStatusInvalidSequenceNumber,
	} {
		if !permanentResumeStatusCode(code) {
			t.Fatalf("resume code %d should be permanent", code)
		}
	}
}
