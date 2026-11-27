package kook

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestRequestRetriesOnRateLimit(t *testing.T) {
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.Header().Set("X-Rate-Limit-Reset", "0.05")
			w.Header().Set("X-Rate-Limit-Bucket", "message/create")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"code":0,"message":"rate limited"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{"ok":true}}`))
	}))
	defer server.Close()

	s := New("token", nopLogger{})
	s.Client = server.Client()
	s.MaxRetry = 2
	s.RetryTimeout = 2 * time.Second

	resp, err := s.Request(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("Request returned error: %v", err)
	}
	if string(resp) != `{"ok":true}` {
		t.Fatalf("response = %s", resp)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("calls = %d, want 2", got)
	}
}

func TestRequestRetriesPostOnRateLimit(t *testing.T) {
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if atomic.AddInt32(&calls, 1) == 1 {
			w.Header().Set("X-Rate-Limit-Reset", "0.05")
			w.Header().Set("X-Rate-Limit-Bucket", "message/create")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"code":0,"message":"rate limited"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{"ok":true}}`))
	}))
	defer server.Close()

	s := New("token", nopLogger{})
	s.Client = server.Client()
	s.MaxRetry = 2
	s.RetryTimeout = 2 * time.Second

	// 429 表示服务端未处理，POST 也应等待 reset 后重试。
	resp, err := s.Request(http.MethodPost, server.URL, map[string]string{"content": "hi"})
	if err != nil {
		t.Fatalf("Request returned error: %v", err)
	}
	if string(resp) != `{"ok":true}` {
		t.Fatalf("response = %s", resp)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("calls = %d, want 2", got)
	}
}

func TestRequestRateLimitExhaustsRetryBudget(t *testing.T) {
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
	s.MaxRetry = 1
	s.RetryTimeout = time.Second

	if _, err := s.Request(http.MethodGet, server.URL, nil); err == nil {
		t.Fatal("Request should fail after retry budget is exhausted")
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("calls = %d, want 2 (initial + 1 retry)", got)
	}
}

func TestRequestRejectsNon2xx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`upstream down`))
	}))
	defer server.Close()

	s := New("token", nopLogger{})
	s.Client = server.Client()
	if _, err := s.Request(http.MethodGet, server.URL, nil); err == nil {
		t.Fatal("Request should reject HTTP 502")
	}
}
