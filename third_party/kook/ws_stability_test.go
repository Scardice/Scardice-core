package kook

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

type nopEntry struct{}

func (nopEntry) Bool(string, bool) Entry             { return nopEntry{} }
func (nopEntry) Bytes(string, []byte) Entry          { return nopEntry{} }
func (nopEntry) Caller(int) Entry                    { return nopEntry{} }
func (nopEntry) Dur(string, time.Duration) Entry     { return nopEntry{} }
func (nopEntry) Err(string, error) Entry             { return nopEntry{} }
func (nopEntry) Float64(string, float64) Entry       { return nopEntry{} }
func (nopEntry) IPAddr(string, net.IP) Entry         { return nopEntry{} }
func (nopEntry) Int(string, int) Entry               { return nopEntry{} }
func (nopEntry) Int64(string, int64) Entry           { return nopEntry{} }
func (nopEntry) Interface(string, interface{}) Entry { return nopEntry{} }
func (nopEntry) Msg(string)                          {}
func (nopEntry) Msgf(string, ...interface{})         {}
func (nopEntry) Str(string, string) Entry            { return nopEntry{} }
func (nopEntry) Strs(string, []string) Entry         { return nopEntry{} }
func (nopEntry) Time(string, time.Time) Entry        { return nopEntry{} }

type nopLogger struct{}

func (nopLogger) Trace() Entry { return nopEntry{} }
func (nopLogger) Debug() Entry { return nopEntry{} }
func (nopLogger) Info() Entry  { return nopEntry{} }
func (nopLogger) Warn() Entry  { return nopEntry{} }
func (nopLogger) Error() Entry { return nopEntry{} }
func (nopLogger) Fatal() Entry { return nopEntry{} }

func TestCloseIsIdempotentAndConcurrent(t *testing.T) {
	s := New("token", nopLogger{})

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.Close()
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent Close calls deadlocked")
	}
}

func TestReconnectStopsAfterClose(t *testing.T) {
	s := New("token", nopLogger{})
	s.gateway = "ws://127.0.0.1:1" // 必定连接失败

	done := make(chan struct{})
	go func() {
		s.reconnect()
		close(done)
	}()

	time.Sleep(200 * time.Millisecond)
	_ = s.Close()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("reconnect kept retrying after user closed the session")
	}
}

func TestOpenAfterCloseReconnects(t *testing.T) {
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.WriteJSON(map[string]interface{}{
			"s": EventSignalHello,
			"d": map[string]interface{}{"code": EventStatusOk},
		})
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer server.Close()

	s := New("token", nopLogger{})
	s.gateway = "ws" + strings.TrimPrefix(server.URL, "http")

	if err := s.Close(); err != nil {
		t.Fatalf("initial Close() error = %v", err)
	}
	if err := s.Open(); err != nil {
		t.Fatalf("Open() after Close() error = %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestGuildUserListParsesItems(t *testing.T) {
	s := New("token", nopLogger{})
	s.Client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		body := `{"code":0,"data":{"items":[{"id":"u1","username":"tester"}],"meta":{"page":1,"page_total":1,"page_size":50,"total":1},"sort":{}}}`
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
		}, nil
	})}

	users, _, meta, err := s.GuildUserList("guild-id", nil)
	if err != nil {
		t.Fatalf("GuildUserList() error = %v", err)
	}
	if len(users) != 1 || users[0].ID != "u1" || users[0].Username != "tester" {
		t.Fatalf("GuildUserList() users = %#v", users)
	}
	if meta == nil || meta.Total != 1 {
		t.Fatalf("GuildUserList() meta = %#v", meta)
	}
}
