package dice

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sealdice/botgo/dto"
	qqevent "github.com/sealdice/botgo/event"
)

func TestOfficialQQWebSocket_dispatchesGroupMemberEventThroughQueue(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		conn, err := upgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.WriteJSON(map[string]any{
			"op": 0,
			"s":  7,
			"t":  "GROUP_MEMBER_ADD",
			"d": map[string]any{
				"group_openid":     "group-open-id",
				"member_openid":    "member-open-id",
				"op_member_openid": "operator-open-id",
				"timestamp":        int64(123),
			},
		})
	}))
	defer server.Close()

	adapter := &PlatformAdapterOfficialQQ{AppID: 200}
	adapter.startOfficialQQEventQueue()
	t.Cleanup(adapter.closeOfficialQQEventQueue)
	received := make(chan officialQQGroupMemberEvent, 1)
	adapter.memberEventSink = func(event officialQQGroupMemberEvent) { received <- event }
	intent := adapter.registerOfficialQQHandlers()
	if intent&officialQQGroupMembersIntent == 0 {
		t.Fatalf("registered intent %d excludes group members", intent)
	}

	url := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()
	_, raw, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage() error = %v", err)
	}
	payload := new(dto.WSPayload)
	if err := json.Unmarshal(raw, payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	payload.RawMessage = raw
	if err := qqevent.ParseAndHandle(payload); err != nil {
		t.Fatalf("ParseAndHandle() error = %v", err)
	}

	select {
	case event := <-received:
		if event.GroupOpenID != "group-open-id" || event.MemberOpenID != "member-open-id" || event.Timestamp != 123 {
			t.Fatalf("member event = %#v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("member event was not dispatched")
	}
}
