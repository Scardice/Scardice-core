package dice

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	milky "github.com/Szzrain/Milky-go-sdk"
	"go.uber.org/zap"
)

type milkyForwardRequest struct {
	GroupID int64 `json:"group_id"`
	UserID  int64 `json:"user_id"`
	Message []struct {
		Type string `json:"type"`
		Data struct {
			Text       string `json:"text"`
			UserID     int64  `json:"user_id"`
			MessageSeq int64  `json:"message_seq"`
			Messages   []struct {
				UserID     int64  `json:"user_id"`
				SenderName string `json:"sender_name"`
				LegacyName string `json:"name"`
				Segments   []struct {
					Type string `json:"type"`
					Data struct {
						Text string `json:"text"`
					} `json:"data"`
				} `json:"segments"`
			} `json:"messages"`
		} `json:"data"`
	} `json:"message"`
}

type milkyForwardHarness struct {
	t        *testing.T
	apiError string

	mu       sync.Mutex
	endpoint string
	request  milkyForwardRequest
	count    int
	signal   chan struct{}
}

func newMilkyForwardHarness(t *testing.T, apiError string) (*milky.Session, *milkyForwardHarness) {
	t.Helper()

	harness := &milkyForwardHarness{t: t, apiError: apiError, signal: make(chan struct{}, 1)}
	server := httptest.NewServer(http.HandlerFunc(harness.handle))
	t.Cleanup(server.Close)
	session, err := milky.New("ws://127.0.0.1", server.URL, "", zap.NewNop().Sugar())
	if err != nil {
		t.Fatalf("create Milky session: %v", err)
	}
	return session, harness
}

func (harness *milkyForwardHarness) handle(w http.ResponseWriter, request *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var body milkyForwardRequest
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
		harness.t.Errorf("decode Milky forward request: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	harness.mu.Lock()
	harness.endpoint = strings.TrimPrefix(request.URL.Path, "/")
	harness.request = body
	harness.count++
	harness.mu.Unlock()
	select {
	case harness.signal <- struct{}{}:
	default:
	}

	if harness.apiError != "" {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "failed",
			"retcode": 1,
			"message": harness.apiError,
		})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":  "ok",
		"retcode": 0,
		"data": map[string]any{
			"message_seq": 321,
			"time":        1,
		},
	})
}

func (harness *milkyForwardHarness) snapshot() (string, milkyForwardRequest) {
	harness.mu.Lock()
	defer harness.mu.Unlock()
	return harness.endpoint, harness.request
}

func newMilkyForwardTestContext(session *milky.Session, onMessageSend func(*MsgContext, *Message, string)) (*PlatformAdapterMilky, *MsgContext) {
	dice := &Dice{
		Config: Config{BaseConfig: BaseConfig{
			MessageDelayRangeStart: 0,
			MessageDelayRangeEnd:   0,
		}},
		ExtList: []*ExtInfo{{OnMessageSend: onMessageSend}},
	}
	dice.ImSession = &IMSession{Parent: dice}
	endpoint := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{
		UserID:       "QQ:10010",
		Nickname:     "MilkyBot",
		Platform:     "QQ",
		ProtocolType: "milky",
	}}
	adapter := &PlatformAdapterMilky{EndPoint: endpoint, IntentSession: session}
	endpoint.Adapter = adapter
	endpoint.BindRuntime(dice.ImSession)
	return adapter, &MsgContext{Dice: dice, EndPoint: endpoint}
}

func Test_PlatformAdapterMilky_SendForwardMessage_preserves_ordered_nodes(t *testing.T) {
	// Given
	nodes := []forwardNode{
		{Data: forwardNodeData{Uin: "10010", Name: "first", Content: "one"}},
		{Data: forwardNodeData{Uin: "10011", Name: "second", Content: "two"}},
	}
	tests := []struct {
		name            string
		endpoint        string
		targetID        int64
		messageType     string
		wantHookGroupID string
		send            func(*PlatformAdapterMilky, *MsgContext) bool
	}{
		{
			name:            "group",
			endpoint:        milky.EndpointSendGroupMessage,
			targetID:        20020,
			messageType:     "group",
			wantHookGroupID: "QQ-Group:20020",
			send: func(adapter *PlatformAdapterMilky, ctx *MsgContext) bool {
				return adapter.SendGroupForwardMsg(ctx, "QQ-Group:20020", nodes)
			},
		},
		{
			name:        "private",
			endpoint:    milky.EndpointSendPrivateMessage,
			targetID:    30030,
			messageType: "private",
			send: func(adapter *PlatformAdapterMilky, ctx *MsgContext) bool {
				return adapter.SendPrivateForwardMsg(ctx, "QQ:30030", nodes)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			session, harness := newMilkyForwardHarness(t, "")
			var hookCalls int
			var hookMessage *Message
			adapter, ctx := newMilkyForwardTestContext(session, func(_ *MsgContext, message *Message, _ string) {
				hookCalls++
				hookMessage = message
			})

			// When
			sent := test.send(adapter, ctx)

			// Then
			if !sent {
				t.Fatal("forward send returned false")
			}
			endpoint, request := harness.snapshot()
			if endpoint != test.endpoint {
				t.Fatalf("endpoint = %q, want %q", endpoint, test.endpoint)
			}
			if request.GroupID != test.targetID && request.UserID != test.targetID {
				t.Fatalf("target IDs = (%d, %d), want %d", request.GroupID, request.UserID, test.targetID)
			}
			if len(request.Message) != 1 || request.Message[0].Type != string(milky.Forward) {
				t.Fatalf("message = %#v, want one forward element", request.Message)
			}
			messages := request.Message[0].Data.Messages
			if len(messages) != len(nodes) {
				t.Fatalf("forward node count = %d, want %d", len(messages), len(nodes))
			}
			for index, node := range messages {
				if node.UserID != int64(10010+index) || node.SenderName != nodes[index].Data.Name {
					t.Errorf("node %d sender = (%d, %q), want (%d, %q)", index, node.UserID, node.SenderName, 10010+index, nodes[index].Data.Name)
				}
				if node.LegacyName != "" {
					t.Errorf("node %d contains deprecated name field %q", index, node.LegacyName)
				}
				if len(node.Segments) != 1 || node.Segments[0].Type != string(milky.Text) || node.Segments[0].Data.Text != nodes[index].Data.Content {
					t.Errorf("node %d segments = %#v, want text %q", index, node.Segments, nodes[index].Data.Content)
				}
			}
			if hookCalls != 1 || hookMessage == nil {
				t.Fatalf("OnMessageSend calls = %d, want 1", hookCalls)
			}
			if hookMessage.MessageType != test.messageType || hookMessage.GroupID != test.wantHookGroupID || hookMessage.RawID != int64(321) {
				t.Errorf("hook message = %#v, want type %q, group %q, raw ID 321", hookMessage, test.messageType, test.wantHookGroupID)
			}
		})
	}
}

func Test_PlatformAdapterMilky_SendForwardMessage_returns_false_without_hook_on_failure(t *testing.T) {
	// Given
	validNodes := []forwardNode{{Data: forwardNodeData{Uin: "10010", Name: "sender", Content: "content"}}}
	session, _ := newMilkyForwardHarness(t, "forward rejected")
	var hookCalls int
	adapter, ctx := newMilkyForwardTestContext(session, func(_ *MsgContext, _ *Message, _ string) {
		hookCalls++
	})
	tests := []struct {
		name string
		send func() bool
	}{
		{name: "API error", send: func() bool { return adapter.SendGroupForwardMsg(ctx, "QQ-Group:20020", validNodes) }},
		{name: "empty nodes", send: func() bool { return adapter.SendGroupForwardMsg(ctx, "QQ-Group:20020", nil) }},
		{name: "invalid group ID", send: func() bool { return adapter.SendGroupForwardMsg(ctx, "QQ-Group:invalid", validNodes) }},
		{name: "invalid private ID", send: func() bool { return adapter.SendPrivateForwardMsg(ctx, "QQ:invalid", validNodes) }},
		{name: "invalid node user ID", send: func() bool {
			return adapter.SendGroupForwardMsg(ctx, "QQ-Group:20020", []forwardNode{{Data: forwardNodeData{Uin: "invalid", Name: "sender", Content: "content"}}})
		}},
		{name: "empty node content", send: func() bool {
			return adapter.SendGroupForwardMsg(ctx, "QQ-Group:20020", []forwardNode{{Data: forwardNodeData{Uin: "10010", Name: "sender"}}})
		}},
		{name: "missing session", send: func() bool {
			return (&PlatformAdapterMilky{}).SendGroupForwardMsg(ctx, "QQ-Group:20020", validNodes)
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// When
			sent := test.send()

			// Then
			if sent {
				t.Fatal("forward send returned true")
			}
			if hookCalls != 0 {
				t.Fatalf("OnMessageSend calls = %d, want 0", hookCalls)
			}
		})
	}
}
