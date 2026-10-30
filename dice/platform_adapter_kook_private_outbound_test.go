package dice

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"Scardice-core/adapterapi"
)

func TestKookRuntimeExecuteSendsPrivateText(t *testing.T) {
	messageSeen := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/api/v3/user-chat/create":
			var body struct {
				TargetID string `json:"target_id"`
			}
			if json.NewDecoder(request.Body).Decode(&body) != nil || body.TargetID != "user-1" {
				http.Error(writer, "invalid target", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{"code": 0, "data": map[string]string{"code": "chat-1"}})
		case "/api/v3/direct-message/create":
			var body struct {
				ChatCode string `json:"chat_code"`
				Type     int    `json:"type"`
				Content  string `json:"content"`
			}
			var cards []struct {
				Type    string `json:"type"`
				Modules []struct {
					Type string `json:"type"`
					Text struct {
						Content string `json:"content"`
						Type    string `json:"type"`
					} `json:"text"`
				} `json:"modules"`
			}
			if json.NewDecoder(request.Body).Decode(&body) != nil ||
				json.Unmarshal([]byte(body.Content), &cards) != nil ||
				body.ChatCode != "chat-1" ||
				body.Type != 7 ||
				len(cards) != 1 ||
				cards[0].Type != "card" ||
				len(cards[0].Modules) != 1 ||
				cards[0].Modules[0].Text.Content != "hello" ||
				cards[0].Modules[0].Text.Type != "plain-text" {
				http.Error(writer, "invalid message", http.StatusBadRequest)
				return
			}
			messageSeen <- struct{}{}
			_ = json.NewEncoder(writer).Encode(map[string]any{"code": 0, "data": map[string]string{"msg_id": "message-2"}})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	runtime := &kookRuntime{config: kookCanonicalConfig{APIBaseURL: server.URL}, token: "runtime-token", selfID: "bot-1", httpClient: server.Client()}
	effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadPersonText, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetPerson, Conversation: "KOOK:user-1"}, Text: "hello"}, adapterapi.CapabilityOutbound)
	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectSucceeded || result.ProviderID != "message-2" {
		t.Fatalf("result = %#v", result)
	}
	<-messageSeen
}
