package dice

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"Scardice-core/adapterapi"
)

func TestSatoriRuntimeExecuteSendsGroupText(t *testing.T) {
	requestSeen := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/message.create" || request.Header.Get("Authorization") != "Bearer runtime-token" || request.Header.Get("X-Platform") != "qq" || request.Header.Get("X-Self-Id") != "bot-1" {
			http.Error(writer, "invalid request", http.StatusBadRequest)
			return
		}
		var body struct {
			ChannelID string `json:"channel_id"`
			Content   string `json:"content"`
		}
		if json.NewDecoder(request.Body).Decode(&body) != nil || body.ChannelID != "guild-1" || body.Content != "hello" {
			http.Error(writer, "invalid body", http.StatusBadRequest)
			return
		}
		requestSeen <- struct{}{}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`[{"id":"provider-message-1"}]`))
	}))
	defer server.Close()
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(serverURL.Port())
	if err != nil {
		t.Fatal(err)
	}
	runtime := &satoriRuntime{config: satoriCanonicalConfig{Version: "v1", Platform: "qq", Host: serverURL.Hostname(), Port: port}, token: "runtime-token", selfID: "bot-1", httpClient: server.Client()}
	effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadGroupText, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "qq-Group:guild-1"}, Text: "hello"}, adapterapi.CapabilityOutbound)
	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectSucceeded || result.ProviderID != "provider-message-1" {
		t.Fatalf("result = %#v", result)
	}
	<-requestSeen
}
