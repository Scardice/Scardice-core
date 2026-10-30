package dice

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"Scardice-core/adapterapi"
)

func TestDiscordRuntimeExecuteSendsChannelText(t *testing.T) {
	requestSeen := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v10/channels/1001/messages" || request.Header.Get("Authorization") != "Bot runtime-token" {
			http.Error(writer, "invalid request", http.StatusBadRequest)
			return
		}
		var body struct {
			Embeds []struct {
				Description string `json:"description"`
				Type        string `json:"type"`
			} `json:"embeds"`
		}
		if json.NewDecoder(request.Body).Decode(&body) != nil ||
			len(body.Embeds) != 1 ||
			body.Embeds[0].Description != "hello" ||
			body.Embeds[0].Type != "article" {
			http.Error(writer, "invalid body", http.StatusBadRequest)
			return
		}
		requestSeen <- struct{}{}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"id":"provider-message-1"}`))
	}))
	defer server.Close()

	runtime := &discordRuntime{config: discordCanonicalConfig{ReverseProxyURL: server.URL}, token: "runtime-token", selfID: "bot-1", httpClient: server.Client()}
	effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadGroupText, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "DISCORD-CH-Group:1001"}, Text: "hello"}, adapterapi.CapabilityOutbound)
	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectSucceeded || result.ProviderID != "provider-message-1" {
		t.Fatalf("result = %#v", result)
	}
	<-requestSeen
}
