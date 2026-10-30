package dice

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"Scardice-core/adapterapi"
)

func TestDiscordRuntimeExecuteSendsPrivateText(t *testing.T) {
	messageSeen := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bot runtime-token" {
			http.Error(writer, "invalid authorization", http.StatusUnauthorized)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/api/v10/users/@me/channels":
			var body struct {
				RecipientID string `json:"recipient_id"`
			}
			if json.NewDecoder(request.Body).Decode(&body) != nil || body.RecipientID != "1001" {
				http.Error(writer, "invalid recipient", http.StatusBadRequest)
				return
			}
			_, _ = writer.Write([]byte(`{"id":"2001"}`))
		case "/api/v10/channels/2001/messages":
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
				http.Error(writer, "invalid message", http.StatusBadRequest)
				return
			}
			messageSeen <- struct{}{}
			_, _ = writer.Write([]byte(`{"id":"provider-message-2"}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	runtime := &discordRuntime{config: discordCanonicalConfig{ReverseProxyURL: server.URL}, token: "runtime-token", selfID: "bot-1", httpClient: server.Client()}
	effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadPersonText, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetPerson, Conversation: "DISCORD:1001"}, Text: "hello"}, adapterapi.CapabilityOutbound)
	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectSucceeded || result.ProviderID != "provider-message-2" {
		t.Fatalf("result = %#v", result)
	}
	<-messageSeen
}
