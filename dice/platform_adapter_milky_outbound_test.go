package dice

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"Scardice-core/adapterapi"
)

func TestMilkyRuntimeExecuteSendsGroupText(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/send_group_message" || request.Header.Get("Authorization") != "Bearer runtime-token" {
			http.Error(writer, "invalid request", http.StatusBadRequest)
			return
		}
		var body struct {
			GroupID int64 `json:"group_id"`
			Message []struct {
				Type string `json:"type"`
				Data struct {
					Text string `json:"text"`
				} `json:"data"`
			} `json:"message"`
		}
		if json.NewDecoder(request.Body).Decode(&body) != nil || body.GroupID != 200 || len(body.Message) != 1 || body.Message[0].Type != "text" || body.Message[0].Data.Text != "hello" {
			http.Error(writer, "invalid body", http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"status":"ok","retcode":0,"data":{"message_seq":42,"time":1700000000}}`))
	}))
	defer server.Close()

	runtime := &milkyRuntime{config: milkyCanonicalConfig{RESTGateway: server.URL}, token: "runtime-token", selfID: 123, httpClient: server.Client()}
	effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadGroupText, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:200"}, Text: "hello"}, adapterapi.CapabilityOutbound)
	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectSucceeded || result.ProviderID != "42" {
		t.Fatalf("result = %#v", result)
	}
}
