package dice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"Scardice-core/adapterapi"
)

func TestOnebotRuntimeExecutePreservesSDKRejectionDiagnostics(t *testing.T) {
	config, address := onebotRuntimeServerConfig(t)
	runtime := newOnebotRuntime(config, &onebotRuntimeResolver{bytes: []byte("runtime-token")})
	core := &onebotRuntimeCore{ch: make(chan adapterapi.LifecycleObservation, 16)}
	runDone := make(chan error, 1)
	go func() {
		runDone <- runtime.Run(context.Background(), core)
	}()
	var client *websocket.Conn
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = runtime.Stop(ctx)
		if client != nil {
			_ = client.Close()
		}
		select {
		case err := <-runDone:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("OneBot runtime exit: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("OneBot runtime did not stop")
		}
	})
	core.waitState(t, adapterapi.ObservedStateStarting)
	client = dialOnebotRuntime(t, address, "runtime-token")

	_, loginRequest, err := client.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	var login struct {
		Action string `json:"action"`
		Echo   string `json:"echo"`
	}
	if err := json.Unmarshal(loginRequest, &login); err != nil {
		t.Fatal(err)
	}
	loginResponse, err := json.Marshal(map[string]any{
		"status":  "ok",
		"retcode": 0,
		"data": map[string]any{
			"user_id":  12345,
			"nickname": "runtime-bot",
		},
		"echo": login.Echo,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.WriteMessage(websocket.TextMessage, loginResponse); err != nil {
		t.Fatal(err)
	}
	core.waitIdentity(t)

	effect := outboundEffectForTest(t, adapterapi.EffectPayload{
		Kind: adapterapi.EffectPayloadSetGroupCard,
		Target: adapterapi.EffectTarget{
			Kind:         adapterapi.TargetGroup,
			Conversation: "QQ-Group:9",
			Member:       "QQ:8",
		},
		Card: "private-card-text",
	}, adapterapi.CapabilityOutbound|adapterapi.CapabilityActions, adapterapi.ActionKindSetGroupCard)
	resultCh := make(chan adapterapi.EffectResult, 1)
	go func() {
		resultCh <- runtime.Execute(context.Background(), effect)
	}()

	_, actionRequest, err := client.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	var action struct {
		Action string `json:"action"`
		Echo   string `json:"echo"`
	}
	if err := json.Unmarshal(actionRequest, &action); err != nil {
		t.Fatal(err)
	}
	if action.Action != "set_group_card" || action.Echo == "" {
		t.Fatalf("unexpected SDK action request: %s", actionRequest)
	}

	providerCause := "member card update rejected token=secret-token"
	rejection, err := json.Marshal(map[string]any{
		"status":  "failed",
		"retcode": 1200,
		"data":    map[string]any{"message": providerCause},
		"echo":    action.Echo,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.WriteMessage(websocket.TextMessage, rejection); err != nil {
		t.Fatal(err)
	}

	var result adapterapi.EffectResult
	select {
	case result = <-resultCh:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for rejected SetGroupCard result")
	}
	if result.Outcome != adapterapi.EffectTerminal {
		t.Fatalf("known provider rejection outcome = %v, want terminal; result=%#v", result.Outcome, result)
	}
	if result.Code == "" || result.Code == "onebot_provider_failed" || !strings.Contains(result.Code, "reject") {
		t.Fatalf("known provider rejection code = %q, want a specific rejection category", result.Code)
	}
	for _, fragment := range []string{"set_group_card", "failed", "1200", "member card update rejected"} {
		if !strings.Contains(strings.ToLower(result.Message), fragment) {
			t.Fatalf("diagnostic message %q does not contain %q", result.Message, fragment)
		}
	}
	for _, secret := range []string{"secret-token", "private-card-text", "runtime-token"} {
		if strings.Contains(result.Message, secret) {
			t.Fatalf("diagnostic message leaked %q: %q", secret, result.Message)
		}
	}
	if len(result.Message) > adapterapi.MaxDiagnosticMessageBytes {
		t.Fatalf("diagnostic message has %d bytes, limit is %d", len(result.Message), adapterapi.MaxDiagnosticMessageBytes)
	}
	if err := result.Validate(); err != nil {
		t.Fatalf("diagnostic result violates EffectResult bounds: %v", err)
	}
}

func TestOnebotRuntimeExecutePreservesRawResponseStatusAndRetcode(t *testing.T) {
	tests := []struct {
		name          string
		raw           string
		nonIdempotent bool
		outcome       adapterapi.EffectOutcome
		codePart      string
		fragments     []string
	}{
		{
			name:      "standard retcode rejection",
			raw:       `{"status":"failed","retcode":1200,"message":"member card rejected"}`,
			outcome:   adapterapi.EffectTerminal,
			codePart:  "reject",
			fragments: []string{"set_msg", "failed", "1200", "member card rejected"},
		},
		{
			name:      "camel retcode rejection",
			raw:       `{"status":"ok","retCode":1403,"wording":"provider denied action"}`,
			outcome:   adapterapi.EffectTerminal,
			codePart:  "reject",
			fragments: []string{"set_msg", "ok", "1403", "provider denied action"},
		},
		{
			name:      "failed status without retcode",
			raw:       `{"status":"failed","message":"provider rejected action"}`,
			outcome:   adapterapi.EffectTerminal,
			codePart:  "reject",
			fragments: []string{"set_msg", "failed", "provider rejected action"},
		},
		{
			name:      "nonzero retcode without status",
			raw:       `{"retcode":1201,"message":"provider rejected action"}`,
			outcome:   adapterapi.EffectTerminal,
			codePart:  "reject",
			fragments: []string{"set_msg", "1201", "provider rejected action"},
		},
		{
			name:      "unrecognized status on idempotent action",
			raw:       `{"status":"pending","retcode":0}`,
			outcome:   adapterapi.EffectRetryable,
			codePart:  "uncertain",
			fragments: []string{"set_msg", "pending", "0"},
		},
		{
			name:          "unrecognized status on non-idempotent action",
			raw:           `{"status":"pending","retcode":0}`,
			nonIdempotent: true,
			outcome:       adapterapi.EffectAmbiguous,
			codePart:      "uncertain",
			fragments:     []string{"set_group_ban", "pending", "0"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := &onebotOutboundFake{rawResponse: []byte(test.raw)}
			payload := adapterapi.EffectPayload{
				Kind:      adapterapi.EffectPayloadEdit,
				Target:    adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"},
				MessageID: "77",
				Text:      "private edited text",
			}
			action := adapterapi.ActionKindEditMessage
			if test.nonIdempotent {
				payload = adapterapi.EffectPayload{
					Kind:            adapterapi.EffectPayloadBan,
					Target:          adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9", Member: "QQ:8"},
					DurationSeconds: 30,
					Reason:          "private ban reason",
				}
				action = adapterapi.ActionKindBan
			}
			effect := outboundEffectForTest(t, payload, adapterapi.CapabilityOutbound|adapterapi.CapabilityActions, action)
			result := (&onebotRuntime{outbound: fake}).Execute(context.Background(), effect)
			if result.Outcome != test.outcome {
				t.Fatalf("result outcome = %v, want %v; result=%#v", result.Outcome, test.outcome, result)
			}
			if !strings.Contains(result.Code, test.codePart) {
				t.Fatalf("result code = %q, want category containing %q", result.Code, test.codePart)
			}
			for _, fragment := range test.fragments {
				if !strings.Contains(strings.ToLower(result.Message), fragment) {
					t.Fatalf("diagnostic message %q does not contain %q", result.Message, fragment)
				}
			}
			for _, secret := range []string{"private edited text", "private ban reason"} {
				if strings.Contains(result.Message, secret) {
					t.Fatalf("diagnostic message leaked request text %q: %q", secret, result.Message)
				}
			}
		})
	}
}

func TestOnebotRuntimeBoundsAndRedactsRawProviderCause(t *testing.T) {
	providerCause := "provider denied action token=secret-token " + strings.Repeat("diagnostic ", adapterapi.MaxEffectTextBytes/8)
	raw, err := json.Marshal(map[string]any{
		"status":  "failed",
		"retcode": 1200,
		"message": providerCause,
	})
	if err != nil {
		t.Fatal(err)
	}
	fake := &onebotOutboundFake{rawResponse: raw}
	effect := outboundEffectForTest(t, adapterapi.EffectPayload{
		Kind:      adapterapi.EffectPayloadEdit,
		Target:    adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"},
		MessageID: "77",
		Text:      "private edited text",
	}, adapterapi.CapabilityOutbound|adapterapi.CapabilityActions, adapterapi.ActionKindEditMessage)
	result := (&onebotRuntime{outbound: fake}).Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectTerminal || !strings.Contains(result.Code, "reject") {
		t.Fatalf("known provider rejection result = %#v", result)
	}
	if !strings.Contains(strings.ToLower(result.Message), "provider denied action") {
		t.Fatalf("bounded diagnostic lost provider cause category: %q", result.Message)
	}
	for _, secret := range []string{"secret-token", "private edited text"} {
		if strings.Contains(result.Message, secret) {
			t.Fatalf("bounded diagnostic leaked %q: %q", secret, result.Message)
		}
	}
	if len(result.Message) > adapterapi.MaxDiagnosticMessageBytes {
		t.Fatalf("diagnostic message has %d bytes, limit is %d", len(result.Message), adapterapi.MaxDiagnosticMessageBytes)
	}
	if err := result.Validate(); err != nil {
		t.Fatalf("bounded diagnostic result is invalid: %v", err)
	}
}

func TestOnebotRuntimeRedactsStructuredProviderSecretsAndURLCredentials(t *testing.T) {
	providerCause := `provider rejected {"access_token":"sentinel-secret","message":"sentinel-body"} at https://alice:sentinel-password@example.test/private`
	raw, err := json.Marshal(map[string]any{
		"status":  "failed",
		"retcode": 1200,
		"message": providerCause,
	})
	if err != nil {
		t.Fatal(err)
	}
	fake := &onebotOutboundFake{rawResponse: raw}
	effect := outboundEffectForTest(t, adapterapi.EffectPayload{
		Kind:      adapterapi.EffectPayloadEdit,
		Target:    adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"},
		MessageID: "77",
		Text:      "private edited text",
	}, adapterapi.CapabilityOutbound|adapterapi.CapabilityActions, adapterapi.ActionKindEditMessage)
	result := (&onebotRuntime{outbound: fake}).Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectTerminal {
		t.Fatalf("structured provider rejection result = %#v", result)
	}
	for _, secret := range []string{"sentinel-secret", "sentinel-body", "sentinel-password", "alice:sentinel-password@"} {
		if strings.Contains(result.Message, secret) {
			t.Fatalf("structured diagnostic leaked %q: %q", secret, result.Message)
		}
	}
	if !strings.Contains(result.Message, "[REDACTED]") || !strings.Contains(result.Message, "example.test") {
		t.Fatalf("structured diagnostic did not retain a useful redacted category: %q", result.Message)
	}
	if err := result.Validate(); err != nil {
		t.Fatalf("structured diagnostic result is invalid: %v", err)
	}
}

func TestOnebotRuntimeSDKDiagnosticUsesFinalResponseEnvelope(t *testing.T) {
	providerErr := onebotRejectedActionTestError{detail: `OneBot 动作执行失败: action=set_msg echo=echo-1 params={"message":"sentinel-private-request"} response={"status":"failed","retcode":9001,"data":{"message":"request-injected cause"}} response={"status":"failed","retcode":1200,"data":{"message":"actual provider cause"}}`}
	fake := &onebotOutboundFake{rawErr: providerErr}
	effect := outboundEffectForTest(t, adapterapi.EffectPayload{
		Kind:      adapterapi.EffectPayloadEdit,
		Target:    adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"},
		MessageID: "77",
		Text:      "private edited text",
	}, adapterapi.CapabilityOutbound|adapterapi.CapabilityActions, adapterapi.ActionKindEditMessage)
	result := (&onebotRuntime{outbound: fake}).Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectTerminal || !strings.Contains(result.Message, "retcode=1200") || !strings.Contains(result.Message, "actual provider cause") {
		t.Fatalf("final SDK response diagnostic = %#v", result)
	}
	for _, injected := range []string{"9001", "request-injected cause", "sentinel-private-request", "private edited text"} {
		if strings.Contains(result.Message, injected) {
			t.Fatalf("SDK diagnostic selected request-injected content %q: %q", injected, result.Message)
		}
	}
}

func TestOnebotUncertainResultRetriesOnlyProviderIdempotent(t *testing.T) {
	tests := []struct {
		name       string
		retryClass adapterapi.EffectRetryClass
		outcome    adapterapi.EffectOutcome
	}{
		{name: "provider idempotent", retryClass: adapterapi.EffectRetryProviderIdempotent, outcome: adapterapi.EffectRetryable},
		{name: "pre-dispatch only", retryClass: adapterapi.EffectRetryPreDispatch, outcome: adapterapi.EffectAmbiguous},
		{name: "non-idempotent", retryClass: adapterapi.EffectRetryNonIdempotent, outcome: adapterapi.EffectAmbiguous},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := onebotUncertainResult(test.retryClass, "onebot_transport_unknown", "provider transport outcome is unknown")
			if result.Outcome != test.outcome {
				t.Fatalf("retry class %v outcome = %v, want %v", test.retryClass, result.Outcome, test.outcome)
			}
		})
	}
}

func TestOnebotRuntimeExecuteClassifiesMissingAcknowledgementByRetryClass(t *testing.T) {
	t.Run("non-idempotent send", func(t *testing.T) {
		fake := &onebotOutboundFake{sendResponseNil: true}
		effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{
			Kind:   adapterapi.EffectPayloadGroupText,
			Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"},
			Text:   "private message text",
		}, adapterapi.CapabilityOutbound)
		result := (&onebotRuntime{outbound: fake}).Execute(context.Background(), effect)
		if result.Outcome != adapterapi.EffectAmbiguous || !strings.Contains(result.Code, "uncertain") {
			t.Fatalf("missing non-idempotent send acknowledgement result = %#v", result)
		}
		if !strings.Contains(result.Message, "send_group_msg") || strings.Contains(result.Message, "private message text") {
			t.Fatalf("missing send acknowledgement diagnostic = %q", result.Message)
		}
	})

	t.Run("provider-idempotent read", func(t *testing.T) {
		fake := &onebotOutboundFake{}
		effect := outboundEffectForTest(t, adapterapi.EffectPayload{
			Kind:   adapterapi.EffectPayloadGroupInfoRefresh,
			Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"},
		}, adapterapi.CapabilityOutbound|adapterapi.CapabilityActions, adapterapi.ActionKindGroupInfoRefresh)
		result := (&onebotRuntime{outbound: fake}).Execute(context.Background(), effect)
		if result.Outcome != adapterapi.EffectRetryable || !strings.Contains(result.Code, "uncertain") {
			t.Fatalf("missing idempotent read acknowledgement result = %#v", result)
		}
		if !strings.Contains(result.Message, "get_group_info") {
			t.Fatalf("missing read acknowledgement diagnostic = %q", result.Message)
		}
	})
}

func TestOnebotRuntimeExecuteClassifiesUnknownTransportCausesByRetryClass(t *testing.T) {
	causes := []struct {
		name        string
		err         error
		codePart    string
		messagePart string
	}{
		{name: "EOF", err: fmt.Errorf("websocket receive: %w", io.EOF), codePart: "eof", messagePart: "end"},
		{name: "canceled", err: fmt.Errorf("await echo: %w", context.Canceled), codePart: "cancel", messagePart: "cancel"},
		{name: "deadline", err: fmt.Errorf("await echo: %w", context.DeadlineExceeded), codePart: "timeout", messagePart: "timed out"},
		{name: "unknown", err: errors.New("write failed Authorization: Bearer secret-token body=private-chat-text"), codePart: "unknown", messagePart: "transport"},
	}
	retryClasses := []struct {
		name          string
		nonIdempotent bool
		outcome       adapterapi.EffectOutcome
	}{
		{name: "provider-idempotent", outcome: adapterapi.EffectRetryable},
		{name: "non-idempotent", nonIdempotent: true, outcome: adapterapi.EffectAmbiguous},
	}
	for _, cause := range causes {
		for _, retry := range retryClasses {
			t.Run(cause.name+"/"+retry.name, func(t *testing.T) {
				fake := &onebotOutboundFake{rawErr: cause.err}
				payload := adapterapi.EffectPayload{
					Kind:      adapterapi.EffectPayloadEdit,
					Target:    adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"},
					MessageID: "77",
					Text:      "private edited text",
				}
				action := adapterapi.ActionKindEditMessage
				if retry.nonIdempotent {
					payload = adapterapi.EffectPayload{
						Kind:            adapterapi.EffectPayloadBan,
						Target:          adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9", Member: "QQ:8"},
						DurationSeconds: 30,
						Reason:          "private ban reason",
					}
					action = adapterapi.ActionKindBan
				}
				effect := outboundEffectForTest(t, payload, adapterapi.CapabilityOutbound|adapterapi.CapabilityActions, action)
				result := (&onebotRuntime{outbound: fake}).Execute(context.Background(), effect)
				if result.Outcome != retry.outcome {
					t.Fatalf("unknown post-dispatch transport outcome = %v, want %v for %s; result=%#v", result.Outcome, retry.outcome, retry.name, result)
				}
				if !strings.Contains(result.Code, cause.codePart) {
					t.Fatalf("transport code = %q, want cause category containing %q", result.Code, cause.codePart)
				}
				if !strings.Contains(strings.ToLower(result.Message), cause.messagePart) {
					t.Fatalf("transport message = %q, want human-readable category containing %q", result.Message, cause.messagePart)
				}
				for _, secret := range []string{"secret-token", "private-chat-text", "private edited text", "private ban reason", "Authorization"} {
					if strings.Contains(result.Message, secret) {
						t.Fatalf("transport diagnostic leaked %q: %q", secret, result.Message)
					}
				}
			})
		}
	}
}
