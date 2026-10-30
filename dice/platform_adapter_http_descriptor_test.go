package dice

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/adapterapi/contracttest"
)

func TestHTTPDescriptorRunsContextBoundRedirectedRequest(t *testing.T) {
	requestSeen := make(chan HTTPSimpleMessage, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/redirect":
			http.Redirect(writer, request, "/hook", http.StatusTemporaryRedirect)
		case "/hook":
			var message HTTPSimpleMessage
			if request.Method != http.MethodPost || json.NewDecoder(request.Body).Decode(&message) != nil {
				http.Error(writer, "invalid request", http.StatusBadRequest)
				return
			}
			requestSeen <- message
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(map[string]string{"id": "http-message-1"})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	runtime, stop := startHTTPRuntimeForTest(t, json.RawMessage(`{"version":"1","url":"`+server.URL+`","method":"POST","path":"/redirect","timeoutSeconds":2}`))
	defer stop()
	effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadGroupText, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "HTTP-Group:room-1"}, Text: "hello outbound"}, adapterapi.CapabilityOutbound)
	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectSucceeded || result.ProviderID != "http-message-1" {
		t.Fatalf("result = %#v", result)
	}
	select {
	case message := <-requestSeen:
		if message.UID != "HTTP-Group:room-1" || message.Message != "hello outbound" || message.MessageType != "group" {
			t.Fatalf("request payload = %#v", message)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for HTTP request")
	}
}

func TestHTTPDescriptorBoundsRedirectsResponsesAndCancellation(t *testing.T) {
	slowStarted := make(chan struct{}, 1)
	slowRelease := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case strings.HasPrefix(request.URL.Path, "/loop"):
			http.Redirect(writer, request, "/loop", http.StatusTemporaryRedirect)
		case request.URL.Path == "/oversize":
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write(make([]byte, httpAdapterMaxResponseBytes+1))
		case request.URL.Path == "/slow":
			slowStarted <- struct{}{}
			select {
			case <-request.Context().Done():
			case <-slowRelease:
			}
		}
	}))
	defer server.Close()

	cases := []struct {
		name string
		path string
		code string
	}{
		{name: "redirect limit", path: "/loop", code: "http_redirect_policy"},
		{name: "response cap", path: "/oversize", code: "http_response_too_large"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			runtime, stop := startHTTPRuntimeForTest(t, json.RawMessage(`{"version":"1","url":"`+server.URL+`","method":"POST","path":"`+test.path+`","timeoutSeconds":2}`))
			defer stop()
			effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadPersonText, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetPerson, Conversation: "HTTP:user-1"}, Text: "hello"}, adapterapi.CapabilityOutbound)
			result := runtime.Execute(context.Background(), effect)
			if result.Outcome != adapterapi.EffectAmbiguous || result.Code != test.code {
				t.Fatalf("result = %#v", result)
			}
		})
	}

	runtime, stop := startHTTPRuntimeForTest(t, json.RawMessage(`{"version":"1","url":"`+server.URL+`","method":"POST","path":"/slow","timeoutSeconds":2}`))
	defer stop()
	effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadPersonText, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetPerson, Conversation: "HTTP:user-1"}, Text: "hello"}, adapterapi.CapabilityOutbound)
	ctx, cancel := context.WithCancel(context.Background())
	resultCh := make(chan adapterapi.EffectResult, 1)
	go func() { resultCh <- runtime.Execute(ctx, effect) }()
	<-slowStarted
	cancel()
	select {
	case result := <-resultCh:
		if result.Outcome != adapterapi.EffectAmbiguous || result.Code != "http_provider_ambiguous" {
			t.Fatalf("canceled result = %#v", result)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("canceled HTTP request did not return")
	}
	close(slowRelease)
}

func TestNormalizeProviderHTTPURLPreservesEscapedPath(t *testing.T) {
	got, err := normalizeProviderHTTPURL("https://example.invalid/v1%20beta/", false)
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://example.invalid/v1%20beta" {
		t.Fatalf("normalized URL = %q", got)
	}
}

func TestNormalizeProviderHTTPURLRejectsBareQueryMarker(t *testing.T) {
	if got, err := normalizeProviderHTTPURL("https://example.invalid?", false); err == nil {
		t.Fatalf("URL with an empty query marker was accepted as %q", got)
	}
}

func TestHTTPDescriptorSatisfiesRuntimeContract(t *testing.T) {
	contracttest.Verify(t, contracttest.Case{
		NewDescriptor:                NewHTTPDescriptor,
		Config:                       json.RawMessage(`{"version":"1","url":"https://example.com","method":"POST","path":"/hook","timeoutSeconds":15}`),
		Init:                         adapterapi.RuntimeInit{EndpointID: "http-contract", Generation: 1, DesiredVersion: 1},
		RequireOwnedResourceManifest: true,
	})
}

func startHTTPRuntimeForTest(t *testing.T, raw json.RawMessage) (adapterapi.AdapterRuntime, func()) {
	t.Helper()
	descriptor := NewHTTPDescriptor()
	config, err := descriptor.ValidateConfig(context.Background(), raw)
	if err != nil {
		t.Fatalf("validate config: %v", err)
	}
	runtime, err := descriptor.NewRuntime(adapterapi.RuntimeInit{EndpointID: "http-smoke", Generation: 1, DesiredVersion: 1, Config: config})
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	core := &onebotRuntimeCore{ch: make(chan adapterapi.LifecycleObservation, 8)}
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(context.Background(), core) }()
	core.waitState(t, adapterapi.ObservedStateConnected)
	return runtime, func() {
		t.Helper()
		if err := runtime.Stop(context.Background()); err != nil {
			t.Fatalf("stop runtime: %v", err)
		}
		select {
		case err := <-runDone:
			if err != nil {
				t.Fatalf("run exit: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("HTTP runtime did not stop")
		}
	}
}
