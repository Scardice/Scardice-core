package dice

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"Scardice-core/dice/sealpack"
	"Scardice-core/utils/jsengine/services"
)

type nativeFetchTestSink struct {
	complete chan services.Response
}

func (s *nativeFetchTestSink) Event(services.RequestID, services.Response) error { return nil }
func (s *nativeFetchTestSink) Complete(_ services.RequestID, response services.Response) error {
	s.complete <- response
	return nil
}
func (s *nativeFetchTestSink) Close(_ services.RequestID, response services.Response) error {
	s.complete <- response
	return nil
}

func TestNativeFetchServiceRequestAndResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.Header.Get("X-Test") != "native-fetch" {
			t.Errorf("request = %s %s, X-Test=%q", request.Method, request.URL.Path, request.Header.Get("X-Test"))
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
			return
		}
		if string(body) != "request body" {
			t.Errorf("request body = %q, want %q", body, "request body")
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusCreated)
		_, _ = writer.Write([]byte(`{"message":"native fetch"}`))
	}))
	defer server.Close()

	d := &Dice{}
	service := newNativeFetchService(d, nil)
	sink := &nativeFetchTestSink{complete: make(chan services.Response, 1)}
	if err := service.Start(services.AsyncCall{
		ID: 1,
		Call: services.Call{Request: services.Request{
			Service:   services.Fetch,
			Operation: services.OpFetchRequest,
			String:    `{"url":"` + server.URL + `","method":"POST","headers":{"X-Test":"native-fetch"}}`,
			Bytes:     []byte("request body"),
		}},
		Sink: sink,
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case response := <-sink.complete:
		if response.Status != services.StatusOK || response.Int64 != http.StatusCreated ||
			string(response.Bytes) != `{"message":"native fetch"}` {
			t.Fatalf("fetch response = %#v, want created JSON response", response)
		}
	case <-time.After(time.Second):
		t.Fatal("fetch service did not complete")
	}
}
func TestNativeFetchRedirectUsesRequestExecutionContext(t *testing.T) {
	const packageID = "author/redirect-permission"
	d := newPermissionTestDice(t, packageID, sealpack.Permissions{
		Network:      true,
		NetworkHosts: []string{"127.0.0.1"},
	})
	redirectTarget := ""
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Location", redirectTarget)
		writer.WriteHeader(http.StatusFound)
	}))
	defer server.Close()
	redirectTarget = strings.Replace(server.URL, "127.0.0.1", "localhost", 1)

	executionContext := &jsExecutionContext{Plugin: &ExtInfo{
		Source: &JsScriptInfo{PackageID: packageID},
	}}
	service := newNativeFetchService(d, nil)
	sink := &nativeFetchTestSink{complete: make(chan services.Response, 1)}
	if err := service.Start(services.AsyncCall{
		ID: 1,
		Call: services.Call{
			Request: services.Request{
				Service:   services.Fetch,
				Operation: services.OpFetchRequest,
				String:    `{"url":"` + server.URL + `"}`,
			},
			Context: executionContext,
		},
		Sink: sink,
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case response := <-sink.complete:
		if response.Status != services.StatusInternal ||
			!strings.Contains(response.String, "network_hosts") {
			t.Fatalf("redirect response = %#v, want network_hosts denial", response)
		}
	case <-time.After(time.Second):
		t.Fatal("redirecting fetch did not complete")
	}
}

func TestReadNativeFetchBodyEnforcesLimit(t *testing.T) {
	body := bytes.Repeat([]byte("x"), 1024*1024+1)
	if _, err := readNativeFetchBody(bytes.NewReader(body), 1); err == nil {
		t.Fatal("readNativeFetchBody() error = nil, want response size error")
	}
}
