package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"Scardice-core/adapterapi"
	"Scardice-core/endpoint"
)

type endpointAPIPendingStopDescriptor struct {
	mu       sync.Mutex
	runtimes []*endpointAPIPendingStopRuntime
}

func (d *endpointAPIPendingStopDescriptor) Key() adapterapi.AdapterKey { return "fake" }
func (d *endpointAPIPendingStopDescriptor) ConfigVersion() uint16      { return 1 }
func (d *endpointAPIPendingStopDescriptor) ValidateConfig(_ context.Context, raw json.RawMessage) (adapterapi.ValidatedConfig, error) {
	canonical, err := adapterapi.CanonicalizeJSON(raw)
	if err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	return adapterapi.ValidatedConfig{Version: 1, Canonical: canonical}, nil
}
func (d *endpointAPIPendingStopDescriptor) SupportedActions(adapterapi.ValidatedConfig) adapterapi.ActionSet {
	return 0
}
func (d *endpointAPIPendingStopDescriptor) Capabilities(adapterapi.ValidatedConfig) adapterapi.CapabilitySet {
	return adapterapi.CapabilityLifecycle
}
func (d *endpointAPIPendingStopDescriptor) Diagnostics(context.Context, adapterapi.ValidatedConfig) (adapterapi.DiagnosticReport, error) {
	return adapterapi.DiagnosticReport{Entries: []adapterapi.DiagnosticEntry{{Severity: adapterapi.DiagnosticInfo, Code: "descriptor.status", Message: "available"}}}, nil
}
func (d *endpointAPIPendingStopDescriptor) NewRuntime(init adapterapi.RuntimeInit) (adapterapi.AdapterRuntime, error) {
	if init.Generation == 0 || init.DesiredVersion == 0 {
		return nil, errors.New("endpoint API test runtime requires a lifecycle fence")
	}
	runtime := &endpointAPIPendingStopRuntime{
		startGeneration:     init.Generation,
		startDesiredVersion: init.DesiredVersion,
		runStarted:          make(chan struct{}),
		allowStart:          make(chan struct{}),
		connected:           make(chan error, 1),
		stopCalled:          make(chan struct{}),
		allowStop:           make(chan struct{}),
	}
	d.mu.Lock()
	d.runtimes = append(d.runtimes, runtime)
	d.mu.Unlock()
	return runtime, nil
}
func (d *endpointAPIPendingStopDescriptor) runtime(index int) *endpointAPIPendingStopRuntime {
	d.mu.Lock()
	defer d.mu.Unlock()
	if index < 0 || index >= len(d.runtimes) {
		return nil
	}
	return d.runtimes[index]
}
func (d *endpointAPIPendingStopDescriptor) releaseStops() {
	d.mu.Lock()
	runtimes := append([]*endpointAPIPendingStopRuntime(nil), d.runtimes...)
	d.mu.Unlock()
	for _, runtime := range runtimes {
		runtime.releaseStop()
	}
}

type endpointAPIPendingStopRuntime struct {
	startGeneration     uint64
	startDesiredVersion uint64
	runStarted          chan struct{}
	allowStart          chan struct{}
	connected           chan error
	stopCalled          chan struct{}
	allowStop           chan struct{}
	startOnce           sync.Once
	stopCalledOnce      sync.Once
	stopOnce            sync.Once
}

func (r *endpointAPIPendingStopRuntime) Run(ctx context.Context, core adapterapi.CorePort) error {
	close(r.runStarted)
	select {
	case <-r.allowStart:
	case <-ctx.Done():
		return ctx.Err()
	}
	err := core.ReportObservation(ctx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateConnected})
	r.connected <- err
	if err != nil {
		return err
	}
	<-ctx.Done()
	return ctx.Err()
}

func (r *endpointAPIPendingStopRuntime) Stop(ctx context.Context) error {
	r.stopCalledOnce.Do(func() { close(r.stopCalled) })
	select {
	case <-r.allowStop:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *endpointAPIPendingStopRuntime) Capabilities() adapterapi.CapabilitySet {
	return adapterapi.CapabilityLifecycle
}
func (r *endpointAPIPendingStopRuntime) Execute(context.Context, adapterapi.OutboundEffect) adapterapi.EffectResult {
	return adapterapi.UnsupportedResult("controlled-stop-test")
}
func (r *endpointAPIPendingStopRuntime) Diagnostics(context.Context) adapterapi.DiagnosticReport {
	return adapterapi.DiagnosticReport{Entries: []adapterapi.DiagnosticEntry{{Severity: adapterapi.DiagnosticInfo, Code: "transport.reconnect_attempts", Message: "Client reconnect attempts: 3"}}}
}
func (r *endpointAPIPendingStopRuntime) allowStartNow() {
	r.startOnce.Do(func() { close(r.allowStart) })
}
func (r *endpointAPIPendingStopRuntime) releaseStop() {
	r.stopOnce.Do(func() { close(r.allowStop) })
}

func endpointAPIPendingStopRequest(client *http.Client, baseURL, method, path, body, idempotencyKey string) (int, []byte, error) {
	var requestBody io.Reader
	if body != "" {
		requestBody = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, baseURL+path, requestBody)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set(echo.HeaderAuthorization, "Bearer "+endpointAPITestSessionToken)
	req.Header.Set("Token", endpointAPITestSessionToken)
	if body != "" {
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	}
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(resp.Body)
	return resp.StatusCode, responseBody, err
}

func runEndpointAPIPendingStopLifecycle(t *testing.T, removeEnabled bool) {
	t.Helper()
	storeService := setupEndpointAPITest(t)
	descriptor := &endpointAPIPendingStopDescriptor{}
	bootstrap, err := endpoint.NewBootstrap(storeService.Store, nil, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	RegisterEndpointBootstrap(bootstrap)

	e := echo.New()
	e.POST("/sd-api/endpoints", endpointCreate)
	e.POST("/sd-api/endpoints/:id/enable", endpointEnable)
	e.POST("/sd-api/endpoints/:id/disable", endpointDisable)
	e.DELETE("/sd-api/endpoints/:id", endpointDelete)
	e.GET("/sd-api/endpoints/:id", endpointGet)
	e.GET("/sd-api/endpoints/:id/diagnostics", endpointDiagnostics)
	e.GET("/sd-api/operations/:id", operationGet)
	server := httptest.NewServer(e)
	t.Cleanup(func() {
		descriptor.releaseStops()
		server.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := bootstrap.Shutdown(ctx); err != nil {
			t.Errorf("shutdown endpoint bootstrap: %v", err)
		}
	})
	client := server.Client()

	createStatus, createBody, err := endpointAPIPendingStopRequest(client, server.URL, http.MethodPost, "/sd-api/endpoints", `{"adapterKey":"fake","config":{"version":1,"payload":{"channel":"stop-lifecycle"}}}`, "stop-lifecycle-create")
	if err != nil || createStatus != http.StatusAccepted {
		t.Fatalf("create status=%d err=%v body=%s", createStatus, err, createBody)
	}
	var created MutationResponse
	if err := json.Unmarshal(createBody, &created); err != nil {
		t.Fatal(err)
	}
	if created.Endpoint == nil || created.Endpoint.EndpointID == "" {
		t.Fatalf("create response=%#v", created)
	}

	enableVersion := created.Endpoint.Version
	enableBody, err := json.Marshal(EndpointCommandRequest{ExpectedAggregateVersion: &enableVersion, IdempotencyKey: "stop-lifecycle-enable"})
	if err != nil {
		t.Fatal(err)
	}
	enableStatus, enableResponseBody, err := endpointAPIPendingStopRequest(client, server.URL, http.MethodPost, "/sd-api/endpoints/"+created.Endpoint.EndpointID+"/enable", string(enableBody), "stop-lifecycle-enable")
	if err != nil || enableStatus != http.StatusAccepted {
		t.Fatalf("enable status=%d err=%v body=%s", enableStatus, err, enableResponseBody)
	}
	runtime := descriptor.runtime(0)
	if runtime == nil {
		t.Fatal("enable did not construct the controlled adapter runtime")
	}
	select {
	case <-runtime.runStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("enabled adapter runtime did not start")
	}
	runtime.allowStartNow()
	select {
	case err := <-runtime.connected:
		if err != nil {
			t.Fatalf("persist connected observation: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("connected observation was not reported")
	}

	readEndpoint := func() EndpointView {
		t.Helper()
		status, body, err := endpointAPIPendingStopRequest(client, server.URL, http.MethodGet, "/sd-api/endpoints/"+created.Endpoint.EndpointID, "", "")
		if err != nil || status != http.StatusOK {
			t.Fatalf("get endpoint status=%d err=%v body=%s", status, err, body)
		}
		var view EndpointView
		if err := json.Unmarshal(body, &view); err != nil {
			t.Fatal(err)
		}
		return view
	}
	connected := readEndpoint()
	if connected.DesiredState != string(endpoint.DesiredStateEnabled) || connected.ObservedState != "connected" || connected.OperationState != string(endpoint.OperationStateSucceeded) {
		t.Fatalf("endpoint was not durably connected before stop: %#v", connected)
	}
	if connected.Generation != runtime.startGeneration || connected.DesiredVersion != runtime.startDesiredVersion {
		t.Fatalf("connected view lost worker start fence: runtime generation=%d desiredVersion=%d view=%#v", runtime.startGeneration, runtime.startDesiredVersion, connected)
	}
	readDiagnostics := func() DiagnosticView {
		t.Helper()
		status, body, err := endpointAPIPendingStopRequest(client, server.URL, http.MethodGet, "/sd-api/endpoints/"+created.Endpoint.EndpointID+"/diagnostics", "", "")
		if err != nil || status != http.StatusOK {
			t.Fatalf("get diagnostics status=%d err=%v body=%s", status, err, body)
		}
		var view DiagnosticView
		if err := json.Unmarshal(body, &view); err != nil {
			t.Fatal(err)
		}
		return view
	}
	diagnostics := readDiagnostics()
	if len(diagnostics.Entries) != 2 || diagnostics.Entries[0].Code != "descriptor.status" || diagnostics.Entries[1].Code != "transport.reconnect_attempts" || diagnostics.Entries[1].Message != "Client reconnect attempts: 3" {
		t.Fatalf("running endpoint diagnostics=%#v", diagnostics)
	}

	version := connected.Version
	request := EndpointCommandRequest{ExpectedAggregateVersion: &version, IdempotencyKey: "stop-lifecycle-terminal", Confirm: removeEnabled}
	mutationBody, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	method, path, pendingDesired, completedDesired := http.MethodPost, "/disable", string(endpoint.DesiredStateDisabled), string(endpoint.DesiredStateDisabled)
	if removeEnabled {
		method, path, pendingDesired, completedDesired = http.MethodDelete, "", string(endpoint.DesiredStateRemoving), string(endpoint.DesiredStateDeleted)
	}
	type mutationResult struct {
		status int
		body   []byte
		err    error
	}
	mutationDone := make(chan mutationResult, 1)
	go func() {
		status, body, err := endpointAPIPendingStopRequest(client, server.URL, method, "/sd-api/endpoints/"+created.Endpoint.EndpointID+path, string(mutationBody), "stop-lifecycle-terminal")
		mutationDone <- mutationResult{status: status, body: body, err: err}
	}()
	select {
	case <-runtime.stopCalled:
	case <-time.After(3 * time.Second):
		t.Fatal("supervisor did not call the runtime Stop method")
	}
	pending := readEndpoint()
	if pending.DesiredState != pendingDesired || pending.OperationState != string(endpoint.OperationStatePending) || pending.ObservedState != "connected" {
		t.Fatalf("endpoint state before Stop completion=%#v", pending)
	}
	if pending.Generation != runtime.startGeneration || pending.DesiredVersion <= runtime.startDesiredVersion {
		t.Fatalf("stop command did not advance beyond the worker start fence: start=%d/%d pending=%#v", runtime.startGeneration, runtime.startDesiredVersion, pending)
	}
	diagnostics = readDiagnostics()
	if len(diagnostics.Entries) != 1 || diagnostics.Entries[0].Code != "descriptor.status" {
		t.Fatalf("stopping endpoint diagnostics=%#v", diagnostics)
	}

	runtime.releaseStop()
	var mutation mutationResult
	select {
	case mutation = <-mutationDone:
	case <-time.After(3 * time.Second):
		t.Fatal("lifecycle API request did not return after Stop completed")
	}
	if mutation.err != nil || mutation.status != http.StatusAccepted {
		t.Fatalf("lifecycle status=%d err=%v body=%s", mutation.status, mutation.err, mutation.body)
	}
	var accepted MutationResponse
	if err := json.Unmarshal(mutation.body, &accepted); err != nil {
		t.Fatal(err)
	}
	if accepted.OperationID == "" {
		t.Fatalf("lifecycle response omitted operation ID: %s", mutation.body)
	}

	completed := readEndpoint()
	if completed.DesiredState != completedDesired || completed.ObservedState != "stopped" {
		t.Fatalf("endpoint did not persist the successful stop: %#v", completed)
	}
	if !removeEnabled && completed.OperationState != string(endpoint.OperationStateSucceeded) {
		t.Fatalf("disable operation remained unfinished after runtime Stop returned nil: %#v", completed)
	}
	if removeEnabled && completed.OperationState != string(endpoint.OperationStateIdle) {
		t.Fatalf("enabled removal did not resolve to terminal deleted state: %#v", completed)
	}

	operationStatus, operationBody, err := endpointAPIPendingStopRequest(client, server.URL, http.MethodGet, "/sd-api/operations/"+accepted.OperationID, "", "")
	if err != nil || operationStatus != http.StatusOK {
		t.Fatalf("get operation status=%d err=%v body=%s", operationStatus, err, operationBody)
	}
	var operation OperationView
	if err := json.Unmarshal(operationBody, &operation); err != nil {
		t.Fatal(err)
	}
	if operation.Status != string(endpoint.OperationStateSucceeded) || operation.ResourceID != created.Endpoint.EndpointID {
		t.Fatalf("stop operation remained unfinished: %#v", operation)
	}
	if removeEnabled && (operation.Kind != "endpoint.deleted" || operation.ResultCode != "endpoint.deleted") {
		t.Fatalf("enabled remove operation=%#v", operation)
	}
}

func TestEndpointDisablePersistsCompletionAfterWorkerStop(t *testing.T) {
	runEndpointAPIPendingStopLifecycle(t, false)
}

func TestEndpointEnabledRemovePersistsCompletionAfterWorkerStop(t *testing.T) {
	runEndpointAPIPendingStopLifecycle(t, true)
}
