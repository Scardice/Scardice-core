package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"Scardice-core/adapterapi"
	"Scardice-core/dice"
	"Scardice-core/endpoint"
	"Scardice-core/eventstore"
)

type endpointAPIDescriptor struct{}

func (endpointAPIDescriptor) Key() adapterapi.AdapterKey { return adapterapi.AdapterKey("fake") }
func (endpointAPIDescriptor) ConfigVersion() uint16      { return 1 }
func (endpointAPIDescriptor) ValidateConfig(_ context.Context, raw json.RawMessage) (adapterapi.ValidatedConfig, error) {
	canonical, err := adapterapi.CanonicalizeJSON(raw)
	if err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	return adapterapi.ValidatedConfig{Version: 1, Canonical: canonical}, nil
}
func (endpointAPIDescriptor) SupportedActions(adapterapi.ValidatedConfig) adapterapi.ActionSet {
	return adapterapi.ActionSet(0).With(adapterapi.ActionKindRequestQRCode)
}
func (endpointAPIDescriptor) Capabilities(adapterapi.ValidatedConfig) adapterapi.CapabilitySet {
	return adapterapi.CapabilityLifecycle | adapterapi.CapabilityActions
}
func (endpointAPIDescriptor) NewRuntime(adapterapi.RuntimeInit) (adapterapi.AdapterRuntime, error) {
	return nil, errors.New("runtime construction is not used by API tests")
}

type endpointAPITestKeySource struct{}

func (endpointAPITestKeySource) IndexRootID(context.Context) (string, error) {
	return "api-test-index-v1", nil
}
func (endpointAPITestKeySource) IndexRootMaterial(context.Context) ([]byte, error) {
	return []byte("01234567890123456789012345678901"), nil
}
func (endpointAPITestKeySource) CurrentEncryptionRoot(context.Context) (eventstore.EncryptionRoot, error) {
	return eventstore.EncryptionRoot{ID: "api-test-root-v1", Material: []byte("abcdefghijklmnopqrstuvwxyz123456")}, nil
}
func (endpointAPITestKeySource) EncryptionRoot(_ context.Context, id string) ([]byte, error) {
	if id != "api-test-root-v1" {
		return nil, eventstore.ErrKeyUnavailable
	}
	return []byte("abcdefghijklmnopqrstuvwxyz123456"), nil
}

type endpointAPIActionExecutor struct{}

func (endpointAPIActionExecutor) ExecuteAction(context.Context, adapterapi.ActionRequest) (adapterapi.ActionResult, error) {
	return adapterapi.ActionResult{
		ResultCode: "qr-ready",
		Artifact:   &adapterapi.ActionArtifact{MediaType: "text/plain", SafeFilename: "qr.txt", Plaintext: []byte("qr-secret")},
	}, nil
}

type endpointAPITestApplication struct {
	service  *endpoint.Service
	executor endpoint.ActionExecutor
}

func (a *endpointAPITestApplication) endpointService() *endpoint.Service {
	return a.service
}

func (a *endpointAPITestApplication) Execute(ctx context.Context, command endpoint.Command) (endpoint.Result, error) {
	return a.service.Execute(ctx, command)
}

func (a *endpointAPITestApplication) ExecuteAction(ctx context.Context, request adapterapi.ActionRequest) (adapterapi.ActionResult, error) {
	if a.executor == nil {
		return adapterapi.ActionResult{}, errors.New("endpoint action executor is unavailable")
	}
	return a.executor.ExecuteAction(ctx, request)
}

func setEndpointAPIActionExecutor(executor endpoint.ActionExecutor) {
	endpointServiceState.Lock()
	defer endpointServiceState.Unlock()
	application, ok := endpointServiceState.application.(*endpointAPITestApplication)
	if !ok {
		panic("endpoint API test application is not registered")
	}
	application.executor = executor
}

func newEndpointAPITestService(t *testing.T) (*endpoint.Service, *eventstore.Database) {
	t.Helper()
	db, err := eventstore.OpenDatabase(context.Background(), eventstore.DatabaseConfig{
		Type:             "sqlite",
		DSN:              filepath.Join(t.TempDir(), "endpoint-api.db"),
		KeySource:        endpointAPITestKeySource{},
		DatabaseIdentity: "endpoint-api-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	store := eventstore.NewStore(db)
	registry := endpoint.NewRegistry()
	if err := registry.Register(endpointAPIDescriptor{}); err != nil {
		db.Close()
		t.Fatal(err)
	}
	service := endpoint.NewService(store, registry)
	if service.InitError != nil {
		db.Close()
		t.Fatal(service.InitError)
	}
	return service, db
}

const endpointAPITestSessionToken = "api-test-ui-session"

func setupEndpointAPITest(t *testing.T) *endpoint.Service {
	t.Helper()
	t.Setenv("SCARDICE_ADMIN_TOKEN", "api-test-secret")
	t.Setenv("SCARDICE_ADMIN_PRINCIPAL_ID", "api-test-principal")
	t.Setenv("SCARDICE_ADMIN_ORIGINS", "")
	ResetAdminAuthForTests()

	service, db := newEndpointAPITestService(t)
	registerEndpointApplication(&endpointAPITestApplication{service: service})
	previousDice, previousManager := myDice, dm
	manager := &dice.DiceManager{}
	manager.AccessTokens.Store(endpointAPITestSessionToken, true)
	myDice = &dice.Dice{Parent: manager, DiceMasters: []string{"QQ:master-user"}}
	dm = manager
	t.Cleanup(func() {
		registerEndpointApplication(nil)
		myDice = previousDice
		dm = previousManager
		ResetAdminAuthForTests()
		_ = db.Close()
	})
	return service
}

func TestCommandSecretsForUpdatePreservesUnchangedReferences(t *testing.T) {
	current := adapterapi.ValidatedConfig{SecretRefs: []adapterapi.SecretRef{{Ref: "token", Version: 1}}}
	next := adapterapi.ValidatedConfig{SecretRefs: []adapterapi.SecretRef{{Ref: "token", Version: 1}}}
	inputs, err := commandSecretsForUpdate(next, current, nil)
	if err != nil {
		t.Fatalf("unchanged secret refs rejected: %v", err)
	}
	if inputs != nil {
		t.Fatalf("unchanged secret refs unexpectedly produced secret inputs: %#v", inputs)
	}

	changed := adapterapi.ValidatedConfig{SecretRefs: []adapterapi.SecretRef{{Ref: "new-token", Version: 1}}}
	if _, err := commandSecretsForUpdate(changed, current, nil); !errors.Is(err, endpoint.ErrInvalidConfig) {
		t.Fatalf("changed secret refs error = %v, want invalid config", err)
	}
}

func TestRegisterEndpointBootstrapNilClearsApplicationState(t *testing.T) {
	RegisterEndpointBootstrap(&endpoint.Bootstrap{Service: &endpoint.Service{}, Supervisor: endpoint.NewSupervisor(nil)})
	RegisterEndpointBootstrap(nil)
	if endpointService() != nil || endpointActionExecutor() != nil {
		t.Fatal("bootstrap unregister retained endpoint application state")
	}
	if _, err := endpointExecute(context.Background(), endpoint.Command{}); err == nil {
		t.Fatal("endpoint command used stale service after bootstrap unregister")
	}
}

func endpointAPIContext(method, path, body string) (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set(echo.HeaderAuthorization, "Bearer "+endpointAPITestSessionToken)
	req.Header.Set("Token", endpointAPITestSessionToken)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.RemoteAddr = "127.0.0.1:34001"
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	parts := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
	for index, part := range parts {
		if part == "endpoints" && index+1 < len(parts) && parts[index+1] != "" {
			ctx.SetParamNames("id")
			ctx.SetParamValues(parts[index+1])
			if index+3 < len(parts) && parts[index+2] == "actions" {
				ctx.SetParamNames("id", "action")
				ctx.SetParamValues(parts[index+1], parts[index+3])
			}
			break
		}
		if part == "operations" && index+1 < len(parts) && parts[index+1] != "" {
			ctx.SetParamNames("id")
			ctx.SetParamValues(parts[index+1])
			break
		}
	}
	return ctx, rec
}

func endpointAPIJSON(t *testing.T, rec *httptest.ResponseRecorder) ErrorResponse {
	t.Helper()
	var response ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func TestEndpointCreateIdempotencyAndStrictAuth(t *testing.T) {
	setupEndpointAPITest(t)
	const renewedSessionToken = "api-test-ui-session-renewed"
	myDice.Parent.AccessTokens.Store(renewedSessionToken, true)
	body := `{"adapterKey":"fake","config":{"version":1,"payload":{"channel":"test"}}}`
	ctx, rec := endpointAPIContext(http.MethodPost, "/sd-api/endpoints", body)
	ctx.Request().Header.Set("Idempotency-Key", "create-key")
	if err := endpointCreate(ctx); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusAccepted {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body.String())
	}
	var first MutationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	if first.OperationID == "" || first.Endpoint == nil || first.Endpoint.AdapterKey != "fake" {
		t.Fatalf("create response=%#v", first)
	}
	if strings.Contains(rec.Body.String(), "api-test-secret") {
		t.Fatal("response leaked bearer secret")
	}

	replayCtx, replayRec := endpointAPIContext(http.MethodPost, "/sd-api/endpoints", body)
	replayCtx.Request().Header.Set(echo.HeaderAuthorization, "Bearer "+renewedSessionToken)
	replayCtx.Request().Header.Set("Token", renewedSessionToken)
	replayCtx.Request().Header.Set("Idempotency-Key", "create-key")
	if err := endpointCreate(replayCtx); err != nil {
		t.Fatal(err)
	}
	if replayRec.Code != http.StatusOK {
		t.Fatalf("replay status=%d body=%s", replayRec.Code, replayRec.Body.String())
	}
	var replay MutationResponse
	if err := json.Unmarshal(replayRec.Body.Bytes(), &replay); err != nil {
		t.Fatal(err)
	}
	if replay.OperationID != first.OperationID || replay.Endpoint.EndpointID != first.Endpoint.EndpointID {
		t.Fatalf("replay=%#v first=%#v", replay, first)
	}

	conflictBody := `{"adapterKey":"fake","config":{"version":1,"payload":{"channel":"different"}}}`
	conflictCtx, conflictRec := endpointAPIContext(http.MethodPost, "/sd-api/endpoints", conflictBody)
	conflictCtx.Request().Header.Set("Idempotency-Key", "create-key")
	if err := endpointCreate(conflictCtx); err != nil {
		t.Fatal(err)
	}
	if conflictRec.Code != http.StatusConflict || endpointAPIJSON(t, conflictRec).Code != "idempotency_conflict" {
		t.Fatalf("idempotency conflict status=%d body=%s", conflictRec.Code, conflictRec.Body.String())
	}

	queryCtx, queryRec := endpointAPIContext(http.MethodGet, "/sd-api/endpoints?token=api-test-secret", "")
	_ = endpointList(queryCtx)
	if queryRec.Code != http.StatusUnauthorized || endpointAPIJSON(t, queryRec).Code != "admin_unauthorized" {
		t.Fatalf("query token status=%d body=%s", queryRec.Code, queryRec.Body.String())
	}

	duplicateCtx, duplicateRec := endpointAPIContext(http.MethodGet, "/sd-api/endpoints", "")
	duplicateCtx.Request().Header.Add(echo.HeaderAuthorization, "Bearer api-test-secret")
	_ = endpointList(duplicateCtx)
	if duplicateRec.Code != http.StatusUnauthorized {
		t.Fatalf("duplicate auth status=%d body=%s", duplicateRec.Code, duplicateRec.Body.String())
	}
}
func TestEndpointAPIUsesWebUISessionAndNotMasterRole(t *testing.T) {
	setupEndpointAPITest(t)

	sessionCtx, sessionRec := endpointAPIContext(http.MethodGet, "/sd-api/endpoints", "")
	if err := endpointList(sessionCtx); err != nil {
		t.Fatal(err)
	}
	if sessionRec.Code != http.StatusOK {
		t.Fatalf("authenticated UI session status=%d body=%s", sessionRec.Code, sessionRec.Body.String())
	}

	masterCtx, masterRec := endpointAPIContext(http.MethodGet, "/sd-api/endpoints", "")
	masterCtx.Request().Header.Set(echo.HeaderAuthorization, "Bearer QQ:master-user")
	_ = endpointList(masterCtx)
	if masterRec.Code != http.StatusUnauthorized {
		t.Fatalf("Master without a UI session status=%d body=%s", masterRec.Code, masterRec.Body.String())
	}

	legacyCtx, legacyRec := endpointAPIContext(http.MethodGet, "/sd-api/endpoints", "")
	legacyCtx.Request().Header.Set(echo.HeaderAuthorization, "Bearer api-test-secret")
	_ = endpointList(legacyCtx)
	if legacyRec.Code != http.StatusUnauthorized {
		t.Fatalf("standalone admin token status=%d body=%s", legacyRec.Code, legacyRec.Body.String())
	}
}

func TestEndpointOperationResolveConfirmedSuccess(t *testing.T) {
	service := setupEndpointAPITest(t)
	createBody := `{"adapterKey":"fake","config":{"version":1,"payload":{"channel":"resolve"}}}`
	createCtx, createRec := endpointAPIContext(http.MethodPost, "/sd-api/endpoints", createBody)
	createCtx.Request().Header.Set("Idempotency-Key", "resolve-create")
	if err := endpointCreate(createCtx); err != nil || createRec.Code != http.StatusAccepted {
		t.Fatalf("create err=%v status=%d body=%s", err, createRec.Code, createRec.Body.String())
	}
	var created MutationResponse
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	expectedVersion := created.Endpoint.Version
	enableBody, _ := json.Marshal(EndpointCommandRequest{
		ExpectedAggregateVersion: &expectedVersion,
		IdempotencyKey:           "resolve-enable",
	})
	enableCtx, enableRec := endpointAPIContext(http.MethodPost, "/sd-api/endpoints/"+created.Endpoint.EndpointID+"/enable", string(enableBody))
	enableCtx.Request().Header.Set("Idempotency-Key", "resolve-enable")
	if err := endpointEnable(enableCtx); err != nil || enableRec.Code != http.StatusAccepted {
		t.Fatalf("enable err=%v status=%d body=%s", err, enableRec.Code, enableRec.Body.String())
	}
	var enabled MutationResponse
	if err := json.Unmarshal(enableRec.Body.Bytes(), &enabled); err != nil {
		t.Fatal(err)
	}
	if enabled.Endpoint == nil || enabled.Endpoint.OperationID == "" {
		t.Fatalf("enable response=%#v", enabled)
	}
	if _, err := service.Complete(context.Background(), endpoint.Command{
		EndpointID:      adapterapi.EndpointID(created.Endpoint.EndpointID),
		OperationID:     enabled.Endpoint.OperationID,
		Generation:      enabled.Endpoint.Generation,
		DesiredVersion:  enabled.Endpoint.DesiredVersion,
		CommandID:       "resolve-ambiguous-complete",
		CorrelationID:   "resolve-ambiguous-correlation",
		PrincipalID:     "api-test-principal",
		RequestID:       "resolve-ambiguous-request",
		CompletionState: endpoint.OperationStateAmbiguous,
		ObservedState:   adapterapi.ObservedStateAmbiguous,
	}); err != nil {
		t.Fatal(err)
	}
	current, err := service.Get(context.Background(), adapterapi.EndpointID(created.Endpoint.EndpointID))
	if err != nil {
		t.Fatal(err)
	}
	stored, err := service.GetOperation(context.Background(), enabled.Endpoint.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	resolveBody, _ := json.Marshal(OperationResolveRequest{
		Resolution:               "confirmed-success",
		ExpectedOperationVersion: &stored.Version,
		ExpectedAggregateVersion: &current.Version,
		Confirm:                  true,
		IdempotencyKey:           "resolve-success",
	})
	resolveCtx, resolveRec := endpointAPIContext(http.MethodPost, "/sd-api/operations/"+stored.OperationID+"/resolve", string(resolveBody))
	resolveCtx.Request().Header.Set("Idempotency-Key", "resolve-success")
	if err := operationResolve(resolveCtx); err != nil || resolveRec.Code != http.StatusAccepted {
		t.Fatalf("resolve err=%v status=%d body=%s", err, resolveRec.Code, resolveRec.Body.String())
	}
	var resolved MutationResponse
	if err := json.Unmarshal(resolveRec.Body.Bytes(), &resolved); err != nil {
		t.Fatal(err)
	}
	if resolved.Endpoint == nil || resolved.Endpoint.ObservedState != "connected" || resolved.Endpoint.OperationState != "succeeded" {
		t.Fatalf("resolved endpoint=%#v", *resolved.Endpoint)
	}
}

func TestEndpointAPIOriginBodyAndVersionGuards(t *testing.T) {
	service := setupEndpointAPITest(t)
	createBody := `{"adapterKey":"fake","config":{"version":1,"payload":{"channel":"test"}}}`
	createCtx, createRec := endpointAPIContext(http.MethodPost, "/sd-api/endpoints", createBody)
	createCtx.Request().Header.Set("Idempotency-Key", "origin-create")
	if err := endpointCreate(createCtx); err != nil || createRec.Code != http.StatusAccepted {
		t.Fatalf("create err=%v status=%d body=%s", err, createRec.Code, createRec.Body.String())
	}
	var created MutationResponse
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	originCtx, originRec := endpointAPIContext(http.MethodGet, "/sd-api/endpoints", "")
	originCtx.Request().Host = "admin.example"
	originCtx.Request().Header.Set(echo.HeaderOrigin, "https://evil.example")
	_ = endpointList(originCtx)
	if originRec.Code != http.StatusForbidden || endpointAPIJSON(t, originRec).Code != "origin_not_allowed" {
		t.Fatalf("origin status=%d body=%s", originRec.Code, originRec.Body.String())
	}

	validOriginCtx, validOriginRec := endpointAPIContext(http.MethodGet, "/sd-api/endpoints", "")
	validOriginCtx.Request().Host = "admin.example"
	validOriginCtx.Request().Header.Set(echo.HeaderOrigin, "http://admin.example")
	if err := endpointList(validOriginCtx); err != nil {
		t.Fatal(err)
	}
	if validOriginRec.Code != http.StatusOK {
		t.Fatalf("same origin status=%d body=%s", validOriginRec.Code, validOriginRec.Body.String())
	}

	oversized := `{"adapterKey":"fake","config":{"version":1,"payload":"` + strings.Repeat("x", 1<<20) + `"}}`
	overCtx, overRec := endpointAPIContext(http.MethodPost, "/sd-api/endpoints", oversized)
	overCtx.Request().Header.Set("Idempotency-Key", "oversized")
	if err := endpointCreate(overCtx); err != nil {
		t.Fatal(err)
	}
	if overRec.Code != http.StatusRequestEntityTooLarge || endpointAPIJSON(t, overRec).Code != "body_too_large" {
		t.Fatalf("oversized status=%d body=%s", overRec.Code, overRec.Body.String())
	}

	stale := uint64(99)
	patch := EndpointConfigRequest{Config: EndpointConfigPayload{Version: 1, Payload: json.RawMessage(`{"channel":"next"}`)}, ExpectedAggregateVersion: &stale, IdempotencyKey: "stale-patch"}
	patchBody, _ := json.Marshal(patch)
	patchCtx, patchRec := endpointAPIContext(http.MethodPatch, "/sd-api/endpoints/"+created.Endpoint.EndpointID+"/config", string(patchBody))
	patchCtx.Request().Header.Set("Idempotency-Key", "stale-patch")
	if err := endpointConfigPatch(patchCtx); err != nil {
		t.Fatal(err)
	}
	if patchRec.Code != http.StatusConflict {
		t.Fatalf("stale version status=%d body=%s", patchRec.Code, patchRec.Body.String())
	}

	stored, err := service.GetOperation(context.Background(), created.OperationID)
	if err != nil || stored.PrincipalID != "api-test-principal" {
		t.Fatalf("stored operation=%#v err=%v", stored, err)
	}
}

func TestEndpointAPIActionAndArtifactAreOwnedAndOneTime(t *testing.T) {
	setupEndpointAPITest(t)
	createBody := `{"adapterKey":"fake","config":{"version":1,"payload":{"channel":"test"}}}`
	createCtx, createRec := endpointAPIContext(http.MethodPost, "/sd-api/endpoints", createBody)
	createCtx.Request().Header.Set("Idempotency-Key", "action-create")
	if err := endpointCreate(createCtx); err != nil || createRec.Code != http.StatusAccepted {
		t.Fatalf("create err=%v status=%d body=%s", err, createRec.Code, createRec.Body.String())
	}
	var created MutationResponse
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	setEndpointAPIActionExecutor(endpointAPIActionExecutor{})
	version := created.Endpoint.Version
	actionBody := EndpointActionRequest{ExpectedAggregateVersion: &version, IdempotencyKey: "qr-action"}
	rawAction, _ := json.Marshal(actionBody)
	actionCtx, actionRec := endpointAPIContext(http.MethodPost, "/sd-api/endpoints/"+created.Endpoint.EndpointID+"/actions/request-qr", string(rawAction))
	actionCtx.Request().Header.Set("Idempotency-Key", "qr-action")
	if err := endpointAction(actionCtx); err != nil || actionRec.Code != http.StatusAccepted {
		t.Fatalf("action err=%v status=%d body=%s", err, actionRec.Code, actionRec.Body.String())
	}
	var actionResponse ActionResponse
	if err := json.Unmarshal(actionRec.Body.Bytes(), &actionResponse); err != nil {
		t.Fatal(err)
	}
	if actionResponse.Operation.Status != "succeeded" || actionResponse.Operation.ArtifactID == "" {
		t.Fatalf("action response=%#v", actionResponse)
	}
	if strings.Contains(actionRec.Body.String(), "qr-secret") {
		t.Fatal("action response leaked artifact bytes")
	}

	artifactCtx, artifactRec := endpointAPIContext(http.MethodGet, "/sd-api/operations/"+actionResponse.OperationID+"/artifact", "")
	if err := operationArtifact(artifactCtx); err != nil {
		t.Fatal(err)
	}
	if artifactRec.Code != http.StatusOK || artifactRec.Body.String() != "qr-secret" || artifactRec.Header().Get(echo.HeaderCacheControl) != "no-store" {
		t.Fatalf("artifact status=%d body=%q headers=%v", artifactRec.Code, artifactRec.Body.String(), artifactRec.Header())
	}
	if !strings.HasPrefix(artifactRec.Header().Get(echo.HeaderContentDisposition), "attachment") {
		t.Fatalf("content disposition=%q", artifactRec.Header().Get(echo.HeaderContentDisposition))
	}

	secondCtx, secondRec := endpointAPIContext(http.MethodGet, "/sd-api/operations/"+actionResponse.OperationID+"/artifact", "")
	if err := operationArtifact(secondCtx); err != nil {
		t.Fatal(err)
	}
	if secondRec.Code != http.StatusGone || endpointAPIJSON(t, secondRec).Code != "artifact_gone" {
		t.Fatalf("second artifact status=%d body=%s", secondRec.Code, secondRec.Body.String())
	}
}
func TestEndpointListOmitsDeletedEndpointsAndPreservesTombstoneReads(t *testing.T) {
	service := setupEndpointAPITest(t)
	e := echo.New()
	e.GET("/sd-api/endpoints", endpointList)
	listServer := httptest.NewServer(e)
	t.Cleanup(listServer.Close)
	readEndpointList := func() []EndpointView {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, listServer.URL+"/sd-api/endpoints", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+endpointAPITestSessionToken)
		req.Header.Set("Token", endpointAPITestSessionToken)
		resp, err := listServer.Client().Do(req)
		if err != nil {
			t.Fatalf("GET endpoint list over TCP: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET endpoint list over TCP status=%d", resp.StatusCode)
		}
		var views []EndpointView
		if err := json.NewDecoder(resp.Body).Decode(&views); err != nil {
			t.Fatal(err)
		}
		return views
	}

	createEndpoint := func(channel, idempotencyKey string) EndpointView {
		t.Helper()
		body := `{"adapterKey":"fake","config":{"version":1,"payload":{"channel":"` + channel + `"}}}`
		ctx, rec := endpointAPIContext(http.MethodPost, "/sd-api/endpoints", body)
		ctx.Request().Header.Set("Idempotency-Key", idempotencyKey)
		if err := endpointCreate(ctx); err != nil || rec.Code != http.StatusAccepted {
			t.Fatalf("create endpoint err=%v status=%d body=%s", err, rec.Code, rec.Body.String())
		}
		var response MutationResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.Endpoint == nil {
			t.Fatalf("create response has no endpoint: %#v", response)
		}
		return *response.Endpoint
	}
	complete := func(view EndpointView, commandID string, observed adapterapi.ObservedState) {
		t.Helper()
		if _, err := service.Complete(context.Background(), endpoint.Command{
			CommandID:       commandID,
			CorrelationID:   commandID,
			OperationID:     view.OperationID,
			EndpointID:      adapterapi.EndpointID(view.EndpointID),
			Generation:      view.Generation,
			DesiredVersion:  view.DesiredVersion,
			PrincipalID:     "api-test-principal",
			CompletionState: endpoint.OperationStateSucceeded,
			ObservedState:   observed,
		}); err != nil {
			t.Fatalf("complete endpoint %s operation: %v", view.EndpointID, err)
		}
	}
	currentVersion := func(id string) uint64 {
		t.Helper()
		view, err := service.Get(context.Background(), adapterapi.EndpointID(id))
		if err != nil {
			t.Fatalf("get endpoint %s aggregate version: %v", id, err)
		}
		return view.Version
	}

	lifecycleMutation := func(path, key string, version uint64, confirm bool, handler func(echo.Context) error) MutationResponse {
		t.Helper()
		body, err := json.Marshal(EndpointCommandRequest{
			ExpectedAggregateVersion: &version,
			IdempotencyKey:           key,
			Confirm:                  confirm,
		})
		if err != nil {
			t.Fatal(err)
		}
		ctx, rec := endpointAPIContext(http.MethodPost, path, string(body))
		ctx.Request().Header.Set("Idempotency-Key", key)
		if err := handler(ctx); err != nil || rec.Code != http.StatusAccepted {
			t.Fatalf("lifecycle mutation %s err=%v status=%d body=%s", path, err, rec.Code, rec.Body.String())
		}
		var response MutationResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.Endpoint == nil {
			t.Fatalf("lifecycle mutation %s has no endpoint: %#v", path, response)
		}
		return response
	}

	deleted := createEndpoint("deleted", "deleted-create")
	survivor := createEndpoint("survivor", "survivor-create")
	enabled := lifecycleMutation("/sd-api/endpoints/"+survivor.EndpointID+"/enable", "survivor-enable", survivor.Version, false, endpointEnable)
	complete(*enabled.Endpoint, "survivor-enable-complete", adapterapi.ObservedStateConnected)

	enabledForDelete := lifecycleMutation("/sd-api/endpoints/"+deleted.EndpointID+"/enable", "deleted-enable", deleted.Version, false, endpointEnable)
	complete(*enabledForDelete.Endpoint, "deleted-enable-complete", adapterapi.ObservedStateConnected)
	disabled := lifecycleMutation("/sd-api/endpoints/"+deleted.EndpointID+"/disable", "deleted-disable", currentVersion(deleted.EndpointID), false, endpointDisable)
	complete(*disabled.Endpoint, "deleted-disable-complete", adapterapi.ObservedStateStopped)
	removing := lifecycleMutation("/sd-api/endpoints/"+deleted.EndpointID, "deleted-remove", currentVersion(deleted.EndpointID), true, endpointDelete)
	if removing.Endpoint.DesiredState != string(endpoint.DesiredStateRemoving) || removing.Endpoint.OperationState != string(endpoint.OperationStatePending) {
		t.Fatalf("delete request did not remain in progress: %#v", removing.Endpoint)
	}
	pendingList := readEndpointList()
	pendingDeleteVisible := false
	for _, view := range pendingList {
		pendingDeleteVisible = pendingDeleteVisible || (view.EndpointID == deleted.EndpointID && view.DesiredState == string(endpoint.DesiredStateRemoving))
	}
	if len(pendingList) != 2 || !pendingDeleteVisible {
		t.Fatalf("pending deletion missing from active endpoint list: %#v", pendingList)
	}
	complete(*removing.Endpoint, "deleted-remove-complete", adapterapi.ObservedStateStopped)
	if _, err := service.Resolve(context.Background(), endpoint.Command{
		CommandID:     "deleted-remove-resolve",
		CorrelationID: "deleted-remove-resolve",
		OperationID:   removing.Endpoint.OperationID,
		EndpointID:    adapterapi.EndpointID(deleted.EndpointID),
		Generation:    removing.Endpoint.Generation,
		PrincipalID:   "api-test-principal",
	}); err != nil {
		t.Fatalf("resolve completed endpoint deletion: %v", err)
	}

	listed := readEndpointList()
	if len(listed) != 1 || listed[0].EndpointID != survivor.EndpointID || listed[0].DesiredState != string(endpoint.DesiredStateEnabled) {
		t.Fatalf("active endpoint list=%#v, want only enabled endpoint %q", listed, survivor.EndpointID)
	}

	getCtx, getRec := endpointAPIContext(http.MethodGet, "/sd-api/endpoints/"+deleted.EndpointID, "")
	if err := endpointGet(getCtx); err != nil || getRec.Code != http.StatusOK {
		t.Fatalf("get deleted endpoint err=%v status=%d body=%s", err, getRec.Code, getRec.Body.String())
	}
	var deletedRead EndpointView
	if err := json.Unmarshal(getRec.Body.Bytes(), &deletedRead); err != nil {
		t.Fatal(err)
	}
	if deletedRead.EndpointID != deleted.EndpointID || deletedRead.DesiredState != string(endpoint.DesiredStateDeleted) || deletedRead.ObservedState != "stopped" || deletedRead.OperationState != string(endpoint.OperationStateIdle) {
		t.Fatalf("deleted endpoint read=%#v", deletedRead)
	}

	operationCtx, operationRec := endpointAPIContext(http.MethodGet, "/sd-api/operations/"+removing.OperationID, "")
	if err := operationGet(operationCtx); err != nil || operationRec.Code != http.StatusOK {
		t.Fatalf("get deletion operation err=%v status=%d body=%s", err, operationRec.Code, operationRec.Body.String())
	}
	var operation OperationView
	if err := json.Unmarshal(operationRec.Body.Bytes(), &operation); err != nil {
		t.Fatal(err)
	}
	if operation.Status != string(endpoint.OperationStateSucceeded) || operation.Kind != "endpoint.deleted" || operation.ResultCode != "endpoint.deleted" || operation.ResourceID != deleted.EndpointID {
		t.Fatalf("deletion operation read=%#v", operation)
	}
}

func TestEndpointViewDTOPreservesImportedIdentityAndStatistics(t *testing.T) {
	view := endpointViewDTO(context.Background(), endpoint.EndpointView{
		EndpointID:  "endpoint-1",
		DisplayName: "Legacy Bot",
		ProviderID:  "QQ:12345",
		AdapterKey:  "fake",
		Statistics: endpoint.Statistics{
			GroupCount: 7, CommandCount: 42, LastCommandAt: 12345, OnlineSeconds: 678,
		},
	})
	if view.DisplayName != "Legacy Bot" || view.ProviderID != "QQ:12345" ||
		view.GroupNum != 7 || view.CmdExecutedNum != 42 ||
		view.CmdExecutedLastTime != 12345 || view.OnlineTotalTime != 678 {
		t.Fatalf("endpoint DTO lost identity or statistics: %#v", view)
	}
}
