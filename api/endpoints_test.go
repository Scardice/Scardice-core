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
func (endpointAPIDescriptor) NewRuntime(adapterapi.RuntimeInit) (adapterapi.AdapterRuntime, error) {
	return nil, errors.New("runtime construction is not used by API tests")
}

type endpointAPITestCodec struct{}

func (endpointAPITestCodec) Encrypt(_ context.Context, plaintext []byte) ([]byte, []byte, string, error) {
	return append([]byte("sealed:"), plaintext...), []byte("nonce"), "test-key", nil
}
func (endpointAPITestCodec) Decrypt(_ context.Context, ciphertext, _ []byte, _ string) ([]byte, error) {
	if !strings.HasPrefix(string(ciphertext), "sealed:") {
		return nil, errors.New("invalid ciphertext")
	}
	return append([]byte(nil), ciphertext[len("sealed:"):]...), nil
}

type endpointAPIActionExecutor struct{}

func (endpointAPIActionExecutor) ExecuteAction(context.Context, adapterapi.ActionRequest) (adapterapi.ActionResult, error) {
	return adapterapi.ActionResult{
		ResultCode: "qr-ready",
		Artifact:   &adapterapi.ActionArtifact{MediaType: "text/plain", SafeFilename: "qr.txt", Plaintext: []byte("qr-secret")},
	}, nil
}

func newEndpointAPITestService(t *testing.T) (*endpoint.Service, *eventstore.Database) {
	t.Helper()
	db, err := eventstore.OpenDatabase(context.Background(), eventstore.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "endpoint-api.db")})
	if err != nil {
		t.Fatal(err)
	}
	store := eventstore.NewStore(db, eventstore.WithPayloadCodec(endpointAPITestCodec{}))
	service := endpoint.NewService(store, map[adapterapi.AdapterKey]adapterapi.Descriptor{
		adapterapi.AdapterKey("fake"): endpointAPIDescriptor{},
	})
	if service.InitError != nil {
		db.Close()
		t.Fatal(service.InitError)
	}
	return service, db
}

func setupEndpointAPITest(t *testing.T) *endpoint.Service {
	t.Helper()
	service, db := newEndpointAPITestService(t)
	RegisterEndpointService(service)
	RegisterEndpointActionExecutor(nil)
	if err := ConfigureAdminAuth("api-test-principal", "api-test-secret", nil); err != nil {
		db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		RegisterEndpointActionExecutor(nil)
		RegisterEndpointService(nil)
		ResetAdminAuthForTests()
		_ = db.Close()
	})
	return service
}

func endpointAPIContext(method, path, body string) (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set(echo.HeaderAuthorization, "Bearer api-test-secret")
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
	RegisterEndpointActionExecutor(endpointAPIActionExecutor{})
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
