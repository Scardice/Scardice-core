package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"Scardice-core/adapterapi"
)

type failingEndpointActionExecutor struct{}

func (failingEndpointActionExecutor) ExecuteAction(context.Context, adapterapi.ActionRequest) (adapterapi.ActionResult, error) {
	return adapterapi.ActionResult{}, errors.New("provider rejected action")
}

func TestEndpointActionRejectsUnknownActionBeforeRuntime(t *testing.T) {
	setupEndpointAPITest(t)
	ctx, rec := endpointAPIContext(http.MethodPost, "/sd-api/endpoints/missing/actions/not-a-real-action", `{"expectedAggregateVersion":1}`)
	if err := endpointAction(ctx); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), `"unsupported_action"`) {
		t.Fatalf("unknown action status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestEndpointActionFailureFinishesDurableOperation(t *testing.T) {
	service := setupEndpointAPITest(t)
	createBody := `{"adapterKey":"fake","config":{"version":1,"payload":{"channel":"test"}}}`
	createCtx, createRec := endpointAPIContext(http.MethodPost, "/sd-api/endpoints", createBody)
	createCtx.Request().Header.Set("Idempotency-Key", "action-failure-create")
	if err := endpointCreate(createCtx); err != nil || createRec.Code != http.StatusAccepted {
		t.Fatalf("create err=%v status=%d body=%s", err, createRec.Code, createRec.Body.String())
	}
	var created MutationResponse
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	setEndpointAPIActionExecutor(failingEndpointActionExecutor{})
	version := created.Endpoint.Version
	actionRequest := EndpointActionRequest{ExpectedAggregateVersion: &version}
	actionBytes, err := json.Marshal(actionRequest)
	if err != nil {
		t.Fatal(err)
	}
	actionCtx, actionRec := endpointAPIContext(http.MethodPost, "/sd-api/endpoints/"+created.Endpoint.EndpointID+"/actions/request-qr", string(actionBytes))
	actionCtx.Request().Header.Set("Idempotency-Key", "action-failure")
	mutation, err := newAdminMutation(actionCtx, "/endpoints/"+created.Endpoint.EndpointID+"/actions/request-qr", "request-qr", "", actionRequest)
	if err != nil {
		t.Fatal(err)
	}
	if actionErr := endpointAction(actionCtx); actionErr != nil {
		t.Fatal(actionErr)
	}
	if actionRec.Code != http.StatusInternalServerError || !strings.Contains(actionRec.Body.String(), `"internal_error"`) {
		t.Fatalf("failure status=%d body=%s", actionRec.Code, actionRec.Body.String())
	}
	operation, err := service.GetOperation(context.Background(), mutation.operationID)
	if err != nil {
		t.Fatal(err)
	}
	if operation.Status != "failed" || operation.ErrorCode != "action_failed" {
		t.Fatalf("failed action operation=%#v", operation)
	}
}
