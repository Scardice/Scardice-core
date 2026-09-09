package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	"Scardice-core/adapterapi"
	"Scardice-core/endpoint"
	"Scardice-core/eventstore"
)

type EndpointActionRequest struct {
	SMSCode                  string  `json:"smsCode,omitempty"`
	Captcha                  string  `json:"captcha,omitempty"`
	ExpectedAggregateVersion *uint64 `json:"expectedAggregateVersion,omitempty"`
	IdempotencyKey           string  `json:"idempotencyKey,omitempty"`
	Confirm                  bool    `json:"confirm,omitempty"`
	TTLSeconds               int64   `json:"ttlSeconds,omitempty"`
}

type ActionResponse struct {
	OperationID string         `json:"operationId"`
	Endpoint    *EndpointView  `json:"endpoint,omitempty"`
	Operation   OperationView  `json:"operation"`
	Diagnostic  DiagnosticView `json:"diagnostic"`
}

var (
	errAdminActionFailed         = errors.New("admin action failed")
	errAdminActionAlreadyPending = errors.New("admin action already pending")
)

func actionName(kind adapterapi.ActionKind) string {
	switch kind {
	case adapterapi.ActionKindRequestQRCode:
		return "request-qr"
	case adapterapi.ActionKindSubmitSMS:
		return "submit-sms-code"
	case adapterapi.ActionKindSubmitCaptcha:
		return "submit-captcha"
	case adapterapi.ActionKindValidateCredentials:
		return "validate-credentials"
	case adapterapi.ActionKindGenerateConfigArtifact:
		return "generate-config-artifact"
	case adapterapi.ActionKindSendMessage:
		return "send-message"
	case adapterapi.ActionKindSendFile:
		return "send-file"
	case adapterapi.ActionKindRecallMessage:
		return "recall-message"
	case adapterapi.ActionKindEditMessage:
		return "edit-message"
	case adapterapi.ActionKindSetGroupCard:
		return "set-group-card"
	case adapterapi.ActionKindQuit:
		return "quit"
	case adapterapi.ActionKindBan:
		return "ban"
	case adapterapi.ActionKindKick:
		return "kick"
	case adapterapi.ActionKindGroupInfoRefresh:
		return "refresh-group-info"
	default:
		return ""
	}
}

func actionFromName(name string) (adapterapi.ActionKind, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "request-qr":
		return adapterapi.ActionKindRequestQRCode, true
	case "submit-sms-code":
		return adapterapi.ActionKindSubmitSMS, true
	case "submit-captcha":
		return adapterapi.ActionKindSubmitCaptcha, true
	case "validate-credentials":
		return adapterapi.ActionKindValidateCredentials, true
	case "generate-config-artifact":
		return adapterapi.ActionKindGenerateConfigArtifact, true
	default:
		return adapterapi.ActionKindInvalid, false
	}
}

func actionResponse(ctx context.Context, operation eventstore.OperationView) (ActionResponse, error) {
	endpointDTO, err := mutationEndpoint(ctx, operation)
	if err != nil {
		return ActionResponse{}, err
	}
	return ActionResponse{OperationID: operation.OperationID, Endpoint: endpointDTO, Operation: operationViewDTO(operation)}, nil
}

func actionOperationCommit(ctx context.Context, mutation adminMutation, endpointID, action string) error {
	service := endpointService()
	if service == nil || service.Store == nil {
		return errors.New("endpoint service unavailable")
	}
	now := time.Now().UTC()
	_, err := service.Store.Commit(ctx, eventstore.UnitOfWork{Operations: []eventstore.OperationUpdate{{
		OperationID: mutation.operationID, ExpectedVersion: 0, Version: 1,
		Kind: "endpoint-action:" + action, Status: "pending", PrincipalID: mutation.principal,
		ResourceID: string(endpointID), RequestID: mutation.requestID,
		CorrelationID: mutation.requestID, IdempotencyScope: mutation.scope,
		IdempotencyKey: mutation.key, RequestDigest: append([]byte(nil), mutation.requestDigest...),
		CreatedAt: now, UpdatedAt: now,
	}}})
	return err
}

func actionOperationFinish(ctx context.Context, mutation adminMutation, action, status, resultCode, errorCode, artifactID string) (eventstore.OperationView, error) {
	service := endpointService()
	if service == nil || service.Store == nil {
		return eventstore.OperationView{}, errors.New("endpoint service unavailable")
	}
	now := time.Now().UTC()
	_, err := service.Store.Commit(ctx, eventstore.UnitOfWork{Operations: []eventstore.OperationUpdate{{
		OperationID: mutation.operationID, ExpectedVersion: 1, Version: 2,
		Kind: "endpoint-action:" + action, Status: status, PrincipalID: mutation.principal,
		RequestID: mutation.requestID, CorrelationID: mutation.requestID,
		IdempotencyScope: mutation.scope, IdempotencyKey: mutation.key,
		RequestDigest: append([]byte(nil), mutation.requestDigest...), ResultCode: resultCode,
		ErrorCode: errorCode, ArtifactID: artifactID, UpdatedAt: now,
	}}})
	if err != nil {
		return eventstore.OperationView{}, err
	}
	return service.GetOperation(ctx, mutation.operationID)
}

func clearActionResult(result *adapterapi.ActionResult) {
	if result == nil || result.Artifact == nil {
		return
	}
	clear(result.Artifact.Plaintext)
	result.Artifact.Plaintext = nil
}

func finishActionFailure(ctx context.Context, mutation adminMutation, action, code string, cause error) error {
	_, finishErr := actionOperationFinish(ctx, mutation, action, "failed", "", code, "")
	if finishErr != nil {
		return errors.Join(cause, finishErr)
	}
	return cause
}

func validateActionRequest(action adapterapi.ActionKind, request EndpointActionRequest) error {
	switch action {
	case adapterapi.ActionKindSubmitSMS:
		if request.SMSCode == "" || len(request.SMSCode) > 256 {
			return fmt.Errorf("%w: invalid SMS code", endpoint.ErrInvalid)
		}
	case adapterapi.ActionKindSubmitCaptcha:
		if request.Captcha == "" || len(request.Captcha) > 8*1024 {
			return fmt.Errorf("%w: invalid captcha", endpoint.ErrInvalid)
		}
	case adapterapi.ActionKindGenerateConfigArtifact:
		if !request.Confirm {
			return fmt.Errorf("%w: artifact generation requires confirmation", endpoint.ErrInvalid)
		}
	}
	if request.TTLSeconds < 0 || time.Duration(request.TTLSeconds)*time.Second > eventstore.MaxArtifactTTL {
		return eventstore.ErrInvalidTTL
	}
	return nil
}

func endpointAction(c echo.Context) error {
	if err := requireAdmin(c); err != nil {
		return err
	}
	id := adapterapi.EndpointID(c.Param("id"))
	if !id.Valid() {
		return adminHTTPError(c, endpoint.ErrNotFound)
	}
	action, ok := actionFromName(c.Param("action"))
	if !ok {
		return adminHTTPError(c, adapterapi.ErrUnsupportedAction)
	}
	ctx, cancel := withAdminContext(c)
	defer cancel()
	request := EndpointActionRequest{}
	if err := decodeAdminJSON(c, &request, true); err != nil {
		return adminHTTPError(c, err)
	}
	if request.ExpectedAggregateVersion == nil || *request.ExpectedAggregateVersion == 0 {
		return adminHTTPError(c, endpoint.ErrConflict)
	}
	if err := validateActionRequest(action, request); err != nil {
		return adminHTTPError(c, err)
	}
	service := endpointService()
	if service == nil {
		return adminHTTPError(c, errors.New("endpoint service unavailable"))
	}
	view, err := service.Get(ctx, id)
	if err != nil {
		return adminHTTPError(c, err)
	}
	if *request.ExpectedAggregateVersion != view.Version {
		return adminHTTPError(c, endpoint.ErrConflict)
	}
	if err := endpointActionSupported(ctx, view, action); err != nil {
		return adminHTTPError(c, err)
	}
	executor := endpointActionExecutor()
	if executor == nil {
		return adminHTTPError(c, adapterapi.ErrUnsupportedAction)
	}
	if action == adapterapi.ActionKindGenerateConfigArtifact && request.TTLSeconds == 0 {
		request.TTLSeconds = int64(eventstore.DefaultArtifactTTL / time.Second)
	}
	mutation, err := newAdminMutation(c, "/endpoints/"+string(id)+"/actions/"+c.Param("action"), actionName(action), request.IdempotencyKey, request)
	if err != nil {
		return adminHTTPError(c, err)
	}
	if existing, found, lookupErr := existingAdminMutation(ctx, mutation); lookupErr != nil {
		return adminHTTPError(c, lookupErr)
	} else if found {
		response, responseErr := actionResponse(ctx, existing)
		if responseErr != nil {
			return adminHTTPError(c, responseErr)
		}
		return c.JSON(http.StatusOK, response)
	}
	if err := actionOperationCommit(ctx, mutation, string(id), actionName(action)); err != nil {
		if errors.Is(err, eventstore.ErrParticipantConflict) || errors.Is(err, eventstore.ErrConflict) {
			if existing, found, lookupErr := existingAdminMutation(ctx, mutation); lookupErr == nil && found {
				response, responseErr := actionResponse(ctx, existing)
				if responseErr != nil {
					return adminHTTPError(c, responseErr)
				}
				return c.JSON(http.StatusOK, response)
			}
		}
		return adminHTTPError(c, err)
	}
	actionResult, actionErr := executor.ExecuteAction(ctx, adapterapi.ActionRequest{EndpointID: id, Generation: view.Generation, Kind: action, Payload: adapterapi.ActionPayload{SMSCode: request.SMSCode, Captcha: request.Captcha, Confirm: request.Confirm}})
	if actionErr != nil {
		clearActionResult(&actionResult)
		failureErr := finishActionFailure(ctx, mutation, actionName(action), "action_failed", actionErr)
		if errors.Is(actionErr, adapterapi.ErrUnsupportedAction) {
			return adminHTTPError(c, failureErr)
		}
		return adminHTTPError(c, errors.Join(errAdminActionFailed, failureErr))
	}
	if err := actionResult.Validate(); err != nil {
		clearActionResult(&actionResult)
		return adminHTTPError(c, finishActionFailure(ctx, mutation, actionName(action), "invalid_action_result", err))
	}
	artifactID := ""
	if actionResult.Artifact != nil {
		if action != adapterapi.ActionKindRequestQRCode && action != adapterapi.ActionKindGenerateConfigArtifact {
			clearActionResult(&actionResult)
			return adminHTTPError(c, finishActionFailure(ctx, mutation, actionName(action), "invalid_action_result", adapterapi.ErrInvalidContract))
		}
		if len(actionResult.Artifact.Plaintext) > eventstore.MaxArtifactBytes {
			clearActionResult(&actionResult)
			return adminHTTPError(c, finishActionFailure(ctx, mutation, actionName(action), "artifact_too_large", eventstore.ErrOversizeInput))
		}
		artifactID = "artifact-" + mutation.operationID
		repository, repositoryOK := service.Store.(eventstore.ArtifactRepository)
		if !repositoryOK {
			clearActionResult(&actionResult)
			return adminHTTPError(c, finishActionFailure(ctx, mutation, actionName(action), "artifact_unavailable", errors.New("artifact repository unavailable")))
		}
		ttl := eventstore.DefaultArtifactTTL
		if request.TTLSeconds > 0 {
			ttl = time.Duration(request.TTLSeconds) * time.Second
		}
		_, artifactErr := repository.PutArtifact(ctx, eventstore.ArtifactPutRequest{ArtifactID: artifactID, OperationID: mutation.operationID, OwnerPrincipalID: mutation.principal, MediaType: actionResult.Artifact.MediaType, SafeFilename: actionResult.Artifact.SafeFilename, Plaintext: actionResult.Artifact.Plaintext, TTL: ttl})
		clearActionResult(&actionResult)
		if artifactErr != nil {
			return adminHTTPError(c, finishActionFailure(ctx, mutation, actionName(action), "artifact_failed", artifactErr))
		}
	}
	resultCode := actionResult.ResultCode
	if resultCode == "" {
		resultCode = actionName(action) + "_accepted"
	}
	operation, err := actionOperationFinish(ctx, mutation, actionName(action), "succeeded", resultCode, "", artifactID)
	if err != nil {
		return adminHTTPError(c, err)
	}
	response, err := actionResponse(ctx, operation)
	if err != nil {
		return adminHTTPError(c, err)
	}
	response.Diagnostic = DiagnosticView{Entries: actionResult.Diagnostic.Entries}
	adminAudit(c, actionName(action), "/endpoints/"+string(id), "accepted")
	return c.JSON(http.StatusAccepted, response)
}
