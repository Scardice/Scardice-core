package api

import (
	"errors"
	"mime"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"Scardice-core/adapterapi"
	"Scardice-core/endpoint"
	"Scardice-core/eventstore"
)

type OperationResolveRequest struct {
	Resolution               string  `json:"resolution"`
	ExpectedOperationVersion *uint64 `json:"expectedOperationVersion,omitempty"`
	ExpectedAggregateVersion *uint64 `json:"expectedAggregateVersion,omitempty"`
	IdempotencyKey           string  `json:"idempotencyKey,omitempty"`
	Confirm                  bool    `json:"confirm,omitempty"`
}

func operationOwnedBy(c echo.Context, view eventstore.OperationView) bool {
	principal := adminPrincipalFromContext(c)
	return principal != "" && view.PrincipalID == principal
}

func operationGet(c echo.Context) error {
	if err := requireAdmin(c); err != nil {
		return err
	}
	id := strings.TrimSpace(c.Param("id"))
	if !adapterapi.OperationID(id).Valid() {
		return adminHTTPError(c, eventstore.ErrNotFound)
	}
	ctx, cancel := withAdminContext(c)
	defer cancel()
	service := endpointService()
	if service == nil {
		return adminHTTPError(c, errors.New("endpoint service unavailable"))
	}
	view, err := service.GetOperation(ctx, id)
	if err != nil {
		return adminHTTPError(c, err)
	}
	if !operationOwnedBy(c, view) {
		return adminHTTPError(c, eventstore.ErrNotFound)
	}
	adminAudit(c, "get-operation", "/operations/"+id, "succeeded")
	return c.JSON(http.StatusOK, operationViewDTO(view))
}

func operationResolve(c echo.Context) error {
	if err := requireAdmin(c); err != nil {
		return err
	}
	operationID := strings.TrimSpace(c.Param("id"))
	if !adapterapi.OperationID(operationID).Valid() {
		return adminHTTPError(c, eventstore.ErrNotFound)
	}
	ctx, cancel := withAdminContext(c)
	defer cancel()
	service := endpointService()
	if service == nil {
		return adminHTTPError(c, errors.New("endpoint service unavailable"))
	}
	stored, err := service.GetOperation(ctx, operationID)
	if err != nil {
		return adminHTTPError(c, err)
	}
	if !operationOwnedBy(c, stored) {
		return adminHTTPError(c, eventstore.ErrNotFound)
	}
	request := OperationResolveRequest{}
	if err := decodeAdminJSON(c, &request, false); err != nil {
		return adminHTTPError(c, err)
	}
	resolution := strings.ToLower(strings.TrimSpace(request.Resolution))
	if resolution != "confirmed-success" && resolution != "confirm-delete" {
		return adminHTTPError(c, endpoint.ErrInvalid)
	}
	if !request.Confirm || request.ExpectedOperationVersion == nil || *request.ExpectedOperationVersion == 0 || *request.ExpectedOperationVersion != stored.Version {
		return adminHTTPError(c, endpoint.ErrConflict)
	}
	if stored.ResourceID == "" {
		return adminHTTPError(c, endpoint.ErrInvalid)
	}
	endpointID := adapterapi.EndpointID(stored.ResourceID)
	current, err := service.Get(ctx, endpointID)
	if err != nil {
		return adminHTTPError(c, err)
	}
	if request.ExpectedAggregateVersion == nil || *request.ExpectedAggregateVersion == 0 || *request.ExpectedAggregateVersion != current.Version {
		return adminHTTPError(c, endpoint.ErrConflict)
	}
	mutation, err := newAdminMutation(c, "/operations/"+operationID+"/resolve", resolution, request.IdempotencyKey, request)
	if err != nil {
		return adminHTTPError(c, err)
	}
	if existing, found, lookupErr := existingAdminMutation(ctx, mutation); lookupErr != nil {
		return adminHTTPError(c, lookupErr)
	} else if found {
		endpointDTO, endpointErr := mutationEndpoint(ctx, existing)
		if endpointErr != nil {
			return adminHTTPError(c, endpointErr)
		}
		return c.JSON(http.StatusOK, MutationResponse{OperationID: existing.OperationID, Endpoint: endpointDTO})
	}
	command := endpoint.Command{CommandID: mutation.commandID, ID: mutation.commandID, CorrelationID: mutation.requestID, OperationID: stored.OperationID, PrincipalID: mutation.principal, RequestID: mutation.requestID, IdempotencyScope: mutation.scope, IdempotencyKey: mutation.key, RequestDigest: mutation.requestDigest, EndpointID: endpointID, ExpectedAggregateVersion: *request.ExpectedAggregateVersion, ExpectedVersion: *request.ExpectedAggregateVersion, ExpectedVersionSet: true, Generation: current.Generation, DesiredVersion: current.DesiredVersion}
	if resolution == "confirmed-success" {
		command.Kind = endpoint.CommandComplete
		command.Type = endpoint.CommandComplete
		command.CompletionState = endpoint.OperationStateSucceeded
		if current.DesiredState == endpoint.DesiredStateEnabled {
			command.ObservedState = adapterapi.ObservedStateConnected
		} else {
			command.ObservedState = adapterapi.ObservedStateStopped
		}
	} else {
		command.Kind = endpoint.CommandResolve
		command.Type = endpoint.CommandResolve
		command.ObservedState = adapterapi.ObservedStateStopped
	}
	result, err := endpointExecute(ctx, command)
	if err != nil {
		return adminHTTPError(c, err)
	}
	response, err := endpointMutationResponse(ctx, result)
	if err != nil {
		return adminHTTPError(c, err)
	}
	adminAudit(c, "resolve", "/operations/"+operationID, "accepted")
	return c.JSON(http.StatusAccepted, response)
}
func operationArtifact(c echo.Context) error {
	if err := requireAdmin(c); err != nil {
		return err
	}
	operationID := strings.TrimSpace(c.Param("id"))
	if !adapterapi.OperationID(operationID).Valid() {
		return adminHTTPError(c, eventstore.ErrNotFound)
	}
	ctx, cancel := withAdminContext(c)
	defer cancel()
	service := endpointService()
	if service == nil {
		return adminHTTPError(c, errors.New("endpoint service unavailable"))
	}
	operation, err := service.GetOperation(ctx, operationID)
	if err != nil {
		return adminHTTPError(c, err)
	}
	if !operationOwnedBy(c, operation) || operation.ArtifactID == "" {
		return adminHTTPError(c, eventstore.ErrArtifactGone)
	}
	repository, ok := service.Store.(eventstore.ArtifactRepository)
	if !ok {
		return adminHTTPError(c, errors.New("artifact repository unavailable"))
	}
	artifact, err := repository.ConsumeArtifact(ctx, eventstore.ArtifactConsumeRequest{ArtifactID: operation.ArtifactID, OwnerPrincipalID: adminPrincipalFromContext(c)})
	if err != nil {
		return adminHTTPError(c, err)
	}
	if artifact.OperationID != operationID {
		clear(artifact.Plaintext)
		return adminHTTPError(c, eventstore.ErrArtifactGone)
	}
	defer clear(artifact.Plaintext)
	filename := strings.TrimSpace(artifact.SafeFilename)
	if filename == "" {
		filename = "artifact.bin"
	}
	contentDisposition := mime.FormatMediaType("attachment", map[string]string{"filename": filename})
	if contentDisposition == "" {
		return adminHTTPError(c, eventstore.ErrInvalidMetadata)
	}
	c.Response().Header().Set(echo.HeaderCacheControl, "no-store")
	c.Response().Header().Set(echo.HeaderContentDisposition, contentDisposition)
	adminAudit(c, "artifact", "/operations/"+operationID, "consumed")
	return c.Blob(http.StatusOK, artifact.MediaType, artifact.Plaintext)
}
