package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	"Scardice-core/adapterapi"
	"Scardice-core/endpoint"
	"Scardice-core/eventstore"
)

// EndpointConfigPayload is the only configuration shape accepted by the
// management API. AdapterKey is the discriminator and Payload is validated by
// the matching Go descriptor before any runtime is constructed.
type EndpointConfigPayload struct {
	Version uint16          `json:"version"`
	Payload json.RawMessage `json:"payload"`
}

type EndpointConfigView struct {
	Version    uint16                 `json:"version"`
	Payload    json.RawMessage        `json:"payload"`
	SecretRefs []adapterapi.SecretRef `json:"secretRefs,omitempty"`
}

type CapabilityView struct {
	Capabilities []string `json:"capabilities"`
	Actions      []string `json:"actions"`
}

type DiagnosticView struct {
	Entries []adapterapi.DiagnosticEntry `json:"entries"`
}

type EndpointView struct {
	EndpointID          string             `json:"endpointId"`
	DisplayName         string             `json:"displayName,omitempty"`
	ProviderID          string             `json:"providerId,omitempty"`
	GroupNum            int64              `json:"groupNum"`
	CmdExecutedNum      int64              `json:"cmdExecutedNum"`
	CmdExecutedLastTime int64              `json:"cmdExecutedLastTime"`
	OnlineTotalTime     int64              `json:"onlineTotalTime"`
	AdapterKey          string             `json:"adapterKey"`
	Config              EndpointConfigView `json:"config"`
	DesiredState        string             `json:"desiredState"`
	ObservedState       string             `json:"observedState"`
	OperationState      string             `json:"operationState"`
	DesiredVersion      uint64             `json:"desiredVersion"`
	Generation          uint64             `json:"generation"`
	OperationID         string             `json:"operationId,omitempty"`
	CorrelationID       string             `json:"correlationId,omitempty"`
	Version             uint64             `json:"version"`
	Capabilities        CapabilityView     `json:"capabilities"`
}

type OperationView struct {
	OperationID string    `json:"operationId"`
	Version     uint64    `json:"version"`
	Kind        string    `json:"kind"`
	Status      string    `json:"status"`
	ResultCode  string    `json:"resultCode,omitempty"`
	ErrorCode   string    `json:"errorCode,omitempty"`
	ArtifactID  string    `json:"artifactId,omitempty"`
	ResourceID  string    `json:"resourceId,omitempty"`
	RequestID   string    `json:"requestId,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
	ExpiresAt   time.Time `json:"expiresAt,omitempty"`
}

type MutationResponse struct {
	OperationID string        `json:"operationId"`
	Endpoint    *EndpointView `json:"endpoint,omitempty"`
}

type ErrorResponse struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"requestId,omitempty"`
}

type EndpointCreateRequest struct {
	EndpointID               string                `json:"endpointId,omitempty"`
	DisplayName              string                `json:"displayName,omitempty"`
	AdapterKey               string                `json:"adapterKey"`
	Config                   EndpointConfigPayload `json:"config"`
	Secrets                  map[string]string     `json:"secrets,omitempty"`
	ExpectedAggregateVersion *uint64               `json:"expectedAggregateVersion,omitempty"`
	IdempotencyKey           string                `json:"idempotencyKey,omitempty"`
	Confirm                  bool                  `json:"confirm,omitempty"`
}

type EndpointConfigRequest struct {
	Config                   EndpointConfigPayload `json:"config"`
	Secrets                  map[string]string     `json:"secrets,omitempty"`
	ExpectedAggregateVersion *uint64               `json:"expectedAggregateVersion,omitempty"`
	IdempotencyKey           string                `json:"idempotencyKey,omitempty"`
	Confirm                  bool                  `json:"confirm,omitempty"`
}

type EndpointCommandRequest struct {
	ExpectedAggregateVersion *uint64 `json:"expectedAggregateVersion,omitempty"`
	IdempotencyKey           string  `json:"idempotencyKey,omitempty"`
	Confirm                  bool    `json:"confirm,omitempty"`
}

type adminMutation struct {
	principal     string
	requestID     string
	scope         string
	key           string
	requestDigest []byte
	commandID     string
	operationID   string
}

func adminAuthHTTPError(c echo.Context, err error) error {
	status, code, message := http.StatusUnauthorized, "admin_unauthorized", "administrator authentication failed"
	switch {
	case errors.Is(err, errAdminOrigin):
		status, code, message = http.StatusForbidden, "origin_not_allowed", "request origin is not allowed"
	case errors.Is(err, errAdminRateLimit):
		status, code, message = http.StatusTooManyRequests, "rate_limited", "administrator rate limit exceeded"
	}
	_ = c.JSON(status, ErrorResponse{Code: code, Message: message, RequestID: adminRequestID(c)})
	return echo.NewHTTPError(status)
}

func adminHTTPError(c echo.Context, err error) error {
	status, code, message := http.StatusInternalServerError, "internal_error", "request failed"
	switch {
	case err == nil:
		return nil
	case errors.Is(err, errAdminUnauthorized):
		status, code, message = http.StatusUnauthorized, "admin_unauthorized", "administrator authentication failed"
	case errors.Is(err, errAdminOrigin):
		status, code, message = http.StatusForbidden, "origin_not_allowed", "request origin is not allowed"
	case errors.Is(err, errAdminRateLimit):
		status, code, message = http.StatusTooManyRequests, "rate_limited", "administrator rate limit exceeded"
	case errors.Is(err, eventstore.ErrKeySourceUnavailable):
		status, code, message = http.StatusServiceUnavailable, "admin_key_unavailable", "administrator request signing is unavailable"
	case errors.Is(err, eventstore.ErrArtifactGone):
		status, code, message = http.StatusGone, "artifact_gone", "artifact is expired or already consumed"
	case errors.Is(err, eventstore.ErrArtifactOwner):
		status, code, message = http.StatusNotFound, "artifact_gone", "artifact is unavailable"
	case errors.Is(err, eventstore.ErrNotFound), errors.Is(err, endpoint.ErrNotFound):
		status, code, message = http.StatusNotFound, "not_found", "resource was not found"
	case errors.Is(err, endpoint.ErrConflict), errors.Is(err, endpoint.ErrCommandConflict), errors.Is(err, endpoint.ErrStaleExpectedVersion), errors.Is(err, endpoint.ErrInvalidTransition), errors.Is(err, eventstore.ErrConflict), errors.Is(err, eventstore.ErrParticipantConflict):
		status, code, message = http.StatusConflict, "conflict", "request conflicts with current state"
	case errors.Is(err, errAdminIdempotencyConflict):
		status, code, message = http.StatusConflict, "idempotency_conflict", "idempotency key was already used with another request"
	case errors.Is(err, adapterapi.ErrUnsupportedAction):
		status, code, message = http.StatusUnprocessableEntity, "unsupported_action", "action is not supported for this endpoint"
	case errors.Is(err, endpoint.ErrUnknownAdapter):
		status, code, message = http.StatusBadRequest, "unsupported_adapter", "adapter is not supported"
	case errors.Is(err, endpoint.ErrInvalid), errors.Is(err, endpoint.ErrInvalidConfig), errors.Is(err, adapterapi.ErrInvalidConfig), errors.Is(err, adapterapi.ErrInvalidContract), errors.Is(err, eventstore.ErrInvalidMetadata):
		status, code, message = http.StatusBadRequest, "invalid_request", "request is invalid"
	case errors.Is(err, context.DeadlineExceeded):
		status, code, message = http.StatusGatewayTimeout, "deadline_exceeded", "request deadline exceeded"
	case errors.Is(err, errAdminBodyTooLarge):
		status, code, message = http.StatusRequestEntityTooLarge, "body_too_large", "request body exceeds 1 MiB"
	}
	adminAudit(c, "request", c.Path(), code)
	return c.JSON(status, ErrorResponse{Code: code, Message: message, RequestID: adminRequestID(c)})
}

var (
	errAdminIdempotencyConflict = errors.New("admin idempotency conflict")
	errAdminBodyTooLarge        = errors.New("admin request body too large")
)

func adminAudit(c echo.Context, action, resource, result string) {
	log.Printf("admin_audit principal=%q request=%q action=%q resource=%q result=%q", adminPrincipalFromContext(c), adminRequestID(c), action, resource, result)
}

func decodeAdminJSON(c echo.Context, target any, allowEmpty bool) error {
	limitAdminBody(c)
	decoder := json.NewDecoder(c.Request().Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		if allowEmpty && errors.Is(err, io.EOF) {
			return nil
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return context.DeadlineExceeded
		}
		if strings.Contains(err.Error(), "request body too large") || strings.Contains(err.Error(), "http: request body too large") {
			return errAdminBodyTooLarge
		}
		return fmt.Errorf("%w: invalid JSON", endpoint.ErrInvalid)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("%w: multiple JSON values", endpoint.ErrInvalid)
		}
		return fmt.Errorf("%w: trailing JSON", endpoint.ErrInvalid)
	}
	return nil
}

func adminIdempotencyKey(c echo.Context, bodyKey string) (string, error) {
	values := c.Request().Header.Values("Idempotency-Key")
	if len(values) > 1 {
		return "", errAdminIdempotencyConflict
	}
	headerKey := ""
	if len(values) == 1 {
		headerKey = values[0]
		if headerKey == "" || strings.ContainsAny(headerKey, ",\r\n") {
			return "", errAdminIdempotencyConflict
		}
	}
	bodyKey = strings.TrimSpace(bodyKey)
	if bodyKey != "" && (strings.ContainsAny(bodyKey, ",\r\n") || len(bodyKey) > 255) {
		return "", errAdminIdempotencyConflict
	}
	if headerKey != "" && bodyKey != "" && headerKey != bodyKey {
		return "", errAdminIdempotencyConflict
	}
	key := headerKey
	if key == "" {
		key = bodyKey
	}
	if key == "" {
		return "", errAdminIdempotencyConflict
	}
	return key, nil
}

func newAdminMutation(c echo.Context, resource, action, bodyKey string, body any) (adminMutation, error) {
	key, err := adminIdempotencyKey(c, bodyKey)
	if err != nil {
		return adminMutation{}, err
	}
	config, _, err := currentAdminAuth()
	if err != nil {
		return adminMutation{}, err
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return adminMutation{}, fmt.Errorf("%w: request digest", endpoint.ErrInvalid)
	}
	service := endpointService()
	if service == nil || service.Store == nil {
		return adminMutation{}, eventstore.ErrKeySourceUnavailable
	}
	digestProvider, ok := service.Store.(interface {
		KeyedDigestBytes(ctx context.Context, namespace string, value []byte) ([]byte, string, error)
	})
	if !ok {
		return adminMutation{}, eventstore.ErrKeySourceUnavailable
	}
	digest, _, err := digestProvider.KeyedDigestBytes(c.Request().Context(), "admin-idempotency-digest/v1", encoded)
	if err != nil {
		return adminMutation{}, err
	}
	identity := config.principal + "\x00" + clientIP(c.Request()) + "\x00" + c.Request().Method + "\x00" + resource + "\x00" + action
	scopeHash := sha256.Sum256([]byte(identity))
	scope := "admin-v1-" + hex.EncodeToString(scopeHash[:16])
	keyHash := sha256.Sum256([]byte(key))
	storedKey := hex.EncodeToString(keyHash[:])
	commandHash := sha256.Sum256([]byte(scope + "\x00" + storedKey))
	commandID := "admin-command-" + hex.EncodeToString(commandHash[:16])
	operationID := "admin-operation-" + hex.EncodeToString(commandHash[:16])
	return adminMutation{principal: config.principal, requestID: adminRequestID(c), scope: scope, key: storedKey, requestDigest: digest, commandID: commandID, operationID: operationID}, nil
}

func existingAdminMutation(ctx context.Context, mutation adminMutation) (eventstore.OperationView, bool, error) {
	service := endpointService()
	if service == nil || service.Store == nil {
		return eventstore.OperationView{}, false, errors.New("endpoint service unavailable")
	}
	repository, ok := service.Store.(interface {
		GetOperationByIdempotency(ctx context.Context, principalID, scope, key string) (eventstore.OperationView, error)
	})
	if !ok {
		return eventstore.OperationView{}, false, errors.New("operation repository unavailable")
	}
	view, err := repository.GetOperationByIdempotency(ctx, mutation.principal, mutation.scope, mutation.key)
	if errors.Is(err, eventstore.ErrNotFound) {
		return eventstore.OperationView{}, false, nil
	}
	if err != nil {
		return eventstore.OperationView{}, false, err
	}
	if !hmac.Equal(view.RequestDigest, mutation.requestDigest) {
		return eventstore.OperationView{}, false, errAdminIdempotencyConflict
	}
	return view, true, nil
}

func endpointDescriptor(ctx context.Context, key adapterapi.AdapterKey) (adapterapi.Descriptor, bool) {
	service := endpointService()
	if service == nil || service.Registry == nil {
		return nil, false
	}
	descriptor, ok := service.Registry.Lookup(ctx, key)
	if !ok || descriptor == nil || descriptor.Key() != key {
		return nil, false
	}
	return descriptor, true
}

func capabilityView(ctx context.Context, key adapterapi.AdapterKey, config adapterapi.ValidatedConfig) CapabilityView {
	descriptor, ok := endpointDescriptor(ctx, key)
	if !ok {
		return CapabilityView{Capabilities: []string{}, Actions: []string{}}
	}
	view := CapabilityView{Capabilities: []string{}, Actions: []string{}}
	for _, action := range descriptor.SupportedActions(config).Kinds() {
		view.Actions = append(view.Actions, actionName(action))
	}
	view.Capabilities = capabilityNames(descriptor.Capabilities(config))
	return view
}

func capabilityNames(set adapterapi.CapabilitySet) []string {
	names := make([]string, 0, 6)
	if set.Has(adapterapi.CapabilityInbound) {
		names = append(names, "inbound")
	}
	if set.Has(adapterapi.CapabilityOutbound) {
		names = append(names, "outbound")
	}
	if set.Has(adapterapi.CapabilityLifecycle) {
		names = append(names, "lifecycle")
	}
	if set.Has(adapterapi.CapabilityActions) {
		names = append(names, "actions")
	}
	if set.Has(adapterapi.CapabilityArtifacts) {
		names = append(names, "artifacts")
	}
	if set.Has(adapterapi.CapabilityRichMessages) {
		names = append(names, "rich-messages")
	}
	return names
}

func endpointViewDTO(ctx context.Context, source endpoint.EndpointView) EndpointView {
	return EndpointView{
		EndpointID: string(source.EndpointID), DisplayName: source.DisplayName,
		ProviderID: string(source.ProviderID), GroupNum: source.Statistics.GroupCount,
		CmdExecutedNum: source.Statistics.CommandCount, CmdExecutedLastTime: source.Statistics.LastCommandAt,
		OnlineTotalTime: source.Statistics.OnlineSeconds, AdapterKey: string(source.AdapterKey),
		Config:       EndpointConfigView{Version: source.Config.Version, Payload: append(json.RawMessage(nil), source.Config.Canonical...), SecretRefs: append([]adapterapi.SecretRef(nil), source.Config.SecretRefs...)},
		DesiredState: string(source.DesiredState), ObservedState: observedStateName(source.ObservedState), OperationState: string(source.OperationState),
		DesiredVersion: source.DesiredVersion, Generation: source.Generation, OperationID: source.OperationID,
		CorrelationID: source.CorrelationID, Version: source.Version, Capabilities: capabilityView(ctx, source.AdapterKey, source.Config),
	}
}

func observedStateName(state adapterapi.ObservedState) string {
	switch state {
	case adapterapi.ObservedStateStopped:
		return "stopped"
	case adapterapi.ObservedStateStarting:
		return "starting"
	case adapterapi.ObservedStateConnected:
		return "connected"
	case adapterapi.ObservedStateStopping:
		return "stopping"
	case adapterapi.ObservedStateFailed:
		return "failed"
	case adapterapi.ObservedStateAmbiguous:
		return "ambiguous"
	default:
		return "invalid"
	}
}

func operationViewDTO(source eventstore.OperationView) OperationView {
	return OperationView{OperationID: source.OperationID, Version: source.Version, Kind: source.Kind, Status: source.Status, ResultCode: source.ResultCode, ErrorCode: source.ErrorCode, ArtifactID: source.ArtifactID, ResourceID: source.ResourceID, RequestID: source.RequestID, CreatedAt: source.CreatedAt, UpdatedAt: source.UpdatedAt, ExpiresAt: source.ExpiresAt}
}

func commandSecrets(config adapterapi.ValidatedConfig, values map[string]string) ([]endpoint.SecretInput, error) {
	if len(config.SecretRefs) == 0 {
		if len(values) != 0 {
			return nil, fmt.Errorf("%w: unexpected secret input", endpoint.ErrInvalidConfig)
		}
		return nil, nil
	}
	if len(values) != len(config.SecretRefs) {
		return nil, fmt.Errorf("%w: missing secret input", endpoint.ErrInvalidConfig)
	}
	inputs := make([]endpoint.SecretInput, 0, len(config.SecretRefs))
	for _, ref := range config.SecretRefs {
		value, ok := values[ref.Ref]
		if !ok || value == "" {
			return nil, fmt.Errorf("%w: missing secret input", endpoint.ErrInvalidConfig)
		}
		inputs = append(inputs, endpoint.SecretInput{Ref: ref.Ref, Version: ref.Version, Plaintext: []byte(value)})
	}
	for ref := range values {
		found := false
		for _, expected := range config.SecretRefs {
			if ref == expected.Ref {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("%w: unexpected secret input", endpoint.ErrInvalidConfig)
		}
	}
	return inputs, nil
}
func commandSecretsForUpdate(config, current adapterapi.ValidatedConfig, values map[string]string) ([]endpoint.SecretInput, error) {
	if len(values) == 0 && sameSecretReferences(config.SecretRefs, current.SecretRefs) {
		return nil, nil
	}
	return commandSecrets(config, values)
}

func sameSecretReferences(left, right []adapterapi.SecretRef) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func mutationEndpoint(ctx context.Context, operation eventstore.OperationView) (*EndpointView, error) {
	if operation.ResourceID == "" {
		return nil, endpoint.ErrInvalid
	}
	service := endpointService()
	if service == nil {
		return nil, errors.New("endpoint service unavailable")
	}
	view, err := service.Get(ctx, adapterapi.EndpointID(operation.ResourceID))
	if err != nil {
		return nil, err
	}
	dto := endpointViewDTO(ctx, view)
	return &dto, nil
}

func endpointMutationResponse(ctx context.Context, result endpoint.Result) (MutationResponse, error) {
	operationID := result.Operation.OperationID
	if operationID == "" {
		operationID = result.State.OperationID
	}
	response := MutationResponse{OperationID: operationID}
	if result.State.EndpointID.Valid() {
		dto := endpointViewDTO(ctx, endpoint.EndpointView{EndpointID: result.State.EndpointID, DisplayName: result.State.DisplayName, Statistics: result.State.Statistics, ProviderID: result.State.ProviderID, AdapterKey: result.State.AdapterKey, Config: result.State.Config, DesiredState: result.State.DesiredState, ObservedState: result.State.ObservedState, OperationState: result.State.OperationState, DesiredVersion: result.State.DesiredVersion, Generation: result.State.Generation, OperationID: result.State.OperationID, CorrelationID: result.State.CorrelationID, Version: result.State.Version})
		response.Endpoint = &dto
	}
	if operationID == "" {
		return MutationResponse{}, errors.New("endpoint operation id missing")
	}
	return response, nil
}

func endpointList(c echo.Context) error {
	if err := requireAdmin(c); err != nil {
		return err
	}
	ctx, cancel := withAdminContext(c)
	defer cancel()
	service := endpointService()
	if service == nil {
		return adminHTTPError(c, errors.New("endpoint service unavailable"))
	}
	views, err := service.List(ctx)
	if err != nil {
		return adminHTTPError(c, err)
	}
	result := make([]EndpointView, 0, len(views))
	// Keep in-flight removals visible; only resolved tombstones leave the
	// manageable endpoint collection. endpointGet remains the historical read.
	for _, view := range views {
		if view.DesiredState == endpoint.DesiredStateDeleted {
			continue
		}
		result = append(result, endpointViewDTO(ctx, view))
	}
	adminAudit(c, "list", "/endpoints", "succeeded")
	return c.JSON(http.StatusOK, result)
}

func endpointGet(c echo.Context) error {
	if err := requireAdmin(c); err != nil {
		return err
	}
	id := adapterapi.EndpointID(c.Param("id"))
	if !id.Valid() {
		return adminHTTPError(c, endpoint.ErrNotFound)
	}
	ctx, cancel := withAdminContext(c)
	defer cancel()
	service := endpointService()
	if service == nil {
		return adminHTTPError(c, errors.New("endpoint service unavailable"))
	}
	view, err := service.Get(ctx, id)
	if err != nil {
		return adminHTTPError(c, err)
	}
	adminAudit(c, "get", "/endpoints/"+string(id), "succeeded")
	return c.JSON(http.StatusOK, endpointViewDTO(ctx, view))
}

func endpointCreate(c echo.Context) error {
	if err := requireAdmin(c); err != nil {
		return err
	}
	ctx, cancel := withAdminContext(c)
	defer cancel()
	request := EndpointCreateRequest{}
	if err := decodeAdminJSON(c, &request, false); err != nil {
		return adminHTTPError(c, err)
	}
	service := endpointService()
	if service == nil {
		return adminHTTPError(c, errors.New("endpoint service unavailable"))
	}
	key, keyErr := adapterapi.NewAdapterKey(request.AdapterKey)
	if keyErr != nil || key == "" {
		return adminHTTPError(c, endpoint.ErrUnknownAdapter)
	}
	if request.ExpectedAggregateVersion != nil && *request.ExpectedAggregateVersion != 0 {
		return adminHTTPError(c, endpoint.ErrConflict)
	}
	if request.Config.Version == 0 || len(request.Config.Payload) == 0 {
		return adminHTTPError(c, endpoint.ErrInvalidConfig)
	}
	validated, err := service.ValidateConfig(ctx, key, request.Config.Payload)
	if err != nil {
		return adminHTTPError(c, err)
	}
	if validated.Version != request.Config.Version {
		return adminHTTPError(c, endpoint.ErrInvalidConfig)
	}
	secretInputs, err := commandSecrets(validated, request.Secrets)
	if err != nil {
		return adminHTTPError(c, err)
	}
	id := adapterapi.EndpointID(strings.TrimSpace(request.EndpointID))
	if id == "" {
		id = adapterapi.EndpointID("endpoint-" + strings.ReplaceAll(adminRequestID(c), "-", ""))
	}
	if !id.Valid() {
		return adminHTTPError(c, endpoint.ErrInvalid)
	}
	bodyForDigest := request
	mutation, err := newAdminMutation(c, "/endpoints", "create", request.IdempotencyKey, bodyForDigest)
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
	command := endpoint.Command{Kind: endpoint.CommandCreate, Type: endpoint.CommandCreate, CommandID: mutation.commandID, ID: mutation.commandID, CorrelationID: mutation.requestID, OperationID: mutation.operationID, PrincipalID: mutation.principal, RequestID: mutation.requestID, IdempotencyScope: mutation.scope, IdempotencyKey: mutation.key, RequestDigest: mutation.requestDigest, EndpointID: id, DisplayName: strings.TrimSpace(request.DisplayName), AdapterKey: key, Config: validated, SecretInputs: secretInputs}
	result, err := endpointExecute(ctx, command)
	if err != nil {
		return adminHTTPError(c, err)
	}
	response, err := endpointMutationResponse(ctx, result)
	if err != nil {
		return adminHTTPError(c, err)
	}
	adminAudit(c, "create", "/endpoints", "accepted")
	return c.JSON(http.StatusAccepted, response)
}

func endpointConfigPatch(c echo.Context) error {
	if err := requireAdmin(c); err != nil {
		return err
	}
	id := adapterapi.EndpointID(c.Param("id"))
	if !id.Valid() {
		return adminHTTPError(c, endpoint.ErrNotFound)
	}
	ctx, cancel := withAdminContext(c)
	defer cancel()
	request := EndpointConfigRequest{}
	if err := decodeAdminJSON(c, &request, false); err != nil {
		return adminHTTPError(c, err)
	}
	service := endpointService()
	if service == nil {
		return adminHTTPError(c, errors.New("endpoint service unavailable"))
	}
	current, err := service.Get(ctx, id)
	if err != nil {
		return adminHTTPError(c, err)
	}
	if request.ExpectedAggregateVersion == nil || *request.ExpectedAggregateVersion == 0 {
		return adminHTTPError(c, endpoint.ErrConflict)
	}
	if request.Config.Version == 0 || len(request.Config.Payload) == 0 {
		return adminHTTPError(c, endpoint.ErrInvalidConfig)
	}
	validated, err := service.ValidateConfig(ctx, current.AdapterKey, request.Config.Payload)
	if err != nil {
		return adminHTTPError(c, err)
	}
	if validated.Version != request.Config.Version {
		return adminHTTPError(c, endpoint.ErrInvalidConfig)
	}
	secretInputs, err := commandSecretsForUpdate(validated, current.Config, request.Secrets)
	if err != nil {
		return adminHTTPError(c, err)
	}
	mutation, err := newAdminMutation(c, "/endpoints/"+string(id)+"/config", "config", request.IdempotencyKey, request)
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
	command := endpoint.Command{Kind: endpoint.CommandUpdateConfig, Type: endpoint.CommandUpdateConfig, CommandID: mutation.commandID, ID: mutation.commandID, CorrelationID: mutation.requestID, OperationID: mutation.operationID, PrincipalID: mutation.principal, RequestID: mutation.requestID, IdempotencyScope: mutation.scope, IdempotencyKey: mutation.key, RequestDigest: mutation.requestDigest, EndpointID: id, AdapterKey: current.AdapterKey, Config: validated, ExpectedAggregateVersion: *request.ExpectedAggregateVersion, ExpectedVersion: *request.ExpectedAggregateVersion, ExpectedVersionSet: true, SecretInputs: secretInputs}
	result, err := endpointExecute(ctx, command)
	if err != nil {
		return adminHTTPError(c, err)
	}
	response, err := endpointMutationResponse(ctx, result)
	if err != nil {
		return adminHTTPError(c, err)
	}
	adminAudit(c, "config", "/endpoints/"+string(id), "accepted")
	return c.JSON(http.StatusAccepted, response)
}

func endpointLifecycle(c echo.Context, kind endpoint.CommandKind) error {
	if err := requireAdmin(c); err != nil {
		return err
	}
	id := adapterapi.EndpointID(c.Param("id"))
	if !id.Valid() {
		return adminHTTPError(c, endpoint.ErrNotFound)
	}
	ctx, cancel := withAdminContext(c)
	defer cancel()
	request := EndpointCommandRequest{}
	if err := decodeAdminJSON(c, &request, true); err != nil {
		return adminHTTPError(c, err)
	}
	if request.ExpectedAggregateVersion == nil || *request.ExpectedAggregateVersion == 0 {
		return adminHTTPError(c, endpoint.ErrConflict)
	}
	if kind == endpoint.CommandRemove && !request.Confirm {
		return adminHTTPError(c, endpoint.ErrInvalid)
	}
	mutation, err := newAdminMutation(c, "/endpoints/"+string(id), string(kind), request.IdempotencyKey, request)
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
	command := endpoint.Command{Kind: kind, Type: kind, CommandID: mutation.commandID, ID: mutation.commandID, CorrelationID: mutation.requestID, OperationID: mutation.operationID, PrincipalID: mutation.principal, RequestID: mutation.requestID, IdempotencyScope: mutation.scope, IdempotencyKey: mutation.key, RequestDigest: mutation.requestDigest, EndpointID: id, ExpectedAggregateVersion: *request.ExpectedAggregateVersion, ExpectedVersion: *request.ExpectedAggregateVersion, ExpectedVersionSet: true}
	result, err := endpointExecute(ctx, command)
	if err != nil {
		return adminHTTPError(c, err)
	}
	response, err := endpointMutationResponse(ctx, result)
	if err != nil {
		return adminHTTPError(c, err)
	}
	adminAudit(c, string(kind), "/endpoints/"+string(id), "accepted")
	return c.JSON(http.StatusAccepted, response)
}

func endpointEnable(c echo.Context) error  { return endpointLifecycle(c, endpoint.CommandEnable) }
func endpointDisable(c echo.Context) error { return endpointLifecycle(c, endpoint.CommandDisable) }
func endpointRelogin(c echo.Context) error { return endpointLifecycle(c, endpoint.CommandRelogin) }
func endpointDelete(c echo.Context) error  { return endpointLifecycle(c, endpoint.CommandRemove) }

func endpointDiagnostics(c echo.Context) error {
	if err := requireAdmin(c); err != nil {
		return err
	}
	id := adapterapi.EndpointID(c.Param("id"))
	if !id.Valid() {
		return adminHTTPError(c, endpoint.ErrNotFound)
	}
	ctx, cancel := withAdminContext(c)
	defer cancel()
	service := endpointService()
	if service == nil {
		return adminHTTPError(c, errors.New("endpoint service unavailable"))
	}
	view, err := service.Get(ctx, id)
	if err != nil {
		return adminHTTPError(c, err)
	}
	diagnostic := adapterapi.DiagnosticReport{}
	if descriptor, ok := endpointDescriptor(ctx, view.AdapterKey); ok {
		if provider, ok := descriptor.(interface {
			Diagnostics(ctx context.Context, config adapterapi.ValidatedConfig) (adapterapi.DiagnosticReport, error)
		}); ok {
			diagnostic, err = provider.Diagnostics(ctx, view.Config)
			if err != nil {
				return adminHTTPError(c, err)
			}
		}
	}
	runtimeDiagnostics, err := endpointRuntimeDiagnostics(ctx, id, view.Generation)
	if err != nil {
		return adminHTTPError(c, err)
	}
	diagnostic.Entries = append(diagnostic.Entries, runtimeDiagnostics.Entries...)
	if err := diagnostic.Validate(); err != nil {
		return adminHTTPError(c, err)
	}
	adminAudit(c, "diagnostics", "/endpoints/"+string(id), "succeeded")
	return c.JSON(http.StatusOK, DiagnosticView{Entries: diagnostic.Entries})
}

func endpointActionSupported(ctx context.Context, view endpoint.EndpointView, action adapterapi.ActionKind) error {
	descriptor, ok := endpointDescriptor(ctx, view.AdapterKey)
	if !ok {
		return endpoint.ErrUnknownAdapter
	}
	if !descriptor.SupportedActions(view.Config).Has(action) {
		return adapterapi.ErrUnsupportedAction
	}
	return nil
}
