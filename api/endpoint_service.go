package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"strings"
	"sync"

	"Scardice-core/adapterapi"
	"Scardice-core/endpoint"
)

var endpointServiceState struct {
	sync.RWMutex
	bootstrap      *endpoint.Bootstrap
	service        *endpoint.Service
	actionExecutor endpoint.ActionExecutor
}

func RegisterEndpointBootstrap(bootstrap *endpoint.Bootstrap) {
	endpointServiceState.Lock()
	endpointServiceState.bootstrap = bootstrap
	if bootstrap != nil {
		endpointServiceState.service = bootstrap.Service
	}
	endpointServiceState.Unlock()
}

func RegisterEndpointService(service *endpoint.Service) {
	endpointServiceState.Lock()
	endpointServiceState.bootstrap = nil
	endpointServiceState.service = service
	endpointServiceState.Unlock()
}

// RegisterEndpointActionExecutor supplies the application action seam. The API
// never receives or stores a live adapter runtime.
func RegisterEndpointActionExecutor(executor endpoint.ActionExecutor) {
	endpointServiceState.Lock()
	endpointServiceState.actionExecutor = executor
	endpointServiceState.Unlock()
}

func endpointActionExecutor() endpoint.ActionExecutor {
	endpointServiceState.RLock()
	defer endpointServiceState.RUnlock()
	if endpointServiceState.actionExecutor != nil {
		return endpointServiceState.actionExecutor
	}
	if endpointServiceState.bootstrap != nil {
		return endpointActionExecutorFromBootstrap(endpointServiceState.bootstrap)
	}
	return nil
}

func endpointActionExecutorFromBootstrap(bootstrap *endpoint.Bootstrap) endpoint.ActionExecutor {
	if bootstrap == nil {
		return nil
	}
	return bootstrap.Supervisor
}

func endpointService() *endpoint.Service {
	endpointServiceState.RLock()
	defer endpointServiceState.RUnlock()
	if endpointServiceState.bootstrap != nil {
		return endpointServiceState.bootstrap.Service
	}
	return endpointServiceState.service
}

func endpointExecute(ctx context.Context, command endpoint.Command) (endpoint.Result, error) {
	endpointServiceState.RLock()
	bootstrap, service := endpointServiceState.bootstrap, endpointServiceState.service
	endpointServiceState.RUnlock()
	if bootstrap != nil {
		return bootstrap.Execute(ctx, command)
	}
	if service != nil {
		return service.Execute(ctx, command)
	}
	return endpoint.Result{}, errors.New("pureonebot endpoint service is unavailable")
}

func pureMutationCommandID(kind endpoint.CommandKind, id, idempotencyKey string) string {
	key := strings.TrimSpace(idempotencyKey)
	if key == "" {
		return "api:" + string(kind) + ":" + id + ":" + uuid.NewString()
	}
	sum := sha256.Sum256([]byte(key))
	return "api:" + string(kind) + ":" + id + ":idem-" + hex.EncodeToString(sum[:16])
}

func pureOnebotCommand(ctx context.Context, id string, kind endpoint.CommandKind, idempotencyKey string) (endpoint.Result, error) {
	service := endpointService()
	if service == nil {
		return endpoint.Result{}, errors.New("pureonebot endpoint service is unavailable")
	}
	endpointID := adapterapi.EndpointID(id)
	if !endpointID.Valid() {
		return endpoint.Result{}, endpoint.ErrNotFound
	}
	commandID := pureMutationCommandID(kind, id, idempotencyKey)
	command := endpoint.Command{CommandID: commandID, CorrelationID: commandID, EndpointID: endpointID}
	switch kind {
	case endpoint.CommandEnable:
		command.Kind, command.Type = endpoint.CommandEnable, endpoint.CommandEnable
	case endpoint.CommandDisable:
		command.Kind, command.Type = endpoint.CommandDisable, endpoint.CommandDisable
	case endpoint.CommandRemove:
		command.Kind, command.Type = endpoint.CommandRemove, endpoint.CommandRemove
	default:
		return endpoint.Result{}, errors.New("unsupported pureonebot endpoint command")
	}
	return endpointExecute(ctx, command)
}

func pureOnebotCreateAndEnable(ctx context.Context, mode, url, listenAddress, account, token, idempotencyKey string) (endpoint.Result, error) {
	service := endpointService()
	if service == nil {
		return endpoint.Result{}, errors.New("pureonebot endpoint service is unavailable")
	}
	mode = strings.ToLower(strings.TrimSpace(mode))
	raw := map[string]any{"mode": mode, "accountHint": strings.TrimSpace(account), "friendRequestPolicy": "accept"}
	if strings.TrimSpace(token) != "" {
		raw["token"] = map[string]any{"secretRef": "onebot-token", "version": uint64(1)}
	}
	if mode == "client" {
		raw["url"] = strings.TrimSpace(url)
	} else {
		raw["listenAddress"] = strings.TrimSpace(listenAddress)
	}
	canonical, marshalErr := json.Marshal(raw)
	if marshalErr != nil {
		return endpoint.Result{}, marshalErr
	}
	config, validateErr := service.ValidateConfig(ctx, adapterapi.AdapterKey("pureonebot"), canonical)
	if validateErr != nil {
		return endpoint.Result{}, validateErr
	}
	id := adapterapi.EndpointID("pureonebot-" + uuid.NewString())
	if strings.TrimSpace(idempotencyKey) != "" {
		sum := sha256.Sum256([]byte(idempotencyKey))
		id = adapterapi.EndpointID("pureonebot-idem-" + hex.EncodeToString(sum[:16]))
	}
	createID := "api:create:" + string(id)
	command := endpoint.Command{CommandID: createID, CorrelationID: createID, EndpointID: id, AdapterKey: adapterapi.AdapterKey("pureonebot"), Config: config}
	if strings.TrimSpace(token) != "" {
		command.SecretInput = &endpoint.SecretInput{Ref: "onebot-token", Version: 1, Plaintext: []byte(token)}
	}
	if _, createErr := endpointExecute(ctx, command); createErr != nil {
		return endpoint.Result{}, createErr
	}
	enableID := "api:enable:" + string(id)
	return endpointExecute(ctx, endpoint.Command{Kind: endpoint.CommandEnable, Type: endpoint.CommandEnable, CommandID: enableID, CorrelationID: enableID, EndpointID: id})
}

func pureOnebotUpdateConfig(ctx context.Context, id string, ignore *bool, assetURL *string, idempotencyKey string) (endpoint.EndpointView, error) {
	service := endpointService()
	if service == nil {
		return endpoint.EndpointView{}, errors.New("pureonebot endpoint service is unavailable")
	}
	endpointID := adapterapi.EndpointID(id)
	view, err := service.Get(ctx, endpointID)
	if err != nil {
		return endpoint.EndpointView{}, err
	}
	if view.AdapterKey != adapterapi.AdapterKey("pureonebot") {
		return endpoint.EndpointView{}, endpoint.ErrNotFound
	}
	var raw map[string]any
	if err := json.Unmarshal(view.Config.Canonical, &raw); err != nil {
		return endpoint.EndpointView{}, err
	}
	if ignore != nil {
		if *ignore {
			raw["friendRequestPolicy"] = "ignore"
		} else {
			raw["friendRequestPolicy"] = "accept"
		}
		raw["ignoreFriendRequest"] = *ignore
	}
	if assetURL != nil {
		raw["imageAssetBaseUrl"] = strings.TrimSpace(*assetURL)
	}
	canonical, err := json.Marshal(raw)
	if err != nil {
		return endpoint.EndpointView{}, err
	}
	config, err := service.ValidateConfig(ctx, view.AdapterKey, canonical)
	if err != nil {
		return endpoint.EndpointView{}, err
	}
	commandID := pureMutationCommandID(endpoint.CommandUpdateConfig, id, idempotencyKey)
	if _, err = endpointExecute(ctx, endpoint.Command{Kind: endpoint.CommandUpdateConfig, Type: endpoint.CommandUpdateConfig, CommandID: commandID, CorrelationID: commandID, EndpointID: endpointID, Config: config}); err != nil {
		return endpoint.EndpointView{}, err
	}
	return service.Get(ctx, endpointID)
}

func pureEndpointHTTPStatus(err error) int {
	if err == nil {
		return 200
	}
	switch {
	case errors.Is(err, endpoint.ErrNotFound):
		return 404
	case errors.Is(err, endpoint.ErrConflict), errors.Is(err, endpoint.ErrCommandConflict), errors.Is(err, endpoint.ErrStaleExpectedVersion), errors.Is(err, endpoint.ErrInvalidTransition):
		return 409
	case errors.Is(err, endpoint.ErrInvalid), errors.Is(err, endpoint.ErrInvalidConfig), errors.Is(err, adapterapi.ErrInvalidConfig), errors.Is(err, endpoint.ErrUnknownAdapter):
		return 400
	default:
		return 503
	}
}
