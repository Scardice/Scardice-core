package api

import (
	"context"
	"errors"
	"sync"

	"Scardice-core/adapterapi"
	"Scardice-core/endpoint"
)

type endpointApplication interface {
	endpointService() *endpoint.Service
	Execute(ctx context.Context, command endpoint.Command) (endpoint.Result, error)
	ExecuteAction(ctx context.Context, request adapterapi.ActionRequest) (adapterapi.ActionResult, error)
}

type bootstrapEndpointApplication struct {
	bootstrap *endpoint.Bootstrap
}

func (a bootstrapEndpointApplication) endpointService() *endpoint.Service {
	if a.bootstrap == nil {
		return nil
	}
	return a.bootstrap.Service
}

func (a bootstrapEndpointApplication) Execute(ctx context.Context, command endpoint.Command) (endpoint.Result, error) {
	if a.bootstrap == nil {
		return endpoint.Result{}, errors.New("endpoint application is unavailable")
	}
	return a.bootstrap.Execute(ctx, command)
}

func (a bootstrapEndpointApplication) ExecuteAction(ctx context.Context, request adapterapi.ActionRequest) (adapterapi.ActionResult, error) {
	if a.bootstrap == nil || a.bootstrap.Supervisor == nil {
		return adapterapi.ActionResult{}, errors.New("endpoint action executor is unavailable")
	}
	return a.bootstrap.Supervisor.ExecuteAction(ctx, request)
}

func (a bootstrapEndpointApplication) RuntimeDiagnostics(ctx context.Context, id adapterapi.EndpointID, generation uint64) (adapterapi.DiagnosticReport, error) {
	if a.bootstrap == nil || a.bootstrap.Supervisor == nil {
		return adapterapi.DiagnosticReport{}, nil
	}
	return a.bootstrap.Supervisor.RuntimeDiagnostics(ctx, id, generation)
}

var endpointServiceState struct {
	sync.RWMutex
	application endpointApplication
}

func RegisterEndpointBootstrap(bootstrap *endpoint.Bootstrap) {
	if bootstrap == nil {
		registerEndpointApplication(nil)
		return
	}
	registerEndpointApplication(bootstrapEndpointApplication{bootstrap: bootstrap})
}

func registerEndpointApplication(application endpointApplication) {
	endpointServiceState.Lock()
	endpointServiceState.application = application
	endpointServiceState.Unlock()
}

func endpointActionExecutor() endpoint.ActionExecutor {
	endpointServiceState.RLock()
	defer endpointServiceState.RUnlock()
	return endpointServiceState.application
}

func endpointService() *endpoint.Service {
	endpointServiceState.RLock()
	defer endpointServiceState.RUnlock()
	if endpointServiceState.application == nil {
		return nil
	}
	return endpointServiceState.application.endpointService()
}

func endpointRuntimeDiagnostics(ctx context.Context, id adapterapi.EndpointID, generation uint64) (adapterapi.DiagnosticReport, error) {
	endpointServiceState.RLock()
	application := endpointServiceState.application
	endpointServiceState.RUnlock()
	provider, ok := application.(interface {
		RuntimeDiagnostics(context.Context, adapterapi.EndpointID, uint64) (adapterapi.DiagnosticReport, error)
	})
	if !ok {
		return adapterapi.DiagnosticReport{}, nil
	}
	return provider.RuntimeDiagnostics(ctx, id, generation)
}

func endpointExecute(ctx context.Context, command endpoint.Command) (endpoint.Result, error) {
	endpointServiceState.RLock()
	application := endpointServiceState.application
	endpointServiceState.RUnlock()
	if application == nil {
		return endpoint.Result{}, errors.New("endpoint application is unavailable")
	}
	return application.Execute(ctx, command)
}
