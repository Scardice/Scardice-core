package dice

import (
	"context"
	"errors"

	"Scardice-core/adapterapi"
	"Scardice-core/endpoint"
	"Scardice-core/eventstore"
)

var ErrEndpointLifecycleUnavailable = errors.New("dice: endpoint lifecycle unavailable")

// EndpointLifecyclePort is the application boundary that commits lifecycle
// commands and immediately reconciles their effects through the supervisor.
type EndpointLifecyclePort interface {
	Execute(ctx context.Context, command endpoint.Command) (endpoint.Result, error)
}

func (d *Dice) DisableEndpoint(ctx context.Context, endpointID string) error {
	if d == nil || d.EndpointLifecycle == nil {
		return ErrEndpointLifecycleUnavailable
	}
	id := adapterapi.EndpointID(endpointID)
	if !id.Valid() {
		return ErrEndpointLifecycleUnavailable
	}
	commandID, err := (eventstore.UUIDGenerator{}).NewID()
	if err != nil {
		return err
	}
	_, err = d.EndpointLifecycle.Execute(ctx, endpoint.Command{
		Kind: endpoint.CommandDisable, Type: endpoint.CommandDisable,
		CommandID: commandID, ID: commandID, CorrelationID: commandID,
		EndpointID: id,
	})
	return err
}

func (d *Dice) ReloginEndpoint(ctx context.Context, endpointID string) error {
	if d == nil || d.EndpointLifecycle == nil {
		return ErrEndpointLifecycleUnavailable
	}
	id := adapterapi.EndpointID(endpointID)
	if !id.Valid() {
		return ErrEndpointLifecycleUnavailable
	}
	commandID, err := (eventstore.UUIDGenerator{}).NewID()
	if err != nil {
		return err
	}
	_, err = d.EndpointLifecycle.Execute(ctx, endpoint.Command{
		Kind: endpoint.CommandRelogin, Type: endpoint.CommandRelogin,
		CommandID: commandID, ID: commandID, CorrelationID: commandID,
		EndpointID: id,
	})
	return err
}
