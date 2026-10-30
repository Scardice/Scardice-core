package dice

import (
	"context"
	"errors"

	"Scardice-core/adapterapi"
	"Scardice-core/endpoint"
	"Scardice-core/eventstore"
)

var ErrEndpointLifecycleUnavailable = errors.New("dice: endpoint lifecycle unavailable")

type EndpointLifecyclePort interface {
	Relogin(ctx context.Context, command endpoint.Command) (endpoint.Result, error)
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
	_, err = d.EndpointLifecycle.Relogin(ctx, endpoint.Command{
		Kind: endpoint.CommandRelogin, Type: endpoint.CommandRelogin,
		CommandID: commandID, ID: commandID, CorrelationID: commandID,
		EndpointID: id,
	})
	return err
}
