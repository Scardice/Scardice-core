package dice

import (
	"context"
	"encoding/json"

	"Scardice-core/adapterapi"
	"Scardice-core/core/execution"
	"Scardice-core/endpoint"
	"Scardice-core/eventstore"
)

// checkEndpointFence binds a worker-delivered root to the durable endpoint
// generation it actually came from, including changes while a Promise waits.
func (t *DurableCallbackTransaction) checkEndpointFence(ctx context.Context, id adapterapi.EndpointID, generation, desiredVersion uint64) error {
	if t == nil || t.domain == nil || !id.Valid() || generation == 0 || desiredVersion == 0 {
		return eventstore.ErrInvalidMetadata
	}
	reader, ok := t.store.(eventstore.ProjectionDependencyRepository)
	if !ok {
		return execution.ErrDependencyUnavailable
	}
	stream := eventstore.StreamID{AggregateType: endpoint.EndpointAggregateType, AggregateID: string(id)}
	key := execution.StreamParticipantKey(stream)
	participant, err := t.domain.Owner(ctx, key, func(loadCtx context.Context) (execution.Participant, execution.ReadDependencies, error) {
		snapshot, loadErr := reader.ReadProjectionDependency(loadCtx, endpoint.EndpointProjectionName, string(id), stream)
		if loadErr != nil {
			return nil, execution.ReadDependencies{}, loadErr
		}
		if !snapshot.Found || snapshot.Stream != stream || snapshot.Row.ProjectionGeneration != snapshot.Snapshot.ProjectionGeneration {
			return nil, execution.ReadDependencies{}, eventstore.ErrNotFound
		}
		var view endpoint.EndpointView
		if decodeErr := json.Unmarshal(snapshot.Row.Payload, &view); decodeErr != nil {
			return nil, execution.ReadDependencies{}, decodeErr
		}
		if view.EndpointID != id || view.Version != snapshot.StreamVersion {
			return nil, execution.ReadDependencies{}, execution.ErrDomainSnapshotChanged
		}
		return &endpointFenceParticipant{view: view}, execution.ReadDependenciesFromProjection(snapshot), nil
	})
	if err != nil {
		return err
	}
	fence, ok := participant.(*endpointFenceParticipant)
	if !ok {
		return execution.ErrParticipantType
	}
	if fence.view.Generation != generation || fence.view.DesiredVersion != desiredVersion {
		return eventstore.ErrStaleLease
	}
	return nil
}

type endpointFenceParticipant struct{ view endpoint.EndpointView }

func (*endpointFenceParticipant) Contribute(context.Context) (eventstore.UnitOfWork, error) {
	return eventstore.UnitOfWork{}, nil
}
