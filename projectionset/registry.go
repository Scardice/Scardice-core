package projectionset

import (
	"Scardice-core/core/attributestate"
	"Scardice-core/core/configstate"
	"Scardice-core/core/extensionstate"
	"Scardice-core/core/groupstate"
	"Scardice-core/core/managerstate"
	"Scardice-core/core/playerstate"
	"Scardice-core/endpoint"
	"Scardice-core/eventstore"
)

const ProjectorVersion = endpoint.EndpointProjectionVersion

// StoreOptions returns the complete projector set for an application-owned
// event store. Runtime startup and migration targets must use the same set so
// readiness identity cannot drift between import and reopen.
func StoreOptions() []eventstore.StoreOption {
	projections := []eventstore.ProjectionDescriptor{
		attributestate.Projection(),
		configstate.ConfigProjection(),
		extensionstate.ExtensionProjection(),
		groupstate.GroupProjection(),
		managerstate.Projection(),
		playerstate.PlayerProjection(),
		playerstate.GroupUserAttrsProjection(),
		playerstate.CharacterProjection(),
		playerstate.ModerationProjection(),
	}
	projections = append(projections, endpoint.EndpointProjections()...)
	options := make([]eventstore.StoreOption, 0, len(projections))
	for _, projection := range projections {
		projection.Version = ProjectorVersion
		options = append(options, eventstore.WithProjection(projection))
	}
	return options
}
