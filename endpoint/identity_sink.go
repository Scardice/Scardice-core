package endpoint

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"Scardice-core/adapterapi"
	"Scardice-core/eventstore"
)

// IdentityObservationHook runs after the matching identity fact is durable.
type IdentityObservationHook func(context.Context, FencedIdentityObservation) error

// NewIdentityObservationSink persists every provider identity behind the
// generation and desired-version fence. Stale and removed endpoints are
// intentionally ignored because their runtime no longer owns current state.
func NewIdentityObservationSink(service *Service, hooks ...IdentityObservationHook) IdentityObservationSink {
	return IdentityObservationSinkFunc(func(ctx context.Context, observation FencedIdentityObservation) error {
		if service == nil || service.Repository == nil {
			return ErrInvalid
		}
		if observation.Observation.Kind != adapterapi.LifecycleObservationIdentity || !observation.Observation.ProviderID.Valid() {
			return ErrInvalid
		}
		state, err := service.Repository.Load(ctx, observation.EndpointID)
		if err != nil {
			if errors.Is(err, ErrNotFound) || errors.Is(err, eventstore.ErrNotFound) {
				return nil
			}
			return err
		}
		if state.Generation != observation.Generation || state.DesiredVersion != observation.DesiredVersion {
			return nil
		}
		displayName := ""
		if observation.Observation.Code == "identity" {
			displayName = strings.TrimSpace(observation.Observation.Detail)
			if !validDisplayName(displayName) {
				displayName = ""
			}
		}
		recordDisplayName := state.DisplayName == "" && displayName != ""
		if state.ProviderID != observation.Observation.ProviderID || recordDisplayName {
			commandDisplayName := ""
			if state.DisplayName == "" {
				commandDisplayName = displayName
			}
			identity := string(observation.Observation.ProviderID)
			if commandDisplayName != "" {
				identity += "\x00" + commandDisplayName
			}
			commandID := fmt.Sprintf("supervisor:identity:%s:%d:%d:%d:%s", observation.EndpointID, observation.Generation, observation.DesiredVersion, state.Version, shortHash(identity))
			if _, err := service.RecordIdentity(ctx, Command{
				CommandID: commandID, CorrelationID: commandID, EndpointID: observation.EndpointID,
				Generation: observation.Generation, DesiredVersion: observation.DesiredVersion,
				ProviderID: observation.Observation.ProviderID, DisplayName: commandDisplayName,
			}); err != nil {
				return err
			}
		}
		for _, hook := range hooks {
			if hook != nil {
				if err := hook(ctx, observation); err != nil {
					return err
				}
			}
		}
		return nil
	})
}
