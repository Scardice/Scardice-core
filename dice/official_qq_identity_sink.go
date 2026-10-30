package dice

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/sealdice/botgo/dto"

	"Scardice-core/endpoint"
)

// NewIdentityObservationSink persists every fenced provider identity and then
// runs the Official QQ migration only for the matching endpoint.
func NewIdentityObservationSink(d *Dice, service *endpoint.Service) endpoint.IdentityObservationSink {
	return endpoint.NewIdentityObservationSink(service, func(ctx context.Context, observation endpoint.FencedIdentityObservation) error {
		if d == nil {
			return nil
		}
		view, err := service.Get(ctx, observation.EndpointID)
		if err != nil {
			return err
		}
		if view.AdapterKey != OfficialQQAdapterKey || view.Generation != observation.Generation || view.DesiredVersion != observation.DesiredVersion || view.ProviderID != observation.Observation.ProviderID {
			return nil
		}
		var config officialQQCanonicalConfig
		if decodeErr := json.Unmarshal(view.Config.Canonical, &config); decodeErr != nil || config.AppID == 0 {
			return errors.New("official QQ identity observation: invalid endpoint config")
		}
		adapter := &PlatformAdapterOfficialQQ{AppID: config.AppID}
		_, err = adapter.migrateVerifiedIdentityAfterMe(ctx, d, &dto.User{ID: observation.Observation.ProviderID.String()})
		return err
	})
}
