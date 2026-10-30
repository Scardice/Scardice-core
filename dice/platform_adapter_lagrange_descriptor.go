package dice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"Scardice-core/adapterapi"
)

const LagrangeAdapterKey adapterapi.AdapterKey = "lagrange"

// LagrangeDescriptor owns external and process-owned Lagrange OneBot v11
// configurations.
type LagrangeDescriptor struct{}

func NewLagrangeDescriptor() adapterapi.Descriptor { return LagrangeDescriptor{} }

func (LagrangeDescriptor) Key() adapterapi.AdapterKey { return LagrangeAdapterKey }
func (LagrangeDescriptor) ConfigVersion() uint16      { return OnebotConfigVersion }

func (LagrangeDescriptor) ValidateConfig(ctx context.Context, raw json.RawMessage) (adapterapi.ValidatedConfig, error) {
	return validateLegacyOnebotDescriptorConfig(ctx, raw, builtinModeLagrange)
}

func (descriptor LagrangeDescriptor) SupportedActions(config adapterapi.ValidatedConfig) adapterapi.ActionSet {
	actions := OnebotDescriptor{}.SupportedActions(config)
	if isBuiltinOnebotConfig(config) {
		actions = actions.With(adapterapi.ActionKindRequestQRCode)
	}
	return actions
}

func (descriptor LagrangeDescriptor) Capabilities(config adapterapi.ValidatedConfig) adapterapi.CapabilitySet {
	capabilities := OnebotDescriptor{}.Capabilities(config)
	if isBuiltinOnebotConfig(config) {
		capabilities |= adapterapi.CapabilityArtifacts
	}
	return capabilities
}

func (descriptor LagrangeDescriptor) NewRuntime(init adapterapi.RuntimeInit) (adapterapi.AdapterRuntime, error) {
	if !init.EndpointID.Valid() || init.Generation == 0 || init.DesiredVersion == 0 {
		return nil, errors.New("lagrange: runtime identity is incomplete")
	}
	if err := init.Config.Validate(); err != nil {
		return nil, err
	}
	builtin, builtinErr := decodeBuiltinOnebotCanonical(init.Config)
	var validated adapterapi.ValidatedConfig
	var err error
	if builtinErr == nil {
		validated, err = descriptor.ValidateConfig(context.Background(), init.Config.Canonical)
	} else {
		validated, err = (OnebotDescriptor{}).validateConfig(context.Background(), init.Config.Canonical, false)
	}
	if err != nil || validated.Version != init.Config.Version || !bytes.Equal(validated.Canonical, init.Config.Canonical) || len(validated.SecretRefs) != len(init.Config.SecretRefs) {
		return nil, errors.New("lagrange: runtime config was not validated by the Lagrange descriptor")
	}
	for index := range validated.SecretRefs {
		if validated.SecretRefs[index] != init.Config.SecretRefs[index] {
			return nil, errors.New("lagrange: runtime secret references do not match canonical config")
		}
	}
	if builtinErr == nil {
		return newBuiltinLagrangeRuntime(init, builtin), nil
	}
	return OnebotDescriptor{}.NewRuntime(init)
}
