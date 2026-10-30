package dice

import (
	"context"

	"Scardice-core/core/configstate"
	"Scardice-core/eventstore"
)

func (d *Dice) saveEventSourcedConfig(ctx context.Context) error {
	d.configUpdateMu.Lock()
	defer d.configUpdateMu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	repository := configstate.NewRepository(d.DurableStore)
	state, err := repository.Load(ctx, d.BaseConfig.Name)
	if err != nil {
		return err
	}
	patch, err := durableConfigPatch(state, d.Config, d.CommandPrefix, d.DiceMasters, nil)
	if err != nil {
		return err
	}
	patch.Advanced = &configstate.AdvancedConfig{
		Show: d.AdvancedConfig.Show, Enable: d.AdvancedConfig.Enable,
		StoryLogBackendURL:                d.AdvancedConfig.StoryLogBackendUrl,
		StoryLogAPIVersion:                d.AdvancedConfig.StoryLogApiVersion,
		StoryLogBackendTokenRef:           state.Advanced.StoryLogBackendTokenRef,
		CustomReplyCooldown:               d.AdvancedConfig.CustomReplyCooldown,
		ExposeDangerousSealInst:           d.AdvancedConfig.ExposeDangerousSealInst,
		AllowFilesystemUnrestrictedAccess: d.AdvancedConfig.AllowFilesystemUnrestrictedAccess,
	}
	commandID, err := (eventstore.UUIDGenerator{}).NewID()
	if err != nil {
		return err
	}
	_, err = repository.DecideAndAppend(ctx, state, state.Version, eventstore.Metadata{
		CommandID: commandID, CorrelationID: commandID, Producer: "dice/config-save",
	}, configstate.Command{Kind: configstate.CommandPatch, Patch: &patch})
	return err
}
