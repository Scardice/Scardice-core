package dice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"Scardice-core/core/configstate"
	"Scardice-core/core/execution"
	"Scardice-core/core/extensionstate"
	"Scardice-core/dice/censor"
	"Scardice-core/eventstore"
	"Scardice-core/utils"
)

var (
	ErrDurableStateUnavailable = errors.New("dice: durable state is not attached")
	ErrDurableProjection       = errors.New("dice: durable state projection is unavailable")
)

// DurableStoreAttached reports whether this Dice instance has an event-store
// owner for migrated configuration and extension state. The store is kept as
// an interface so callers cannot reach a mutable aggregate or projection row.
func (d *Dice) DurableStoreAttached() bool {
	return d != nil && d.DurableStore != nil
}

// AttachDurableStore binds the event-store owner before runtime/plugin setup.
// The caller remains responsible for registering the required projections.
func (d *Dice) AttachDurableStore(store eventstore.Store) error {
	if d == nil {
		return ErrDurableStateUnavailable
	}
	if store == nil {
		return errors.New("dice: durable store is nil")
	}
	d.DurableStore = store
	if d.ConfigManager != nil {
		d.ConfigManager.SetOwner(d)
	}
	return nil
}

func (d *Dice) durableStoreAndID() (eventstore.Store, string, error) {
	if d == nil || d.DurableStore == nil {
		return nil, "", ErrDurableStateUnavailable
	}
	id := strings.TrimSpace(d.BaseConfig.Name)
	if id == "" {
		return nil, "", fmt.Errorf("%w: Dice name is empty", ErrDurableStateUnavailable)
	}
	return d.DurableStore, id, nil
}

func (d *Dice) DurableConfigState(ctx context.Context) (configstate.State, error) {
	store, id, err := d.durableStoreAndID()
	if err != nil {
		return configstate.State{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	state, err := configstate.ReadProjected(ctx, store, id)
	if err != nil {
		return configstate.State{}, fmt.Errorf("%w: config: %w", ErrDurableProjection, err)
	}
	return state, nil
}

func (d *Dice) DurableExtensionState(ctx context.Context) (extensionstate.State, error) {
	store, id, err := d.durableStoreAndID()
	if err != nil {
		return extensionstate.State{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	state, err := extensionstate.ReadProjected(ctx, store, id)
	if err != nil {
		return extensionstate.State{}, fmt.Errorf("%w: extension: %w", ErrDurableProjection, err)
	}
	return state, nil
}

// durableExtensionStateShared returns the extension state without copying it.
// The result is shared with the read cache and with every concurrent reader, so
// the caller must only read it and must not retain or modify any map inside it.
// Callers that need a private copy use DurableExtensionState.
func (d *Dice) durableExtensionStateShared(ctx context.Context) (extensionstate.State, error) {
	store, id, err := d.durableStoreAndID()
	if err != nil {
		return extensionstate.State{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	state, err := d.extensionReads.ReadShared(ctx, store, id)
	if err != nil {
		return extensionstate.State{}, fmt.Errorf("%w: extension: %w", ErrDurableProjection, err)
	}
	return state, nil
}

// DurableExtensionConfigItems returns detached compatibility DTOs ordered by
// extension identity and config key. It never returns projection-owned maps.
func (d *Dice) DurableExtensionConfigItems(ctx context.Context, pluginName string) ([]*ConfigItem, error) {
	state, err := d.durableExtensionStateShared(ctx)
	if err != nil {
		return nil, err
	}
	return d.extensionConfigItemsFromState(ctx, state, pluginName)
}

func (d *Dice) extensionConfigItemsFromState(ctx context.Context, state extensionstate.State, pluginName string) ([]*ConfigItem, error) {
	definitions := state.ConfigDefinitions[pluginName]
	keys := make([]string, 0, len(definitions))
	for key := range definitions {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	items := make([]*ConfigItem, 0, len(keys))
	for _, key := range keys {
		definition := definitions[key]
		item := durableConfigItem(definition)
		if value, ok := state.ConfigValues[pluginName][key]; ok {
			item.Value = durableLegacyValue(value)
		}
		items = append(items, item)
	}
	return items, nil
}

func (d *Dice) durableExtensionRepository() (*extensionstate.Repository, string, error) {
	store, id, err := d.durableStoreAndID()
	if err != nil {
		return nil, "", err
	}
	repo := extensionstate.NewRepository(store)
	// Repositories are cheap and built per call, so the state they continue
	// from has to live on the Dice.
	repo.Cache = &d.extensionSnapshots
	return repo, id, nil
}

type extensionParticipant struct {
	diceID   string
	base     extensionstate.State
	state    extensionstate.State
	events   []extensionstate.TypedEvent
	metadata eventstore.Metadata
}

func (p *extensionParticipant) Contribute(context.Context) (eventstore.UnitOfWork, error) {
	if p == nil || len(p.events) == 0 {
		return eventstore.UnitOfWork{}, nil
	}
	factory := eventstore.EventFactory{Clock: eventstore.SystemClock{}, IDs: eventstore.UUIDGenerator{}}
	metadata := p.metadata
	events := make([]eventstore.NewEvent, 0, len(p.events))
	for _, typed := range p.events {
		event, err := extensionstate.NewEventWithFactory(factory, typed, metadata)
		if err != nil {
			return eventstore.UnitOfWork{}, err
		}
		events = append(events, event)
		metadata.EventID = ""
	}
	return eventstore.UnitOfWork{Streams: []eventstore.StreamAppend{{
		Stream:          extensionstate.ExtensionStream(p.diceID),
		ExpectedVersion: p.base.Version,
		Events:          events,
	}}}, nil
}

func (p *extensionParticipant) decide(command extensionstate.Command, metadata eventstore.Metadata) error {
	if p == nil {
		return execution.ErrInvalidParticipant
	}
	command.ExpectedVersion = p.state.Version
	command.ExpectedVersionSet = true
	decision, err := extensionstate.Decide(p.state, command)
	if err != nil {
		return err
	}
	next := p.state
	for _, event := range decision.Events {
		next, err = extensionstate.Reduce(next, event)
		if err != nil {
			return err
		}
	}
	p.state = next
	p.events = append(p.events, decision.Events...)
	if p.metadata.CommandID == "" {
		p.metadata = metadata
	}
	return nil
}

func (d *Dice) extensionOwner(ctx context.Context, tx *execution.DomainTx) (*extensionParticipant, execution.ParticipantKey, error) {
	if d == nil || tx == nil || d.DurableStore == nil {
		return nil, execution.ParticipantKey{}, execution.ErrDomainTxUnavailable
	}
	stream := extensionstate.ExtensionStream(d.BaseConfig.Name)
	key := execution.StreamParticipantKey(stream)
	participant, err := tx.Owner(ctx, key, func(loadCtx context.Context) (execution.Participant, execution.ReadDependencies, error) {
		reader, ok := d.DurableStore.(eventstore.ProjectionDependencyRepository)
		if !ok {
			return nil, execution.ReadDependencies{}, ErrDurableProjection
		}
		snapshot, readErr := reader.ReadProjectionDependency(
			loadCtx, extensionstate.ExtensionProjectionName, stream.AggregateID, stream,
		)
		if readErr != nil {
			return nil, execution.ReadDependencies{}, readErr
		}
		var state extensionstate.State
		if snapshot.Found {
			if readErr = json.Unmarshal(snapshot.Row.Payload, &state); readErr != nil {
				return nil, execution.ReadDependencies{}, fmt.Errorf("dice: decode extension projection: %w", readErr)
			}
			if readErr = extensionstate.ValidateState(state); readErr != nil {
				return nil, execution.ReadDependencies{}, readErr
			}
			if state.DiceID != d.BaseConfig.Name || state.Version != snapshot.StreamVersion {
				return nil, execution.ReadDependencies{}, execution.ErrDomainSnapshotChanged
			}
		} else if snapshot.StreamVersion != 0 {
			return nil, execution.ReadDependencies{}, execution.ErrDomainSnapshotChanged
		}
		installed := &extensionParticipant{
			diceID: d.BaseConfig.Name,
			base:   state.Clone(),
			state:  state.Clone(),
		}
		return installed, execution.ReadDependenciesFromStream(eventstore.StreamSnapshot{
			Stream: stream, Version: snapshot.StreamVersion, Snapshot: snapshot.Snapshot,
		}), nil
	})
	if err != nil {
		return nil, execution.ParticipantKey{}, err
	}
	typed, ok := participant.(*extensionParticipant)
	if !ok {
		return nil, execution.ParticipantKey{}, execution.ErrInvalidParticipant
	}
	return typed, key, nil
}

func (d *Dice) ExtensionStateForDomain(ctx context.Context, tx *execution.DomainTx) (extensionstate.State, error) {
	participant, _, err := d.extensionOwner(ctx, tx)
	if err != nil {
		return extensionstate.State{}, err
	}
	return participant.state.Clone(), nil
}

func (d *Dice) ContributeExtensionCommand(
	ctx context.Context,
	tx *execution.DomainTx,
	metadata eventstore.Metadata,
	command extensionstate.Command,
) error {
	_, key, err := d.extensionOwner(ctx, tx)
	if err != nil {
		return err
	}
	return tx.Mutate(key, func(participant execution.Participant) error {
		typed, ok := participant.(*extensionParticipant)
		if !ok {
			return execution.ErrInvalidParticipant
		}
		return typed.decide(command, metadata)
	})
}

func (d *Dice) ensureExtensionInDomain(
	ctx context.Context,
	tx *execution.DomainTx,
	metadata eventstore.Metadata,
	ext *ExtInfo,
) error {
	if ext == nil {
		return errors.New("dice: extension is nil")
	}
	return d.ContributeExtensionCommand(ctx, tx, metadata, extensionstate.Command{
		Kind:     extensionstate.CommandDiscover,
		DiceID:   d.BaseConfig.Name,
		Identity: durableExtensionIdentity(ext),
	})
}

func durableExtensionIdentity(ext *ExtInfo) extensionstate.ExtensionIdentity {
	source := "script"
	if ext != nil && !ext.IsJsExt {
		source = "builtin"
	}
	if ext != nil && ext.Source != nil && ext.Source.PackageID != "" {
		source = "package:" + ext.Source.PackageID
	}
	identity := extensionstate.ExtensionIdentity{Source: source}
	if ext != nil {
		identity.ID = ext.Name
		identity.Name = ext.Name
		identity.Version = ext.Version
		identity.Aliases = append([]string(nil), ext.Aliases...)
	}
	return identity
}

func (d *Dice) DurableDiscoverExtension(ctx context.Context, ext *ExtInfo) error {
	return d.withFreshDomainExecution(ctx, "extension-discover", durableExtensionIdentity(ext), func(transaction *DurableCallbackTransaction, metadata eventstore.Metadata) error {
		return d.ensureExtensionInDomain(ctx, transaction.Domain(), metadata, ext)
	})
}

func (d *Dice) DurableRegisterConfig(ctx context.Context, ext *ExtInfo, item *ConfigItem) error {
	if ext == nil {
		return errors.New("dice: extension is nil")
	}
	return d.withFreshDomainExecution(ctx, "extension-config-register", struct {
		Extension extensionstate.ExtensionIdentity `json:"extension"`
		Item      *ConfigItem                      `json:"item"`
	}{durableExtensionIdentity(ext), item}, func(transaction *DurableCallbackTransaction, metadata eventstore.Metadata) error {
		if err := d.ensureExtensionInDomain(ctx, transaction.Domain(), metadata, ext); err != nil {
			return err
		}
		return d.registerConfigInDomain(ctx, transaction, metadata, ext.Name, item)
	})
}

func (d *Dice) DurableSetConfig(ctx context.Context, ext *ExtInfo, key string, value any) error {
	if ext == nil {
		return errors.New("dice: extension is nil")
	}
	return d.withFreshDomainExecution(ctx, "extension-config-set", struct {
		ExtensionID string `json:"extensionId"`
		Key         string `json:"key"`
		Value       any    `json:"value"`
	}{ext.Name, key, value}, func(transaction *DurableCallbackTransaction, metadata eventstore.Metadata) error {
		if err := d.ensureExtensionInDomain(ctx, transaction.Domain(), metadata, ext); err != nil {
			return err
		}
		return d.setConfigInDomain(ctx, transaction, metadata, ext.Name, key, value)
	})
}

func (d *Dice) DurableUnregisterConfig(ctx context.Context, ext *ExtInfo, key string) error {
	if ext == nil {
		return errors.New("dice: extension is nil")
	}
	return d.withFreshDomainExecution(ctx, "extension-config-unregister", struct {
		ExtensionID string `json:"extensionId"`
		Key         string `json:"key"`
	}{ext.Name, key}, func(transaction *DurableCallbackTransaction, metadata eventstore.Metadata) error {
		if err := d.ensureExtensionInDomain(ctx, transaction.Domain(), metadata, ext); err != nil {
			return err
		}
		return d.unregisterConfigInDomain(ctx, transaction, metadata, ext.Name, key)
	})
}

func (d *Dice) DurableConfigItem(ctx context.Context, ext *ExtInfo, key string) (*ConfigItem, error) {
	if ext == nil {
		return nil, errors.New("dice: extension is nil")
	}
	state, err := d.durableExtensionStateShared(ctx)
	if err != nil {
		return nil, err
	}
	var item *ConfigItem
	if definition, ok := state.ConfigDefinitions[ext.Name][key]; ok {
		item = durableConfigItem(definition)
		if value, ok := state.ConfigValues[ext.Name][key]; ok {
			item.Value = durableLegacyValue(value)
		}
	}
	return item, nil
}

func (d *Dice) DurableSetExtensionEnabled(ctx context.Context, ext *ExtInfo, enabled bool) error {
	if ext == nil {
		return errors.New("dice: extension is nil")
	}
	return d.withFreshDomainExecution(ctx, "extension-enabled", struct {
		Extension extensionstate.ExtensionIdentity `json:"extension"`
		Enabled   bool                             `json:"enabled"`
	}{durableExtensionIdentity(ext), enabled}, func(transaction *DurableCallbackTransaction, metadata eventstore.Metadata) error {
		tx := transaction.Domain()
		if err := d.ensureExtensionInDomain(ctx, tx, metadata, ext); err != nil {
			return err
		}
		kind := extensionstate.CommandDisable
		if enabled {
			kind = extensionstate.CommandEnable
		}
		return d.ContributeExtensionCommand(ctx, tx, metadata, extensionstate.Command{
			Kind: kind, ExtensionID: ext.Name,
		})
	})
}

func durableConfigDefinition(extensionID string, item *ConfigItem) (extensionstate.ConfigDefinition, error) {
	if strings.TrimSpace(extensionID) == "" || item == nil || strings.TrimSpace(item.Key) == "" {
		return extensionstate.ConfigDefinition{}, extensionstate.ErrInvalidCommand
	}
	typ, err := durableConfigType(item.Type)
	if err != nil {
		return extensionstate.ConfigDefinition{}, err
	}
	definition := extensionstate.ConfigDefinition{
		ExtensionID: extensionID,
		Key:         item.Key,
		Type:        typ,
		Description: item.Description,
		Group:       item.Group,
		Deprecated:  item.Deprecated,
	}
	if options, ok := item.Option.([]string); ok {
		definition.Options = append([]string(nil), options...)
	}
	if item.DefaultValue != nil {
		value, valueErr := durableConfigValue(typ, item.DefaultValue)
		if valueErr != nil {
			return extensionstate.ConfigDefinition{}, valueErr
		}
		definition.Default = value
		definition.DefaultSet = true
	}
	return definition, nil
}

func durableConfigType(value string) (extensionstate.ConfigType, error) {
	switch strings.TrimSpace(value) {
	case "string":
		return extensionstate.ConfigString, nil
	case "bool":
		return extensionstate.ConfigBool, nil
	case "float":
		return extensionstate.ConfigFloat, nil
	case "int":
		return extensionstate.ConfigInt, nil
	case "template":
		return extensionstate.ConfigTemplate, nil
	case "option":
		return extensionstate.ConfigOption, nil
	case "secret":
		return extensionstate.ConfigSecret, nil
	case "task:cron":
		return extensionstate.ConfigTaskCron, nil
	case "task:daily":
		return extensionstate.ConfigTaskDaily, nil
	case "task:once":
		return extensionstate.ConfigTaskOnce, nil
	default:
		return "", fmt.Errorf("dice: unsupported extension config type %q", value)
	}
}

func durableConfigValue(typ extensionstate.ConfigType, value any) (extensionstate.ConfigValue, error) {
	switch typ {
	case extensionstate.ConfigString, extensionstate.ConfigTaskCron, extensionstate.ConfigTaskDaily, extensionstate.ConfigTaskOnce:
		text, ok := value.(string)
		if !ok {
			return extensionstate.ConfigValue{}, extensionstate.ErrInvalidConfigValue
		}
		return extensionstate.ConfigValue{Type: typ, String: text}, nil
	case extensionstate.ConfigBool:
		item, ok := value.(bool)
		if !ok {
			return extensionstate.ConfigValue{}, extensionstate.ErrInvalidConfigValue
		}
		return extensionstate.BoolValue(item), nil
	case extensionstate.ConfigInt:
		switch item := value.(type) {
		case int:
			return extensionstate.IntValue(int64(item)), nil
		case int8:
			return extensionstate.IntValue(int64(item)), nil
		case int16:
			return extensionstate.IntValue(int64(item)), nil
		case int32:
			return extensionstate.IntValue(int64(item)), nil
		case int64:
			return extensionstate.IntValue(item), nil
		case uint:
			return extensionstate.IntValue(int64(item)), nil
		case uint8:
			return extensionstate.IntValue(int64(item)), nil
		case uint16:
			return extensionstate.IntValue(int64(item)), nil
		case uint32:
			return extensionstate.IntValue(int64(item)), nil
		case uint64:
			if uint64(int64(item)) != item {
				return extensionstate.ConfigValue{}, extensionstate.ErrInvalidConfigValue
			}
			return extensionstate.IntValue(int64(item)), nil
		case float64:
			if math.Trunc(item) != item || float64(int64(item)) != item {
				return extensionstate.ConfigValue{}, extensionstate.ErrInvalidConfigValue
			}
			return extensionstate.IntValue(int64(item)), nil
		default:
			return extensionstate.ConfigValue{}, extensionstate.ErrInvalidConfigValue
		}
	case extensionstate.ConfigFloat:
		item, ok := value.(float64)
		if !ok {
			if integer, integerOK := value.(int64); integerOK {
				item = float64(integer)
			} else {
				return extensionstate.ConfigValue{}, extensionstate.ErrInvalidConfigValue
			}
		}
		if math.IsNaN(item) || math.IsInf(item, 0) {
			return extensionstate.ConfigValue{}, extensionstate.ErrInvalidConfigValue
		}
		return extensionstate.FloatValue(item), nil
	case extensionstate.ConfigTemplate:
		switch items := value.(type) {
		case []string:
			return extensionstate.TemplateValue(items), nil
		case []any:
			// A list decoded from JSON, as the WebUI and the HTTP API send it.
			texts := make([]string, len(items))
			for index, item := range items {
				text, ok := item.(string)
				if !ok {
					return extensionstate.ConfigValue{}, extensionstate.ErrInvalidConfigValue
				}
				texts[index] = text
			}
			return extensionstate.TemplateValue(texts), nil
		default:
			return extensionstate.ConfigValue{}, extensionstate.ErrInvalidConfigValue
		}
	case extensionstate.ConfigOption:
		item, ok := value.(string)
		if !ok {
			return extensionstate.ConfigValue{}, extensionstate.ErrInvalidConfigValue
		}
		return extensionstate.OptionValue(item), nil
	case extensionstate.ConfigSecret:
		item, ok := value.(string)
		if !ok || !durableSecretReference(item) {
			return extensionstate.ConfigValue{}, errors.New("dice: secret config requires a reference")
		}
		return extensionstate.SecretValue(item), nil
	default:
		return extensionstate.ConfigValue{}, extensionstate.ErrUnsupportedConfigType
	}
}

func durableConfigItem(definition extensionstate.ConfigDefinition) *ConfigItem {
	item := &ConfigItem{
		Key:          definition.Key,
		Type:         string(definition.Type),
		Group:        definition.Group,
		Description:  definition.Description,
		Deprecated:   definition.Deprecated,
		DefaultValue: durableLegacyValue(definition.Default),
		Value:        durableLegacyValue(definition.Default),
		Option:       append([]string(nil), definition.Options...),
	}
	return item
}

func durableLegacyValue(value extensionstate.ConfigValue) any {
	switch value.Type {
	case extensionstate.ConfigString, extensionstate.ConfigTaskCron, extensionstate.ConfigTaskDaily, extensionstate.ConfigTaskOnce:
		return value.String
	case extensionstate.ConfigBool:
		return value.Bool
	case extensionstate.ConfigFloat:
		return value.Float
	case extensionstate.ConfigInt:
		return value.Int
	case extensionstate.ConfigTemplate:
		return append([]string(nil), value.Strings...)
	case extensionstate.ConfigOption:
		return value.String
	case extensionstate.ConfigSecret:
		return value.SecretRef
	default:
		return nil
	}
}

func durableSecretReference(value string) bool {
	value = strings.TrimSpace(value)
	return strings.HasPrefix(value, "vault:") || strings.HasPrefix(value, "secret:")
}

func (d *Dice) registerConfigInDomain(
	ctx context.Context,
	transaction *DurableCallbackTransaction,
	metadata eventstore.Metadata,
	pluginName string,
	item *ConfigItem,
) error {
	if transaction == nil || item == nil {
		return errors.New("dice: config transaction and item are required")
	}
	state, err := d.ExtensionStateForDomain(ctx, transaction.Domain())
	if err != nil {
		return err
	}
	if _, ok := state.Extensions[pluginName]; !ok {
		return extensionstate.ErrUnknownExtension
	}
	definition, err := durableConfigDefinition(pluginName, item)
	if err != nil {
		return err
	}
	if err = d.ContributeExtensionCommand(ctx, transaction.Domain(), metadata, extensionstate.Command{
		Kind:        extensionstate.CommandRegisterConfig,
		ExtensionID: pluginName,
		Definition:  definition,
	}); err != nil {
		return err
	}
	return nil
}

func (d *Dice) setConfigInDomain(
	ctx context.Context,
	transaction *DurableCallbackTransaction,
	metadata eventstore.Metadata,
	pluginName, key string,
	value any,
) error {
	if transaction == nil {
		return ErrDurableStateUnavailable
	}
	state, err := d.ExtensionStateForDomain(ctx, transaction.Domain())
	if err != nil {
		return err
	}
	definition, ok := state.ConfigDefinitions[pluginName][key]
	if !ok {
		return extensionstate.ErrUnknownConfig
	}
	configValue, err := durableConfigValue(definition.Type, value)
	if err != nil {
		return err
	}
	return d.ContributeExtensionCommand(ctx, transaction.Domain(), metadata, extensionstate.Command{
		Kind:        extensionstate.CommandSetConfig,
		ExtensionID: pluginName,
		Key:         key,
		Value:       configValue,
	})
}

func (d *Dice) unregisterConfigInDomain(
	ctx context.Context,
	transaction *DurableCallbackTransaction,
	metadata eventstore.Metadata,
	pluginName, key string,
) error {
	if transaction == nil {
		return ErrDurableStateUnavailable
	}
	state, err := d.ExtensionStateForDomain(ctx, transaction.Domain())
	if err != nil {
		return err
	}
	if _, ok := state.Extensions[pluginName]; !ok {
		return extensionstate.ErrUnknownExtension
	}
	if err = d.ContributeExtensionCommand(ctx, transaction.Domain(), metadata, extensionstate.Command{
		Kind:        extensionstate.CommandUnregisterConfig,
		ExtensionID: pluginName,
		Key:         key,
	}); err != nil {
		return err
	}
	return nil
}

func (d *Dice) withOwnedConfigExecution(
	ctx context.Context,
	operation string,
	request any,
	run func(*DurableCallbackTransaction, eventstore.Metadata) error,
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	return d.withFreshDomainExecution(ctx, operation, request, run)
}

func (d *Dice) durableRegisterConfigsByName(ctx context.Context, pluginName string, items []*ConfigItem) error {
	return d.withOwnedConfigExecution(ctx, "extension-config-register-by-name", struct {
		PluginName string        `json:"pluginName"`
		Items      []*ConfigItem `json:"items"`
	}{pluginName, items}, func(transaction *DurableCallbackTransaction, metadata eventstore.Metadata) error {
		for _, item := range items {
			if err := d.registerConfigInDomain(ctx, transaction, metadata, pluginName, item); err != nil {
				return err
			}
		}
		return nil
	})
}

func (d *Dice) durableUnregisterConfigsByName(ctx context.Context, pluginName string, keys []string) error {
	return d.withOwnedConfigExecution(ctx, "extension-config-unregister-by-name", struct {
		PluginName string   `json:"pluginName"`
		Keys       []string `json:"keys"`
	}{pluginName, keys}, func(transaction *DurableCallbackTransaction, metadata eventstore.Metadata) error {
		for _, key := range keys {
			if err := d.unregisterConfigInDomain(ctx, transaction, metadata, pluginName, key); err != nil {
				return err
			}
		}
		return nil
	})
}

func (d *Dice) durableSetConfigByName(ctx context.Context, pluginName, key string, value any) error {
	return d.withOwnedConfigExecution(ctx, "extension-config-set-by-name", struct {
		PluginName string `json:"pluginName"`
		Key        string `json:"key"`
		Value      any    `json:"value"`
	}{pluginName, key, value}, func(transaction *DurableCallbackTransaction, metadata eventstore.Metadata) error {
		return d.setConfigInDomain(ctx, transaction, metadata, pluginName, key, value)
	})
}

//nolint:nilnil // Missing configuration is an ordinary lookup miss, surfaced as JS null.
func (d *Dice) configItemForDomain(
	ctx context.Context,
	transaction *DurableCallbackTransaction,
	pluginName, key string,
) (*ConfigItem, error) {
	if transaction == nil {
		return nil, execution.ErrDomainTxUnavailable
	}
	state, err := d.ExtensionStateForDomain(ctx, transaction.Domain())
	if err != nil {
		return nil, err
	}
	definition, ok := state.ConfigDefinitions[pluginName][key]
	if !ok {
		return nil, nil
	}
	item := durableConfigItem(definition)
	if value, exists := state.ConfigValues[pluginName][key]; exists {
		item.Value = durableLegacyValue(value)
	}
	if d.ConfigManager != nil {
		item.task = d.ConfigManager.taskFor(pluginName, key)
	}
	return item, nil
}

//nolint:nilnil // An absent extension/configuration maps to JS undefined, not an I/O failure.
func (d *Dice) compatibilityConfigItemWithError(ext *ExtInfo, key string) (*ConfigItem, error) {
	if d == nil || ext == nil {
		return nil, nil
	}
	item, err := d.DurableConfigItem(context.Background(), ext, key)
	if err != nil || item == nil {
		return item, err
	}
	if d.ConfigManager != nil {
		item.task = d.ConfigManager.taskFor(ext.Name, key)
	}
	return item, nil
}

func (d *Dice) compatibilityConfigItem(ext *ExtInfo, key string) *ConfigItem {
	item, err := d.compatibilityConfigItemWithError(ext, key)
	if err != nil {
		panic(err)
	}
	return item
}

func (d *Dice) durablePluginKV() (eventstore.PluginKVRepository, error) {
	if d == nil || d.DurableStore == nil {
		return nil, ErrDurableStateUnavailable
	}
	repository, ok := d.DurableStore.(eventstore.PluginKVRepository)
	if !ok || repository == nil {
		return nil, errors.New("dice: attached store does not support plugin KV")
	}
	return repository, nil
}

func (d *Dice) durableStorageSet(extensionID, key, value string) error {
	return d.withFreshDomainExecution(context.Background(), "extension-storage-set", struct {
		ExtensionID string `json:"extensionId"`
		Key         string `json:"key"`
		Value       string `json:"value"`
	}{extensionID, key, value}, func(transaction *DurableCallbackTransaction, _ eventstore.Metadata) error {
		return transaction.StorageSet(context.Background(), extensionID, key, value)
	})
}

func (d *Dice) durableStorageGet(extensionID, key string) (string, error) {
	repository, err := d.durablePluginKV()
	if err != nil {
		return "", err
	}
	item, err := repository.GetPluginKV(context.Background(), extensionID, key)
	if errors.Is(err, eventstore.ErrPluginKVNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return string(item.Value), nil
}

func (d *Dice) durableStorageList(extensionID string) ([]string, error) {
	repository, err := d.durablePluginKV()
	if err != nil {
		return nil, err
	}
	items, err := repository.ListPluginKV(context.Background(), eventstore.PluginKVListRequest{
		ExtensionID: extensionID,
		Limit:       eventstore.MaxPluginResults,
	})
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(items))
	for _, item := range items {
		keys = append(keys, item.Key)
	}
	return keys, nil
}

func (d *Dice) clearDurableExtensionStorage(extensionID string) error {
	return d.withOwnedConfigExecution(context.Background(), "extension-storage-clear", struct {
		ExtensionID string `json:"extensionId"`
	}{extensionID}, func(transaction *DurableCallbackTransaction, _ eventstore.Metadata) error {
		keys, err := transaction.StorageList(context.Background(), extensionID)
		if err != nil {
			return err
		}
		for _, key := range keys {
			if err = transaction.StorageDelete(context.Background(), extensionID, key); err != nil {
				return err
			}
		}
		return nil
	})
}

// DurableLegacyConfigView adapts the detached configuration projection to the
// historical Core/API shape. External resources and secret material remain
// absent; callers receive only the projection-owned values.
func (d *Dice) DurableLegacyConfigView(ctx context.Context) (Config, AdvancedConfig, configstate.State, error) {
	state, err := d.DurableConfigState(ctx)
	if err != nil {
		return Config{}, AdvancedConfig{}, configstate.State{}, err
	}
	config, advanced, err := d.legacyConfigViewFromState(state)
	return config, advanced, state, err
}

func (d *Dice) legacyConfigViewFromState(state configstate.State) (Config, AdvancedConfig, error) {
	if err := configstate.ValidateState(state); err != nil {
		return Config{}, AdvancedConfig{}, err
	}
	config := NewConfig(d)
	config.ConfigVersion = state.ConfigVersion
	config.BaseConfig = BaseConfig{
		CommandCompatibleMode:   state.Base.CommandCompatibleMode,
		NoticeIDs:               append([]string(nil), state.Base.NoticeIDs...),
		OnlyLogCommandInGroup:   state.Base.OnlyLogCommandInGroup,
		OnlyLogCommandInPrivate: state.Base.OnlyLogCommandInPrivate,
		VersionCode:             state.Base.VersionCode,
		MessageDelayRangeStart:  state.Base.MessageDelayRangeStart,
		MessageDelayRangeEnd:    state.Base.MessageDelayRangeEnd,
		WorkInQQChannel:         state.Base.WorkInQQChannel,
		QQChannelAutoOn:         state.Base.QQChannelAutoOn,
		QQChannelLogMessage:     state.Base.QQChannelLogMessage,
		QQEnablePoke:            state.Base.QQEnablePoke,
		TextCmdTrustOnly:        state.Base.TextCmdTrustOnly,
		IgnoreUnaddressedBotCmd: state.Base.IgnoreUnaddressedBotCmd,
		UILogLimit:              state.Base.UILogLimit,
		FriendAddComment:        state.Base.FriendAddComment,
		CustomReplyConfigEnable: state.Base.CustomReplyConfigEnable,
		AutoReloginEnable:       state.Base.AutoReloginEnable,
		RefuseGroupInvite:       state.Base.RefuseGroupInvite,
		BotExtFreeSwitch:        state.Base.BotExtFreeSwitch,
		BotExitWithoutAt:        state.Base.BotExitWithoutAt,
		TrustOnlyMode:           state.Base.TrustOnlyMode,
		AliveNoticeEnable:       state.Base.AliveNoticeEnable,
		AliveNoticeValue:        state.Base.AliveNoticeValue,
		ReplyDebugMode:          state.Base.ReplyDebugMode,
		PlayerNameWrapEnable:    state.Base.PlayerNameWrapEnable,
		DiceRandomMode:          state.Base.DiceRandomMode,
		VMVersionForReply:       state.Base.VMVersionForReply,
		VMVersionForDeck:        state.Base.VMVersionForDeck,
		VMVersionForCustomText:  state.Base.VMVersionForCustomText,
		VMVersionForMsg:         state.Base.VMVersionForMsg,
		Name:                    d.BaseConfig.Name,
		DataDir:                 d.BaseConfig.DataDir,
	}
	config.RateLimitConfig = RateLimitConfig{
		RateLimitEnabled:          state.Rate.RateLimitEnabled,
		PersonalReplenishRateStr:  state.Rate.PersonalReplenishRate,
		GroupReplenishRateStr:     state.Rate.GroupReplenishRate,
		PersonalBurst:             state.Rate.PersonalBurst,
		GroupBurst:                state.Rate.GroupBurst,
		SpamSameCommandWindowSec:  state.Rate.SpamSameCommandWindowSec,
		SpamRecoveryMultiplierMax: state.Rate.SpamRecoveryMultiplierMax,
	}
	config.PersonalReplenishRate, _ = utils.ParseRate(config.PersonalReplenishRateStr)
	config.GroupReplenishRate, _ = utils.ParseRate(config.GroupReplenishRateStr)
	config.QuitInactiveConfig = QuitInactiveConfig{
		QuitInactiveNoticeSummaryMode: state.Quit.QuitInactiveNoticeSummaryMode,
		QuitInactiveBatchSize:         state.Quit.QuitInactiveBatchSize,
		QuitInactiveBatchWait:         state.Quit.QuitInactiveBatchWait,
	}
	config.QuitInactiveThreshold, _ = time.ParseDuration(state.Quit.QuitInactiveThreshold)
	config.QuitInactiveThresholdDays = config.QuitInactiveThreshold.Hours() / 24
	config.ExtConfig = ExtConfig{
		DefaultCocRuleIndex: state.Extension.DefaultCocRuleIndex,
		MaxExecuteTime:      state.Extension.MaxExecuteTime,
		MaxCocCardGen:       state.Extension.MaxCocCardGen,
		CocCardMergeForward: state.Extension.CocCardMergeForward,
	}
	config.BanList.BanBehaviorRefuseReply = state.Ban.RefuseReply
	config.BanList.BanBehaviorRefuseInvite = state.Ban.RefuseInvite
	config.BanList.BanBehaviorQuitLastPlace = state.Ban.QuitLastPlace
	config.BanList.BanBehaviorQuitPlaceImmediately = state.Ban.QuitPlaceImmediately
	config.BanList.BanBehaviorQuitIfAdmin = state.Ban.QuitIfAdmin
	config.BanList.BanBehaviorQuitIfAdminSilentIfNotAdmin = state.Ban.QuitIfAdminSilentIfNotAdmin
	config.BanList.ThresholdWarn = state.Ban.ThresholdWarn
	config.BanList.ThresholdBan = state.Ban.ThresholdBan
	config.BanList.AutoBanMinutes = state.Ban.AutoBanMinutes
	config.BanList.ScoreReducePerMinute = state.Ban.ScoreReducePerMinute
	config.BanList.ScoreGroupMuted = state.Ban.ScoreGroupMuted
	config.BanList.ScoreGroupKicked = state.Ban.ScoreGroupKicked
	config.BanList.ScoreTooManyCommand = state.Ban.ScoreTooManyCommand
	config.BanList.BanNotifyIntervalMinutes = state.Ban.BanNotifyIntervalMinutes
	config.BanList.JointScorePercentOfGroup = state.Ban.JointScorePercentOfGroup
	config.BanList.JointScorePercentOfInviter = state.Ban.JointScorePercentOfInviter
	config.JsConfig = JsConfig{
		JsEnable:                       state.JS.JsEnable,
		JsEngine:                       state.JS.JsEngine,
		JsRuntimeOptions:               cloneJSRuntimeOptions(state.JS.JsRuntimeOptions),
		JsRuntimeRoutes:                cloneJSRuntimeRoutes(state.JS.JsRuntimeRoutes),
		DisabledJsScripts:              cloneDisabledJsScripts(state.JS.DisabledJsScripts),
		QuickJSMemoryLimitMiB:          state.JS.QuickJSMemoryLimitMiB,
		QuickJSGCThresholdMiB:          state.JS.QuickJSGCThresholdMiB,
		QuickJSMaxStackSizeKiB:         state.JS.QuickJSMaxStackSizeKiB,
		QuickJSExecuteTimeoutSeconds:   state.JS.QuickJSExecuteTimeoutSeconds,
		QuickJSMaxFetchConcurrent:      state.JS.QuickJSMaxFetchConcurrent,
		QuickJSMaxFetchResponseMiB:     state.JS.QuickJSMaxFetchResponseMiB,
		QuickJSMaxWebSocketConnections: state.JS.QuickJSMaxWebSocketConnections,
		QuickJSMaxWebSocketMessageMiB:  state.JS.QuickJSMaxWebSocketMessageMiB,
		QuickJSMaxFilesystemReadMiB:    state.JS.QuickJSMaxFilesystemReadMiB,
		QuickJSMaxFilesystemWriteMiB:   state.JS.QuickJSMaxFilesystemWriteMiB,
		QuickJSMaxPBKDF2Iterations:     state.JS.QuickJSMaxPBKDF2Iterations,
		QuickJSMaxPBKDF2OutputBytes:    state.JS.QuickJSMaxPBKDF2OutputBytes,
	}
	config.StoryLogConfig = StoryLogConfig{LogSizeNoticeEnable: state.StoryLog.LogSizeNoticeEnable, LogSizeNoticeCount: state.StoryLog.LogSizeNoticeCount}
	config.MailConfig = MailConfig{MailEnable: state.Mail.MailEnable, MailFrom: state.Mail.MailFrom, MailSMTP: state.Mail.MailSMTP}
	config.NewsConfig = NewsConfig{NewsMark: state.News.NewsMark}
	config.PublicDiceConfig = PublicDiceConfig{
		Enable: state.PublicDice.Enable, ID: state.PublicDice.ID, Name: state.PublicDice.Name,
		Brief: state.PublicDice.Brief, Note: state.PublicDice.Note, Avatar: state.PublicDice.Avatar,
		EndpointIDs: append([]string(nil), state.PublicDice.EndpointIDs...),
	}
	config.EnableCensor = state.Censor.Enable
	config.CensorMode = CensorMode(state.Censor.Mode)
	config.CensorCaseSensitive = state.Censor.CaseSensitive
	config.CensorMatchPinyin = state.Censor.MatchPinyin
	config.CensorFilterRegexStr = state.Censor.FilterRegex
	for key, value := range state.Censor.Thresholds {
		if level, parseErr := strconv.Atoi(key); parseErr == nil {
			config.CensorThresholds[censor.Level(level)] = value
		}
	}
	for key, value := range state.Censor.Handlers {
		if level, parseErr := strconv.Atoi(key); parseErr == nil {
			config.CensorHandlers[censor.Level(level)] = value
		}
	}
	for key, value := range state.Censor.Scores {
		if level, parseErr := strconv.Atoi(key); parseErr == nil {
			config.CensorScores[censor.Level(level)] = value
		}
	}
	config.StoreConfig = StoreConfig{BackendUrls: append([]string(nil), state.Store.BackendURLs...), DisabledBackendUrls: append([]string(nil), state.Store.DisabledBackendURLs...)}
	config.CommandPrefix = append([]string(nil), state.Outer.CommandPrefix...)
	config.DiceMasters = append([]string(nil), state.Outer.DiceMasters...)
	config.UpgradeWindowID = state.Outer.UpgradeWindowID
	config.UpgradeEndpointID = state.Outer.UpgradeEndpointID

	advanced := AdvancedConfig{
		Show:                              state.Advanced.Show,
		Enable:                            state.Advanced.Enable,
		StoryLogBackendUrl:                state.Advanced.StoryLogBackendURL,
		StoryLogApiVersion:                state.Advanced.StoryLogAPIVersion,
		CustomReplyCooldown:               state.Advanced.CustomReplyCooldown,
		ExposeDangerousSealInst:           state.Advanced.ExposeDangerousSealInst,
		AllowFilesystemUnrestrictedAccess: state.Advanced.AllowFilesystemUnrestrictedAccess,
	}
	return config, advanced, nil
}
