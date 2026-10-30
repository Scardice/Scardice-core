package dice

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"Scardice-core/core/configstate"
	"Scardice-core/core/extensionstate"
	"Scardice-core/dice/censor"
	"Scardice-core/eventstore"
	"Scardice-core/utils"
)

var (
	ErrDurableStateUnavailable      = errors.New("dice: durable state is not attached")
	ErrDurableProjection            = errors.New("dice: durable state projection is unavailable")
	errDurableReservedStorageDomain = errors.New("dice: extension storage identity uses a reserved internal domain")
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

// DurableExtensionConfigItems returns detached compatibility DTOs ordered by
// extension identity and config key. It never returns projection-owned maps.
func (d *Dice) DurableExtensionConfigItems(ctx context.Context, pluginName string) ([]*ConfigItem, error) {
	state, err := d.DurableExtensionState(ctx)
	if err != nil {
		return nil, err
	}
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
		if durableEncryptedConfig(definition.Type, key) {
			value, exists, valueErr := d.durableEncryptedConfigValue(ctx, pluginName, key, definition.Type)
			if valueErr != nil {
				return nil, valueErr
			}
			if exists {
				item.Value = value
				items = append(items, item)
				continue
			}
		}
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

func (d *Dice) ensureDurableExtension(ctx context.Context, ext *ExtInfo) (extensionstate.State, error) {
	if ext == nil {
		return extensionstate.State{}, errors.New("dice: extension is nil")
	}
	repo, diceID, err := d.durableExtensionRepository()
	if err != nil {
		return extensionstate.State{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	state, err := repo.Load(ctx, diceID)
	if err != nil {
		return extensionstate.State{}, err
	}
	identity := durableExtensionIdentity(ext)
	command := extensionstate.Command{
		Kind:     extensionstate.CommandDiscover,
		DiceID:   diceID,
		Identity: identity,
	}
	for range 2 {
		result, appendErr := repo.DecideAndAppend(ctx, state, state.Version, eventstore.Metadata{}, command)
		if appendErr == nil {
			if result.Idempotent {
				return state, nil
			}
			return repo.Load(ctx, diceID)
		}
		if !errors.Is(appendErr, eventstore.ErrConflict) {
			return extensionstate.State{}, appendErr
		}
		state, err = repo.Load(ctx, diceID)
		if err != nil {
			return extensionstate.State{}, err
		}
	}
	return extensionstate.State{}, eventstore.ErrConflict
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
	_, err := d.ensureDurableExtension(ctx, ext)
	return err
}

func (d *Dice) DurableRegisterConfig(ctx context.Context, ext *ExtInfo, item *ConfigItem) error {
	if item == nil {
		return errors.New("dice: config item is nil")
	}
	if _, err := d.ensureDurableExtension(ctx, ext); err != nil {
		return err
	}
	return d.durableRegisterConfigByName(ctx, ext.Name, item)
}

func (d *Dice) DurableSetConfig(ctx context.Context, ext *ExtInfo, key string, value any) error {
	if ext == nil {
		return errors.New("dice: extension is nil")
	}
	if _, err := d.ensureDurableExtension(ctx, ext); err != nil {
		return err
	}
	return d.durableSetConfigByName(ctx, ext.Name, key, value)
}

func (d *Dice) DurableUnregisterConfig(ctx context.Context, ext *ExtInfo, key string) error {
	if ext == nil {
		return errors.New("dice: extension is nil")
	}
	if _, err := d.ensureDurableExtension(ctx, ext); err != nil {
		return err
	}
	return d.durableUnregisterConfigByName(ctx, ext.Name, key)
}

func (d *Dice) DurableConfigItem(ctx context.Context, ext *ExtInfo, key string) (*ConfigItem, error) {
	if ext == nil {
		return nil, errors.New("dice: extension is nil")
	}
	state, err := d.DurableExtensionState(ctx)
	if err != nil {
		return nil, err
	}
	var item *ConfigItem
	if definition, ok := state.ConfigDefinitions[ext.Name][key]; ok {
		item = durableConfigItem(definition)
		if durableEncryptedConfig(definition.Type, key) {
			value, exists, valueErr := d.durableEncryptedConfigValue(ctx, ext.Name, key, definition.Type)
			if valueErr != nil {
				return nil, valueErr
			}
			if exists {
				item.Value = value
				return item, nil
			}
		}
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
	state, err := d.ensureDurableExtension(ctx, ext)
	if err != nil {
		return err
	}
	repo, _, err := d.durableExtensionRepository()
	if err != nil {
		return err
	}
	kind := extensionstate.CommandDisable
	if enabled {
		kind = extensionstate.CommandEnable
	}
	_, err = repo.DecideAndAppend(ctx, state, state.Version, eventstore.Metadata{}, extensionstate.Command{
		Kind:        kind,
		ExtensionID: ext.Name,
	})
	return err
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
	if item.DefaultValue != nil && !durableEncryptedConfig(typ, item.Key) {
		value, valueErr := durableConfigValue(typ, item.DefaultValue, item.Key)
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

func durableConfigValue(typ extensionstate.ConfigType, value any, key string) (extensionstate.ConfigValue, error) {
	if durableEncryptedConfig(typ, key) {
		return extensionstate.ConfigValue{}, errors.New("dice: raw sensitive config value is not allowed in the event stream")
	}
	return durableTypedConfigValue(typ, value)
}

func durableTypedConfigValue(typ extensionstate.ConfigType, value any) (extensionstate.ConfigValue, error) {
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

func durableSensitiveConfig(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	for _, marker := range []string{"password", "passwd", "token", "secret", "privatekey", "private_key", "apikey", "api_key"} {
		if strings.Contains(key, marker) {
			return true
		}
	}
	return false
}

const durableConfigValueExtensionPrefix = "scardice.internal.config/v1/"

func durableEncryptedConfig(typ extensionstate.ConfigType, key string) bool {
	return typ != extensionstate.ConfigSecret && durableSensitiveConfig(key)
}

func durableConfigStorageExtensionID(pluginName string) string {
	digest := sha256.Sum256([]byte(pluginName))
	return durableConfigValueExtensionPrefix + hex.EncodeToString(digest[:])
}

func durableConfigStorageKey(configKey string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(configKey))
}

type durableConfigKVMutation struct {
	pluginName         string
	key                string
	value              []byte
	deleted            bool
	expectedVersion    uint64
	expectedVersionSet bool
}

func durableEncryptedConfigPayload(pluginName, key string, typ extensionstate.ConfigType, value any) ([]byte, error) {
	stored, err := durableTypedConfigValue(typ, value)
	if err != nil {
		return nil, fmt.Errorf(
			"dice: encrypted plugin config value type mismatch: plugin=%q key=%q declared=%q actual=%q: %w",
			pluginName,
			key,
			typ,
			fmt.Sprintf("%T", value),
			err,
		)
	}
	payload, err := json.Marshal(stored)
	if err != nil {
		return nil, fmt.Errorf("dice: encode encrypted plugin config: plugin=%q key=%q declared=%q: %w", pluginName, key, typ, err)
	}
	return payload, nil
}

func durableDecodeEncryptedConfigValue(payload []byte, pluginName, key string, typ extensionstate.ConfigType) (any, error) {
	var stored extensionstate.ConfigValue
	if err := json.Unmarshal(payload, &stored); err != nil {
		return nil, fmt.Errorf("dice: encrypted plugin config metadata invalid: plugin=%q key=%q declared=%q: %w", pluginName, key, typ, err)
	}
	if stored.Type != typ {
		return nil, fmt.Errorf("dice: encrypted plugin config type mismatch: plugin=%q key=%q declared=%q actual=%q", pluginName, key, typ, stored.Type)
	}
	value := durableLegacyValue(stored)
	if _, err := durableTypedConfigValue(typ, value); err != nil {
		return nil, fmt.Errorf("dice: encrypted plugin config value type mismatch: plugin=%q key=%q declared=%q actual=%q", pluginName, key, typ, fmt.Sprintf("%T", value))
	}
	return value, nil
}

type durablePluginKVUpdatePreparer interface {
	PreparePluginKVUpdate(ctx context.Context, request eventstore.PluginKVPutRequest) (eventstore.PluginKVUpdate, error)
}

func (d *Dice) durablePrepareConfigKVMutation(ctx context.Context, mutation durableConfigKVMutation) ([]eventstore.PluginKVUpdate, error) {
	if d == nil || d.DurableStore == nil {
		return nil, ErrDurableStateUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	repository, err := d.durablePluginKV()
	if err != nil {
		return nil, err
	}
	extensionID := durableConfigStorageExtensionID(mutation.pluginName)
	storageKey := durableConfigStorageKey(mutation.key)
	currentVersion := mutation.expectedVersion
	if !mutation.expectedVersionSet {
		current, getErr := repository.GetPluginKV(ctx, extensionID, storageKey)
		if errors.Is(getErr, eventstore.ErrPluginKVNotFound) {
			if mutation.deleted {
				return nil, nil
			}
			currentVersion = 0
		} else if getErr != nil {
			return nil, getErr
		} else {
			currentVersion = current.Version
		}
	} else if mutation.deleted && currentVersion == 0 {
		return nil, nil
	}
	if mutation.deleted {
		if currentVersion >= ^uint64(0)>>1 {
			return nil, eventstore.ErrVersionExhausted
		}
		sealer, ok := d.DurableStore.(JSPluginKVSealer)
		if !ok {
			return nil, errors.New("dice: attached store does not support encrypted plugin KV sealing")
		}
		index, _, digestErr := sealer.KeyedDigest(ctx, "plugin-key-index/v1", extensionID, storageKey)
		if digestErr != nil {
			return nil, digestErr
		}
		if len(index) != sha256.Size {
			return nil, errors.New("dice: invalid encrypted plugin KV index")
		}
		return []eventstore.PluginKVUpdate{{
			ExtensionID:     extensionID,
			KeyHMAC:         index,
			ExpectedVersion: currentVersion,
			Version:         currentVersion + 1,
			Deleted:         true,
		}}, nil
	}
	preparer, ok := d.DurableStore.(durablePluginKVUpdatePreparer)
	if !ok {
		return nil, errors.New("dice: attached store cannot prepare encrypted plugin KV updates")
	}
	update, err := preparer.PreparePluginKVUpdate(ctx, eventstore.PluginKVPutRequest{
		ExtensionID:     extensionID,
		Key:             storageKey,
		Value:           mutation.value,
		ExpectedVersion: currentVersion,
	})
	if err != nil {
		return nil, err
	}
	return []eventstore.PluginKVUpdate{update}, nil
}

func (d *Dice) durableCommitConfigMutation(
	ctx context.Context,
	repository *extensionstate.Repository,
	state extensionstate.State,
	command *extensionstate.Command,
	mutation *durableConfigKVMutation,
) error {
	if d == nil || d.DurableStore == nil {
		return ErrDurableStateUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	work := eventstore.UnitOfWork{}
	if command != nil {
		if repository == nil {
			return extensionstate.ErrRepositoryUnavailable
		}
		stream, err := repository.PrepareCommands(state, state.Version, eventstore.Metadata{}, []extensionstate.Command{*command})
		if err != nil {
			return err
		}
		if len(stream.Events) > 0 {
			work.Streams = append(work.Streams, stream)
		}
	}
	if mutation != nil {
		updates, err := d.durablePrepareConfigKVMutation(ctx, *mutation)
		if err != nil {
			return err
		}
		work.PluginKVUpdates = append(work.PluginKVUpdates, updates...)
	}
	if len(work.Streams) == 0 && len(work.PluginKVUpdates) == 0 {
		return nil
	}
	_, err := d.DurableStore.Commit(ctx, work)
	return err
}

func (d *Dice) durableEncryptedConfigVersion(ctx context.Context, pluginName, key string) (uint64, bool, error) {
	repository, err := d.durablePluginKV()
	if err != nil {
		return 0, false, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	item, err := repository.GetPluginKV(ctx, durableConfigStorageExtensionID(pluginName), durableConfigStorageKey(key))
	if errors.Is(err, eventstore.ErrPluginKVNotFound) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return item.Version, true, nil
}

func (d *Dice) durableEncryptedConfigValue(ctx context.Context, pluginName, key string, typ extensionstate.ConfigType) (any, bool, error) {
	repository, err := d.durablePluginKV()
	if err != nil {
		return nil, false, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	item, err := repository.GetPluginKV(ctx, durableConfigStorageExtensionID(pluginName), durableConfigStorageKey(key))
	if errors.Is(err, eventstore.ErrPluginKVNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	value, err := durableDecodeEncryptedConfigValue(item.Value, pluginName, key, typ)
	if err != nil {
		return nil, false, err
	}
	return value, true, nil
}

func (d *Dice) durableSetEncryptedConfigValue(ctx context.Context, pluginName, key string, typ extensionstate.ConfigType, value any) error {
	payload, err := durableEncryptedConfigPayload(pluginName, key, typ, value)
	if err != nil {
		return err
	}
	mutation := durableConfigKVMutation{pluginName: pluginName, key: key, value: payload}
	return d.durableCommitConfigMutation(ctx, nil, extensionstate.State{}, nil, &mutation)
}

func (d *Dice) durableDeleteEncryptedConfigValue(ctx context.Context, pluginName, key string) error {
	mutation := durableConfigKVMutation{pluginName: pluginName, key: key, deleted: true}
	return d.durableCommitConfigMutation(ctx, nil, extensionstate.State{}, nil, &mutation)
}

func durableSecretReference(value string) bool {
	value = strings.TrimSpace(value)
	return strings.HasPrefix(value, "vault:") || strings.HasPrefix(value, "secret:")
}

func (d *Dice) durableRegisterConfigByName(ctx context.Context, pluginName string, item *ConfigItem) error {
	if item == nil {
		return errors.New("dice: config item is nil")
	}
	repo, diceID, err := d.durableExtensionRepository()
	if err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	state, err := repo.Load(ctx, diceID)
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
	command := extensionstate.Command{
		Kind:        extensionstate.CommandRegisterConfig,
		ExtensionID: pluginName,
		Definition:  definition,
	}
	var mutation *durableConfigKVMutation
	previous, previouslyConfigured := state.ConfigDefinitions[pluginName][item.Key]
	if durableEncryptedConfig(definition.Type, item.Key) {
		typeChanged := previouslyConfigured && previous.Type != definition.Type
		if typeChanged {
			version, valueExists, versionErr := d.durableEncryptedConfigVersion(ctx, pluginName, item.Key)
			if versionErr != nil {
				return versionErr
			}
			if item.DefaultValue == nil {
				if valueExists {
					mutation = &durableConfigKVMutation{
						pluginName: pluginName, key: item.Key, deleted: true,
						expectedVersion: version, expectedVersionSet: true,
					}
				}
			} else {
				payload, payloadErr := durableEncryptedConfigPayload(pluginName, item.Key, definition.Type, item.DefaultValue)
				if payloadErr != nil {
					return payloadErr
				}
				mutation = &durableConfigKVMutation{
					pluginName: pluginName, key: item.Key, value: payload,
					expectedVersion: version, expectedVersionSet: true,
				}
			}
		} else {
			_, exists, valueErr := d.durableEncryptedConfigValue(ctx, pluginName, item.Key, definition.Type)
			if valueErr != nil {
				return valueErr
			}
			if !exists {
				initialValue := item.DefaultValue
				if legacyValue, legacyExists := state.ConfigValues[pluginName][item.Key]; legacyExists {
					initialValue = durableLegacyValue(legacyValue)
				}
				if initialValue != nil {
					payload, payloadErr := durableEncryptedConfigPayload(pluginName, item.Key, definition.Type, initialValue)
					if payloadErr != nil {
						return payloadErr
					}
					mutation = &durableConfigKVMutation{
						pluginName: pluginName, key: item.Key, value: payload,
						expectedVersionSet: true,
					}
				}
			}
		}
	} else if previouslyConfigured && durableEncryptedConfig(previous.Type, item.Key) {
		mutation = &durableConfigKVMutation{pluginName: pluginName, key: item.Key, deleted: true}
	}
	return d.durableCommitConfigMutation(ctx, repo, state, &command, mutation)
}

func (d *Dice) durableSetConfigByName(ctx context.Context, pluginName, key string, value any) error {
	repo, diceID, err := d.durableExtensionRepository()
	if err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	state, err := repo.Load(ctx, diceID)
	if err != nil {
		return err
	}
	definition, ok := state.ConfigDefinitions[pluginName][key]
	if !ok {
		return extensionstate.ErrUnknownConfig
	}
	if durableEncryptedConfig(definition.Type, key) {
		return d.durableSetEncryptedConfigValue(ctx, pluginName, key, definition.Type, value)
	}
	configValue, err := durableConfigValue(definition.Type, value, key)
	if err != nil {
		return err
	}
	_, err = repo.DecideAndAppend(ctx, state, state.Version, eventstore.Metadata{}, extensionstate.Command{
		Kind:        extensionstate.CommandSetConfig,
		ExtensionID: pluginName,
		Key:         key,
		Value:       configValue,
	})
	return err
}

func (d *Dice) durableUnregisterConfigByName(ctx context.Context, pluginName, key string) error {
	repo, diceID, err := d.durableExtensionRepository()
	if err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	state, err := repo.Load(ctx, diceID)
	if err != nil {
		return err
	}
	if _, ok := state.Extensions[pluginName]; !ok {
		return extensionstate.ErrUnknownExtension
	}
	definition, configured := state.ConfigDefinitions[pluginName][key]
	deleteEncryptedValue := durableSensitiveConfig(key)
	if configured {
		deleteEncryptedValue = durableEncryptedConfig(definition.Type, key)
	}
	command := extensionstate.Command{
		Kind:        extensionstate.CommandUnregisterConfig,
		ExtensionID: pluginName,
		Key:         key,
	}
	var mutation *durableConfigKVMutation
	if deleteEncryptedValue {
		mutation = &durableConfigKVMutation{pluginName: pluginName, key: key, deleted: true}
	}
	return d.durableCommitConfigMutation(ctx, repo, state, &command, mutation)
}

//nolint:nilnil // An absent extension/configuration maps to JS undefined, not an I/O failure.
func (d *Dice) compatibilityConfigItemWithError(ext *ExtInfo, key string) (*ConfigItem, error) {
	if ext == nil {
		return nil, nil
	}
	if d != nil && d.DurableStore != nil {
		item, err := d.DurableConfigItem(context.Background(), ext, key)
		if err != nil {
			return nil, err
		}
		if item == nil {
			return nil, nil
		}
		if d.ConfigManager != nil {
			if local := d.ConfigManager.getConfig(ext.Name, key); local != nil {
				item.task = local.task
			}
		}
		return item, nil
	}
	if d == nil || d.ConfigManager == nil {
		return nil, nil
	}
	return d.ConfigManager.getConfig(ext.Name, key), nil
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
		return nil, errors.New("dice: attached store does not support encrypted plugin KV")
	}
	return repository, nil
}

func validateDurablePublicStorageExtensionID(extensionID string) error {
	if strings.HasPrefix(extensionID, durableConfigValueExtensionPrefix) {
		return errDurableReservedStorageDomain
	}
	return nil
}

func (d *Dice) durablePublicPluginKV(extensionID string) (eventstore.PluginKVRepository, error) {
	if err := validateDurablePublicStorageExtensionID(extensionID); err != nil {
		return nil, err
	}
	return d.durablePluginKV()
}

func (d *Dice) durableStorageSet(extensionID, key, value string) error {
	if message := d.currentJSMessageContext(); message != nil {
		if err := message.checkExecution(); err != nil {
			return err
		}
		if message.callbackTransaction != nil {
			return message.callbackTransaction.StorageSet(message.messageJSExecution().ctx, extensionID, key, value)
		}
	}
	repository, err := d.durablePublicPluginKV(extensionID)
	if err != nil {
		return err
	}
	current, err := repository.GetPluginKV(context.Background(), extensionID, key)
	expected := uint64(0)
	if err == nil {
		expected = current.Version
	} else if !errors.Is(err, eventstore.ErrPluginKVNotFound) {
		return err
	}
	_, err = repository.SetPluginKV(context.Background(), eventstore.PluginKVPutRequest{
		ExtensionID:     extensionID,
		Key:             key,
		Value:           []byte(value),
		ExpectedVersion: expected,
	})
	return err
}

func (d *Dice) durableStorageGet(extensionID, key string) (string, error) {
	if message := d.currentJSMessageContext(); message != nil {
		if err := message.checkExecution(); err != nil {
			return "", err
		}
		if message.callbackTransaction != nil {
			return message.callbackTransaction.StorageGet(message.messageJSExecution().ctx, extensionID, key)
		}
	}
	repository, err := d.durablePublicPluginKV(extensionID)
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
	if message := d.currentJSMessageContext(); message != nil {
		if err := message.checkExecution(); err != nil {
			return nil, err
		}
		if message.callbackTransaction != nil {
			return message.callbackTransaction.StorageList(message.messageJSExecution().ctx, extensionID)
		}
	}
	repository, err := d.durablePublicPluginKV(extensionID)
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
	repository, err := d.durablePublicPluginKV(extensionID)
	if err != nil {
		return err
	}
	items, err := repository.ListPluginKV(context.Background(), eventstore.PluginKVListRequest{
		ExtensionID: extensionID,
		Limit:       eventstore.MaxPluginResults,
	})
	if err != nil {
		return err
	}
	for _, item := range items {
		if err := repository.DeletePluginKV(context.Background(), extensionID, item.Key, item.Version); err != nil {
			return err
		}
	}
	return nil
}

// DurableLegacyConfigView adapts the detached configuration projection to the
// historical Core/API shape. External resources and secret material remain
// absent; callers receive only the projection-owned values.
func (d *Dice) DurableLegacyConfigView(ctx context.Context) (Config, AdvancedConfig, configstate.State, error) {
	state, err := d.DurableConfigState(ctx)
	if err != nil {
		return Config{}, AdvancedConfig{}, configstate.State{}, err
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

	advanced := AdvancedConfig{
		Show:                              state.Advanced.Show,
		Enable:                            state.Advanced.Enable,
		StoryLogBackendUrl:                state.Advanced.StoryLogBackendURL,
		StoryLogApiVersion:                state.Advanced.StoryLogAPIVersion,
		CustomReplyCooldown:               state.Advanced.CustomReplyCooldown,
		ExposeDangerousSealInst:           state.Advanced.ExposeDangerousSealInst,
		AllowFilesystemUnrestrictedAccess: state.Advanced.AllowFilesystemUnrestrictedAccess,
	}
	return config, advanced, state, nil
}
