package dice

import (
	"context"
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
		return configstate.State{}, fmt.Errorf("%w: config: %v", ErrDurableProjection, err)
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
		return extensionstate.State{}, fmt.Errorf("%w: extension: %v", ErrDurableProjection, err)
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
		item := durableConfigItem(definitions[key])
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
	return extensionstate.NewRepository(store), id, nil
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
	if state.Version == 0 {
		_, err = repo.DecideAndAppend(ctx, state, 0, eventstore.Metadata{}, extensionstate.Command{
			Kind:     extensionstate.CommandDiscover,
			DiceID:   diceID,
			Identity: identity,
		})
		if err != nil && !errors.Is(err, eventstore.ErrConflict) {
			return extensionstate.State{}, err
		}
		state, err = repo.Load(ctx, diceID)
		if err != nil {
			return extensionstate.State{}, err
		}
	}
	if existing, ok := state.Extensions[identity.ID]; ok {
		if existing.Version != identity.Version || existing.Source != identity.Source {
			return extensionstate.State{}, fmt.Errorf("dice: durable extension identity changed: %s", identity.ID)
		}
	}
	return state, nil
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
	state, err := d.ensureDurableExtension(ctx, ext)
	if err != nil {
		return err
	}
	definition, err := durableConfigDefinition(ext.Name, item)
	if err != nil {
		return err
	}
	repo, _, err := d.durableExtensionRepository()
	if err != nil {
		return err
	}
	_, err = repo.DecideAndAppend(ctx, state, state.Version, eventstore.Metadata{}, extensionstate.Command{
		Kind:        extensionstate.CommandRegisterConfig,
		ExtensionID: definition.ExtensionID,
		Definition:  definition,
	})
	return err
}

func (d *Dice) DurableSetConfig(ctx context.Context, ext *ExtInfo, key string, value any) error {
	if ext == nil {
		return errors.New("dice: extension is nil")
	}
	state, err := d.ensureDurableExtension(ctx, ext)
	if err != nil {
		return err
	}
	definition, ok := state.ConfigDefinitions[ext.Name][key]
	if !ok {
		return extensionstate.ErrUnknownConfig
	}
	configValue, err := durableConfigValue(definition.Type, value, key)
	if err != nil {
		return err
	}
	repo, _, err := d.durableExtensionRepository()
	if err != nil {
		return err
	}
	_, err = repo.DecideAndAppend(ctx, state, state.Version, eventstore.Metadata{}, extensionstate.Command{
		Kind:        extensionstate.CommandSetConfig,
		ExtensionID: ext.Name,
		Key:         key,
		Value:       configValue,
	})
	return err
}

func (d *Dice) DurableUnregisterConfig(ctx context.Context, ext *ExtInfo, key string) error {
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
	_, err = repo.DecideAndAppend(ctx, state, state.Version, eventstore.Metadata{}, extensionstate.Command{
		Kind:        extensionstate.CommandUnregisterConfig,
		ExtensionID: ext.Name,
		Key:         key,
	})
	return err
}

func (d *Dice) DurableConfigItem(ctx context.Context, ext *ExtInfo, key string) (*ConfigItem, error) {
	if ext == nil {
		return nil, errors.New("dice: extension is nil")
	}
	state, err := d.DurableExtensionState(ctx)
	if err != nil {
		return nil, err
	}
	definition, ok := state.ConfigDefinitions[ext.Name][key]
	if !ok {
		return nil, nil
	}
	item := durableConfigItem(definition)
	if value, ok := state.ConfigValues[ext.Name][key]; ok {
		item.Value = durableLegacyValue(value)
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
	if item.DefaultValue != nil && !durableSensitiveConfig(item.Key) {
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
	if durableSensitiveConfig(key) && typ != extensionstate.ConfigSecret {
		text, ok := value.(string)
		if !ok || !durableSecretReference(text) {
			return extensionstate.ConfigValue{}, errors.New("dice: raw sensitive config value is not allowed")
		}
	}
	switch typ {
	case extensionstate.ConfigString, extensionstate.ConfigTaskCron, extensionstate.ConfigTaskDaily, extensionstate.ConfigTaskOnce:
		text, ok := value.(string)
		if !ok {
			return extensionstate.ConfigValue{}, extensionstate.ErrInvalidConfigValue
		}
		return extensionstate.StringValue(text), nil
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
		items, ok := value.([]string)
		if !ok {
			return extensionstate.ConfigValue{}, extensionstate.ErrInvalidConfigValue
		}
		return extensionstate.TemplateValue(items), nil
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
	_, err = repo.DecideAndAppend(ctx, state, state.Version, eventstore.Metadata{}, extensionstate.Command{
		Kind:        extensionstate.CommandRegisterConfig,
		ExtensionID: pluginName,
		Definition:  definition,
	})
	return err
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
	_, err = repo.DecideAndAppend(ctx, state, state.Version, eventstore.Metadata{}, extensionstate.Command{
		Kind:        extensionstate.CommandUnregisterConfig,
		ExtensionID: pluginName,
		Key:         key,
	})
	return err
}

func (d *Dice) compatibilityConfigItem(ext *ExtInfo, key string) *ConfigItem {
	if ext == nil {
		return nil
	}
	if d != nil && d.DurableStore != nil {
		item, err := d.DurableConfigItem(context.Background(), ext, key)
		if err != nil {
			panic(err)
		}
		if item == nil {
			return nil
		}
		if d.ConfigManager != nil {
			if local := d.ConfigManager.getConfig(ext.Name, key); local != nil {
				item.task = local.task
			}
		}
		return item
	}
	if d == nil || d.ConfigManager == nil {
		return nil
	}
	return d.ConfigManager.getConfig(ext.Name, key)
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

func (d *Dice) durableStorageSet(extensionID, key, value string) error {
	repository, err := d.durablePluginKV()
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
	repository, err := d.durablePluginKV()
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
	config.PublicDiceConfig = PublicDiceConfig{Enable: state.PublicDice.Enable, ID: state.PublicDice.ID, Name: state.PublicDice.Name, Brief: state.PublicDice.Brief, Note: state.PublicDice.Note, Avatar: state.PublicDice.Avatar}
	config.CensorConfig.EnableCensor = state.Censor.Enable
	config.CensorConfig.CensorMode = CensorMode(state.Censor.Mode)
	config.CensorConfig.CensorCaseSensitive = state.Censor.CaseSensitive
	config.CensorConfig.CensorMatchPinyin = state.Censor.MatchPinyin
	config.CensorConfig.CensorFilterRegexStr = state.Censor.FilterRegex
	for key, value := range state.Censor.Thresholds {
		if level, parseErr := strconv.Atoi(key); parseErr == nil {
			config.CensorConfig.CensorThresholds[censor.Level(level)] = value
		}
	}
	for key, value := range state.Censor.Handlers {
		if level, parseErr := strconv.Atoi(key); parseErr == nil {
			config.CensorConfig.CensorHandlers[censor.Level(level)] = value
		}
	}
	for key, value := range state.Censor.Scores {
		if level, parseErr := strconv.Atoi(key); parseErr == nil {
			config.CensorConfig.CensorScores[censor.Level(level)] = value
		}
	}
	config.StoreConfig = StoreConfig{BackendUrls: append([]string(nil), state.Store.BackendURLs...), DisabledBackendUrls: append([]string(nil), state.Store.DisabledBackendURLs...)}
	config.DirtyConfig.CommandPrefix = append([]string(nil), state.Outer.CommandPrefix...)
	config.DirtyConfig.DiceMasters = append([]string(nil), state.Outer.DiceMasters...)

	advanced := AdvancedConfig{
		Show:                              state.Advanced.Show,
		Enable:                            state.Advanced.Enable,
		StoryLogBackendUrl:                state.Advanced.StoryLogBackendURL,
		CustomReplyCooldown:               state.Advanced.CustomReplyCooldown,
		ExposeDangerousSealInst:           state.Advanced.ExposeDangerousSealInst,
		AllowFilesystemUnrestrictedAccess: state.Advanced.AllowFilesystemUnrestrictedAccess,
	}
	return config, advanced, state, nil
}
