package dice

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"Scardice-core/core/configstate"
	"Scardice-core/eventstore"
	"Scardice-core/logger"

	"github.com/robfig/cron/v3"
)

// PrepareEventSourcedState creates the first durable configuration aggregate for
// a fresh store and hydrates the compatibility view from its projection. It
// never reads the legacy YAML/database files.
func (dm *DiceManager) PrepareEventSourcedState(ctx context.Context) error {
	if dm == nil || !dm.EventSourcedMode {
		return errors.New("dice manager is not in event-sourced mode")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for _, instance := range dm.Dice {
		if instance == nil {
			continue
		}
		if err := instance.prepareEventSourcedConfig(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (d *Dice) prepareEventSourcedConfig(ctx context.Context) error {
	if d == nil || d.DurableStore == nil {
		return errors.New("dice: event-sourced store is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(d.BaseConfig.Name) == "" {
		return errors.New("dice: event-sourced Dice name is empty")
	}
	if d.BaseConfig.DataDir == "" {
		d.BaseConfig.DataDir = filepath.Join("./data", d.BaseConfig.Name)
	}
	d.Config = NewConfig(d)
	d.Config.BaseConfig = d.BaseConfig
	d.Config.CommandCompatibleMode = true
	if len(d.CommandPrefix) == 0 {
		d.CommandPrefix = append([]string(nil), DefaultConfig.CommandPrefix...)
	}
	repository := configstate.NewRepository(d.DurableStore)
	state, err := repository.Load(ctx, d.BaseConfig.Name)
	if err != nil {
		return fmt.Errorf("dice: load event-sourced config: %w", err)
	}
	if state.Version == 0 {
		patch, patchErr := durableConfigPatch(configstate.State{}, d.Config, d.CommandPrefix, d.DiceMasters, nil)
		if patchErr != nil {
			return fmt.Errorf("dice: build default config baseline: %w", patchErr)
		}
		baseline := baselineFromConfigPatch(d.BaseConfig.Name, d.Config.ConfigVersion, patch, d.CommandPrefix, d.DiceMasters)
		if _, err = repository.DecideAndAppend(ctx, state, 0, eventstore.Metadata{}, configstate.Command{
			Kind:     configstate.CommandImportBaseline,
			Baseline: &baseline,
		}); err != nil {
			return fmt.Errorf("dice: append default config baseline: %w", err)
		}
	}
	config, advanced, projected, err := d.DurableLegacyConfigView(ctx)
	if err != nil {
		return fmt.Errorf("dice: hydrate event-sourced config: %w", err)
	}
	d.Config = config
	d.AdvancedConfig = advanced
	d.CommandPrefix = append([]string(nil), projected.Outer.CommandPrefix...)
	d.DiceMasters = append([]string(nil), projected.Outer.DiceMasters...)
	return nil
}

func baselineFromConfigPatch(diceID string, configVersion int, patch configstate.ConfigPatch, commandPrefix, diceMasters []string) configstate.Baseline {
	baseline := configstate.Baseline{
		DiceID:        diceID,
		ConfigVersion: configVersion,
		CommandPrefix: append([]string(nil), commandPrefix...),
		DiceMasters:   append([]string(nil), diceMasters...),
	}
	if patch.Base != nil {
		baseline.Base = *patch.Base
	}
	if patch.Rate != nil {
		baseline.Rate = *patch.Rate
	}
	if patch.Quit != nil {
		baseline.Quit = *patch.Quit
	}
	if patch.Extension != nil {
		baseline.Extension = *patch.Extension
	}
	if patch.Ban != nil {
		baseline.Ban = *patch.Ban
	}
	if patch.JS != nil {
		baseline.JS = *patch.JS
	}
	if patch.StoryLog != nil {
		baseline.StoryLog = *patch.StoryLog
	}
	if patch.Mail != nil {
		baseline.Mail = *patch.Mail
	}
	if patch.News != nil {
		baseline.News = *patch.News
	}
	if patch.PublicDice != nil {
		baseline.PublicDice = *patch.PublicDice
	}
	if patch.Censor != nil {
		baseline.Censor = *patch.Censor
	}
	if patch.Store != nil {
		baseline.Store = *patch.Store
	}
	if patch.Advanced != nil {
		baseline.Advanced = *patch.Advanced
	}
	return baseline
}

// initEventSourcedRuntime wires only process-owned Core compatibility state.
// Legacy configuration, group state, stores, and periodic save loops remain
// outside this path; their authoritative replacements are event-store owned.
func (d *Dice) initEventSourcedRuntime(uiWriter *logger.UIWriter) {
	log := logger.M()
	d.Logger = log
	d.LogWriter = uiWriter
	d.Cron = cron.New()
	d.Cron.Start()
	d.CocExtraRules = map[int]*CocRuleInfo{}
	d.DBOperator = nil
	d.BaseConfig.CommandCompatibleMode = true
	d.ImSession = &IMSession{Parent: d, ServiceAtNew: new(SyncMap[string, *GroupInfo]), PendingQuits: new(SyncMap[string, *PendingQuitInfo])}
	d.UIEndpoint = &EndPointInfo{Adapter: &PlatformAdapterHTTP{}}
	d.UIEndpoint.Enable = true
	d.UIEndpoint.Platform = "UI"
	d.UIEndpoint.ID = "1"
	d.UIEndpoint.State = StateConnected
	d.UIEndpoint.UserID = "UI:1000"
	d.UIEndpoint.Session = d.ImSession
	if adapter, ok := d.UIEndpoint.Adapter.(*PlatformAdapterHTTP); ok {
		adapter.EndPoint = d.UIEndpoint
	}
	d.CmdMap = CmdMapCls{}
	d.ExtRegistry = new(SyncMap[string, *ExtInfo])
	d.GameSystemMap = new(SyncMap[string, *GameSystemTemplate])
	d.DirtyGroups = new(SyncMap[string, int64])
	d.ConfigManager = NewConfigManager(filepath.Join(d.BaseConfig.DataDir, "configs", "plugin-configs.json"))
	d.ConfigManager.SetOwner(d)
	d.registerCoreCommands()
	d.RegisterBuiltinExt()
	d.IsAlreadyLoadConfig = false
	if d.Config.JsEnable {
		d.ExtLoopManager = NewJsLoopManager()
		d.JsInit()
		d.StartStartupJsLoad()
	} else {
		log.Info("js扩展支持已关闭，跳过js脚本的加载")
	}
	d.ApplyAliveNotice()
	d.ResetQuitInactiveCron()
	d.MarkModified()
}
