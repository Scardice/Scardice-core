package dice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"Scardice-core/core/configstate"
	"Scardice-core/dice/service"
	"Scardice-core/eventstore"
	"Scardice-core/logger"

	"github.com/robfig/cron/v3"
)

// PrepareEventSourcedState creates the first durable configuration aggregate for
// a fresh store and hydrates the compatibility view from its projection. It
// never reads the legacy YAML/database files.
func (dm *DiceManager) PrepareEventSourcedState(ctx context.Context) error {
	return dm.prepareEventSourcedState(ctx, logEventSourcedInitialization)
}

func (dm *DiceManager) prepareEventSourcedState(ctx context.Context, observer eventSourcedInitializationObserver) error {
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
		if err := instance.prepareEventSourcedConfig(ctx, observer); err != nil {
			return err
		}
	}
	return nil
}

type eventSourcedProjectionLister interface {
	ListProjectionRows(ctx context.Context, projectionName string) ([]eventstore.ProjectionRow, error)
}

// RestoreEventSourcedDice reconstructs the process-owned Dice shells from the
// durable config projection. It does not read dice.yaml or any legacy store.
func (dm *DiceManager) RestoreEventSourcedDice(ctx context.Context, store eventstore.Store) error {
	if dm == nil || !dm.EventSourcedMode || store == nil {
		return errors.New("dice manager is not ready for event-sourced restore")
	}
	logArchive, ok := store.(eventstore.LogRepository)
	if !ok {
		return errors.New("dice: event store does not provide the story-log archive")
	}
	lister, ok := store.(eventSourcedProjectionLister)
	if !ok {
		return errors.New("dice: event store cannot list config projections")
	}
	rows, err := lister.ListProjectionRows(ctx, configstate.ConfigProjectionName)
	if err != nil {
		return fmt.Errorf("dice: list event-sourced configurations: %w", err)
	}
	dm.diceLock.Lock()
	defer dm.diceLock.Unlock()
	if len(dm.Dice) != 0 {
		return errors.New("dice: restore requires an empty manager")
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].RowKey < rows[j].RowKey })
	if len(rows) == 0 {
		names := make([]string, 0, len(dm.managerState.Public.DiceDataDirs))
		for name := range dm.managerState.Public.DiceDataDirs {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			dm.Dice = append(dm.Dice, &Dice{
				BaseConfig:    BaseConfig{Name: name, DataDir: dm.managerState.Public.DiceDataDirs[name]},
				DurableStore:  store,
				LogRepository: service.NewEventStoreLogRepository(logArchive, name),
				ContainerMode: dm.ContainerMode,
			})
		}
		return nil
	}
	for _, row := range rows {
		var state configstate.State
		if err = json.Unmarshal(row.Payload, &state); err != nil {
			return fmt.Errorf("dice: decode event-sourced configuration %q: %w", row.RowKey, err)
		}
		if state.Version == 0 || state.DiceID == "" || state.DiceID != row.RowKey {
			return errors.New("dice: invalid event-sourced configuration identity")
		}
		dataDir := dm.managerState.Public.DiceDataDirs[state.DiceID]
		if dataDir == "" {
			dataDir = filepath.Join("./data", state.DiceID)
		}
		dm.Dice = append(dm.Dice, &Dice{
			BaseConfig:    BaseConfig{Name: state.DiceID, DataDir: dataDir},
			DurableStore:  store,
			LogRepository: service.NewEventStoreLogRepository(logArchive, state.DiceID),
			ContainerMode: dm.ContainerMode,
		})
	}
	return nil
}

func (d *Dice) prepareEventSourcedConfig(ctx context.Context, observer eventSourcedInitializationObserver) error {
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
		if len(d.DiceMasters) == 0 {
			d.DiceMasters = append([]string(nil), DefaultConfig.DiceMasters...)
		}
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
		if observer != nil {
			observer(eventSourcedInitializationEvent{
				Resource: eventSourcedInitializationResourceDiceConfig,
				ID:       d.BaseConfig.Name,
			})
		}
	} else if len(state.Outer.DiceMasters) == 0 {
		shouldSeed, seedErr := shouldSeedDefaultDiceMasters(ctx, d.DurableStore, d.BaseConfig.Name)
		if seedErr != nil {
			return fmt.Errorf("dice: inspect default UI master migration: %w", seedErr)
		}
		if shouldSeed {
			masters := append([]string(nil), DefaultConfig.DiceMasters...)
			if _, err = repository.DecideAndAppend(ctx, state, state.Version, eventstore.Metadata{}, configstate.Command{
				Kind: configstate.CommandPatch,
				Patch: &configstate.ConfigPatch{
					SetDiceMasters: true,
					DiceMasters:    masters,
				},
			}); err != nil {
				return fmt.Errorf("dice: migrate default UI master: %w", err)
			}
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
	if d.Config.BanList != nil {
		d.Config.BanList.Parent = d
		if err := d.Config.BanList.LoadsWithError(); err != nil {
			return fmt.Errorf("dice: load event-sourced ban list: %w", err)
		}
	}
	return nil
}

func shouldSeedDefaultDiceMasters(ctx context.Context, store eventstore.Store, diceID string) (bool, error) {
	readinessStore, ok := store.(eventstore.ReadinessRepository)
	if !ok {
		return false, nil
	}
	var readiness eventstore.Readiness
	var err error
	if metadata, hasMetadata := readinessStore.(eventstore.ReadinessMetadataRepository); hasMetadata {
		readiness, err = metadata.GetReadinessMetadata(ctx)
	} else {
		readiness, err = readinessStore.GetReadiness(ctx)
	}
	if err != nil {
		return false, err
	}
	if readiness.Mode != "fresh" {
		return false, nil
	}

	events, err := store.Load(ctx, configstate.ConfigStream(diceID), 1)
	if err != nil {
		return false, err
	}
	outerChanges := 0
	for _, envelope := range events {
		if envelope.EventType == string(configstate.EventConfigOuterChanged) {
			outerChanges++
		}
	}
	return outerChanges == 1, nil
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
	d.preferFileBackedGameSystemTemplates = true
	log := logger.M()
	d.Logger = log
	d.LogWriter = uiWriter
	d.Cron = cron.New()
	d.Cron.Start()
	d.clearCocExtraRules()
	d.DBOperator = nil
	d.BaseConfig.CommandCompatibleMode = true
	d.ImSession = &IMSession{Parent: d, ServiceAtNew: new(SyncMap[string, *GroupInfo]), PendingQuits: new(SyncMap[string, *PendingQuitInfo])}
	d.UIEndpoint = newUIEndpoint(d.ImSession)
	d.CmdMap = CmdMapCls{}
	d.ExtRegistry = new(SyncMap[string, *ExtInfo])
	d.GameSystemMap = new(SyncMap[string, *GameSystemTemplate])
	d.DirtyGroups = new(SyncMap[string, int64])
	d.ConfigManager = NewConfigManager(filepath.Join(d.BaseConfig.DataDir, "configs", "plugin-configs.json"))
	d.ConfigManager.SetOwner(d)
	d.AttrsManager = &AttrsManager{}
	if err := d.AttrsManager.InitDurable(d); err != nil {
		panic(fmt.Errorf("dice: initialize durable attributes: %w", err))
	}
	d.initializeTextTemplates()
	d.registerCoreCommands()
	d.RegisterBuiltinExt()
	d.initPackageManager()
	d.StoreSetup()
	if banList := d.Config.BanList; banList != nil {
		banList.Parent = d
		banList.AfterLoads()
	}
	if d.Config.EnableCensor {
		d.NewCensorManager()
	}
	d.ApplyExtDefaultSettings()
	d.IsAlreadyLoadConfig = false
	// 始终在启动时应用待生效的运行时包，JS 执行开关只控制脚本加载。
	d.jsRuntimeManager = NewJSRuntimeManagerForDice(d)
	loadStartupJS := d.Config.JsEnable
	if loadStartupJS {
		d.ExtLoopManager = NewJsLoopManager()
		d.JsInit()
	} else {
		log.Info("js扩展支持已关闭，跳过js脚本的加载")
		d.PackageSetup()
	}
	d.ApplyAliveNotice()
	d.ResetQuitInactiveCron()
	d.MarkModified()
	if loadStartupJS {
		d.startStartupJsLoad(func() {
			d.PackageSetup()
			d.runExtensionOnLoad()
		})
	} else {
		d.runExtensionOnLoad()
	}
}
