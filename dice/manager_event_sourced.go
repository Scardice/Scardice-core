package dice

import (
	"context"
	"errors"
	"time"

	"Scardice-core/core/managerstate"
	"Scardice-core/eventstore"
	"Scardice-core/logger"
)

const (
	eventSourcedInitializationResourceManagerConfig = "默认 Core 配置"
	eventSourcedInitializationResourceDiceConfig    = "Dice 默认配置"
)

type eventSourcedInitializationEvent struct {
	Resource string
	ID       string
}

type eventSourcedInitializationObserver func(eventSourcedInitializationEvent)

func logEventSourcedInitialization(event eventSourcedInitializationEvent) {
	logger.M().Infof("自动创建%s：id=%s", event.Resource, event.ID)
}

func (dm *DiceManager) RestoreEventSourcedManager(ctx context.Context, store eventstore.Store) error {
	return dm.restoreEventSourcedManager(ctx, store, logEventSourcedInitialization)
}

func (dm *DiceManager) restoreEventSourcedManager(ctx context.Context, store eventstore.Store, observer eventSourcedInitializationObserver) error {
	if dm == nil {
		return errors.New("dice manager is nil")
	}
	if store == nil {
		return errors.New("dice: event store is required for manager restore")
	}
	repository, err := managerstate.NewRepository(store)
	if err != nil {
		return err
	}
	state, auth, err := repository.Load(ctx)
	if errors.Is(err, eventstore.ErrNotFound) {
		public := managerstate.PublicConfig{
			ServeAddress: dm.ServeAddress, TrayTooltip: dm.GetTrayTooltip(),
			HelpDocEngineType: dm.HelpDocEngineType, DiceRandomMode: dm.DiceRandomMode,
			AutoBackupEnable: dm.AutoBackupEnable, AutoBackupTime: dm.AutoBackupTime,
			AutoBackupSelection: uint64(dm.AutoBackupSelection), ConfigVersion: 9914,
			DiceDataDirs: map[string]string{"default": "./data/default"},
		}
		auth = managerstate.Auth{UIPasswordSalt: dm.UIPasswordSalt, UIPasswordHash: dm.UIPasswordHash}
		state, err = repository.Save(ctx, managerstate.State{}, public, auth)
		if err == nil && observer != nil {
			observer(eventSourcedInitializationEvent{
				Resource: eventSourcedInitializationResourceManagerConfig,
				ID:       "manager",
			})
		}
	}
	if err != nil {
		return err
	}
	dm.managerStateMu.Lock()
	defer dm.managerStateMu.Unlock()
	dm.durableStore = store
	dm.managerState = state
	dm.applyEventSourcedManager(state.Public, auth)
	return nil
}

func (dm *DiceManager) applyEventSourcedManager(public managerstate.PublicConfig, auth managerstate.Auth) {
	dm.applyEventSourcedManagerPublic(public)
	if auth.UIPasswordSalt != "" {
		dm.UIPasswordSalt = auth.UIPasswordSalt
	}
	dm.UIPasswordHash = auth.UIPasswordHash
	dm.AccessTokens = SyncMap[string, bool]{}
	for _, token := range auth.AccessTokens {
		dm.AccessTokens.Store(token, true)
	}
}

func (dm *DiceManager) applyEventSourcedManagerPublic(public managerstate.PublicConfig) {
	dm.ServeAddress = public.ServeAddress
	dm.SetTrayTooltip(public.TrayTooltip)
	dm.HelpDocEngineType = public.HelpDocEngineType
	dm.DiceRandomMode = public.DiceRandomMode
	dm.AutoBackupEnable = public.AutoBackupEnable
	dm.AutoBackupTime = public.AutoBackupTime
	if dm.AutoBackupTime == "" {
		dm.AutoBackupEnable = true
		dm.AutoBackupTime = "@every 12h"
	}
	dm.AutoBackupSelection = BackupSelection(public.AutoBackupSelection)
	dm.BackupCleanStrategy = BackupCleanStrategy(public.BackupClean.Strategy)
	dm.BackupCleanKeepCount = public.BackupClean.KeepCount
	dm.BackupCleanKeepDur = time.Duration(public.BackupClean.KeepDuration)
	dm.BackupCleanTrigger = BackupCleanTrigger(public.BackupClean.Trigger)
	dm.BackupCleanCron = public.BackupClean.Cron
	dm.ServiceName = public.ServiceName
}
