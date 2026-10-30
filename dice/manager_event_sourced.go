package dice

import (
	"context"
	"errors"
	"sort"
	"strings"
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
	if dm == nil || !dm.EventSourcedMode || store == nil {
		return errors.New("dice manager is not ready for event-sourced restore")
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

func (dm *DiceManager) saveEventSourcedManager() error {
	dm.managerStateMu.Lock()
	defer dm.managerStateMu.Unlock()
	return dm.saveEventSourcedManagerLocked()
}

func (dm *DiceManager) saveEventSourcedManagerLocked() error {
	if dm.durableStore == nil || dm.managerState.Version == 0 {
		return errors.New("event-sourced manager state is unavailable")
	}
	public, auth := dm.eventSourcedManagerSnapshot()
	repository, err := managerstate.NewRepository(dm.durableStore)
	if err != nil {
		return err
	}
	state, err := repository.Save(context.Background(), dm.managerState, public, auth)
	if err != nil {
		return err
	}
	dm.managerState = state
	return nil
}

// AuthenticateAndStoreAccessToken serializes login with manager configuration
// changes so a token is checked, stored, and durably published as one update.
func (dm *DiceManager) AuthenticateAndStoreAccessToken(password, token string) (bool, error) {
	if dm == nil || strings.TrimSpace(token) == "" {
		return false, errors.New("manager authentication is unavailable")
	}
	dm.managerStateMu.Lock()
	defer dm.managerStateMu.Unlock()
	if dm.UIPasswordHash != "" && dm.UIPasswordHash != password {
		return false, nil
	}
	dm.AccessTokens.Store(token, true)
	if err := dm.saveEventSourcedManagerLocked(); err != nil {
		dm.AccessTokens.Delete(token)
		return false, err
	}
	return true, nil
}

func (dm *DiceManager) eventSourcedManagerSnapshot() (managerstate.PublicConfig, managerstate.Auth) {
	tokens := make([]string, 0)
	dm.AccessTokens.Range(func(token string, enabled bool) bool {
		if enabled {
			tokens = append(tokens, token)
		}
		return true
	})
	sort.Strings(tokens)
	dataDirs := make(map[string]string, len(dm.Dice))
	for _, instance := range dm.Dice {
		if instance == nil || instance.BaseConfig.Name == "" {
			continue
		}
		dataDir := instance.BaseConfig.DataDir
		if dataDir == "" {
			dataDir = "./data/" + instance.BaseConfig.Name
		}
		dataDirs[instance.BaseConfig.Name] = dataDir
	}
	public := managerstate.PublicConfig{
		ServeAddress: dm.ServeAddress, TrayTooltip: dm.GetTrayTooltip(),
		WebUIAddress: dm.managerState.Public.WebUIAddress, HelpDocEngineType: dm.HelpDocEngineType,
		DiceRandomMode: dm.DiceRandomMode, AutoBackupEnable: dm.AutoBackupEnable,
		AutoBackupTime: dm.AutoBackupTime, AutoBackupSelection: uint64(dm.AutoBackupSelection),
		BackupClean: managerstate.BackupCleanConfig{
			Strategy: int(dm.BackupCleanStrategy), KeepCount: dm.BackupCleanKeepCount,
			KeepDuration: int64(dm.BackupCleanKeepDur), Trigger: int(dm.BackupCleanTrigger),
			Cron: dm.BackupCleanCron,
		},
		ServiceName: dm.ServiceName, ConfigVersion: dm.managerState.Public.ConfigVersion,
		DiceDataDirs: dataDirs,
	}
	auth := managerstate.Auth{UIPasswordSalt: dm.UIPasswordSalt, UIPasswordHash: dm.UIPasswordHash, AccessTokens: tokens}
	return public, auth
}
