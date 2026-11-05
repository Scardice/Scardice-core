package dice

import (
	"context"
	"errors"
	"strings"

	ds "github.com/sealdice/dicescript"

	"Scardice-core/eventstore"
	"Scardice-core/logger"
	randcore "Scardice-core/utils/random"
)

func normalizeGlobalDiceRandomMode(configured string, legacy []BaseConfig) DiceRandomMode {
	if strings.TrimSpace(configured) != "" {
		return randcore.NormalizeMode(configured)
	}
	for _, config := range legacy {
		if strings.TrimSpace(config.DiceRandomMode) != "" {
			return randcore.NormalizeMode(config.DiceRandomMode)
		}
	}
	return DiceRandomModePCG
}

func (dm *DiceManager) GetDiceRandomMode() DiceRandomMode {
	if dm == nil {
		return DiceRandomModePCG
	}
	dm.managerStateMu.Lock()
	configured := dm.DiceRandomMode
	if dm.managerState.Version != 0 {
		configured = dm.managerState.Public.DiceRandomMode
	}
	dm.managerStateMu.Unlock()
	return randcore.NormalizeMode(configured)
}

func (dm *DiceManager) ActivateDiceRandomMode() error {
	if dm == nil {
		return errors.New("dice manager is nil")
	}

	configuredMode := dm.GetDiceRandomMode()
	effectiveMode, initErr := globalRandSource.SetActive(configuredMode)
	if effectiveMode != configuredMode {
		return initErr
	}
	return nil
}

func (dm *DiceManager) SetDiceRandomMode(mode DiceRandomMode) (DiceRandomMode, error) {
	if dm == nil {
		return "", errors.New("dice manager is nil")
	}
	requested := string(randcore.NormalizeMode(string(mode)))
	effective, err := dm.ValidateDiceRandomMode(DiceRandomMode(requested))
	if err != nil {
		return effective, err
	}
	ctx := context.Background()
	err = dm.withFreshDomainExecution(ctx, "manager-random-mode", requested, func(transaction *DurableCallbackTransaction, _ eventstore.Metadata) error {
		return dm.contributeManagerPatch(ctx, transaction.Domain(), &DurableManagerConfigPatch{DiceRandomMode: &requested})
	})
	if err != nil {
		return globalRandSource.CurrentMode(), err
	}
	if err = dm.reloadManagerRuntime(ctx); err != nil {
		return globalRandSource.CurrentMode(), &ConfigRuntimeApplyError{Err: err}
	}
	if err = dm.ActivateDiceRandomMode(); err != nil {
		return globalRandSource.CurrentMode(), &ConfigRuntimeApplyError{Err: err}
	}
	return globalRandSource.CurrentMode(), nil
}

func (dm *DiceManager) SetDiceRandomModeForContext(ctx *MsgContext, mode DiceRandomMode) (DiceRandomMode, error) {
	if dm == nil || ctx == nil || ctx.Dice == nil || ctx.Dice.Parent != dm || ctx.callbackTransaction == nil {
		return "", ErrDomainTxUnavailable
	}
	requested := randcore.NormalizeMode(string(mode))
	effective, err := dm.ValidateDiceRandomMode(requested)
	if err != nil {
		return effective, err
	}
	value := string(requested)
	if err = dm.contributeManagerPatch(ctx.domainContext(), ctx.callbackTransaction.Domain(), &DurableManagerConfigPatch{DiceRandomMode: &value}); err != nil {
		return effective, err
	}
	if err = ctx.callbackTransaction.AfterCommit(func() {
		if reloadErr := dm.reloadManagerRuntime(context.Background()); reloadErr != nil {
			logger.M().Errorf("随机模式已提交但运行配置刷新失败: %v", reloadErr)
			return
		}
		if activateErr := dm.ActivateDiceRandomMode(); activateErr != nil {
			logger.M().Errorf("随机模式已提交但运行源激活失败: %v", activateErr)
		}
	}); err != nil {
		return effective, err
	}
	return requested, nil
}

func (dm *DiceManager) ValidateDiceRandomMode(mode DiceRandomMode) (DiceRandomMode, error) {
	if dm == nil {
		return "", errors.New("dice manager is nil")
	}
	requestedMode := randcore.NormalizeMode(string(mode))
	return globalRandSource.ValidateActive(requestedMode)
}

func (d *Dice) Roll(points int) int {
	if points <= 0 {
		return 0
	}
	val := ds.Roll(globalRandSource, ds.IntType(points), 0)
	return int(val)
}

func (d *Dice) Roll64(points int64) int64 {
	return DiceRoll64x(globalRandSource, points)
}

func (d *Dice) RandIntn(n int) int {
	return randIntnFromSource(globalRandSource, n)
}

func (d *Dice) Shuffle(n int, swap func(i, j int)) {
	shuffleWithSource(globalRandSource, n, swap)
}
func DiceRandUint64() uint64 {
	return globalRandSource.Uint64()
}

func DiceRandIntn(n int) int {
	return globalRandSource.IntN(n)
}

func DiceRandFloat64() float64 {
	return globalRandSource.Float64()
}

func DiceRandString(n int, alphabet string) string {
	return globalRandSource.String(n, alphabet)
}
