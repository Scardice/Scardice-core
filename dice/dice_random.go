package dice

import (
	"errors"
	"strings"

	ds "github.com/sealdice/dicescript"

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
	return randcore.NormalizeMode(dm.DiceRandomMode)
}

func (dm *DiceManager) syncDiceRandomMode() {
	if dm == nil {
		return
	}
	mode := string(dm.GetDiceRandomMode())
	for _, d := range dm.Dice {
		if d != nil {
			d.Config.DiceRandomMode = mode
		}
	}
}

func (dm *DiceManager) ActivateDiceRandomMode() error {
	if dm == nil {
		return errors.New("dice manager is nil")
	}

	configuredMode := dm.GetDiceRandomMode()
	dm.DiceRandomMode = string(configuredMode)
	effectiveMode, initErr := globalRandSource.SetActive(configuredMode)
	dm.syncDiceRandomMode()
	if effectiveMode != configuredMode {
		return initErr
	}
	return nil
}

func (dm *DiceManager) SetDiceRandomMode(mode DiceRandomMode) (DiceRandomMode, error) {
	if dm == nil {
		return "", errors.New("dice manager is nil")
	}

	requestedMode := randcore.NormalizeMode(string(mode))
	effectiveMode, err := globalRandSource.SetActive(requestedMode)
	if err != nil || effectiveMode != requestedMode {
		return effectiveMode, err
	}
	dm.DiceRandomMode = string(requestedMode)
	dm.syncDiceRandomMode()
	return effectiveMode, nil
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
