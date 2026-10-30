package dice

import (
	"errors"
	"testing"
)

func TestDiceManagerActivateRandomModeSynchronizesDiceMirrors(t *testing.T) {
	installGlobalDiceSourceState(t, completeSourceMap(
		sourceOverride{mode: DiceRandomModePCG, src: &countingDiceSource{values: []uint64{1}}},
		sourceOverride{mode: DiceRandomModeGM, src: &countingDiceSource{values: []uint64{2}}},
	), nil)

	manager := &DiceManager{
		DiceRandomMode: string(DiceRandomModeGM),
		Dice:           []*Dice{{}, {}},
	}
	if err := manager.ActivateDiceRandomMode(); err != nil {
		t.Fatalf("ActivateDiceRandomMode() error = %v", err)
	}
	if got := globalRandSource.CurrentMode(); got != DiceRandomModeGM {
		t.Fatalf("CurrentMode() = %s, want %s", got, DiceRandomModeGM)
	}
	for index, d := range manager.Dice {
		if got := d.Config.DiceRandomMode; got != string(DiceRandomModeGM) {
			t.Fatalf("Dice[%d].Config.DiceRandomMode = %q, want %q", index, got, DiceRandomModeGM)
		}
	}
}

func TestDiceManagerSetRandomModeDoesNotCommitFallback(t *testing.T) {
	installGlobalDiceSourceState(t, completeSourceMap(
		sourceOverride{mode: DiceRandomModePCG, src: &countingDiceSource{values: []uint64{1}}},
	), nil)

	manager := &DiceManager{
		DiceRandomMode: string(DiceRandomModePCG),
		Dice:           []*Dice{{}},
	}
	effective, err := manager.SetDiceRandomMode(DiceRandomModeGM)
	if err == nil {
		t.Fatal("SetDiceRandomMode() error = nil, want fallback error")
	}
	if effective == DiceRandomModeGM {
		t.Fatalf("SetDiceRandomMode() effective mode = %s, want a fallback", effective)
	}
	if got := manager.DiceRandomMode; got != string(DiceRandomModePCG) {
		t.Fatalf("DiceRandomMode = %q, want %q", got, DiceRandomModePCG)
	}
}

func TestDiceManagerValidateRandomModeDoesNotMutate(t *testing.T) {
	installGlobalDiceSourceState(t, completeSourceMap(
		sourceOverride{mode: DiceRandomModePCG, src: &countingDiceSource{values: []uint64{1}}},
	), nil)

	diceInstance := &Dice{}
	diceInstance.Config.DiceRandomMode = "existing"
	manager := &DiceManager{
		DiceRandomMode: string(DiceRandomModePCG),
		Dice:           []*Dice{diceInstance},
	}
	effective, err := manager.ValidateDiceRandomMode(DiceRandomModeGM)
	if err == nil {
		t.Fatalf("ValidateDiceRandomMode(gm) unexpectedly accepted missing source (effective=%q)", effective)
	}
	if got := manager.DiceRandomMode; got != string(DiceRandomModePCG) {
		t.Fatalf("validation changed manager mode to %q", got)
	}
	if got := globalRandSource.CurrentMode(); got != DiceRandomModePCG {
		t.Fatalf("validation changed active source to %q", got)
	}
	if got := diceInstance.Config.DiceRandomMode; got != "existing" {
		t.Fatalf("validation changed Dice config mode to %q", got)
	}
}

func TestDiceManagerRandomModeCommitIsAtomicWithActivation(t *testing.T) {
	installGlobalDiceSourceState(t, completeSourceMap(
		sourceOverride{mode: DiceRandomModePCG, src: &countingDiceSource{values: []uint64{1}}},
		sourceOverride{mode: DiceRandomModeGM, src: &countingDiceSource{values: []uint64{2}}},
	), nil)

	diceInstance := &Dice{}
	diceInstance.Config.DiceRandomMode = string(DiceRandomModePCG)
	manager := &DiceManager{
		DiceRandomMode: string(DiceRandomModePCG),
		Dice:           []*Dice{diceInstance},
	}
	commitErr := errors.New("durable commit failed")
	err := manager.setDiceRandomModeWithCommit(DiceRandomModeGM, func() error {
		return commitErr
	})
	if !errors.Is(err, commitErr) {
		t.Fatalf("failed durable commit error = %v, want %v", err, commitErr)
	}
	if got := globalRandSource.CurrentMode(); got != DiceRandomModePCG {
		t.Fatalf("failed commit left active mode %q, want PCG", got)
	}
	if manager.DiceRandomMode != string(DiceRandomModePCG) ||
		diceInstance.Config.DiceRandomMode != string(DiceRandomModePCG) {
		t.Fatalf("failed commit published mode: manager=%q dice=%q", manager.DiceRandomMode, diceInstance.Config.DiceRandomMode)
	}

	committed := false
	if err := manager.setDiceRandomModeWithCommit(DiceRandomModeGM, func() error {
		committed = true
		return nil
	}); err != nil {
		t.Fatalf("successful durable commit error = %v", err)
	}
	if !committed || globalRandSource.CurrentMode() != DiceRandomModeGM ||
		manager.DiceRandomMode != string(DiceRandomModeGM) ||
		diceInstance.Config.DiceRandomMode != string(DiceRandomModeGM) {
		t.Fatalf("successful activation not published atomically: committed=%v active=%q manager=%q dice=%q",
			committed, globalRandSource.CurrentMode(), manager.DiceRandomMode, diceInstance.Config.DiceRandomMode)
	}
}
func TestNormalizeGlobalDiceRandomModePrefersTopLevelConfig(t *testing.T) {
	legacy := []BaseConfig{
		{DiceRandomMode: string(DiceRandomModeGM)},
		{DiceRandomMode: string(DiceRandomModeNIST)},
	}

	if got := normalizeGlobalDiceRandomMode(string(DiceRandomModeCRNG), legacy); got != DiceRandomModeCRNG {
		t.Fatalf("normalizeGlobalDiceRandomMode() = %s, want %s", got, DiceRandomModeCRNG)
	}
}

func TestNormalizeGlobalDiceRandomModeMigratesFirstLegacyConfig(t *testing.T) {
	legacy := []BaseConfig{
		{DiceRandomMode: string(DiceRandomModeGM)},
		{DiceRandomMode: string(DiceRandomModeNIST)},
	}

	if got := normalizeGlobalDiceRandomMode("", legacy); got != DiceRandomModeGM {
		t.Fatalf("normalizeGlobalDiceRandomMode() = %s, want %s", got, DiceRandomModeGM)
	}
}
