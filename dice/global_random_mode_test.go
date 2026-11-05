package dice

import (
	"context"
	"errors"
	"testing"

	"Scardice-core/core/managerstate"
)

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

	manager := &DiceManager{
		DiceRandomMode: string(DiceRandomModePCG),
		Dice:           []*Dice{{}},
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
}

func TestDiceManagerRandomModePublishesOnlyAfterCanonicalCommit(t *testing.T) {
	installGlobalDiceSourceState(t, completeSourceMap(
		sourceOverride{mode: DiceRandomModePCG, src: &countingDiceSource{values: []uint64{1}}},
		sourceOverride{mode: DiceRandomModeGM, src: &countingDiceSource{values: []uint64{2}}},
	), nil)
	d, store := newCanonicalTestDice(t)
	manager := &DiceManager{
		DiceRandomMode: string(DiceRandomModePCG), Dice: []*Dice{d},
	}
	d.Parent = manager
	ctx := context.Background()
	if err := manager.RestoreEventSourcedManager(ctx, store); err != nil {
		t.Fatal(err)
	}
	stage := func(transaction *DurableCallbackTransaction) error {
		_, err := manager.SetDiceRandomModeForContext(&MsgContext{Dice: d, callbackTransaction: transaction}, DiceRandomModeGM)
		if err != nil {
			return err
		}
		if got := globalRandSource.CurrentMode(); got != DiceRandomModePCG {
			t.Fatalf("uncommitted command activated %q", got)
		}
		return nil
	}
	hostErr := errors.New("command failed after selecting a mode")
	err := d.WithDomainExecution(ctx, "random-mode-aborted", []byte("gm"), func(transaction *DurableCallbackTransaction) error {
		if err := stage(transaction); err != nil {
			return err
		}
		return hostErr
	})
	if !errors.Is(err, hostErr) {
		t.Fatalf("failed root error = %v", err)
	}
	if got := globalRandSource.CurrentMode(); got != DiceRandomModePCG {
		t.Fatalf("failed root activated %q", got)
	}
	repository, err := managerstate.NewRepository(store)
	if err != nil {
		t.Fatal(err)
	}
	state, _, err := repository.Load(ctx)
	if err != nil || state.Public.DiceRandomMode != string(DiceRandomModePCG) {
		t.Fatalf("failed root changed canonical mode: state=%+v err=%v", state, err)
	}
	if err := d.WithDomainExecution(ctx, "random-mode-committed", []byte("gm"), stage); err != nil {
		t.Fatal(err)
	}
	state, _, err = repository.Load(ctx)
	if err != nil || state.Public.DiceRandomMode != string(DiceRandomModeGM) {
		t.Fatalf("committed mode: state=%+v err=%v", state, err)
	}
	if got := globalRandSource.CurrentMode(); got != DiceRandomModeGM {
		t.Fatalf("committed root did not activate canonical mode: %q", got)
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
