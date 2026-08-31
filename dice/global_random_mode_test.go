package dice

import "testing"

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
