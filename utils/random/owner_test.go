package random_test

import (
	"reflect"
	"testing"

	ds "github.com/sealdice/dicescript"

	randcore "Scardice-core/utils/random"
)

type fixedDiceSource struct {
	value uint64
}

func (s *fixedDiceSource) Uint64() uint64 {
	return s.value
}

func TestGlobalOwnerSetActiveFallsBackToAnyAvailableSource(t *testing.T) {
	owner := randcore.NewEmptyGlobalOwner()
	owner.RegisterSource(randcore.ModeGM, &fixedDiceSource{value: 7})

	mode, err := owner.SetActive(randcore.ModeNIST)
	if err == nil {
		t.Fatal("expected SetActive to report fallback error")
	}
	if mode != randcore.ModeGM {
		t.Fatalf("SetActive(nist) fallback mode = %s, want gm", mode)
	}
	if got := owner.Uint64(); got != 7 {
		t.Fatalf("Uint64() = %d, want 7", got)
	}
}

func TestGlobalOwnerHybridRequiresAtLeastTwoSources(t *testing.T) {
	owner := randcore.NewEmptyGlobalOwner()
	owner.RegisterSource(randcore.ModePCG, &fixedDiceSource{value: 7})
	if err := owner.RegisterHybridSource(); err == nil {
		t.Fatal("RegisterHybridSource accepted a single available source")
	}
	fallbackMode, fallbackErr := owner.SetActive(randcore.ModeHybrid)
	if fallbackErr == nil || fallbackMode != randcore.ModePCG {
		t.Fatalf("SetActive(hybrid) with one source = (%s, %v), want (pcg, error)", fallbackMode, fallbackErr)
	}

	owner.RegisterSource(randcore.ModeGM, &fixedDiceSource{value: 3})
	if err := owner.RegisterHybridSource(); err != nil {
		t.Fatalf("RegisterHybridSource with two sources: %v", err)
	}
	mode, err := owner.SetActive(randcore.ModeHybrid)
	if err != nil || mode != randcore.ModeHybrid {
		t.Fatalf("SetActive(hybrid) = (%s, %v), want (hybrid, nil)", mode, err)
	}
	if got := owner.Uint64(); got != 7^3 {
		t.Fatalf("hybrid Uint64() = %d, want %d", got, 7^3)
	}
}

func TestNewSourceForModeCreatesDistinctReaderSources(t *testing.T) {
	gm, err := randcore.NewSourceForMode(randcore.ModeGM, nil)
	if err != nil {
		t.Fatalf("NewSourceForMode(gm): %v", err)
	}
	nist, err := randcore.NewSourceForMode(randcore.ModeNIST, nil)
	if err != nil {
		t.Fatalf("NewSourceForMode(nist): %v", err)
	}

	if reflect.TypeOf(gm) == reflect.TypeOf(nist) {
		t.Fatalf("gm and nist sources should not share the same concrete type: %T", gm)
	}
}

var _ ds.DiceSource = (*fixedDiceSource)(nil)
