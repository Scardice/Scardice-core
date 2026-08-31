package random

import (
	"errors"
	"testing"

	ds "github.com/sealdice/dicescript"
)

type flakySource struct {
	calls     int
	available bool
}

func (s *flakySource) Uint64() uint64 {
	s.calls++
	s.available = false
	return 0
}

func (s *flakySource) Available() bool {
	return s.available
}

func (s *flakySource) SourceError() error {
	return errors.New("source failed")
}

type constantSource uint64

func (s constantSource) Uint64() uint64 {
	return uint64(s)
}

func TestGlobalRandRetriesAfterActiveSourceFails(t *testing.T) {
	failing := &flakySource{available: true}
	owner := NewEmptyGlobalOwner()
	owner.RegisterSource(ModeGM, failing)
	owner.RegisterSource(ModePCG, constantSource(42))
	if _, err := owner.SetActive(ModeGM); err != nil {
		t.Fatalf("SetActive(gm) error = %v", err)
	}

	if got := owner.Uint64(); got != 42 {
		t.Fatalf("Uint64() = %d, want fallback value 42", got)
	}
	if got := owner.CurrentMode(); got != ModePCG {
		t.Fatalf("CurrentMode() = %s, want %s", got, ModePCG)
	}
}

func TestHybridSkipsFailedChildSource(t *testing.T) {
	failing := &flakySource{available: true}
	owner := NewEmptyGlobalOwner()
	owner.RegisterSource(ModePCG, constantSource(42))
	owner.RegisterSource(ModeGM, failing)
	if err := owner.RegisterHybridSource(); err != nil {
		t.Fatalf("RegisterHybridSource() error = %v", err)
	}
	if _, err := owner.SetActive(ModeHybrid); err != nil {
		t.Fatalf("SetActive(hybrid) error = %v", err)
	}

	if got := owner.Uint64(); got != 42 {
		t.Fatalf("first hybrid Uint64() = %d, want 42", got)
	}
	if got := owner.Uint64(); got != 42 {
		t.Fatalf("second hybrid Uint64() = %d, want 42", got)
	}
	if failing.calls != 1 {
		t.Fatalf("failed child calls = %d, want 1", failing.calls)
	}
}

func TestCRNGSourceExposesAvailabilityForFallback(t *testing.T) {
	src, err := NewSourceForMode(ModeCRNG, nil)
	if err != nil {
		t.Fatalf("NewSourceForMode(crng) error = %v", err)
	}
	if _, ok := src.(sourceAvailability); !ok {
		t.Fatalf("CRNG source type %T does not expose availability", src)
	}
}

var _ ds.DiceSource = (*flakySource)(nil)
