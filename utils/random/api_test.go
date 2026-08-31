package random_test

import (
	"math"
	"testing"

	randcore "Scardice-core/utils/random"
)

type sequenceSource struct {
	values []uint64
	index  int
}

func (s *sequenceSource) Uint64() uint64 {
	if len(s.values) == 0 {
		return 0
	}
	value := s.values[s.index%len(s.values)]
	s.index++
	return value
}

func newTestOwner(source *sequenceSource) *randcore.GlobalRand {
	owner := randcore.NewEmptyGlobalOwner()
	owner.RegisterSource(randcore.ModePCG, source)
	_, _ = owner.SetActive(randcore.ModePCG)
	return owner
}

func TestGlobalRandBoundedAPIsRejectInvalidBounds(t *testing.T) {
	owner := newTestOwner(&sequenceSource{})

	for name, call := range map[string]func(){
		"Uint64N": func() { owner.Uint64N(0) },
		"IntN":    func() { owner.IntN(0) },
		"Int63N":  func() { owner.Int63N(0) },
	} {
		t.Run(name, func(t *testing.T) {
			t.Helper()
			defer func() {
				if recover() == nil {
					t.Fatalf("%s did not panic for zero bound", name)
				}
			}()
			call()
		})
	}
}

func TestGlobalRandBoundedAPIsUseSourceWithoutModuloBias(t *testing.T) {
	owner := newTestOwner(&sequenceSource{values: []uint64{0, 7}})

	if got := owner.Uint64N(3); got != 1 {
		t.Fatalf("Uint64N(3) = %d, want 1 after rejecting zero", got)
	}
	if got := owner.IntN(5); got < 0 || got >= 5 {
		t.Fatalf("IntN(5) = %d, outside [0, 5)", got)
	}
	if got := owner.Int63N(3); got < 0 || got >= 3 {
		t.Fatalf("Int63N(3) = %d, outside [0, 3)", got)
	}
}

func TestGlobalRandFloat64UsesUint64Source(t *testing.T) {
	owner := newTestOwner(&sequenceSource{values: []uint64{math.MaxUint64}})

	if got := owner.Float64(); got < 0 || got >= 1 {
		t.Fatalf("Float64() = %v, outside [0, 1)", got)
	}
}

func TestGlobalRandStringUsesAlphabet(t *testing.T) {
	owner := newTestOwner(&sequenceSource{values: []uint64{0}})

	got := owner.String(32, "ab")
	if len(got) != 32 {
		t.Fatalf("String() length = %d, want 32", len(got))
	}
	for _, char := range got {
		if char != 'a' && char != 'b' {
			t.Fatalf("String() returned disallowed character %q", char)
		}
	}
}
