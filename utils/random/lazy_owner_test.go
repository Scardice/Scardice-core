package random

import "testing"

func TestNewGlobalOwnerDefersOptionalRandomSources(t *testing.T) {
	owner := NewGlobalOwner(nil)
	if len(owner.sources) != 1 || owner.sources[ModePCG] == nil {
		t.Fatalf("startup sources = %v, want only %s", owner.sources, ModePCG)
	}

	for _, requested := range []Mode{ModeCRNG, ModeGM} {
		t.Run(string(requested), func(t *testing.T) {
			mode, err := owner.SetActive(requested)
			if err != nil {
				t.Fatalf("SetActive(%s): %v", requested, err)
			}
			if mode != requested || owner.sources[requested] == nil {
				t.Fatalf("on-demand source = (%s, %T), want initialized %s", mode, owner.sources[requested], requested)
			}
			_ = owner.Uint64()
		})
	}
}
