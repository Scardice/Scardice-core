//go:build cgo

package native

import (
	"testing"
)

type keyedTestContext struct {
	id      int
	payload []string
}

func (c *keyedTestContext) ContextKey() any { return c.id }

func newContextLoop() *nativeLoop {
	return &nativeLoop{
		contexts:      make(map[uint64]any),
		contextTokens: make(map[any]uint64),
	}
}

// Callers allocate a fresh context per realm entry, so tokens must be interned
// by identity or the table would grow once per call and never shrink.
func TestNativeRegisterContextInternsEqualIdentities(t *testing.T) {
	loop := newContextLoop()
	first := loop.registerContext(&keyedTestContext{id: 7, payload: []string{"a"}})
	if first == 0 {
		t.Fatal("registerContext returned the empty token")
	}
	for i := 0; i < 64; i++ {
		again := loop.registerContext(&keyedTestContext{id: 7, payload: []string{"b"}})
		if again != first {
			t.Fatalf("token for equal identity = %d, want %d", again, first)
		}
	}
	other := loop.registerContext(&keyedTestContext{id: 8})
	if other == first {
		t.Fatalf("token for identity 8 = %d, want a distinct token", other)
	}
	if got := len(loop.contexts); got != 2 {
		t.Fatalf("retained contexts = %d, want 2", got)
	}
	// The latest context wins so callbacks observe current state.
	current, ok := loop.contexts[first].(*keyedTestContext)
	if !ok || len(current.payload) != 1 || current.payload[0] != "b" {
		t.Fatalf("interned context = %#v, want the most recent value", loop.contexts[first])
	}
}

func TestNativeRegisterContextInternsComparableContexts(t *testing.T) {
	loop := newContextLoop()
	first := loop.registerContext("plugin-a")
	second := loop.registerContext("plugin-a")
	if first != second {
		t.Fatalf("token for repeated comparable context = %d, want %d", second, first)
	}
	if third := loop.registerContext("plugin-b"); third == first {
		t.Fatalf("token for plugin-b = %d, want a distinct token", third)
	}
	if got := len(loop.contextTokens); got != 2 {
		t.Fatalf("interned identities = %d, want 2", got)
	}
}

// A context that is neither keyed nor comparable cannot be interned; it must
// still produce a usable token instead of panicking on a map write.
func TestNativeRegisterContextAcceptsUninternableContexts(t *testing.T) {
	loop := newContextLoop()
	first := loop.registerContext([]string{"a"})
	second := loop.registerContext([]string{"a"})
	if first == 0 || second == 0 || first == second {
		t.Fatalf("tokens = (%d, %d), want two distinct non-empty tokens", first, second)
	}
	if got := len(loop.contextTokens); got != 0 {
		t.Fatalf("interned identities = %d, want 0", got)
	}
	if got := loop.registerContext(nil); got != 0 {
		t.Fatalf("token for nil context = %d, want 0", got)
	}
}
