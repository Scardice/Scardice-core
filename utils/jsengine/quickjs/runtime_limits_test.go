package quickjs

import (
	"errors"
	"testing"

	"Scardice-core/utils/jsengine"
)

func TestWithRuntimeLimitsAppliesMemoryAndGCThreshold(t *testing.T) {
	loop, err := New(WithRuntimeLimits(RuntimeLimits{
		MemoryLimit: 2 * 1024 * 1024,
		GCThreshold: 512 * 1024,
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer loop.Close()

	if err := loop.Run(func(current jsengine.Runtime) error {
		realm := current.(*runtime)
		usage := realm.ctx.Runtime().MemoryUsage()
		if usage.MallocLimit != 2*1024*1024 {
			return errors.New("QuickJS memory limit was not applied")
		}
		if got := realm.ctx.Runtime().GCThreshold(); got != 512*1024 {
			return errors.New("QuickJS GC threshold was not applied")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestWithRuntimeLimitsRestrictsStack(t *testing.T) {
	loop, err := New(WithRuntimeLimits(RuntimeLimits{MaxStackSize: 64 * 1024}))
	if err != nil {
		t.Fatal(err)
	}
	defer loop.Close()

	if err := loop.Run(func(current jsengine.Runtime) error {
		_, err := current.RunString("stack-limit.js", `
			function recurse(depth) {
				return depth === 0 ? 0 : 1 + recurse(depth - 1);
			}
			recurse(4096);
		`)
		if err == nil {
			return errors.New("deep recursion unexpectedly bypassed the QuickJS stack limit")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
