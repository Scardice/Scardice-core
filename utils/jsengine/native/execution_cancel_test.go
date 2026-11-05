//go:build cgo

package native

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"Scardice-core/utils/jsengine"
)

func TestNativeCPULoopObservesCurrentExecutionCancellation(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		name := "cancel"
		if deadline {
			name = "deadline"
		}
		t.Run(name, func(t *testing.T) {
			loop := openQuickJSJSONLoop(t).(*nativeLoop)
			execution, cancel := context.WithCancel(context.Background())
			defer cancel()
			stop := func() {
				if deadline {
					<-execution.Done()
				} else {
					cancel()
				}
			}
			if err := loop.Run(func(runtime jsengine.Runtime) error {
				if err := runtime.Set("stopCurrentExecution", stop); err != nil {
					return err
				}
				_, err := runtime.RunString("initialize-execution-cancel.js", `globalThis.cancelEscaped = false`)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			// Start the real deadline only after the host fixture is installed;
			// setup work must not consume the execution's timeout.
			if deadline {
				cancel()
				execution, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
				defer cancel()
			}
			var engineErr error
			err := loop.RunWithContext(&invocationTestContext{Context: execution, id: 201}, func(runtime jsengine.Runtime) error {
				_, engineErr = runtime.RunString("cancel-native-pure-cpu.js", `
					stopCurrentExecution();
					for (let index = 0; index < 1000000; index++) {}
					globalThis.cancelEscaped = true;
				`)
				return engineErr
			})
			wantContextErr, wantEngineErr := context.Canceled, ErrNativeClosed
			if deadline {
				wantContextErr, wantEngineErr = context.DeadlineExceeded, ErrNativeTimeout
			}
			if !errors.Is(err, wantContextErr) {
				t.Fatalf("execution error = %v, want %v", err, wantContextErr)
			}
			if !errors.Is(engineErr, wantEngineErr) {
				t.Errorf("pure CPU engine error = %v, want %v before reaching the next host call", engineErr, wantEngineErr)
			}
			if err := loop.Run(func(runtime jsengine.Runtime) error {
				result, err := runtime.RunString("recover-native-after-cancel.js", `cancelEscaped === false && 6 * 7`)
				if err != nil {
					return err
				}
				if got := result.Export(); got != int64(42) {
					return fmt.Errorf("canceled CPU loop escaped or poisoned the next entry: %v", got)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNativeExecutionStatusUsesProviderTokenNotAnotherActiveEntry(t *testing.T) {
	loop := openQuickJSJSONLoop(t).(*nativeLoop)
	execution, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := loop.RunWithContext(&invocationTestContext{Context: execution, id: 202}, func(runtime jsengine.Runtime) error {
		_, err := runtime.RunString("initialize-provider-token.js", `globalThis.revokedTokenEscaped = false`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	loop.contextMu.RLock()
	token := loop.contextTokens[202]
	loop.contextMu.RUnlock()
	cancel()
	waitNativeContextCondition(t, func() bool {
		loop.contextMu.RLock()
		defer loop.contextMu.RUnlock()
		_, retained := loop.contexts[token]
		return !retained
	})
	liveScope := &invocationTestContext{Context: context.Background(), id: 203}
	err := loop.RunWithContext(liveScope, func(runtime jsengine.Runtime) error {
		// The real provider context extension models a timer/Promise restoring
		// an expired token while another Go entry is live. That entry's scope
		// must not lend the old callback its authority.
		if err := loop.setNativeToken(token); err != nil {
			return err
		}
		_, err := runtime.RunString("revoked-provider-token-pure-cpu.js", `
			for (let index = 0; index < 1000000; index++) {}
			globalThis.revokedTokenEscaped = true;
		`)
		return err
	})
	if !errors.Is(err, ErrNativeClosed) {
		t.Errorf("revoked provider token error = %v, want ErrNativeClosed", err)
	}
	if err := loop.RunWithContext(liveScope, func(runtime jsengine.Runtime) error {
		result, err := runtime.RunString("live-provider-token-recovery.js", `revokedTokenEscaped === false && 40 + 2`)
		if err != nil {
			return err
		}
		if got := result.Export(); got != int64(42) {
			return fmt.Errorf("retired token borrowed a live entry or poisoned recovery: %v", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestNativeRevokedTimerDropsShortJavaScript(t *testing.T) {
	for _, timer := range []string{"setTimeout", "setInterval"} {
		t.Run(timer, func(t *testing.T) {
			loop := openQuickJSJSONLoop(t).(*nativeLoop)
			execution, cancel := context.WithCancel(t.Context())
			defer cancel()
			if err := loop.Run(func(runtime jsengine.Runtime) error {
				return runtime.Bind("cancelTimerOrigin", cancel)
			}); err != nil {
				t.Fatal(err)
			}
			err := loop.RunWithContext(&invocationTestContext{Context: execution, id: 211}, func(runtime jsengine.Runtime) error {
				_, err := runtime.RunString("revoked-short-timer.js", fmt.Sprintf(`
globalThis.revokedTimerEscaped = false;
(function () {
  const callback = () => { revokedTimerEscaped = true; };
  globalThis.revokedTimerWeak = new WeakRef(callback);
  %s(callback, 10);
})();
cancelTimerOrigin();`, timer))
				return err
			})
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			// Let the real provider tick reach the due timer before inspecting
			// both its language side effect and its retained callback.
			time.Sleep(40 * time.Millisecond)
			live := &invocationTestContext{Context: t.Context(), id: 212}
			if err := loop.RunWithContext(live, func(runtime jsengine.Runtime) error {
				value, err := runtime.RunString("revoked-short-timer-observe.js",
					"revokedTimerEscaped === false && revokedTimerWeak.deref() === undefined")
				if err == nil && !value.ToBoolean() {
					t.Errorf("%s executed or retained its revoked callback", timer)
				}
				return err
			}); err != nil {
				t.Fatalf("revoked %s failed a live root: %v", timer, err)
			}
		})
	}
}
