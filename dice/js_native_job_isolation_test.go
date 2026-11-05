package dice

import (
	"context"
	"os"
	"testing"
	"time"

	"Scardice-core/utils/jsengine"
)

func nativeJobIsolationFixture(t *testing.T, deadline bool) (jsengine.Loop, *jsExecutionContext, *jsExecutionContext, context.CancelFunc) {
	t.Helper()
	if os.Getenv("SCARDICE_RUNTIME_ROOT") == "" && os.Getenv("SCARDICE_QUICKJS_PACKAGE") == "" {
		t.Skip("native QuickJS package is not configured")
	}
	d, loop, script := persistentLifecycleFixture(t, "quickjs")
	var parent context.Context
	var cancel context.CancelFunc
	if deadline {
		parent, cancel = context.WithTimeout(t.Context(), 3*time.Second)
	} else {
		parent, cancel = context.WithCancel(t.Context())
	}
	origin := jsContextForRoot(parent, d, nil, script, nil, false)
	resolver := jsContextForRoot(t.Context(), d, nil, script, nil, false)
	t.Cleanup(func() {
		cancel()
		_ = origin.execution.stop()
		_ = resolver.execution.stop()
	})
	return loop, origin, resolver, cancel
}

func TestNativeAwaitCancellationDuringJobDoesNotFailResolverRoot(t *testing.T) {
	for _, cause := range []string{"cancel", "deadline"} {
		t.Run(cause, func(t *testing.T) {
			loop, origin, resolver, cancel := nativeJobIsolationFixture(t, cause == "deadline")
			if err := loop.Run(func(runtime jsengine.Runtime) error {
				return runtime.Bind("__expireAwaitJob", func() {
					if cause == "deadline" {
						<-origin.ExecutionContext().Done()
					} else {
						cancel()
					}
				})
			}); err != nil {
				t.Fatal(err)
			}
			if err := jsengine.RunWithContext(loop, origin, func(runtime jsengine.Runtime) error {
				_, err := runtime.RunString("mid-job-cancel-origin.js", `
globalThis.__midJobCancelledEscaped = false;
(async function () {
  await new Promise(resolve => globalThis.__resolveMidJobCancel = resolve);
  __expireAwaitJob();
  for (let i = 0; i < 1000000; ++i) {}
  __midJobCancelledEscaped = true;
})(); 0`)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if err := jsengine.RunWithContext(loop, resolver, func(runtime jsengine.Runtime) error {
				value, err := runtime.RunString("mid-job-cancel-resolver.js", "__resolveMidJobCancel(); 6 * 7 === 42")
				if err == nil && !value.ToBoolean() {
					t.Error("live resolver did not finish its own JavaScript")
				}
				return err
			}); err != nil {
				t.Fatalf("origin cancellation failed independent resolver root: %v", err)
			}
			requireJSGlobalFalse(t, loop, "__midJobCancelledEscaped")
			if err := resolver.ExecutionContext().Err(); err != nil {
				t.Fatalf("origin cancellation ended independent execution: %v", err)
			}
		})
	}
}

func TestNativeJobExceptionFormattingKeepsOriginContext(t *testing.T) {
	loop, origin, resolver, _ := nativeJobIsolationFixture(t, false)
	observed := make(chan *jsExecutionContext, 4)
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		return runtime.Bind("__recordJobFormatterScope", func() {
			observed <- jsOpaqueExecutionContext(jsengine.CurrentContext(loop))
		})
	}); err != nil {
		t.Fatal(err)
	}
	if err := jsengine.RunWithContext(loop, origin, func(runtime jsengine.Runtime) error {
		_, err := runtime.RunString("job-formatter-origin.js", `
new Promise(resolve => globalThis.__resolveJobFormatter = resolve).then(() => {
  queueMicrotask(() => {
    throw {toString() { __recordJobFormatterScope(); return "job formatter error"; }};
  });
}); 0`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := jsengine.RunWithContext(loop, resolver, func(runtime jsengine.Runtime) error {
		_, err := runtime.RunString("job-formatter-resolver.js", "__resolveJobFormatter()")
		return err
	}); err == nil {
		t.Fatal("live-origin job exception was silently swallowed")
	}
	scope := awaitPersistentLifecycle(t, observed, "actual exception formatter to enter its Go host callback")
	if scope == nil || scope.executionScope() != origin.executionScope() {
		t.Fatalf("job formatter borrowed resolver authority: scope=%p origin=%p resolver=%p", scope.executionScope(), origin.executionScope(), resolver.executionScope())
	}
	if err := jsengine.RunWithContext(loop, resolver, func(runtime jsengine.Runtime) error {
		current := jsOpaqueExecutionContext(jsengine.CurrentContext(loop))
		if current == nil || current.executionScope() != resolver.executionScope() {
			t.Error("job error left the provider under its origin instead of restoring the resolver")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestNativeDiscardedJobsDoNotExhaustIndependentRootBudget(t *testing.T) {
	loop, origin, resolver, cancel := nativeJobIsolationFixture(t, false)
	if err := jsengine.RunWithContext(loop, origin, func(runtime jsengine.Runtime) error {
		_, err := runtime.RunString("discard-budget-origin.js", `
globalThis.__discardedJobEscaped = false;
const pending = new Promise(resolve => globalThis.__resolveDiscardBudget = resolve);
for (let i = 0; i < 1025; ++i) pending.then(() => { __discardedJobEscaped = true; });
0`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := jsengine.RunWithContext(loop, resolver, func(runtime jsengine.Runtime) error {
		_, err := runtime.RunString("discard-budget-resolver.js", `
__resolveDiscardBudget();
globalThis.__liveJobAfterDiscard = false;
Promise.resolve().then(() => { __liveJobAfterDiscard = true; }); 0`)
		return err
	}); err != nil {
		t.Fatalf("discarded jobs consumed the live resolver budget: %v", err)
	}
	requireJSGlobalFalse(t, loop, "__discardedJobEscaped")
	if err := jsengine.RunWithContext(loop, resolver, func(runtime jsengine.Runtime) error {
		value, err := runtime.RunString("discard-budget-live-job.js", "__liveJobAfterDiscard")
		if err == nil && !value.ToBoolean() {
			t.Error("live job was discarded with revoked-origin jobs")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
