# Phase 9 — Callback Dispatcher Unification

## Result

Callback entry points now cross one neutral `jsengine.Loop` boundary. `OnMessagePreprocessEngine` and `SolveEngine` are selected before legacy callbacks, run on the callback's captured generation, install and restore `Dice.JsCurrentPlugin`, consume returned values inside `Loop.Run`, and convert callback panics into logged errors. The loop manager exposes one active loop/generation lifecycle; `GetWebLoop` was removed and callers migrated.

## TDD evidence

### RED

First red test: `TestCallOnMessagePreprocessEngineSupportsNonJSProviderAndRestoresContext`.

Command:

```text
go test ./dice -run TestCallOnMessagePreprocessEngineSupportsNonJSProviderAndRestoresContext -count=1
```

Exact failure after fixing the test's struct-literal setup:

```text
WARNING: sonic/ast only supports (go1.17~1.26 and amd64 CPU) or (go1.20~1.26 and arm64 CPU), but your environment is not suitable and will fallback to encoding/json
--- FAIL: TestCallOnMessagePreprocessEngineSupportsNonJSProviderAndRestoresContext (0.00s)
    js_engine_value_test.go:151: decision = dice.messagePreprocessDecision{action:0, message:"", reason:""}
FAIL
FAIL    Scardice-core/dice    0.040s
FAIL
```

The failure was the pre-existing `!ext.IsJsExt` gate, before implementation changes.

### GREEN

Focused dispatcher tests:

```text
go test ./dice -run 'Test(CallOnMessagePreprocess|ParseJSSolveEngineResult|ParseMessagePreprocessEngineValue|ParseEngineValues|CommandSolve_|JsLoopManager)' -count=1
ok      Scardice-core/dice    0.062s
```

Error/panic behavior:

```text
go test ./dice -run 'TestCallOnMessagePreprocessEngine' -count=1
ok      Scardice-core/dice    0.043s
```

Legacy and lifecycle paths:

```text
go test ./dice -run 'TestCommandSolve_|TestJsLoopManagerStoresEngineLoopByVersion|TestJs.*(Init|QuickJS)|TestCallOnMessagePreprocess' -count=1
ok      Scardice-core/dice    0.220s
```

Relevant engine contracts:

```text
go test ./utils/jsengine/... -run 'Test' -count=1
ok      Scardice-core/utils/jsengine          0.030s
ok      Scardice-core/utils/jsengine/builtin/goja  0.004s
ok      Scardice-core/utils/jsengine/goja      0.004s
ok      Scardice-core/utils/jsengine/hostbridge 0.002s
ok      Scardice-core/utils/jsengine/native   0.004s
ok      Scardice-core/utils/jsengine/quickjs  0.020s
```

## Files changed

- `dice/dice.go`: one-loop manager snapshot API (`CurrentLoop`), generation mismatch behavior, same-loop replacement does not double-close, and removal of `GetWebLoop`.
- `dice/ext.go`: neutral preprocess dispatch, explicit legacy Goja compatibility branch, panic-to-error callback wrapper, and shared extension callback dispatch.
- `dice/im_session.go`: neutral solve context restoration, generation-aware dispatch, explicit `SolveRaw` compatibility fallback, and migration of non-command callbacks through `callWithJsCheck`.
- `dice/dice_jsvm.go`: script loading migrated from `GetWebLoop` to the manager snapshot.
- `dice/dice_jsvm_test.go`, `dice/forward_validation_test.go`: migrated loop access.
- `dice/js_engine_value_test.go`: non-JS-provider neutral preprocess, context restoration, callback error/panic behavior, and object-result coverage.
- `dice/im_session_command_solve_test.go`: SolveEngine provider/context coverage while retaining SolveRaw coverage.
- `dice/js_loop_manager_test.go`: stale generation and exactly-once replacement/clear close coverage.

`Scardice-ui/plan.md` and the pre-existing root `plan.md` worktree state were not changed.

## Compatibility policy

Neutral callbacks are authoritative whenever present. Legacy `goja.Value` fields remain only for the explicitly labeled compatibility branches:

- `ExtInfo.OnMessagePreprocess` is invoked only through the legacy Goja adapter when `IsJsExt` is true and `JsEnable` is enabled.
- `CmdItemInfo.SolveRaw` is invoked only through the legacy Goja adapter; the no-generation non-JS override uses the manager's current-loop snapshot solely because old command objects do not carry `JSLoopVersion`.
- Native/non-JS providers are never routed through `gojaengine.Raw` for neutral callbacks.

## Remaining engine-specific sites

These are intentional and outside the generic dispatcher cutover:

- `dice/ext.go`: legacy `OnMessagePreprocess` compatibility branch uses `gojaengine.Raw`.
- `dice/im_session.go`: legacy `SolveRaw` compatibility branch uses `gojaengine.Raw`.
- `dice/dice_jsvm_dangerous_expose.go`: explicitly engine-specific dangerous `seal.inst` exposure (Goja raw proxy versus QuickJS reflection proxy).
- `dice/dice_jsvm_fs.go`: legacy Goja fs promise implementation uses `eventloop.EventLoop.RunOnLoop` and raw Goja values.
- `utils/jsengine/goja/runtime.go`: adapter internals use Goja's `RunOnLoop` to implement neutral `Loop.Run`; this is not a dice generic dispatcher path.

No QuickJS C++/ABI/event-loop implementation was changed.

## Follow-up fixes

### RED

Added `TestJsScriptTaskRunWithoutActiveLoopReturnsWithoutPanic` before the task guard implementation.

```text
go test ./dice -run TestJsScriptTaskRunWithoutActiveLoopReturnsWithoutPanic -count=1
WARNING: sonic/ast only supports (go1.17~1.26 and amd64 CPU) or (go1.20~1.26 and arm64 CPU), but your environment is not suitable and will fallback to encoding/json
--- FAIL: TestJsScriptTaskRunWithoutActiveLoopReturnsWithoutPanic (0.00s)
    --- FAIL: TestJsScriptTaskRunWithoutActiveLoopReturnsWithoutPanic/nil_manager (0.00s)
        dice_jsvm_test.go:111: JsScriptTask.run panicked: runtime error: invalid memory address or nil pointer dereference
FAIL
FAIL    Scardice-core/dice    0.045s
FAIL
```

Added `TestCallOnMessagePreprocessEngineHonorsJsEnableForJSProvider` before adding the JS-provider gate.

```text
go test ./dice -run TestCallOnMessagePreprocessEngineHonorsJsEnableForJSProvider -count=1
WARNING: sonic/ast only supports (go1.17~1.26 and amd64 CPU) or (go1.20~1.26 and arm64 CPU), but your environment is not suitable and will fallback to encoding/json
--- FAIL: TestCallOnMessagePreprocessEngineHonorsJsEnableForJSProvider (0.00s)
    js_engine_value_test.go:226: disabled JS provider callback was invoked
FAIL
FAIL    Scardice-core/dice    0.039s
FAIL
```

### GREEN

```text
go test ./dice -run 'TestJsScriptTaskRunWithoutActiveLoopReturnsWithoutPanic' -count=1
ok      Scardice-core/dice    0.040s

go test ./dice -run 'TestCallOnMessagePreprocessEngine(HonorsJsEnableForJSProvider|SupportsNonJSProviderAndRestoresContext|ReportsCallbackErrorAndPanicAsNoop)' -count=1
ok      Scardice-core/dice    0.054s
```

Follow-up changes are included in commit `a16a4696`.
