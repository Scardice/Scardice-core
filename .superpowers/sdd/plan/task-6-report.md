# Phase 6 HostBridge report

## TDD evidence

- RED command: `go test ./utils/jsengine/hostbridge -count=1`
- RED result: failed at compilation because the new contract (`Value`, `NewSession`, and value constructors) did not exist yet. This established the focused tests were exercising the missing HostBridge implementation.
- GREEN command: `go test ./utils/jsengine/hostbridge -count=1`
- GREEN result: `ok Scardice-core/utils/jsengine/hostbridge 0.003s`

## Delivered files

- `utils/jsengine/hostbridge/registry.go`: fixed-width `HostRef`, `HostFuncRef`, callback/value kinds, mutex-protected session registry, identity reuse, generation tracking, deterministic teardown, and explicit runtime codec seam.
- `utils/jsengine/hostbridge/bridge.go`: reflection bridge for tagged/dangerous struct fields, `jsbindlock`, lower-camel methods, pointer/copy semantics, map and slice operations, function calls, explicit codec callback trampolines, panic/error handling, and diagnostics.
- `utils/jsengine/hostbridge/hostbridge_test.go`: focused behavior tests for all Phase 6 required cases, including a real callback codec/runtime function and stale generation rejection.

## Concerns

- HostBridge is intentionally engine-neutral and is not wired into QuickJS, Goja, the native loader, or the frozen ABI in this phase. A later adapter must translate runtime values to/from `Value` and implement `RuntimeValueCodec` without `Export`/JSON shortcuts.
- `RuntimeValueCodec` is an explicit Go adapter seam; callback invocation remains owned by the later runtime adapter and must enforce its own runtime-thread/realm rules.
- Teardown closes a session permanently; callers must create a new session for a new runtime generation.

## Fix TDD evidence

- RED command: `go test ./utils/jsengine/hostbridge -count=1`
- RED result: failed first on the new uint contract (`KindUint`/`Value.Uint` absent), then on the new callable-handle behavior (method/slice property values were zero markers), before the implementation changes.
- GREEN command: `go test ./utils/jsengine/hostbridge -count=1`
- GREEN result: `ok Scardice-core/utils/jsengine/hostbridge 0.002s`
- Fix files: `utils/jsengine/hostbridge/registry.go`, `utils/jsengine/hostbridge/bridge.go`, `utils/jsengine/hostbridge/hostbridge_test.go`.

## Fix concerns

- Method and `slice.push` properties now allocate session-scoped non-zero `HostFuncRef` operation entries carrying owner/operation metadata; adapters must call `CallFunctionWithCodec` rather than infer ownership from a zero marker.
- `Value` now distinguishes signed `int64`, unsigned `uint64`, and `float64`; adapters must preserve these explicit cases when encoding runtime values.

## Commit
Implementation commits: `fe37e0c9` (`feat: add engine-neutral host bridge`), `f2421730` (`fix: return undefined for missing host properties`), `d47d5e6c` (`fix: expose callable host operation handles`).
