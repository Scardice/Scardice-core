# Task 14 QuickJS parity report

## Corpus and runner

The black-box corpus lives in `runtime-plugins/quickjs/test/testdata/corpus/` and is loaded by `runtime-plugins/quickjs/test/corpus_test.go`. Each JSON fixture contains named entries (`script`, `commonjs`, `esm`, or `extension`), identical source, and a JavaScript observer. The runner opens a fresh legacy QuickJS-Go loop and a fresh native provider loop for every fixture, binds the same minimal host when requested, and logs an old/new normalized matrix.

Fixtures:

- `script.json`: script evaluation and observable global state.
- `commonjs-cache.json`: CommonJS dependency evaluation once, object identity, and cache state.
- `esm.json`: ESM evaluation and exported-value side effect.
- `promise-order.json`: synchronous, Promise, and `queueMicrotask` order.
- `timers.json`: zero-delay order, cancellation, delayed execution, and an explicit post-delay pump.
- `seal-extension.json`: minimal `seal.version`, extension registration, callback dispatch, and host event order through `Bind`/HostBridge.
- `error-stack.json`: thrown JavaScript error category, message, filename, and stack-shaped source location.
- `resource-boundary.json`: explicit capability-gated resource fixture; neither descriptor advertises resource-limit support, so it reports `unsupported` rather than silently skipping.

## Normalization policy

The comparison includes the observer's primitive result, success/error status, deterministic error category, normalized error message, stack presence, source filename presence, and HostBridge call/event state. It intentionally does not compare raw error text, native library paths, pointer-backed values, engine object representations, or stack indentation/wrapping. Error categories are `javascript`, `host`, and `timeout`; engine-specific operation prefixes are discarded. A fixture fails on any remaining observable mismatch.

The error fixture supplies a source-location line in the thrown error message because the legacy QuickJS-Go descriptor does not advertise `CapabilitySourceLocation`; this keeps the corpus honest about the currently shared contract. The runner still verifies that both providers preserve that filename and stack-shaped line while normalizing the wrapper text.

## Red/green evidence

Pinned native build:

```text
cmake -S runtime-plugins/quickjs -B /tmp/scardice-quickjs-build -DQUICKJS_ROOT=/tmp/quickjs-ng-v0.15.1 -DSCARDICE_QUICKJS_BUILD_TESTS=ON
cmake --build /tmp/scardice-quickjs-build -j2
ctest --test-dir /tmp/scardice-quickjs-build --output-on-failure
1/1 Test #1: scardice-runtime-quickjs-smoke ... Passed
100% tests passed out of 1
```

The first corpus run failed as intended on the observable CommonJS cache divergence:

```text
commonjs-module-cache legacy={same:true loads:1} native={same:false loads:3}
```

It also exposed that the delay fixture needed the same explicit pump boundary as the existing provider contract test. The native implementation was fixed only for the supported CommonJS module-cache contract by retaining cached exports for the lifetime of a runtime and releasing them during teardown.

Final focused command:

```text
SCARDICE_QUICKJS_PACKAGE=/tmp/scardice-quickjs-package go test -v ./runtime-plugins/quickjs/test -run TestQuickJSBlackBoxCorpusParity -count=1
```

Final result:

```text
commonjs-module-cache       old/new {same:true,loads:1,value:dep}
esm-module-load             old/new {answer:42,type:number}
promise-microtask-order     old/new [sync,promise,microtask]
resource-boundary-capability old/new unsupported (resource-limits not advertised; old capabilities=127, new=383)
script-evaluation            old/new {answer:42,trace:[script]}
seal-version-extension-callback old/new {version:14.0.0,registered:true,callback:callback:event}; host calls=1; events=register,dispatch:start,dispatch:end
thrown-error-source-location old/new javascript/parity boom; stack present; filename=errors/source.js
 timer-order-cancellation-delay old/new [zero,delayed]
--- PASS: TestQuickJSBlackBoxCorpusParity
PASS
ok   Scardice-core/runtime-plugins/quickjs/test 0.073s
```

Native capability-gated behavior without a package is explicit:

```text
env -u SCARDICE_QUICKJS_PACKAGE go test -v ./runtime-plugins/quickjs/test -run TestQuickJSBlackBoxCorpusParity -count=1
--- SKIP: TestQuickJSBlackBoxCorpusParity
SCARDICE_QUICKJS_PACKAGE is not set; native parity provider is unavailable
```

## Divergences and fixes

- Native CommonJS `require` evaluated a module on every call. Added a per-runtime native cache keyed by module filename, duplicated cached JS values for callers, and released cache values before context teardown. The corpus now observes `same:true` and `loads:1` on both providers.
- The timer fixture initially observed only the zero-delay callback on native because the primitive observer result was serialized before a later callback could mutate the array. The corpus now models the existing contract explicitly: wait, execute a no-op pump, then observe. Both providers report `["zero","delayed"]`.
- Extension host parity uses an ESM entry with the minimal `seal` host surface. This matches the legacy QuickJS-Go module-loading contract while testing version, registration, callback dispatch, and event order; no broad console, crypto, fetch, HTTP, websocket, filesystem, or process service was added.

## Limitations and concerns

- Neither provider advertises a resource-limit capability in its descriptor, so resource options are reported as `unsupported`; no resource option is forwarded silently.
- Automatic engine-generated stack formatting is not treated as a shared contract because legacy QuickJS-Go currently omits `CapabilitySourceLocation`. The error fixture verifies shared source-location data embedded in the thrown error and normalizes wrapper/formatting differences.
- The complete package test command currently remains blocked by the pre-existing uncommitted event-loop test panic in `reentrant_callbacks_test.go` (`reflect: function created by MakeFunc using closure returned zero Value`). That file and the uncommitted provider/parity event-loop tests were preserved unchanged. The focused corpus and pinned native CTest pass independently.
- No ABI or dispatcher changes were made.
