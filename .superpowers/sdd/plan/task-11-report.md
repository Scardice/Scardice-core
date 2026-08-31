# Phase 11 — QuickJS host proxy parity report

## Scope and provenance

The same table-driven assertions live in `utils/jsengine/hostparity/parity.go` and are invoked by wrappers for legacy QuickJS-Go and the native provider. The suite covers struct reads/writes, deterministic `Object.keys`, maps, slices, methods/lower-camel names, nested pointer/map/slice mutation, variadic Go methods/functions, Go errors, callback assignment, missing/undefined, `jsbind`, `jsbindlock`, dangerous exposure/filtering, and read-only returned slices.

The native provider was built against `/tmp/quickjs-ng-v0.15.1`. The source tree contained `quickjs.h`; its Git revision was `fd0a0210b7be00957751871e7e01b8291268fc29`. No source tree was copied into the repository. The package used for tests was staged at `/tmp/scardice-quickjs-root/quickjs` with the built shared library and `runtime.json`.

## Matrix

| Contract | Legacy QuickJS-Go | Native QuickJS-NG |
| --- | ---: | ---: |
| Struct `obj.foo` read/write | PASS | PASS |
| `Object.keys(obj)` deterministic names | PASS | PASS |
| Map read/write/delete/missing | PASS | PASS |
| Slice index/assignment/length/push | PASS | PASS |
| Lower-camel methods and method state | PASS | PASS |
| Nested pointers/maps/slices | PASS | PASS |
| Variadic Go method and function | PASS | PASS |
| Go method/function errors | PASS | PASS |
| Callback field assignment | PASS | PASS |
| Reentrant callback host call | PASS (existing legacy behavior tests) | PASS (existing native provider test) |
| `jsbind` filtering | PASS | PASS |
| `jsbindlock` locking path | PASS | PASS |
| Dangerous exposure/filtering | PASS | PASS |
| Missing/undefined | PASS | PASS |
| Read-only returned slice | PASS | PASS |

Numeric assertions intentionally compare the numeric value across engines because QuickJS-Go exports JavaScript numbers as `float64` while the native adapter preserves integer primitives as `int64` where available. This is an engine representation difference, not an observable JavaScript value difference.

## Commands and output

Build the pinned provider:

```text
cmake -S runtime-plugins/quickjs -B /tmp/scardice-quickjs-build -DQUICKJS_ROOT=/tmp/quickjs-ng-v0.15.1 -DSCARDICE_QUICKJS_BUILD_TESTS=ON
cmake --build /tmp/scardice-quickjs-build -j2
```

Output: build completed successfully; target `scardice-runtime-quickjs` reached 51% and all configured targets reached 100%. QuickJS-NG emitted two existing `-Wmaybe-uninitialized` warnings in `quickjs.c` (`buf2`); no provider build error occurred.

Legacy parity:

```text
go test ./utils/jsengine/quickjs -run TestQuickJSHostProxyParityContract -count=1
ok   Scardice-core/utils/jsengine/quickjs  0.019s
```

Native parity with explicit package environment:

```text
SCARDICE_QUICKJS_PACKAGE=/tmp/scardice-quickjs-root go test ./runtime-plugins/quickjs/test -run TestNativeQuickJSHostProxyParityContract -count=1
ok   Scardice-core/runtime-plugins/quickjs/test  0.006s
```

Native provider tests with the same explicit environment:

```text
SCARDICE_QUICKJS_PACKAGE=/tmp/scardice-quickjs-root go test ./runtime-plugins/quickjs/test -count=1
ok   Scardice-core/runtime-plugins/quickjs/test  0.023s
```

Read-only HostBridge regression:

```text
go test ./utils/jsengine/hostbridge -run TestHostBridgeReadOnlySliceRejectsWrites -count=1
ok   Scardice-core/utils/jsengine/hostbridge  0.002s
```

No runtime skip was taken: both explicit runtime environments were available. No formatter, linter, or project-wide suite was run.

## Fixes and owned files

- Added the shared parity table and both runtime wrappers:
  - `utils/jsengine/hostparity/parity.go`
  - `utils/jsengine/quickjs/host_parity_test.go`
  - `runtime-plugins/quickjs/test/host_parity_test.go`
- Added native `ExposeDangerous` adapter support and callback trampolines using the existing `function_call`/retain/release ABI slots; no ABI header or dispatcher change was needed.
- Fixed native-relevant HostBridge conversion: nil Go function fields map to undefined, variadic calls select the element type without indexing past the function signature, and read-only slices return the existing `slice is read-only` error. The focused HostBridge regression now passes.

## Remaining differences / concerns

- QuickJS-Go and native providers expose different host-side primitive representation through `ExportPrimitive` (`float64` versus integer-preserving values); the suite compares values, not Go representation types.
- Reentrant callback coverage remains represented by each provider's existing focused test because invoking a QuickJS-Go callback from a Go host method while the event loop task is active is not engine-neutral. No callback dispatcher, event-loop, fetch, or websocket code was changed.
- Build warnings originate in the pinned QuickJS-NG source and are not provider warnings.
