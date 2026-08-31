# JavaScript value export contract

This document records the Phase 8 audit of `Value.Export()` after the native adapter was added. `Export()` remains a compatibility escape hatch; generic Core code uses `Object()` and `ExportPrimitive()`.

## Contract

`jsengine.Value.ExportPrimitive() (any, error)` is the engine-neutral conversion boundary.

- `bool`, `string`, and numeric JavaScript primitives are returned as Go scalar values. Numeric width follows the adapter (`int64`/`uint64` for native values; Goja and QuickJS retain their existing numeric export representation).
- JavaScript `undefined` and `null` both return `(nil, nil)`. Callers must use `Object()` first when an object must be distinguished from a nullish value.
- Objects, functions, and host references return an error wrapping `jsengine.ErrPrimitiveExportUnsupported`. No map, slice, Go pointer/interface, JSON string, or arbitrary object coercion crosses this boundary.
- A nil `Value` is handled by the caller as an absent result; implementations return `(nil, nil)` for a nil wrapped raw value where applicable.
- `Export()` is retained only for legacy compatibility and engine-owned values. It must not be used to decide whether a generic result is an object.

## Implementation capability

| Implementation | Primitive conversion | Objects/functions/host refs | Nullish result |
| --- | --- | --- | --- |
| `utils/jsengine/goja` | bool, string, Goja numeric scalar | deterministic unsupported error | `nil, nil` |
| `utils/jsengine/native` | bool, string, i64, u64, f64 through native conversion calls | deterministic unsupported error for object, host object, host function | `nil, nil` |
| `utils/jsengine/quickjs` | bool, string, number | deterministic unsupported error; this does not change QuickJS's legacy `Export` behavior | `nil, nil` |
| `dice.gojaEngineValue` | Same explicit primitive policy for the legacy Goja callback adapter | deterministic unsupported error | `nil, nil` |

The frozen C ABI is unchanged. There is no export opcode, JSON fallback, or object-to-Go conversion in the ABI.

## Callsite audit

The table covers every repository `.Export()` call found by repository search. Line numbers refer to the Phase 8 working tree; implementation line numbers can move without changing the classification.

| File and line/symbol | Value category required | Native-capable? | Migration or intentional rationale |
| --- | --- | --- | --- |
| `api/js.go:85`, QuickJS `jsExec` branch | API execution result | N/A for native; QuickJS-specific branch | Intentionally retained while QuickJS engine branching remains legacy-owned. Goja/API results use `exportJSAPIValue` below. The later QuickJS cutover must replace this legacy JSON-oriented path with the same explicit policy. |
| `api/js.go:exportJSAPIValue`, Goja `jsExec` branch | primitive API result | Yes | Migrated to `ExportPrimitive`; native/object results produce a diagnostic unsupported error rather than silently becoming `nil`. |
| `dice/ext.go:parseMessagePreprocessEngineValue` | string/nullish fields and object fields | Yes | Migrated: inspect `Object()` first, then call `ExportPrimitive` for scalar fields. Native objects are read with `Has`/`Get`. |
| `dice/im_session.go:parseJSSolveEngineResult` | solve result object and nullish result | Yes | Migrated: object fields are read through `Object()`; nullish is identified by `ExportPrimitive`. No generic `Export` type assertion remains. |
| `dice/im_session.go:resolveJSSolveValue` | `goja.Promise` | No | Intentional Goja-only use: function accepts raw `goja.Value` and must inspect promise state/then callbacks. |
| `dice/dice_jsvm_fs.go:jsFsBytesFrom` | string, byte slice, number array | No | Intentional Goja-only use: function accepts raw `goja.Value` and supports Goja's `[]byte`/`[]interface{}` conversion for the existing fs API. |
| `dice/js_engine_value.go:gojaEngineValue.Export` | legacy raw Goja export | No | Adapter implementation required by compatibility API. New generic code uses `ExportPrimitive`. |
| `utils/jsengine/goja/runtime.go:value.Export` | legacy raw Goja export | No | Adapter implementation required by compatibility API; primitive callers use `ExportPrimitive`. |
| `utils/jsengine/native/native_cgo.go:nativeValue.Export` | legacy scalar or native object wrapper | Yes for scalars; object wrapper only | Compatibility implementation. Native objects are deliberately returned as an adapter object from legacy `Export`; generic callers must use `Object()`. `ExportPrimitive` rejects the object instead. |
| `utils/jsengine/quickjs/runtime.go:value.Export` / `export` | legacy QuickJS scalar or JSON object projection | QuickJS only | Intentional QuickJS-specific compatibility behavior. Object JSON stringification is not part of `ExportPrimitive` or the C ABI and is not used by migrated generic callers. |
| `utils/jsengine/runtime_contract_test.go` (all `got = value.Export()` assertions) | compatibility scalar results | Engine-specific test coverage | Tests preserve the established `Export` compatibility contract while object behavior is tested via `Object()` and the new primitive tests. |
| `utils/jsengine/runtime_contract_test.go:TestQuickJSCallbackReturnsLiveValueOnOwnerLoop` | callback object's scalar property | Yes | Existing test-only legacy assertion; it verifies a live value and does not implement Core conversion. |
| `utils/jsengine/builtin/goja/provider_test.go` | Goja numeric result | No | Test-only compatibility assertion for the builtin provider. |
| `utils/jsengine/goja/runtime_test.go` | Goja numeric result | No | Test-only compatibility assertion for adapter behavior. |
| `utils/jsengine/quickjs/runtime_test.go` | QuickJS scalar and readiness values | No | Test-only QuickJS compatibility assertions. |
| `utils/jsengine/native/adapter_test.go` | native scalars, missing property, host function, retained value | Yes for scalar assertions | Test-only compatibility and lifecycle coverage. New `ExportPrimitive` assertions cover native scalar/object policy. Host-function assertions intentionally inspect native function implementation. |
| `dice/dice_jsvm_dangerous_expose_test.go:TestDangerousExpose` | Goja exposed map | No | Explicit dangerous Goja-only test of the opt-in exposure API; not a generic Core path. |
| `dice/js_host_api_test.go` | diagnostic value in test failure | No | Test-only diagnostic formatting; not a conversion decision. |
| `dice/js_quickjs_fs_test.go` | QuickJS diagnostic value | No | Test-only QuickJS-specific diagnostic formatting. |
| `utils/plugin/crypto/alg_helpers.go` | Goja string or object algorithm options | No | Function receives raw Goja values and then uses Goja `ToObject`; intentionally engine-specific. |
| `utils/plugin/crypto/*_test.go` | Goja Promise, ArrayBuffer, typed byte output | No | Explicit Goja Promise/ArrayBuffer/typed internal tests. These values are not engine-neutral primitives. |
| `utils/plugin/crypto/key_io.go` | Goja JWK map/object | No | Goja-only crypto implementation; object projection is deliberately local and not exposed through `jsengine.Value`. |
| `utils/plugin/crypto/runtime_helpers.go` | Goja arrays, ArrayBuffer, CryptoKey host handle | No | Goja-only plugin internals; direct `Export` is required for typed values and host handles, followed by explicit Goja object handling. |
| `utils/plugin/httpextra/fetch.go` | Goja private form-data host handle | No | Goja-only sealed plugin state. |
| `utils/plugin/httpextra/httpextra.go` | Goja private headers handle, string/bytes, ArrayBuffer | No | Goja-only plugin state and typed internal data. |
| `utils/plugin/httpextra/httpextra_test.go` | Goja Promise and ArrayBuffer | No | Goja-only typed integration tests. |
| `utils/plugin/websocket/websocket.go` | Goja protocol array | No | Goja-only websocket API; raw value is consumed as a Goja array. |

## Compatibility and API policy

Existing `Export()` callers are not silently reinterpreted. Goja Promise, ArrayBuffer, typed plugin values, host handles, dangerous exposure, and QuickJS branching remain in their engine-specific code paths. The generic solve and preprocess paths no longer treat `Export() == nil` as “not an object”.

The API execution endpoint supports primitive return values. When a Goja/native execution result is an object, function, or host reference, it returns the explicit error text from `ExportPrimitive` in the response's `err` field and leaves `ret` unset. It never JSON-stringifies or silently reports `nil`. QuickJS's existing branch is documented above and remains intentionally unchanged for this phase; later QuickJS cutover work owns its migration.

## Focused verification

- RED: `go test ./utils/jsengine/... ./dice -run 'TestExportPrimitive|TestParseEngineValuesReadsObjectWithoutLegacyExport|TestParseSolveEngineValueReadsObjectWithoutLegacyExport'` initially failed because `Value.ExportPrimitive` and `ErrPrimitiveExportUnsupported` did not exist. The same command also exposed unrelated pre-existing `dice` loop-manager compile errors in the Phase 7 working tree.
- GREEN: `go test ./utils/jsengine -run 'TestExportPrimitive' -v` passes Goja and QuickJS primitive/nullish and object/function rejection tests.
- GREEN: `go test ./utils/jsengine/...` passes. Native adapter tests compile and targeted adapter tests pass with skips when `SCARDICE_ECHO_RUNTIME` is unset.
