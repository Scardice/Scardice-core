# Task 8 report: Export contract audit

## Scope

Audited repository `.Export()` callsites from Phase 7 baseline `688955b1`. Added the smallest explicit engine-neutral conversion contract, migrated generic solve/preprocess handling, and documented intentional engine-specific compatibility uses. `Scardice-ui` and the existing root `plan.md` were not modified.

## TDD evidence

### RED

Command:

```text
go test ./utils/jsengine/... ./dice -run 'TestExportPrimitive|TestParseEngineValuesReadsObjectWithoutLegacyExport|TestParseSolveEngineValueReadsObjectWithoutLegacyExport'
```

Observed output before implementing `ExportPrimitive`:

```text
# Scardice-core/utils/jsengine_test [Scardice-core/utils/jsengine.test]
utils/jsengine/export_contract_test.go:49:23: value.ExportPrimitive undefined (type jsengine.Value has no field or method ExportPrimitive)
utils/jsengine/export_contract_test.go:93:25: value.ExportPrimitive undefined (type jsengine.Value has no field or method ExportPrimitive)
utils/jsengine/export_contract_test.go:93:69: undefined: jsengine.ErrPrimitiveExportUnsupported
FAIL Scardice-core/utils/jsengine [build failed]
ok Scardice-core/utils/jsengine/builtin/goja 0.003s [no tests to run]
ok Scardice-core/utils/jsengine/goja 0.003s [no tests to run]
ok Scardice-core/utils/jsengine/hostbridge 0.003s [no tests to run]
ok Scardice-core/utils/jsengine/native 0.003s [no tests to run]
ok Scardice-core/utils/jsengine/quickjs 0.003s [no tests to run]
# Scardice-core/dice [Scardice-core/dice.test]
dice/im_session.go:2986:39: s.Parent.ExtLoopManager.GetEngineLoop undefined (type *JsLoopManager has no field or method GetEngineLoop)
dice/im_session.go:3140:16: cannot use 1st function result (value of interface type jsengine.Loop) as *"github.com/dop251/goja_nodejs/eventloop".EventLoop value in multiple assignment
dice/im_session.go:3145:13: cannot use s.Parent.ExtLoopManager.GetWebLoop() (value of interface type jsengine.Loop) as *"github.com/dop251/goja_nodejs/eventloop".EventLoop value in assignment
dice/js_quickjs.go:109:32: d.ExtLoopManager.SetEngineLoop undefined (type *JsLoopManager has no field or method SetEngineLoop)
dice/js_quickjs.go:142:20: d.ExtLoopManager.SetEngineLoop undefined (type *JsLoopManager has no field or method SetEngineLoop)
dice/js_quickjs.go:147:20: d.ExtLoopManager.SetEngineLoop undefined (type *JsLoopManager has no field or method SetEngineLoop)
dice/dice_jsvm_test.go:66:13: loop.RunOnLoop undefined (type jsengine.Loop has no field or method RunOnLoop)
dice/dice_jsvm_test.go:104:21: d.ExtLoopManager.SetEngineLoop undefined (type *JsLoopManager has no field or method SetEngineLoop)
dice/dice_jsvm_test.go:116:32: d.ExtLoopManager.GetEngineLoop undefined (type *JsLoopManager has no field or method GetEngineLoop)
dice/dice_jsvm_test.go:179:21: d.ExtLoopManager.SetEngineLoop undefined (type *JsLoopManager has no field or method SetEngineLoop)
dice/js_engine_value_test.go:40:20: too many errors
FAIL Scardice-core/dice [build failed]
```

The `dice` errors were stale loop-manager callers in the shared pre-implementation tree; the Export RED itself is the missing contract symbols above.

### GREEN

Command:

```text
go test ./utils/jsengine -run 'TestExportPrimitive' -v
```

Observed output:

```text
=== RUN   TestExportPrimitiveSupportsPrimitiveValuesAndNullishValues
=== RUN   TestExportPrimitiveSupportsPrimitiveValuesAndNullishValues/goja
=== RUN   TestExportPrimitiveSupportsPrimitiveValuesAndNullishValues/quickjs
--- PASS: TestExportPrimitiveSupportsPrimitiveValuesAndNullishValues (goja, quickjs)
    --- PASS: TestExportPrimitiveSupportsPrimitiveValuesAndNullishValues/goja
    --- PASS: TestExportPrimitiveSupportsPrimitiveValuesAndNullishValues/quickjs
=== RUN   TestExportPrimitiveRejectsObjectsAndFunctions
=== RUN   TestExportPrimitiveRejectsObjectsAndFunctions/goja
=== RUN   TestExportPrimitiveRejectsObjectsAndFunctions/quickjs
--- PASS: TestExportPrimitiveRejectsObjectsAndFunctions (goja, quickjs)
    --- PASS: TestExportPrimitiveRejectsObjectsAndFunctions/goja
    --- PASS: TestExportPrimitiveRejectsObjectsAndFunctions/quickjs
PASS
ok Scardice-core/utils/jsengine
```

Command:

```text
go test ./utils/jsengine/native -run 'TestNativeAdapterEchoContract|TestNativeAdapterRetainedValueAndClose' -v
```

Observed output:

```text
=== RUN   TestNativeAdapterEchoContract
    adapter_test.go:51: SCARDICE_ECHO_RUNTIME is not set
--- SKIP: TestNativeAdapterEchoContract
=== RUN   TestNativeAdapterRetainedValueAndClose
    adapter_test.go:149: SCARDICE_ECHO_RUNTIME is not set
--- SKIP: TestNativeAdapterRetainedValueAndClose
PASS
ok Scardice-core/utils/jsengine/native
```

Command:

```text
go test ./dice -run 'TestParseEngineValuesReadsObjectWithoutLegacyExport|TestParseSolveEngineValueReadsObjectWithoutLegacyExport|TestParseJSSolveEngineResult|TestParseMessagePreprocessEngineValue' -count=1 -v
```

Observed output:

```text
go test: 1 packages ok
```

Command:

```text
go test ./api -run TestExportJSAPIValueRejectsObjects -count=1 -v
```

Observed output:

```text
WARNING: sonic/ast only supports (go1.17~1.26 and amd64 CPU) or (go1.20~1.26 and arm64 CPU), but your environment is not suitable and will fallback to encoding/json
=== RUN   TestExportJSAPIValueRejectsObjects
--- PASS: TestExportJSAPIValueRejectsObjects
PASS
ok Scardice-core/api
```

Final focused package proof:

```text
go test ./utils/jsengine/...
ok Scardice-core/utils/jsengine 0.034s
ok Scardice-core/utils/jsengine/builtin/goja 0.004s
ok Scardice-core/utils/jsengine/goja 0.003s
ok Scardice-core/utils/jsengine/hostbridge 0.003s
ok Scardice-core/utils/jsengine/native 0.003s
ok Scardice-core/utils/jsengine/quickjs 0.017s
```

No formatter, linter, or project-wide suite was run.

## Changed files

- `utils/jsengine/runtime.go`: added `ErrPrimitiveExportUnsupported` and `Value.ExportPrimitive` contract.
- `utils/jsengine/export_contract_test.go`: primitive/nullish support and object/function rejection tests for Goja and QuickJS.
- `utils/jsengine/goja/runtime.go`: Goja primitive conversion.
- `utils/jsengine/quickjs/runtime.go`: explicit primitive conversion while retaining legacy QuickJS `Export` behavior.
- `utils/jsengine/native/native_cgo.go`: native scalar conversion and deterministic rejection for object/host object/host function.
- `utils/jsengine/native/adapter_test.go`: native scalar/object contract assertions (fixture-gated).
- `dice/js_engine_value.go`: contract implementation for the legacy Goja callback adapter.
- `dice/ext.go`: generic preprocess migration to `Object` + `ExportPrimitive`.
- `dice/im_session.go`: generic solve migration to `Object` + explicit nullish conversion.
- `dice/js_engine_value_test.go`: fake engine-object regression tests proving object handling does not depend on legacy `Export()==nil`.
- `api/js.go`: engine-neutral loop execution and explicit Goja primitive API policy; QuickJS branch retains its legacy Export behavior.
- `api/js_test.go`: API helper rejection test for object results and loop-manager cleanup migration.
- `docs/runtime-abi/export-contract.md`: complete callsite classification, capability matrix, and compatibility/API policy.
- `.superpowers/sdd/plan/task-8-report.md`: this report.

## Commit

Task-scoped commit: `c8dc2d8f` (`Define explicit JavaScript export contract`). It excludes `Scardice-ui` and root `plan.md`.

## Concerns

1. `SCARDICE_ECHO_RUNTIME` was unavailable, so native runtime behavior was compile-tested and the new native assertions were skipped rather than exercised against a real provider.
2. The initial RED exposed stale loop-manager callers; the focused dice and API tests pass after those task-tree callers were migrated to `jsengine.Loop`/`GetWebLoop`/`SetLoop`.
3. QuickJS's old `Export` implementation still JSON-stringifies object values for its intentionally retained engine-specific branch. `ExportPrimitive` never does this; the later QuickJS cutover owns migration of that branch.
