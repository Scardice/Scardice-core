# Task 4 report — native loader

## Scope

Implemented only the lazy native loader/provider shell under `utils/jsengine/native/` and focused tests. The frozen ABI header, Phase 3 fixture, Dice, QuickJS, HostBridge, `Scardice-ui`, and `plan.md` were not modified.

## TDD red

Tests were written before the loader implementation. The first focused command failed at package compilation because the requested discovery and error API did not exist:

```text
go test ./utils/jsengine/native -run 'TestDiscover|TestMissingLibrary' -count=1

utils/jsengine/native/loader_test.go:21:21: undefined: Discover
utils/jsengine/native/loader_test.go:46:12: undefined: Discover
utils/jsengine/native/loader_test.go:47:21: undefined: ErrUnsupportedArchitecture
utils/jsengine/native/loader_test.go:53:15: undefined: Candidate
utils/jsengine/native/loader_test.go:53:90: undefined: Manifest
utils/jsengine/native/loader_test.go:55:21: undefined: ErrMissingLibrary
FAIL
```

## TDD green

The Phase 3 echo fixture was built first:

```text
cmake -S runtimeabi/testdata/echo-runtime -B /tmp/scardice-echo-phase4 && cmake --build /tmp/scardice-echo-phase4
-- Build files have been written to: /tmp/scardice-echo-phase4
[100%] Built target echo_runtime_harness
```

Focused native tests, including manifest discovery, unsupported architecture, missing library, missing query symbol, builtin/candidate separation, identity mismatch, valid echo descriptor, create/start/stop/destroy, and resident-library behavior:

```text
SCARDICE_ECHO_RUNTIME=/tmp/scardice-echo-phase4/libecho_runtime.so go test ./utils/jsengine/native -count=1
ok   Scardice-core/utils/jsengine/native 0.003s
```

No-cgo fallback focused check:

```text
CGO_ENABLED=0 go test ./utils/jsengine/native -run 'TestDiscover|TestMissingLibrary' -count=1
ok   Scardice-core/utils/jsengine/native 0.003s
```

## Implementation

- `bridge.h` / `bridge.c`: C-owned fixed-width library identity, query/create/lifecycle wrappers, vtable/descriptor/API size validation, status-to-diagnostic bridge, and no-unload resident semantics.
- `loader_unix.c`: `dlopen(path, RTLD_NOW | RTLD_LOCAL)` and `dlsym("scardice_runtime_query_v1")`; no `dlclose`.
- `loader_windows.c`: UTF-8-to-wide absolute-path loading through `LoadLibraryExW` with restricted search flags and `GetProcAddress`; no `FreeLibrary`.
- `loader.go`: schema-1 manifest parsing, immediate `runtimes/*/runtime.json` discovery only, architecture selection, package-contained path validation, lazy candidates, and registry metadata registration without replacing builtins.
- `errors.go`: stable `errors.Is` categories for loader, ABI, manifest/descriptor, vtable/size, and create failures.
- `native_cgo.go`: C-only function-pointer invocation, descriptor copying into engine-neutral values, provider shell, create/start/stop/destroy lifecycle, and explicit diagnostics.
- `native_nocgo.go`: metadata remains available while native use reports `ErrNativeUnavailable` (and missing paths retain `ErrMissingLibrary`).
- `loader_test.go`: focused behavior tests.

## Commits

- Baseline: `3ff0fa42b3a76cf8727f9680943c53418b2b4afe`
- Task implementation commit: `41052437` (`feat(jsengine): add lazy native runtime loader`)

## Concerns

The provider shell intentionally returns `ErrNativeUnavailable` from `Loop.Run`; value/host adapter behavior belongs to later phases. Malformed ABI fixtures beyond the Phase 3 echo library are covered by validation branches and should be expanded only with dedicated fixture ownership in a later focused test phase. Native plugins are trusted in-process code and remain resident until process exit by design.
