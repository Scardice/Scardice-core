# Phase 10 — Native QuickJS C++ runtime report

## Result

GREEN on Linux with a reproducible QuickJS-NG source checkout. The provider is a shared library built from `runtime-plugins/quickjs/quickjs_runtime.cpp` against the frozen runtime ABI v1 header. The native smoke test loads the produced `.so` with `dlopen`, queries the plugin, creates and starts a runtime, exercises the ABI, and stops/destroys it.

## TDD evidence

RED was established before the provider prerequisite was supplied:

```text
$ cmake -S runtime-plugins/quickjs -B /tmp/scardice-task10-red
CMake Error at CMakeLists.txt:6 (message):
  QUICKJS_ROOT must point to a pinned QuickJS-NG source tree
-- Configuring incomplete, errors occurred!
```

After adding the real smoke harness, the initial harness run also failed as expected on the existing implementation:

```text
$ ctest --test-dir /tmp/scardice-task10-build --output-on-failure
1/1 Test #1: scardice-runtime-quickjs-smoke ...***Failed
smoke failure: host callbacks (got -10, want 0)
0% tests passed, 1 tests failed out of 1
```

The failure identified missing host-object `this` metadata and loss of host callback status through a JavaScript exception. The provider was then corrected and the test rerun.

## Dependency provenance

The source was fetched without vendoring generated artifacts:

```text
git clone --depth 1 --branch v0.15.1 \
  https://github.com/quickjs-ng/quickjs.git /tmp/quickjs-ng-v0.15.1
QuickJS-NG commit: fd0a0210b7be00957751871e7e01b8291268fc29
```

The build requires `-DQUICKJS_ROOT=/absolute/or/relative/path/to/that/source/tree`; CMake canonicalizes it to an absolute path and fails clearly when `quickjs.h` is absent. The runtime ABI include directory is likewise canonicalized and checked before compilation.

## GREEN verification

Exact focused verification command:

```text
cmake -S runtime-plugins/quickjs -B /tmp/scardice-task10-build \
  -DQUICKJS_ROOT=/tmp/quickjs-ng-v0.15.1 \
  -DSCARDICE_QUICKJS_BUILD_TESTS=ON
cmake --build /tmp/scardice-task10-build -j2
ctest --test-dir /tmp/scardice-task10-build --output-on-failure
```

Observed result:

```text
1/1 Test #1: scardice-runtime-quickjs-smoke ...   Passed    0.00 sec
100% tests passed out of 1
```

The build emitted two upstream QuickJS-NG `-Wmaybe-uninitialized` warnings in `quickjs.c`; no provider compile error occurred. The frozen ABI layout was separately checked with:

```text
c++ -std=c++17 -Iruntimeabi/include -c runtimeabi/tests/layout.cc \
  -o /tmp/scardice-task10-layout.o
```

That command completed with no output or errors.

Export-surface check:

```text
$ nm -D --defined-only /tmp/scardice-task10-build/libscardice-runtime-quickjs.so
0000000000000000 A SCARDICE_RUNTIME
00000000000170a0 T scardice_runtime_query_v1@@SCARDICE_RUNTIME
```

The Linux linker version script and `--exclude-libs,ALL` keep QuickJS and C++ implementation symbols out of the dynamic export surface. Only `scardice_runtime_query_v1` is exported (the version node is linker metadata).

## Smoke coverage

- query negotiation, descriptor ABI/version/identity/capabilities, and all v1 API slots;
- real create/start/stop/destroy lifecycle;
- `1 + 2` evaluation and integer/string conversion through the caller-buffer protocol;
- object new/get/set/has;
- script, CommonJS, ESM, and extension entry loading;
- promise evaluation and bounded pending-job draining;
- integer host references for host objects and host functions;
- host property get/set/has/delete and `Object.keys` property-name preservation;
- host function `this` identity and callback arguments;
- host callback failure returning `SC_EHOST` with propagated last-error text;
- JavaScript exceptions and runtime last-error copy;
- retain/release, including multiple retains;
- wrong-thread operation rejection before QuickJS primitive allocation;
- calls rejected after stop.

The host callbacks in the harness are C ABI `noexcept` functions and use only integer opaque handles. No Go c-shared bridge, QuickJS-Go, JSON result emulation, fetch, or websocket implementation is involved.

## Changed task files

- `runtime-plugins/quickjs/CMakeLists.txt`
- `runtime-plugins/quickjs/quickjs_runtime.cpp`
- `runtime-plugins/quickjs/runtime.json`
- `runtime-plugins/quickjs/runtime-exports.map`
- `runtime-plugins/quickjs/testdata/smoke.cpp`
- `.superpowers/sdd/plan/task-10-report.md`

The existing Go test under `runtime-plugins/quickjs/test/provider_test.go` was not modified. Go/Dice sources and the frozen ABI were not modified for this phase.

## Limitations and later parity work

- `options_json` is validated as a borrowed ABI view but intentionally not interpreted by the provider; this avoids an ad-hoc JSON parser. QuickJS default memory/stack settings therefore apply in this phase.
- ESM module loading is implemented for entries and the in-memory loader, but there is no filesystem/package resolver or asynchronous module service.
- Timers, fetch, websocket, and other host services are intentionally outside this phase.
- The export allowlist is implemented and verified on Linux/ELF. Windows and Darwin builds were not run on this Linux host.
- The upstream QuickJS-NG warning noted above is outside task-owned source.
