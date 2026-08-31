# Phase 13 — Native QuickJS event loop

## Scope

Completed and validated the native QuickJS-NG event loop without changing ABI v1, Go code, dispatcher behavior, fetch, or websocket code. The provider now installs the explicit `setTimeout`, `clearTimeout`, and `queueMicrotask` API, pumps Promise/QuickJS jobs after script, module, CommonJS, extension, and function-call entries, and executes due timers on the provider owner thread.

The timer queue uses stable positive handles bounded to `INT64_MAX`, cancellation by handle, and deterministic ordering by deadline followed by handle allocation order. The event pump has a 1024-step bound and reports `SC_ETIMEOUT` with a convergence diagnostic when jobs or due callbacks do not converge. Exact-boundary convergence is accepted when the queue is empty after the final permitted job/callback.

Shutdown marks the runtime stopping before canceling every owned timer. Public event APIs reject work while stopping, pending jobs are not executed by `stop`, and context/runtime teardown frees the remaining QuickJS job queue. This prevents callbacks after stop or destruction while preserving the existing worker-thread affinity and reentrant host callback path.

## RED

The focused smoke test was extended first with the event-loop contract and the descriptor expectation for `SC_CAP_TIMERS`. Before the implementation/capability corrections, the pinned provider build succeeded but the smoke test failed at the expected capability assertion:

```text
$ ctest --test-dir /tmp/scardice-task13-build --output-on-failure -R scardice-runtime-quickjs-smoke
Test project /tmp/scardice-task13-build
    Start 1: scardice-runtime-quickjs-smoke
1/1 Test #1: scardice-runtime-quickjs-smoke ...***Failed    0.00 sec
smoke failure: descriptor identity and capabilities
0% tests passed, 1 tests failed out of 1
The following tests FAILED:
  1 - scardice-runtime-quickjs-smoke
Errors while running CTest
```

The failure was the intended red signal: the implementation exposed timers but the descriptor and manifest still advertised capability mask `367` (no timers), and the test had not yet reached the event behavior assertions.

## GREEN

Implemented the provider-owned event loop in `runtime-plugins/quickjs/quickjs_runtime.cpp` and aligned `runtime-plugins/quickjs/runtime.json` and the native smoke test. The descriptor/manifest capability mask is now exactly `383`:

```text
SC_CAP_SCRIPT | SC_CAP_COMMONJS | SC_CAP_ESM | SC_CAP_PROMISE |
SC_CAP_TIMERS | SC_CAP_HOST_OBJECT | SC_CAP_HOST_FUNCTION |
SC_CAP_SOURCE_LOCATION
```

`SC_CAP_ASYNC_HOST_SERVICE` is intentionally absent. The C++ smoke assertions cover:

- Promise reaction before `queueMicrotask`, then zero-delay timer execution.
- Stable, distinct timer handles and `clearTimeout` cancellation.
- Due timers pumped on a later command, ordered by deadline rather than insertion order.
- Timer callback exception propagation and `last_error_copy` text.
- Microtask callback exception propagation and `last_error_copy` text.
- A recursive microtask chain returning bounded `SC_ETIMEOUT` with a convergence diagnostic.
- Stop aborting pending jobs and canceling a timer that would mutate the host after stop/shutdown.
- Calls rejected after stop, existing host callbacks, thread affinity, entry kinds, and Promise behavior.

## Provenance

- QuickJS-NG source: `/tmp/quickjs-ng-v0.15.1`.
- Provider source: `runtime-plugins/quickjs/quickjs_runtime.cpp`.
- Provider metadata: `runtime-plugins/quickjs/runtime.json`.
- Focused native test: `runtime-plugins/quickjs/testdata/smoke.cpp`.
- CMake build directory: `/tmp/scardice-task13-build`.
- Explicit native package root used by Go discovery: `/tmp/scardice-task13-runtimes`, containing the installed package under `quickjs/`.
- Existing uncommitted `runtime-plugins/quickjs/test/provider_test.go`, `runtime-plugins/quickjs/test/parity_test.go`, `plan.md`, and `Scardice-ui` changes were preserved; no Go or ABI files were edited.

## Exact output

### Pinned provider build and CTest

```text
$ cmake -S runtime-plugins/quickjs -B /tmp/scardice-task13-build -DQUICKJS_ROOT=/tmp/quickjs-ng-v0.15.1 -DSCARDICE_QUICKJS_BUILD_TESTS=ON
$ cmake --build /tmp/scardice-task13-build -j2
[100%] Built target scardice-runtime-quickjs

$ ctest --test-dir /tmp/scardice-task13-build --output-on-failure -R scardice-runtime-quickjs-smoke
Test project /tmp/scardice-task13-build
    Start 1: scardice-runtime-quickjs-smoke
1/1 Test #1: scardice-runtime-quickjs-smoke ...   Passed    0.04 sec
100% tests passed out of 1
Total Test time (real) =   0.04 sec
```

### Focused native provider, entry, reentrant, and parity tests

```text
$ SCARDICE_QUICKJS_PACKAGE=/tmp/scardice-task13-runtimes go test ./runtime-plugins/quickjs/test -run 'TestQuickJSProvider(EventLoop|EntryKinds|ReentrantCallback)$|TestNativeQuickJSMatchesLegacyFixtures$' -count=1 -timeout=30s -v
=== RUN   TestNativeQuickJSMatchesLegacyFixtures
=== RUN   TestNativeQuickJSMatchesLegacyFixtures/script
=== RUN   TestNativeQuickJSMatchesLegacyFixtures/promise
=== RUN   TestNativeQuickJSMatchesLegacyFixtures/commonjs
=== RUN   TestNativeQuickJSMatchesLegacyFixtures/esm
--- PASS: TestNativeQuickJSMatchesLegacyFixtures (0.01s)
    --- PASS: TestNativeQuickJSMatchesLegacyFixtures/script (0.00s)
    --- PASS: TestNativeQuickJSMatchesLegacyFixtures/promise (0.00s)
    --- PASS: TestNativeQuickJSMatchesLegacyFixtures/commonjs (0.00s)
    --- PASS: TestNativeQuickJSMatchesLegacyFixtures/esm (0.00s)
=== RUN   TestQuickJSProviderReentrantCallback
--- PASS: TestQuickJSProviderReentrantCallback (0.00s)
=== RUN   TestQuickJSProviderEventLoop
--- PASS: TestQuickJSProviderEventLoop (0.01s)
=== RUN   TestQuickJSProviderEntryKinds
--- PASS: TestQuickJSProviderEntryKinds (0.00s)
PASS
ok  	Scardice-core/runtime-plugins/quickjs/test	0.021s
```

### Focused race run

```text
$ SCARDICE_QUICKJS_PACKAGE=/tmp/scardice-task13-runtimes go test -race ./runtime-plugins/quickjs/test -run 'TestQuickJSProvider(EventLoop|EntryKinds|ReentrantCallback)$|TestNativeQuickJSMatchesLegacyFixtures$' -count=1 -timeout=30s -v
PASS
ok  	Scardice-core/runtime-plugins/quickjs/test	1.035s
```

### CTest watchdog

```text
$ timeout 5s ctest --test-dir /tmp/scardice-task13-build --output-on-failure -R scardice-runtime-quickjs-smoke
1/1 Test #1: scardice-runtime-quickjs-smoke ...   Passed    0.04 sec
100% tests passed out of 1
```

No formatter, linter, or project-wide test suite was run.

## Limitations and explicit ABI-v1 decision

ABI v1 has no host-to-runtime asynchronous completion submission operation or completion-token type. A provider-owned completion queue would therefore have no honest host/runtime producer contract. This provider does **not** advertise `SC_CAP_ASYNC_HOST_SERVICE`, does not fabricate async completion support, and documents the limitation here through the phase report and exact capability mask.

Timers are provider-owned and deterministic but are pumped synchronously after a runtime command; there is no background timer thread or autonomous callback delivery. Callers must issue another runtime operation after a delay for due timers to run. During shutdown, the public QuickJS job queue has no discard-only API; `stop` prevents all further pumping and context/runtime destruction then aborts/frees queued jobs without executing them.
