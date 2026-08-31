# Task 3 report — fake C runtime

## TDD red

The harness assertions were written before `echo_runtime.c` existed. Configure and build succeeded, while the integration test failed because the provider shared library was absent:

```text
cmake -S runtimeabi/testdata/echo-runtime -B /tmp/scardice-echo-red
cmake --build /tmp/scardice-echo-red
ctest --test-dir /tmp/scardice-echo-red --output-on-failure
```

Relevant red output:

```text
1/1 Test #1: echo_runtime_integration .........***Failed
FAIL: provider shared library loads (line 102)
0% tests passed, 1 tests failed out of 1
```

## TDD green

After the minimal provider was added:

```text
cmake -S runtimeabi/testdata/echo-runtime -B /tmp/scardice-echo-green
cmake --build /tmp/scardice-echo-green
ctest --test-dir /tmp/scardice-echo-green --output-on-failure
```

The final focused run passed:

```text
1/1 Test #1: echo_runtime_integration .........   Passed
100% tests passed out of 1
```

`nm -D --defined-only /tmp/scardice-echo-green/libecho_runtime.so` confirmed the only exported symbol is `scardice_runtime_query_v1`.

## Changed files

- `runtimeabi/testdata/echo-runtime/CMakeLists.txt` — shared provider, C harness, and CTest wiring.
- `runtimeabi/testdata/echo-runtime/echo_runtime.c` — static v1 descriptor/API, opaque value table with refcounts, lifecycle, eval, globals/objects, host proxies/callbacks, conversions, and bounded copy APIs.
- `runtimeabi/testdata/echo-runtime/harness.c` — real `dlopen`/query integration assertions for ABI negotiation, lifecycle, values, callbacks, retention, and two-call buffers.
- `.superpowers/sdd/plan/task-3-report.md` — this TDD report.

## Commits

- Baseline: `ab09ee852380990c9f576c978453f9fafa309c13`
- Fixture implementation: `52bec245` (`test(runtimeabi): add echo fake runtime fixture`)
- Report: `268b4a62` (`docs(sdd): record fake runtime fixture verification`)
- Harness assertion cleanup: `24040f38` (`test(runtimeabi): tighten object has assertion`)

## Concerns

The fixture intentionally supports only the documented deterministic eval sources (`1 + 2` and `throw echo error`), a single in-process runtime, fixed-size internal tables, and no unload behavior. It does not implement the native loader, QuickJS, Dice, or Go integration.
