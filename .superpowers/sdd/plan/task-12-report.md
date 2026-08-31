# Phase 12 — Reentrant callback safety

## Scope

Added `runtime-plugins/quickjs/test/reentrant_callbacks_test.go` with real host bindings and callback adapters. The tests exercise the A–G matrix against legacy QuickJS-Go and a native QuickJS provider when `SCARDICE_QUICKJS_PACKAGE` is explicitly configured. Legacy tests start the real event loop before the callback cases so nested callbacks use the supported inline callback path; no recursive `Loop.Run` is used by a host method.

The host records ordered events and exposes methods that call passed JavaScript callbacks, while callback bodies call host methods again. Assertions cover callback results, host-call counters, exact event order, panic/exception/timeout diagnostics, context recovery, and stale callback behavior after close and loop recreation. Every engine operation and close path is bounded by a two-second per-case watchdog.

## Matrix

| Cell | Legacy QuickJS-Go | Native QuickJS | Assertions |
| --- | --- | --- | --- |
| A Go→JS | PASS | SKIP (package env absent) | Go invokes retained JS callback; result 10; bounded completion |
| B JS→Go | PASS | SKIP (package env absent) | Host call result 1; one ordered host event |
| C Go→JS→Go | PASS | SKIP (package env absent) | Result 6; `go.call.start → record.nested → go.call.end` |
| D JS→Go→JS | PASS | SKIP (package env absent) | Result 16; `invoke.enter → invoke.exit` |
| E Go→JS→Go→JS | PASS | SKIP (package env absent) | Result 12; exact five-event order across both callback boundaries |
| F close/recreate | PASS | SKIP (package env absent) | Old callback returns deterministic closed/stale error before and after recreation; new callback returns 3 |
| G panic/exception/timeout | PASS | SKIP (package env absent) | Host panic, JS exception, callback deadline error are surfaced; timeout host error is catchable; subsequent host call succeeds |

Native cells are explicit subtest skips only because `SCARDICE_QUICKJS_PACKAGE` is not set. No native package was available to build locally: the pinned source probe found no `quickjs.h` under `$HOME/quickjs-ng`, `$HOME/src/quickjs-ng`, or `$HOME/.cache/quickjs-ng`, and no prebuilt `libscardice-runtime-quickjs.so` was present.

## Exact commands and output

### Native package probe

```text
$ for p in "$HOME/quickjs-ng" "$HOME/src/quickjs-ng" "$HOME/.cache/quickjs-ng"; do if test -f "$p/quickjs.h"; then printf 'quickjs-ng=%s\n' "$p"; exit 0; fi; done; printf '%s\n' 'no pinned QuickJS-NG source tree found'
no pinned QuickJS-NG source tree found
```

### Focused matrix

```text
$ go test ./runtime-plugins/quickjs/test -run 'TestReentrantMatrix' -count=1 -timeout=30s -v
=== RUN   TestReentrantMatrixA_GoToJS
=== RUN   TestReentrantMatrixA_GoToJS/legacy-quickjs
=== RUN   TestReentrantMatrixA_GoToJS/native-quickjs
    reentrant_callbacks_test.go:110: SCARDICE_QUICKJS_PACKAGE is not set
--- PASS: TestReentrantMatrixA_GoToJS (0.00s)
    --- PASS: TestReentrantMatrixA_GoToJS/legacy-quickjs (0.00s)
    --- SKIP: TestReentrantMatrixA_GoToJS/native-quickjs (0.00s)
=== RUN   TestReentrantMatrixB_JSToGo
=== RUN   TestReentrantMatrixB_JSToGo/legacy-quickjs
=== RUN   TestReentrantMatrixB_JSToGo/native-quickjs
    reentrant_callbacks_test.go:110: SCARDICE_QUICKJS_PACKAGE is not set
--- PASS: TestReentrantMatrixB_JSToGo (0.00s)
    --- PASS: TestReentrantMatrixB_JSToGo/legacy-quickjs (0.00s)
    --- SKIP: TestReentrantMatrixB_JSToGo/native-quickjs (0.00s)
=== RUN   TestReentrantMatrixC_GoToJSToGo
=== RUN   TestReentrantMatrixC_GoToJSToGo/legacy-quickjs
=== RUN   TestReentrantMatrixC_GoToJSToGo/native-quickjs
    reentrant_callbacks_test.go:110: SCARDICE_QUICKJS_PACKAGE is not set
--- PASS: TestReentrantMatrixC_GoToJSToGo (0.00s)
    --- PASS: TestReentrantMatrixC_GoToJSToGo/legacy-quickjs (0.00s)
    --- SKIP: TestReentrantMatrixC_GoToJSToGo/native-quickjs (0.00s)
=== RUN   TestReentrantMatrixD_JSToGoToJS
=== RUN   TestReentrantMatrixD_JSToGoToJS/legacy-quickjs
=== RUN   TestReentrantMatrixD_JSToGoToJS/native-quickjs
    reentrant_callbacks_test.go:110: SCARDICE_QUICKJS_PACKAGE is not set
--- PASS: TestReentrantMatrixD_JSToGoToJS (0.00s)
    --- PASS: TestReentrantMatrixD_JSToGoToJS/legacy-quickjs (0.00s)
    --- SKIP: TestReentrantMatrixD_JSToGoToJS/native-quickjs (0.00s)
=== RUN   TestReentrantMatrixE_GoToJSToGoToJS
=== RUN   TestReentrantMatrixE_GoToJSToGoToJS/legacy-quickjs
=== RUN   TestReentrantMatrixE_GoToJSToGoToJS/native-quickjs
    reentrant_callbacks_test.go:110: SCARDICE_QUICKJS_PACKAGE is not set
--- PASS: TestReentrantMatrixE_GoToJSToGoToJS (0.00s)
    --- PASS: TestReentrantMatrixE_GoToJSToGoToJS/legacy-quickjs (0.00s)
    --- SKIP: TestReentrantMatrixE_GoToJSToGoToJS/native-quickjs (0.00s)
=== RUN   TestReentrantMatrixF_ClosedCallbackIsDeterministic
=== RUN   TestReentrantMatrixF_ClosedCallbackIsDeterministic/legacy-quickjs
=== RUN   TestReentrantMatrixF_ClosedCallbackIsDeterministic/native-quickjs
    reentrant_callbacks_test.go:324: SCARDICE_QUICKJS_PACKAGE is not set
--- PASS: TestReentrantMatrixF_ClosedCallbackIsDeterministic (0.00s)
    --- PASS: TestReentrantMatrixF_ClosedCallbackIsDeterministic/legacy-quickjs (0.00s)
    --- SKIP: TestReentrantMatrixF_ClosedCallbackIsDeterministic/native-quickjs (0.00s)
=== RUN   TestReentrantMatrixG_ErrorsRestoreContext
=== RUN   TestReentrantMatrixG_ErrorsRestoreContext/legacy-quickjs
=== RUN   TestReentrantMatrixG_ErrorsRestoreContext/native-quickjs
    reentrant_callbacks_test.go:110: SCARDICE_QUICKJS_PACKAGE is not set
--- PASS: TestReentrantMatrixG_ErrorsRestoreContext (0.00s)
    --- PASS: TestReentrantMatrixG_ErrorsRestoreContext/legacy-quickjs (0.00s)
    --- SKIP: TestReentrantMatrixG_ErrorsRestoreContext/native-quickjs (0.00s)
PASS
ok   Scardice-core/runtime-plugins/quickjs/test 0.025s
```

### Focused race run

```text
$ go test -race ./runtime-plugins/quickjs/test -run 'TestReentrantMatrix' -count=1 -timeout=30s
ok   Scardice-core/runtime-plugins/quickjs/test 1.036s
```

The verbose race run also passed with the same seven legacy passes and seven explicit native skips:

```text
$ go test -race ./runtime-plugins/quickjs/test -run 'TestReentrantMatrix' -count=1 -timeout=30s -v
PASS
ok   Scardice-core/runtime-plugins/quickjs/test 1.031s
```

No formatter, linter, or project-wide test suite was run. Existing uncommitted QuickJS event-loop/provider/parity files, `plan.md`, and `Scardice-ui` were not modified.
