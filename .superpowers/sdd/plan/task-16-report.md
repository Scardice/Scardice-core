# Task 16 — QuickJS resource options

## RED

The Go contract test was written before the builder and initially failed at compile time because the requested API did not exist:

```text
go test ./dice -run 'TestBuildQuickJSRuntimeOptions|TestDiceQuickJSRuntimeOptions' -count=1
undefined: BuildQuickJSRuntimeOptions
undefined: ErrQuickJSOptionsOverflow
... too many errors
FAIL
```

The first native CTest run also exposed a missing timeout test branch and an out-of-range boundary that was not rejected. Those cases were corrected before the final run. The provider test was written before the native options application was verified and is skipped only when no installed native package is provided.

## GREEN

Focused Go builder tests:

```text
go test ./dice -run 'TestBuildQuickJSRuntimeOptions|TestDiceQuickJSRuntimeOptions' -count=1
ok   Scardice-core/dice
```

Pinned QuickJS-NG fixture (the repository's CMake requires `QUICKJS_ROOT`; this run used the pinned v0.7.7 source already in the module cache):

```text
cmake -S runtime-plugins/quickjs -B /tmp/scardice-qjs-build \
  -DQUICKJS_ROOT=/home/lyjjl/go/pkg/mod/github.com/buke/quickjs-go@v0.7.7/deps/quickjs
cmake --build /tmp/scardice-qjs-build -j2
ctest --test-dir /tmp/scardice-qjs-build --output-on-failure \
  -R 'scardice-runtime-quickjs-(smoke|options)'
100% tests passed out of 8
```

The CTest cases cover malformed JSON, unknown keys, out-of-range memory, an actual execution interrupt/deadline, actual memory exhaustion, actual stack exhaustion, and a full serialized payload containing every service-policy field. The provider-owned Go test was run against the installed fixture:

```text
SCARDICE_QUICKJS_PACKAGE=/tmp/scardice-qjs-package \
  go test ./runtime-plugins/quickjs/test \
  -run TestQuickJSProviderAppliesTimeoutOption -count=1
ok   Scardice-core/runtime-plugins/quickjs/test
```

## Fields and semantics

| JsConfig field | Payload field | Unit conversion | Zero/default/overflow |
| --- | --- | --- | --- |
| `QuickJSMemoryLimitMiB` | `runtime.memoryLimitBytes` | MiB × 1,048,576 | zero = 256 MiB; multiplication overflow is an error |
| `QuickJSGCThresholdMiB` | `runtime.gcThresholdBytes` | MiB × 1,048,576 | zero = 64 MiB; threshold at/above memory is clamped to memory/4 in Go; native rejects malformed `gc > memory` |
| `QuickJSMaxStackSizeKiB` | `runtime.maxStackSizeBytes` | KiB × 1,024 | zero = 1 MiB; multiplication overflow is an error |
| `QuickJSExecuteTimeoutSeconds` | `runtime.executionTimeoutMillis` | seconds × 1,000 | zero = unlimited; multiplication overflow is an error |
| `QuickJSMaxFetchConcurrent` | `services.fetch.maxConcurrent` | scalar | zero = unlimited; service policy metadata only |
| `QuickJSMaxFetchResponseMiB` | `services.fetch.maxResponseBytes` | MiB × 1,048,576 | zero = unlimited; multiplication overflow is an error |
| `QuickJSMaxWebSocketConnections` | `services.websocket.maxConnections` | scalar | zero = unlimited; service policy metadata only |
| `QuickJSMaxWebSocketMessageMiB` | `services.websocket.maxMessageBytes` | MiB × 1,048,576 | zero = unlimited; multiplication overflow is an error |
| `QuickJSMaxFilesystemReadMiB` | `services.filesystem.maxReadBytes` | MiB × 1,048,576 | zero = unlimited; multiplication overflow is an error |
| `QuickJSMaxFilesystemWriteMiB` | `services.filesystem.maxWriteBytes` | MiB × 1,048,576 | zero = unlimited; multiplication overflow is an error |
| `QuickJSMaxPBKDF2Iterations` | `services.pbkdf2.maxIterations` | scalar | zero = unlimited; policy metadata only |
| `QuickJSMaxPBKDF2OutputBytes` | `services.pbkdf2.maxOutputBytes` | bytes | zero = unlimited; policy metadata only |

The serialized object is deterministic and versioned as `version: 1`. The builder emits no credentials or other secret-bearing config fields. Native parsing is bounded to 64 KiB, accepts only unsigned integer values, rejects duplicates, malformed syntax, unknown fields, integer overflow, and runtime values above 1 TiB memory / 1 GiB stack / 24 hours timeout. Native CTest policy values are validated but deliberately not enforced by the JS engine.

## Enforcement and provenance

- Go source provenance: `dice.JsConfig` in `dice/dice_config.go`; the builder is `dice/js_quickjs_options.go` and returns the existing borrowed `jsengine.RuntimeOptions.OptionsJSON` field.
- Native source provenance: `runtime-plugins/quickjs/quickjs_runtime.cpp`; the provider parses the payload before creating the context.
- Runtime-owned enforcement uses QuickJS-NG `JS_SetMemoryLimit`, `JS_SetGCThreshold`, `JS_SetMaxStackSize`, and `JS_SetInterruptHandler`. Each evaluation starts a monotonic deadline; the interrupt callback returns the stable `SC_ETIMEOUT` status and preserves a deterministic error string.
- `utils/jsengine/native/native_cgo.go` already forwards the borrowed options bytes unchanged during provider creation; the provider option test proves the payload reaches the native runtime and the infinite script is interrupted.
- Fetch, WebSocket, filesystem, and PBKDF2 values are shared service-policy metadata. Their enforcement remains in the Go service adapters/HostServices policy layer; the native JS provider advertises no named service capability and does not claim to enforce them.
- Goja remains explicit: non-empty unsupported options are rejected by its builtin provider rather than silently ignored.

## Limitations

No fetch or WebSocket implementation was added. The frozen ABI v1 header was not changed. The native parser intentionally supports the documented version-1 object only; future payload versions require an explicit parser update. Native memory/stack behavior is dependent on QuickJS-NG's allocator and stack checks, while the CTest watchdog bounds timeout regressions. The direct in-process `buke/quickjs-go` adapter continues to receive its existing typed runtime/node options; this task's JSON payload is the native-provider contract.
