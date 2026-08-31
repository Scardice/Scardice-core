# Phase 7 Native Runtime Adapter Report

## TDD evidence

### RED

The first echo-backed behavior test exercised `RunString("1 + 2")`, object property set/get/has, and export through the real native provider. With the existing lifecycle-only shim it failed at the first evaluation:

```text
--- FAIL: TestNativeAdapterEvalAndObjectBehavior
    adapter_test.go:34: native runtime unavailable
FAIL
FAIL Scardice-core/utils/jsengine/native 0.003s
```

This established that the adapter behavior was missing rather than merely untested.

### GREEN

The echo fixture was rebuilt and the focused adapter tests were run against the resulting shared object:

```text
$ cc -shared -fPIC -std=c11 -Iruntimeabi/include runtimeabi/testdata/echo-runtime/echo_runtime.c -o /tmp/libecho_runtime.so
$ SCARDICE_ECHO_RUNTIME=/tmp/libecho_runtime.so go test ./utils/jsengine/native -run 'TestNativeAdapter' -count=1 -timeout=60s
ok  Scardice-core/utils/jsengine/native  0.004s
```

The complete scoped native package also passed:

```text
$ SCARDICE_ECHO_RUNTIME=/tmp/libecho_runtime.so go test ./utils/jsengine/native -count=1 -timeout=60s
ok  Scardice-core/utils/jsengine/native  0.004s
```

A focused race run passed as well:

```text
$ SCARDICE_ECHO_RUNTIME=/tmp/libecho_runtime.so go test -race ./utils/jsengine/native -run 'TestNativeAdapter' -count=1 -timeout=60s
ok  Scardice-core/utils/jsengine/native  1.010s
```

## Implemented files

- `utils/jsengine/native/bridge.h`: fixed-width wrapper declarations for runtime lifecycle, eval/load-entry, globals, objects, values, conversions, host proxies, function calls, retain/release, and last-error copy.
- `utils/jsengine/native/bridge.c`: C-owned safe wrapper implementation and HostBridge callback table. Go never invokes a provider vtable pointer directly; the C shim does so with fixed-width/opaque ABI values.
- `utils/jsengine/native/native_cgo.go`: worker-thread native loop, descriptor and entry forwarding, deterministic scope/persistent ownership, same-runtime checks, primitive/object adaptation, host binding, and native function call support.
- `utils/jsengine/native/host_cgo.go`: cgo-handle host context and status-returning HostBridge callbacks for property and function operations, explicit primitive/host-ref conversion, callback error capture, and panic containment.
- `utils/jsengine/native/errors.go`: stable closed/stale/timeout/exception/host error categories.
- `utils/jsengine/native/adapter_test.go`: real `/tmp` echo-provider tests covering descriptor, eval, primitive state, object state, host property roundtrip, host function invocation, errors, retention, shutdown, closed rejection, and all four entry kinds.
- `runtimeabi/testdata/echo-runtime/echo_runtime.c`: real `load_entry` forwarding for Script/CommonJS/ESModule/Extension kinds using the fixture grammar; invalid kinds are rejected by the Go adapter before the ABI call.

## Lifecycle and residency

The loop worker owns provider calls on its locked OS thread. `Close` marks the loop closed, queues a worker-owned stop operation, releases retained values, destroys the runtime, tears down the host session, and deletes the cgo handle. The C loader has no unload entry point, so the loaded library remains resident as required; `ResidentLibraryCount` remains non-zero after loop teardown.

Scope releases preserve multiplicity (each returned ABI handle is tracked as one scope item). A retained value is excluded from scope release, remains usable after `Run`, and is released by `releasePersistent` or worker shutdown. Stale/closed values are rejected deterministically.

## Concerns and limitations

- The echo provider has one executable grammar (`1 + 2` and its deterministic throw); it validates that every entry kind reaches the ABI `load_entry` path but cannot expose filename semantics in a JavaScript result.
- The frozen ABI has no host-function-ref extraction operation for arbitrary native host-function values. Host functions created from HostBridge refs still invoke correctly through `function_call`; decoding an arbitrary provider-created host function remains intentionally rejected rather than represented with an unsafe fallback.
- The native callback codec cannot synthesize a JavaScript callback value because ABI v1 has no callback-value constructor. Host object methods and registered Go functions use the supported host-ref/function-ref path.
- Broader `go test ./utils/jsengine/...` validation is intentionally left to the main session after sibling Loop contract changes land.
