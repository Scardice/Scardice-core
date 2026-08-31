# QuickJS Plugin Safety Design

**Status:** Approved for implementation planning  
**Date:** 2026-08-30  
**Supersedes:** The environment decision in `2026-08-30-quickjs-nodejs-integration-design.md`; all other integration decisions remain in force.

## Goal

Harden the shared QuickJS plugin runtime against host-process crashes, secret environment disclosure, host-global rebinding, and concurrent Go-container access while preserving Scardice's established cross-plugin model and current network and administrative capabilities.

## Compatibility Evidence

The reviewed production and development plugin corpus relies on the following behavior:

- `globalThis.http`, `globalThis.teamManager`, `globalThis.timer`, `globalThis.clueboard`, and `globalThis.Handlebars` are plugin-defined coordination namespaces.
- `fetch`, polling loops, timers, configurable HTTP services, and local OneBot HTTP endpoints are active use cases.
- Cross-plugin storage uses `seal.ext.find(name).storageGet` and `storageSet`.
- Plugins populate `ext.cmdMap` with direct JavaScript property assignments before registration.

The design therefore protects only host-owned globals, preserves the one-realm model, keeps private-network routing and global administrative APIs unchanged, and does not restrict live Go objects returned by `seal.ext.find`.

## Scope

### In scope

1. Convert any panic escaping the QuickJS reflection binder into a JavaScript exception.
2. Expose only an explicit, non-secret `process.env` snapshot.
3. Retain same-name extension replacement while logging both plugin origins before replacement.
4. Make host-installed global-property descriptors non-writable and non-configurable after bootstrap.
5. Eliminate unsynchronized access to Go maps and slices exposed through QuickJS host-object proxies without changing their JavaScript mutation API.
6. Add optional, default-disabled QuickJS execution and native-resource limits in `github.com/Scardice/quickjs_nodejs`.
7. Surface those optional limits through Scardice `JsConfig` and its QuickJS Node environment.

### Explicit non-goals

- Do not create a Realm, Worker, or context per plugin.
- Do not change `seal.ext.find` return identity, cross-plugin storage, or live Go object access.
- Do not add hostname, IP-range, proxy, or private-network restrictions to `fetch` or `WebSocket`.
- Do not remove or gate global administrative host APIs.
- Do not change same-name extension takeover semantics beyond warning logs.
- Do not freeze arbitrary plugin-created globals or prototypes.
- Do not alter Goja behavior.

## Core Design

### Panic boundary

`utils/jsengine/quickjs/host.go` is the process boundary for reflected host functions and methods. Every callback produced by `bindFunction` and `defineMethod` must defer a recovery boundary around Go reflection invocation.

The recovery boundary must:

1. Format the recovered value with `fmt.Sprint`.
2. Throw a JavaScript `Error` on the active QuickJS context.
3. Return the QuickJS exception sentinel instead of unwinding the event-loop owner goroutine.

Normal Go-returned errors retain their existing JavaScript error conversion. The boundary must not recover panics outside a JavaScript-to-host callback: it is a containment boundary, not a process-wide panic suppressor.

### Environment allowlist

`dice.snapshotProcessEnv` replaces its full `os.Environ` copy with a snapshot of these exact host keys when present:

```text
LANG
LC_ALL
LC_CTYPE
LC_MESSAGES
LC_TIME
TZ
```

No other environment key is copied. The resulting map remains an initialization-time snapshot and is passed identically to the `process` module and the global `process` installer. `process.env` stays mutable inside JavaScript; mutations affect only the JavaScript snapshot.

### Same-name extension warning

The existing `seal.ext.register` replacement flow is unchanged. Before it overwrites a registered JavaScript extension with the same `Name`, it writes a warning through `Dice.Logger` containing:

- extension name;
- incumbent `JsScriptInfo.Name`, `Filename`, `PackageID`, and `HomePage`;
- replacing `JsScriptInfo.Name`, `Filename`, `PackageID`, and `HomePage`.

The log message explicitly says the replacement is occurring and asks the operator to verify both sources. It does not wait for user input, reject registration, or preserve the incumbent.

### Host-global descriptor lock

After `installJSHostAPI`, `installJSExtHostAPI`, `installDangerousJSInstance`, `__dirname`, and all QuickJS Node global installers succeed, one synchronous bootstrap script changes descriptors for the following host-owned own-properties when they exist:

```text
seal
process
require
Buffer
Blob
URL
crypto
AbortController
structuredClone
MessageChannel
fetch
WebSocket
```

For each own property, `Object.defineProperty(globalThis, name, {
  writable: false,
  configurable: false,
})` runs without replacing its current value or enumerability. The script must not reference absent globals as variables; it must first check `Object.prototype.hasOwnProperty.call(globalThis, name)`.

Timers, console, standard language globals, object prototypes, and every plugin-defined global remain writable under their present semantics. Existing shallow `Object.freeze(seal)` calls remain unchanged in this security slice; the descriptor lock prevents reassignment of `globalThis.seal` rather than extending the API object's immutability surface.

### Concurrent host containers

The binder gains a generic `jsbindlock:"MethodName"` field tag for map and slice fields. When present, the tagged no-argument method on the containing Go value returns the `*sync.RWMutex` that guards the field. The binder captures that guard in every map/slice proxy and propagates it to values reached through that proxy. A read lock covers one property read or enumeration snapshot; a write lock covers one set, delete, append, or length mutation. Enumeration copies keys or values before returning to JavaScript, so no Go iterator escapes the lock.

`ExtInfo.CmdMap` receives `jsbindlock:"CmdMapLock"`. `(*ExtInfo).CmdMapLock() *sync.RWMutex` lazily installs one stable lock with `sync.Once`, and `(*ExtInfo).CmdMapSnapshot() CmdMapCls` copies its map and every `CmdItemInfo` entry while holding the read lock. QuickJS map reads, writes, deletes, enumeration, and mutations of a `CmdItemInfo` reached through `ext.cmdMap` use that same lock. Command resolution replaces direct `CmdMap` iteration/indexing with a snapshot, then releases the lock before invoking a command callback. This prevents lock re-entry from JavaScript and preserves all direct JavaScript forms, including `ext.cmdMap[name] = cmd`, `delete ext.cmdMap[name]`, `Object.keys(ext.cmdMap)`, and `cmd.solve = fn`.

The `jsbindlock` mechanism is reusable for later mutable host containers, but this change applies it only to `ExtInfo.CmdMap`, the observed concurrently read extension container. No command map is replaced by an immutable copy or a new JavaScript API.

## Optional Execution and Resource Limits

### Compatibility posture

Every newly introduced limit defaults to `0`, meaning unlimited. Existing configurations therefore keep current behavior. Operators opt in by setting a positive `JsConfig` value; `JsReload` applies updated values when it builds the next QuickJS runtime.

Because one QuickJS realm hosts all JavaScript extensions, limits are per QuickJS runtime rather than per extension. They are not presented as isolation or tenant controls.

### qnode capability contract

`github.com/Scardice/quickjs_nodejs` gains an exported `limits` package shared by its event loop and native modules:

```go
package limits

type Config struct {
    ExecuteTimeout          time.Duration
    MaxFetchConcurrent      int
    MaxFetchResponseBytes   int64
    MaxWebSocketConnections int
    MaxFilesystemReadBytes  int64
    MaxFilesystemWriteBytes int64
    MaxPBKDF2Iterations     int
    MaxPBKDF2OutputBytes    int
}

func (Config) Validate() error
func NewRuntime(Config) (*Runtime, error)
```

Each zero-valued field is unlimited. `Validate` rejects negative fields. `NewRuntime` copies the configuration and constructs the runtime-local counters and semaphores. Core code creates exactly one `*limits.Runtime` for each QuickJS realm and passes that same instance to every native-module installer, so `fetch` imported as a module and `globalThis.fetch` consume the same concurrency budget.

| Package | Added option |
| --- | --- |
| `eventloop` | `WithResourceLimits(config limits.Config) Option` |
| `fetch` | `WithResourceLimits(runtime *limits.Runtime) Option` |
| `websocket` | `WithResourceLimits(runtime *limits.Runtime) Option` |
| `fs` | `WithResourceLimits(runtime *limits.Runtime) Option` |
| `crypto` | `WithResourceLimits(runtime *limits.Runtime) Option` |

The event loop uses only `ExecuteTimeout`; each module reads only the field it owns:

- `fetch`: acquire a runtime-local semaphore before starting its goroutine; reject the Promise when full; abort and reject once streamed response bytes exceed `MaxFetchResponseBytes`.
- `websocket`: reserve one runtime-local connection slot before dialing; release it exactly once when construction fails or the connection closes.
- `fs`: reject synchronous and Promise operations before allocation/read/write when the requested or observed byte count exceeds their configured limit.
- `crypto`: reject `pbkdf2` and `subtle.deriveBits` before work when iterations or output length exceed configured maxima.
- execution: arm `quickjs.Runtime.SetExecuteTimeout` only while JavaScript source, a JavaScript callback, or a queued JavaScript job is running. Clear it before the event loop waits for I/O or dispatches an asynchronous resource completion. On expiry, QuickJS reports the existing execution exception to JavaScript; the Go process and event-loop goroutine remain live.

The values remain deliberately operator-selected; no hard-coded deadline, response-size, connection-count, filesystem-size, or PBKDF2 threshold is introduced by this design.

### Scardice configuration contract

`dice.JsConfig` gains these JSON/YAML-compatible fields:

```go
QuickJSExecuteTimeoutMillis      uint64 `json:"quickJSExecuteTimeoutMillis" yaml:"quickJSExecuteTimeoutMillis"`
QuickJSMaxFetchConcurrent        uint64 `json:"quickJSMaxFetchConcurrent" yaml:"quickJSMaxFetchConcurrent"`
QuickJSMaxFetchResponseMiB       uint64 `json:"quickJSMaxFetchResponseMiB" yaml:"quickJSMaxFetchResponseMiB"`
QuickJSMaxWebSocketConnections   uint64 `json:"quickJSMaxWebSocketConnections" yaml:"quickJSMaxWebSocketConnections"`
QuickJSMaxFilesystemReadMiB      uint64 `json:"quickJSMaxFilesystemReadMiB" yaml:"quickJSMaxFilesystemReadMiB"`
QuickJSMaxFilesystemWriteMiB     uint64 `json:"quickJSMaxFilesystemWriteMiB" yaml:"quickJSMaxFilesystemWriteMiB"`
QuickJSMaxPBKDF2Iterations       uint64 `json:"quickJSMaxPBKDF2Iterations" yaml:"quickJSMaxPBKDF2Iterations"`
QuickJSMaxPBKDF2OutputBytes      uint64 `json:"quickJSMaxPBKDF2OutputBytes" yaml:"quickJSMaxPBKDF2OutputBytes"`
```

`Dice.quickJSNodeResourceLimits()` converts positive unsigned settings into the qnode signed/int/time values, rejects overflow at initialization, and leaves a zero setting unlimited. The existing memory, GC, and stack limits keep their current non-zero fallback policy; these new optional limits do not reuse `quickJSConfigLimitBytes`.

`newQuickJSNodeEnvironment` creates one `*limits.Runtime` from the validated configuration and passes it to the relevant `fetch`, `websocket`, `fs`, and `crypto` module options. `utils/jsengine/quickjs` adds `WithNodeResourceLimits(limits.Config)` and forwards it to `eventloop.WithResourceLimits` when constructing its qnode owner loop. The core does not duplicate qnode's semaphore, byte-accounting, or crypto validation logic.

## Dependency Ownership

The qnode repository owns generic event-loop execution limits plus `fetch`, `websocket`, `fs`, and `crypto` resource enforcement and their focused tests. It publishes a revision only after its test, vet, and race suites pass.

Scardice owns process-environment policy, host reflection recovery, host-global locking, extension collision warnings, QuickJS config conversion, and all Go-container synchronization. Scardice updates `go.mod` to the tested qnode revision; it does not commit a local `replace` directive.

## Test Contract

### qnode tests

1. An infinite JavaScript loop fails with an execution exception when `ExecuteTimeout` is positive, then a subsequent simple JavaScript task succeeds on the same event loop.
2. A slow asynchronous fetch does not consume JavaScript execution time while awaiting I/O.
3. The fetch concurrency limit rejects the excess Promise and releases a slot after completion.
4. A response exceeding the configured byte limit rejects and closes the response body.
5. WebSocket connection slots are released after close and after dial failure.
6. Oversized filesystem read/write requests and PBKDF2 inputs reject before their unbounded operation starts.
7. Every zero limit retains existing behavior.

### Scardice tests

1. A plugin-callable Go function that panics returns a JavaScript exception and the QuickJS loop subsequently evaluates JavaScript successfully.
2. `process.env` includes a present allowlisted test key, excludes a present secret test key, and does not reflect later host environment changes.
3. Registering two JavaScript extensions with the same name still replaces the first and emits one warning containing both filenames.
4. Assigning or deleting each host-owned global fails or leaves the original binding intact; assigning `globalThis.http` still succeeds.
5. Parallel JavaScript map/slice mutations and Go command-table reads complete under `go test -race` without `concurrent map` panics or races.
6. Default zero limit configuration creates the same QuickJS Node environment and retains current fetch, WebSocket, fs, and crypto behavior.
7. A positive Scardice setting reaches qnode and enforces the corresponding configured limit.

## Verification

Run focused package tests after each slice. Before integration, in the qnode checkout run:

```text
go test ./... -count=1 -timeout=240s
go vet ./...
go test -race ./... -count=1 -timeout=300s
```

After Scardice consumes the published qnode revision, run:

```text
go test -race ./... -count=1
go vet ./...
```
