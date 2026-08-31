# Task 15 — Shared host services report

## RED

The contract was implemented test-first. The initial focused runs failed because the requested surfaces did not exist yet:

```text
go test ./utils/jsengine/services -run 'TestRegistry|TestNativeDescriptor' -count=1
Scardice-core/utils/jsengine/services: no non-test Go files in .../utils/jsengine/services
FAIL
```

The Goja installer test initially failed for the same reason:

```text
go test ./utils/jsengine/services/goja -run TestInstallerPreservesCoreGojaServiceBehavior -count=1
Scardice-core/utils/jsengine/services/goja: no non-test Go files in .../utils/jsengine/services/goja
FAIL
```

After the registry implementation, policy-bound fetch and WebSocket tests were added before their adapter hooks. Their intended RED failures were compile-time missing API failures:

```text
utils/plugin/httpextra/fetch_policy_test.go:21:12: undefined: EnableFetchWithPolicy
utils/plugin/websocket/policy_test.go:15:3: undefined: EnableWithPolicy
```

The Dice SealPack integration test likewise failed before the policy helper existed:

```text
dice/dice_js_service_policy_test.go:27:12: undefined: jsNetworkAuthorize
```

## GREEN

Implemented and verified the shared registry, Goja installer boundary, SealPack policy checks, and adapter lifecycle hooks.

Final focused contract/adapter run:

```text
go test ./utils/jsengine/services/... ./utils/plugin/httpextra ./utils/plugin/websocket ./dice -run 'Test(Registry|NativeDescriptor|InstallerPreservesCoreGojaServiceBehavior|FetchLifecycle|EnableFetchWithPolicy|WebSocketPolicy|JS(Network|Filesystem)Authorize|JsFs|InstallJS|Js.*)' -count=1
ok   Scardice-core/utils/jsengine/services
ok   Scardice-core/utils/jsengine/services/goja
ok   Scardice-core/utils/plugin/httpextra
ok   Scardice-core/utils/plugin/websocket
ok   Scardice-core/dice
```

Existing adapter behavior:

```text
go test ./utils/plugin/... -count=1
[abort/structuredclone/utilinspect have no package-local tests]
ok   Scardice-core/utils/plugin/crypto
ok   Scardice-core/utils/plugin/httpextra
ok   Scardice-core/utils/plugin/websocket

go test ./dice -run 'Test(Js|InstallJS|QuickJS)' -count=1
ok   Scardice-core/dice
```

Engine contract regression run:

```text
go test ./utils/jsengine/... -count=1
ok   Scardice-core/utils/jsengine
ok   Scardice-core/utils/jsengine/builtin/goja
ok   Scardice-core/utils/jsengine/goja
ok   Scardice-core/utils/jsengine/hostbridge
ok   Scardice-core/utils/jsengine/native
ok   Scardice-core/utils/jsengine/quickjs
ok   Scardice-core/utils/jsengine/services
ok   Scardice-core/utils/jsengine/services/goja
```

No formatter, linter, project-wide test suite, ABI-header edit, or broad QuickJS C++ edit was run.

## Files

- `utils/jsengine/services/registry.go`: engine-neutral names, numeric operation IDs, scalar/bytes request and response unions, typed statuses, cancellation/deadline metadata, SealPack policy authorization, concrete-service registry, adapter installer ownership, deterministic duplicate/missing/unsupported/closed errors, and shutdown.
- `utils/jsengine/services/registry_test.go`: duplicate/missing, permission, deadline, cancellation, adapter-only, ownership, native unsupported, and descriptor advertisement tests.
- `utils/jsengine/services/goja/installer.go`: explicit Goja adapter installer for console, crypto, fetch/HTTP, WebSocket, filesystem, abort, structured clone, and util.inspect. Existing JS-visible module names and implementations remain unchanged behind this boundary.
- `utils/jsengine/services/goja/installer_test.go`: representative console/abort/structuredClone/util.inspect/CommonJS behavior plus all available service registrations.
- `utils/jsengine/descriptor.go`: optional Go-level `Services` metadata. ABI-v1 native descriptors leave it empty because the frozen C ABI has no named-service field.
- `dice/dice.go`: per-Dice service-registry lifecycle field.
- `dice/dice_jsvm.go`: Goja module registration migrated to the installer/registry boundary; reflection host installation remains separate.
- `dice/dice_jsvm_fs.go`: package-aware network/filesystem authorization before synchronous or asynchronous IO.
- `dice/dice_js_service_policy_test.go`: current SealPack network and filesystem permission coverage.
- `utils/plugin/httpextra/fetch.go`: policy-aware fetch entrypoint and request lifecycle tracker that cancels in-flight requests on shutdown.
- `utils/plugin/httpextra/fetch_policy_test.go`, `fetch_lifecycle_test.go`: denial-before-network and shutdown cancellation coverage.
- `utils/plugin/websocket/websocket.go`: pre-dial policy hook and explicit policy-aware installer while preserving `Enable` compatibility.
- `utils/plugin/websocket/policy_test.go`: denial-before-dial coverage.
- `.superpowers/sdd/plan/task-15-report.md`: this report.

## API contract

Stable service names are `console`, `crypto`, `fetch`, `http`, `websocket`, `filesystem`, `abort`, `structuredclone`, and `util.inspect`. The service package also exports `Service*` aliases for these names.

`OperationID` is a numeric, grouped ID (for example `OpFilesystemReadFile`, `OpFetchRequest`, and `OpStructuredClone`), not a free-form string. `Request` and `Response` use explicit scalar fields and byte buffers; there is no JSON dispatch payload, `goja.Value`, reflection object, or host pointer in this contract. `Response.Status` is one of `ok`, `invalid`, `permission-denied`, `cancelled`, `deadline-exceeded`, `unsupported`, `closed`, or `internal`.

`Call` carries `Request`, a `Policy`, an absolute `Deadline`, and a cancellation channel. Registry dispatch checks closed/missing/operation validity, deadline, cancellation, and SealPack policy before invoking a concrete service. `errors.Is` remains deterministic through `CallError` and `PolicyError` unwrapping.

`Registry.Register` accepts concrete engine-neutral services. Adapter-specific modules use `Registry.Install(Installer)`, where one installer owns one or more definitions and has exactly-once `Install`/`Close` lifecycle ownership. Adapter-only definitions return `StatusUnsupported`/`ErrUnsupported` through generic invocation rather than a no-op or fallback. `Registry.Close` removes all bindings and invokes each owner shutdown hook exactly once.

`gojaservices.Installer` is the only module-registration boundary used by `dice_jsvm.go`. It installs existing Goja module loaders before the owner-loop callback and enables globals on that same loop. `HostBridge` reflection binding is still installed by `installJSHostAPI` independently.

## Supported / unsupported matrix

| Service | Goja adapter | SealPack policy | ABI-v1 native provider |
| --- | --- | --- | --- |
| console | Supported; existing global and CommonJS behavior | No external permission | Not advertised |
| crypto | Supported; existing WebCrypto module | Local operation; no network/filesystem permission | Not advertised |
| fetch | Supported when loop+proxy are present | Current package `Network` and host allowlist checked before request goroutine | Not advertised; deterministic `ErrUnsupported` |
| HTTP | Existing `@seal/http` constructors plus fetch path | Fetch path uses the network policy hook | Not advertised |
| websocket | Supported when loop+proxy service set is present | Current package network permission checked before dial | Not advertised |
| filesystem | Supported through Dice's existing `fs`/`data://` adapter | Package `file_read`/`file_write` checked before all sync/async operations; existing traversal and unrestricted-config rules remain | Not advertised |
| abort | Supported; existing `AbortController`/`AbortSignal` behavior | No external permission | Not advertised |
| structuredclone | Supported; existing Goja implementation | No external permission | Not advertised |
| util.inspect | Supported; existing Goja implementation and `util.inspect` global | No external permission | Not advertised |

ABI v1 has no named service field, service operation IDs, or host-to-runtime async completion submission. The native loader therefore reads an empty Go-level `Descriptor.Services` list for ABI-v1 plugins and rejects every named service unless a future provider explicitly supplies Go metadata outside this frozen ABI. No native capability is inferred from generic host-object/function bits, and no async host-service bit is added.

## Lifecycle and concerns

- `JsLoopManager.SetLoop` closes the replaced loop as before. `Dice.jsClear` now closes the service registry first, which closes in-flight fetch contexts and all WebSocket connections before releasing the loop.
- Fetch lifecycle tracking is provider-owned, uses no background watcher, and calls request cancellation exactly once per active request. Policy rejection happens before any network goroutine starts.
- WebSocket policy rejection happens on the Goja owner thread before the connection goroutine starts; installer shutdown uses the existing global connection manager.
- Filesystem operations retain the existing adapter behavior and existing asynchronous implementation. Their authorization happens before scheduling, but the legacy fs worker goroutines are not converted into a second global watcher; loop shutdown still owns the final callback boundary.
- Core scripts without a SealPack package identity retain historical network behavior for compatibility. Package-backed scripts require an installed package sandbox and never fall back to unrestricted package IO.
- The native service matrix is intentionally empty until ABI/runtime support can represent named requests, typed results, and asynchronous completion honestly.
