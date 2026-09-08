# Slice 05 Task 1 — Bounded normalized pure OneBot ingress

## Status

Implemented and committed as `0032f198` (`Implement bounded durable inbound ingress`). The production pure OneBot path now hands normalized facts to a bounded durable ingress service. It does not call `IMSession.ExecutePureOnebotInbound`, `ExecuteNew`, Core/plugin code, or any callback from the provider callback/reader handoff.

## Contract and implementation

- `adapterapi.InboundMessage` now represents optional platform, target, and causation alongside provider event ID, message ID, sender, conversation, kind, normalized text, timestamp, and bounded typed segments. Empty provider IDs are valid at the leaf contract so adapters without stable IDs can use the durable fallback key path. Endpoint, generation, and desired version remain exclusively on `endpoint.FencedInbound`.
- `core/messageflow.InboundService` is the narrow durable ingress service. `HandleInbound` validates the normalized DTO and fence, takes a non-blocking bounded admission slot, computes keyed content and lane digests through `IngressSecurity`, encrypts an ingress envelope with `EncryptBound`, and calls `InboxRepository.AcceptInbox` before returning.
- The encrypted inbox payload contains the fenced ingress envelope, normalized message, keyed content digest metadata, and pending status. No plaintext provider body is placed in immutable event metadata or receipt fields. The receipt is metadata-only.
- Stable provider IDs remain the provider dedupe key. Providers without stable IDs receive a keyed fallback identity over endpoint/platform/sender/target/timestamp; the keyed body digest remains persisted separately, so same-identity/different-body collisions are surfaced as `eventstore.ErrConflict` and counted through `CollisionCount`/the optional observer.
- Inbox IDs are endpoint-scoped keyed identifiers, avoiding cross-endpoint primary-key collisions while remaining stable across retries. Existing eventstore dedupe returns the prior inbox ID and ordering sequence for duplicates.
- Conversation lanes use an index-root keyed digest and rely on the existing eventstore lane allocator for ordered sequences. The service sets an explicit 7-day payload/dedupe TTL (`IngressPayloadTTL`). Existing terminal inbox resolution/scrubbing remains responsible for clearing ciphertext and nonce; eventstore expiry handling rejects/scrubs expired unresolved payloads without exposing body data.
- Admission is explicitly bounded and non-blocking. A full capacity returns `ErrIngressBackpressure`; there is no unbounded goroutine or queue fallback.
- `eventstore.GORMStore.KeyedDigest` exposes only the keyed digest and non-secret key ID through the admitted eventstore security boundary; Core does not duplicate key derivation or access key material.
- Main now installs `InboundService` directly as the endpoint inbound sink. The OneBot runtime maps platform, target, causation, text, and typed segments into the normalized DTO before calling the generation-fenced CorePort.

## TDD evidence

### RED (before production implementation)

```text
go test ./core/messageflow -run 'TestInboundService' -count=1

core/messageflow/inbound_test.go:67:179: unknown field Platform in struct literal of type adapterapi.InboundMessage
core/messageflow/inbound_test.go:67:240: unknown field Target in struct literal of type adapterapi.InboundMessage
core/messageflow/inbound_test.go:72:14: undefined: NewInboundService
core/messageflow/inbound_test.go:72:59: undefined: WithIngressCapacity
core/messageflow/inbound_test.go:86:14: undefined: NewInboundService
core/messageflow/inbound_test.go:103:105: undefined: ErrIngressBackpressure
FAIL Scardice-core/core/messageflow [build failed]
```

### GREEN focused behavior

```text
go test ./core/messageflow ./eventstore ./adapterapi ./dice -run 'Test(InboundService|Inbox|Onebot.*Inbound|ExecutePureOnebotInbound)' -count=1

ok   Scardice-core/core/messageflow  0.004s
ok   Scardice-core/eventstore         0.046s
ok   Scardice-core/adapterapi         0.002s [no tests to run]
ok   Scardice-core/dice               2.086s
```

The focused ingress tests cover stable duplicate prior receipt, fallback duplicate and collision telemetry, encrypted-body admission, bounded capacity/backpressure, lane ordering, endpoint-scoped sequencing, and the seven-day expiry. Existing eventstore inbox tests cover durable dedupe/lane behavior and terminal/expiry scrubbing semantics.

A package compile smoke was also run without executing the broad suite:

```text
go test ./... -run '^$'
go test: 37 packages ok, 36 no tests
```

No formatter, linter, or project-wide test suite was run.

## Files changed in commit

- `adapterapi/inbound.go`
- `core/messageflow/inbound.go`
- `core/messageflow/inbound_test.go`
- `dice/platform_adapter_onebot_runtime.go`
- `eventstore/task6.go`
- `main.go`

## Concerns and boundaries

- LSP/codegraph references were unavailable (also recorded in repository `AGENTS.md`); precise repository searches were used for all execution/context/group/attrs/ban/local-data-delete and inbound callsites.
- Provider notice/request conversion remains outside this task; the pure OneBot runtime continues to advertise and normalize message events only.
- The legacy `IMSession.ExecutePureOnebotInbound` method remains for compatibility and its existing direct unit test; no production provider ingress sink calls it after this change. Later Slice05 tasks own inbox callback execution and execution-path collapse.
- `GORMStore.KeyedDigest` intentionally returns `ErrKeySourceUnavailable` when the store has no admitted key source; it does not fall back to plaintext hashing. Production configuration must provide the eventstore security source for encrypted ingress.

## Round 1 fixes

The parent review identified five Task1 correctness gaps; all are now addressed:

- OneBot uses `onebot-message-<message_id>` as the stable provider event key when `message_id` is present. Events without one leave `ProviderEventID` empty so Core computes the bounded fallback key. A stable ID with a changed normalized envelope reaches the same durable identity and returns `eventstore.ErrConflict`.
- Raw OneBot frames are rejected before JSON parsing/copying above `maxOnebotInboundBytes` (`adapterapi.MaxInboundTextBytes`). The transport queue remains bounded and stop-cancellable; oversized and queue-rejected ingress are observable through runtime counters. Retryable ingress/backpressure errors are consumed by the Run loop without publishing Failed or terminating the runtime.
- Lane HMAC input now uses canonical length-prefixed tuple encoding. Conversation is preferred over Target for lane selection, so two target facts in one conversation cannot split ordering lanes. Target remains in the normalized fact and fallback identity.
- `InboxUpdate.AllowExpiredDedupe` is a non-persisted explicit capability for callers that own a shorter dedupe TTL. After expiry, the eventstore deletes the old dedupe row and allocates a new ordered inbox row instead of returning a permanent duplicate. Existing Task5 callers retain the prior expired-replay rejection behavior.

### Round 1 RED/GREEN evidence

```text
go test ./dice -run 'TestOnebotInboundProviderKey|TestOnebotInboundWithoutMessageID' -count=1
FAIL: stable ID returned raw-hash onebot-15b329712bded911; no-ID returned onebot-1c2b555340f27ffc

go test ./core/messageflow -run 'TestInboundService(StableIDChangedBody|ConversationLane)' -count=1
FAIL: conversation split lanes

go test ./eventstore -run 'TestInboxIngressAllowsExplicitReacceptAfterDedupeTTL' -count=1
FAIL: InboxUpdate had no AllowExpiredDedupe field
```

```text
go test ./dice ./core/messageflow ./eventstore -run 'Test(InboundService|InboxIngressAllowsExplicitReaccept|OnebotInbound|OnebotRuntimeKeepsAlive)' -count=1
ok   Scardice-core/dice
ok   Scardice-core/core/messageflow
ok   Scardice-core/eventstore

go test ./dice -run 'TestOnebotRuntime' -count=1
ok   Scardice-core/dice

go test ./eventstore -run 'Test(Task5PublicExpiredReplayScrubsBeforeDedupe|Task5UOWExpiredInitialDedupePrecedesReplay|InboxIngressRejectsPayloadTTLBypass)' -count=1
ok   Scardice-core/eventstore
```

No formatter, linter, or project-wide test suite was run for the fixes. Prior Slice02–04 source/test files are present as untracked shared-worktree dependencies; the fix commit stages only direct Task1 files plus the focused runtime/TTL test files and the directly modified eventstore ingress contracts.

The post-TTL replacement path also checks the delete row count and returns `ErrConflict` if the locked expired identity disappeared concurrently; no silent duplicate admission occurs.

## Round 2 fixes

- Explicit `AllowExpiredDedupe` replacement now applies to every inbox status, including terminal/resolved rows whose ciphertext was already scrubbed. Non-capable legacy callers retain the existing expired-replay rejection behavior. A focused terminal-resolution/post-TTL reaccept test covers this path.
- Stable-ID body conflicts are treated as nonfatal provider collisions by the runtime: the event is rejected/dropped, collision and rejection counters increment, and the runtime remains alive. Retryable Core/storage ingress errors are likewise consumed without a Failed lifecycle observation. No provider ACK is fabricated; the durable ingress contract is the ACK boundary, while a provider-specific transport can retry according to its own delivery semantics.
- The expired-row delete is locked and checks `RowsAffected == 1`; concurrent disappearance returns `ErrConflict`.

Round 2 focused verification:

```text
go test ./dice ./eventstore ./core/messageflow -run 'Test(InboundService|InboxIngressAllowsExplicitReacceptAfter.*DedupeTTL|OnebotInbound|OnebotRuntime)' -count=1
ok   Scardice-core/dice
ok   Scardice-core/eventstore
ok   Scardice-core/core/messageflow
```

## Round 3 fixes

- The pineutil websocket wrapper now bounds its serialized callback queue at 32 events. Admission checks the queue cap before incrementing the wait group, drops overflow without starting another drain, and exposes a dropped-event counter for operational observation. This closes the unbounded wrapper queue around the already-bounded runtime event channel.
- Retryable dequeued inbound failures now receive at most two bounded rehandoffs through the runtime queue. Exhausted retries are rejected without a Failed lifecycle report or fabricated provider acknowledgement. Conflict handling remains nonfatal and observable through `InboundConflictCount`; retry activity is observable through `InboundRetryCount`.
- The fallback identity regression now uses a zero `OccurredAt` value, proving deterministic no-ID/no-time duplicate behavior.

### Round 3 RED/GREEN evidence

```text
go test ./evsocket/v2 -run 'TestWrapperEventQueueIsBounded' -count=1
FAIL: undefined maxWrapperEventQueue and WebsocketWrapper.DroppedEventCount

go test ./evsocket/v2 -run 'Test(WrapperEventQueueIsBounded|ShutdownWaitDrainsQueuedWrapperEvents)' -count=1
ok   github.com/PaienNate/pineutil/evsocket/v2

go test ./dice ./core/messageflow -run 'Test(InboundServiceFallbackDuplicateAndCollision|OnebotRuntimeInboundRetryIsBounded|OnebotRuntimeInboundQueueBackpressureIsStopCancellable|OnebotInbound)' -count=1
ok   Scardice-core/dice
ok   Scardice-core/core/messageflow
```

No formatter, linter, or project-wide suite was run.

Round 3 files changed:

- `third_party/pineutil/evsocket/v2/socketio.go`
- `third_party/pineutil/evsocket/v2/socketio_test.go`
- `dice/platform_adapter_onebot_runtime.go`
- `dice/platform_adapter_onebot_runtime_test.go`
- `core/messageflow/inbound_test.go`

## Round 4 fixes

- OneBot no longer substitutes `time.Now()` when the provider omits its event timestamp. A missing timestamp remains zero and the Core fallback provider identity includes the keyed content digest only for the zero-time/no-ID branch; identical deliveries deduplicate deterministically while distinct bodies receive distinct deterministic fallback identities. Timestamped fallback events retain collision detection.
- Queue admission now reserves terminal transport events (`disconnect`, `error`, and `close`) by evicting an already queued nonterminal event when full. Terminal lifecycle/error delivery therefore cannot be displaced by a saturated message queue; the queue remains bounded and evictions are counted.
- `onebotRuntime.Diagnostics` exposes bounded snapshots for rejection, backpressure, conflicts, retries, and summed transport queue drops through the Core runtime diagnostics seam.

### Round 4 RED/GREEN evidence

```text
go test ./core/messageflow -run 'TestInboundServiceNoIDNoTimeUsesContentDigestIdentity' -count=1
FAIL: eventstore: conflict

go test ./evsocket/v2 -run 'Test(WrapperEventQueueIsBounded|ShutdownWaitDrainsQueuedWrapperEvents)' -count=1
ok   github.com/PaienNate/pineutil/evsocket/v2

go test ./dice ./core/messageflow -run 'Test(InboundService(FallbackDuplicateAndCollision|NoIDNoTimeUsesContentDigestIdentity)|OnebotRuntime(InboundRetryIsBounded|DiagnosticsExposeIngressCounters)|OnebotInbound)' -count=1
ok   Scardice-core/dice
ok   Scardice-core/core/messageflow
```

Round 4 files changed:

- `core/messageflow/inbound.go`
- `core/messageflow/inbound_test.go`
- `dice/platform_adapter_onebot_runtime.go`
- `dice/platform_adapter_onebot_runtime_test.go`
- `third_party/pineutil/evsocket/v2/socketio.go`
- `third_party/pineutil/evsocket/v2/socketio_test.go`

## Round 5 fixes

- The wrapper readiness gate is now one-shot: reconnects no longer replace `connectReady`, so an in-flight drain cannot wait on a stale channel that a later connection never closes. Existing queued callbacks continue draining after the first successful connection, and shutdown wait remains balanced.
- `transportHandler.OnMessage` checks the frame length against a 256 KiB transport bound before copying `message.Bytes()`. Oversized frames are closed and counted as transport drops without entering the wrapper queue.
- Runtime event admission is explicitly nonblocking when the bounded Core event channel is full. Inbound callbacks receive observable backpressure accounting instead of blocking the wrapper drain; retry rehandoff remains bounded.
- Terminal event reservation and runtime diagnostics from Round 4 remain covered; diagnostics now include the transport-level pre-copy drop count.

### Round 5 GREEN evidence

```text
go test ./evsocket/v2 -run 'Test(WrapperEventQueueIsBounded|ShutdownWaitDrainsQueuedWrapperEvents|TransportMessageIsBoundBeforeCopy)' -count=1
ok   github.com/PaienNate/pineutil/evsocket/v2

go test ./dice ./core/messageflow -run 'Test(InboundService(FallbackDuplicateAndCollision|NoIDNoTimeUsesContentDigestIdentity)|OnebotRuntime(InboundRetryIsBounded|DiagnosticsExposeIngressCounters|InboundQueueBackpressureIsNonBlocking|KeepsAliveOnRetryableInboundError)|OnebotInbound)' -count=1
ok   Scardice-core/dice
ok   Scardice-core/core/messageflow
```

Round 5 files changed:

- `third_party/pineutil/evsocket/v2/socketio.go`
- `third_party/pineutil/evsocket/v2/socketio_test.go`
- `dice/platform_adapter_onebot_runtime.go`
- `dice/platform_adapter_onebot_runtime_test.go`

## Round 6 fixes

- Runtime queue admission is nonblocking for every callback. A full bounded event channel immediately rejects inbound admission and increments backpressure telemetry instead of blocking the wrapper drain; this prevents a bounded wrapper queue from being held behind an unbounded callback wait.
- The transport-level raw-frame bound and one-shot readiness gate remain in force, so oversized frames are rejected before copying and reconnects cannot strand queue drains.

### Round 6 GREEN evidence

```text
go test ./evsocket/v2 -run 'Test(WrapperEventQueueIsBounded|ShutdownWaitDrainsQueuedWrapperEvents|TransportMessageIsBoundBeforeCopy)' -count=1
ok   github.com/PaienNate/pineutil/evsocket/v2

go test ./dice ./core/messageflow -run 'Test(InboundService(FallbackDuplicateAndCollision|NoIDNoTimeUsesContentDigestIdentity)|OnebotRuntime(InboundRetryIsBounded|DiagnosticsExposeIngressCounters|InboundQueueBackpressureIsNonBlocking|KeepsAliveOnRetryableInboundError)|OnebotInbound)' -count=1
ok   Scardice-core/dice
ok   Scardice-core/core/messageflow

## Round 7 fixes

- The one-shot readiness gate is now guarded by `sync.Once`; repeated successful `OnOpen` calls during reconnect cannot panic while the drain remains released.
- Runtime diagnostics retain completed wrapper drop counts in a cumulative counter before connection deletion, then add active wrapper counts for the current snapshot.
- The pre-existing EventConnect/disconnect ordering behavior is outside this Task1 bounded-ingress seam and was not broadened; this round only hardens reconnect readiness and historical diagnostics.

### Round 7 GREEN evidence

```text
go test ./evsocket/v2 -run 'Test(ConnectReadySignalIsIdempotentAcrossReconnects|WrapperEventQueueIsBounded|TransportMessageIsBoundBeforeCopy)' -count=1
ok   github.com/PaienNate/pineutil/evsocket/v2

go test ./dice -run 'TestOnebotRuntimeDiagnostics(RetainCompletedTransportDrops|ExposeIngressCounters)' -count=1
ok   Scardice-core/dice
```

## Round 8 fixes

- Completed-wrapper transport drops now use a per-wrapper last-accounted baseline. Reconnects no longer add a wrapper's lifetime cumulative count twice; diagnostics combine the exact historical delta with the active wrapper delta. A focused two-snapshot regression covers counts 3 then 5 producing cumulative 5, not 8.
- `connectReady` signaling is idempotent across reconnects via `sync.Once`, and a full terminal-only queue gives a new disconnect event priority over queued non-disconnect terminal events while remaining bounded. Duplicate/unadmittable terminal events are still counted rather than blocking shutdown.

### Round 8 GREEN evidence

```text
go test ./evsocket/v2 -run 'Test(ConnectReadySignalIsIdempotentAcrossReconnects|WrapperEventQueueIsBounded|TransportMessageIsBoundBeforeCopy)' -count=1
ok   github.com/PaienNate/pineutil/evsocket/v2

go test ./dice -run 'TestOnebotRuntimeDiagnostics(RetainCompletedTransportDrops|ExposeIngressCounters)' -count=1
ok   Scardice-core/dice
```

## Round 9 fixes

- Diagnostics now loads the cumulative transport-drop counter only after acquiring the same connection/drop locks used by completion accounting. A completed reconnect cannot interleave between the cumulative load and active-wrapper delta snapshot.

### Round 9 GREEN evidence

```text
go test ./dice -run 'TestOnebotRuntimeDiagnostics(RetainCompletedTransportDrops|ExposeIngressCounters)' -count=1
ok   Scardice-core/dice
```

## Round 10 fixes

- Oversized transport frames now fail fast: after incrementing the bounded drop counter, `OnMessage` sends WebSocket close code 1009 (`message too large`) when a socket is available, while retaining a nil-safe path for deterministic unit tests. The frame is never copied or admitted to the wrapper queue.

### Round 10 GREEN evidence

```text
go test ./evsocket/v2 -run 'TestTransportMessageIsBoundBeforeCopy' -count=1
ok   github.com/PaienNate/pineutil/evsocket/v2
```


- Runtime terminal admission now uses a separate bounded priority channel, preserving disconnect/connect/auth-failed control delivery without blocking callbacks. Oversized transport close behavior is nil-safe and bounded.

```text
go test ./dice -run 'TestOnebotRuntime(PriorityEventEvictsInboundAdmission|Diagnostics(RetainCompletedTransportDrops|ExposeIngressCounters))' -count=1
ok   Scardice-core/dice
```

## Round 11 fixes

- Runtime control events use a separate bounded priority channel consumed by the Run loop before ordinary ingress events. Connect, disconnect, and auth-failed events cannot be displaced by a saturated inbound channel or an unrelated queue head; the priority channel remains nonblocking and bounded.
- Transport-drop baselines now live in the active connection state and are deleted with the connection. Reconnect deltas remain exact without retaining a map entry for every disconnected wrapper.

### Round 11 GREEN evidence

```text
go test ./dice -run 'TestOnebotRuntime(PriorityEventEvictsInboundAdmission|InboundRetryIsBounded|Diagnostics(RetainCompletedTransportDrops|ExposeIngressCounters)|InboundQueueBackpressureIsNonBlocking)' -count=1
ok   Scardice-core/dice

go test ./evsocket/v2 -run 'TestTransportMessageIsBoundBeforeCopy' -count=1
ok   github.com/PaienNate/pineutil/evsocket/v2
```


## Round 12 fixes

- Control ingress now has bounded per-kind slots for connect, disconnect, and auth-failed events. Repeated controls coalesce and increment `priority.coalesced`; they never block or silently displace a different control kind. Run drains all control slots before ordinary ingress processing.
- The wrapper queues EventConnect with disconnect/error lifecycle events, preserving callback ordering through reconnect and shutdown.
- Active connection state carries the drop baseline, so disconnected wrapper pointers are not retained.

### Round 12 GREEN evidence

```text
go test ./dice ./core/messageflow -run 'Test(InboundService|OnebotInbound|OnebotRuntime(PriorityEventCoalescesAndPreemptsInbound|InboundRetryIsBounded|Diagnostics(RetainCompletedTransportDrops|ExposeIngressCounters)|InboundQueueBackpressureIsNonBlocking|KeepsAliveOnRetryableInboundError))' -count=1
ok   Scardice-core/dice
ok   Scardice-core/messageflow

go test ./evsocket/v2 -run 'Test(WrapperEventQueueIsBounded|ShutdownWaitDrainsQueuedWrapperEvents|ConnectReadySignalIsIdempotentAcrossReconnects|TransportMessageIsBoundBeforeCopy)' -count=1
ok   github.com/PaienNate/pineutil/evsocket/v2
```

## Round 13 fixes

- Run now performs a nonblocking priority drain before entering the ordinary select loop, while retaining dedicated priority cases for controls arriving concurrently. A focused regression confirms distinct connect and disconnect controls remain available while duplicate disconnects coalesce and are diagnosed.

### Round 13 GREEN evidence

```text
go test ./dice -run 'TestOnebotRuntime(PriorityEventCoalescesAndPreemptsInbound|DiagnosticsExposeIngressCounters|InboundRetryIsBounded)' -count=1
ok   Scardice-core/dice
```

## Round 14 fixes

- Server wrapper registration is now lifecycle-bounded: failed upgrades and failed reader starts unregister immediately, and terminal server transport closure unregisters the wrapper after terminal events are queued. Client wrappers remain registered for reuse/reconnect.
- A churn regression registers and unregisters 128 server wrappers and verifies the instance registry returns to zero.

### Round 14 GREEN evidence

```text
go test ./evsocket/v2 -run 'Test(ServerWrapperRegistryUnregistersChurn|WrapperEventQueueIsBounded|ShutdownWaitDrainsQueuedWrapperEvents|TransportMessageIsBoundBeforeCopy)' -count=1
ok   github.com/PaienNate/pineutil/evsocket/v2

go test ./dice -run 'TestOnebotRuntime(PriorityEventCoalescesAndPreemptsInbound|Diagnostics(RetainCompletedTransportDrops|ExposeIngressCounters)|InboundRetryIsBounded)' -count=1
ok   Scardice-core/dice
```

## Round 15 fixes

- Server wrappers now mark terminal closure but defer registry removal until their queued terminal callbacks have drained. This preserves `ShutdownWait`'s callback-drain contract while still preventing registry retention after lifecycle completion. Failed upgrade/start-reader paths continue to unregister immediately.
- Added a lifecycle regression that queues a server disconnect callback, waits for callback completion, and verifies registry removal only after the drain.

### Round 15 GREEN evidence

```text
go test ./evsocket/v2 -run 'Test(ServerWrapperRegistryUnregistersChurn|ServerWrapperUnregistersAfterTerminalCallbacksDrain|ShutdownWaitDrainsQueuedWrapperEvents|WrapperEventQueueIsBounded)' -count=1
ok   github.com/PaienNate/pineutil/evsocket/v2
```

## Round 16 fixes

- Restored safe-pool removal in `finalizeTransportClose`, preventing dead wrappers from remaining in Broadcast/Shutdown pool state.
- Added a transport-open drop baseline captured by `OnOpen`; runtime connection state uses that baseline rather than sampling after queued EventConnect delivery, so pre-EventConnect transport drops are accounted in the subsequent close delta.
- Added focused pool cleanup and pre-connect baseline regressions.

### Round 16 GREEN evidence

```text
go test ./evsocket/v2 -run 'Test(ServerWrapperRegistryUnregistersChurn|ServerWrapperUnregistersAfterTerminalCallbacksDrain|TransportDropBaselineCapturesPreConnectDrops|ShutdownWaitDrainsQueuedWrapperEvents)' -count=1
ok   github.com/PaienNate/pineutil/evsocket/v2

go test ./dice -run 'TestOnebotRuntime(DiagnosticsRetainCompletedTransportDrops|PriorityEventCoalescesAndPreemptsInbound)' -count=1
ok   Scardice-core/dice
```