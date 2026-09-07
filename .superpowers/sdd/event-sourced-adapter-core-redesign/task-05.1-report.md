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
