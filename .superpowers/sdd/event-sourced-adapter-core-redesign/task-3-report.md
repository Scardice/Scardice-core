# Task 3 — Optimistic multi-stream UnitOfWork

## Status

Implemented and committed the A2 database-backed eventstore commit path. The narrow `Store` interface remains `Commit`, `Load`, and `Close`.

## Changed files

- `eventstore/store.go`: typed `*Database` store wiring (no raw GORM bypass), pre-transaction UnitOfWork validation, SQLite/GORM transaction commit path, canonical lock order, aggregate head materialization and CAS conflicts, contiguous event positions, immutable event insertion, checksum verification, participant persistence/CAS, rollback-safe participant/projector hooks, and checksum-validating load.
- `eventstore/contracts.go`: bounded encoded-size accounting across stream IDs, event types, metadata fields, and participant bytes, duplicate participant-key validation with structural tuple keys, and redacted participant conflict labels.
- `eventstore/store_test.go`: TDD commit-path coverage for caller-order/contiguous positions, empty/duplicate/oversize work, complete stream conflicts, typed/redacted participant conflicts, lock ordering, zero-stream participant updates, sparse operation/artifact/inbox/effect/plugin/fence preservation, secret history/delete semantics, projector rollback including hook writes, checksum corruption, and concurrent opposing stream order.

## A2 behavior

The event-bearing path acquires locks in this order:

1. `projection_control` singleton (dialects supporting row locks use `FOR UPDATE`; SQLite relies on its configured immediate transaction)
2. Missing/materialized `aggregate_heads`, read in lexicographic `(AggregateType, AggregateID)` order (row-lock clause on non-SQLite dialects)
3. `event_global_sequence` singleton (only when at least one event is present; row-lock clause on non-SQLite dialects)

Expected versions are compared for every requested stream after all heads are read. A `ConflictError` contains every stale stream's identity and expected/current versions and no event content. Events are allocated and emitted in the original `UnitOfWork.Streams` order and each stream's original event order; lock sorting never reorders emitted events. SQLite's configured immediate transaction provides single-writer serialization. Zero-stream participant-only work does not read or advance `event_global_sequence`.

The event sequence is advanced once for one contiguous range. Domain event rows contain exact payload bytes, metadata scalars, stream version, global position, and checksum. `Load` verifies persisted checksum bytes before returning an envelope.

Participant rows are applied in the exact A2 order `operations -> inbox_messages -> outbox_effects -> operation_artifacts -> adapter_secrets -> plugin_kv -> subject_fences`, with stable key sorting inside each group and optimistic row-version checks. Every conditional update requires one affected row and returns a redacted `ParticipantConflictError` (unwrapping `ErrParticipantConflict`) on a lost CAS; true SQL failures remain `ErrParticipantFailure`. Duplicate participant keys use structural tuple keys, and the aggregate encoded byte budget includes stream IDs, event type, metadata strings, and all persisted participant fields; both are rejected before transaction allocation. Every stream/global/participant version increment is checked against uint64 exhaustion. Existing sparse updates preserve durable state across all participant columns, secret updates append immutable history rows, and plugin/fence creates, updates, and deletes report their keys in `CommitResult` while using expected-version CAS. Transaction-aware participant/projector hooks receive the same transaction and are never invoked as external side effects. Hook errors are redacted to typed `ErrParticipantFailure`/`ErrProjectorFailure`. Any error rolls back heads, sequence, events, hook writes, and participant rows together. No domain decision callback or projector callback is retried.


## TDD evidence

Red state before implementation:

```text
go test ./eventstore -run 'TestCommit'
# Scardice-core/eventstore [Scardice-core/eventstore.test]
eventstore/store_test.go:13:11: undefined: NewStore
FAIL	Scardice-core/eventstore	[build failed]
FAIL
```

Green focused race run:

```text
go test -race ./eventstore -run 'TestCommit|TestMultiStreamConflict|TestLockOrder|TestRollback|TestChecksum' -count=1
ok  Scardice-core/eventstore  1.241s
```

Green package run:

```text
go test ./eventstore -count=1
ok  Scardice-core/eventstore  0.270s
```

No formatter, linter, or project-wide test suite was run.

## Commit

Implementation commits: `9fc13ec5` (atomic UnitOfWork), `636ff72f` (redacted participant keys), `89426b55` (artifact CAS persistence), `b32a9be6` (locks/transaction-only hooks/participant CAS), `cb355ca1` (sparse preservation/history/delete), `17ce7d0d` (validation/fence/hook evidence), `a896bcbd` (delete result consistency), `2812e553` (plugin update results), `ffc6cfd1` (participant order/typed-store/sparse inbox-effect/encoded-size), `ed03ae73` (overflow-safe field accounting), `92c1e34c` (metadata/CAS/structural-key hardening), `c8e7aa4d` (version exhaustion guards/regression).
Additional focused regression: `go test -race ./eventstore -run 'TestZeroStream|TestParticipantConflict' -count=1` → `ok Scardice-core/eventstore 1.073s`; `TestVersionExhaustionRejectsWithoutMutation` passes under race.

- SQLite and GORM paths are covered locally. Remote MySQL/PostgreSQL integration remains opt-in because no remote credentials are available.
- SQLite cannot represent uint64 values with the high bit set in its INTEGER driver path, so the exhaustion regression exercises the shared max-value guards directly; production DB paths reject overflow before writes.
