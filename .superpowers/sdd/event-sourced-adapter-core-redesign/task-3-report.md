# Task 3 — Optimistic multi-stream UnitOfWork

## Status

Implemented and committed the A2 database-backed eventstore commit path. The narrow `Store` interface remains `Commit`, `Load`, and `Close`.

## Changed files

- `eventstore/store.go`: explicit `GORMStore` wiring, pre-transaction UnitOfWork validation, SQLite/GORM transaction commit path, canonical lock order, aggregate head materialization and CAS conflicts, contiguous event positions, immutable event insertion, checksum verification, participant persistence/CAS, rollback-safe participant/projector hooks, and checksum-validating load.
- `eventstore/store_test.go`: TDD commit-path coverage for caller-order/contiguous positions, empty work, complete stream conflicts, lock ordering, zero-stream participant updates, projector rollback, checksum corruption, and concurrent opposing stream order.

No endpoint/provider/API/JS/startup or later projection rebuild/inbox/outbox/encryption services were wired.

## A2 behavior

The event-bearing path acquires locks in this order:

1. `projection_control` singleton
2. Missing/materialized `aggregate_heads`, read in lexicographic `(AggregateType, AggregateID)` order
3. `event_global_sequence` singleton (only when at least one event is present)

Expected versions are compared for every requested stream after all heads are read. A `ConflictError` contains every stale stream's identity and expected/current versions and no event content. Events are allocated and emitted in the original `UnitOfWork.Streams` order and each stream's original event order; lock sorting never reorders emitted events. SQLite's configured immediate transaction provides single-writer serialization. Zero-stream participant-only work does not read or advance `event_global_sequence`.

The event sequence is advanced once for one contiguous range. Domain event rows contain exact payload bytes, metadata scalars, stream version, global position, and checksum. `Load` verifies persisted checksum bytes before returning an envelope.

Participant rows are applied in fixed table order with stable key sorting and optimistic row-version checks. Transaction-aware participant/projector hooks are available for narrow rollback tests; hook errors are redacted to typed `ErrParticipantFailure`/`ErrProjectorFailure`. Any error rolls back heads, sequence, events, and participant rows together. No domain decision callback or projector callback is retried.

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
ok  Scardice-core/eventstore  1.147s
```

Green package run:

```text
go test ./eventstore
ok  Scardice-core/eventstore  0.215s
```

No formatter, linter, or project-wide test suite was run.

## Commit

Implementation commits: `9fc13ec5` (atomic UnitOfWork), `636ff72f` (redacted participant keys), and the artifact CAS-column fix follow-up.
The report is committed as the required Task 3 report follow-up on the same branch.

- SQLite and GORM paths are covered locally. Remote MySQL/PostgreSQL integration remains opt-in because no remote credentials are available.
- Participant payloads are intentionally treated as opaque ciphertext/nonce fields; encryption and business semantics remain later-slice responsibilities.
