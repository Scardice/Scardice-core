# Task 2 report — independent durable event database

## Files

- `eventstore/database.go`: `DatabaseConfig`, independent `OpenDatabase`, bounded pool setup, SQLite effective PRAGMA configuration/validation, remote TLS policy validation, redacted errors, and idempotent per-instance close ownership.
- `eventstore/schema.go`: GORM models, explicit table names, indexes/unique indexes, singleton/head rows, generation-keyed read-model support, encrypted-field columns, HMAC-keyed fence columns, and readiness root/manifest fields.
- `eventstore/database_test.go`: focused TDD coverage for SQLite defaults/effective settings, schema and index contracts, singleton initialization, idempotent migration/reopen, remote invalid-config redaction, and double close.

## Schema and ownership decisions

- SQLite defaults to `${DATADIR}/events.db` (or `./events.db` when `DATADIR` is unset). The DSN requests WAL, foreign keys, a 15-second busy timeout, FULL synchronous durability, and immediate write transactions. The owned SQL pool is limited to one open/idle connection; effective `journal_mode`, `foreign_keys`, `busy_timeout`, and `synchronous` values are read back and rejected if unsafe.
- Remote MySQL/PostgreSQL opens require an explicit DSN and explicit verified-TLS configuration, unless `AllowInsecureLoopback` is explicitly enabled for a loopback or Unix-socket DSN. Remote pools have bounded open/idle counts and connection lifetime plus a bounded connection ping context. Errors intentionally omit raw DSNs and driver error text so credentials/query secrets cannot leak.
- The schema creates `domain_events`, `event_global_sequence`, `aggregate_heads`, `projection_control`, `projection_read_models`, `operations`, `operation_artifacts`, `lane_heads`, `inbox_messages`, `outbox_effects`, `adapter_secrets`, `plugin_kv`, `subject_fences`, and `store_readiness`.
- Explicit unique indexes cover event stream/version, event ID, global position, operation ID/idempotency scope, artifact ID, inbox endpoint/provider key and lane/sequence, outbox effect ID and lane/sequence, adapter secret ref/version, plugin extension/key HMAC, and subject fence key/scope. Claim/dispatch indexes begin with the required status and timing columns. Singleton initialization and count invariants cover global sequence, projection control, and readiness rows.
- No package-global database handle or open-once state is used. A `Database` instance owns its SQL pool; `Close` serializes ownership and is harmless when called repeatedly. Schema failures close the partially opened pool.

## Verification

Required focused command:

```text
go test ./eventstore -run 'TestOpenDatabase|TestEventStoreSchema|TestDatabaseClose'
ok  Scardice-core/eventstore  0.016s
```

Required package command:

```text
go test ./eventstore
ok  Scardice-core/eventstore  (cached)
```

No formatter, linter, race run, or project-wide test suite was run, as required. Remote integration tests were not run because they must remain opt-in and no credentials were supplied.

## Concerns and scope boundaries

- Remote connectivity is policy-tested before attempting a connection; live MySQL/PostgreSQL integration remains an opt-in deployment check.
- This task intentionally implements only database ownership/opening/schema. It does not implement UnitOfWork, projections, inbox/outbox behavior, encryption, readiness service behavior, startup wiring, adapters, API, or UI.
- The generic generation-keyed `projection_read_models` table is schema support only; later tasks own its projection behavior.

## Commit

Commit SHA: pending final commit.
