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
ok  Scardice-core/eventstore  0.023s
```

Required package command:

```text
go test ./eventstore
ok  Scardice-core/eventstore  0.039s
```

No formatter, linter, race run, or project-wide test suite was run, as required. Remote integration tests were not run because they must remain opt-in and no credentials were supplied.

## Concerns and scope boundaries

- Remote connectivity is policy-tested before attempting a connection; live MySQL/PostgreSQL integration remains an opt-in deployment check.
- This task intentionally implements only database ownership/opening/schema. It does not implement UnitOfWork, projections, inbox/outbox behavior, encryption, readiness service behavior, startup wiring, adapters, API, or UI.
- The generic generation-keyed `projection_read_models` table is schema support only; later tasks own its projection behavior.

## Commit

Implementation commit SHA: `385c7fda`.

## Review follow-up

Follow-up implementation commit: `81b7a35f`.

- Replaced dialect-invalid `type:blob` tags with native `[]byte` mappings. MySQL size tags select sufficient `mediumblob`/`longblob` capacity while PostgreSQL uses `bytea`; SQLite remains `blob`.
- Added restrictive operation-artifact → operation foreign-key enforcement and SQLite assertions for `RESTRICT` delete/update actions plus orphan rejection.
- Tightened MySQL TLS acceptance to only verified `true`/`verify-full` modes.
- Propagated a bounded `QueryTimeout` context through migration, singleton initialization, schema, and index validation.
- Added runtime index contract validation for required names, ordered columns, and uniqueness.
- Hardened loopback/Unix PostgreSQL exceptions to require every effective host in a parsed host list to be loopback or Unix; mixed/ambiguous/fallback hosts are rejected.
- Added regression tests for restrictive FKs, TLS downgrade/custom rejection, and mixed PostgreSQL host lists.

Focused and package tests were rerun after these fixes and passed.

## Review follow-up 2

Follow-up implementation commit: `f04a6921`.

- Disabled GORM automatic remote pings and MySQL version initialization before the explicitly bounded `PingContext`; schema migration, singleton initialization, and all runtime invariants use a bounded query context.
- Parsed PostgreSQL URL query host overrides and keyword host lists; every effective host must be loopback or Unix, with mixed, fallback, and ambiguous whitespace forms rejected.
- Added restrictive foreign keys for artifact-to-operation, operation-to-artifact, and subject-fence-to-purge-operation references, including orphan rejection/action tests.
- Runtime schema validation now checks both required unique and required non-unique index semantics and every ordered composite column contract.
- Added immediate single-writer contention and failed SQLite initialization/recovery tests.
- Restricted MySQL TLS to the driver's certificate-verifying `tls=true` mode; `preferred`, `skip-verify`, and unregistered custom names fail closed.

Final verification after this follow-up:

```text
go test ./eventstore -run 'TestOpenDatabase|TestEventStoreSchema|TestDatabaseClose'
ok  Scardice-core/eventstore  0.033s
go test ./eventstore
ok  Scardice-core/eventstore  0.146s

```
Additional round-two hardening commit: `a85a7c9e`.

- Remote GORM opens now skip automatic foreign-key creation until all tables exist, then add the restrictive relationships in a deterministic second phase; SQLite keeps GORM's native cyclic-constraint migration path.
- PostgreSQL URL query hosts are treated as effective hosts, and keyword DSNs with malformed/ambiguous whitespace tokens fail closed.
- MySQL acceptance is limited to `tls=true`, the driver's certificate-verifying built-in mode.

Final post-hardening evidence:

```text
go test ./eventstore -run 'TestOpenDatabase|TestEventStoreSchema|TestDatabaseClose'
ok  Scardice-core/eventstore  0.041s
go test ./eventstore
ok  Scardice-core/eventstore  (cached)
```

## Review follow-up 3

Follow-up implementation commit: `ced22571`.

- Restored `domain_events.payload` as a required native `[]byte` column with a 256 KiB size declaration; the SQLite schema test asserts its presence, native blob type, and non-null contract.
- Rejected duplicate MySQL `tls` keys, duplicate PostgreSQL URL/keyword `sslmode` keys, duplicate keyword hosts, and ambiguous effective settings.
- Split PostgreSQL URL-query host lists on commas before loopback/Unix validation; mixed remote hosts reject while all-loopback lists pass.
- Kept MySQL acceptance to the driver's built-in certificate-verifying `tls=true` mode.

Final uncached verification:

```text
go test -count=1 ./eventstore -run 'TestOpenDatabase|TestEventStoreSchema|TestDatabaseClose'
ok  Scardice-core/eventstore  0.038s
go test -count=1 ./eventstore
ok  Scardice-core/eventstore  0.151s
```

## Review follow-up 4

Follow-up implementation commit: `c2ce960c`.

- Restored both `domain_events.payload` and the complete A1 metadata sequence, including `command_id` immediately before `correlation_id`; a schema test now asserts every required domain-event column.
- Rejected PostgreSQL keyword settings with whitespace-separated key/equal/value fragments, duplicate `sslmode`/`host` entries, and ambiguous malformed tokens.
- Rechecked duplicate MySQL URL TLS keys and duplicate/effective PostgreSQL URL host/TLS settings; URL host lists are comma-split before loopback/Unix validation.

Final uncached verification:

```text
go test -count=1 ./eventstore -run 'TestOpenDatabase|TestEventStoreSchema|TestDatabaseClose'
ok  Scardice-core/eventstore  0.034s
go test -count=1 ./eventstore
ok  Scardice-core/eventstore  0.154s
```
 
## Review follow-up 4b

Follow-up implementation commit: `fcfe8f60`.

- Restored the full `domain_events` metadata contract and made SQLite PRAGMA setup use the caller-bounded context for every statement/readback.
- Removed the unusable reverse `operations.artifact_id -> operation_artifacts` FK. The operation artifact row and subject fence retain restrictive dependent-to-operation FKs; `operations.artifact_id` remains an application-validated nullable reference.
- SQLite creates the operation-artifact dependent table with its restrictive FK before GORM migration, while remote constraint creation remains a second phase after all tables exist.
- Added a valid nullable-first operation/artifact linking regression: create operation, create artifact, set `artifact_id`, and verify deleting the referenced operation is restricted.

Final uncached verification:

```text
go test -count=1 ./eventstore -run 'TestOpenDatabase|TestEventStoreSchema|TestDatabaseClose'
ok  Scardice-core/eventstore  0.044s
go test -count=1 ./eventstore
ok  Scardice-core/eventstore  0.170s
```
