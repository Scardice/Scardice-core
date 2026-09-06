# Task 4 — Deterministic synchronous projection and rebuild

## Status

Implemented and committed A3 projection behavior in `eventstore` only.

## Changed files

- `eventstore/store.go`: store-local stable projector descriptors and deterministic name ordering; backward-compatible A2 callback registration; synchronous live projector application in the existing UnitOfWork transaction; active-generation context and terminal-position/projector-set control updates.
- `eventstore/projection.go`: generation-aware projection row helper/reader, canonical SHA-256 digest, keyset event scanning, checksum/schema validation, shadow generation rebuild, catch-up, publication fence, and generation publication.
- `eventstore/projection_test.go`: registration/version validation, live write/rollback, 1,024-event rebuild and digest equality, checksum/schema refusal, generation-independent digest, and active-generation reader coverage.

## Registration/version contract

`ProjectionDescriptor` carries stable `Name`, `Version`, and transactional `Apply(context.Context, *gorm.DB, []Envelope) error`; `ProjectorDescriptor`, `ProjectorRegistration`, and `ProjectorSpec` are aliases. `RegisterProjection` rejects empty/whitespace names or versions, nil callbacks, duplicate names, and same-name version conflicts. Registrations are owned by each `GORMStore`, copied under its mutex, and sorted by name before application. A descriptor's `SchemaVersion`, `ProjectorSetVersion`, or `ProjectorVersion` fields are accepted as compatibility aliases for `Version`. A set with one version stores that version; mixed descriptor versions use the deterministic `name=version|...` form.

The existing `RegisterProjector(Projector)` form remains supported for A2 callers using deterministic legacy names/version `legacy`. Descriptor callers can use either `RegisterProjection` or `RegisterProjector`; `WithProjector` accepts both forms and `WithProjection` is provided for descriptors.

## Live protocol

A2's existing transaction still acquires `projection_control` first, then aggregate heads, then the global sequence. After event insertion/sequence/head/participant work, the current active generation is placed in the GORM transaction context and registered projectors consume the newly inserted envelopes in caller/global allocation order and deterministic projector-name order. `UpsertProjectionRow` writes only to that generation. Projector errors return `ErrProjectorFailure`, causing the existing transaction rollback; events, heads, sequence, control updates, participant rows, and projection rows remain unchanged.

## Rebuild and publication protocol

Rebuild validates the requested projector-set version, reads the current active control and sequence high-water, allocates a UUID generation ID, and scans `domain_events` ascending by `global_position` with the keyset predicate `global_position > cursor AND global_position <= highWater`, `LIMIT 1000`. Every row is reconstructed into a fresh envelope, copied without payload aliasing, checked for supported schema version 1, and verified against its persisted A1 checksum before any projector callback. Each shadow page is applied in its own transaction with only the new generation context; no publication fence is held during the scan or catch-up.

Catch-up repeats pages while lag exceeds 1,000. The final transaction begins, locks `projection_control` first using the existing dialect-aware locking helper (SQLite uses the validated `_txlock=immediate` configuration), then locks/reads the latest sequence, applies the final tail, validates generation/name/key invariants, computes the canonical digest, updates active generation/terminal/projector-set version/publication state, and commits exactly once. The previous generation is never deleted and remains queryable by explicit generation. Any checksum/schema/projector/invariant/digest/publication error rolls the final transaction back, leaving active control and its terminal unchanged.

`ReadProjectionRow` begins one read transaction, captures control's active generation once, and selects all data by that captured generation; it cannot mix generations. Registered callbacks receive only persisted envelopes and their transaction; no adapter, JS, subscriber, HTTP, timer, effect-dispatch, or runtime callback is invoked by this implementation.

## Digest canonicalization

Digest domain tag: `eventstore.projection.digest.v1`. Rows are ordered explicitly by `projection_name ASC, row_key ASC`; generation is deliberately excluded. Each row streams length-prefixed canonical string field names and values (`projection_name`, `row_key`, `payload`) through the existing typed canonical scalar encoding, including explicit type and null markers. Payload bytes are copied as a non-null byte scalar unless nil, which retains its null marker. No database row order, timestamps, generation ID, or ad-hoc JSON affects the digest.

## TDD evidence

Red, before implementation:

```text
go test ./eventstore -run 'TestProjection|TestRebuild|TestDigest|TestProjector|TestGeneration' -count=1
# eventstore/projection_test.go:24:60: undefined: ProjectionDescriptor
# eventstore/projection_test.go:29:9: undefined: UpsertProjectionRow
# eventstore/projection_test.go:36:18: store.RegisterProjection undefined
# ...
FAIL Scardice-core/eventstore [build failed]
```

Green focused race validation:

```text
go test -race ./eventstore -run 'TestProjection|TestRebuild|TestDigest|TestProjector|TestGeneration'
ok   Scardice-core/eventstore  1.679s
```

Green package validation:

```text
go test ./eventstore
ok   Scardice-core/eventstore  0.432s
```

No formatter, linter, or project-wide suite was run.

## Commit

Implementation commit: `a1ee6229` (`eventstore: add deterministic synchronous projections`).

## Concerns

- The pre-existing A2 function-only registration has no caller-supplied stable name/version; it is retained as a deterministic legacy compatibility path. New A3 code should use `ProjectionDescriptor` registrations.
- Remote-dialect lock behavior is implemented through GORM's existing `FOR UPDATE` clause but was not exercised without remote credentials. SQLite immediate/WAL behavior was exercised by the focused race and package tests.
