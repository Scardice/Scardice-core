# Slice 05.6 controlled privacy purge

Implemented the durable SQLite/GORM history scrubber and core orchestration state machine.

## Focused verification

- `go test ./eventstore ./core/privacypurge ./core/messageflow -run 'Privacy|Callback|DryRun|Confirm' -count=1` — pass.
- `go test ./eventstore -count=1` — pass.
- Earlier focused contract checks (`go test ./core/privacypurge -count=1` and targeted eventstore tests) — pass.

No formatter, linter, or project-wide suite was run.

## Changed files

- `eventstore/contracts.go`: bounded privacy count, dry-run, encrypted operation context, batch, and narrow repository contracts.
- `eventstore/privacy.go`: keyed dry-run digest, subject HMAC fence, operation-private A6 encryption/CAS, bounded 500-record/8 MiB keyset deletion, pending-work resolution, projection publication, anonymized append-only audit, and scrub.
- `eventstore/store.go`, `eventstore/task5.go`, `eventstore/schema.go`, `eventstore/database.go`: fenced aggregate and inbox/outbox subject admission; opaque SubjectKey persisted on inbox/outbox rows and audit table support.
- `core/privacypurge/service.go`: dry-run/confirm/resume state machine with constant-time confirmation and resumable failure behavior.
- `api/privacy_service.go`, `api/group.go`: composition and additive route fields while retaining legacy fields.
- `main.go`: registers purge service only when the configured durable event store exists; no legacy fallback is presented as durable purge.
- Focused tests under `eventstore/` and `core/privacypurge/`.

## Coverage and residual risks

The event-store coverage is exact for `group_record`, `players`, and `attrs`; legacy GroupInfo/GroupPlayerInfo/group-attrs tables, moderation, encrypted plugin KV, logs, user-global characters, external stores, and backups are returned as uncovered and are not claimed as durably purged. A configured durable backend and A6 key source are required; without them confirmation fails closed. Confirmation is rechecked after fencing; operation ownership is bound to the keyed subject and the original digest/version is encrypted for resume. Projection rebuilding publishes a new generation and deletes prior generations before readiness publication. Ingress acceptance, callback effects, and outbound Submit carry the same opaque SubjectKey; matching fences reject admission and missing keys fail closed while a fence exists. Pending inbox/outbox rows resolve by SubjectKey rather than lane_hmac. Batch deletion validates operation identity/private selector, cursor, readiness, and the 500-record/8 MiB bounds. Completion uses an owner-checked atomic finalizer that removes the fence, appends an anonymized audit record (operation/scopes digests and counts), marks terminal status, and scrubs private context in one transaction. Active state is supplied as an explicit authoritative snapshot and included in the dry-run digest; omitted snapshots fail closed for destructive confirmation. Completion with uncovered stores returns a non-success API result (`completed-uncovered` plus `ErrUncoveredData`) so covered deletion is not overclaimed.
