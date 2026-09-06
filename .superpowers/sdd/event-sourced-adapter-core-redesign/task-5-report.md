# Task 5 report — ordered inbox/outbox and encrypted artifacts

## Changed files

- `eventstore/contracts.go`: ordered-lane constants, typed errors, resolution/lease/dispatch/completion/artifact request/result types, codec seam, and narrow repository interfaces. `Store` remains aggregate-only.
- `eventstore/schema.go`: durable resolution audit fields and bounded outbox retry metadata.
- `eventstore/store.go`: injected clock, ID generator, and payload codec options with production defaults. `Commit` preserves atomic UoW expiry scrub when a participant returns `ErrPayloadExpired`: it rolls back the failed UoW and persists only the scrub in a compensating transaction.
- `eventstore/task5.go`: transactional inbox/outbox acceptance, lane allocation, provider dedupe, predecessor-blocked claims, lease/CAS lifecycle, resolution, payload scrubbing/expiry, risk transitions, and artifact put/consume. Final hardening uses retained keyed digests for scrub-safe replay, validates opaque replay metadata before dedupe, enforces nonce size 12, requires active leases for worker status changes, rejects generic terminal rewrites and leased-to-terminal completion, preserves retry metadata, records UoW callback start time, and keeps the inbox transition table intact. UoW artifact creation fails closed without a codec and verifies decrypted plaintext size against the declared size and 32 MiB artifact bound.
- `eventstore/task5_test.go`: behavior-first regression coverage for dedupe, lane ordering/concurrency, lease/CAS/state transitions, ambiguity, scrubbing/TTL, artifact codec/size/expiry/one-winner, fail-closed encryption, strict participant contracts, stable digest replay, terminal rewrite rejection, pending termination rejection, nonce boundaries, participant supplied-version checks, sparse leased-effect identity, replay bounds, callback timestamps, and compensating UoW expiry scrubbing; completion coverage dispatches before terminal completion and rejects a terminal replay without an active lease.
- `eventstore/store_test.go`: migrated legacy participant fixtures to the injected test codec and valid opaque artifact metadata while retaining aggregate/UoW compatibility coverage without allowing arbitrary ingress state injection.
`Store.Commit` participant application runs through the same transaction-bound invariant helpers: new inbox/effect rows ignore caller ordering, reject invalid status/risk/lease/encryption metadata, allocate typed lanes, enforce dedupe and TTL caps, and reject direct artifact terminal/oversize updates. Existing participant updates retain expected-version and active-lease CAS; terminal rows cannot be rewritten through the aggregate-only store.
## Algorithms and transitions

Acceptance starts one database transaction, checks inbox provider dedupe `(endpoint_id, provider_event_id)`, then materializes/locks the typed `lane_heads` row and allocates `NextSequence`. Caller ordering values are ignored. The head update and message/effect insert commit together, so row failure rolls back the head. Inbox and outbox use distinct lane kinds. Dedupe compares retained keyed content digests after scrub; when no digest was supplied, it compares live ciphertext/nonce and refuses scrubbed replay rather than guessing content identity. Claims use ordered candidates with a same-lane predecessor `NOT EXISTS` query; no `SKIP LOCKED` or process-global mutex is used. Non-SQLite dialects use the existing `FOR UPDATE` helper, while SQLite relies on its immediate transaction and busy timeout.
Inbox unresolved states are `pending`, `leased`, `callback-started`, and `ambiguous`. Only pending work or expired pre-callback leases are claimable. Callback start is persisted before external work, including through UoW participant updates. Lease owner, epoch, attempt, expiry, and expected row version are checked atomically, including `lease_expiry > now` in every worker mutation CAS. Explicit operator resolutions are `confirmed-consumed`, `retry`, and `skip`; retry returns to pending only while ciphertext is inside the 30-day TTL. Ambiguous/callback-started predecessors block later lane items. Terminal outcomes scrub ciphertext and nonce in the same commit. Observed callback-started/ambiguous expiry is scrubbed and returns `ErrPayloadExpired`; UoW expiry uses a compensating scrub transaction after rolling back the failed participant work.
Outbox accepts only `pending` and the declared risk classes `pre-dispatch-retryable`, `provider-idempotent`, and `non-idempotent-after-dispatch`. Claims use the same predecessor algorithm. Renew, dispatch marker, and completion require effect/owner/epoch/attempt CAS and an active lease. Dispatch allocates a fresh attempt ID and persists `dispatched_at` before provider I/O. Completion rejects stale leases and leased-to-terminal transitions; matching terminal completion is idempotent only while the lease remains active, scrubs terminal payloads, and records result metadata. Expired post-dispatch non-idempotent or pre-dispatch-only work becomes `ambiguous`; provider-idempotent work may be reclaimed with a saturating retry count. Retry metadata (`retry_count`, `next_attempt_at`, `deadline_at`) is retained across update/resolution paths, and leased→pending/ambiguous transitions scrub expired payloads before returning `ErrPayloadExpired`.
Artifacts accept plaintext only through the injected codec boundary, cap plaintext and stored ciphertext at 32 MiB, default to 10 minutes, and reject TTLs over 60 minutes. Without a codec/key boundary, put, consume, and UoW artifact creation fail closed with `ErrEncryptionUnavailable`; plaintext-as-ciphertext fallback is not used. Consume/expiry is one transaction with a row CAS: one winner decrypts and returns plaintext, losers/expired requests receive `ErrArtifactGone` without terminal-loser mutation, and ciphertext/nonce are scrubbed before commit. Commit errors return a zero `ArtifactResult`, never plaintext.

## TDD evidence

The initial focused run was intentionally red before production implementation:

```text
go test ./eventstore -run 'TestTask5' -count=1
# FAIL: undefined WithClock, WithPayloadCodec, status constants, and repository methods
```

After the narrow implementation, the same behavior tests passed. The tests assert observable outcomes rather than row existence alone, including monotonic concurrent allocation, blocked successors, stale lease rejection, active-lease terminal completion, ambiguity, scrubbed bytes, codec round-trip, bounded artifacts, no-codec rollback, participant supplied-version validation, sparse leased-effect identity, opaque replay bounds, callback timestamps, and compensating UoW expiry scrubbing.

## Verification

Exact required commands and results:

```text
go test -race ./eventstore -run 'TestInbox|TestOutbox|TestArtifact|TestLane|TestLease|TestEffect|TestDedup' -count=1
ok   Scardice-core/eventstore  1.422s

go test -count=1 ./eventstore
ok   Scardice-core/eventstore  0.830s
```

The commands were rerun after the final source/test commits and included the Task5 tests whose names match the required filters. No formatter, linter, or project-wide suite was run.

## Commits

- Implementation and tests: `0470750b` (`eventstore: add ordered inbox outbox and artifacts`)
- Lease/completion and scrub hardening: `19330c86`, `ab3a177f`
- Participant bypass closure, strict UoW invariants, TTL/expiry scrub coverage: `b0fd9b28`, `a276823a`
- Strict ingress, dedupe conflict, canonical lane ordering, artifact ownership/status/TTL, and participant contract hardening: `2828cb0c`
- Lease lifecycle guard requiring identity for generic leased updates: `87de65fa`
- UoW replay/expiry, compensating scrub transactions, callback timestamps, and active ambiguity expiry: `faec2583`
## Limitation

Verification exercised SQLite, including its race path. Live MySQL/PostgreSQL integration and remote `FOR UPDATE` execution were not available in this focused environment; dialect-aware locking remains opt-in through the existing helper and should be covered by deployment-specific credentials/integration tests.
