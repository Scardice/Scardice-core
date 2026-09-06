# Task 5 report — ordered inbox/outbox and encrypted artifacts

## Changed files

- `eventstore/contracts.go`: ordered-lane constants, typed errors, resolution/lease/dispatch/completion/artifact request/result types, codec seam, and narrow repository interfaces. `Store` remains aggregate-only.
- `eventstore/schema.go`: durable resolution audit fields and bounded outbox retry metadata.
- `eventstore/store.go`: injected clock, ID generator, and payload codec options with production defaults.
- `eventstore/task5.go`: transactional inbox/outbox acceptance, lane allocation, provider dedupe, predecessor-blocked claims, lease/CAS lifecycle, resolution, payload scrubbing/expiry, risk transitions, and artifact put/consume.
- `eventstore/task5_test.go`: behavior-first regression coverage for dedupe, lane ordering/concurrency, lease/CAS/state transitions, ambiguity, scrubbing/TTL, artifact codec/size/expiry/one-winner, and fail-closed encryption.

## Algorithms and transitions

Acceptance starts one database transaction, checks inbox provider dedupe `(endpoint_id, provider_event_id)`, then materializes/locks the typed `lane_heads` row and allocates `NextSequence`. Caller ordering values are ignored. The head update and message/effect insert commit together, so row failure rolls back the head. Inbox and outbox use distinct lane kinds. Claims use ordered candidates with a same-lane predecessor `NOT EXISTS` query; no `SKIP LOCKED` or process-global mutex is used. Non-SQLite dialects use the existing `FOR UPDATE` helper, while SQLite relies on its immediate transaction and busy timeout.

Inbox unresolved states are `pending`, `leased`, `callback-started`, and `ambiguous`. Only pending work or expired pre-callback leases are claimable. Callback start is persisted before external work. Lease owner, epoch, attempt, expiry, and expected row version are checked atomically. Explicit operator resolutions are `confirmed-consumed`, `retry`, and `skip`; retry returns to pending only while ciphertext is inside the 30-day TTL. Ambiguous/callback-started predecessors block later lane items. Terminal outcomes scrub ciphertext and nonce in the same commit. TTL scrub retains status, metadata, keyed digest, and identifiers and returns `ErrPayloadExpired`, preventing retry.

Outbox accepts only `pending` and the declared risk classes `pre-dispatch-retryable`, `provider-idempotent`, and `non-idempotent-after-dispatch`. Claims use the same predecessor algorithm. Renew, dispatch marker, and completion require effect/owner/epoch/attempt CAS. Dispatch allocates a fresh attempt ID and persists `dispatched_at` before provider I/O. Completion rejects stale leases, is idempotent for the same terminal result, scrubs terminal payloads, and records result metadata. Expired post-dispatch non-idempotent or pre-dispatch-only work becomes `ambiguous`; provider-idempotent work may be reclaimed. Retry counters saturate at `math.MaxUint32`.

Artifacts accept plaintext only through the injected codec boundary, cap plaintext at 32 MiB, default to 10 minutes, and reject TTLs over 60 minutes. Without a codec/key boundary, put and consume fail closed with `ErrEncryptionUnavailable`; plaintext-as-ciphertext fallback is not used. Consume/expiry is one transaction with a row CAS: one winner decrypts and returns plaintext, losers/expired requests receive `ErrArtifactGone`, and ciphertext/nonce are scrubbed before commit.

## TDD evidence

The initial focused run was intentionally red before production implementation:

```text
go test ./eventstore -run 'TestTask5' -count=1
# FAIL: undefined WithClock, WithPayloadCodec, status constants, and repository methods
```

After the narrow implementation, the same behavior tests passed. The tests assert observable outcomes rather than row existence alone, including monotonic concurrent allocation, blocked successors, stale lease rejection, idempotent completion, ambiguity, scrubbed bytes, codec round-trip, bounded artifacts, and no-codec rollback.

## Verification

Exact required commands and results:

```text
go test -race ./eventstore -run 'TestInbox|TestOutbox|TestArtifact|TestLane|TestLease|TestEffect|TestDedup' -count=1
ok   Scardice-core/eventstore  1.281s

go test -count=1 ./eventstore
ok   Scardice-core/eventstore  0.639s
```

The commands were rerun after the final source/test commits and included the Task5 tests whose names match the required filters. No formatter, linter, or project-wide suite was run.

## Commits

- Implementation and tests: `0470750b` (`eventstore: add ordered inbox outbox and artifacts`)
- Follow-up completion identity hardening: `19330c86` (`eventstore: enforce terminal completion lease identity`)
- Report: committed separately after implementation.

## Limitation

Verification exercised SQLite, including its race path. Live MySQL/PostgreSQL integration and remote `FOR UPDATE` execution were not available in this focused environment; dialect-aware locking remains opt-in through the existing helper and should be covered by deployment-specific credentials/integration tests.
