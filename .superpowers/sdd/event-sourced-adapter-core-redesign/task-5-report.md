# Task 5 report — ordered inbox/outbox and encrypted artifacts

## Changed files

- `eventstore/contracts.go`: ordered-lane constants, typed errors, resolution/lease/dispatch/completion/artifact request/result types, codec seam, and narrow repository interfaces. `Store` remains aggregate-only.
- `eventstore/schema.go`: durable resolution audit fields and bounded outbox retry metadata.
- `eventstore/store.go`: injected clock, ID generator, and payload codec options with production defaults. `Commit` rolls back a failed UoW and, for payload/artifact expiry, runs detached bounded compensating transactions that scrub every expired inbox/outbox participant and every eligible (`available`/`ready`) expired artifact in canonical table/ID order; compensation errors are returned instead of claiming expiry was scrubbed.
- `eventstore/task5.go`: transactional inbox/outbox acceptance, lane allocation, provider dedupe, predecessor-blocked claims, lease/CAS lifecycle, resolution, payload scrubbing/expiry, risk transitions, and artifact put/consume. Public accepts reject supplied versions, defer incoming TTL validation until after existing-row expiry observation, and restore default/cap validation for new rows; public updates validate versions and reject ignored identity/opaque/lifecycle fields, dispatched terminal completion is reserved for `CompleteOutbox`, and stale-lease paths scrub observed expiry before returning. Expired replay handling scrubs before dedupe/conflict evaluation; UoW initial dedupe/relookup returns typed expiry before idempotent success and non-pending status mutations require an active lease. Non-idempotent dispatched outbox expiry transitions to `ambiguous` with resolution metadata preserved. Loaded scrub paths avoid version churn when bytes are already absent. Artifact commit failures return a zero result and never expose decrypted bytes.
- `eventstore/task6.go`: A6 plugin key-index HMAC recomputation with constant-time comparison, readiness terminal/publication validation, startup fail-closed readiness gating, index-root material fingerprint pinning, rotation preflight, and redacted artifact authentication/unavailability mapping.
- `eventstore/contracts.go`: separate payload-encryption and stable content-digest key identities for inbox/effect records, while retaining the legacy field as a compatibility fallback.
- `eventstore/schema.go`: durable index-root fingerprint in the readiness singleton.
- `eventstore/task5_test.go`: behavior-first regression coverage for dedupe, lane ordering/concurrency, lease/CAS/state transitions, ambiguity, scrubbing/TTL, artifact codec/size/expiry/one-winner, fail-closed encryption, strict participant contracts, stable digest replay, terminal rewrite rejection, pending termination rejection, nonce boundaries, participant supplied-version checks, sparse leased-effect identity, replay bounds, callback timestamps, public immutable-field/version validation, terminal completion idempotence, stale-lease expiry scrubbing, corrupt codec rejection, multi-artifact compensation, consumed-artifact compensation exclusion, expired replay precedence, explicit expired/default/capped ingress TTLs, commit-error zero-result plaintext protection, and compensating UoW expiry scrubbing.
- `eventstore/store_test.go`: migrated legacy participant fixtures to sparse artifact updates while retaining aggregate/UoW compatibility coverage without allowing arbitrary ingress state injection.
`Store.Commit` participant application runs through the same transaction-bound invariant helpers: new inbox/effect rows ignore caller ordering, reject invalid status/risk/lease/encryption metadata, allocate typed lanes, enforce dedupe and TTL caps, and reject direct artifact terminal/oversize updates. Existing participant updates retain expected-version and active-lease CAS; terminal rows cannot be rewritten through the aggregate-only store.
- `eventstore/database.go`, `eventstore/projection.go`: SQLite artifact payload-version migration/defaults and unified readiness gating for projection reads/rebuilds.
- `eventstore/task6_test.go`: A6 ingress fixtures now use the explicit payload-encryption key field required when a key source is configured.
## Algorithms and transitions

Acceptance starts one database transaction, checks inbox provider dedupe `(endpoint_id, provider_event_id)`, then materializes/locks the typed `lane_heads` row and allocates `NextSequence`. Caller ordering values are ignored. The head update and message/effect insert commit together, so row failure rolls back the head. Inbox and outbox use distinct lane kinds. Dedupe compares retained keyed content digests after scrub; when no digest was supplied, it compares live ciphertext/nonce and refuses scrubbed replay rather than guessing content identity. Claims use ordered candidates with a same-lane predecessor `NOT EXISTS` query; no `SKIP LOCKED` or process-global mutex is used. Non-SQLite dialects use the existing `FOR UPDATE` helper, while SQLite relies on its immediate transaction and busy timeout.
A6-enabled inbox/outbox rows now carry separate rotatable payload encryption key IDs and stable index-root content-digest key IDs. Readiness records pin a SHA-256 fingerprint of index-root material (without storing the material); startup and rotation validate the pin before allowing writes. Plugin key indexes are recomputed from decrypted keys and checked with `hmac.Equal`; artifact authentication failures remain distinct from unavailable key-source errors.
Inbox unresolved states are `pending`, `leased`, `callback-started`, and `ambiguous`. Only pending work or expired pre-callback leases are claimable. Callback start is persisted before external work, including through UoW participant updates. Lease owner, epoch, attempt, expiry, and expected row version are checked atomically, including `lease_expiry > now` in every worker mutation CAS. Explicit operator resolutions are `confirmed-consumed`, `retry`, and `skip`; retry returns to pending only while ciphertext is inside the 30-day TTL. Ambiguous/callback-started predecessors block later lane items. Terminal outcomes scrub ciphertext and nonce in the same commit. Observed expiry is scrubbed before stale-lease responses and returns `ErrPayloadExpired`; UoW compensation scrubs all expired participants before returning the typed error, and UoW initial dedupe/relookup rejects expired replay before idempotent success.
Outbox accepts only `pending` and the declared risk classes `pre-dispatch-retryable`, `provider-idempotent`, and `non-idempotent-after-dispatch`. Claims use the same predecessor algorithm. Renew, dispatch marker, and completion require effect/owner/epoch/attempt CAS and an active lease, but observed payload expiry is scrubbed before lease errors. Dispatch allocates a fresh attempt ID and persists `dispatched_at` before provider I/O. Generic public updates cannot complete dispatched work; completion rejects stale leases and leased-to-terminal transitions. Exact terminal completion replays for the same attempt are idempotent even after the lease is cleared, while mismatched attempts remain stale. Expired post-dispatch non-idempotent work transitions to `ambiguous` with resolution metadata preserved, regardless of which public/UoW/resolution observer first sees expiry; repeat observation with no bytes is a no-op.
Artifacts accept plaintext only through the injected codec boundary, cap plaintext and stored ciphertext at 32 MiB, default to 10 minutes, and reject TTLs over 60 minutes. Without a codec/key boundary, put, consume, and UoW artifact creation fail closed with `ErrEncryptionUnavailable`; plaintext-as-ciphertext fallback is not used. Consume/expiry is one transaction with a row CAS: one winner decrypts and returns plaintext only when decoded length matches stored size and remains within the cap, losers/expired requests receive `ErrArtifactGone`, and ciphertext/nonce are scrubbed before commit. `ready` and `available` are consumed/expired consistently; compensation only rewrites eligible non-terminal rows and skips already-scrubbed rows, so consumed/terminal artifacts keep their state/version. Commit errors return a zero `ArtifactResult`, never plaintext.
All Task5 and A6 persistence APIs pass through the cached startup readiness gate before opening transactions; only readiness inspection/repair methods bypass that gate. Reopened non-empty stores with invalid readiness therefore remain read-only/quarantined across inbox, outbox, aggregate, projection, secret, plugin, and artifact paths. Operation private payloads and inbox/outbox/artifact payloads persist an immutable `PayloadVersion`/`PrivatePayloadVersion` (default 1); status/version CAS updates never modify it, and claims, consume, validation, and root rotation use the persisted value for AAD. SQLite artifact migration upgrades legacy tables with payload version 1 defaults.

## TDD evidence

The initial focused run was intentionally red before production implementation:

```text
go test ./eventstore -run 'TestTask5' -count=1
# FAIL: undefined WithClock, WithPayloadCodec, status constants, and repository methods
```

After the narrow implementation, the same behavior tests passed. The tests assert observable outcomes rather than row existence alone, including monotonic concurrent allocation, blocked successors, stale lease rejection, stale-version expiry precedence, active-lease terminal completion, terminal replay idempotence, ambiguity, scrubbed bytes, codec round-trip, bounded artifacts, no-codec rollback, participant supplied-version validation, sparse leased-effect identity, opaque replay bounds, callback timestamps, public immutable-field rejection, artifact expiry immutability, unsupported-codec fail-closed behavior, stale-lease expiry scrubbing, corrupt decoded-size rejection, dispatched completion contract, multi-artifact compensation that excludes consumed rows, plugin key-index tamper rejection, empty-database import terminal checks, same-ID changed-material readiness quarantine, startup gate rejection for nonempty fresh stores, and rotation preflight rejection.

## Verification

Exact required commands and results:

```text
go test -race ./eventstore -run 'TestInbox|TestOutbox|TestArtifact|TestLane|TestLease|TestEffect|TestDedup' -count=1
ok  	Scardice-core/eventstore	1.362s

go test -race ./eventstore -run 'TestReadiness|TestKey|TestCrypto|TestSecret|TestPlugin|TestKV|TestRotation|TestA6|TestEncryption' -count=1
ok  	Scardice-core/eventstore	1.643s

go test -count=1 ./eventstore
ok  	Scardice-core/eventstore	0.788s
```

The commands were rerun after the final source/test commits and included the Task5 tests whose names match the required filters. No formatter, linter, or project-wide suite was run.
The final source/test hardening commit also passed `go test ./eventstore -run 'Test(SQLite|Database|Schema)' -count=1` and `go test -race ./eventstore -run 'TestA6|TestReadiness|TestKey|TestCrypto|TestSecret|TestPlugin|TestKV|TestRotation|TestEncryption' -count=1`. No formatter, linter, or project-wide suite was run.

## Commits

- Implementation and tests: `0470750b` (`eventstore: add ordered inbox outbox and artifacts`)
- Lease/completion and scrub hardening: `19330c86`, `ab3a177f`
- Participant bypass closure, strict UoW invariants, TTL/expiry scrub coverage: `b0fd9b28`, `a276823a`
- Strict ingress, dedupe conflict, canonical lane ordering, artifact ownership/status/TTL, and participant contract hardening: `2828cb0c`
- Lease lifecycle guard requiring identity for generic leased updates: `87de65fa`
- Final Task5 bypass/expiry/codec/terminal-idempotence hardening: `caf959fe`.
- Expiry observation ordering, conflict-safe effect insertion, artifact compensation/bounds, and strict completion contract: `f24a93a2`.
- Artifact compensation status compatibility and report refresh: `0da12e1c`.
- Stale-version expiry precedence across public/UoW/resolution paths and regression coverage: `ea42b89d`.
- Dispatched outbox update expiry scrub and regression coverage: `6830225f`.
- Final expiry observation, replay scrub-before-conflict, UoW initial-dedupe expiry, non-idempotent dispatch ambiguity, and terminal artifact compensation exclusion: `b8174220`.
- Replay assertion refinement and final verification refresh: `95b6c90d`.
- Consumed-artifact compensation coverage and final suite rerun: `99190962`.
- Final review closure: post-lookup TTL ordering, UoW non-pending lease enforcement, commit-error artifact zero-result protection, and regression coverage: `e883a075`.
- UoW pending terminal fixture migration to stable `ErrStaleLease` semantics and final suite rerun: `aa8f3f9c`.
- A6 encrypted repository hardening, readiness startup/fingerprint gates, stable digest-key separation, and plugin/artifact authentication coverage: `a1afa714`.
- Readiness gate unification, canonical payload/digest key enforcement, encrypted plugin delete/quota integrity, plugin key root references, immutable AAD payload versions, and SQLite migration compatibility: `d49cd789`.
## Limitation

Verification exercised SQLite, including its race path. Live MySQL/PostgreSQL integration and remote `FOR UPDATE` execution were not available in this focused environment; dialect-aware locking remains opt-in through the existing helper and should be covered by deployment-specific credentials/integration tests.
