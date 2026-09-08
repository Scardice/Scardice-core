# Task 05.4 — Durable callback execution

## Ownership and transition matrix

| Owner | Responsibility | Durable transition |
| --- | --- | --- |
| `InboxRepository` | Lane ordering, lease owner/epoch/attempt, callback marker, terminal payload scrub | `pending → leased → callback-started → confirmed-consumed` or `ambiguous`; callback-started/ambiguous are never auto-rerun |
| `CallbackService` | Decode/decrypt, scope resolution, pure read-model loading, marker CAS, one host invocation, one atomic commit | Host is called only after `callback-started`; ordinary terminal completion has no workflow ID |
| `MutationCollector` | Sole host mutation output; deterministic streams, encrypted PluginKV updates, encrypted effects | Duplicate stream/participant and bounds are rejected before commit; `$t` data is rejected from durable output |
| `eventstore.Store` | Atomic stream, participant, effect, PluginKV, workflow, and inbox commit | Any participant failure rolls back the complete UnitOfWork |
| Compatibility host | Mutable legacy decision seam | Receives copied Group/Player/attrs views, normalized message/scope, one request-local `$t` overlay, and one collector |

## Retry and ambiguity semantics

1. `ProcessOne` uses only `ClaimInbox`; claim ordering and A4 lease checks remain in eventstore.
2. Decryption, strict ingress decoding, scope resolution, and all three read-model loads happen before the marker. A failure marks the leased row `failed` (best effort), never invokes the host, and never commits callback mutations.
3. A marker CAS conflict retries the entire claim/load/marker sequence at most three times. The host is not called during these retries.
4. After `callback-started`, host errors and panics mark the row `ambiguous`. A UnitOfWork validation/commit error also attempts the same ambiguous transition. Recovery and subsequent claims cannot auto-run callback-started or ambiguous rows.
5. Successful callbacks submit exactly one UnitOfWork, including the terminal inbox transition even when no streams/effects/plugin state were collected. Terminal transitions scrub ciphertext and nonce.

## Workflow exception

Ordinary callbacks cannot add a `message-workflow` stream and leave `InboxUpdate.WorkflowID` empty. A host may return a nonempty bounded workflow ID only together with a `message-workflow.terminated` event. The service validates the named event and appends it with the terminal inbox update in the same UnitOfWork. Eventstore permits the link only from an unresolved callback-started row, checks the exact lease/version fields, rejects malformed/conflicting identities, and never permits an existing WorkflowID to be changed.

## TDD RED/GREEN evidence

- RED: `go test ./core/messageflow -run 'Callback' -count=1` initially failed because `NewCallbackService`/`CallbackConfig` were absent.
- RED: `go test ./eventstore -run 'Task4Workflow' -count=1` initially failed with `eventstore: invalid state transition` for callback-started → confirmed-consumed plus workflow linking.
- GREEN focused proof:
  - `go test ./core/messageflow -run 'Callback|Workflow|Inbox|Atomic|Ambiguous' -count=1`
  - `go test ./eventstore -run 'Task4Workflow' -count=1`

## Changed files

- `core/messageflow/callback.go`: callback service, strict payload decoder, callback DTOs, collector, workflow validation, retry/ambiguity handling.
- `core/messageflow/callback_test.go`: fake repository/codec/host tests for marker ordering, load/decode rejection, retries, panic/commit ambiguity, atomic output, workflow rules, overlay exclusion, and duplicate streams.
- `eventstore/task5.go`: callback-started terminal success transition and bounded immutable WorkflowID linking for UOW/direct inbox updates.
- `eventstore/task4_workflow_test.go`: SQLite workflow-link success, invalid-link rollback, and participant-failure rollback tests.

## Deferred boundary

No concrete Dice writer, `dice/core_compat.go`, duplicate `Execute` path, purge service, or JS facade was added. Slice06 owns mutable compatibility redesign; later work can consume the narrow `CompatibilityHost` seam without moving provider SDK pointers or raw ingress payloads into callback DTOs.
