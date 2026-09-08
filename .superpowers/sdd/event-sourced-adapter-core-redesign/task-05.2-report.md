# Slice 05 Task 2 — Group state and deletion ownership

## Status

Implemented the smallest standalone Group-state boundary in `core/groupstate`. Group record facts are typed, replayable, projection-backed, and value-copied for compatibility reads. Group attrs, group-user attrs, player records, and moderation have separate stream identities and are not represented in Group event payloads.

No UI repository files were changed.

## Ownership inventory

| Legacy concern | Existing legacy locations | Task 2 owner | Stream/projection boundary |
|---|---|---|---|
| Group activation and per-dice existence/active membership | `dice/im_helpers.go`, `dice/im_session.go`, provider adapters | Group record | `group/<diceID>/<groupID>` (`AggregateType=group`) |
| Group name, guild/channel identity, invite/entered facts | `dice/im_session.go`, `dice/platform_adapter_*.go` | Group record | Group stream |
| Extension enabled/inactivated membership | `dice/ext.go`, `dice/builtin_commands.go`, `dice/config.go` | Group record | Group stream; extension pointers/runtime are not persisted |
| System/template/roll-shaper settings | `dice/builtin_commands.go`, `dice/ext_coc7.go`, `dice/im_vars.go`, `dice/im_session.go` | Group record | Group stream |
| Help packages/default help group | `dice/dice_help.go`, `dice/builtin_commands.go`, `dice/im_session.go` | Group record | Group stream |
| Welcome enabled/message | `dice/ext_fun.go`, `dice/im_session.go` | Group record | Group stream |
| Bot list | `dice/builtin_commands.go`, `dice/im_session.go` | Group record | Group stream |
| Explicit group privilege facts (while runtime `PrivilegeLevel` remains derived from sender/player context) | `dice/im_session.go` privilege filling and command checks | Group record event vocabulary | Group stream |
| Group-local attributes | `model/attrs.go`, `dice/service/attrs_new.go`, `dice/dice_attrs_manager.go` | Dedicated attrs owner | `attrs/group/<diceID>/<groupID>` |
| Group-user attrs and character binding | `model/attrs.go`, `dice/service/attrs_new.go`, `dice/dice_attrs_manager.go` | Dedicated attrs owner | `attrs/group-user/<diceID>/<groupID>/<userID>` |
| Player records | `model/group_info.go`, `dice/service/group_info.go`, `dice/im_session.go` | Later Task 3 player owner | `player/<diceID>/<groupID>/<userID>` |
| Moderation/ban/censor state | `dice/dice_ban.go`, `dice/dice_censor.go`, `dice/config.go` | Separate moderation owner | `moderation/group/<diceID>/<groupID>` helper only; no Group event carries moderation |

## Implementation

- `events.go` defines a closed typed event vocabulary for creation, activation, name, extension, system, template, help, welcome, bot-list, privilege, and group-record deletion facts. Payloads are concrete `*V1` structs and can be encoded/decoded by event type.
- `aggregate.go` defines value `State`, immutable `Clone`, pure `Reduce`, typed envelope validation, ordered `Replay`, and `ReplayEnvelopes`. Envelope replay checks schema, stream version, aggregate type, and group identity.
- `projection.go` registers the generation-aware `group-record`/`v1` projector. The projector rebuilds each Group state from event envelopes using the existing `eventstore.UpsertProjectionRow` contract. `ReadProjected` returns a deep value copy; mutating it cannot mutate projection/reducer state.
- `repository.go` provides `Load`, `Append`, `AppendTyped`, and `DecideAndAppend` as the one Group-record write seam. It also defines stream helpers and a deletion planning contract.
- Deletion planning preserves default `group_record`, explicit scopes, `dryRun`, and `allowActive`. A group-record plan contains only the Group stream. An attrs plan contains the group attrs stream and a group-user attrs prefix; player plans contain a player prefix. Moderation is never silently included.

## Writer migration

Every writer represented by this implemented path goes through `Repository.DecideAndAppend` and the typed `Command` vocabulary: activation, name, extension, system, template, help, welcome, bot-list, privilege, create, and record deletion. There is no second Group event writer in `core/groupstate`.

The pre-existing Dice runtime writers listed in the inventory remain compatibility writers until the later messageflow/Dice-host wiring task can inject an eventstore repository into `Dice` without creating a second authority. They were not speculatively migrated here: changing those concrete legacy callers now would require callback execution, attrs/player loading, and startup repository wiring owned by later Slice 05 tasks. The existing API delete handler already executes `group_record`, `players`, and `attrs` branches independently; this task adds the same ownership decision as a reusable pure plan rather than claiming the legacy DB is already event-backed.

## TDD evidence

### RED

```text
go test ./core/groupstate -run 'TestGroup' -count=1

core/groupstate/groupstate_test.go:13:14: undefined: TypedEvent
core/groupstate/groupstate_test.go:14:3: undefined: NewGroupCreatedV1
core/groupstate/groupstate_test.go:23:11: undefined: State
core/groupstate/groupstate_test.go:26:16: undefined: Reduce
FAIL
```

The initial focused test failed because the typed Group event/reducer/projection API did not exist.

### GREEN

```text
go test ./core/groupstate -count=1

ok   Scardice-core/core/groupstate  0.019s
```

The focused tests cover typed replay, exclusion of attrs/moderation payloads, independent stream identities, immutable compatibility reads, projection live writes and rebuild, deletion scopes, dry-run/allowActive, and repository availability behavior.

No formatter, linter, or project-wide suite was run, as required by the task brief.

## Changed files

- `core/groupstate/events.go`
- `core/groupstate/aggregate.go`
- `core/groupstate/commands.go`
- `core/groupstate/projection.go`
- `core/groupstate/repository.go`
- `core/groupstate/groupstate_test.go`
- `.superpowers/sdd/event-sourced-adapter-core-redesign/task-05.2-report.md`

## Limitations and handoff

- The later player/character task owns player streams, attrs event reducers, and user-global character ownership.
- The later callback task owns wiring this repository into the durable inbound callback and migrating concrete Dice runtime callers.
- The later purge task owns destructive append-only history deletion, fencing, batching, and resumable operations. This task exposes deletion ownership/planning but does not implement purge service behavior.
- LSP/codegraph was unavailable; the inventory uses precise repository searches, as recorded in the prior Slice 05 report.
