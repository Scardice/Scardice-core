# Slice 05 Task 3 — Player/Character ownership

## Status

Implemented `core/playerstate` as a pure, typed, replayable boundary for player records, group-user attrs/binding, user-global character sheets, and moderation. Compatibility reads are value copies. `$t` remains a request-local `LocalOverlay`; it is not represented by any event or aggregate state.

Sensitive attr and character contents are represented only as `EncryptedValue{Ciphertext, KeyID}`. Event JSON therefore carries opaque ciphertext bytes (base64 JSON encoding), never plaintext values. Increment/delete/clear operations remain ordered facts; increment does not attempt to decrypt or invent a plaintext value.

## Ownership inventory

| Legacy concern | Existing readers/writers | New owner | Deletion identity |
|---|---|---|---|
| Player display name, last-command timestamp, auto-name template, per-player privilege compatibility value | `model/group_info.go:GroupPlayerInfoBase`; `dice/im_session.go:GroupPlayerInfo`; `dice/im_helpers.go:GetPlayerInfoBySenderRaw`; `dice/service/group_info.go:GroupPlayerInfoGet/Save`; `dice/config.go` save loop; `dice/builtin_commands.go`, `dice/ext_log.go`, `dice/ext_st_helper.go` direct mutation | Player aggregate | `player`, canonical `(diceID, groupID, userID)` stream; group players prefix |
| Active group-user binding, local attribute values, ordered set/increment/delete/clear operations | `model/attrs.go:AttributesItemModel`; `dice/service/attrs_new.go`; `dice/dice_attrs_manager.go:Load`, `LoadByCtx`, `CharBind`, `CharGetBindingId`; `dice/im_vars.go` attr access | Group-user attrs aggregate | `attrs/group-user`, canonical `(diceID, groupID, userID)` stream; group-user prefix |
| User-global character sheet identity/name/type and encrypted sheet contents | `model/attrs.go`; `dice/service/attrs_new.go:AttrsNewItem/AttrsPutById/AttrsDeleteById/AttrsGetCharacterListByUserId`; `dice/dice_attrs_manager.go:CharNew/CharDelete/GetCharacterList` and SealChat character handlers | Character aggregate | `character`, canonical `(diceID, userID, characterID)` stream. No group ID; character ID isolates multiple sheets for one user. DiceID is the deployment/Dice partition, not a conversation/group purge scope. |
| Ban score/rank and moderation decision metadata | `dice/dice_ban.go`; `dice/dice_censor.go`; `dice/config.go:BanList`; moderation checks in `dice/im_session.go` | Moderation aggregate (separate from Player and attrs) | `moderation/group`, canonical `(diceID, groupID, subjectID)` stream; group purge uses a moderation prefix; reason is a digest only |
| `$t` temporary variables | `dice/im_vars.go:SetTempVars/VarSetValue/VarGetValue`; many command/extensions | Request-local `LocalOverlay` | No stream, no event, no projection field |

## Contracts

- `PlayerEvent`, `GroupUserAttrsEvent`, `CharacterEvent`, and `ModerationEvent` are sealed typed event interfaces.
- Pure reducers (`ReducePlayer`, `ReduceGroupUserAttrs`, `ReduceCharacter`, `ReduceModeration`) copy state before applying facts. Replay requires creation at version zero and rejects mutation after deletion.
- Repository seams (`Append*Typed`, `Load*`, `DecideAndAppendPlayer`) use `eventstore.Store`, injected event factories, stream CAS versions, and generation-aware projectors. Typed append replays persisted and candidate envelopes before commit, so malformed first events, identity mismatches, duplicate creation, and mutation-after-delete are rejected without a projector.
- Projections (`PlayerProjection`, `GroupUserAttrsProjection`, `CharacterProjection`, `ModerationProjection`) strictly decode existing rows, reject unknown/trailing/null payloads, and expose deep-copy compatibility reads.
- `PlanDelete` selects player/attrs/character/moderation prefixes only where identity is explicit. Group-wide character deletion is rejected; `PlanDeleteForUser` validates the canonical user scope. Moderation streams are keyed by subject, and group moderation deletion is a prefix.

## TDD evidence

### RED

```text
go test ./core/playerstate -run 'TestOwnership|TestPlayer|TestOpaque' -count=1

core/playerstate/playerstate_test.go:13:12: undefined: PlayerStream
core/playerstate/playerstate_test.go:14:11: undefined: GroupUserAttrsStream
core/playerstate/playerstate_test.go:15:15: undefined: CharacterStream
...
FAIL
```

The focused tests first failed because the player/character ownership package and contracts did not exist.

### GREEN

```text
go test ./core/playerstate -run 'TestOwnership|TestPlayer|TestOpaque|TestMultiple' -count=1

ok   Scardice-core/core/playerstate  0.024s
```

Coverage includes disjoint streams and purge prefixes, player replay and immutable reads, request-local exclusion, opaque attrs/character payloads, ordered attr operation semantics, repository replay, projections, attrs-only purge selection, and multiple character stream isolation.

## Strictness follow-up

The focused regressions also cover bounded scoped identities (including character IDs, binding IDs, subjects, and purge users), typed-nil event rejection before interface method dispatch, payload-size rejection before JSON parsing, reducer version-overflow rejection, and two moderation subjects replaying in independent streams while remaining covered by one group purge prefix.

## Writer migration boundary

No legacy Dice runtime writer was migrated in this task. The current writers remain compatibility writers until the later messageflow/Dice-host wiring can inject one repository and commit all already-decided streams in one UnitOfWork. In particular, `dice/config.go` still calls `service.GroupPlayerInfoSave`, `AttrsManager.CheckForSave` still calls `AttrsPutsByIDBatch`, character APIs still call legacy attrs services, and ban/censor paths still mutate `Config.BanList`. Removing only those calls here would create a second authority or lose callback state, so this task intentionally exposes narrow repository seams and records the deferral rather than claiming cutover. No callback execution, JS compatibility, purge service, or duplicate Execute path is implemented.

LSP/codegraph references were unavailable in this checkout; the inventory uses precise repository searches and the existing Task 05.2 inventory. No formatter, linter, or project-wide suite was run.

## Changed files

- `core/playerstate/events.go`
- `core/playerstate/aggregate.go`
- `core/playerstate/commands.go`
- `core/playerstate/projection.go`
- `core/playerstate/repository.go`
- `core/playerstate/playerstate_test.go`
- `.superpowers/sdd/event-sourced-adapter-core-redesign/task-05.3-report.md`
