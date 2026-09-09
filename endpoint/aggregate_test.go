package endpoint

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"Scardice-core/adapterapi"
)

func testEndpointID(t *testing.T) adapterapi.EndpointID {
	t.Helper()
	id, err := adapterapi.NewEndpointID("endpoint-1")
	if err != nil { t.Fatal(err) }
	return id
}

func testAdapterKey(t *testing.T) adapterapi.AdapterKey {
	t.Helper()
	key, err := adapterapi.NewAdapterKey("fake")
	if err != nil { t.Fatal(err) }
	return key
}

func testConfig() adapterapi.ValidatedConfig {
	return adapterapi.ValidatedConfig{Version: 1, Canonical: []byte(`{"channel":"test"}`), SecretRefs: []adapterapi.SecretRef{{Ref: "secret-ref", Version: 1}}}
}

func createCommand(t *testing.T, id string) Command {
	t.Helper()
	return Command{Kind: CommandCreate, CommandID: id, CorrelationID: "corr-" + id, EndpointID: testEndpointID(t), AdapterKey: testAdapterKey(t), Config: testConfig()}
}

func applyDecision(t *testing.T, state State, decision Decision) State {
	t.Helper()
	for _, event := range decision.Events {
		var err error
		state, err = Apply(state, event)
		if err != nil { t.Fatal(err) }
	}
	return state
}

func TestEndpointAggregateCreateAndDuplicateCreate(t *testing.T) {
	initial := State{}
	cmd := createCommand(t, "create-1")
	first, err := Decide(initial, cmd)
	if err != nil { t.Fatal(err) }
	if len(first.Events) != 1 || len(first.Effects) != 0 { t.Fatalf("create decision = %#v", first) }
	if first.Events[0].ID == "" || first.Events[0].CommandID != cmd.CommandID { t.Fatalf("missing deterministic event identity: %#v", first.Events[0]) }
	state := applyDecision(t, initial, first)
	if state.DesiredState != DesiredStateDisabled || state.Version != 1 { t.Fatalf("state after create = %#v", state) }
	second, err := Decide(state, cmd)
	if err != nil { t.Fatal(err) }
	if len(second.Events) != 0 || len(second.Effects) != 0 { t.Fatalf("duplicate create was not idempotent: %#v", second) }
	if second.Replay == false { t.Fatalf("duplicate command should be marked replay") }
}

func TestEndpointAggregateEnableDuplicateEnableDisable(t *testing.T) {
	state := State{}
	create, err := Decide(state, createCommand(t, "create-1"))
	if err != nil { t.Fatal(err) }
	state = applyDecision(t, state, create)
	expectedEnableVersion := state.Version
	enableCmd := Command{Kind: CommandEnable, CommandID: "enable-1", ID: "enable-1", CorrelationID: "corr-enable", EndpointID: state.EndpointID, ExpectedVersion: expectedEnableVersion, ExpectedVersionSet: true}
	enableCmd.SecretRefs = []adapterapi.SecretRef{{Ref: "enable-secret", Version: 1}}
	enableCmd.Config.SecretRefs = append([]adapterapi.SecretRef(nil), enableCmd.SecretRefs...)
	enable, err := Decide(state, enableCmd)
	if err != nil { t.Fatal(err) }
	if len(enable.Events) != 1 || len(enable.Effects) != 1 { t.Fatalf("enable decision = %#v", enable) }
	if enable.Events[0].DesiredState != DesiredStateEnabled || enable.Effects[0].DesiredVersion != 2 || enable.Effects[0].CorrelationID != enableCmd.CorrelationID { t.Fatalf("enable metadata = %#v", enable) }
	if enable.Effects[0].Kind != EffectStart { t.Fatalf("enable effect = %#v", enable.Effects[0]) }
	state = applyDecision(t, state, enable)
	record := state.ProcessedCommands[enableCmd.CommandID]
	if len(record.EffectIDs) != 1 || record.EffectIDs[0] != enable.Effects[0].ID { t.Fatalf("effect ledger = %#v", record) }
	if _, ok := state.AppliedEffects[enable.Effects[0].ID]; !ok { t.Fatalf("applied effect ledger missing %q", enable.Effects[0].ID) }
	state.OperationState = OperationStateSucceeded
	replay, err := Decide(state, enableCmd)
	if err != nil { t.Fatal(err) }
	if !replay.Replay || len(replay.Events) != 0 || len(replay.Effects) != 0 { t.Fatalf("duplicate enable = %#v", replay) }
	aliasReplay := enableCmd
	aliasReplay.CommandID = ""
	aliasReplay.Kind = ""
	aliasReplay.Type = CommandEnable
	aliasReplay.ExpectedVersion = 0
	aliasReplay.ExpectedVersionSet = false
	aliasReplay.ExpectedAggregateVersion = expectedEnableVersion
	aliasReplay.SecretRefs = nil
	aliasDecision, err := Decide(state, aliasReplay)
	if err != nil || !aliasDecision.Replay { t.Fatalf("command/type/version/reference alias replay = %#v, %v", aliasDecision, err) }
	disable, err := Decide(state, Command{Kind: CommandDisable, CommandID: "disable-1", CorrelationID: "corr-disable", EndpointID: state.EndpointID})
	if err != nil { t.Fatal(err) }
	if len(disable.Effects) != 1 || disable.Effects[0].Kind != EffectStop || disable.Events[0].DesiredState != DesiredStateDisabled { t.Fatalf("disable = %#v", disable) }
}

func TestEndpointAggregateReloginAndRemove(t *testing.T) {
	state := State{}
	create, err := Decide(state, createCommand(t, "create-1")); if err != nil { t.Fatal(err) }
	state = applyDecision(t, state, create)
	enable, err := Decide(state, Command{Kind: CommandEnable, CommandID: "enable-1", CorrelationID: "corr-enable", EndpointID: state.EndpointID}); if err != nil { t.Fatal(err) }
	state = applyDecision(t, state, enable)
	state.OperationState = OperationStateSucceeded
	relogin, err := Decide(state, Command{Kind: CommandRelogin, CommandID: "relogin-1", CorrelationID: "corr-relogin", EndpointID: state.EndpointID}); if err != nil { t.Fatal(err) }
	if len(relogin.Events) != 1 || len(relogin.Effects) != 1 || relogin.Effects[0].Kind != EffectRelogin { t.Fatalf("relogin = %#v", relogin) }
	state = applyDecision(t, state, relogin)
	state.OperationState = OperationStateSucceeded
	remove, err := Decide(state, Command{Kind: CommandRemove, CommandID: "remove-1", CorrelationID: "corr-remove", EndpointID: state.EndpointID}); if err != nil { t.Fatal(err) }
	if remove.Events[0].DesiredState != DesiredStateRemoving || remove.Effects[0].Kind != EffectStop { t.Fatalf("remove = %#v", remove) }
	state = applyDecision(t, state, remove)
	resolve, err := Decide(state, Command{Kind: CommandResolve, CommandID: "resolve-1", CorrelationID: "corr-resolve", EndpointID: state.EndpointID, ObservedState: adapterapi.ObservedStateStopped}); if err != nil { t.Fatal(err) }
	if resolve.Events[0].DesiredState != DesiredStateDeleted { t.Fatalf("resolve = %#v", resolve) }
	state = applyDecision(t, state, resolve)
	if state.DesiredState != DesiredStateDeleted { t.Fatalf("applied resolve state = %#v", state) }
}

func TestEndpointAggregateRejectsDeletedStaleAndConflictingReuse(t *testing.T) {
	state := State{}
	create, err := Decide(state, createCommand(t, "create-1")); if err != nil { t.Fatal(err) }
	state = applyDecision(t, state, create)
	_, err = Decide(state, Command{Kind: CommandEnable, CommandID: "stale", CorrelationID: "corr-stale", EndpointID: state.EndpointID, ExpectedVersion: 0, ExpectedVersionSet: true})
	var rejection *RejectError
	if !errors.As(err, &rejection) || rejection.Code != RejectStaleVersion { t.Fatalf("stale error = %v", err) }
	enable, err := Decide(state, Command{Kind: CommandEnable, CommandID: "enable-1", CorrelationID: "corr-enable", EndpointID: state.EndpointID}); if err != nil { t.Fatal(err) }
	state = applyDecision(t, state, enable)
	_, err = Decide(state, Command{Kind: CommandEnable, CommandID: "enable-1", CorrelationID: "different", EndpointID: state.EndpointID})
	if !errors.As(err, &rejection) || rejection.Code != RejectCommandConflict { t.Fatalf("reuse error = %v", err) }
	state.DesiredState = DesiredStateDeleted
	_, err = Decide(state, Command{Kind: CommandDisable, CommandID: "deleted", CorrelationID: "corr-deleted", EndpointID: state.EndpointID})
	if !errors.As(err, &rejection) || rejection.Code != RejectDeleted { t.Fatalf("deleted error = %v", err) }
}

func TestEndpointAggregatePayloadCopiesAndEventIdentityIsDeterministic(t *testing.T) {
	cmd := createCommand(t, "create-1")
	original := append([]byte(nil), cmd.Config.Canonical...)
	first, err := Decide(State{}, cmd); if err != nil { t.Fatal(err) }
	cmd.Config.Canonical[0] = 'X'
	if !bytes.Equal(first.Events[0].Config.Canonical, original) { t.Fatalf("event config was aliased: %#v", first.Events[0].Config.Canonical) }
	second, err := Decide(State{}, createCommand(t, "create-1")); if err != nil { t.Fatal(err) }
	if first.Events[0].ID != second.Events[0].ID { t.Fatalf("event identity not deterministic: %q != %q", first.Events[0].ID, second.Events[0].ID) }
	if first.Effects != nil { t.Fatalf("create unexpectedly has effect: %#v", first.Effects) }
}

func TestEndpointAggregateRejectsInvalidConfigAndPreservesState(t *testing.T) {
	before := State{}
	cmd := createCommand(t, "bad")
	cmd.Config.Canonical = []byte(`{`)
	_, err := Decide(before, cmd)
	if err == nil { t.Fatal("invalid non-canonical config accepted") }
	if !errors.As(err, new(*RejectError)) { t.Fatalf("error is not typed rejection: %v", err) }
	if !reflect.DeepEqual(before, State{}) { t.Fatalf("state mutated on rejection: %#v", before) }
}

func TestEndpointAggregateConfigAndSecretReferenceUpdate(t *testing.T) {
	state := State{}
	create, err := Decide(state, createCommand(t, "create-1")); if err != nil { t.Fatal(err) }
	state = applyDecision(t, state, create)
	newRefs := []adapterapi.SecretRef{{Ref: "new-secret", Version: 2}}
	update := Command{
		Kind: CommandUpdateConfig, CommandID: "update-1", CorrelationID: "corr-update",
		EndpointID: state.EndpointID, Config: adapterapi.ValidatedConfig{Version: 2, Canonical: []byte(`{"channel":"updated"}`)},
		SecretRefs: newRefs,
	}
	decision, err := Decide(state, update); if err != nil { t.Fatal(err) }
	if len(decision.Events) != 1 || !decision.Events[0].ConfigSet { t.Fatalf("config update = %#v", decision) }
	if len(decision.Events[0].Config.SecretRefs) != 1 || decision.Events[0].Config.SecretRefs[0].Ref != "new-secret" { t.Fatalf("secret refs = %#v", decision.Events[0].Config.SecretRefs) }
	state = applyDecision(t, state, decision)
	newRefs[0].Ref = "mutated"
	if state.Config.SecretRefs[0].Ref != "new-secret" { t.Fatalf("state secret refs were aliased: %#v", state.Config.SecretRefs) }
}

func TestEndpointAggregateUnknownAdapterIsTyped(t *testing.T) {
	cmd := createCommand(t, "unknown")
	state := State{AllowedAdapters: map[adapterapi.AdapterKey]struct{}{}}
	_, err := Decide(state, cmd)
	var rejection *RejectError
	if !errors.As(err, &rejection) || rejection.Code != RejectUnknownAdapter { t.Fatalf("unknown adapter error = %v", err) }
	knownState := State{AllowedAdapters: map[adapterapi.AdapterKey]struct{}{cmd.AdapterKey: {}}}
	decision, err := Decide(knownState, createCommand(t, "known"))
	if err != nil { t.Fatal(err) }
	applied := applyDecision(t, knownState, decision)
	if applied.AllowedAdapters == nil { t.Fatal("allowed-adapter registry was dropped during Apply") }
}

func TestEndpointAggregateGenerationFenceAndDurableObservation(t *testing.T) {
	state := State{}
	var rejection *RejectError
	create, err := Decide(state, createCommand(t, "create-1")); if err != nil { t.Fatal(err) }
	state = applyDecision(t, state, create)
	otherAdapter, err := adapterapi.NewAdapterKey("other")
	if err != nil { t.Fatal(err) }
	_, err = Decide(state, Command{Kind: CommandEnable, CommandID: "wrong-adapter", CorrelationID: "corr-wrong-adapter", EndpointID: state.EndpointID, AdapterKey: otherAdapter})
	if !errors.As(err, &rejection) || rejection.Code != RejectInvalidCommand { t.Fatalf("mismatched adapter key accepted: %v", err) }
	_, err = Decide(state, Command{Kind: CommandEnable, CommandID: "invalid-adapter", CorrelationID: "corr-invalid-adapter", EndpointID: state.EndpointID, AdapterKey: adapterapi.AdapterKey(" ")})
	if !errors.As(err, &rejection) || rejection.Code != RejectInvalidCommand { t.Fatalf("invalid adapter key accepted: %v", err) }
	enable, err := Decide(state, Command{Kind: CommandEnable, CommandID: "enable-1", CorrelationID: "corr-enable", EndpointID: state.EndpointID}); if err != nil { t.Fatal(err) }
	if enable.Events[0].Generation != 1 || enable.Effects[0].Generation != 1 { t.Fatalf("enable generation = %#v", enable) }
	state = applyDecision(t, state, enable)
	if state.Generation != 1 { t.Fatalf("durable generation = %d", state.Generation) }
	_, err = Decide(state, Command{Kind: CommandDisable, CommandID: "overlap", CorrelationID: "corr-overlap", EndpointID: state.EndpointID})
	if !errors.As(err, &rejection) || rejection.Code != RejectInvalidTransition { t.Fatalf("pending overlap = %v", err) }
	state.OperationState = OperationStateSucceeded
	relogin, err := Decide(state, Command{Kind: CommandRelogin, CommandID: "relogin-1", CorrelationID: "corr-relogin", EndpointID: state.EndpointID}); if err != nil { t.Fatal(err) }
	if relogin.Events[0].Generation != 2 || relogin.Effects[0].Generation != 2 { t.Fatalf("relogin generation = %#v", relogin) }
	state = applyDecision(t, state, relogin)
	state.OperationState = OperationStateSucceeded
	state.DesiredState = DesiredStateRemoving
	state.ObservedState = adapterapi.ObservedStateConnected
	_, err = Decide(state, Command{Kind: CommandResolve, CommandID: "spoofed-resolve", CorrelationID: "corr-spoofed", EndpointID: state.EndpointID, ObservedState: adapterapi.ObservedStateStopped})
	if !errors.As(err, &rejection) || rejection.Code != RejectInvalidTransition { t.Fatalf("spoofed resolve = %v", err) }
}

func TestEndpointAggregateRejectsConflictingAliases(t *testing.T) {
	cmd := createCommand(t, "alias")
	cmd.ID = "different"
	_, err := Decide(State{}, cmd)
	var rejection *RejectError
	if !errors.As(err, &rejection) || rejection.Code != RejectInvalidCommand { t.Fatalf("id alias error = %v", err) }
	cmd = createCommand(t, "alias-kind")
	cmd.Type = CommandDisable
	_, err = Decide(State{}, cmd)
	if !errors.As(err, &rejection) || rejection.Code != RejectInvalidCommand { t.Fatalf("kind alias error = %v", err) }
	cmd = createCommand(t, "alias-version")
	cmd.ExpectedVersionSet = true
	cmd.ExpectedAggregateVersion = 1
	_, err = Decide(State{}, cmd)
	if !errors.As(err, &rejection) || rejection.Code != RejectInvalidCommand { t.Fatalf("explicit zero version alias error = %v", err) }
	cmd = createCommand(t, "alias-secret")
	cmd.SecretRefs = []adapterapi.SecretRef{{Ref: "different", Version: 9}}
	_, err = Decide(State{}, cmd)
	if !errors.As(err, &rejection) || rejection.Code != RejectInvalidCommand { t.Fatalf("secret alias error = %v", err) }
}

func TestEndpointAggregateCompletionAndStrictEventIdentity(t *testing.T) {
	var rejection *RejectError
	state := State{}
	create, err := Decide(state, createCommand(t, "create-1")); if err != nil { t.Fatal(err) }
	if _, err := Apply(State{OperationID: "malformed"}, create.Events[0]); err == nil { t.Fatal("non-zero empty-state metadata accepted") }
	state = applyDecision(t, state, create)
	enable, err := Decide(state, Command{Kind: CommandEnable, CommandID: "enable-1", CorrelationID: "corr-enable", EndpointID: state.EndpointID}); if err != nil { t.Fatal(err) }
	state = applyDecision(t, state, enable)
	invalidCompletion, err := Decide(state, Command{Kind: CommandComplete, CommandID: "invalid-complete", CorrelationID: "corr-invalid-complete", EndpointID: state.EndpointID, Generation: state.Generation, CompletionState: OperationStateIdle, ObservedState: adapterapi.ObservedStateInvalid})
	if !errors.As(err, &rejection) || rejection.Code != RejectInvalidCommand { t.Fatalf("invalid completion accepted: %#v", invalidCompletion) }
	_, err = Decide(state, Command{Kind: CommandComplete, CommandID: "mismatched-complete", CorrelationID: "corr-mismatched-complete", EndpointID: state.EndpointID, OperationID: "wrong-operation", Generation: state.Generation, CompletionState: OperationStateSucceeded, ObservedState: adapterapi.ObservedStateConnected})
	if !errors.As(err, &rejection) || rejection.Code != RejectInvalidCommand { t.Fatalf("mismatched completion operation accepted: %v", err) }
	complete, err := Decide(state, Command{Kind: CommandComplete, CommandID: "complete-1", CorrelationID: "corr-complete", EndpointID: state.EndpointID, Generation: state.Generation, CompletionState: OperationStateSucceeded, ObservedState: adapterapi.ObservedStateConnected}); if err != nil { t.Fatal(err) }
	explicitComplete, err := Decide(state, Command{Kind: CommandComplete, CommandID: "complete-1", CorrelationID: "corr-complete", EndpointID: state.EndpointID, OperationID: state.OperationID, Generation: state.Generation, CompletionState: OperationStateSucceeded, ObservedState: adapterapi.ObservedStateConnected}); if err != nil { t.Fatal(err) }
	if complete.Events[0].CommandDigest != explicitComplete.Events[0].CommandDigest { t.Fatal("omitted and explicit completion operation IDs diverged") }
	malformedCompletion := complete.Events[0]
	malformedCompletion.OperationState = OperationStateIdle
	if _, err := Apply(state, malformedCompletion); err == nil { t.Fatal("malformed completion operation state accepted") }
	malformedCompletion = complete.Events[0]
	malformedCompletion.ObservedState = adapterapi.ObservedStateInvalid
	if _, err := Apply(state, malformedCompletion); err == nil { t.Fatal("malformed completion observation accepted") }
	malformedState := state
	malformedState.OperationID = ""
	if _, err := Apply(malformedState, complete.Events[0]); err == nil { t.Fatal("malformed current operation metadata accepted") }
	malformedVersion := state
	malformedVersion.DesiredVersion++
	if _, err := Decide(malformedVersion, Command{Kind: CommandComplete, CommandID: "bad-version-state", CorrelationID: "corr-bad-version-state", EndpointID: state.EndpointID, Generation: state.Generation, CompletionState: OperationStateSucceeded, ObservedState: adapterapi.ObservedStateConnected}); err == nil { t.Fatal("desired-version mismatch accepted by Decide") }
	if _, err := Apply(malformedVersion, complete.Events[0]); err == nil { t.Fatal("desired-version mismatch accepted by Apply") }
	state = applyDecision(t, state, complete)
	bad := complete.Events[0]
	bad.ID = "event-forged"
	bad.CommandID = "forged-command"
	bad.CorrelationID = "forged-correlation"
	bad.Sequence = state.Version + 1
	bad.AggregateVersion = bad.Sequence
	bad.CommandDigest = "forged-digest"
	badReplay := complete.Events[0]
	badReplay.ObservedState = adapterapi.ObservedStateFailed
	if _, err := Apply(state, badReplay); err == nil { t.Fatal("forged replay payload accepted") }
	if _, err := Apply(state, bad); err == nil { t.Fatal("forged event identity accepted") }
}
func TestEndpointAggregateSucceededOperationObservationRefresh(t *testing.T) {
	state := State{}
	create, err := Decide(state, createCommand(t, "refresh-create")); if err != nil { t.Fatal(err) }
	state = applyDecision(t, state, create)
	enable, err := Decide(state, Command{Kind: CommandEnable, CommandID: "refresh-enable", CorrelationID: "refresh-enable", EndpointID: state.EndpointID}); if err != nil { t.Fatal(err) }
	state = applyDecision(t, state, enable)
	completed, err := Decide(state, Command{Kind: CommandComplete, CommandID: "refresh-complete", CorrelationID: "refresh-complete", EndpointID: state.EndpointID, Generation: state.Generation, CompletionState: OperationStateSucceeded, ObservedState: adapterapi.ObservedStateConnected}); if err != nil { t.Fatal(err) }
	state = applyDecision(t, state, completed)
	operationID := state.OperationID
	refreshed, err := Decide(state, Command{Kind: CommandComplete, CommandID: "refresh-observed-failed", CorrelationID: "refresh-observed-failed", EndpointID: state.EndpointID, Generation: state.Generation, CompletionState: OperationStateSucceeded, ObservedState: adapterapi.ObservedStateFailed}); if err != nil { t.Fatal(err) }
	state = applyDecision(t, state, refreshed)
	if state.OperationState != OperationStateSucceeded || state.OperationID != operationID || state.ObservedState != adapterapi.ObservedStateFailed { t.Fatalf("observation refresh state=%+v", state) }
	if _, err := Decide(state, Command{Kind: CommandComplete, CommandID: "refresh-generation-mismatch", CorrelationID: "refresh-generation-mismatch", EndpointID: state.EndpointID, Generation: state.Generation + 1, CompletionState: OperationStateSucceeded, ObservedState: adapterapi.ObservedStateStopped}); err == nil { t.Fatal("generation-mismatched observation refresh accepted") }
	if _, err := Decide(state, Command{Kind: CommandComplete, CommandID: "refresh-failed-completion", CorrelationID: "refresh-failed-completion", EndpointID: state.EndpointID, Generation: state.Generation, CompletionState: OperationStateFailed, ObservedState: adapterapi.ObservedStateFailed}); err == nil { t.Fatal("failed completion overwrote succeeded operation") }
	if _, err := Decide(state, Command{Kind: CommandComplete, CommandID: "refresh-ambiguous-completion", CorrelationID: "refresh-ambiguous-completion", EndpointID: state.EndpointID, Generation: state.Generation, CompletionState: OperationStateAmbiguous, ObservedState: adapterapi.ObservedStateAmbiguous}); err == nil { t.Fatal("ambiguous completion overwrote succeeded operation") }
}
func TestEndpointAggregateFailedAndAmbiguousCompletionFence(t *testing.T) {
	state := State{}
	var rejection *RejectError
	create, err := Decide(state, createCommand(t, "create-1")); if err != nil { t.Fatal(err) }
	state = applyDecision(t, state, create)
	enable, err := Decide(state, Command{Kind: CommandEnable, CommandID: "enable-1", CorrelationID: "corr-enable", EndpointID: state.EndpointID}); if err != nil { t.Fatal(err) }
	state = applyDecision(t, state, enable)
	failed, err := Decide(state, Command{Kind: CommandComplete, CommandID: "failed-1", CorrelationID: "corr-failed", EndpointID: state.EndpointID, Generation: state.Generation, CompletionState: OperationStateFailed, ObservedState: adapterapi.ObservedStateFailed}); if err != nil { t.Fatal(err) }
	state = applyDecision(t, state, failed)
	if _, err = Decide(state, Command{Kind: CommandDisable, CommandID: "blocked", CorrelationID: "corr-blocked", EndpointID: state.EndpointID}); err == nil { t.Fatal("failed operation allowed overlapping disable") }
	ambiguous, err := Decide(state, Command{Kind: CommandComplete, CommandID: "ambiguous-1", CorrelationID: "corr-ambiguous", EndpointID: state.EndpointID, Generation: state.Generation, CompletionState: OperationStateAmbiguous, ObservedState: adapterapi.ObservedStateAmbiguous}); if err != nil { t.Fatal(err) }
	state = applyDecision(t, state, ambiguous)
	if _, err = Decide(state, Command{Kind: CommandRelogin, CommandID: "blocked-2", CorrelationID: "corr-blocked-2", EndpointID: state.EndpointID}); err == nil { t.Fatal("ambiguous operation allowed overlapping relogin") }
	removeState := State{}
	create, err = Decide(removeState, createCommand(t, "remove-create")); if err != nil { t.Fatal(err) }
	removeState = applyDecision(t, removeState, create)
	remove, err := Decide(removeState, Command{Kind: CommandRemove, CommandID: "remove-1", CorrelationID: "corr-remove", EndpointID: removeState.EndpointID}); if err != nil { t.Fatal(err) }
	removeState = applyDecision(t, removeState, remove)
	removeState.ObservedState = adapterapi.ObservedStateStopped
	removeState.OperationState = OperationStateFailed
	_, err = Decide(removeState, Command{Kind: CommandResolve, CommandID: "resolve-mismatch", CorrelationID: "corr-resolve-mismatch", EndpointID: removeState.EndpointID, OperationID: "wrong-operation"}); if !errors.As(err, &rejection) || rejection.Code != RejectInvalidCommand { t.Fatalf("mismatched resolve operation accepted: %v", err) }
	resolve, err := Decide(removeState, Command{Kind: CommandResolve, CommandID: "resolve-failed", CorrelationID: "corr-resolve-failed", EndpointID: removeState.EndpointID}); if err != nil { t.Fatal(err) }
	explicitResolve, err := Decide(removeState, Command{Kind: CommandResolve, CommandID: "resolve-failed", CorrelationID: "corr-resolve-failed", EndpointID: removeState.EndpointID, OperationID: removeState.OperationID}); if err != nil { t.Fatal(err) }
	if resolve.Events[0].CommandDigest != explicitResolve.Events[0].CommandDigest { t.Fatal("omitted and explicit current resolve operation IDs diverged") }
	removeState = applyDecision(t, removeState, resolve)
	if removeState.DesiredState != DesiredStateDeleted { t.Fatalf("failed operation resolution = %#v", removeState) }
}
func TestEndpointAggregateResolveOperationStateTable(t *testing.T) {
	state := State{}
	create, err := Decide(state, createCommand(t, "resolve-table-create")); if err != nil { t.Fatal(err) }
	state = applyDecision(t, state, create)
	remove, err := Decide(state, Command{Kind: CommandRemove, CommandID: "resolve-table-remove", CorrelationID: "corr-resolve-table-remove", EndpointID: state.EndpointID}); if err != nil { t.Fatal(err) }
	removing := applyDecision(t, state, remove)
	for index, operationState := range []OperationState{OperationStatePending, OperationStateFailed, OperationStateAmbiguous, OperationStateSucceeded} {
		candidate := removing
		candidate.ObservedState = adapterapi.ObservedStateStopped
		candidate.OperationState = operationState
		commandID := fmt.Sprintf("resolve-table-%d", index)
		decision, err := Decide(candidate, Command{Kind: CommandResolve, CommandID: commandID, CorrelationID: "corr-" + commandID, EndpointID: candidate.EndpointID}); if err != nil { t.Fatalf("%s resolve: %v", operationState, err) }
		resolved := applyDecision(t, candidate, decision)
		if resolved.DesiredState != DesiredStateDeleted { t.Fatalf("%s resolve desired state = %s", operationState, resolved.DesiredState) }
	}
}
func TestEndpointAggregateVersionAndGenerationOverflow(t *testing.T) {
	state := State{}
	create, err := Decide(state, createCommand(t, "overflow-create")); if err != nil { t.Fatal(err) }
	state = applyDecision(t, state, create)
	state.OperationState = OperationStateIdle
	state.Generation = ^uint64(0)
	_, err = Decide(state, Command{Kind: CommandEnable, CommandID: "overflow-generation", CorrelationID: "corr-overflow-generation", EndpointID: state.EndpointID})
	if !errors.Is(err, ErrVersionExhausted) { t.Fatalf("generation overflow error = %v", err) }
	versionState := state
	versionState.Generation = 0
	versionState.Version = ^uint64(0)
	versionState.DesiredVersion = ^uint64(0)
	_, err = Decide(versionState, Command{Kind: CommandEnable, CommandID: "overflow-version", CorrelationID: "corr-overflow-version", EndpointID: versionState.EndpointID})
	if !errors.Is(err, ErrVersionExhausted) { t.Fatalf("version overflow error = %v", err) }
}
