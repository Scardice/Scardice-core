package endpoint

import (
	"testing"

	"Scardice-core/adapterapi"
)

func TestPendingLifecycleEffectRetainsDurableKindAndIdentity(t *testing.T) {
	state := State{
		EndpointID: adapterapi.EndpointID("endpoint-1"), DesiredState: DesiredStateEnabled, Generation: 4,
		DesiredVersion: 9, OperationID: "operation-9", CorrelationID: "correlation-9",
		PendingEffectID: "effect-replace-9", PendingEffectKind: EffectReplace, PendingCommandID: "command-update-9",
	}
	effects := pendingLifecycleEffect(state)
	if len(effects) != 1 { t.Fatalf("effects = %#v, want one effect", effects) }
	e := effects[0]
	if e.Kind != EffectReplace || e.EffectID != "effect-replace-9" || e.ID != "effect-replace-9" || e.CommandID != "command-update-9" { t.Fatalf("effect identity = %#v", e) }
	state.PendingEffectKind, state.PendingEffectID, state.PendingCommandID = EffectRelogin, "effect-relogin-10", "command-relogin-10"
	if e = pendingLifecycleEffect(state)[0]; e.Kind != EffectRelogin || e.EffectID != "effect-relogin-10" || e.CommandID != "command-relogin-10" { t.Fatalf("relogin effect identity = %#v", e) }
	state.DesiredState = DesiredStateRemoving
	state.PendingEffectKind, state.PendingEffectID, state.PendingCommandID = EffectDelete, "effect-delete-11", "command-remove-11"
	if e = pendingLifecycleEffect(state)[0]; e.Kind != EffectDelete || e.EffectID != "effect-delete-11" || e.CommandID != "command-remove-11" { t.Fatalf("delete effect identity = %#v", e) }
}

func TestApplyRecordsExactPendingEffectMetadata(t *testing.T) {
	id := adapterapi.EndpointID("endpoint-apply")
	key := adapterapi.AdapterKey("fake")
	create := Command{Kind: CommandCreate, Type: CommandCreate, CommandID: "create-apply", CorrelationID: "create-apply", EndpointID: id, AdapterKey: key, Config: adapterapi.ValidatedConfig{Version: 1, Canonical: []byte(`{"x":1}`)}}
	decision, err := Decide(State{}, create)
	if err != nil { t.Fatal(err) }
	state, err := Apply(State{}, decision.Events[0])
	if err != nil { t.Fatal(err) }
	enable := Command{Kind: CommandEnable, Type: CommandEnable, CommandID: "enable-apply", CorrelationID: "enable-apply", EndpointID: id}
	decision, err = Decide(state, enable)
	if err != nil { t.Fatal(err) }
	state, err = Apply(state, decision.Events[0])
	if err != nil { t.Fatal(err) }
	if state.PendingEffectKind != EffectStart || state.PendingEffectID == "" || state.PendingCommandID != enable.CommandID { t.Fatalf("pending start metadata = %#v", state) }
}
