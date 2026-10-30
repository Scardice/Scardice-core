package configstate

import (
	"testing"
)

func TestJSRuntimeRoutesCloneCompareAndSurviveEventRoundTrip(t *testing.T) {
	baseline := testBaseline()
	baselineEvents, err := Decide(State{}, Command{Kind: CommandImportBaseline, Baseline: &baseline})
	if err != nil {
		t.Fatal(err)
	}
	state, err := Replay(baselineEvents.Events)
	if err != nil {
		t.Fatal(err)
	}

	routes := map[string]string{"author/example": "quickjs"}
	patch := ConfigPatch{JS: &JSConfig{JsRuntimeRoutes: routes}}
	decision, err := Decide(state, Command{Kind: CommandPatch, Patch: &patch})
	if err != nil {
		t.Fatal(err)
	}
	if len(decision.Events) != 1 {
		t.Fatalf("event count = %d, want one JS config event", len(decision.Events))
	}

	// A decided event must own its route map; later request mutation cannot
	// change the event that will be persisted.
	routes["author/example"] = "mutated"
	payload, err := MarshalTypedEvent(decision.Events[0])
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeTypedEvent(EventConfigJSChanged, payload)
	if err != nil {
		t.Fatal(err)
	}
	jsEvent, ok := decoded.(*JSChangedV1)
	if !ok {
		t.Fatalf("decoded event type = %T, want *JSChangedV1", decoded)
	}
	if got := jsEvent.JsRuntimeRoutes["author/example"]; got != "quickjs" {
		t.Fatalf("event route = %q, want quickjs", got)
	}

	replayed, err := Replay(append(baselineEvents.Events, decoded))
	if err != nil {
		t.Fatal(err)
	}
	if got := replayed.JS.JsRuntimeRoutes["author/example"]; got != "quickjs" {
		t.Fatalf("replayed route = %q, want quickjs", got)
	}

	repeatPatch := ConfigPatch{JS: &JSConfig{JsRuntimeRoutes: map[string]string{"author/example": "quickjs"}}}
	repeat, err := Decide(replayed, Command{Kind: CommandPatch, Patch: &repeatPatch})
	if err != nil {
		t.Fatal(err)
	}
	if len(repeat.Events) != 0 {
		t.Fatalf("unchanged route map emitted %d events, want none", len(repeat.Events))
	}
}
