package configstate

import "testing"

func TestPublicDiceEndpointIDsAreDeepCopied(t *testing.T) {
	t.Run("state clone", func(t *testing.T) {
		baseline := testBaseline()
		baseline.PublicDice.EndpointIDs = []string{"endpoint-original"}
		state, err := Replay(decideEvents(t, State{}, Command{Kind: CommandImportBaseline, Baseline: &baseline}))
		if err != nil {
			t.Fatalf("replay baseline: %v", err)
		}

		clone := state.Clone()
		clone.PublicDice.EndpointIDs[0] = "clone-mutated"
		if state.PublicDice.EndpointIDs[0] != "endpoint-original" {
			t.Fatalf("mutating cloned endpoint IDs changed source state: %q", state.PublicDice.EndpointIDs[0])
		}
	})

	t.Run("baseline decision", func(t *testing.T) {
		baseline := testBaseline()
		baseline.PublicDice.EndpointIDs = []string{"endpoint-original"}
		decision, err := Decide(State{}, Command{Kind: CommandImportBaseline, Baseline: &baseline})
		if err != nil {
			t.Fatalf("decide baseline: %v", err)
		}
		baseline.PublicDice.EndpointIDs[0] = "source-mutated"
		state, err := Replay(decision.Events)
		if err != nil {
			t.Fatalf("replay baseline decision: %v", err)
		}
		if state.PublicDice.EndpointIDs[0] != "endpoint-original" {
			t.Fatalf("mutating baseline changed decided endpoint IDs: %q", state.PublicDice.EndpointIDs[0])
		}
	})

	t.Run("event constructor and reduction", func(t *testing.T) {
		baseline := testBaseline()
		state, err := Replay(decideEvents(t, State{}, Command{Kind: CommandImportBaseline, Baseline: &baseline}))
		if err != nil {
			t.Fatalf("replay baseline: %v", err)
		}
		source := PublicDiceConfig{EndpointIDs: []string{"endpoint-original"}}
		event := NewPublicDiceChangedV1(source)
		source.EndpointIDs[0] = "source-mutated"
		if event.EndpointIDs[0] != "endpoint-original" {
			t.Fatalf("mutating constructor input changed event: %q", event.EndpointIDs[0])
		}

		next, err := Reduce(state, event)
		if err != nil {
			t.Fatalf("reduce public dice event: %v", err)
		}
		event.EndpointIDs[0] = "event-mutated"
		if next.PublicDice.EndpointIDs[0] != "endpoint-original" {
			t.Fatalf("mutating event changed reduced state: %q", next.PublicDice.EndpointIDs[0])
		}
	})
}
