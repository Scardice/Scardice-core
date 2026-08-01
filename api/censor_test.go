package api

import (
	"slices"
	"testing"

	"Scardice-core/dice"
	"Scardice-core/dice/censor"
)

func TestCensorEncodedDetailsHandlerConfigRoundTrip(t *testing.T) {
	// Given
	previousDice := myDice
	t.Cleanup(func() { myDice = previousDice })
	myDice = &dice.Dice{}
	myDice.Config.CensorHandlers = map[censor.Level]uint8{}

	// When
	setLevelHandlers(censor.Warning, []string{"SendWarning", "SendEncodedDetails"})
	got := getLevelConfig(
		censor.Warning,
		map[censor.Level]int{censor.Warning: 1},
		myDice.Config.CensorHandlers,
		map[censor.Level]int{censor.Warning: 100},
	)

	// Then
	if !slices.Contains(got.Handlers, "SendEncodedDetails") {
		t.Fatalf("encoded details handler missing after config round trip: %v", got.Handlers)
	}
}
