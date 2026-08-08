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
		map[censor.Level]int{
			censor.Ignore:  0,
			censor.Notice:  0,
			censor.Caution: 0,
			censor.Warning: 1,
			censor.Danger:  0,
		},
		myDice.Config.CensorHandlers,
		map[censor.Level]int{
			censor.Ignore:  0,
			censor.Notice:  0,
			censor.Caution: 0,
			censor.Warning: 100,
			censor.Danger:  0,
		},
	)

	// Then
	if !slices.Contains(got.Handlers, "SendEncodedDetails") {
		t.Fatalf("encoded details handler missing after config round trip: %v", got.Handlers)
	}
}
