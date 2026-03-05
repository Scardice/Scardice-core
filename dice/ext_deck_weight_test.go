package dice

import (
	"testing"

	wr "github.com/mroth/weightedrand"
)

func TestExtractWeight(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  string
		weight uint
		text   string
	}{
		{name: "default", input: "plain", weight: 100, text: "plain"},
		{name: "int", input: "::9::item", weight: 900, text: "item"},
		{name: "float", input: "::1.23::item", weight: 123, text: "item"},
		{name: "round-down", input: "::1.234::item", weight: 123, text: "item"},
		{name: "round-up", input: "::1.235::item", weight: 124, text: "item"},
		{name: "tiny-round-down-to-zero", input: "::0.004::item", weight: 0, text: "item"},
		{name: "tiny-round-up", input: "::0.005::item", weight: 1, text: "item"},
		{name: "zero", input: "::0::item", weight: 0, text: "item"},
		{name: "negative", input: "::-1::item", weight: 0, text: "item"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			weight, text := extractWeight(tt.input)
			if weight != tt.weight {
				t.Fatalf("unexpected weight: got=%d want=%d", weight, tt.weight)
			}
			if text != tt.text {
				t.Fatalf("unexpected text: got=%q want=%q", text, tt.text)
			}
		})
	}
}

func TestDeckPoolIgnoreNonPositiveWeight(t *testing.T) {
	t.Parallel()

	deck := []string{"::0::zero", "::-2::negative", "::0.004::tiny"}
	if DeckToRandomPool(deck) != nil {
		t.Fatal("random pool should be nil when all weights are non-positive")
	}
	if DeckToShuffleRandomPool(deck) != nil {
		t.Fatal("shuffle pool should be nil when all weights are non-positive")
	}
}

func TestDeckPoolPickWithNonPositiveWeightEntries(t *testing.T) {
	t.Parallel()

	deck := []string{"::0::zero", "::-2::negative", "::0.004::tiny", "::1::ok"}
	randomPool := DeckToRandomPool(deck)
	if randomPool == nil {
		t.Fatal("random pool should not be nil")
	}
	if got := randomPool.Pick().(string); got != "ok" {
		t.Fatalf("unexpected random pick: got=%q want=%q", got, "ok")
	}

	shufflePool := DeckToShuffleRandomPool(deck)
	if shufflePool == nil {
		t.Fatal("shuffle pool should not be nil")
	}
	if got := shufflePool.Pick().(string); got != "ok" {
		t.Fatalf("unexpected shuffle pick: got=%q want=%q", got, "ok")
	}
}

func TestBuildNormalizedWeightedChoices(t *testing.T) {
	t.Parallel()

	toWeights := func(choices []wr.Choice) []uint {
		weights := make([]uint, 0, len(choices))
		for _, c := range choices {
			weights = append(weights, c.Weight)
		}
		return weights
	}

	tests := []struct {
		name string
		deck []string
		want []uint
	}{
		{
			name: "int-reduced-by-gcd",
			deck: []string{"::10::a", "::20::b"},
			want: []uint{1, 2},
		},
		{
			name: "float-preserves-ratio",
			deck: []string{"::1.50::a", "::2.25::b"},
			want: []uint{2, 3},
		},
		{
			name: "skip-non-positive",
			deck: []string{"::0::a", "::-1::b", "::0.01::c"},
			want: []uint{1},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := toWeights(buildNormalizedWeightedChoices(tt.deck))
			if len(got) != len(tt.want) {
				t.Fatalf("unexpected weight count: got=%d want=%d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("unexpected weight at index %d: got=%d want=%d", i, got[i], tt.want[i])
				}
			}
		})
	}
}
