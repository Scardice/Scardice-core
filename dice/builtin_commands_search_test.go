package dice

import (
	"testing"

	"Scardice-core/dice/docengine"
)

func TestShouldShowBestHelpResultUsesRelativeScoreGap(t *testing.T) {
	// Given
	newHits := func(scores ...float64) docengine.MatchCollection {
		hits := make(docengine.MatchCollection, 0, len(scores))
		for _, score := range scores {
			hits = append(hits, &docengine.MatchResult{Score: score})
		}
		return hits
	}
	tests := []struct {
		name       string
		hits       docengine.MatchCollection
		exactTitle bool
		want       bool
	}{
		{name: "no result", want: false},
		{name: "single result", hits: newHits(0.1), want: true},
		{name: "exact title", hits: newHits(10, 9.9), exactTitle: true, want: true},
		{name: "relative gap at threshold", hits: newHits(12, 9), want: true},
		{name: "relative gap below threshold", hits: newHits(12, 9.01), want: false},
		{name: "tied scores", hits: newHits(12, 12), want: false},
		{name: "non-positive best score", hits: newHits(0, 0), want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// When
			got := shouldShowBestHelpResult(test.hits, test.exactTitle, 0.25)

			// Then
			if got != test.want {
				t.Fatalf("shouldShowBestHelpResult() = %v, want %v", got, test.want)
			}
		})
	}
}
