package dice

import "Scardice-core/dice/docengine"

func shouldShowBestHelpResult(hits docengine.MatchCollection, exactTitle bool, minRelativeGap float64) bool {
	if len(hits) == 0 {
		return false
	}
	if len(hits) == 1 || exactTitle {
		return true
	}
	bestScore := hits[0].Score
	if bestScore <= 0 {
		return false
	}
	return (bestScore-hits[1].Score)/bestScore >= minRelativeGap
}
