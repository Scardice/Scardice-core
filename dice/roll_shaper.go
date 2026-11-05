package dice

import (
	"math"
	"strings"
	"sync"

	ds "github.com/sealdice/dicescript"
)

type DiceRollShaperMode string

const (
	DiceRollShaperModeRaw      DiceRollShaperMode = "raw"
	DiceRollShaperModeBalanced DiceRollShaperMode = "balanced"
	DiceRollShaperModeSoft     DiceRollShaperMode = "soft"
	DiceRollShaperModeStable   DiceRollShaperMode = "stable"
	DiceRollShaperModeSafeTail DiceRollShaperMode = "safe-tail"
)

const diceRollShaperMaxBalancedDicePoints int64 = 1 << 20

func parseDiceRollShaperMode(raw string) (DiceRollShaperMode, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "raw", "uniform":
		return DiceRollShaperModeRaw, true
	case "balanced", "shuffle-bag", "shufflebag":
		return DiceRollShaperModeBalanced, true
	case "soft", "beta":
		return DiceRollShaperModeSoft, true
	case "stable", "median", "median-of-3", "medianof3":
		return DiceRollShaperModeStable, true
	case "safe-tail", "safetail":
		return DiceRollShaperModeSafeTail, true
	default:
		return DiceRollShaperModeRaw, false
	}
}

type diceRollShaper struct {
	mu   sync.Mutex
	mode DiceRollShaperMode

	bags map[int64][]int64
}

func (g *GroupInfo) getDiceRollShaper() *diceRollShaper {
	if g == nil || g.requireRuntimeAuthority() != nil {
		return nil
	}
	mode, ok := parseDiceRollShaperMode(g.RollShaperMode())
	if !ok {
		mode = DiceRollShaperModeRaw
	}

	g.rollShaperCacheMu.Lock()
	defer g.rollShaperCacheMu.Unlock()
	if g.localRollShaper != nil && g.localRollShaper.getMode() == mode {
		return g.localRollShaper
	}

	resources := g.runtime
	resources.rollShaperMu.Lock()
	shared := resources.rollShaper
	resources.rollShaperMu.Unlock()
	if shared != nil && shared.getMode() == mode {
		return shared
	}

	local := newDiceRollShaper(mode)
	g.localRollShaper = local
	if g.transaction != nil {
		_ = g.transaction.AfterCommit(func() {
			currentMode, valid := parseDiceRollShaperMode(g.RollShaperMode())
			if !valid {
				currentMode = DiceRollShaperModeRaw
			}
			if resources.revoked.Load() || currentMode != mode {
				return
			}
			resources.rollShaperMu.Lock()
			if !resources.revoked.Load() {
				resources.rollShaper = local
			}
			resources.rollShaperMu.Unlock()
		})
	}
	return local
}

func (g *GroupInfo) setDiceRollShaperMode(raw string) (DiceRollShaperMode, bool, error) {
	mode, ok := parseDiceRollShaperMode(raw)
	if !ok {
		return DiceRollShaperModeRaw, false, nil
	}
	if g == nil {
		return DiceRollShaperModeRaw, false, ErrGroupHandleUnavailable
	}
	if err := g.SetRollShaperMode(string(mode)); err != nil {
		return DiceRollShaperModeRaw, false, err
	}
	if g.getDiceRollShaper() == nil {
		return DiceRollShaperModeRaw, false, ErrGroupRuntimeRevoked
	}
	return mode, true, nil
}

func (g *GroupInfo) getDiceRollShaperMode() DiceRollShaperMode {
	if g == nil {
		return DiceRollShaperModeRaw
	}
	mode, ok := parseDiceRollShaperMode(g.RollShaperMode())
	if !ok {
		return DiceRollShaperModeRaw
	}
	return mode
}

func newDiceRollShaper(mode DiceRollShaperMode) *diceRollShaper {
	normalized, ok := parseDiceRollShaperMode(string(mode))
	if !ok {
		normalized = DiceRollShaperModeRaw
	}
	return &diceRollShaper{mode: normalized, bags: make(map[int64][]int64)}
}

func (s *diceRollShaper) getMode() DiceRollShaperMode {
	return s.mode
}

func (s *diceRollShaper) roll(src ds.DiceSource, dicePoints ds.IntType, mod int) ds.IntType {
	if dicePoints <= 0 {
		return 0
	}
	if mod == -1 {
		return 1
	}
	if mod == 1 {
		return dicePoints
	}

	switch s.getMode() {
	case DiceRollShaperModeBalanced:
		if int64(dicePoints) > diceRollShaperMaxBalancedDicePoints {
			return ds.RollUniform(src, dicePoints, mod)
		}
		return ds.IntType(s.rollBalanced(src, int64(dicePoints)))
	case DiceRollShaperModeSoft:
		return ds.IntType(s.rollBeta(src, int64(dicePoints), 1.35))
	case DiceRollShaperModeStable:
		return ds.IntType(s.rollStable(src, int64(dicePoints)))
	case DiceRollShaperModeSafeTail:
		return ds.IntType(s.rollSafeTail(src, int64(dicePoints)))
	default:
		return ds.RollUniform(src, dicePoints, mod)
	}
}

func (s *diceRollShaper) rollBalanced(src ds.DiceSource, dicePoints int64) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	bag := s.bags[dicePoints]
	if len(bag) == 0 {
		bag = make([]int64, int(dicePoints))
		for index := range dicePoints {
			bag[index] = index + 1
		}
		for index := dicePoints - 1; index > 0; index-- {
			swapIndex := uniformInt64(src, 0, index)
			bag[index], bag[swapIndex] = bag[swapIndex], bag[index]
		}
	}

	result := bag[len(bag)-1]
	s.bags[dicePoints] = bag[:len(bag)-1]
	return result
}

func (s *diceRollShaper) rollBeta(src ds.DiceSource, dicePoints int64, alpha float64) int64 {
	x := sampleGamma(src, alpha)
	y := sampleGamma(src, alpha)
	return unitToInt((x / (x + y)), dicePoints)
}

func (s *diceRollShaper) rollStable(src ds.DiceSource, dicePoints int64) int64 {
	first := uniformOpen(src)
	second := uniformOpen(src)
	third := uniformOpen(src)
	if first > second {
		first, second = second, first
	}
	if second > third {
		second = third
	}
	if first > second {
		second = first
	}
	return unitToInt(second, dicePoints)
}

func (s *diceRollShaper) rollSafeTail(src ds.DiceSource, dicePoints int64) int64 {
	tailWidth := maxInt64(1, (dicePoints-1)/20+1)
	if dicePoints <= 2*tailWidth {
		return uniformInt64(src, 1, dicePoints)
	}
	result := uniformInt64(src, 1, dicePoints)
	if result <= tailWidth || result > dicePoints-tailWidth {
		if uniformOpen(src) >= 0.5 {
			return uniformInt64(src, tailWidth+1, dicePoints-tailWidth)
		}
	}
	return result
}

func sampleGamma(src ds.DiceSource, alpha float64) float64 {
	if alpha < 1 {
		return sampleGamma(src, alpha+1) * math.Pow(uniformOpen(src), 1/alpha)
	}

	d := alpha - 1.0/3.0
	c := 1 / math.Sqrt(9*d)
	for {
		normal := sampleStandardNormal(src)
		v := 1 + c*normal
		if v <= 0 {
			continue
		}
		v = v * v * v
		u := uniformOpen(src)
		if u < 1-0.0331*normal*normal*normal*normal || math.Log(u) < 0.5*normal*normal+d*(1-v+math.Log(v)) {
			return d * v
		}
	}
}

func sampleStandardNormal(src ds.DiceSource) float64 {
	radius := math.Sqrt(-2 * math.Log(uniformOpen(src)))
	angle := 2 * math.Pi * uniformOpen(src)
	return radius * math.Cos(angle)
}

func uniformOpen(src ds.DiceSource) float64 {
	const scale = 1.0 / (1 << 53)
	return (float64(src.Uint64()>>11) + 0.5) * scale
}

func unitToInt(unit float64, dicePoints int64) int64 {
	result := int64(unit*float64(dicePoints)) + 1
	if result < 1 {
		return 1
	}
	if result > dicePoints {
		return dicePoints
	}
	return result
}

func uniformInt64(src ds.DiceSource, minimum, maximum int64) int64 {
	if minimum >= maximum {
		return minimum
	}
	size := uint64(maximum - minimum + 1)
	limit := math.MaxUint64 - (math.MaxUint64 % size)
	for {
		value := src.Uint64()
		if value < limit {
			return minimum + int64(value%size)
		}
	}
}

func maxInt64(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
}
