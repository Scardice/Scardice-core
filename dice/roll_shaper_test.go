package dice

import (
	"math"
	"testing"

	ds "github.com/sealdice/dicescript"
)

func TestDiceRollShaperBalancedUsesEachFaceBeforeRefill(t *testing.T) {
	shaper := newDiceRollShaper(DiceRollShaperModeBalanced)
	src := &countingDiceSource{values: []uint64{0}}
	seen := make(map[int]bool)

	for index := range 12 {
		got := int(shaper.roll(src, 6, 0))
		if got < 1 || got > 6 {
			t.Fatalf("roll %d = %d, want range 1..6", index, got)
		}
		if index < 6 && seen[got] {
			t.Fatalf("roll %d = %d, duplicate before bag refill", index, got)
		}
		seen[got] = true
		if index == 5 {
			seen = make(map[int]bool)
		}
	}
}

func TestDiceRollShaperBalancedFallsBackForHugeDice(t *testing.T) {
	shaper := newDiceRollShaper(DiceRollShaperModeBalanced)
	src := &countingDiceSource{values: []uint64{0}}

	got := shaper.roll(src, ds.IntType(diceRollShaperMaxBalancedDicePoints+1), 0)
	if got != 1 {
		t.Fatalf("huge balanced roll = %d, want raw result 1", got)
	}
	shaper.mu.Lock()
	defer shaper.mu.Unlock()
	if len(shaper.bags) != 0 {
		t.Fatalf("huge balanced roll created %d bags, want 0", len(shaper.bags))
	}
}

func TestDiceRollShaperKeepsSoftAndStableInBounds(t *testing.T) {
	for _, mode := range []DiceRollShaperMode{DiceRollShaperModeSoft, DiceRollShaperModeStable} {
		shaper := newDiceRollShaper(mode)
		src := &countingDiceSource{values: []uint64{0x123456789abcdef0}}
		for index := range 1000 {
			got := shaper.roll(src, 20, 0)
			if got < 1 || got > 20 {
				t.Fatalf("mode %s roll %d = %d, want range 1..20", mode, index, got)
			}
		}
	}
}

func TestDiceRollShaperSafeTailSuppressesTailIntoInterior(t *testing.T) {
	shaper := newDiceRollShaper(DiceRollShaperModeSafeTail)
	src := &countingDiceSource{values: []uint64{99, math.MaxUint64, 0}}

	if got := shaper.roll(src, 100, 0); got != 6 {
		t.Fatalf("safe-tail roll = %d, want interior result 6", got)
	}
}

func TestDiceRollShaperSafeTailFallsBackForTooSmallInterior(t *testing.T) {
	shaper := newDiceRollShaper(DiceRollShaperModeSafeTail)
	src := &countingDiceSource{values: []uint64{0}}

	if got := shaper.roll(src, 2, 0); got != 1 {
		t.Fatalf("safe-tail d2 = %d, want raw result 1", got)
	}
}

func TestDiceRollShaperRejectsNonPositiveDice(t *testing.T) {
	shaper := newDiceRollShaper(DiceRollShaperModeStable)
	src := &countingDiceSource{values: []uint64{0}}

	if got := shaper.roll(src, 0, 0); got != 0 {
		t.Fatalf("zero-sided roll = %d, want 0", got)
	}
	if got := shaper.roll(src, -1, 0); got != 0 {
		t.Fatalf("negative-sided roll = %d, want 0", got)
	}
}

func TestMsgContextDiceRollSourceShapesOnlyDiceRolls(t *testing.T) {
	group := &GroupInfo{
		GroupID:        "group:test",
		RollShaperMode: string(DiceRollShaperModeBalanced),
	}
	raw := &countingDiceSource{values: []uint64{0}}
	ctx := &MsgContext{Group: group, diceRandSrc: raw}

	diceSource := ctx.getDiceRollSource()
	if diceSource == raw {
		t.Fatal("getDiceRollSource() returned the raw source")
	}
	if ctx._v1Rand != diceSource {
		t.Fatal("_v1Rand does not use the shaped source")
	}
	if got := ctx.getDiceSource(); got != raw {
		t.Fatalf("getDiceSource() = %T, want raw source", got)
	}
	if ctx._v1Rand == raw {
		t.Fatal("getDiceSource() replaced the shaped V1 source")
	}

	seen := make(map[int64]bool)
	for range 6 {
		got := ds.Roll(diceSource, 6, 0)
		if seen[int64(got)] {
			t.Fatalf("shaped roll %d repeated before bag refill", got)
		}
		seen[int64(got)] = true
	}
}

func TestDiceRollShaperSoftAndStableSuppressExtremeDeciles(t *testing.T) {
	const samples = 100_000

	countExtreme := func(mode DiceRollShaperMode) int {
		shaper := newDiceRollShaper(mode)
		src := ds.NewPCGDiceSource(12345)
		count := 0
		for range samples {
			result := shaper.roll(src, 100, 0)
			if result <= 10 || result >= 91 {
				count++
			}
		}
		return count
	}

	raw := countExtreme(DiceRollShaperModeRaw)
	soft := countExtreme(DiceRollShaperModeSoft)
	stable := countExtreme(DiceRollShaperModeStable)
	if raw < 17_000 || raw > 23_000 {
		t.Fatalf("raw extreme deciles = %d, want approximately 20%%", raw)
	}
	if soft >= 18_000 {
		t.Fatalf("soft extreme deciles = %d, want below 18%%", soft)
	}
	if stable >= 10_000 {
		t.Fatalf("stable extreme deciles = %d, want below 10%%", stable)
	}
}

func TestDiceRollShaperFlowsThroughV2VM(t *testing.T) {
	group := &GroupInfo{
		GroupID:        "group:v2",
		RollShaperMode: string(DiceRollShaperModeBalanced),
	}
	ctx := &MsgContext{
		Dice:        &Dice{},
		Group:       group,
		diceRandSrc: &countingDiceSource{values: []uint64{0}},
	}
	seen := make(map[int]bool)

	for range 6 {
		result := ctx.Eval("d6", nil)
		if result == nil || result.vm == nil || result.vm.Error != nil {
			t.Fatalf("V2 eval failed: %#v", result)
		}
		value := int(result.MustReadInt())
		if seen[value] {
			t.Fatalf("V2 shaped result %d repeated before bag refill", value)
		}
		seen[value] = true
	}
}

func TestDiceRollShaperFlowsThroughV1VM(t *testing.T) {
	group := &GroupInfo{
		GroupID:        "group:v1",
		RollShaperMode: string(DiceRollShaperModeBalanced),
	}
	ctx := &MsgContext{
		Dice:        &Dice{},
		Group:       group,
		diceRandSrc: &countingDiceSource{values: []uint64{0}},
	}
	seen := make(map[int]bool)

	for range 6 {
		result, _, err := DiceExprEvalBase(ctx, "d6", RollExtraFlags{V1Only: true})
		if err != nil {
			t.Fatalf("V1 eval error = %v", err)
		}
		value := int(result.MustReadInt())
		if seen[value] {
			t.Fatalf("V1 shaped result %d repeated before bag refill", value)
		}
		seen[value] = true
	}
}

func TestDiceRollShaperFlowsThroughRuleDice(t *testing.T) {
	for _, expression := range []string{"b", "8a11m10k1", "10c11m10"} {
		t.Run(expression, func(t *testing.T) {
			ctx := &MsgContext{
				Dice: &Dice{},
				Group: &GroupInfo{
					GroupID:        "group:rules",
					RollShaperMode: string(DiceRollShaperModeStable),
				},
				diceRandSrc: &countingDiceSource{values: []uint64{0}},
			}
			result := ctx.Eval(expression, nil)
			if result == nil || result.vm == nil || result.vm.Error != nil {
				t.Fatalf("rule expression failed: %#v", result)
			}
		})
	}
}
