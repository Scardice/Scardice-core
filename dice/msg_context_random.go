package dice

import (
	randv2 "math/rand/v2"

	ds "github.com/sealdice/dicescript"
)

func (ctx *MsgContext) getDiceSource() ds.DiceSource {
	if ctx.diceRandSrc != nil {
		return ctx.diceRandSrc
	}
	// 默认随机源直接走进程内唯一的全局 owner。
	return globalRandSource
}

type scopedDiceRollSource struct {
	raw    ds.DiceSource
	shaper *diceRollShaper
}

func (s *scopedDiceRollSource) Uint64() uint64 {
	return s.raw.Uint64()
}

func (s *scopedDiceRollSource) Roll(points ds.IntType, mod int) ds.IntType {
	return s.shaper.roll(s.raw, points, mod)
}

func (ctx *MsgContext) getDiceRollSource() ds.DiceSource {
	raw := ctx.getDiceSource()
	if ctx.diceRollSource == nil || ctx.diceRollRaw != raw || ctx.diceRollGroup != ctx.Group {
		ctx.diceRollRaw = raw
		ctx.diceRollGroup = ctx.Group
		if ctx.Group == nil {
			ctx.diceRollSource = raw
		} else {
			ctx.diceRollSource = &scopedDiceRollSource{
				raw:    raw,
				shaper: ctx.Group.getDiceRollShaper(),
			}
		}
	}
	ctx._v1Rand = ctx.diceRollSource
	return ctx.diceRollSource
}

func (ctx *MsgContext) getChooserRand() *randv2.Rand {
	src := normalizeDiceSource(ctx.getDiceSource())
	if ctx.chooserRand == nil || ctx.chooserSrc != src {
		ctx.chooserSrc = src
		ctx.chooserRand = randv2.New(src)
	}
	return ctx.chooserRand
}

func (ctx *MsgContext) Roll(points int) int {
	if points <= 0 {
		return 0
	}
	return int(ds.Roll(ctx.getDiceRollSource(), ds.IntType(points), 0))
}

func (ctx *MsgContext) Roll64(points int64) int64 {
	return DiceRoll64x(ctx.getDiceRollSource(), points)
}

func (ctx *MsgContext) RandIntn(n int) int {
	return randIntnFromSource(ctx.getDiceSource(), n)
}

func (ctx *MsgContext) Shuffle(n int, swap func(i, j int)) {
	shuffleWithSource(ctx.getDiceSource(), n, swap)
}
