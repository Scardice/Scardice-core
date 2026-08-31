package dice

import randcore "Scardice-core/utils/random"

type DiceRandomMode = randcore.Mode

const (
	DiceRandomModePCG    = randcore.ModePCG
	DiceRandomModeGM     = randcore.ModeGM
	DiceRandomModeNIST   = randcore.ModeNIST
	DiceRandomModeCRNG   = randcore.ModeCRNG
	DiceRandomModeHybrid = randcore.ModeHybrid
)

var supportedDiceRandomModes = randcore.SupportedModes()

func ParseDiceRandomMode(raw string) (DiceRandomMode, bool) {
	return randcore.ParseModeStrict(raw)
}
func parseDiceRandomModeStrict(raw string) (DiceRandomMode, bool) {
	return ParseDiceRandomMode(raw)
}
