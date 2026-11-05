package dice

import "testing"

func newRollShaperCommandContext(t *testing.T, private bool, privilege int, label string) *MsgContext {
	t.Helper()
	d, _ := newCanonicalTestDice(t)
	endpoint := newCanonicalTestEndpoint(d, "QQ:roll-shaper-bot")
	var message *Message
	if private {
		message = newPrivateMsg("QQ:roll-shaper-user", "")
	} else {
		message = newGroupMsg("QQ-Group:roll-shaper", "QQ:roll-shaper-user", "")
	}
	ctx := newCanonicalTestMessageContext(t, d, endpoint, message, label)
	ctx.PrivilegeLevel = privilege
	ctx.IsPrivate = private
	return ctx
}

func TestGroupInfoRollShaperModeRoundTripsThroughProjection(t *testing.T) {
	d, _ := newCanonicalTestDice(t)
	endpoint := newCanonicalTestEndpoint(d, "QQ:roll-shaper-bot")
	message := newGroupMsg("QQ-Group:roll-shaper-persist", "QQ:roll-shaper-user", "")
	var (
		setMode DiceRollShaperMode
		setOK   bool
	)
	withCanonicalTestMessageContext(t, d, endpoint, message, "persist-roll-shaper", func(ctx *MsgContext) error {
		var err error
		setMode, setOK, err = ctx.Group.setDiceRollShaperMode("stable")
		return err
	})
	if !setOK || setMode != DiceRollShaperModeStable {
		t.Fatalf("setDiceRollShaperMode() = (%s, %v), want stable, true", setMode, setOK)
	}

	restored := newCanonicalTestMessageContext(t, d, endpoint, message, "read-roll-shaper")
	if restored.Group.RollShaperMode() != string(DiceRollShaperModeStable) {
		t.Fatalf("RollShaperMode() = %q, want %q", restored.Group.RollShaperMode(), DiceRollShaperModeStable)
	}
	if got := restored.Group.getDiceRollShaperMode(); got != DiceRollShaperModeStable {
		t.Fatalf("getDiceRollShaperMode() = %s, want stable", got)
	}
}

func TestGroupInfoRollShaperModeChangeClearsBalancedBag(t *testing.T) {
	ctx := newRollShaperCommandContext(t, false, 50, "roll-shaper-bag")
	if _, ok, err := ctx.Group.setDiceRollShaperMode("balanced"); err != nil || !ok {
		t.Fatalf("set balanced = ok:%v err:%v", ok, err)
	}
	shaper := ctx.Group.getDiceRollShaper()
	shaper.roll(&countingDiceSource{values: []uint64{0}}, 6, 0)
	if len(shaper.bags) == 0 {
		t.Fatal("balanced roll did not create a bag")
	}

	if _, ok, err := ctx.Group.setDiceRollShaperMode("stable"); err != nil || !ok {
		t.Fatalf("set stable = ok:%v err:%v", ok, err)
	}
	if len(ctx.Group.getDiceRollShaper().bags) != 0 {
		t.Fatal("mode change retained balanced bags")
	}
}

func TestCanManageDiceRollShaper(t *testing.T) {
	cases := []struct {
		name    string
		ctx     *MsgContext
		allowed bool
	}{
		{name: "group member", ctx: &MsgContext{PrivilegeLevel: 0}, allowed: false},
		{name: "group inviter", ctx: &MsgContext{PrivilegeLevel: 40}, allowed: false},
		{name: "group admin", ctx: &MsgContext{PrivilegeLevel: 50}, allowed: true},
		{name: "private user", ctx: &MsgContext{IsPrivate: true}, allowed: true},
		{name: "master", ctx: &MsgContext{PrivilegeLevel: 100}, allowed: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := canManageDiceRollShaper(testCase.ctx); got != testCase.allowed {
				t.Fatalf("canManageDiceRollShaper() = %v, want %v", got, testCase.allowed)
			}
		})
	}
}

func TestSolveDiceRollShaperSetsGroupMode(t *testing.T) {
	ctx := newRollShaperCommandContext(t, false, 50, "solve-roll-shaper")
	result := solveDiceRollShaper(ctx, nil, &CmdArgs{Args: []string{"set", "safe-tail"}})

	if !result.Matched || !result.Solved {
		t.Fatalf("solve result = %#v, want matched and solved", result)
	}
	if got := ctx.Group.getDiceRollShaperMode(); got != DiceRollShaperModeSafeTail {
		t.Fatalf("group mode = %s, want safe-tail", got)
	}
}

func TestSolveDiceRollShaperAllowsPrivateSender(t *testing.T) {
	ctx := newRollShaperCommandContext(t, true, 0, "private-roll-shaper")
	solveDiceRollShaper(ctx, nil, &CmdArgs{Args: []string{"set", "soft"}})

	if got := ctx.Group.getDiceRollShaperMode(); got != DiceRollShaperModeSoft {
		t.Fatalf("private group mode = %s, want soft", got)
	}
}

func TestSolveDiceRollShaperRejectsInvalidModeWithoutMutation(t *testing.T) {
	ctx := newRollShaperCommandContext(t, false, 40, "invalid-roll-shaper")
	if _, ok, err := ctx.Group.setDiceRollShaperMode("stable"); err != nil || !ok {
		t.Fatalf("seed stable mode = ok:%v err:%v", ok, err)
	}

	solveDiceRollShaper(ctx, nil, &CmdArgs{Args: []string{"set", "unknown"}})

	if got := ctx.Group.getDiceRollShaperMode(); got != DiceRollShaperModeStable {
		t.Fatalf("group mode = %s, want stable after invalid set", got)
	}
}
