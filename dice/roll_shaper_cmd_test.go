package dice

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGroupInfoRollShaperModeRoundTrips(t *testing.T) {
	original := &GroupInfo{GroupID: "group:test"}
	if mode, ok := original.setDiceRollShaperMode("stable"); !ok || mode != DiceRollShaperModeStable {
		t.Fatalf("setDiceRollShaperMode() = (%s, %v), want stable, true", mode, ok)
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	var restored GroupInfo
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if restored.RollShaperMode != string(DiceRollShaperModeStable) {
		t.Fatalf("RollShaperMode = %q, want %q", restored.RollShaperMode, DiceRollShaperModeStable)
	}
	if got := restored.getDiceRollShaperMode(); got != DiceRollShaperModeStable {
		t.Fatalf("getDiceRollShaperMode() = %s, want stable", got)
	}
}

func TestFormatDiceRollShaperHelpText(t *testing.T) {
	help := formatDiceRollShaperHelpText()
	for _, expected := range []string{
		".rollshape set <模式>",
		"群聊需管理员，私聊由发送者本人设置",
		"balanced // 每轮均匀覆盖所有面；超过 1048576 面时使用 Raw",
		"safe-tail // 两端结果概率减半；没有中间区间时使用 Raw",
	} {
		if !strings.Contains(help, expected) {
			t.Fatalf("help text missing %q:\n%s", expected, help)
		}
	}
}

func TestGroupInfoRollShaperModeChangeClearsBalancedBag(t *testing.T) {
	group := &GroupInfo{GroupID: "group:test"}
	if _, ok := group.setDiceRollShaperMode("balanced"); !ok {
		t.Fatal("set balanced failed")
	}
	shaper := group.getDiceRollShaper()
	shaper.roll(&countingDiceSource{values: []uint64{0}}, 6, 0)
	if len(shaper.bags) == 0 {
		t.Fatal("balanced roll did not create a bag")
	}

	if _, ok := group.setDiceRollShaperMode("stable"); !ok {
		t.Fatal("set stable failed")
	}
	if len(group.getDiceRollShaper().bags) != 0 {
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
	group := &GroupInfo{GroupID: "group:test"}
	ctx := &MsgContext{
		Dice:           &Dice{},
		Group:          group,
		PrivilegeLevel: 50,
	}

	result := solveDiceRollShaper(ctx, nil, &CmdArgs{Args: []string{"set", "safe-tail"}})

	if !result.Matched || !result.Solved {
		t.Fatalf("solve result = %#v, want matched and solved", result)
	}
	if got := group.getDiceRollShaperMode(); got != DiceRollShaperModeSafeTail {
		t.Fatalf("group mode = %s, want safe-tail", got)
	}
}

func TestSolveDiceRollShaperAllowsPrivateSender(t *testing.T) {
	group := &GroupInfo{GroupID: "PG-user:test"}
	ctx := &MsgContext{
		Dice:      &Dice{},
		Group:     group,
		IsPrivate: true,
	}

	solveDiceRollShaper(ctx, nil, &CmdArgs{Args: []string{"set", "soft"}})

	if got := group.getDiceRollShaperMode(); got != DiceRollShaperModeSoft {
		t.Fatalf("private group mode = %s, want soft", got)
	}
}

func TestSolveDiceRollShaperRejectsInvalidModeWithoutMutation(t *testing.T) {
	group := &GroupInfo{
		GroupID:        "group:test",
		RollShaperMode: string(DiceRollShaperModeStable),
	}
	ctx := &MsgContext{
		Dice:           &Dice{},
		Group:          group,
		PrivilegeLevel: 40,
	}

	solveDiceRollShaper(ctx, nil, &CmdArgs{Args: []string{"set", "unknown"}})

	if got := group.getDiceRollShaperMode(); got != DiceRollShaperModeStable {
		t.Fatalf("group mode = %s, want stable after invalid set", got)
	}
}
