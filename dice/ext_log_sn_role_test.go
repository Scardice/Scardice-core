//nolint:testpackage
package dice

import (
	"strconv"
	"testing"
)

func TestSNRolePolicyAllowsManagersAndFallsBackWhenRoleUnavailable(t *testing.T) {
	d, defaultEndpoint, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()

	logExt, ok := d.ExtRegistry.Load("log")
	if !ok {
		t.Fatal("log extension is not registered")
	}
	snCommand := logExt.CmdMap["sn"]
	if snCommand == nil {
		t.Fatal("sn command is not registered")
	}

	tests := []struct {
		name        string
		role        string
		apiError    string
		unsupported bool
		wantAllowed bool
	}{
		{name: "owner passes", role: "owner", wantAllowed: true},
		{name: "admin passes", role: "admin", wantAllowed: true},
		{name: "member warns but continues", role: "member", wantAllowed: true},
		{name: "unsupported adapter keeps fallback", unsupported: true, wantAllowed: true},
		{name: "role read failure keeps fallback", apiError: "role lookup failed", wantAllowed: true},
	}

	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			groupQQID := int64(3100 + index)
			botQQID := int64(4100 + index)
			groupID := "QQ-Group:" + strconv.FormatInt(groupQQID, 10)
			botUserID := "QQ:" + strconv.FormatInt(botQQID, 10)
			endpoint := defaultEndpoint
			closeHarness := func() {}

			if !test.unsupported {
				session, _, closeServer := newMilkyRESTHarness(t, test.role, test.apiError, groupQQID, botQQID)
				adapter := &PlatformAdapterMilky{IntentSession: session}
				endpoint = &EndPointInfo{
					EndPointInfoBase: EndPointInfoBase{UserID: botUserID, Platform: "QQ", ProtocolType: "milky"},
					Adapter:          adapter,
				}
				adapter.EndPoint = endpoint
				closeHarness = closeServer
			}
			defer closeHarness()

			ctx, msg := newQuitCommandTestContext(t, d, endpoint, "QQ:"+strconv.Itoa(5100+index), groupID, "SNRoleGroup")

			result := snCommand.Solve(ctx, msg, &CmdArgs{Args: []string{"unknown-template"}})

			if !result.Matched || !result.Solved {
				t.Fatalf("unexpected command result: %#v", result)
			}
			if result.ShowHelp != test.wantAllowed {
				t.Fatalf("command reached existing fallback = %v, want %v", result.ShowHelp, test.wantAllowed)
			}
		})
	}
}
