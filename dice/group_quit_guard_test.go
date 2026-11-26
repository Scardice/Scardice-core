package dice

import (
	"testing"
	"time"

	sealdiceLogger "Scardice-core/logger"
)

func mockAdapterQuitCalls(adapter *mockPlatformAdapter) []string {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	return append([]string(nil), adapter.quitGroups...)
}

func waitForMockAdapterQuitCalls(t *testing.T, adapter *mockPlatformAdapter, want int) []string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		calls := mockAdapterQuitCalls(adapter)
		if len(calls) >= want || time.Now().After(deadline) {
			return calls
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func newGroupQuitTestContext(platform string, protocolType string) (*MsgContext, *mockPlatformAdapter) {
	adapter := newMockPlatformAdapter()
	session := &IMSession{}
	d := &Dice{
		Logger:    sealdiceLogger.M(),
		ImSession: session,
	}
	ep := &EndPointInfo{
		EndPointInfoBase: EndPointInfoBase{
			ID:           "test-ep",
			UserID:       "QQ:100000",
			Platform:     platform,
			ProtocolType: protocolType,
		},
		Adapter: adapter,
	}
	ep.Session = session
	ctx := &MsgContext{
		Dice:        d,
		Session:     session,
		EndPoint:    ep,
		Group:       &GroupInfo{GroupID: "QQ-Group:10001"},
		MessageType: "group",
	}
	return ctx, adapter
}

func TestAutoQuitGroupRoleGuard(t *testing.T) {
	ctx, adapter := newGroupQuitTestContext("QQ", "onebot")

	oldChecker := getBotGroupRoleChecker()
	defer setBotGroupRoleChecker(oldChecker)

	tests := []struct {
		name           string
		role           string
		ok             bool
		wantQuit       bool
		wantBeforeQuit bool
	}{
		{name: "owner blocked", role: "owner", ok: true, wantQuit: false, wantBeforeQuit: false},
		{name: "admin allowed", role: "admin", ok: true, wantQuit: true, wantBeforeQuit: true},
		{name: "member allowed", role: "member", ok: true, wantQuit: true, wantBeforeQuit: true},
		{name: "identity check failed", role: "get_group_member_info failed", ok: false, wantQuit: false, wantBeforeQuit: false},
		{name: "unsupported adapter keeps legacy behaviour", role: errGroupRoleCheckUnsupported, ok: false, wantQuit: true, wantBeforeQuit: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setBotGroupRoleChecker(func(_ *MsgContext, _ string) (string, bool) {
				return tt.role, tt.ok
			})
			adapter.quitGroups = nil
			beforeQuitCalled := false
			got := autoQuitGroup(ctx, "QQ-Group:10001", func(_ *MsgContext) {
				beforeQuitCalled = true
			})
			if got != tt.wantQuit {
				t.Fatalf("autoQuitGroup = %v, want %v", got, tt.wantQuit)
			}
			if beforeQuitCalled != tt.wantBeforeQuit {
				t.Fatalf("beforeQuit called = %v, want %v", beforeQuitCalled, tt.wantBeforeQuit)
			}
			wantQuitCalls := 0
			if tt.wantQuit {
				wantQuitCalls = 1
			}
			if len(adapter.quitGroups) != wantQuitCalls {
				t.Fatalf("quit calls = %v, want %d", adapter.quitGroups, wantQuitCalls)
			}
		})
	}
}

func TestAutoQuitGroupSkipsRoleCheckForNonQQ(t *testing.T) {
	ctx, adapter := newGroupQuitTestContext("KOOK", "")

	oldChecker := getBotGroupRoleChecker()
	defer setBotGroupRoleChecker(oldChecker)
	setBotGroupRoleChecker(func(_ *MsgContext, _ string) (string, bool) {
		t.Fatal("非 QQ 平台不应查询群角色")
		return "", false
	})

	if !autoQuitGroup(ctx, "KOOK-Guild:10001", nil) {
		t.Fatal("非 QQ 平台自动退群不应被阻断")
	}
	if len(adapter.quitGroups) != 1 {
		t.Fatalf("quit calls = %v, want 1", adapter.quitGroups)
	}
}

func newBlacklistAutoQuitTestContext(t *testing.T) (*Dice, *mockPlatformAdapter, *MsgContext, *Message, func()) {
	t.Helper()
	d, ep, adapter, cleanup := newExecuteNewTestDice(t)
	d.Config.BanList.BanBehaviorQuitIfAdmin = true
	d.Config.BanList.Map.Store("QQ:200001", &BanListInfoItem{
		ID:      "QQ:200001",
		Rank:    BanRankBanned,
		Reasons: []string{"test reason"},
		Places:  []string{"QQ-Group:100001"},
		Times:   []int64{time.Unix(1_700_000_000, 0).Unix()},
	})
	ctx := &MsgContext{
		Dice:            d,
		Session:         d.ImSession,
		EndPoint:        ep,
		Group:           &GroupInfo{GroupID: "QQ-Group:100001"},
		PrivilegeLevel:  -30,
		GroupRoleLevel:  40,
		IsCurGroupBotOn: true,
	}
	msg := &Message{
		Platform:    "QQ",
		MessageType: "group",
		GroupID:     "QQ-Group:100001",
		Sender:      SenderBase{UserID: "QQ:200001", Nickname: "Blocked"},
	}
	return d, adapter, ctx, msg, cleanup
}

func TestCheckBanDoesNotQuitOwnerGroup(t *testing.T) {
	_, adapter, ctx, msg, cleanup := newBlacklistAutoQuitTestContext(t)
	defer cleanup()

	oldChecker := getBotGroupRoleChecker()
	defer setBotGroupRoleChecker(oldChecker)
	setBotGroupRoleChecker(func(_ *MsgContext, _ string) (string, bool) {
		return "owner", true
	})

	if !checkBan(ctx, msg) {
		t.Fatal("黑名单用户消息应被拦截")
	}
	time.Sleep(100 * time.Millisecond)
	if calls := mockAdapterQuitCalls(adapter); len(calls) != 0 {
		t.Fatalf("群主群不应自动退群，got %v", calls)
	}
}

func TestCheckBanQuitsNonOwnerGroup(t *testing.T) {
	_, adapter, ctx, msg, cleanup := newBlacklistAutoQuitTestContext(t)
	defer cleanup()

	oldChecker := getBotGroupRoleChecker()
	defer setBotGroupRoleChecker(oldChecker)
	setBotGroupRoleChecker(func(_ *MsgContext, _ string) (string, bool) {
		return "member", true
	})

	if !checkBan(ctx, msg) {
		t.Fatal("黑名单用户消息应被拦截")
	}
	if calls := waitForMockAdapterQuitCalls(t, adapter, 1); len(calls) != 1 || calls[0] != "QQ-Group:100001" {
		t.Fatalf("非群主群应自动退群，got %v", calls)
	}
}

func TestParseQQGroupRole(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{in: "owner", want: "owner", ok: true},
		{in: "creator", want: "owner", ok: true},
		{in: "群主", want: "owner", ok: true},
		{in: "admin", want: "admin", ok: true},
		{in: "administrator", want: "admin", ok: true},
		{in: "管理员", want: "admin", ok: true},
		{in: "member", want: "member", ok: true},
		{in: "membernormal", want: "member", ok: true},
		{in: "成员", want: "member", ok: true},
		{in: "OWNER", want: "owner", ok: true},
		{in: "", want: "", ok: false},
		{in: "guest", want: "", ok: false},
		{in: "administrator_unknown", want: "", ok: false},
	}

	for _, tt := range tests {
		got, ok := parseQQGroupRole(tt.in)
		if got != tt.want || ok != tt.ok {
			t.Fatalf("parseQQGroupRole(%q) = (%q, %v), want (%q, %v)", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}
