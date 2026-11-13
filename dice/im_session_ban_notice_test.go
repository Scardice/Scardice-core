package dice

import (
	"strings"
	"testing"
	"time"
)

func TestCheckBanThrottlesRepeatedBlacklistedMemberNotice(t *testing.T) {
	// Given
	d, ep, adapter, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	d.Config.BanList.BanBehaviorQuitIfAdmin = true
	d.Config.BanList.BanNotifyIntervalMinutes = 10
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
		PrivilegeLevel:  -30,
		GroupRoleLevel:  0,
		IsCurGroupBotOn: true,
	}
	msg := &Message{
		Platform:    "QQ",
		MessageType: "group",
		GroupID:     "QQ-Group:100001",
		Sender:      SenderBase{UserID: "QQ:200001", Nickname: "Blocked"},
	}

	// When
	firstBlocked := checkBan(ctx, msg)
	secondBlocked := checkBan(ctx, msg)

	// Then
	if !firstBlocked || !secondBlocked {
		t.Fatalf("blacklisted message results = %v, %v, want both blocked", firstBlocked, secondBlocked)
	}
	adapter.mu.Lock()
	groupMessages := append([]string(nil), adapter.groupMsgs...)
	adapter.mu.Unlock()
	if len(groupMessages) != 1 {
		t.Fatalf("blacklisted member notices = %d, want 1", len(groupMessages))
	}
	if !strings.Contains(groupMessages[0], "test reason") {
		t.Fatalf("blacklisted member notice omits reason: %q", groupMessages[0])
	}
}
