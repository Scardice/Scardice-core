package dice

import (
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestOfficialQQSelfMentionIsNotDelegateTarget(t *testing.T) {
	t.Parallel()

	const (
		uin         = "123"
		botOpenID   = "bot-member-openid"
		botMemberID = "OpenQQ:123-" + botOpenID
	)
	ctx := &MsgContext{
		EndPoint: &EndPointInfo{EndPointInfoBase: EndPointInfoBase{
			Platform:     "QQ",
			ProtocolType: "official",
			UserID:       "OpenQQ:" + uin,
		}},
		Player: &GroupPlayerInfo{UserID: "OpenQQ:" + uin},
	}
	cmdArgs := &CmdArgs{
		At:           []*AtInfo{{UserID: botMemberID}},
		uidForAtInfo: botMemberID,
	}
	ctx.DelegateText = "由<骰子>代骰:\n"

	if !cmdArgs.isBotSelfMention(ctx, botMemberID) {
		t.Fatal("official QQ self mention was not recognized")
	}

	proxy := GetCtxProxyAtPosRaw(ctx, cmdArgs, 0, false)
	if proxy != ctx {
		t.Fatal("self mention was selected as delegate target")
	}
	if ctx.DelegateText != "" {
		t.Fatalf("delegate text was not cleared for self mention: %q", ctx.DelegateText)
	}
}

func TestOfficialQQOtherMentionIsStillDelegateTarget(t *testing.T) {
	t.Parallel()

	ctx := &MsgContext{
		EndPoint: &EndPointInfo{EndPointInfoBase: EndPointInfoBase{
			Platform:     "QQ",
			ProtocolType: "official",
			UserID:       "OpenQQ:123",
		}},
		Player: &GroupPlayerInfo{UserID: "OpenQQ:123"},
	}
	cmdArgs := &CmdArgs{
		At:           []*AtInfo{{UserID: "OpenQQ:123-other-member"}},
		uidForAtInfo: "OpenQQ:123-bot-member",
	}

	if cmdArgs.isBotSelfMention(ctx, "OpenQQ:123-other-member") {
		t.Fatal("another member was mistaken for the bot")
	}
}

func TestAtParseOfficialQQMentionTags(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		text string
		want string
	}{
		{name: "qqbot tag", text: `<qqbot-at-user id="bot-open-id" /> .r`, want: "OpenQQ:bot-open-id"},
		{name: "legacy tag", text: `<@!member-open-id> .r`, want: "OpenQQ:member-open-id"},
	} {
		remaining, at := AtParse(tc.text, "OpenQQ")
		if len(at) != 1 || at[0].UserID != tc.want {
			t.Fatalf("%s: At = %#v, want %s", tc.name, at, tc.want)
		}
		if !strings.Contains(remaining, ".r") {
			t.Fatalf("%s: remaining text = %q", tc.name, remaining)
		}
	}
}

func TestOfficialQQQRLoginStateCompatibility(t *testing.T) {
	t.Parallel()

	// Scardice-ui 硬编码了 0/1/2 三个扫码状态，不能随上游枚举顺序变化。
	if OfficialQQLoginStateInit != 0 || OfficialQQLoginStateQRWaitingForScan != 1 || OfficialQQLoginStateFailed != 2 {
		t.Fatalf("QR login state values changed: init=%d waiting=%d failed=%d",
			OfficialQQLoginStateInit, OfficialQQLoginStateQRWaitingForScan, OfficialQQLoginStateFailed)
	}
}

func TestOfficialQQAppIDNumericCompatibility(t *testing.T) {
	t.Parallel()

	var adapter PlatformAdapterOfficialQQ
	if err := yaml.Unmarshal([]byte("appID: 123456789\nappSecret: secret\n"), &adapter); err != nil {
		t.Fatal(err)
	}
	if adapter.AppID.String() != "123456789" {
		t.Fatalf("YAML appID = %q", adapter.AppID.String())
	}
	if err := json.Unmarshal([]byte(`{"appID":123456789}`), &adapter); err != nil {
		t.Fatal(err)
	}
	if adapter.AppID.String() != "123456789" {
		t.Fatalf("JSON appID = %q", adapter.AppID.String())
	}
	raw, err := json.Marshal(&adapter)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"appID":"123456789"`) {
		t.Fatalf("serialized appID = %s", raw)
	}
}
