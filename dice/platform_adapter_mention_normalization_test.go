package dice

import "testing"

func TestAtParseConsumesNormalizedProviderMentions(t *testing.T) {
	for _, platform := range []string{"DISCORD", "KOOK", "TG", "DODO", "SLACK", "SEALCHAT"} {
		t.Run(platform, func(t *testing.T) {
			rest, mentions := AtParse("<@user-1> .r 1d6", platform)
			if rest != " .r 1d6" || len(mentions) != 1 || mentions[0].UserID != platform+":user-1" {
				t.Fatalf("rest=%q mentions=%#v", rest, mentions)
			}
		})
	}
}

func TestAtParseReadsUISandboxCQMentions(t *testing.T) {
	rest, mentions := AtParse("[CQ:at,qq=1000] .ra 侦查 [CQ:at,qq=alice,name=爱丽丝]", "UI")
	if rest != " .ra 侦查 " {
		t.Fatalf("rest = %q, want mentions removed", rest)
	}
	if len(mentions) != 2 || mentions[0].UserID != "UI:1000" || mentions[1].UserID != "UI:alice" {
		t.Fatalf("mentions = %#v, want UI:1000 and UI:alice", mentions)
	}
	if got := AtBuild("UI:alice"); got != "[CQ:at,qq=alice]" {
		t.Fatalf("AtBuild(UI:alice) = %q, want CQ mention", got)
	}
	if _, mentions := AtParse("<@alice> .r", "UI"); len(mentions) != 0 {
		t.Fatalf("UI should not parse provider-normalized mentions: %#v", mentions)
	}
}

func TestProviderMentionCodecsNormalizeBeforeCore(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{name: "kook", got: normalizeKookInboundText("hi (met)user-1(met)"), want: "hi <@user-1>"},
		{name: "telegram", got: normalizeTelegramInboundText("hi tg://user?id=123"), want: "hi <@123>"},
		{name: "dodo", got: normalizeDodoInboundText("hi <@!user-1>"), want: "hi <@user-1>"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if test.got != test.want {
				t.Fatalf("normalized text = %q, want %q", test.got, test.want)
			}
		})
	}
}
