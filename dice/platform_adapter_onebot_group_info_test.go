package dice

import (
	"testing"

	"Scardice-core/adapterapi"
)

func TestOnebotGroupInfoRefreshResultToleratesProviderQuirks(t *testing.T) {
	target := adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:2002"}
	cases := []struct {
		name      string
		data      string
		wantMax   bool
		wantCount uint32
	}{
		{"standard", `{"group_id":2002,"group_name":"G","member_count":45,"max_member_count":500}`, true, 45},
		{"max zero means unknown", `{"group_id":2002,"group_name":"G","member_count":45,"max_member_count":0}`, false, 45},
		{"max below count means unknown", `{"group_id":2002,"group_name":"G","member_count":45,"max_member_count":40}`, false, 45},
		{"string group id", `{"group_id":"2002","group_name":"G","member_count":45,"max_member_count":500}`, true, 45},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte(`{"status":"ok","retcode":0,"data":` + tc.data + `}`)
			result := onebotGroupInfoRefreshResult(adapterapi.EffectRetryClass(0), raw, target, 2002)
			if result.Outcome != adapterapi.EffectSucceeded || result.GroupInfo == nil {
				t.Fatalf("result = %+v", result)
			}
			if result.GroupInfo.MaxMemberCountKnown != tc.wantMax || result.GroupInfo.MemberCount != tc.wantCount {
				t.Fatalf("info = %+v", *result.GroupInfo)
			}
		})
	}
}

func TestOnebotGroupInfoRefreshResultRejectsOtherGroup(t *testing.T) {
	target := adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:2002"}
	raw := []byte(`{"status":"ok","retcode":0,"data":{"group_id":999,"group_name":"G"}}`)
	if result := onebotGroupInfoRefreshResult(adapterapi.EffectRetryClass(0), raw, target, 2002); result.Outcome == adapterapi.EffectSucceeded {
		t.Fatalf("mismatched group accepted: %+v", result)
	}
}

func TestLogSafeNameStripsControlCharacters(t *testing.T) {
	got := logSafeName("喵\n   \n$\x00\x1b[31mC\xff")
	if got != "喵   $[31mC" {
		t.Fatalf("logSafeName = %q", got)
	}
	if logSafeName("普通昵称🍜") != "普通昵称🍜" {
		t.Fatal("clean name must stay unchanged")
	}
}
