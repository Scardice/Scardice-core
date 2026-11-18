package dice

import "testing"

// 1118: 被动回复条数限制必须按消息单元计算。一个文本块里的 6 张图片会被
// 拆成 6 条 API 消息，旧实现只截断 textList 会漏掉第 6 条。
func TestOfficialQQPassiveLimitUsesUnits_1118(t *testing.T) {
	chunk := "[CQ:image,file=a][CQ:image,file=b][CQ:image,file=c]" +
		"[CQ:image,file=d][CQ:image,file=e][CQ:image,file=f]"
	units, hasMedia := officialQQSplitTextList([]string{chunk})
	if !hasMedia {
		t.Fatal("expected media units")
	}
	if len(units) != 6 {
		t.Fatalf("units = %d, want 6", len(units))
	}
	limited := limitOfficialQQUnits(units, officialQQPassiveMsgLimit)
	if len(limited) != officialQQPassiveMsgLimit {
		t.Fatalf("limited units = %d, want %d", len(limited), officialQQPassiveMsgLimit)
	}
}
