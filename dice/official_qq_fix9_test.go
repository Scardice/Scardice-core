package dice

import (
	"fmt"
	"testing"
)

func TestNormalizeOfficialQQWebhookConfig(t *testing.T) {
	path, port, err := normalizeOfficialQQWebhookConfig("webhook", 0)
	if err != nil {
		t.Fatalf("normalize webhook failed: %v", err)
	}
	if path != "/webhook" || port != 8099 {
		t.Fatalf("normalized = (%q, %d), want (/webhook, 8099)", path, port)
	}
	if _, _, err := normalizeOfficialQQWebhookConfig("/webhook", 70000); err == nil {
		t.Fatal("out-of-range port was accepted")
	}
	if _, _, err := normalizeOfficialQQWebhookConfig("/{bad", 8099); err == nil {
		t.Fatal("invalid ServeMux pattern was accepted")
	}
}

func TestReplaceOfficialQQCredentialsAcceptsLegacyBotID(t *testing.T) {
	existing := NewOfficialQQConnItem("old-app", "old-secret", "123", false)
	existing.UserID = "OpenQQ:bot-open-id"
	adapter := existing.Adapter.(*PlatformAdapterOfficialQQ)
	adapter.UIN = ""

	replaced, err := replaceOfficialQQCredentials(
		existing,
		&PlatformAdapterOfficialQQ{AppID: "new-app", AppSecret: "new-secret"},
		&OfficialQQAccountProbeResult{UIN: "123", BotID: "bot-open-id", Nickname: "new bot"},
	)
	if err != nil {
		t.Fatalf("legacy botID replacement rejected: %v", err)
	}
	if replaced != adapter || existing.UserID != "OpenQQ:123" || adapter.getUIN() != "123" {
		t.Fatalf("replacement state = userID %q uin %q", existing.UserID, adapter.getUIN())
	}
}

func TestFindOfficialQQEndpointByUINOrBotID(t *testing.T) {
	legacy := NewOfficialQQConnItem("old-app", "old-secret", "", false)
	legacy.UserID = "OpenQQ:bot-open-id"
	legacy.Adapter.(*PlatformAdapterOfficialQQ).UIN = ""
	session := &IMSession{EndPoints: []*EndPointInfo{legacy}}

	if got := FindOfficialQQEndpointByUINOrBotID(session, "123", "bot-open-id", ""); got != legacy {
		t.Fatalf("legacy endpoint not found by botID: %#v", got)
	}
	if got := FindOfficialQQEndpointByUINOrBotID(session, "123", "other", ""); got != nil {
		t.Fatalf("unexpected endpoint match: %#v", got)
	}
	if got := FindOfficialQQEndpointByUINOrBotID(session, "", "", ""); got != nil {
		t.Fatalf("empty lookup matched endpoint: %#v", got)
	}
}

func TestMustExtractTwoIDRejectsMalformedChannel(t *testing.T) {
	pa := &PlatformAdapterOfficialQQ{UIN: "123"}
	if _, _, kind := pa.mustExtractTwoID("OpenQQCH-Channel:"); kind != OpenQQUnknown {
		t.Fatalf("malformed channel kind = %d, want unknown", kind)
	}
	channel, guild, kind := pa.mustExtractTwoID("OpenQQCH-Channel:100-200")
	if kind != OpenQQCHChannel || channel != "200" || guild != "100" {
		t.Fatalf("channel=%q guild=%q kind=%d", channel, guild, kind)
	}
}

func TestQQBotIDStringAvoidsScientificNotation(t *testing.T) {
	if got := qqBotIDString(float64(12345678901)); got != "12345678901" {
		t.Fatalf("float bot appid = %q", got)
	}
	if got := qqBotIDString(" 123 "); got != "123" {
		t.Fatalf("string bot appid = %q", got)
	}
	if got := qqBotIDString(nil); got != "" {
		t.Fatalf("nil bot appid = %q", got)
	}
}

func TestPaginationCacheEvictionKeepsFreshEntries(t *testing.T) {
	pa := &PlatformAdapterOfficialQQ{}
	for i := 0; i < 1001; i++ {
		pa.addToPaginationCache(fmt.Sprintf("id-%d", i), []string{"page"})
	}
	pa.paginationMu.Lock()
	defer pa.paginationMu.Unlock()
	if len(pa.paginationCache) != 1000 {
		t.Fatalf("cache size = %d, want 1000", len(pa.paginationCache))
	}
	if _, ok := pa.paginationCache["id-1000"]; !ok {
		t.Fatal("newest pagination entry was evicted")
	}
}
