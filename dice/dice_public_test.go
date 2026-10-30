package dice

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPublicDiceEndpointsReportOfficialQQAppID(t *testing.T) {
	t.Parallel()

	d := &Dice{ImSession: &IMSession{EndPoints: []*EndPointInfo{
		{
			EndPointInfoBase: EndPointInfoBase{
				ID:           "official-qq",
				Platform:     "QQ",
				ProtocolType: "official",
				UserID:       "OpenQQ:1",
				IsPublic:     true,
				State:        StateConnected,
			},
			Adapter: &PlatformAdapterOfficialQQ{AppID: "123456789", UIN: "1"},
		},
		{
			EndPointInfoBase: EndPointInfoBase{
				ID:           "onebot",
				Platform:     "QQ",
				ProtocolType: "onebot",
				UserID:       "QQ:10000",
				IsPublic:     true,
			},
		},
	}}}
	d.ImSession.Parent = d

	endpoints := d.publicDiceEndpoints()
	if len(endpoints) != 2 {
		t.Fatalf("publicDiceEndpoints() = %d, want 2", len(endpoints))
	}
	raw, err := json.Marshal(endpoints)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, `"appId":"123456789"`) {
		t.Fatalf("endpoint payload omitted official QQ appId: %s", text)
	}
	if !strings.Contains(text, `"uid":"OpenQQ:1"`) {
		t.Fatalf("endpoint payload omitted official QQ uid: %s", text)
	}

	tickRaw, err := json.Marshal(d.publicDiceTickEndpoints())
	if err != nil {
		t.Fatal(err)
	}
	tickText := string(tickRaw)
	if !strings.Contains(tickText, `"appId":"123456789"`) {
		t.Fatalf("tick payload omitted official QQ appId: %s", tickText)
	}
	if !strings.Contains(tickText, `"uid":"OpenQQ:1"`) {
		t.Fatalf("tick payload omitted official QQ uid: %s", tickText)
	}
}

func TestPublicDiceEndpointAppIDOnlyForOfficialQQ(t *testing.T) {
	t.Parallel()

	official := &EndPointInfo{
		EndPointInfoBase: EndPointInfoBase{Platform: "QQ", ProtocolType: "official"},
		Adapter:          &PlatformAdapterOfficialQQ{AppID: "123"},
	}
	if got := publicDiceEndpointAppID(official); got != "123" {
		t.Fatalf("official appID = %q", got)
	}

	onebot := &EndPointInfo{
		EndPointInfoBase: EndPointInfoBase{Platform: "QQ", ProtocolType: "onebot"},
		Adapter:          &PlatformAdapterOfficialQQ{AppID: "123"},
	}
	if got := publicDiceEndpointAppID(onebot); got != "" {
		t.Fatalf("onebot appID = %q", got)
	}
	if got := publicDiceEndpointAppID(nil); got != "" {
		t.Fatalf("nil appID = %q", got)
	}
}
