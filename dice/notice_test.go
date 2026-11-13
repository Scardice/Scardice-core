//nolint:testpackage
package dice

import (
	"reflect"
	"testing"

	"go.uber.org/zap"
)

type noticeCaptureAdapter struct {
	*mockPlatformAdapter
	personIDs chan string
}

func (adapter *noticeCaptureAdapter) SendToPerson(_ *MsgContext, userID string, _ string, _ string) {
	adapter.personIDs <- userID
}

func Test_ParseNoticeTarget_preserves_legacy_ID_and_canonicalizes_filter(t *testing.T) {
	// Given
	raw := "OpenQQ-Group:100-abc-OpenQQ:100-user:only=ban,group,ban"

	// When
	target := ParseNoticeTarget(raw)

	// Then
	wantTypes := []NoticeType{NoticeTypeGroup, NoticeTypeBan}
	if target.ID != "OpenQQ-Group:100-abc-OpenQQ:100-user" {
		t.Fatalf("target ID = %q, want embedded-colon ID preserved", target.ID)
	}
	if !reflect.DeepEqual(target.NoticeTypes, wantTypes) {
		t.Fatalf("notice types = %v, want %v", target.NoticeTypes, wantTypes)
	}
	if got := target.String(); got != "OpenQQ-Group:100-abc-OpenQQ:100-user:only=group,ban" {
		t.Fatalf("canonical target = %q", got)
	}
}

func Test_FilterNoticeTargets_selects_only_enabled_configured_category(t *testing.T) {
	// Given
	rawTargets := []string{
		"QQ:1001:only=ban",
		"QQ:1002:only=group",
		"QQ:1003:disable:only=ban",
		"QQ:1004",
	}

	// When
	targets := filterNoticeTargets(rawTargets, NoticeTypeBan)

	// Then
	want := []NoticeTarget{
		ParseNoticeTarget("QQ:1001:only=ban"),
		ParseNoticeTarget("QQ:1004"),
	}
	if !reflect.DeepEqual(targets, want) {
		t.Fatalf("delivery targets = %#v, want %#v", targets, want)
	}
}

func Test_NoticeTargetMatchesEndpoint_separates_official_and_ordinary_QQ(t *testing.T) {
	tests := []struct {
		name         string
		raw          string
		protocolType string
		want         bool
	}{
		{name: "ordinary target reaches onebot", raw: "QQ:1", protocolType: "onebot", want: true},
		{name: "ordinary target skips official", raw: "QQ:1", protocolType: "official", want: false},
		{name: "official target reaches official", raw: "OpenQQ:app-user", protocolType: "official", want: true},
		{name: "official target skips onebot", raw: "OpenQQ:app-user", protocolType: "onebot", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// When
			got := ParseNoticeTarget(test.raw).MatchesEndpoint("QQ", test.protocolType)

			// Then
			if got != test.want {
				t.Fatalf("MatchesEndpoint(QQ, %q) = %t, want %t", test.protocolType, got, test.want)
			}
		})
	}
}

func Test_sendNoticeTargetCrossPlatform_delivers_selected_target_without_metadata(t *testing.T) {
	// Given
	adapter := &noticeCaptureAdapter{
		mockPlatformAdapter: newMockPlatformAdapter(),
		personIDs:           make(chan string, 1),
	}
	d := &Dice{Logger: zap.NewNop().Sugar(), Config: Config{BaseConfig: BaseConfig{NoticeIDs: []string{
		"QQ:1001:only=ban",
		"QQ:1002:only=group",
		"QQ:1003:disable:only=ban",
	}}}}
	endpoint := &EndPointInfo{
		EndPointInfoBase: EndPointInfoBase{
			Platform:     "QQ",
			ProtocolType: "onebot",
			Enable:       true,
			State:        StateConnected,
		},
		Adapter: adapter,
	}
	session := &IMSession{Parent: d, EndPoints: []*EndPointInfo{endpoint}}
	d.ImSession = session
	endpoint.Session = session
	ctx := &MsgContext{Dice: d, Session: session, EndPoint: endpoint}

	// When
	targets := filterNoticeTargets(d.Config.NoticeIDs, NoticeTypeBan)
	if len(targets) != 1 {
		t.Fatalf("selected targets = %#v, want one ban target", targets)
	}
	sent := sendNoticeTargetCrossPlatform(ctx, targets[0], "ban notice")

	// Then
	if !sent {
		t.Fatal("selected notice target was not delivered")
	}
	if userID := <-adapter.personIDs; userID != "QQ:1001" {
		t.Fatalf("delivered user ID = %q, want QQ:1001", userID)
	}
}
