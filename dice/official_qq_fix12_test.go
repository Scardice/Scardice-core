package dice

import (
	"testing"

	"github.com/sealdice/botgo/dto"
	qqevent "github.com/sealdice/botgo/event"
	"golang.org/x/oauth2"
)

type fakeReadyTokenSource struct{ id byte }

func (f *fakeReadyTokenSource) Token() (*oauth2.Token, error) {
	_ = f.id // 非零大小，保证不同实例的 interface 指针可区分
	return &oauth2.Token{}, nil
}

func TestOfficialQQCanSendDuringReadyWindow(t *testing.T) {
	ep := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{Enable: true, State: StateConnecting}}
	pa := &PlatformAdapterOfficialQQ{EndPoint: ep}
	if !pa.canSend() {
		t.Fatal("a connecting session must be allowed to reply before READY")
	}
	ep.State = StateConnected
	if !pa.canSend() {
		t.Fatal("a connected session must be allowed to send")
	}
	ep.State = StateConnectionFailed
	if pa.canSend() {
		t.Fatal("a failed session must not send")
	}
	ep.State = StateConnected
	ep.Enable = false
	if pa.canSend() {
		t.Fatal("a disabled session must not send")
	}
}

func TestOfficialQQReadySinkDispatchesByAppID(t *testing.T) {
	if qqevent.DefaultHandlers.Ready == nil {
		t.Fatal("botgo READY dispatcher is not installed")
	}
	var got *dto.WSReadyData
	tokenSource := &fakeReadyTokenSource{}
	registerOfficialQQReadySink("ready-app", tokenSource, func(data *dto.WSReadyData) {
		got = data
	})

	qqevent.DefaultHandlers.Ready(
		&dto.WSPayload{Session: &dto.Session{AppID: "another-app"}},
		&dto.WSReadyData{},
	)
	if got != nil {
		t.Fatal("READY for a different AppID reached the sink")
	}

	// 1118: 旧连接（不同 token source）的迟到 READY 必须被忽略。
	qqevent.DefaultHandlers.Ready(
		&dto.WSPayload{Session: &dto.Session{AppID: "ready-app", TokenSource: &fakeReadyTokenSource{}}},
		&dto.WSReadyData{SessionID: "stale-session"},
	)
	if got != nil {
		t.Fatal("READY from a replaced session reached the sink")
	}

	want := &dto.WSReadyData{SessionID: "session-1"}
	qqevent.DefaultHandlers.Ready(
		&dto.WSPayload{Session: &dto.Session{AppID: "ready-app", TokenSource: tokenSource}},
		want,
	)
	if got != want {
		t.Fatalf("sink received %#v, want %#v", got, want)
	}
}
