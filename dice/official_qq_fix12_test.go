package dice

import (
	"testing"

	"github.com/sealdice/botgo/dto"
	qqevent "github.com/sealdice/botgo/event"
)

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
	registerOfficialQQReadySink("ready-app", func(data *dto.WSReadyData) {
		got = data
	})

	qqevent.DefaultHandlers.Ready(
		&dto.WSPayload{Session: &dto.Session{AppID: "another-app"}},
		&dto.WSReadyData{},
	)
	if got != nil {
		t.Fatal("READY for a different AppID reached the sink")
	}

	want := &dto.WSReadyData{SessionID: "session-1"}
	qqevent.DefaultHandlers.Ready(
		&dto.WSPayload{Session: &dto.Session{AppID: "ready-app"}},
		want,
	)
	if got != want {
		t.Fatalf("sink received %#v, want %#v", got, want)
	}
}
