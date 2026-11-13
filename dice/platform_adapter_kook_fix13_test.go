package dice

import (
	"testing"

	"github.com/lonelyevil/kook"
)

// A panic inside Serve (also reachable from SetEnable/DoRelogin) must leave the
// endpoint in a clear failed state instead of "连接中" with serving still set.
func TestKookAbortServeAfterPanicClearsState(t *testing.T) {
	ep := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{Enable: true, State: StateConnecting}}
	pa := &PlatformAdapterKook{EndPoint: ep}
	pa.serving = true
	pa.adminCache = map[string]kookAdminCacheEntry{"guild\x00user": {admin: true}}
	pa.guildCache = map[string]kookGuildCacheEntry{"guild": {}}

	pa.abortServeAfterPanic(nil)

	if pa.serving {
		t.Fatal("serving flag was not cleared after a panic")
	}
	if ep.Enable || ep.State != StateConnectionFailed {
		t.Fatalf("endpoint = (enable=%v, state=%d), want disabled/failed", ep.Enable, ep.State)
	}
	if pa.adminCache != nil || pa.guildCache != nil {
		t.Fatal("permission caches were not cleared")
	}
}

// The panic cleanup of an old Serve must not touch a session that already
// replaced it, otherwise a fast disable→enable would be marked failed.
func TestKookAbortServeAfterPanicKeepsNewerSession(t *testing.T) {
	ep := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{Enable: true, State: StateConnected}}
	pa := &PlatformAdapterKook{EndPoint: ep}
	newSession := &kook.Session{}
	pa.IntentSession = newSession
	pa.serving = true

	pa.abortServeAfterPanic(&kook.Session{})

	if pa.IntentSession != newSession {
		t.Fatal("newer session was cleared")
	}
	if !pa.serving || !ep.Enable || ep.State != StateConnected {
		t.Fatalf("newer session state was clobbered: serving=%v enable=%v state=%d", pa.serving, ep.Enable, ep.State)
	}
}

// A Serve that panics before creating a session must not turn a user-disabled
// endpoint into "connection failed".
func TestKookAbortServeAfterPanicKeepsDisabledState(t *testing.T) {
	ep := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{Enable: false, State: StateDisconnected}}
	pa := &PlatformAdapterKook{EndPoint: ep}
	pa.serving = true

	pa.abortServeAfterPanic(nil)

	if pa.serving {
		t.Fatal("serving flag should be cleared")
	}
	if ep.Enable || ep.State != StateDisconnected {
		t.Fatalf("disabled endpoint was clobbered: enable=%v state=%d", ep.Enable, ep.State)
	}
}
