package dice

import (
	"testing"

	"github.com/lonelyevil/kook"
)

func TestKookAdapterSessionOwnership(t *testing.T) {
	pa := &PlatformAdapterKook{}
	s1 := &kook.Session{}
	s2 := &kook.Session{}

	if pa.getSession() != nil {
		t.Fatal("new adapter should have no session")
	}
	pa.setSession(s1)
	if pa.getSession() != s1 || !pa.isCurrentSession(s1) {
		t.Fatal("setSession/getSession mismatch")
	}
	if pa.clearSessionIf(s2) {
		t.Fatal("clearSessionIf must not clear a different session")
	}
	if pa.getSession() != s1 {
		t.Fatal("current session was cleared by a stale owner")
	}
	if !pa.clearSessionIf(s1) {
		t.Fatal("clearSessionIf must clear the current session")
	}
	if pa.getSession() != nil {
		t.Fatal("current session was not cleared")
	}
	if pa.clearSessionIf(s1) {
		t.Fatal("double clear should be a no-op")
	}
}
