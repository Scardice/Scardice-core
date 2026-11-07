package dice

import (
	"testing"

	"github.com/lonelyevil/kook"
)

func TestKookPermissionCache(t *testing.T) {
	pa := &PlatformAdapterKook{}
	key := "guild\x00user"
	if _, ok := pa.cachedGuildAdmin(key); ok {
		t.Fatal("empty cache should miss")
	}
	pa.storeGuildAdmin(key, true)
	if admin, ok := pa.cachedGuildAdmin(key); !ok || !admin {
		t.Fatal("cached admin value was not returned")
	}
	pa.setSession(&kook.Session{})
	if _, ok := pa.cachedGuildAdmin(key); ok {
		t.Fatal("new session must invalidate permission cache")
	}
}
