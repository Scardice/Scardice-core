package dice

import (
	"testing"

	"golang.org/x/time/rate"
)

func TestGroupRuntimeRegistryKeepsLimiterAcrossFacadeReconstruction(t *testing.T) {
	registry := NewGroupPlayerRuntimeRegistry()
	first := registry.Group("dice-1", "group-1")
	first.limiterMu.Lock()
	first.limiter = rate.NewLimiter(0, 1)
	first.limiterMu.Unlock()
	if !first.allowCommand() {
		t.Fatal("first limiter token was unavailable")
	}

	second := registry.Group("dice-1", "group-1")
	if first != second {
		t.Fatal("registry rebuilt group runtime resources")
	}
	if second.allowCommand() {
		t.Fatal("reconstructed facade received a fresh limiter")
	}
}

func TestGroupRuntimeRegistryKeepsPlayerLimiterAcrossFacadeReconstruction(t *testing.T) {
	registry := NewGroupPlayerRuntimeRegistry()
	first := registry.Player("dice-1", "group-1", "user-1")
	first.limiterMu.Lock()
	first.limiter = rate.NewLimiter(0, 1)
	first.limiterMu.Unlock()
	if !first.limiter.Allow() {
		t.Fatal("first player limiter token was unavailable")
	}

	second := registry.Player("dice-1", "group-1", "user-1")
	if first != second {
		t.Fatal("registry rebuilt player runtime resources")
	}
	if second.limiter.Allow() {
		t.Fatal("reconstructed player facade received a fresh limiter")
	}
}

func TestGroupRuntimeRegistryKeepsSpamStateAcrossFacadeReconstruction(t *testing.T) {
	registry := NewGroupPlayerRuntimeRegistry()
	group := registry.Group("dice-1", "group-1")
	group.limiterMu.Lock()
	group.spamLastCommand, group.spamLastCommandAt, group.spamSameCommandCount = ".r", 100, 3
	group.limiterMu.Unlock()
	player := registry.Player("dice-1", "group-1", "user-1")
	player.limiterMu.Lock()
	player.spamLastCommand, player.spamLastCommandAt, player.spamSameCommandCount = ".st", 200, 5
	player.limiterMu.Unlock()

	group = registry.Group("dice-1", "group-1")
	player = registry.Player("dice-1", "group-1", "user-1")
	if group.spamLastCommand != ".r" || group.spamLastCommandAt != 100 || group.spamSameCommandCount != 3 {
		t.Fatalf("group spam state was reset: %q/%d/%d", group.spamLastCommand, group.spamLastCommandAt, group.spamSameCommandCount)
	}
	if player.spamLastCommand != ".st" || player.spamLastCommandAt != 200 || player.spamSameCommandCount != 5 {
		t.Fatalf("player spam state was reset: %q/%d/%d", player.spamLastCommand, player.spamLastCommandAt, player.spamSameCommandCount)
	}
}

func TestGroupRuntimeRegistryIsolatesLimiterAndSpamByGroupAndPlayer(t *testing.T) {
	registry := NewGroupPlayerRuntimeRegistry()
	first := registry.Player("dice-1", "group-1", "user-1")
	first.limiterMu.Lock()
	first.limiter = rate.NewLimiter(0, 1)
	first.spamLastCommand, first.spamSameCommandCount = ".r", 4
	first.limiterMu.Unlock()

	for name, other := range map[string]*PlayerRuntimeResources{
		"other group": registry.Player("dice-1", "group-2", "user-1"),
		"other user":  registry.Player("dice-1", "group-1", "user-2"),
		"other dice":  registry.Player("dice-2", "group-1", "user-1"),
	} {
		other.limiterMu.Lock()
		leaked := other.limiter != nil || other.spamLastCommand != "" || other.spamSameCommandCount != 0
		other.limiterMu.Unlock()
		if leaked {
			t.Fatalf("%s inherited limiter or spam state", name)
		}
	}

	group := registry.Group("dice-1", "group-1")
	group.limiterMu.Lock()
	group.limiter = rate.NewLimiter(0, 1)
	group.spamLastCommand = ".r"
	group.limiterMu.Unlock()
	other := registry.Group("dice-1", "group-2")
	other.limiterMu.Lock()
	leaked := other.limiter != nil || other.spamLastCommand != ""
	other.limiterMu.Unlock()
	if leaked {
		t.Fatal("another group inherited limiter or spam state")
	}
}

func TestGroupRuntimeRegistrySeparatesDiceAndPlayerIdentities(t *testing.T) {
	registry := NewGroupPlayerRuntimeRegistry()
	if registry.Group("dice-1", "group-1") == registry.Group("dice-2", "group-1") {
		t.Fatal("group runtime resources crossed Dice identities")
	}
	if registry.Player("dice-1", "group-1", "user-1") == registry.Player("dice-1", "group-1", "user-2") {
		t.Fatal("player runtime resources crossed user identities")
	}
}

func TestGroupRuntimeRegistryRevokesDetachedFacades(t *testing.T) {
	registry := NewGroupPlayerRuntimeRegistry()
	group := registry.Group("dice-1", "group-1")
	player := registry.Player("dice-1", "group-1", "user-1")

	registry.DeleteGroup("dice-1", "group-1")

	if !group.revoked.Load() || !player.revoked.Load() {
		t.Fatal("group invalidation left detached runtime authority active")
	}
	if fresh := registry.Group("dice-1", "group-1"); fresh == group || fresh.revoked.Load() {
		t.Fatal("recreated group did not receive fresh runtime resources")
	}
}
