package dice

import "testing"

func TestOfficialQQDelegateKeepsCanonicalIdentitiesDistinct(t *testing.T) {
	d, _ := newCanonicalTestDice(t)
	endpoint := newCanonicalTestEndpoint(d, "OpenQQ:fixture-bot")
	endpoint.Platform = "OpenQQ"
	endpoint.Adapter = &PlatformAdapterOfficialQQ{AppID: 123456789}
	message := newGroupMsg(officialQQIdentityGroupID, officialQQIdentityMemberID, "")
	message.Platform = "OpenQQ"
	ctx := newCanonicalTestMessageContext(t, d, endpoint, message, "official-qq-canonical-delegates")
	targets := []struct {
		userID string
		name   string
	}{
		{userID: "OpenQQ-Member-T:123456789-group-open-id-other-member", name: "AppID-scoped player"},
		{userID: "OpenQQ:member-open-id", name: "imported unscoped player"},
		{userID: "OpenQQ:99887766-member-open-id", name: "distinct UIN-scoped player"},
	}
	for _, target := range targets {
		requireOfficialQQCanonicalPlayer(t, ctx, target.userID, target.name)
	}
	for _, target := range targets {
		delegated, found := (&AtInfo{UserID: target.userID}).CopyCtx(ctx)
		if !found || delegated.Player == nil {
			t.Fatalf("canonical delegate %q not found: %#v", target.userID, delegated.Player)
		}
		if delegated.Player.UserID() != target.userID || delegated.Player.Name() != target.name {
			t.Fatalf("delegate %q resolved to %q (%q)", target.userID, delegated.Player.UserID(), delegated.Player.Name())
		}
	}
}

func TestOfficialQQDelegateCreatesUnmappedCanonicalIdentity(t *testing.T) {
	d, _ := newCanonicalTestDice(t)
	endpoint := newCanonicalTestEndpoint(d, "OpenQQ:fixture-bot")
	endpoint.Platform = "OpenQQ"
	endpoint.Adapter = &PlatformAdapterOfficialQQ{AppID: 123456789}
	message := newGroupMsg(officialQQIdentityGroupID, officialQQIdentityMemberID, "")
	message.Platform = "OpenQQ"
	ctx := newCanonicalTestMessageContext(t, d, endpoint, message, "official-qq-new-canonical-delegate")
	const targetID = "OpenQQ-Member-T:123456789-group-open-id-new-member"
	delegated, found := (&AtInfo{UserID: targetID}).CopyCtx(ctx)
	if found || delegated.Player == nil || delegated.Player.UserID() != targetID {
		t.Fatalf("unmapped delegate = %#v, found=%t", delegated.Player, found)
	}
	again, found := (&AtInfo{UserID: targetID}).CopyCtx(ctx)
	if !found || again.Player != delegated.Player {
		t.Fatalf("created canonical delegate not reused: %#v, found=%t", again.Player, found)
	}
}

func requireOfficialQQCanonicalPlayer(t *testing.T, ctx *MsgContext, userID, name string) *GroupPlayerInfo {
	t.Helper()
	player, err := ctx.ResolvePlayer(ctx.domainContext(), ctx.Group.GroupID(), userID)
	if err != nil {
		t.Fatalf("resolve canonical player %q: %v", userID, err)
	}
	if player.Version() == 0 {
		if err = player.create(ctx.Dice.BaseConfig.Name, ctx.Group.GroupID(), userID, name); err != nil {
			t.Fatalf("create canonical player %q: %v", userID, err)
		}
	}
	return player
}
