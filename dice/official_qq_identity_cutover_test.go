package dice

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"Scardice-core/dice/service"
	"Scardice-core/model"
)

func TestOfficialQQDelegateIdentityCutover_usesOnlyAppliedMapping(t *testing.T) {
	operator, err := newMockDatabaseOperator(filepath.Join(t.TempDir(), "delegate-cutover.db"))
	if err != nil {
		t.Fatalf("newMockDatabaseOperator() error = %v", err)
	}
	t.Cleanup(operator.Close)
	if err := operator.db.AutoMigrate(&model.GroupInfo{}); err != nil {
		t.Fatalf("migrate group_info: %v", err)
	}
	const oldID = "OpenQQ:member-open-id"
	const newID = "OpenQQ:1-member-open-id"
	updatedAt := int64(1)
	if err := operator.db.Create(&model.GroupInfo{ID: "OpenQQ-Group-T:123456789-group-open-id", CreatedAt: 1, UpdatedAt: &updatedAt}).Error; err != nil {
		t.Fatalf("seed group_info: %v", err)
	}
	migrator := service.NewOfficialQQIdentityMigrator(operator, time.Now)
	source := service.OfficialQQVerifiedIdentitySource{
		AppID:       123456789,
		VerifiedUIN: "1",
		Groups: []service.OfficialQQGroupIdentitySource{{
			GroupOpenID:   "group-open-id",
			MemberOpenIDs: []string{"member-open-id"},
		}},
	}
	if result, err := migrator.MigrateVerifiedSource(context.Background(), source, 1); err != nil || result.Processed != 1 {
		t.Fatalf("prepare pending delegate mapping = %#v, %v", result, err)
	}

	oldPlayer := &GroupPlayerInfo{Name: "old", UserID: oldID}
	newPlayer := &GroupPlayerInfo{Name: "new", UserID: newID}
	group := &GroupInfo{Players: new(SyncMap[string, *GroupPlayerInfo])}
	group.Players.Store(oldID, oldPlayer)
	group.Players.Store(newID, newPlayer)
	ctx := &MsgContext{
		Dice:  &Dice{DBOperator: operator},
		Group: group,
		EndPoint: &EndPointInfo{Adapter: &PlatformAdapterOfficialQQ{
			AppID: 123456789,
		}},
	}

	pendingCtx, found := (&AtInfo{UserID: oldID}).CopyCtx(ctx)
	if !found || pendingCtx.Player != oldPlayer {
		t.Fatalf("pending delegate player = %#v, found %t, want old player", pendingCtx.Player, found)
	}
	if result, err := migrator.MigrateVerifiedSource(context.Background(), source, 1); err != nil || result.Processed != 1 {
		t.Fatalf("apply delegate mapping = %#v, %v", result, err)
	}

	appliedCtx, found := (&AtInfo{UserID: oldID}).CopyCtx(ctx)
	if !found || appliedCtx.Player != newPlayer {
		t.Fatalf("applied delegate player = %#v, found %t, want new player", appliedCtx.Player, found)
	}
}

func TestOfficialQQDelegateIdentityCutover_keepsBlockedAndUnmappedIDs(t *testing.T) {
	operator, err := newMockDatabaseOperator(filepath.Join(t.TempDir(), "delegate-fallback.db"))
	if err != nil {
		t.Fatalf("newMockDatabaseOperator() error = %v", err)
	}
	t.Cleanup(operator.Close)
	journal := service.NewOfficialQQIdentityJournal(operator, time.Now)
	if err := operator.db.AutoMigrate(&model.GroupInfo{}); err != nil {
		t.Fatalf("migrate group_info: %v", err)
	}
	const blockedID = "OpenQQ:blocked-member"
	const unmappedID = "OpenQQ:unmapped-member"
	updatedAt := int64(1)
	if err := operator.db.Create(&model.GroupInfo{ID: "OpenQQ-Group-T:123456789-group-open-id", CreatedAt: 1, UpdatedAt: &updatedAt}).Error; err != nil {
		t.Fatalf("seed group_info: %v", err)
	}
	migrator := service.NewOfficialQQIdentityMigrator(operator, time.Now)
	source := service.OfficialQQVerifiedIdentitySource{
		AppID:       123456789,
		VerifiedUIN: "1",
		Groups: []service.OfficialQQGroupIdentitySource{{
			GroupOpenID:   "group-open-id",
			MemberOpenIDs: []string{"blocked-member"},
		}},
	}
	if result, err := migrator.MigrateVerifiedSource(context.Background(), source, 1); err != nil || result.Processed != 1 {
		t.Fatalf("prepare blocked delegate mapping = %#v, %v", result, err)
	}
	key := service.OfficialQQIdentityMappingKey{
		MigrationID: service.OfficialQQExplicitIdentityMigrationID,
		Account:     "123456789",
		Store:       service.OfficialQQIdentityStoreDelegate,
		Keyspace:    service.OfficialQQIdentityKeyspacePlayerUserID,
		OldID:       blockedID,
	}
	if err := journal.Transition(context.Background(), service.OfficialQQIdentityMappingTransition{
		Key:   key,
		State: model.OfficialQQIdentityMappingBlocked,
		Error: "target exists",
	}); err != nil {
		t.Fatalf("Transition() error = %v", err)
	}
	blockedPlayer := &GroupPlayerInfo{Name: "blocked", UserID: blockedID}
	unmappedPlayer := &GroupPlayerInfo{Name: "unmapped", UserID: unmappedID}
	group := &GroupInfo{Players: new(SyncMap[string, *GroupPlayerInfo])}
	group.Players.Store(blockedID, blockedPlayer)
	group.Players.Store(unmappedID, unmappedPlayer)
	ctx := &MsgContext{
		Dice:  &Dice{DBOperator: operator},
		Group: group,
		EndPoint: &EndPointInfo{Adapter: &PlatformAdapterOfficialQQ{
			AppID: 123456789,
		}},
	}

	blockedCtx, blockedFound := (&AtInfo{UserID: blockedID}).CopyCtx(ctx)
	unmappedCtx, unmappedFound := (&AtInfo{UserID: unmappedID}).CopyCtx(ctx)

	if !blockedFound || blockedCtx.Player != blockedPlayer {
		t.Fatalf("blocked delegate player = %#v, found %t", blockedCtx.Player, blockedFound)
	}
	if !unmappedFound || unmappedCtx.Player != unmappedPlayer {
		t.Fatalf("unmapped delegate player = %#v, found %t", unmappedCtx.Player, unmappedFound)
	}
}
