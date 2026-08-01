package dice

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/sealdice/botgo/dto"

	"Scardice-core/model"
)

func TestOfficialQQVerifiedAccountAdmission_rejectsDuplicateWithoutChangingBlockedMapping(t *testing.T) {
	operator, err := newMockDatabaseOperator(filepath.Join(t.TempDir(), "official-qq-duplicate.db"))
	if err != nil {
		t.Fatalf("newMockDatabaseOperator() error = %v", err)
	}
	t.Cleanup(operator.Close)
	if err := operator.db.AutoMigrate(&model.OfficialQQIdentityMapping{}); err != nil {
		t.Fatalf("migrate identity journal: %v", err)
	}
	blocked := model.OfficialQQIdentityMapping{
		MigrationID: "official-qq-explicit-identity-v1",
		Account:     "200",
		Store:       "delegate",
		Keyspace:    "player_user_id",
		OldID:       "OpenQQ:member-open-id",
		NewID:       "OpenQQ:1-member-open-id",
		SourceHash:  "f3c16a62",
		State:       model.OfficialQQIdentityMappingBlocked,
		CreatedAt:   1,
		UpdatedAt:   1,
		Error:       "target exists",
	}
	if err := operator.db.Create(&blocked).Error; err != nil {
		t.Fatalf("seed blocked mapping: %v", err)
	}

	existing := NewOfficialQQConnItem(100, "", "", false)
	existing.UserID = "OpenQQ:1"
	existing.Nickname = "existing"
	candidate := NewOfficialQQConnItem(200, "", "", false)
	session := &IMSession{EndPoints: []*EndPointInfo{existing, candidate}}
	d := &Dice{DBOperator: operator, ImSession: session}
	session.Parent = d
	existing.BindRuntime(session)
	candidate.BindRuntime(session)
	adapter := candidate.Adapter.(*PlatformAdapterOfficialQQ)

	err = adapter.acceptVerifiedAccount(context.Background(), d, &dto.User{ID: "1", Username: "candidate"})

	if !errors.Is(err, ErrOfficialQQDuplicateAccount) {
		t.Fatalf("acceptVerifiedAccount() error = %v", err)
	}
	if existing.UserID != "OpenQQ:1" || existing.Nickname != "existing" {
		t.Fatalf("existing endpoint changed: %#v", existing.EndPointInfoBase)
	}
	if candidate.UserID != "" || candidate.Nickname != "" {
		t.Fatalf("candidate identity changed: %#v", candidate.EndPointInfoBase)
	}
	var after model.OfficialQQIdentityMapping
	if err := operator.db.First(&after, blocked.ID).Error; err != nil {
		t.Fatalf("read blocked mapping: %v", err)
	}
	if after.State != model.OfficialQQIdentityMappingBlocked || after.NewID != blocked.NewID || after.Error != blocked.Error {
		t.Fatalf("blocked mapping changed: %#v", after)
	}
}

func TestOfficialQQWebsocketLifecycle_rejectsZeroShards(t *testing.T) {
	ws := &dto.WebsocketAP{Shards: 0}

	err := validateOfficialQQWebsocketAP(ws)

	if !errors.Is(err, ErrOfficialQQZeroShards) {
		t.Fatalf("validateOfficialQQWebsocketAP() error = %v", err)
	}
	if ws.Shards != 0 {
		t.Fatalf("zero shards mutated to %d", ws.Shards)
	}
}

func TestOfficialQQWebsocketLifecycle_retriesReconnectInOrder(t *testing.T) {
	var attempts int

	err := runOfficialQQSession(t.Context(), func(context.Context) error {
		attempts++
		if attempts == 1 {
			return ErrOfficialQQReconnect
		}
		return nil
	})

	if err != nil {
		t.Fatalf("runOfficialQQSession() error = %v", err)
	}
	if attempts != 2 {
		t.Fatalf("session attempts = %d, want 2", attempts)
	}
}

func TestOfficialQQConnectionEntry_skipsRunningSessionWithoutStateChange(t *testing.T) {
	adapter := &PlatformAdapterOfficialQQ{Ctx: t.Context()}
	endpoint := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{
		State:  StateConnected,
		Enable: true,
	}}

	serverOfficialQQ(&Dice{}, endpoint, adapter)

	if adapter.DiceServing {
		t.Fatal("running session was marked as a new server")
	}
	if endpoint.State != StateConnected || !endpoint.Enable {
		t.Fatalf("running endpoint changed: state=%d enable=%t", endpoint.State, endpoint.Enable)
	}
}
