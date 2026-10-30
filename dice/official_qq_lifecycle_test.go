package dice

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"Scardice-core/adapterapi"
	endpointstate "Scardice-core/endpoint"
	"Scardice-core/eventstore"

	"github.com/sealdice/botgo/dto"

	"Scardice-core/model"
)

type officialQQProjectionStore struct {
	rows []eventstore.ProjectionRow
}

func (s officialQQProjectionStore) Commit(context.Context, eventstore.UnitOfWork) (eventstore.CommitResult, error) {
	return eventstore.CommitResult{}, errors.New("not used")
}

func (s officialQQProjectionStore) Load(context.Context, eventstore.StreamID, uint64) ([]eventstore.Envelope, error) {
	return nil, errors.New("not used")
}

func (officialQQProjectionStore) Close() error { return nil }

func (s officialQQProjectionStore) ListProjectionRows(context.Context, string) ([]eventstore.ProjectionRow, error) {
	return append([]eventstore.ProjectionRow(nil), s.rows...), nil
}

func TestOfficialQQVerifiedAccountAdmission_rejectsDuplicateWithoutChangingBlockedMapping(t *testing.T) {
	operator, err := newMockDatabaseOperator(filepath.Join(t.TempDir(), "official-qq-duplicate.db"))
	if err != nil {
		t.Fatalf("newMockDatabaseOperator() error = %v", err)
	}
	t.Cleanup(operator.Close)
	if err = operator.db.AutoMigrate(&model.OfficialQQIdentityMapping{}); err != nil {
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
	if err = operator.db.Create(&blocked).Error; err != nil {
		t.Fatalf("seed blocked mapping: %v", err)
	}

	existing := &EndPointInfo{
		EndPointInfoBase: EndPointInfoBase{ID: "existing-official"},
	}
	existing.UserID = "OpenQQ:1"
	existing.Nickname = "existing"
	candidate := &EndPointInfo{
		EndPointInfoBase: EndPointInfoBase{ID: "candidate-official"},
		Adapter:          &PlatformAdapterOfficialQQ{AppID: 200},
	}
	session := &IMSession{}
	projected, err := json.Marshal(endpointstate.EndpointView{
		EndpointID: adapterapi.EndpointID(existing.ID),
		AdapterKey: OfficialQQAdapterKey,
		Config: adapterapi.ValidatedConfig{
			Version:   1,
			Canonical: json.RawMessage(`{"accountHint":"OpenQQ:1"}`),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	d := &Dice{
		DBOperator:   operator,
		ImSession:    session,
		DurableStore: officialQQProjectionStore{rows: []eventstore.ProjectionRow{{RowKey: existing.ID, Payload: projected}}},
	}
	session.Parent = d
	candidate.bindCompatibilityRuntime(session)
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
