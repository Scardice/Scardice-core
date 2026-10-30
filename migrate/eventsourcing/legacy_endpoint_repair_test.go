package eventsourcing

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"Scardice-core/adapterapi"
	"Scardice-core/endpoint"
)

func TestRepairLegacyEndpointMetadataAppendsOneIdempotentEvent(t *testing.T) {
	ctx := context.Background()
	target := NewSQLiteTarget(filepath.Join(t.TempDir(), "events.db"), sqliteTargetKeySource{})
	if err := target.Initialize(ctx, "legacy-repair-target"); err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	service := endpoint.NewService(target.store, nil)

	endpointID := adapterapi.EndpointID("legacy-onebot")
	create, err := endpoint.Decide(endpoint.State{}, endpoint.Command{
		Kind: endpoint.CommandCreate, CommandID: "old-import-create", CorrelationID: "old-import",
		EndpointID: endpointID, AdapterKey: "fake",
		Config: adapterapi.ValidatedConfig{Version: 1, Canonical: []byte(`{"channel":"test"}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Repository.Commit(ctx, endpoint.State{}, create); err != nil {
		t.Fatal(err)
	}
	operationProjectionBefore, err := target.store.ReadProjectionRow(ctx, endpoint.OperationProjectionName, create.Events[0].OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if err = target.database.GORM().Exec("DELETE FROM operations").Error; err != nil {
		t.Fatal(err)
	}
	if _, err = service.GetOperation(ctx, create.Events[0].OperationID); err == nil {
		t.Fatal("fixture retained the imported operation row")
	}

	root := filepath.Join(t.TempDir(), "legacy")
	dataDir := filepath.Join(root, "default")
	if err = makeLegacyEndpointRepairFixture(dataDir, root); err != nil {
		t.Fatal(err)
	}

	repaired, err := RepairLegacyEndpointMetadata(ctx, root, service)
	if err != nil {
		t.Fatal(err)
	}
	if repaired != 1 {
		t.Fatalf("repaired endpoints = %d, want 1", repaired)
	}
	state, err := service.Repository.Load(ctx, endpointID)
	if err != nil {
		t.Fatal(err)
	}
	wantStatistics := endpoint.Statistics{GroupCount: 7, CommandCount: 84, LastCommandAt: 23456, OnlineSeconds: 789}
	if state.DisplayName != "Legacy Bot" || state.ProviderID != "QQ:12345" || state.Statistics != wantStatistics || state.Version != 2 {
		t.Fatalf("repaired endpoint state = %#v", state)
	}
	view, err := service.Get(ctx, endpointID)
	if err != nil || view.DisplayName != "Legacy Bot" || view.ProviderID != "QQ:12345" || view.Statistics != wantStatistics {
		t.Fatalf("repaired endpoint projection = %#v, %v", view, err)
	}
	operationProjectionAfter, err := target.store.ReadProjectionRow(ctx, endpoint.OperationProjectionName, create.Events[0].OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if string(operationProjectionAfter.Payload) != string(operationProjectionBefore.Payload) ||
		!operationProjectionAfter.UpdatedAt.Equal(operationProjectionBefore.UpdatedAt) {
		t.Fatalf("metadata repair changed operation projection: before=%#v after=%#v", operationProjectionBefore, operationProjectionAfter)
	}
	if _, err = service.GetOperation(ctx, create.Events[0].OperationID); err == nil {
		t.Fatal("metadata repair created an operation row")
	}

	repaired, err = RepairLegacyEndpointMetadata(ctx, root, service)
	if err != nil || repaired != 0 {
		t.Fatalf("idempotent repair = %d, %v", repaired, err)
	}
	state, err = service.Repository.Load(ctx, endpointID)
	if err != nil || state.Version != 2 {
		t.Fatalf("state after idempotent repair = %#v, %v", state, err)
	}
}

func makeLegacyEndpointRepairFixture(dataDir, root string) error {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, "dice.yaml"), []byte("diceConfigs:\n  - name: default\n    dataDir: default\n"), 0o600); err != nil {
		return err
	}
	serve := []byte(`imSession:
  endPoints:
    - baseInfo:
        id: legacy-onebot
        nickname: Legacy Bot
        platform: QQ
        protocolType: pureonebot
        userId: QQ:12345
        groupNum: 7
        cmdExecutedNum: 42
        cmdExecutedLastTime: 12345
        onlineTotalTime: 678
`)
	if err := os.WriteFile(filepath.Join(dataDir, "serve.yaml"), serve, 0o600); err != nil {
		return err
	}
	database, err := sql.Open("sqlite", filepath.Join(dataDir, "data.db"))
	if err != nil {
		return err
	}
	defer database.Close()
	if _, err = database.Exec(`CREATE TABLE endpoint_info (user_id TEXT PRIMARY KEY, cmd_num INTEGER, cmd_last_time INTEGER, online_time INTEGER, updated_at INTEGER)`); err != nil {
		return err
	}
	_, err = database.Exec(`INSERT INTO endpoint_info (user_id, cmd_num, cmd_last_time, online_time, updated_at) VALUES (?, ?, ?, ?, ?)`, "QQ:12345", 84, 23456, 789, 34567)
	return err
}
