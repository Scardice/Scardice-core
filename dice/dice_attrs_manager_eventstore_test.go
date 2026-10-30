package dice

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	ds "github.com/sealdice/dicescript"
	"go.uber.org/zap"

	"Scardice-core/core/attributestate"
	"Scardice-core/dice/service"
	"Scardice-core/eventstore"
)

func TestAttrsManagerLoadsAndPersistsEncryptedEventState(t *testing.T) {
	ctx := context.Background()
	database, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "attrs.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store := eventstore.NewStore(database, eventstore.WithKeySource(compatKeySource{}), eventstore.WithProjection(attributestate.Projection()))
	if err = store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "attrs-test", IndexRootID: "index-v1",
		EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32),
		TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	repository, err := attributestate.NewRepository(store)
	if err != nil {
		t.Fatal(err)
	}
	values := &ds.ValueMap{}
	values.Store("hp", ds.NewIntVal(60))
	payload, err := ds.NewDictVal(values).V().ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	state, err := repository.Save(ctx, attributestate.State{
		DiceID: "dice-1", ID: "QQ-Group:100-QQ:200", AttrsType: service.AttrsTypeGroupUser,
		SecretRef: attributestate.SecretRef("dice-1", "QQ-Group:100-QQ:200"), CreatedAt: 1, UpdatedAt: 1,
	}, payload)
	if err != nil || state.Version != 1 {
		t.Fatalf("seed attributes state=%#v err=%v", state, err)
	}

	manager := &AttrsManager{}
	die := &Dice{BaseConfig: BaseConfig{Name: "dice-1"}, DurableStore: store, Logger: zap.NewNop().Sugar()}
	if err = manager.InitDurable(die); err != nil {
		t.Fatal(err)
	}
	defer manager.Stop()
	item, err := manager.Load("QQ-Group:100", "QQ:200")
	if err != nil || item.Load("hp").ToString() != "60" {
		t.Fatalf("loaded attributes=%v err=%v", item, err)
	}
	item.Store("hp", ds.NewIntVal(42))
	if err = manager.CheckForSave(); err != nil {
		t.Fatal(err)
	}
	persisted, plaintext, err := repository.Load(ctx, "dice-1", item.ID)
	if err != nil || persisted.Version != 2 {
		t.Fatalf("persisted state=%#v err=%v", persisted, err)
	}
	decoded, err := ds.VMValueFromJSON(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	dict, ok := decoded.ReadDictData()
	if !ok {
		t.Fatal("persisted attributes are not a dictionary")
	}
	hp, ok := dict.Dict.Load("hp")
	if !ok || hp.ToString() != "42" {
		t.Fatalf("persisted hp=%v exists=%v", hp, ok)
	}
}
