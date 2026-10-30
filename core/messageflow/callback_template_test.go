package messageflow

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"Scardice-core/core/playerstate"
	"Scardice-core/eventstore"
)

func TestCallbackCollectorPersistsDollarTTemplate(t *testing.T) {
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "template.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithKeySource(defaultIntegrationKeySource()))
	collector := NewMutationCollector(eventstore.EventFactory{})
	metadata := eventstore.Metadata{CommandID: "template-command", CorrelationID: "template-correlation", OccurredAt: time.Now().UTC()}
	const template = "{$t玩家_RAW} SAN{理智} HP{生命值}/{生命值上限} DEX{敏捷}"
	stream := playerstate.PlayerStream("dice-template", "group-template", "user-template")
	if err := collector.AddPlayerEvents(stream, 0, metadata, []playerstate.PlayerEvent{
		playerstate.NewPlayerCreatedV1("dice-template", "group-template", "user-template", "Player"),
		playerstate.NewPlayerAutoSetNameTemplateChangedV1(template),
	}); err != nil {
		t.Fatalf("collect persistent player template: %v", err)
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, work); err != nil {
		t.Fatalf("commit persistent player template: %v", err)
	}
	state, err := playerstate.NewRepository(store).LoadPlayer(ctx, "dice-template", "group-template", "user-template")
	if err != nil {
		t.Fatal(err)
	}
	if state.AutoSetNameTemplate != template || state.Version != 2 {
		t.Fatalf("persisted template = %q, version = %d", state.AutoSetNameTemplate, state.Version)
	}
}

func TestCallbackCollectorRejectsRequestLocalAttributeKeys(t *testing.T) {
	for _, event := range []playerstate.GroupUserAttrsEvent{
		playerstate.NewGroupUserAttrsSetV1("$t临时", []byte("encrypted"), "root-v1"),
		playerstate.NewGroupUserAttrsIncrementedV1("$t临时", 1),
		playerstate.NewGroupUserAttrsDeletedV1("$t临时"),
	} {
		t.Run(string(event.EventType()), func(t *testing.T) {
			collector := NewMutationCollector(eventstore.EventFactory{})
			err := collector.AddGroupUserAttrsEvents(playerstate.GroupUserAttrsStream("dice", "group", "user"), 0, eventstore.Metadata{
				CommandID: "local-command", CorrelationID: "local-correlation", OccurredAt: time.Now().UTC(),
			}, []playerstate.GroupUserAttrsEvent{event})
			if !errors.Is(err, playerstate.ErrInvalidState) {
				t.Fatalf("request-local key error = %v", err)
			}
		})
	}
}
