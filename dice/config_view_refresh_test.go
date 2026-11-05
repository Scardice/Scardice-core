package dice

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"Scardice-core/core/configstate"
	"Scardice-core/eventstore"
)

type configViewSnapshotStore struct {
	mu    sync.Mutex
	reads []func() eventstore.ProjectionLookupSnapshot
}

func (s *configViewSnapshotStore) Commit(context.Context, eventstore.UnitOfWork) (eventstore.CommitResult, error) {
	return eventstore.CommitResult{}, nil
}

func (s *configViewSnapshotStore) Load(context.Context, eventstore.StreamID, uint64) ([]eventstore.Envelope, error) {
	return nil, nil
}

func (s *configViewSnapshotStore) Close() error { return nil }

func (s *configViewSnapshotStore) ReadProjectionDependency(context.Context, string, string, eventstore.StreamID) (eventstore.ProjectionLookupSnapshot, error) {
	s.mu.Lock()
	read := s.reads[0]
	s.reads = s.reads[1:]
	s.mu.Unlock()
	return read(), nil
}

func (s *configViewSnapshotStore) ListCatalogProjectionSnapshot(context.Context, eventstore.CatalogProjectionListRequest) (eventstore.CatalogProjectionListSnapshot, error) {
	return eventstore.CatalogProjectionListSnapshot{}, nil
}

func configViewTestState(t *testing.T, diceID string, prefixes []string) configstate.State {
	t.Helper()
	decision, err := configstate.Decide(configstate.State{}, configstate.Command{
		Kind:     configstate.CommandImportBaseline,
		Baseline: &configstate.Baseline{DiceID: diceID, ConfigVersion: 1, CommandPrefix: prefixes},
	})
	if err != nil {
		t.Fatal(err)
	}
	state := configstate.State{}
	for _, event := range decision.Events {
		state, err = configstate.Reduce(state, event)
		if err != nil {
			t.Fatal(err)
		}
	}
	return state
}

func configViewTestSnapshot(t *testing.T, state configstate.State, generation string) eventstore.ProjectionLookupSnapshot {
	t.Helper()
	payload, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	stream := configstate.ConfigStream(state.DiceID)
	return eventstore.ProjectionLookupSnapshot{
		Found:         true,
		Stream:        stream,
		StreamVersion: state.Version,
		Row:           eventstore.ProjectionRow{ProjectionGeneration: generation, ProjectionName: configstate.ConfigProjectionName, RowKey: stream.AggregateID, Payload: payload},
		Snapshot:      eventstore.DependencySnapshot{ProjectionGeneration: generation},
	}
}

func TestReloadConfigViewDoesNotPublishOutOfOrderResult(t *testing.T) {
	const diceID = "config-view-order"
	oldState := configViewTestState(t, diceID, []string{"."})
	newState := oldState.Clone()
	newState.Version++
	newState.Outer.CommandPrefix = []string{"!"}
	newestState := newState.Clone()
	newestState.Version++
	newestState.Outer.CommandPrefix = []string{"?"}

	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	store := &configViewSnapshotStore{reads: []func() eventstore.ProjectionLookupSnapshot{
		func() eventstore.ProjectionLookupSnapshot {
			close(firstEntered)
			<-releaseFirst
			return configViewTestSnapshot(t, newState, "generation-two")
		},
		func() eventstore.ProjectionLookupSnapshot {
			return configViewTestSnapshot(t, newestState, "generation-three")
		},
		func() eventstore.ProjectionLookupSnapshot {
			return configViewTestSnapshot(t, newestState, "generation-three")
		},
	}}
	d := &Dice{BaseConfig: BaseConfig{Name: diceID}, DurableStore: store}
	initial, err := d.configReadViewFromState(oldState, eventstore.DependencySnapshot{ProjectionGeneration: "generation-one"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	d.configView.Store(initial)

	firstDone := make(chan error, 1)
	go func() { firstDone <- d.ReloadConfigView(context.Background()) }()
	<-firstEntered
	if err = d.ReloadConfigView(context.Background()); err != nil {
		t.Fatal(err)
	}
	close(releaseFirst)
	if err = <-firstDone; err != nil {
		t.Fatal(err)
	}
	view := d.currentConfigView()
	if view.version != newestState.Version || view.dependency.ProjectionGeneration != "generation-three" || view.config.CommandPrefix[0] != "?" {
		t.Fatalf("out-of-order reload published stale view: %#v", view)
	}
}

func TestReloadConfigViewRefreshesProjectionEpochWithoutFactChange(t *testing.T) {
	const diceID = "config-view-epoch"
	state := configViewTestState(t, diceID, []string{"."})
	store := &configViewSnapshotStore{reads: []func() eventstore.ProjectionLookupSnapshot{
		func() eventstore.ProjectionLookupSnapshot {
			return configViewTestSnapshot(t, state, "rebuilt-generation")
		},
	}}
	d := &Dice{BaseConfig: BaseConfig{Name: diceID}, DurableStore: store}
	initial, err := d.configReadViewFromState(state, eventstore.DependencySnapshot{ProjectionGeneration: "old-generation"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	d.configView.Store(initial)
	if err = d.ReloadConfigView(context.Background()); err != nil {
		t.Fatal(err)
	}
	view := d.currentConfigView()
	if view.version != state.Version || view.dependency.ProjectionGeneration != "rebuilt-generation" {
		t.Fatalf("projection epoch was not refreshed: %#v", view.dependency)
	}
}

func TestDetachedConfigCommitRejectsRefreshedSource(t *testing.T) {
	d, _ := newCanonicalTestDice(t)
	stale, _ := d.ConfigEditSnapshot()
	updateCanonicalTestConfig(t, d, func(config *Config) {
		config.FriendAddComment = "newer"
	})
	stale.RefuseGroupInvite = true
	err := d.DurableCommitConfigSnapshot(
		context.Background(),
		stale,
		stale.CommandPrefix,
		stale.DiceMasters,
		nil,
	)
	if !errors.Is(err, ErrConfigViewChanged) {
		t.Fatalf("stale detached commit error = %v, want %v", err, ErrConfigViewChanged)
	}
	if d.Config().FriendAddComment != "newer" || d.Config().RefuseGroupInvite {
		t.Fatalf("stale detached commit changed config: %#v", d.Config())
	}
}

func TestDetachedModerationViewRejectsRefreshedConfigSource(t *testing.T) {
	d, _ := newCanonicalTestDice(t)
	stale := d.Config().BanList
	updateCanonicalTestConfig(t, d, func(config *Config) {
		config.BanList.ThresholdWarn++
	})
	if _, err := stale.AddScoreBaseWithError("QQ:stale-config", 1, "test", "stale view", nil); !errors.Is(err, ErrConfigViewChanged) {
		t.Fatalf("stale moderation view error = %v, want %v", err, ErrConfigViewChanged)
	}
	if _, exists := d.Config().BanList.GetByID("QQ:stale-config"); exists {
		t.Fatal("stale moderation view committed a score")
	}
}
