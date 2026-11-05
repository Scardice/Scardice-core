package dice

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"Scardice-core/core/configstate"
	"Scardice-core/core/managerstate"
	"Scardice-core/eventstore"

	"gorm.io/gorm"
)

var errManagerStartupProjection = errors.New("manager startup projection rejected")

type managerStartupStore struct {
	*eventstore.GORMStore
	works []eventstore.UnitOfWork
}

func (s *managerStartupStore) Commit(ctx context.Context, work eventstore.UnitOfWork) (eventstore.CommitResult, error) {
	s.works = append(s.works, work)
	return s.GORMStore.Commit(ctx, work)
}

type managerStartupFixture struct {
	manager          *DiceManager
	store            *managerStartupStore
	rejectProjection bool
}

func newManagerStartupFixture(t *testing.T, mode string) *managerStartupFixture {
	t.Helper()
	ctx := context.Background()
	database, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{
		Type: "sqlite", DSN: filepath.Join(t.TempDir(), "manager-startup.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	fixture := &managerStartupFixture{manager: &DiceManager{}}
	projection := managerstate.Projection()
	apply := projection.Apply
	projection.Apply = func(ctx context.Context, tx *gorm.DB, events []eventstore.Envelope) error {
		if err := apply(ctx, tx, events); err != nil {
			return err
		}
		if fixture.rejectProjection {
			for _, event := range events {
				if event.Stream == managerstate.Stream() {
					return errManagerStartupProjection
				}
			}
		}
		return nil
	}
	fixture.store = &managerStartupStore{GORMStore: eventstore.NewStore(database,
		eventstore.WithProjection(projection), eventstore.WithProjection(configstate.ConfigProjection()),
	)}
	readiness := eventstore.Readiness{Mode: mode, SchemaVersion: 2, DatabaseIdentity: "manager-startup"}
	if mode == "import" {
		readiness.CompletedAt = time.Unix(1, 0).UTC()
	}
	if err = fixture.store.SetReadiness(ctx, readiness); err != nil {
		t.Fatal(err)
	}
	if mode == "import" {
		repository, repoErr := managerstate.NewRepository(fixture.store)
		if repoErr != nil {
			t.Fatal(repoErr)
		}
		if _, err = repository.Save(ctx, managerstate.State{}, managerstate.PublicConfig{
			ServiceName: "Scardice-old", DiceDataDirs: map[string]string{"imported": "./imported"},
		}, managerstate.Auth{UIPasswordSalt: "imported-salt", UIPasswordHash: "imported-hash", AccessTokens: []string{"imported-token"}}); err != nil {
			t.Fatal(err)
		}
		if _, err = configstate.NewRepository(fixture.store).DecideAndAppend(ctx, configstate.State{}, 0, eventstore.Metadata{}, configstate.Command{
			Kind: configstate.CommandImportBaseline, Baseline: &configstate.Baseline{DiceID: "imported"},
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err = fixture.manager.restoreEventSourcedManager(ctx, fixture.store, nil); err != nil {
		t.Fatal(err)
	}
	if err = fixture.manager.RestoreEventSourcedDice(ctx, fixture.store); err != nil {
		t.Fatal(err)
	}
	fixture.store.works = nil
	assertManagerStartupUninitialized(t, fixture.manager)
	return fixture
}

func assertManagerStartupUninitialized(t *testing.T, manager *DiceManager) {
	t.Helper()
	if manager.Operator != nil || manager.JsRegistry != nil || manager.Cron != nil {
		t.Fatal("manager startup mutation initialized legacy or JavaScript runtime")
	}
	for _, instance := range manager.DiceSnapshot() {
		if instance == nil || instance.Parent != nil || instance.configView.Load() != nil ||
			instance.ImSession != nil || instance.ConfigManager != nil || instance.DBOperator != nil || instance.jsRuntimeManager != nil {
			t.Fatal("manager startup mutation requires an initialized Dice")
		}
	}
}

func TestManagerStartupServiceNamePersistsBeforeDiceInitialization(t *testing.T) {
	for _, scenario := range []struct {
		mode        string
		name        string
		withoutDice bool
	}{
		{mode: "fresh", name: "Scardice"},
		{mode: "import", name: "Scardice-renamed"},
		{mode: "fresh", name: "Scardice-headless", withoutDice: true},
		{mode: "import", name: "Scardice-imported-headless", withoutDice: true},
	} {
		label := scenario.mode
		if scenario.withoutDice {
			label += "/without-dice"
		}
		t.Run(label, func(t *testing.T) {
			ctx := context.Background()
			fixture := newManagerStartupFixture(t, scenario.mode)
			if scenario.withoutDice {
				fixture.manager.Dice = nil
			}
			repository, err := managerstate.NewRepository(fixture.store)
			if err != nil {
				t.Fatal(err)
			}
			before, authBefore, err := repository.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err = fixture.manager.DurableMutateManagerConfig(ctx, "service-name", scenario.name, func(public *managerstate.PublicConfig) error {
				public.ServiceName = scenario.name
				return nil
			}); err != nil {
				t.Fatalf("persist service name before Dice initialization: %v", err)
			}
			after, authAfter, err := repository.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if after.Version != before.Version+1 || after.Public.ServiceName != scenario.name ||
				fixture.manager.ServiceName != scenario.name || !reflect.DeepEqual(authBefore, authAfter) {
				t.Fatalf("service-name commit: state=%#v runtime=%q auth=%#v", after, fixture.manager.ServiceName, authAfter)
			}
			snapshot, passwordConfigured := fixture.manager.ManagerPublicConfigSnapshot()
			if snapshot.ServiceName != scenario.name || passwordConfigured != (scenario.mode == "import") {
				t.Fatalf("published manager snapshot = %#v password configured=%v", snapshot, passwordConfigured)
			}
			for name := range snapshot.DiceDataDirs {
				snapshot.DiceDataDirs[name] = "./detached"
			}
			again, _ := fixture.manager.ManagerPublicConfigSnapshot()
			if !reflect.DeepEqual(after.Public, again) {
				t.Fatalf("manager snapshot leaked mutable data dirs: %#v", again.DiceDataDirs)
			}
			if len(fixture.store.works) != 1 {
				t.Fatalf("manager mutation commits = %d, want one atomic commit", len(fixture.store.works))
			}
			work := fixture.store.works[0]
			if work.Execution == nil || len(work.Streams) != 1 || work.Streams[0].Stream != managerstate.Stream() || len(work.SecretUpdates) != 1 {
				t.Fatalf("manager mutation did not atomically commit its execution, manager, and auth: %#v", work)
			}
			if len(work.StreamReads) != 1 || work.StreamReads[0].Stream != managerstate.Stream() || work.StreamReads[0].ExpectedVersion != before.Version {
				t.Fatalf("manager mutation borrowed a Dice config dependency: %#v", work.StreamReads)
			}
			receipt, err := fixture.store.LookupExecution(ctx, work.Execution.Identity)
			if err != nil || receipt.Status != eventstore.ExecutionStatusCommitted {
				t.Fatalf("manager execution receipt = %#v, err=%v", receipt, err)
			}
			restored := &DiceManager{}
			if err = restored.restoreEventSourcedManager(ctx, fixture.store, nil); err != nil {
				t.Fatal(err)
			}
			if restored.ServiceName != scenario.name {
				t.Fatalf("reloaded service name = %q, want %q", restored.ServiceName, scenario.name)
			}
			rows, err := fixture.store.ListProjectionRows(ctx, configstate.ConfigProjectionName)
			wantRows := 0
			if scenario.mode == "import" {
				wantRows = 1
			}
			if err != nil || len(rows) != wantRows {
				t.Fatalf("manager mutation created Dice config state: rows=%d err=%v", len(rows), err)
			}
			assertManagerStartupUninitialized(t, fixture.manager)
		})
	}
}

func TestManagerStartupServiceNameFailureDoesNotPublish(t *testing.T) {
	for _, mode := range []string{"fresh", "import"} {
		for _, failure := range []string{"mutation", "projection"} {
			t.Run(mode+"/"+failure, func(t *testing.T) {
				ctx := context.Background()
				fixture := newManagerStartupFixture(t, mode)
				repository, err := managerstate.NewRepository(fixture.store)
				if err != nil {
					t.Fatal(err)
				}
				before, authBefore, err := repository.Load(ctx)
				if err != nil {
					t.Fatal(err)
				}
				wantErr := errors.New("manager startup mutation rejected")
				if failure == "projection" {
					fixture.rejectProjection = true
					wantErr = errManagerStartupProjection
				}
				err = fixture.manager.DurableMutateManagerConfig(ctx, "service-name", "uncommitted", func(public *managerstate.PublicConfig) error {
					public.ServiceName = "uncommitted"
					for name := range public.DiceDataDirs {
						public.DiceDataDirs[name] = "./uncommitted"
					}
					if failure == "mutation" {
						return wantErr
					}
					return nil
				})
				if !errors.Is(err, wantErr) {
					t.Fatalf("manager mutation error = %v, want %v", err, wantErr)
				}
				after, authAfter, err := repository.Load(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(authBefore, authAfter) ||
					!reflect.DeepEqual(before, fixture.manager.managerState) || fixture.manager.ServiceName != before.Public.ServiceName {
					t.Fatalf("failed mutation published partial state: durable=%#v runtime=%#v auth=%#v", after, fixture.manager.managerState, authAfter)
				}
				events, err := fixture.store.Load(ctx, managerstate.Stream(), 0)
				if err != nil || uint64(len(events)) != before.Version {
					t.Fatalf("failed mutation appended manager events: events=%d err=%v", len(events), err)
				}
				if failure == "mutation" && len(fixture.store.works) != 0 {
					t.Fatal("rejected mutation submitted a durable commit")
				}
				if _, err = fixture.store.ResolveSecret(ctx, managerstate.AuthSecretRef, before.AuthSecretVersion+1); !errors.Is(err, eventstore.ErrNotFound) {
					t.Fatalf("failed mutation published a new auth secret: %v", err)
				}
				assertManagerStartupUninitialized(t, fixture.manager)
			})
		}
	}
}
