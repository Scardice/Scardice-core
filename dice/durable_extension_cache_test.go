package dice

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"Scardice-core/core/configstate"
	"Scardice-core/core/extensionstate"
	"Scardice-core/eventstore"
)

type extensionLoad struct {
	from   uint64
	events int
}

// extensionLoadRecorder keeps the store's full surface (projections, readiness)
// and only records how the extension stream is loaded.
type extensionLoadRecorder struct {
	*eventstore.GORMStore
	mu    sync.Mutex
	loads []extensionLoad
}

func (s *extensionLoadRecorder) Load(ctx context.Context, stream eventstore.StreamID, from uint64) ([]eventstore.Envelope, error) {
	events, err := s.GORMStore.Load(ctx, stream, from)
	if stream.AggregateType == extensionstate.ExtensionAggregateType {
		s.mu.Lock()
		s.loads = append(s.loads, extensionLoad{from: from, events: len(events)})
		s.mu.Unlock()
	}
	return events, err
}

func (s *extensionLoadRecorder) takeLoads() []extensionLoad {
	s.mu.Lock()
	defer s.mu.Unlock()
	loads := s.loads
	s.loads = nil
	return loads
}

func newDurableExtensionDice(t *testing.T) (*Dice, *extensionLoadRecorder) {
	t.Helper()
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/extensions.db"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := eventstore.NewStore(db,
		eventstore.WithKeySource(compatKeySource{}),
		eventstore.WithProjection(configstate.ConfigProjection()),
		eventstore.WithProjection(extensionstate.ExtensionProjection()),
	)
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "extension-cache-db", IndexRootID: "index-v1",
		EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32),
		TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	recorder := &extensionLoadRecorder{GORMStore: store}
	d := &Dice{
		BaseConfig:    BaseConfig{Name: "dice-1"},
		DurableStore:  recorder,
		ConfigManager: NewConfigManager(t.TempDir() + "/plugin-configs.json"),
	}
	d.ConfigManager.SetOwner(d)
	return d, recorder
}

func registerDurablePlugin(t *testing.T, d *Dice, index int) *ExtInfo {
	t.Helper()
	ctx := context.Background()
	ext := &ExtInfo{Name: fmt.Sprintf("plugin-%04d", index), Version: "1.0.0", IsJsExt: true, dice: d}
	for _, item := range []*ConfigItem{
		{Key: "enabled", Type: "bool", DefaultValue: false, Value: false, Description: "enabled"},
		{Key: "mode", Type: "option", DefaultValue: "safe", Value: "safe", Description: "mode", Option: []string{"safe", "fast"}},
	} {
		if err := d.DurableRegisterConfig(ctx, ext, item); err != nil {
			t.Fatal(err)
		}
	}
	return ext
}

// Registering a plugin's config used to replay the whole extension stream
// several times, so loading a hundred plugins allocated tens of gigabytes.
func TestDurableRegistrationContinuesFromTheLastKnownStateInsteadOfReplayingTheStream(t *testing.T) {
	d, recorder := newDurableExtensionDice(t)
	var last *ExtInfo
	for i := range 30 {
		last = registerDurablePlugin(t, d, i)
	}
	recorder.takeLoads()

	// Registering what is already known changes nothing and must stay cheap.
	if err := d.DurableRegisterConfig(context.Background(), last, &ConfigItem{Key: "enabled", Type: "bool", DefaultValue: false, Value: false, Description: "enabled"}); err != nil {
		t.Fatal(err)
	}
	// A new plugin appends events.
	registerDurablePlugin(t, d, 30)

	loads := recorder.takeLoads()
	if len(loads) == 0 {
		t.Fatal("the extension stream was never read")
	}
	for _, load := range loads {
		if load.from <= 1 || load.events > 3 {
			t.Fatalf("a registration reloaded %d events from version %d: the stream is being replayed instead of continued (%+v)", load.events, load.from, loads)
		}
	}
}

// A restart registers every plugin again and appends nothing. That must cost a
// load and a copy of the state per call, not a replay of the stream per call:
// replaying measured about 1.3 GB for this workload, continuing about 0.12 GB.
func TestReRegisteringKnownPluginsDoesNotReplayTheStreamPerCall(t *testing.T) {
	d, recorder := newDurableExtensionDice(t)
	for i := range 100 {
		registerDurablePlugin(t, d, i)
	}
	versionBefore, err := d.DurableExtensionState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	recorder.takeLoads()

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for i := range 100 {
		registerDurablePlugin(t, d, i)
	}
	runtime.ReadMemStats(&after)

	versionAfter, err := d.DurableExtensionState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if versionAfter.Version != versionBefore.Version {
		t.Fatalf("re-registering known plugins appended events: version %d -> %d", versionBefore.Version, versionAfter.Version)
	}
	const budget = 400 << 20
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > budget {
		t.Fatalf("re-registering 100 known plugins allocated %.0f MB, want under %d MB: the stream is being replayed per call", float64(allocated)/(1<<20), budget>>20)
	}
}
