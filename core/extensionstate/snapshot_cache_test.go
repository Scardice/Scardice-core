package extensionstate

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"sync"
	"testing"

	"Scardice-core/eventstore"
)

// buildExtensionStream returns the persisted form of a stream in which every
// extension is discovered and then registers two config items.
func buildExtensionStream(t *testing.T, extensions int) ([]eventstore.Envelope, State) {
	t.Helper()
	stream := ExtensionStream("dice-1")
	state := State{}
	var envelopes []eventstore.Envelope
	run := func(command Command) {
		t.Helper()
		decision, err := Decide(state, command)
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range decision.Events {
			item, err := NewEventWithFactory(eventstore.EventFactory{Clock: eventstore.SystemClock{}, IDs: eventstore.UUIDGenerator{}}, event, testMetadata())
			if err != nil {
				t.Fatal(err)
			}
			envelopes = append(envelopes, eventstore.Envelope{
				Stream: stream, StreamVersion: uint64(len(envelopes) + 1),
				EventType: item.EventType, SchemaVersion: item.SchemaVersion, Payload: item.Payload,
			})
			if state, err = Reduce(state, event); err != nil {
				t.Fatal(err)
			}
		}
	}
	for i := range extensions {
		id := fmt.Sprintf("plugin-%04d", i)
		run(Command{Kind: CommandDiscover, DiceID: "dice-1", Identity: ExtensionIdentity{ID: id, Name: id, Version: "1.0.0", Source: "script"}})
		run(Command{Kind: CommandRegisterConfig, ExtensionID: id, Definition: ConfigDefinition{ExtensionID: id, Key: "enabled", Type: ConfigBool, Default: BoolValue(false)}})
		run(Command{Kind: CommandRegisterConfig, ExtensionID: id, Definition: ConfigDefinition{ExtensionID: id, Key: "mode", Type: ConfigOption, Options: []string{"safe", "fast"}, Default: OptionValue("safe")}})
	}
	return envelopes, state
}

func allocatedBy(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func TestReplayEnvelopesMatchesApplyingEventsOneByOne(t *testing.T) {
	envelopes, want := buildExtensionStream(t, 40)
	got, err := ReplayEnvelopes(envelopes)
	if err != nil {
		t.Fatal(err)
	}
	stepped := State{}
	for _, envelope := range envelopes {
		if stepped, err = ApplyEnvelope(stepped, envelope); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(got, stepped) || !reflect.DeepEqual(got, want) {
		t.Fatalf("replay diverged from stepwise application:\n got  %+v\n step %+v", got.Version, stepped.Version)
	}
}

func TestReplayEnvelopesStillRejectsBrokenStreams(t *testing.T) {
	envelopes, _ := buildExtensionStream(t, 3)

	gap := append([]eventstore.Envelope(nil), envelopes...)
	gap[4].StreamVersion++
	if _, err := ReplayEnvelopes(gap); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("a version gap = %v, want ErrInvalidState", err)
	}

	foreign := append([]eventstore.Envelope(nil), envelopes...)
	foreign[2].Stream = ExtensionStream("another-dice")
	if _, err := ReplayEnvelopes(foreign); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("an event of another aggregate = %v, want ErrInvalidIdentity", err)
	}

	wrongSchema := append([]eventstore.Envelope(nil), envelopes...)
	wrongSchema[1].SchemaVersion++
	if _, err := ReplayEnvelopes(wrongSchema); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("an unknown schema = %v, want ErrInvalidEvent", err)
	}
}

// Replaying a stream once must cost time and memory proportional to its length.
// Cloning and revalidating the whole state for every event makes it quadratic,
// which is what made every plugin registration allocate gigabytes.
func TestReplayEnvelopesAllocationGrowsLinearlyWithTheStream(t *testing.T) {
	small, _ := buildExtensionStream(t, 100)
	large, _ := buildExtensionStream(t, 300)
	replay := func(events []eventstore.Envelope) func() {
		return func() {
			if _, err := ReplayEnvelopes(events); err != nil {
				t.Fatal(err)
			}
		}
	}
	replay(small)()
	smallBytes := allocatedBy(replay(small))
	largeBytes := allocatedBy(replay(large))
	// Three times the events: linear is about 3x, quadratic about 9x.
	if ratio := float64(largeBytes) / float64(smallBytes); ratio > 4.5 {
		t.Fatalf("replaying 3x the events allocated %.1fx the memory (%d -> %d bytes): replay is not linear", ratio, smallBytes, largeBytes)
	}
}

type loadCall struct {
	from   uint64
	events int
}

type loadRecordingStore struct {
	eventstore.Store
	mu    sync.Mutex
	calls []loadCall
}

func (s *loadRecordingStore) Load(ctx context.Context, stream eventstore.StreamID, from uint64) ([]eventstore.Envelope, error) {
	events, err := s.Store.Load(ctx, stream, from)
	s.mu.Lock()
	s.calls = append(s.calls, loadCall{from: from, events: len(events)})
	s.mu.Unlock()
	return events, err
}

func (s *loadRecordingStore) take() []loadCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	calls := s.calls
	s.calls = nil
	return calls
}

func openExtensionStore(t *testing.T, name string) eventstore.Store {
	t.Helper()
	db, err := eventstore.OpenDatabase(context.Background(), eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/" + name + ".db"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return eventstore.NewStore(db, eventstore.WithProjection(ExtensionProjection()))
}

func discover(t *testing.T, repo *Repository, id string) State {
	t.Helper()
	ctx := context.Background()
	state, err := repo.Load(ctx, "dice-1")
	if err != nil {
		t.Fatal(err)
	}
	command := Command{Kind: CommandDiscover, DiceID: "dice-1", Identity: ExtensionIdentity{ID: id, Name: id, Version: "1.0.0", Source: "script"}}
	if _, err := repo.DecideAndAppend(ctx, state, state.Version, testMetadata(), command); err != nil {
		t.Fatal(err)
	}
	state, err = repo.Load(ctx, "dice-1")
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func TestCachedRepositoryLoadsOnlyWhatChangedSinceTheLastLoad(t *testing.T) {
	ctx := context.Background()
	recorder := &loadRecordingStore{Store: openExtensionStore(t, "cache")}
	cached := NewRepository(recorder)
	cached.Cache = NewSnapshotCache()
	uncached := NewRepository(recorder.Store)

	var state State
	for i := range 25 {
		state = discover(t, cached, fmt.Sprintf("plugin-%02d", i))
	}
	recorder.take()

	// Nothing changed: one query that returns just the last event already known.
	again, err := cached.Load(ctx, "dice-1")
	if err != nil || !reflect.DeepEqual(again, state) {
		t.Fatalf("unchanged reload = %+v, %v", again.Version, err)
	}
	if calls := recorder.take(); !reflect.DeepEqual(calls, []loadCall{{from: state.Version, events: 1}}) {
		t.Fatalf("an unchanged stream was reloaded as %+v, want a single query returning only the last known event", calls)
	}

	// Another writer appends; the cached repository catches up from where it was.
	other := discover(t, uncached, "written-elsewhere")
	recorder.take()
	caught, err := cached.Load(ctx, "dice-1")
	if err != nil || !reflect.DeepEqual(caught, other) {
		t.Fatalf("catch-up = %+v, %v; want the other writer's state at version %d", caught.Version, err, other.Version)
	}
	if calls := recorder.take(); len(calls) != 1 || calls[0].from != state.Version || calls[0].events != 2 {
		t.Fatalf("catch-up queries = %+v, want one query from version %d returning the known event and the new one", calls, state.Version)
	}
}

func TestCachedRepositoryAppendsWithoutReplayingTheStream(t *testing.T) {
	ctx := context.Background()
	recorder := &loadRecordingStore{Store: openExtensionStore(t, "append")}
	repo := NewRepository(recorder)
	repo.Cache = NewSnapshotCache()
	var state State
	for i := range 20 {
		state = discover(t, repo, fmt.Sprintf("plugin-%02d", i))
	}
	recorder.take()

	command := Command{Kind: CommandDiscover, DiceID: "dice-1", Identity: ExtensionIdentity{ID: "late", Name: "late", Version: "1.0.0", Source: "script"}}
	if _, err := repo.DecideAndAppend(ctx, state, state.Version, testMetadata(), command); err != nil {
		t.Fatal(err)
	}
	for _, call := range recorder.take() {
		if call.from <= 1 {
			t.Fatalf("appending reloaded the whole stream: %+v", call)
		}
	}
	if _, err := repo.DecideAndAppend(ctx, state, state.Version, testMetadata(), Command{Kind: CommandEnable, ExtensionID: "plugin-00"}); !errors.Is(err, eventstore.ErrConflict) {
		t.Fatalf("a stale expected version = %v, want ErrConflict", err)
	}
}

func TestCachedRepositoryReturnsStateTheCallerMayChange(t *testing.T) {
	repo := NewRepository(openExtensionStore(t, "detached"))
	repo.Cache = NewSnapshotCache()
	state := discover(t, repo, "alpha")
	state.Extensions["intruder"] = ExtensionIdentity{ID: "intruder"}
	state.ExtensionOrder = append(state.ExtensionOrder, "intruder")
	delete(state.Extensions, "alpha")

	again, err := repo.Load(context.Background(), "dice-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := again.Extensions["alpha"]; !ok || len(again.Extensions) != 1 || len(again.ExtensionOrder) != 1 {
		t.Fatalf("a caller's edit leaked into the cache: %+v", again)
	}
}

// The cache is only trusted while the stream still contains the event it ended
// on. A different store, a restore or a rewrite must fall back to a full replay.
func TestCachedRepositoryNeverServesAStateTheStreamNoLongerHas(t *testing.T) {
	ctx := context.Background()
	cache := NewSnapshotCache()

	first := NewRepository(openExtensionStore(t, "first"))
	first.Cache = cache
	discover(t, first, "from-first-a")
	discover(t, first, "from-first-b")

	secondStore := openExtensionStore(t, "second")
	second := NewRepository(secondStore)
	second.Cache = cache
	want := discover(t, NewRepository(secondStore), "from-second")

	got, err := second.Load(ctx, "dice-1")
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("after switching stores Load = %+v, %v; want the second store's own state", got.Extensions, err)
	}

	empty := NewRepository(openExtensionStore(t, "empty"))
	empty.Cache = cache
	if got, err := empty.Load(ctx, "dice-1"); err != nil || got.Version != 0 {
		t.Fatalf("a stream that lost its history must read as empty, got version %d, %v", got.Version, err)
	}
}
