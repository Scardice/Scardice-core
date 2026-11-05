package execution

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"Scardice-core/core/groupstate"
	"Scardice-core/core/playerstate"
	"Scardice-core/eventstore"
)

type domainTxContextKey string

type domainTxTestStore struct {
	mu       sync.Mutex
	versions map[eventstore.StreamID]uint64
	rows     map[string]eventstore.ProjectionRow
	loads    map[eventstore.StreamID]int
	snapshot eventstore.DependencySnapshot
}

func newDomainTxTestStore() *domainTxTestStore {
	return &domainTxTestStore{
		versions: make(map[eventstore.StreamID]uint64),
		rows:     make(map[string]eventstore.ProjectionRow),
		loads:    make(map[eventstore.StreamID]int),
		snapshot: eventstore.DependencySnapshot{ProjectionGeneration: "generation-1"},
	}
}

func (s *domainTxTestStore) Commit(context.Context, eventstore.UnitOfWork) (eventstore.CommitResult, error) {
	return eventstore.CommitResult{}, nil
}

func (s *domainTxTestStore) Load(context.Context, eventstore.StreamID, uint64) ([]eventstore.Envelope, error) {
	return nil, nil
}

func (s *domainTxTestStore) Close() error { return nil }

func (s *domainTxTestStore) ReadProjectionDependency(_ context.Context, projectionName, rowKey string, stream eventstore.StreamID) (eventstore.ProjectionLookupSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loads[stream]++
	row, found := s.rows[projectionName+"\x00"+rowKey]
	row.Payload = append([]byte(nil), row.Payload...)
	return eventstore.ProjectionLookupSnapshot{
		Row: row, Found: found, Stream: stream, StreamVersion: s.versions[stream], Snapshot: s.snapshot,
	}, nil
}

func (s *domainTxTestStore) seedGroup(t *testing.T, state groupstate.State) {
	t.Helper()
	payload, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	stream := groupstate.GroupStream(state.DiceID, state.GroupID)
	s.mu.Lock()
	s.versions[stream] = state.Version
	s.rows[groupstate.GroupProjectionName+"\x00"+stream.AggregateID] = eventstore.ProjectionRow{
		ProjectionGeneration: s.snapshot.ProjectionGeneration,
		ProjectionName:       groupstate.GroupProjectionName,
		RowKey:               stream.AggregateID,
		Payload:              payload,
	}
	s.mu.Unlock()
}

func (s *domainTxTestStore) seedPlayer(t *testing.T, state playerstate.PlayerState) {
	t.Helper()
	payload, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	stream := playerstate.PlayerStream(state.DiceID, state.GroupID, state.UserID)
	s.mu.Lock()
	s.versions[stream] = state.Version
	s.rows[playerstate.PlayerProjectionName+"\x00"+stream.AggregateID] = eventstore.ProjectionRow{
		ProjectionGeneration: s.snapshot.ProjectionGeneration,
		ProjectionName:       playerstate.PlayerProjectionName,
		RowKey:               stream.AggregateID,
		Payload:              payload,
	}
	s.mu.Unlock()
}

func (s *domainTxTestStore) loadCount(stream eventstore.StreamID) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loads[stream]
}

func newDomainTxForTest(t *testing.T, store eventstore.Store) (*DomainTx, *MutationCollector) {
	t.Helper()
	collector := NewMutationCollector(eventstore.EventFactory{
		Clock: domainTxTestClock{},
		IDs:   &domainTxTestIDs{},
	})
	tx, err := NewDomainTx(context.Background(), store, collector, eventstore.Metadata{
		CommandID:     "command-1",
		CorrelationID: "correlation-1",
		OccurredAt:    time.Unix(1, 0).UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return tx, collector
}

type domainTxTestClock struct{}

func (domainTxTestClock) Now() time.Time { return time.Unix(1, 0).UTC() }

type domainTxTestIDs struct {
	mu sync.Mutex
	n  int
}

func (i *domainTxTestIDs) NewID() (string, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.n++
	return "event-id-" + string(rune('a'+i.n)), nil
}
func TestMutationCollectorClonesStreamEventsFromOriginalSource(t *testing.T) {
	events := []eventstore.NewEvent{{
		EventType: "group.changed", SchemaVersion: 1, Payload: []byte(`{"name":"before"}`),
		Metadata: eventstore.Metadata{
			EventID: "event-1", CommandID: "command-1", CorrelationID: "correlation-1",
		},
	}}
	collector := NewMutationCollector(eventstore.EventFactory{})
	if err := collector.AddStream(eventstore.StreamID{AggregateType: "group", AggregateID: "group"}, 1, events); err != nil {
		t.Fatal(err)
	}
	events[0].EventType = "mutated"
	events[0].Payload[0] = '!'
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(work.Streams) != 1 || len(work.Streams[0].Events) != 1 {
		t.Fatalf("stream work=%+v", work.Streams)
	}
	got := work.Streams[0].Events[0]
	if got.EventType != "group.changed" || string(got.Payload) != `{"name":"before"}` {
		t.Fatalf("cloned event=%+v payload=%q", got, got.Payload)
	}
}

func TestMutationCollectorRejectsTransientSecretIdentitiesOnly(t *testing.T) {
	valid := eventstore.SecretUpdate{
		SecretRef: "secret-ref", EndpointID: "endpoint", AdapterID: "adapter", SecretVersion: 1,
		Value: []byte("$t plaintext value"),
	}
	if err := NewMutationCollector(eventstore.EventFactory{}).AddSecretUpdate(valid); err != nil {
		t.Fatalf("valid raw secret rejected: %v", err)
	}
	for _, field := range []string{"SecretRef", "EndpointID", "AdapterID"} {
		update := valid
		switch field {
		case "SecretRef":
			update.SecretRef = "$t-secret"
		case "EndpointID":
			update.EndpointID = "$t-endpoint"
		case "AdapterID":
			update.AdapterID = "$t-adapter"
		}
		err := NewMutationCollector(eventstore.EventFactory{}).AddSecretUpdate(update)
		if !errors.Is(err, eventstore.ErrInvalidMetadata) {
			t.Fatalf("transient %s error = %v", field, err)
		}
	}
}

func TestMutationCollectorPayloadIdentityUsesTransientPrefixRule(t *testing.T) {
	stream := eventstore.StreamID{AggregateType: "extension-state", AggregateID: "dice"}
	add := func(payload string) error {
		return NewMutationCollector(eventstore.EventFactory{}).AddStream(stream, 0, []eventstore.NewEvent{{
			EventType:     "config_definition_registered",
			SchemaVersion: 1,
			Metadata:      eventstore.Metadata{EventID: "event", CommandID: "command", CorrelationID: "correlation"},
			Payload:       []byte(payload),
		}})
	}
	if err := add(`{"definition":{"key":"access$t token"}}`); err != nil {
		t.Fatalf("opaque key containing $t rejected: %v", err)
	}
	for name, payload := range map[string]string{
		"key":       `{"key":"$tName"}`,
		"secretRef": `{"secretRef":"$tvault"}`,
	} {
		if err := add(payload); !errors.Is(err, eventstore.ErrInvalidEvent) {
			t.Fatalf("transient %s err=%v", name, err)
		}
	}
}

func TestDomainTxReadYourWritesAndRepeatIdentity(t *testing.T) {
	store := newDomainTxTestStore()
	store.seedGroup(t, groupstate.State{Version: 1, DiceID: "dice", GroupID: "group", GroupName: "before"})
	tx, collector := newDomainTxForTest(t, store)

	first, err := tx.Group(context.Background(), "dice", "group")
	if err != nil {
		t.Fatal(err)
	}
	loads := store.loadCount(groupstate.GroupStream("dice", "group"))
	type contextKey struct{}
	second, err := tx.Group(context.WithValue(context.Background(), contextKey{}, "other-context"), "dice", "group")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("repeated group identity returned a different handle")
	}
	if got := store.loadCount(groupstate.GroupStream("dice", "group")); got != loads {
		t.Fatalf("repeated identity reloaded committed state: loads=%d, want %d", got, loads)
	}
	if err := first.Decide(groupstate.Command{Kind: groupstate.CommandName, GroupName: "after"}); err != nil {
		t.Fatal(err)
	}
	if got := second.GroupName(); got != "after" {
		t.Fatalf("read-your-writes name=%q, want after", got)
	}
	if err := tx.Seal(context.Background()); err != nil {
		t.Fatal(err)
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(work.Streams) != 1 || work.Streams[0].Stream != groupstate.GroupStream("dice", "group") || len(work.Streams[0].Events) != 1 {
		t.Fatalf("sealed group work=%+v", work.Streams)
	}
}
func TestDomainTxWorkingStateIsIsolatedPerTransaction(t *testing.T) {
	store := newDomainTxTestStore()
	store.seedGroup(t, groupstate.State{Version: 1, DiceID: "dice", GroupID: "group", GroupName: "committed"})
	txA, _ := newDomainTxForTest(t, store)
	txB, _ := newDomainTxForTest(t, store)
	groupA, err := txA.Group(context.Background(), "dice", "group")
	if err != nil {
		t.Fatal(err)
	}
	groupB, err := txB.Group(context.Background(), "dice", "group")
	if err != nil {
		t.Fatal(err)
	}
	if groupA == groupB {
		t.Fatal("independent transactions shared a group handle")
	}
	if err := groupA.Decide(groupstate.Command{Kind: groupstate.CommandName, GroupName: "tx-a"}); err != nil {
		t.Fatal(err)
	}
	if groupA.GroupName() != "tx-a" {
		t.Fatalf("transaction A name=%q", groupA.GroupName())
	}
	if groupB.GroupName() != "committed" {
		t.Fatalf("transaction B observed uncommitted name=%q", groupB.GroupName())
	}
}

func TestDomainTxFailedAndClosedMutation(t *testing.T) {
	store := newDomainTxTestStore()
	store.seedPlayer(t, playerstate.PlayerState{Version: 1, DiceID: "dice", GroupID: "group", UserID: "user", Name: "before"})
	tx, _ := newDomainTxForTest(t, store)
	player, err := tx.Player(context.Background(), "dice", "group", "user")
	if err != nil {
		t.Fatal(err)
	}
	if err := player.Decide(playerstate.PlayerCommand{}); !errors.Is(err, playerstate.ErrInvalidCommand) {
		t.Fatalf("invalid mutation error=%v", err)
	}
	if tx.Err() == nil {
		t.Fatal("failed mutation did not poison transaction")
	}
	if got := player.Name(); got != "before" {
		t.Fatalf("failed mutation changed state to %q", got)
	}
	if err := tx.Seal(context.Background()); err == nil {
		t.Fatal("failed transaction sealed successfully")
	}

	clean, _ := newDomainTxForTest(t, store)
	cleanPlayer, err := clean.Player(context.Background(), "dice", "group", "user")
	if err != nil {
		t.Fatal(err)
	}
	if err := clean.Seal(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := cleanPlayer.Name(); got != "before" {
		t.Fatalf("post-seal read=%q", got)
	}
	if err := cleanPlayer.Decide(playerstate.PlayerCommand{Kind: playerstate.CommandPlayerName, Name: "before"}); !errors.Is(err, ErrDomainTxClosed) {
		t.Fatalf("closed equal-value mutation error=%v", err)
	}
	if err := cleanPlayer.Decide(playerstate.PlayerCommand{Kind: playerstate.CommandPlayerName, Name: "late"}); !errors.Is(err, ErrDomainTxClosed) {
		t.Fatalf("closed mutation error=%v", err)
	}
}

func TestDomainTxSharesGroupAndPlayerAcrossContexts(t *testing.T) {
	store := newDomainTxTestStore()
	store.seedGroup(t, groupstate.State{Version: 1, DiceID: "dice", GroupID: "group", GroupName: "group"})
	store.seedPlayer(t, playerstate.PlayerState{Version: 1, DiceID: "dice", GroupID: "group", UserID: "user", Name: "player"})
	tx, _ := newDomainTxForTest(t, store)

	groupA, err := tx.Group(context.WithValue(context.Background(), domainTxContextKey("context"), "a"), "dice", "group")
	if err != nil {
		t.Fatal(err)
	}
	groupB, err := tx.Group(context.WithValue(context.Background(), domainTxContextKey("context"), "b"), "dice", "group")
	if err != nil {
		t.Fatal(err)
	}
	playerA, err := tx.Player(context.WithValue(context.Background(), domainTxContextKey("context"), "a"), "dice", "group", "user")
	if err != nil {
		t.Fatal(err)
	}
	playerB, err := tx.Player(context.WithValue(context.Background(), domainTxContextKey("context"), "b"), "dice", "group", "user")
	if err != nil {
		t.Fatal(err)
	}
	if groupA != groupB || playerA != playerB {
		t.Fatal("cross-context identity did not reuse canonical handles")
	}
	if err := groupA.Decide(groupstate.Command{Kind: groupstate.CommandName, GroupName: "shared-group"}); err != nil {
		t.Fatal(err)
	}
	if err := playerA.Decide(playerstate.PlayerCommand{Kind: playerstate.CommandPlayerName, Name: "shared-player"}); err != nil {
		t.Fatal(err)
	}
	if groupB.GroupName() != "shared-group" || playerB.Name() != "shared-player" {
		t.Fatalf("cross-context reads group=%q player=%q", groupB.GroupName(), playerB.Name())
	}
}
func TestDomainTxSerializesConcurrentMaskedGroupDecisions(t *testing.T) {
	store := newDomainTxTestStore()
	store.seedGroup(t, groupstate.State{
		Version: 1, DiceID: "dice", GroupID: "group",
		DiceSideNum: 100, RollShaperMode: "legacy",
	})
	tx, collector := newDomainTxForTest(t, store)
	group, err := tx.Group(context.Background(), "dice", "group")
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	failures := make(chan error, 2)
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		<-start
		failures <- group.Decide(groupstate.Command{
			Kind: groupstate.CommandTemplate, DiceSideNum: 20, DiceSideNumSet: true,
		})
	}()
	go func() {
		defer workers.Done()
		<-start
		failures <- group.Decide(groupstate.Command{
			Kind: groupstate.CommandTemplate, RollShaperMode: "coc7", RollShaperModeSet: true,
		})
	}()
	close(start)
	workers.Wait()
	close(failures)
	for decisionErr := range failures {
		if decisionErr != nil {
			t.Fatal(decisionErr)
		}
	}
	if group.DiceSideNum() != 20 || group.RollShaperMode() != "coc7" {
		t.Fatalf("concurrent masked state dice=%d mode=%q", group.DiceSideNum(), group.RollShaperMode())
	}
	if err := tx.Seal(context.Background()); err != nil {
		t.Fatal(err)
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(work.Streams) != 1 || len(work.Streams[0].Events) != 2 {
		t.Fatalf("concurrent masked work=%+v", work.Streams)
	}
}

func TestDomainTxRetainsReadOnlyAndAbsentDependencies(t *testing.T) {
	store := newDomainTxTestStore()
	store.seedPlayer(t, playerstate.PlayerState{Version: 1, DiceID: "dice", GroupID: "group", UserID: "user", Name: "before"})
	tx, collector := newDomainTxForTest(t, store)
	group, err := tx.Group(context.Background(), "dice", "absent")
	if err != nil {
		t.Fatal(err)
	}
	if group.Version() != 0 {
		t.Fatalf("absent group version=%d", group.Version())
	}
	player, err := tx.Player(context.Background(), "dice", "group", "user")
	if err != nil {
		t.Fatal(err)
	}
	if err := player.Decide(playerstate.PlayerCommand{Kind: playerstate.CommandPlayerName, Name: "after"}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Seal(context.Background()); err != nil {
		t.Fatal(err)
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	want := map[eventstore.StreamID]uint64{
		groupstate.GroupStream("dice", "absent"):          0,
		playerstate.PlayerStream("dice", "group", "user"): 1,
	}
	if len(work.StreamReads) != len(want) {
		t.Fatalf("stream reads=%+v, want %d", work.StreamReads, len(want))
	}
	for _, read := range work.StreamReads {
		version, ok := want[read.Stream]
		if !ok || version != read.ExpectedVersion {
			t.Fatalf("unexpected stream read=%+v", read)
		}
		delete(want, read.Stream)
	}
	if len(want) != 0 {
		t.Fatalf("missing dependencies=%+v", want)
	}
	if len(work.ProjectionReads) != 1 || work.ProjectionReads[0].Generation != store.snapshot.ProjectionGeneration {
		t.Fatalf("projection reads=%+v", work.ProjectionReads)
	}
}
func TestDomainTxRejectsChangedProjectionSnapshotWithoutDroppingReads(t *testing.T) {
	store := newDomainTxTestStore()
	store.seedGroup(t, groupstate.State{Version: 1, DiceID: "dice", GroupID: "group", GroupName: "group"})
	store.seedPlayer(t, playerstate.PlayerState{Version: 1, DiceID: "dice", GroupID: "group", UserID: "user", Name: "player"})
	tx, collector := newDomainTxForTest(t, store)
	if _, err := tx.Group(context.Background(), "dice", "group"); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.snapshot.ProjectionGeneration = "generation-2"
	for key, row := range store.rows {
		row.ProjectionGeneration = "generation-2"
		store.rows[key] = row
	}
	store.mu.Unlock()
	if _, err := tx.Player(context.Background(), "dice", "group", "user"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Seal(context.Background()); !errors.Is(err, eventstore.ErrConflict) {
		t.Fatalf("changed projection snapshot error=%v", err)
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(work.StreamReads) != 0 || len(work.ProjectionReads) != 0 {
		t.Fatalf("failed seal partially installed dependencies: %+v", work)
	}
}

func TestDomainTxCollectsParticipantsInCanonicalOrder(t *testing.T) {
	store := newDomainTxTestStore()
	tx, collector := newDomainTxForTest(t, store)
	if err := tx.AddReadDependencies(ReadDependencies{
		StreamReads: []eventstore.StreamReadExpectation{
			{Stream: eventstore.StreamID{AggregateType: "read", AggregateID: "z"}, ExpectedVersion: 3},
			{Stream: eventstore.StreamID{AggregateType: "read", AggregateID: "a"}, ExpectedVersion: 1},
			{Stream: eventstore.StreamID{AggregateType: "read", AggregateID: "m"}, ExpectedVersion: 2},
		},
		ProjectionReads: []eventstore.ProjectionReadExpectation{{Generation: "generation-1"}},
	}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"z", "a", "m"} {
		work := eventstore.UnitOfWork{Operations: []eventstore.OperationUpdate{{OperationID: id}}}
		if err := tx.Contribute(ParticipantKey{Kind: "config", ID: id}, ReadDependencies{}, work); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Seal(context.Background()); err != nil {
		t.Fatal(err)
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(work.Operations) != 3 || work.Operations[0].OperationID != "a" || work.Operations[1].OperationID != "m" || work.Operations[2].OperationID != "z" {
		t.Fatalf("operation order=%+v", work.Operations)
	}
	if len(work.StreamReads) != 3 ||
		work.StreamReads[0].Stream.AggregateID != "a" ||
		work.StreamReads[1].Stream.AggregateID != "m" ||
		work.StreamReads[2].Stream.AggregateID != "z" {
		t.Fatalf("read order=%+v", work.StreamReads)
	}
}

type domainTxTestParticipant struct {
	id          string
	contributed int
}

func (p *domainTxTestParticipant) Contribute(context.Context) (eventstore.UnitOfWork, error) {
	p.contributed++
	return eventstore.UnitOfWork{Operations: []eventstore.OperationUpdate{{OperationID: p.id}}}, nil
}

func TestDomainTxConcurrentOwnerInstallAndPureMutation(t *testing.T) {
	tx, collector := newDomainTxForTest(t, newDomainTxTestStore())
	key := ParticipantKey{Kind: "attributes", ID: "owner"}
	arrived := make(chan struct{}, 2)
	release := make(chan struct{})
	load := func(context.Context) (Participant, ReadDependencies, error) {
		participant := &domainTxTestParticipant{id: "participant"}
		arrived <- struct{}{}
		<-release
		return participant, ReadDependencies{}, nil
	}
	results := make(chan Participant, 2)
	failures := make(chan error, 2)
	for range 2 {
		go func() {
			participant, err := tx.Owner(context.Background(), key, load)
			results <- participant
			failures <- err
		}()
	}
	<-arrived
	<-arrived
	close(release)
	first, second := <-results, <-results
	if err := <-failures; err != nil {
		t.Fatal(err)
	}
	if err := <-failures; err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("concurrent first reads installed different participants")
	}
	if err := tx.Mutate(key, func(participant Participant) error {
		participant.(*domainTxTestParticipant).id = "mutated"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Seal(context.Background()); err != nil {
		t.Fatal(err)
	}
	lookedUp, ok := tx.LookupOwner(key)
	if !ok || lookedUp != first {
		t.Fatalf("post-seal owner lookup=(%T,%v)", lookedUp, ok)
	}
	if _, ok := tx.LookupOwner(ParticipantKey{Kind: "attributes", ID: "absent"}); ok {
		t.Fatal("post-seal lookup fabricated an absent owner")
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(work.Operations) != 1 || work.Operations[0].OperationID != "mutated" {
		t.Fatalf("participant work=%+v", work.Operations)
	}
	if first.(*domainTxTestParticipant).contributed != 1 {
		t.Fatalf("canonical participant contributed %d times", first.(*domainTxTestParticipant).contributed)
	}
	aborted, _ := newDomainTxForTest(t, newDomainTxTestStore())
	abortKey := ParticipantKey{Kind: "story", ID: "scope"}
	abortOwner, err := aborted.Owner(context.Background(), abortKey, func(context.Context) (Participant, ReadDependencies, error) {
		return &domainTxTestParticipant{id: "aborted"}, ReadDependencies{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	aborted.Abort()
	lookedUp, ok = aborted.LookupOwner(abortKey)
	if !ok || lookedUp != abortOwner {
		t.Fatalf("post-abort owner lookup=(%T,%v)", lookedUp, ok)
	}
}
