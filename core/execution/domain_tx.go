package execution

import (
	"context"
	"errors"
	"slices"
	"sort"
	"strings"
	"sync"

	"Scardice-core/core/groupstate"
	"Scardice-core/core/playerstate"
	"Scardice-core/eventstore"
)

var (
	ErrDomainTxUnavailable   = errors.New("execution: domain transaction unavailable")
	ErrDomainTxClosed        = errors.New("execution: domain transaction closed")
	ErrDomainTxAborted       = errors.New("execution: domain transaction aborted")
	ErrDependencyUnavailable = errors.New("execution: dependency projection repository unavailable")
	ErrDomainSnapshotChanged = errors.New("execution: committed domain snapshot changed during load")
	ErrInvalidParticipant    = errors.New("execution: invalid participant")
	ErrParticipantType       = errors.New("execution: participant identity has a different type")
	ErrParticipantNotFound   = errors.New("execution: participant not found")
)

// ParticipantKey is one execution-local durable owner identity. Stream-backed
// owners should use StreamParticipantKey so all packages share one namespace.
type ParticipantKey struct {
	Kind string
	ID   string
}

func StreamParticipantKey(stream eventstore.StreamID) ParticipantKey {
	return ParticipantKey{Kind: "stream:" + stream.AggregateType, ID: stream.AggregateID}
}

// ReadDependencies contains only optimistic read expectations. It can be
// contributed independently from writes, including observations of absence.
type ReadDependencies struct {
	StreamReads            []eventstore.StreamReadExpectation
	ProjectionReads        []eventstore.ProjectionReadExpectation
	PluginKVReads          []eventstore.PluginKVReadExpectation
	PluginKVNamespaceReads []eventstore.PluginKVNamespaceReadExpectation
	CatalogReads           []eventstore.CatalogReadExpectation
}

func ReadDependenciesFromStream(snapshot eventstore.StreamSnapshot) ReadDependencies {
	return ReadDependencies{
		StreamReads:     []eventstore.StreamReadExpectation{{Stream: snapshot.Stream, ExpectedVersion: snapshot.Version}},
		ProjectionReads: []eventstore.ProjectionReadExpectation{{Generation: snapshot.Snapshot.ProjectionGeneration}},
	}
}

func ReadDependenciesFromProjection(snapshot eventstore.ProjectionLookupSnapshot) ReadDependencies {
	return ReadDependencies{
		StreamReads:     []eventstore.StreamReadExpectation{{Stream: snapshot.Stream, ExpectedVersion: snapshot.StreamVersion}},
		ProjectionReads: []eventstore.ProjectionReadExpectation{{Generation: snapshot.Snapshot.ProjectionGeneration}},
	}
}

func (d ReadDependencies) unitOfWork() eventstore.UnitOfWork {
	return eventstore.UnitOfWork{
		StreamReads:            d.StreamReads,
		ProjectionReads:        d.ProjectionReads,
		PluginKVReads:          d.PluginKVReads,
		PluginKVNamespaceReads: d.PluginKVNamespaceReads,
		CatalogReads:           d.CatalogReads,
	}
}

func readDependenciesFromWork(work eventstore.UnitOfWork) ReadDependencies {
	cloned := cloneUnitOfWork(work)
	return ReadDependencies{
		StreamReads:            cloned.StreamReads,
		ProjectionReads:        cloned.ProjectionReads,
		PluginKVReads:          cloned.PluginKVReads,
		PluginKVNamespaceReads: cloned.PluginKVNamespaceReads,
		CatalogReads:           cloned.CatalogReads,
	}
}

func mergeReadDependencies(target *ReadDependencies, addition ReadDependencies) {
	owned := readDependenciesFromWork(addition.unitOfWork())
	target.StreamReads = append(target.StreamReads, owned.StreamReads...)
	target.ProjectionReads = append(target.ProjectionReads, owned.ProjectionReads...)
	target.PluginKVReads = append(target.PluginKVReads, owned.PluginKVReads...)
	target.PluginKVNamespaceReads = append(target.PluginKVNamespaceReads, owned.PluginKVNamespaceReads...)
	target.CatalogReads = append(target.CatalogReads, owned.CatalogReads...)
}

// Participant owns one typed execution-local working value. Contribute is
// called once after DomainTx has closed to mutation and never while its mutex is
// held. It must return owned durable work without committing it.
type Participant interface {
	Contribute(context.Context) (eventstore.UnitOfWork, error)
}

type ParticipantFunc func(context.Context) (eventstore.UnitOfWork, error)

func (f ParticipantFunc) Contribute(ctx context.Context) (eventstore.UnitOfWork, error) {
	if f == nil {
		return eventstore.UnitOfWork{}, ErrInvalidParticipant
	}
	return f(ctx)
}

type staticParticipant struct{ work eventstore.UnitOfWork }

func (p *staticParticipant) Contribute(context.Context) (eventstore.UnitOfWork, error) {
	if p == nil {
		return eventstore.UnitOfWork{}, ErrInvalidParticipant
	}
	return cloneUnitOfWork(p.work), nil
}

type participantRecord struct {
	key         ParticipantKey
	participant Participant
	reads       ReadDependencies
}

type domainTxStatus uint8

const (
	domainTxOpen domainTxStatus = iota
	domainTxSealing
	domainTxSealed
	domainTxAborted
)

type projectionDependencyReader interface {
	ReadProjectionDependency(ctx context.Context, projectionName, rowKey string, stream eventstore.StreamID) (eventstore.ProjectionLookupSnapshot, error)
}

// DomainTx is one root execution's canonical identity table and commit
// contribution boundary. Its mutex protects only local lookup, mutation, and
// close; projection loads and participant contribution callbacks run outside it.
type DomainTx struct {
	mu          sync.Mutex
	projections projectionDependencyReader
	collector   *MutationCollector
	metadata    eventstore.Metadata
	status      domainTxStatus
	err         error
	owners      map[ParticipantKey]*participantRecord
	reads       ReadDependencies
}

func NewDomainTx(ctx context.Context, store eventstore.Store, collector *MutationCollector, metadata eventstore.Metadata) (*DomainTx, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if isNil(store) || collector == nil {
		return nil, ErrDomainTxUnavailable
	}
	projections, ok := store.(projectionDependencyReader)
	if !ok || isNil(projections) {
		return nil, ErrDependencyUnavailable
	}
	return &DomainTx{
		projections: projections, collector: collector, metadata: metadata,
		owners: make(map[ParticipantKey]*participantRecord),
	}, nil
}

func validParticipantKey(key ParticipantKey) bool {
	return strings.TrimSpace(key.Kind) != "" && strings.TrimSpace(key.ID) != "" && !ContainsTransientText(key.Kind) && !ContainsTransientText(key.ID)
}

func (t *DomainTx) stateErrorLocked() error {
	if t.err != nil {
		return t.err
	}
	switch t.status {
	case domainTxOpen:
		return nil
	case domainTxAborted:
		return ErrDomainTxAborted
	default:
		return ErrDomainTxClosed
	}
}

func (t *DomainTx) failLocked(err error) error {
	if err == nil {
		return nil
	}
	if t.err == nil {
		t.err = err
	} else if !errors.Is(t.err, err) {
		t.err = errors.Join(t.err, err)
	}
	return err
}

// CheckOpen atomically validates the mutation lifetime for external controlled
// facades. Scalar/history reads remain available after Seal.
func (t *DomainTx) CheckOpen() error {
	if t == nil {
		return ErrDomainTxUnavailable
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.stateErrorLocked()
}

func (t *DomainTx) Err() error {
	if t == nil {
		return ErrDomainTxUnavailable
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.err != nil {
		return t.err
	}
	if t.status == domainTxAborted {
		return ErrDomainTxAborted
	}
	return nil
}

// Owner returns the one participant for key. A missing owner is loaded without
// holding the transaction mutex, then installed only after a second lookup so
// concurrent first reads cannot create two canonical working values.
func (t *DomainTx) Owner(
	ctx context.Context,
	key ParticipantKey,
	load func(context.Context) (Participant, ReadDependencies, error),
) (Participant, error) {
	if t == nil {
		return nil, ErrDomainTxUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if !validParticipantKey(key) || load == nil {
		return nil, ErrInvalidParticipant
	}
	t.mu.Lock()
	if err := t.stateErrorLocked(); err != nil {
		t.mu.Unlock()
		return nil, err
	}
	if existing := t.owners[key]; existing != nil {
		participant := existing.participant
		t.mu.Unlock()
		return participant, nil
	}
	t.mu.Unlock()

	participant, reads, err := load(ctx)
	if err == nil && isNil(participant) {
		err = ErrInvalidParticipant
	}
	if err != nil {
		t.mu.Lock()
		defer t.mu.Unlock()
		if stateErr := t.stateErrorLocked(); stateErr != nil {
			return nil, stateErr
		}
		if existing := t.owners[key]; existing != nil {
			return existing.participant, nil
		}
		return nil, t.failLocked(err)
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.stateErrorLocked(); err != nil {
		return nil, err
	}
	if existing := t.owners[key]; existing != nil {
		return existing.participant, nil
	}
	t.owners[key] = &participantRecord{key: key, participant: participant, reads: readDependenciesFromWork(reads.unitOfWork())}
	return participant, nil
}

// LookupOwner returns an already-loaded canonical participant without loading
// or reopening mutation. It remains available after Seal or Abort so retained
// read facades can inspect their execution-local snapshot.
func (t *DomainTx) LookupOwner(key ParticipantKey) (Participant, bool) {
	if t == nil || !validParticipantKey(key) {
		return nil, false
	}
	t.mu.Lock()
	record := t.owners[key]
	t.mu.Unlock()
	if record == nil {
		return nil, false
	}
	return record.participant, true
}

// Mutate serializes one pure local participant mutation with Seal. mutate runs
// under the short DomainTx mutex and therefore must not perform I/O, re-enter
// DomainTx, await, or invoke untrusted callbacks.
func (t *DomainTx) Mutate(key ParticipantKey, mutate func(Participant) error) error {
	if t == nil {
		return ErrDomainTxUnavailable
	}
	if !validParticipantKey(key) || mutate == nil {
		return ErrInvalidParticipant
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.stateErrorLocked(); err != nil {
		return err
	}
	record := t.owners[key]
	if record == nil {
		return t.failLocked(ErrParticipantNotFound)
	}
	if err := mutate(record.participant); err != nil {
		return t.failLocked(err)
	}
	return nil
}

// Contribute registers a static owner fragment in the same identity table as
// typed group/player handles. Duplicate owner registration is rejected.
func (t *DomainTx) Contribute(key ParticipantKey, reads ReadDependencies, work eventstore.UnitOfWork) error {
	if t == nil {
		return ErrDomainTxUnavailable
	}
	if !validParticipantKey(key) {
		return ErrInvalidParticipant
	}
	participant := &staticParticipant{work: cloneUnitOfWork(work)}
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.stateErrorLocked(); err != nil {
		return err
	}
	if _, exists := t.owners[key]; exists {
		return t.failLocked(eventstore.ErrDuplicateParticipant)
	}
	t.owners[key] = &participantRecord{key: key, participant: participant, reads: readDependenciesFromWork(reads.unitOfWork())}
	return nil
}

// AddReadDependencies contributes durable command reads that are not owned by
// one participant, such as permission or scope checks.
func (t *DomainTx) AddReadDependencies(reads ReadDependencies) error {
	if t == nil {
		return ErrDomainTxUnavailable
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.stateErrorLocked(); err != nil {
		return err
	}
	mergeReadDependencies(&t.reads, reads)
	return nil
}

func (t *DomainTx) Group(ctx context.Context, diceID, groupID string) (*GroupHandle, error) {
	stream := groupstate.GroupStream(diceID, groupID)
	if stream.AggregateID == "" {
		return nil, groupstate.ErrInvalidIdentity
	}
	key := StreamParticipantKey(stream)
	participant, err := t.Owner(ctx, key, func(loadCtx context.Context) (Participant, ReadDependencies, error) {
		state, snapshot, loadErr := t.loadGroup(loadCtx, diceID, groupID, stream)
		if loadErr != nil {
			return nil, ReadDependencies{}, loadErr
		}
		entry := &groupParticipant{tx: t, key: key, stream: stream, baseVersion: snapshot.StreamVersion, state: state}
		entry.handle = &GroupHandle{tx: t, entry: entry}
		return entry, ReadDependenciesFromProjection(snapshot), nil
	})
	if err != nil {
		return nil, err
	}
	entry, ok := participant.(*groupParticipant)
	if !ok {
		return nil, t.recordFailure(ErrParticipantType)
	}
	return entry.handle, nil
}

func (t *DomainTx) Player(ctx context.Context, diceID, groupID, userID string) (*PlayerHandle, error) {
	stream := playerstate.PlayerStream(diceID, groupID, userID)
	if stream.AggregateID == "" {
		return nil, playerstate.ErrInvalidIdentity
	}
	key := StreamParticipantKey(stream)
	participant, err := t.Owner(ctx, key, func(loadCtx context.Context) (Participant, ReadDependencies, error) {
		state, snapshot, loadErr := t.loadPlayer(loadCtx, diceID, groupID, userID, stream)
		if loadErr != nil {
			return nil, ReadDependencies{}, loadErr
		}
		entry := &playerParticipant{tx: t, key: key, stream: stream, baseVersion: snapshot.StreamVersion, state: state}
		entry.handle = &PlayerHandle{tx: t, entry: entry}
		return entry, ReadDependenciesFromProjection(snapshot), nil
	})
	if err != nil {
		return nil, err
	}
	entry, ok := participant.(*playerParticipant)
	if !ok {
		return nil, t.recordFailure(ErrParticipantType)
	}
	return entry.handle, nil
}

func (t *DomainTx) recordFailure(err error) error {
	if t == nil || err == nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.status == domainTxOpen {
		return t.failLocked(err)
	}
	return err
}

type capturedProjectionReader struct {
	row   eventstore.ProjectionRow
	found bool
}

func (r capturedProjectionReader) ReadProjectionRow(context.Context, string, string) (eventstore.ProjectionRow, error) {
	if !r.found {
		return eventstore.ProjectionRow{}, eventstore.ErrNotFound
	}
	return r.row, nil
}

func validProjectionLookup(snapshot eventstore.ProjectionLookupSnapshot, projectionName, rowKey string, stream eventstore.StreamID) bool {
	if snapshot.Stream != stream || snapshot.Snapshot.ProjectionGeneration == "" {
		return false
	}
	if !snapshot.Found {
		return true
	}
	return snapshot.Row.ProjectionGeneration == snapshot.Snapshot.ProjectionGeneration &&
		snapshot.Row.ProjectionName == projectionName &&
		snapshot.Row.RowKey == rowKey
}

func (t *DomainTx) loadGroup(ctx context.Context, diceID, groupID string, stream eventstore.StreamID) (groupstate.State, eventstore.ProjectionLookupSnapshot, error) {
	snapshot, err := t.projections.ReadProjectionDependency(ctx, groupstate.GroupProjectionName, stream.AggregateID, stream)
	if err != nil {
		return groupstate.State{}, eventstore.ProjectionLookupSnapshot{}, err
	}
	if !validProjectionLookup(snapshot, groupstate.GroupProjectionName, stream.AggregateID, stream) {
		return groupstate.State{}, eventstore.ProjectionLookupSnapshot{}, ErrDomainSnapshotChanged
	}
	if !snapshot.Found {
		if snapshot.StreamVersion != 0 {
			return groupstate.State{}, eventstore.ProjectionLookupSnapshot{}, ErrDomainSnapshotChanged
		}
		return groupstate.State{DiceID: diceID, GroupID: groupID}, snapshot, nil
	}
	state, err := groupstate.ReadProjected(ctx, capturedProjectionReader{row: snapshot.Row, found: true}, diceID, groupID)
	if err != nil {
		return groupstate.State{}, eventstore.ProjectionLookupSnapshot{}, err
	}
	if state.Version != snapshot.StreamVersion {
		return groupstate.State{}, eventstore.ProjectionLookupSnapshot{}, ErrDomainSnapshotChanged
	}
	return state, snapshot, nil
}

func (t *DomainTx) loadPlayer(ctx context.Context, diceID, groupID, userID string, stream eventstore.StreamID) (playerstate.PlayerState, eventstore.ProjectionLookupSnapshot, error) {
	snapshot, err := t.projections.ReadProjectionDependency(ctx, playerstate.PlayerProjectionName, stream.AggregateID, stream)
	if err != nil {
		return playerstate.PlayerState{}, eventstore.ProjectionLookupSnapshot{}, err
	}
	if !validProjectionLookup(snapshot, playerstate.PlayerProjectionName, stream.AggregateID, stream) {
		return playerstate.PlayerState{}, eventstore.ProjectionLookupSnapshot{}, ErrDomainSnapshotChanged
	}
	if !snapshot.Found {
		if snapshot.StreamVersion != 0 {
			return playerstate.PlayerState{}, eventstore.ProjectionLookupSnapshot{}, ErrDomainSnapshotChanged
		}
		return playerstate.PlayerState{DiceID: diceID, GroupID: groupID, UserID: userID}, snapshot, nil
	}
	state, err := playerstate.ReadProjectedPlayer(ctx, capturedProjectionReader{row: snapshot.Row, found: true}, diceID, groupID, userID)
	if err != nil {
		return playerstate.PlayerState{}, eventstore.ProjectionLookupSnapshot{}, err
	}
	if state.Version != snapshot.StreamVersion {
		return playerstate.PlayerState{}, eventstore.ProjectionLookupSnapshot{}, ErrDomainSnapshotChanged
	}
	return state, snapshot, nil
}

func (t *DomainTx) Seal(ctx context.Context) error {
	if t == nil {
		return ErrDomainTxUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	t.mu.Lock()
	if t.status == domainTxSealed {
		err := t.err
		t.mu.Unlock()
		return err
	}
	if err := t.stateErrorLocked(); err != nil {
		t.mu.Unlock()
		return err
	}
	t.status = domainTxSealing
	records := make([]*participantRecord, 0, len(t.owners))
	reads := readDependenciesFromWork(t.reads.unitOfWork())
	for _, record := range t.owners {
		records = append(records, record)
		mergeReadDependencies(&reads, record.reads)
	}
	t.mu.Unlock()

	sort.Slice(records, func(i, j int) bool {
		if records[i].key.Kind != records[j].key.Kind {
			return records[i].key.Kind < records[j].key.Kind
		}
		return records[i].key.ID < records[j].key.ID
	})
	staged := NewMutationCollector(t.collector.factory)
	if err := staged.AddUnitOfWork(reads.unitOfWork()); err != nil {
		return t.finishSeal(err)
	}
	for _, record := range records {
		if err := ctx.Err(); err != nil {
			return t.finishSeal(err)
		}
		var err error
		switch participant := record.participant.(type) {
		case *groupParticipant:
			err = participant.contribute(staged, t.metadata)
		case *playerParticipant:
			err = participant.contribute(staged, t.metadata)
		default:
			var work eventstore.UnitOfWork
			work, err = participant.Contribute(ctx)
			if err == nil {
				err = staged.AddUnitOfWork(work)
			}
		}
		if err != nil {
			return t.finishSeal(err)
		}
	}
	work, err := staged.UnitOfWork()
	if err != nil {
		return t.finishSeal(err)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.status != domainTxSealing || t.err != nil {
		return t.stateErrorLocked()
	}
	if err = t.collector.AddUnitOfWork(work); err != nil {
		_ = t.failLocked(err)
	}
	t.status = domainTxSealed
	return t.err
}

func (t *DomainTx) finishSeal(err error) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err != nil {
		_ = t.failLocked(err)
	}
	if t.status == domainTxSealing {
		t.status = domainTxSealed
	}
	return t.err
}

func (t *DomainTx) Abort() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.status == domainTxSealed || t.status == domainTxAborted {
		return
	}
	t.status = domainTxAborted
	if t.err == nil {
		t.err = ErrDomainTxAborted
	}
}

type groupParticipant struct {
	tx          *DomainTx
	key         ParticipantKey
	stream      eventstore.StreamID
	baseVersion uint64
	state       groupstate.State
	events      []groupstate.TypedEvent
	handle      *GroupHandle
}

func (p *groupParticipant) Contribute(context.Context) (eventstore.UnitOfWork, error) {
	return eventstore.UnitOfWork{}, nil
}

func (p *groupParticipant) contribute(collector *MutationCollector, metadata eventstore.Metadata) error {
	if p == nil || len(p.events) == 0 {
		return nil
	}
	return collector.AddGroupEvents(p.stream, p.baseVersion, metadata, p.events)
}

type playerParticipant struct {
	tx          *DomainTx
	key         ParticipantKey
	stream      eventstore.StreamID
	baseVersion uint64
	state       playerstate.PlayerState
	events      []playerstate.PlayerEvent
	handle      *PlayerHandle
}

func (p *playerParticipant) Contribute(context.Context) (eventstore.UnitOfWork, error) {
	return eventstore.UnitOfWork{}, nil
}

func (p *playerParticipant) contribute(collector *MutationCollector, metadata eventstore.Metadata) error {
	if p == nil || len(p.events) == 0 {
		return nil
	}
	return collector.AddPlayerEvents(p.stream, p.baseVersion, metadata, p.events)
}

// GroupHandle is the controlled typed view of one canonical group entry.
type GroupHandle struct {
	tx    *DomainTx
	entry *groupParticipant
}

func (h *GroupHandle) current() groupstate.State {
	if h == nil || h.tx == nil || h.entry == nil {
		return groupstate.State{}
	}
	h.tx.mu.Lock()
	state := h.entry.state
	h.tx.mu.Unlock()
	return state
}

func (h *GroupHandle) Snapshot() groupstate.State { return h.current().Clone() }

func (h *GroupHandle) Decide(command groupstate.Command) error {
	if h == nil || h.tx == nil || h.entry == nil {
		return ErrDomainTxUnavailable
	}
	h.tx.mu.Lock()
	defer h.tx.mu.Unlock()
	if err := h.tx.stateErrorLocked(); err != nil {
		return err
	}
	decision, err := groupstate.Decide(h.entry.state, command)
	if err != nil {
		return h.tx.failLocked(err)
	}
	next := h.entry.state
	for _, event := range decision.Events {
		next, err = groupstate.Reduce(next, event)
		if err != nil {
			return h.tx.failLocked(err)
		}
	}
	h.entry.state = next
	h.entry.events = append(h.entry.events, decision.Events...)
	return nil
}

func (h *GroupHandle) Version() uint64        { return h.current().Version }
func (h *GroupHandle) DiceID() string         { return h.current().DiceID }
func (h *GroupHandle) GroupID() string        { return h.current().GroupID }
func (h *GroupHandle) GroupName() string      { return h.current().GroupName }
func (h *GroupHandle) InviteUserID() string   { return h.current().InviteUserID }
func (h *GroupHandle) GuildID() string        { return h.current().GuildID }
func (h *GroupHandle) ChannelID() string      { return h.current().ChannelID }
func (h *GroupHandle) Active() bool           { return h.current().Active }
func (h *GroupHandle) System() string         { return h.current().System }
func (h *GroupHandle) DiceSideNum() int64     { return h.current().DiceSideNum }
func (h *GroupHandle) DiceSideExpr() string   { return h.current().DiceSideExpr }
func (h *GroupHandle) RollShaperMode() string { return h.current().RollShaperMode }
func (h *GroupHandle) CocRuleIndex() int      { return h.current().CocRuleIndex }
func (h *GroupHandle) DefaultHelpGroup() string {
	return h.current().DefaultHelpGroup
}
func (h *GroupHandle) ShowGroupWelcome() bool {
	return h.current().ShowGroupWelcome
}
func (h *GroupHandle) GroupWelcomeMessage() string {
	return h.current().GroupWelcomeMessage
}
func (h *GroupHandle) EnteredAt() int64 { return h.current().EnteredAt }
func (h *GroupHandle) Deleted() bool    { return h.current().Deleted }
func (h *GroupHandle) DiceIDActive(diceID string) bool {
	return h.current().DiceIDActive[diceID]
}
func (h *GroupHandle) DiceIDExists(diceID string) bool {
	return h.current().DiceIDExists[diceID]
}
func (h *GroupHandle) ExtensionActive(extensionID string) bool {
	return slices.Contains(h.current().ActivatedExtensions, extensionID)
}
func (h *GroupHandle) ExtensionInactivated(extensionID string) bool {
	return h.current().InactivatedExtensions[extensionID]
}
func (h *GroupHandle) BotExists(userID string) bool {
	return h.current().BotList[userID]
}
func (h *GroupHandle) Privilege(userID string) (int, bool) {
	value, ok := h.current().Privileges[userID]
	return value, ok
}
func (h *GroupHandle) ActivatedExtensionIDs() []string {
	return slices.Clone(h.current().ActivatedExtensions)
}
func (h *GroupHandle) InactivatedExtensionIDs() []string {
	return trueMapKeys(h.current().InactivatedExtensions)
}
func (h *GroupHandle) HelpPackageIDs() []string {
	return slices.Clone(h.current().HelpPackages)
}
func (h *GroupHandle) ActiveDiceIDs() []string {
	return trueMapKeys(h.current().DiceIDActive)
}
func (h *GroupHandle) ExistingDiceIDs() []string {
	return trueMapKeys(h.current().DiceIDExists)
}
func (h *GroupHandle) BotIDs() []string {
	return trueMapKeys(h.current().BotList)
}
func (h *GroupHandle) TeamMembers(name string) []string {
	return slices.Clone(h.current().PlayerGroups[name])
}
func (h *GroupHandle) TeamNames() []string {
	groups := h.current().PlayerGroups
	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func trueMapKeys(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for key, present := range values {
		if present {
			result = append(result, key)
		}
	}
	sort.Strings(result)
	return result
}

// PlayerHandle is the controlled typed view of one canonical player entry.
type PlayerHandle struct {
	tx    *DomainTx
	entry *playerParticipant
}

func (h *PlayerHandle) current() playerstate.PlayerState {
	if h == nil || h.tx == nil || h.entry == nil {
		return playerstate.PlayerState{}
	}
	h.tx.mu.Lock()
	state := h.entry.state
	h.tx.mu.Unlock()
	return state
}

func (h *PlayerHandle) Snapshot() playerstate.PlayerState { return h.current().Clone() }

func (h *PlayerHandle) Decide(command playerstate.PlayerCommand) error {
	if h == nil || h.tx == nil || h.entry == nil {
		return ErrDomainTxUnavailable
	}
	h.tx.mu.Lock()
	defer h.tx.mu.Unlock()
	if err := h.tx.stateErrorLocked(); err != nil {
		return err
	}
	decision, err := playerstate.DecidePlayer(h.entry.state, command)
	if err != nil {
		return h.tx.failLocked(err)
	}
	next := h.entry.state
	for _, event := range decision.Events {
		next, err = playerstate.ReducePlayer(next, event)
		if err != nil {
			return h.tx.failLocked(err)
		}
	}
	h.entry.state = next
	h.entry.events = append(h.entry.events, decision.Events...)
	return nil
}

func (h *PlayerHandle) Version() uint64 { return h.current().Version }
func (h *PlayerHandle) DiceID() string  { return h.current().DiceID }
func (h *PlayerHandle) GroupID() string { return h.current().GroupID }
func (h *PlayerHandle) UserID() string  { return h.current().UserID }
func (h *PlayerHandle) Name() string    { return h.current().Name }
func (h *PlayerHandle) Privilege() int {
	return h.current().Privilege
}
func (h *PlayerHandle) AutoSetNameTemplate() string {
	return h.current().AutoSetNameTemplate
}
func (h *PlayerHandle) LastCommandAt() int64 {
	return h.current().LastCommandAt
}
func (h *PlayerHandle) DiceSideNum() int64 {
	return h.current().DiceSideNum
}
func (h *PlayerHandle) Deleted() bool {
	return h.current().Deleted
}
