package attributestate

import (
	"context"
	"errors"
	"sort"

	"Scardice-core/eventstore"
)

type secretStore interface {
	eventstore.Store
	PrepareSecretUpdate(ctx context.Context, req eventstore.SecretPutRequest) (eventstore.SecretUpdate, error)
	ResolveSecret(ctx context.Context, ref string, version uint64) (eventstore.SecretResolution, error)
	ResolveSecrets(ctx context.Context, lookups []eventstore.SecretLookup) ([]eventstore.SecretResolution, error)
}

type Repository struct {
	store   secretStore
	factory eventstore.EventFactory
}

type LoadedState struct {
	State     State
	Plaintext []byte
}

func NewRepository(store eventstore.Store) (*Repository, error) {
	secrets, ok := store.(secretStore)
	if !ok || secrets == nil {
		return nil, ErrRepositoryUnavailable
	}
	return &Repository{
		store:   secrets,
		factory: eventstore.EventFactory{Clock: eventstore.SystemClock{}, IDs: eventstore.UUIDGenerator{}},
	}, nil
}

func SecretRef(diceID, id string) string {
	return "vault:attributes:" + Stream(diceID, id).AggregateID
}

func (repository *Repository) Load(ctx context.Context, diceID, id string) (State, []byte, error) {
	if repository == nil || repository.store == nil {
		return State{}, nil, ErrRepositoryUnavailable
	}
	state, err := ReadProjected(ctx, repository.store, diceID, id)
	if err != nil {
		return State{}, nil, err
	}
	secret, err := repository.store.ResolveSecret(ctx, state.SecretRef, state.SecretVersion)
	if errors.Is(err, eventstore.ErrNotFound) {
		return State{}, nil, ErrSecretUnavailable
	}
	if err != nil {
		return State{}, nil, err
	}
	if secret.SecretRef != state.SecretRef || secret.SecretVersion != state.SecretVersion {
		clear(secret.Value)
		return State{}, nil, ErrSecretUnavailable
	}
	return state, secret.Value, nil
}

func (repository *Repository) LoadBatch(ctx context.Context, states []State) ([]LoadedState, error) {
	if repository == nil || repository.store == nil {
		return nil, ErrRepositoryUnavailable
	}
	if len(states) == 0 {
		return []LoadedState{}, nil
	}
	for _, state := range states {
		if ValidateState(state) != nil {
			return nil, ErrInvalidState
		}
	}

	loaded := make([]LoadedState, 0, len(states))
	for start := 0; start < len(states); start += eventstore.MaxSecretBatchLookups {
		end := min(start+eventstore.MaxSecretBatchLookups, len(states))
		lookups := make([]eventstore.SecretLookup, end-start)
		for index, state := range states[start:end] {
			lookups[index] = eventstore.SecretLookup{SecretRef: state.SecretRef, SecretVersion: state.SecretVersion}
		}
		secrets, err := repository.store.ResolveSecrets(ctx, lookups)
		if errors.Is(err, eventstore.ErrNotFound) {
			clearLoadedStates(loaded)
			return nil, ErrSecretUnavailable
		}
		if err != nil {
			clearLoadedStates(loaded)
			return nil, err
		}
		if len(secrets) != end-start {
			clearSecretResolutions(secrets)
			clearLoadedStates(loaded)
			return nil, ErrSecretUnavailable
		}
		for index, secret := range secrets {
			state := states[start+index]
			if secret.SecretRef != state.SecretRef || secret.SecretVersion != state.SecretVersion {
				clearSecretResolutions(secrets)
				clearLoadedStates(loaded)
				return nil, ErrSecretUnavailable
			}
			loaded = append(loaded, LoadedState{State: state, Plaintext: secret.Value})
		}
	}
	return loaded, nil
}

func clearSecretResolutions(secrets []eventstore.SecretResolution) {
	for index := range secrets {
		clear(secrets[index].Value)
	}
}

func clearLoadedStates(states []LoadedState) {
	for index := range states {
		clear(states[index].Plaintext)
	}
}

// ExecutionLoad is the dependency-bearing attribute snapshot used by one
// DomainTx owner. Missing identities retain their stream and projection
// expectations so a concurrent creator conflicts at commit.
type ExecutionLoad struct {
	State         State
	Plaintext     []byte
	Found         bool
	StreamVersion uint64
	Snapshot      eventstore.DependencySnapshot
}

func (repository *Repository) LoadForExecution(ctx context.Context, diceID, id string) (ExecutionLoad, error) {
	if repository == nil || repository.store == nil {
		return ExecutionLoad{}, ErrRepositoryUnavailable
	}
	dependencies, ok := any(repository.store).(eventstore.ProjectionDependencyRepository)
	if !ok || dependencies == nil {
		return ExecutionLoad{}, ErrRepositoryUnavailable
	}
	stream := Stream(diceID, id)
	if stream.AggregateID == "" {
		return ExecutionLoad{}, ErrInvalidIdentity
	}
	loaded, err := dependencies.ReadProjectionDependency(ctx, ProjectionName, stream.AggregateID, stream)
	if err != nil {
		return ExecutionLoad{}, err
	}
	if loaded.Stream != stream || loaded.Snapshot.ProjectionGeneration == "" {
		return ExecutionLoad{}, ErrInvalidState
	}
	result := ExecutionLoad{
		Found: loaded.Found, StreamVersion: loaded.StreamVersion, Snapshot: loaded.Snapshot,
	}
	if !loaded.Found {
		if loaded.StreamVersion != 0 {
			return ExecutionLoad{}, ErrInvalidState
		}
		return result, nil
	}
	if loaded.Row.ProjectionName != ProjectionName ||
		loaded.Row.ProjectionGeneration != loaded.Snapshot.ProjectionGeneration ||
		loaded.Row.RowKey != stream.AggregateID {
		return ExecutionLoad{}, ErrInvalidState
	}
	state, err := decodeProjectedRow(loaded.Row)
	if err != nil || state.DiceID != diceID || state.ID != id || state.Version != loaded.StreamVersion {
		return ExecutionLoad{}, ErrInvalidState
	}
	secret, err := repository.store.ResolveSecret(ctx, state.SecretRef, state.SecretVersion)
	if errors.Is(err, eventstore.ErrNotFound) {
		return ExecutionLoad{}, ErrSecretUnavailable
	}
	if err != nil {
		return ExecutionLoad{}, err
	}
	if secret.SecretRef != state.SecretRef || secret.SecretVersion != state.SecretVersion {
		clear(secret.Value)
		return ExecutionLoad{}, ErrSecretUnavailable
	}
	result.State = state
	result.Plaintext = secret.Value
	return result, nil
}

// PreparedSnapshot owns the event and value update produced by
// serializing a transaction-local attribute container at seal.
type PreparedSnapshot struct {
	State State
	Work  eventstore.UnitOfWork
}

func (repository *Repository) PrepareSnapshot(
	ctx context.Context,
	state State,
	plaintext []byte,
	metadata eventstore.Metadata,
) (PreparedSnapshot, error) {
	if repository == nil || repository.store == nil || len(plaintext) == 0 {
		return PreparedSnapshot{}, ErrRepositoryUnavailable
	}
	stream := Stream(state.DiceID, state.ID)
	if stream.AggregateID == "" {
		return PreparedSnapshot{}, ErrInvalidIdentity
	}
	if state.SecretRef == "" {
		state.SecretRef = SecretRef(state.DiceID, state.ID)
	}
	expectedVersion := state.Version
	nextVersion := expectedVersion + 1
	if nextVersion == 0 {
		return PreparedSnapshot{}, eventstore.ErrVersionExhausted
	}
	state.SecretVersion = nextVersion
	payload, err := MarshalBaselineImportedV1(NewBaselineImportedV1(state))
	if err != nil {
		return PreparedSnapshot{}, err
	}
	eventType := EventSnapshotReplaced
	if expectedVersion == 0 {
		eventType = EventBaselineImported
	}
	newEvent, err := repository.factory.NewEvent(eventType, EventSchemaVersion, payload, metadata)
	if err != nil {
		return PreparedSnapshot{}, err
	}
	secret, err := repository.store.PrepareSecretUpdate(ctx, eventstore.SecretPutRequest{
		SecretRef: state.SecretRef, EndpointID: state.ID, AdapterID: AggregateType,
		SecretVersion: nextVersion, ExpectedVersion: expectedVersion, Value: plaintext,
	})
	if err != nil {
		return PreparedSnapshot{}, err
	}
	state.Version = nextVersion
	return PreparedSnapshot{
		State: state,
		Work: eventstore.UnitOfWork{
			Streams: []eventstore.StreamAppend{{
				Stream: stream, ExpectedVersion: expectedVersion, Events: []eventstore.NewEvent{newEvent},
			}},
			SecretUpdates: []eventstore.SecretUpdate{secret},
		},
	}, nil
}

// SnapshotWrite contains one complete attribute snapshot for an atomic batch.
type SnapshotWrite struct {
	State     State
	Plaintext []byte
}

func (repository *Repository) Save(ctx context.Context, state State, plaintext []byte) (State, error) {
	if repository == nil || repository.store == nil {
		return State{}, ErrRepositoryUnavailable
	}
	before, err := repository.projectedStateForWrite(ctx, state)
	if err != nil {
		return State{}, err
	}
	state, stream, secret, err := repository.prepareSnapshot(ctx, state, plaintext)
	if err != nil {
		return State{}, err
	}
	catalogs, err := repository.catalogUpdates(ctx, []catalogTransition{{before: before, after: state}})
	if err != nil {
		return State{}, err
	}
	if _, err = repository.store.Commit(ctx, eventstore.UnitOfWork{
		Streams: []eventstore.StreamAppend{stream}, SecretUpdates: []eventstore.SecretUpdate{secret}, CatalogUpdates: catalogs,
	}); err != nil {
		return State{}, err
	}
	return state, nil
}

// SaveBatch commits every snapshot and secret version in one UnitOfWork.
func (repository *Repository) SaveBatch(ctx context.Context, writes []SnapshotWrite) ([]State, error) {
	if repository == nil || repository.store == nil {
		return nil, ErrRepositoryUnavailable
	}
	if len(writes) == 0 {
		return []State{}, nil
	}
	streams := make([]eventstore.StreamAppend, 0, len(writes))
	secrets := make([]eventstore.SecretUpdate, 0, len(writes))
	states := make([]State, 0, len(writes))
	transitions := make([]catalogTransition, 0, len(writes))
	for _, write := range writes {
		before, err := repository.projectedStateForWrite(ctx, write.State)
		if err != nil {
			return nil, err
		}
		state, stream, secret, err := repository.prepareSnapshot(ctx, write.State, write.Plaintext)
		if err != nil {
			return nil, err
		}
		states = append(states, state)
		streams = append(streams, stream)
		secrets = append(secrets, secret)
		transitions = append(transitions, catalogTransition{before: before, after: state})
	}
	catalogs, err := repository.catalogUpdates(ctx, transitions)
	if err != nil {
		return nil, err
	}
	if _, err = repository.store.Commit(ctx, eventstore.UnitOfWork{
		Streams: streams, SecretUpdates: secrets, CatalogUpdates: catalogs,
	}); err != nil {
		return nil, err
	}
	return states, nil
}

func (repository *Repository) prepareSnapshot(ctx context.Context, state State, plaintext []byte) (State, eventstore.StreamAppend, eventstore.SecretUpdate, error) {
	prepared, err := repository.PrepareSnapshot(ctx, state, plaintext, eventstore.Metadata{})
	if err != nil {
		return State{}, eventstore.StreamAppend{}, eventstore.SecretUpdate{}, err
	}
	return prepared.State, prepared.Work.Streams[0], prepared.Work.SecretUpdates[0], nil
}

type catalogTransition struct {
	before State
	after  State
}

type catalogIdentity struct {
	diceID  string
	catalog string
	owner   string
}

func (repository *Repository) projectedStateForWrite(ctx context.Context, state State) (State, error) {
	dependencies, ok := any(repository.store).(eventstore.ProjectionDependencyRepository)
	if !ok || dependencies == nil {
		return State{}, ErrRepositoryUnavailable
	}
	stream := Stream(state.DiceID, state.ID)
	loaded, err := dependencies.ReadProjectionDependency(ctx, ProjectionName, stream.AggregateID, stream)
	if err != nil {
		return State{}, err
	}
	if loaded.Stream != stream || loaded.Snapshot.ProjectionGeneration == "" {
		return State{}, eventstore.ErrProjectionInvariant
	}
	if !loaded.Found {
		if state.Version != 0 || loaded.StreamVersion != 0 {
			return State{}, eventstore.ErrConflict
		}
		return State{}, nil
	}
	if loaded.Row.ProjectionName != ProjectionName ||
		loaded.Row.ProjectionGeneration != loaded.Snapshot.ProjectionGeneration ||
		loaded.Row.RowKey != stream.AggregateID {
		return State{}, eventstore.ErrProjectionInvariant
	}
	before, err := decodeProjectedRow(loaded.Row)
	if err != nil || before.Version != loaded.StreamVersion || state.Version != loaded.StreamVersion {
		return State{}, eventstore.ErrConflict
	}
	return before, nil
}

func catalogIdentities(transition catalogTransition) map[catalogIdentity]struct{} {
	result := make(map[catalogIdentity]struct{}, 4)
	add := func(state State) {
		if state.AttrsType == AttrsTypeCharacter && state.OwnerID != "" {
			result[catalogIdentity{diceID: state.DiceID, catalog: CharacterCatalog, owner: state.OwnerID}] = struct{}{}
		}
		if state.BindingSheetID != "" {
			result[catalogIdentity{diceID: state.DiceID, catalog: BindingCatalog, owner: state.BindingSheetID}] = struct{}{}
		}
	}
	add(transition.before)
	add(transition.after)
	return result
}

func (repository *Repository) catalogUpdates(ctx context.Context, transitions []catalogTransition) ([]eventstore.CatalogRevisionUpdate, error) {
	identities := make(map[catalogIdentity]struct{})
	for _, transition := range transitions {
		for identity := range catalogIdentities(transition) {
			identities[identity] = struct{}{}
		}
	}
	if len(identities) == 0 {
		return nil, nil
	}
	revisions, ok := any(repository.store).(eventstore.CatalogRevisionRepository)
	if !ok || revisions == nil {
		return nil, ErrRepositoryUnavailable
	}
	updates := make([]eventstore.CatalogRevisionUpdate, 0, len(identities))
	for identity := range identities {
		snapshot, err := revisions.ReadCatalogRevision(ctx, identity.catalog, CatalogOwner(identity.diceID, identity.owner))
		if err != nil {
			return nil, err
		}
		updates = append(updates, eventstore.CatalogRevisionUpdate{Catalog: snapshot.Catalog, Owner: snapshot.Owner, ExpectedRevision: snapshot.Revision})
	}
	sort.Slice(updates, func(i, j int) bool {
		if updates[i].Catalog != updates[j].Catalog {
			return updates[i].Catalog < updates[j].Catalog
		}
		return updates[i].Owner < updates[j].Owner
	})
	return updates, nil
}
