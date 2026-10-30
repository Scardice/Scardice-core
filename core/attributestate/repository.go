package attributestate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

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
	digest := sha256.Sum256([]byte(diceID + "\x00" + id))
	return "vault:attributes-" + hex.EncodeToString(digest[:16])
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
	return state, append([]byte(nil), secret.Plaintext...), nil
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
			loaded = append(loaded, LoadedState{State: state, Plaintext: secret.Plaintext})
		}
	}
	return loaded, nil
}

func clearSecretResolutions(secrets []eventstore.SecretResolution) {
	for index := range secrets {
		clear(secrets[index].Plaintext)
	}
}

func clearLoadedStates(states []LoadedState) {
	for index := range states {
		clear(states[index].Plaintext)
	}
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
	state, stream, secret, err := repository.prepareSnapshot(ctx, state, plaintext)
	if err != nil {
		return State{}, err
	}
	if _, err = repository.store.Commit(ctx, eventstore.UnitOfWork{
		Streams:       []eventstore.StreamAppend{stream},
		SecretUpdates: []eventstore.SecretUpdate{secret},
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
	for _, write := range writes {
		state, stream, secret, err := repository.prepareSnapshot(ctx, write.State, write.Plaintext)
		if err != nil {
			return nil, err
		}
		states = append(states, state)
		streams = append(streams, stream)
		secrets = append(secrets, secret)
	}
	if _, err := repository.store.Commit(ctx, eventstore.UnitOfWork{
		Streams: streams, SecretUpdates: secrets,
	}); err != nil {
		return nil, err
	}
	return states, nil
}

func (repository *Repository) prepareSnapshot(ctx context.Context, state State, plaintext []byte) (State, eventstore.StreamAppend, eventstore.SecretUpdate, error) {
	if len(plaintext) == 0 {
		return State{}, eventstore.StreamAppend{}, eventstore.SecretUpdate{}, ErrRepositoryUnavailable
	}
	stream := Stream(state.DiceID, state.ID)
	if stream.AggregateID == "" {
		return State{}, eventstore.StreamAppend{}, eventstore.SecretUpdate{}, ErrInvalidIdentity
	}
	if state.SecretRef == "" {
		state.SecretRef = SecretRef(state.DiceID, state.ID)
	}
	expectedVersion := state.Version
	nextVersion := expectedVersion + 1
	state.SecretVersion = nextVersion
	event := NewBaselineImportedV1(state)
	payload, err := MarshalBaselineImportedV1(event)
	if err != nil {
		return State{}, eventstore.StreamAppend{}, eventstore.SecretUpdate{}, err
	}
	eventType := EventSnapshotReplaced
	if expectedVersion == 0 {
		eventType = EventBaselineImported
	}
	newEvent, err := repository.factory.NewEvent(eventType, EventSchemaVersion, payload, eventstore.Metadata{
		SubjectKey: append([]byte(nil), state.PrivacySubjectKey...),
	})
	if err != nil {
		return State{}, eventstore.StreamAppend{}, eventstore.SecretUpdate{}, err
	}
	secret, err := repository.store.PrepareSecretUpdate(ctx, eventstore.SecretPutRequest{
		SecretRef: state.SecretRef, EndpointID: state.ID, AdapterID: AggregateType,
		SecretVersion: nextVersion, ExpectedVersion: expectedVersion, Plaintext: plaintext,
	})
	if err != nil {
		return State{}, eventstore.StreamAppend{}, eventstore.SecretUpdate{}, err
	}
	state.Version = nextVersion
	return state, eventstore.StreamAppend{
		Stream: stream, ExpectedVersion: expectedVersion, Events: []eventstore.NewEvent{newEvent},
	}, secret, nil
}
