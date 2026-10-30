package managerstate

import (
	"context"

	"Scardice-core/eventstore"
)

type secretStore interface {
	eventstore.Store
	PrepareSecretUpdate(ctx context.Context, request eventstore.SecretPutRequest) (eventstore.SecretUpdate, error)
	ResolveSecret(ctx context.Context, secretRef string, version uint64) (eventstore.SecretResolution, error)
}

type Repository struct {
	store   secretStore
	factory eventstore.EventFactory
}

func NewRepository(store eventstore.Store) (*Repository, error) {
	secrets, ok := store.(secretStore)
	if !ok || secrets == nil {
		return nil, ErrRepositoryUnavailable
	}
	return &Repository{store: secrets, factory: eventstore.EventFactory{Clock: eventstore.SystemClock{}, IDs: eventstore.UUIDGenerator{}}}, nil
}

func (repository *Repository) Load(ctx context.Context) (State, Auth, error) {
	if repository == nil || repository.store == nil {
		return State{}, Auth{}, ErrRepositoryUnavailable
	}
	state, err := ReadProjected(ctx, repository.store)
	if err != nil {
		return State{}, Auth{}, err
	}
	secret, err := repository.store.ResolveSecret(ctx, state.AuthSecretRef, state.AuthSecretVersion)
	if err != nil {
		return State{}, Auth{}, err
	}
	auth, err := DecodeAuth(secret.Plaintext)
	if err != nil {
		return State{}, Auth{}, err
	}
	return state, auth, nil
}

func (repository *Repository) Save(ctx context.Context, state State, public PublicConfig, auth Auth) (State, error) {
	prepared, err := repository.PrepareSave(ctx, state, public, auth)
	if err != nil {
		return State{}, err
	}
	if _, err = repository.store.Commit(ctx, eventstore.UnitOfWork{
		Streams:       []eventstore.StreamAppend{prepared.Stream},
		SecretUpdates: []eventstore.SecretUpdate{prepared.Secret},
	}); err != nil {
		return State{}, err
	}
	return prepared.State, nil
}

type PreparedSave struct {
	State  State
	Stream eventstore.StreamAppend
	Secret eventstore.SecretUpdate
}

// PrepareSave creates a manager snapshot append and its encrypted auth update
// without publishing either. It is intended for composition into a larger
// atomic UnitOfWork.
func (repository *Repository) PrepareSave(ctx context.Context, state State, public PublicConfig, auth Auth) (PreparedSave, error) {
	if repository == nil || repository.store == nil {
		return PreparedSave{}, ErrRepositoryUnavailable
	}
	plaintext, err := MarshalAuth(auth)
	if err != nil {
		return PreparedSave{}, err
	}
	nextVersion := state.Version + 1
	snapshot := NewSnapshotV1(public, nextVersion)
	payload, err := MarshalSnapshotV1(snapshot)
	if err != nil {
		return PreparedSave{}, err
	}
	eventType := EventSnapshotReplaced
	if state.Version == 0 {
		eventType = EventBaselineImported
	}
	event, err := repository.factory.NewEvent(eventType, EventSchemaVersion, payload, eventstore.Metadata{})
	if err != nil {
		return PreparedSave{}, err
	}
	secret, err := repository.store.PrepareSecretUpdate(ctx, eventstore.SecretPutRequest{
		SecretRef: AuthSecretRef, EndpointID: AggregateID, AdapterID: AggregateType,
		SecretVersion: nextVersion, ExpectedVersion: state.Version, Plaintext: plaintext,
	})
	if err != nil {
		return PreparedSave{}, err
	}
	next, err := Apply(state, snapshot)
	if err != nil {
		return PreparedSave{}, err
	}
	return PreparedSave{
		State: next,
		Stream: eventstore.StreamAppend{
			Stream: Stream(), ExpectedVersion: state.Version, Events: []eventstore.NewEvent{event},
		},
		Secret: secret,
	}, nil
}
