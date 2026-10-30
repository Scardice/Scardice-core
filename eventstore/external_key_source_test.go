package eventstore_test

import (
	"context"

	"Scardice-core/eventstore"
)

type fixedExternalKeySource struct {
	indexID string
	rootID  string
}

func (s fixedExternalKeySource) IndexRootID(context.Context) (string, error) {
	return s.indexID, nil
}

func (fixedExternalKeySource) IndexRootMaterial(context.Context) ([]byte, error) {
	return []byte("01234567890123456789012345678901"), nil
}

func (s fixedExternalKeySource) CurrentEncryptionRoot(context.Context) (eventstore.EncryptionRoot, error) {
	return eventstore.EncryptionRoot{ID: s.rootID, Material: []byte("abcdefghijklmnopqrstuvwxyz123456")}, nil
}

func (s fixedExternalKeySource) EncryptionRoot(_ context.Context, id string) ([]byte, error) {
	if id != s.rootID {
		return nil, eventstore.ErrKeyUnavailable
	}
	return []byte("abcdefghijklmnopqrstuvwxyz123456"), nil
}
