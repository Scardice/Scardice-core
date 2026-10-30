package eventstore

import (
	"context"
	"strings"
)

// PrepareSecretUpdate encrypts one plaintext secret for inclusion in a larger
// atomic UnitOfWork. Commit still owns version and publication checks.
func (s *GORMStore) PrepareSecretUpdate(ctx context.Context, req SecretPutRequest) (SecretUpdate, error) {
	if err := s.requireReady(ctx); err != nil {
		return SecretUpdate{}, err
	}
	if strings.TrimSpace(req.SecretRef) == "" || strings.TrimSpace(req.EndpointID) == "" || strings.TrimSpace(req.AdapterID) == "" {
		return SecretUpdate{}, ErrInvalidMetadata
	}
	if len(req.Plaintext) > MaxSecretBytes {
		return SecretUpdate{}, ErrOversizeInput
	}
	rowVersion, err := nextVersion(req.ExpectedVersion)
	if err != nil {
		return SecretUpdate{}, err
	}
	secretVersion := req.SecretVersion
	if secretVersion == 0 {
		secretVersion = rowVersion
	}
	if secretVersion >= maxPersistedVersion {
		return SecretUpdate{}, ErrVersionExhausted
	}
	root, err := keySourceCurrent(ctx, s.keySource)
	if err != nil {
		return SecretUpdate{}, err
	}
	ciphertext, nonce, keyID, err := a6SealWithRoot(root, "adapter-secret/v1", req.SecretRef, req.EndpointID+"/"+req.AdapterID, secretVersion, req.Plaintext)
	if err != nil {
		return SecretUpdate{}, err
	}
	return SecretUpdate{
		SecretRef: req.SecretRef, ExpectedVersion: req.ExpectedVersion, Version: rowVersion,
		EndpointID: req.EndpointID, AdapterID: req.AdapterID, SecretVersion: secretVersion,
		Ciphertext: ciphertext, Nonce: nonce, EncryptionKeyID: keyID, UpdatedAt: s.task5Now(),
	}, nil
}

// PreparePluginKVUpdate encrypts one plaintext plugin value for inclusion in a
// larger atomic UnitOfWork. It is intended for callers that already own the
// optimistic version sequence.
func (s *GORMStore) PreparePluginKVUpdate(ctx context.Context, req PluginKVPutRequest) (PluginKVUpdate, error) {
	if err := s.requireReady(ctx); err != nil {
		return PluginKVUpdate{}, err
	}
	if req.ExtensionID == "" || len(req.ExtensionID) > MaxPluginExtensionBytes || len(req.Key) > MaxPluginKeyBytes || len(req.Value) > MaxPluginValueBytes {
		return PluginKVUpdate{}, ErrOversizeInput
	}
	index, err := a6HMAC(ctx, s.keySource, "plugin-key-index/v1", req.ExtensionID, req.Key)
	if err != nil {
		return PluginKVUpdate{}, err
	}
	version, err := nextVersion(req.ExpectedVersion)
	if err != nil {
		return PluginKVUpdate{}, err
	}
	root, err := keySourceCurrent(ctx, s.keySource)
	if err != nil {
		return PluginKVUpdate{}, err
	}
	keyCipher, keyNonce, keyID, err := a6SealWithRoot(root, "plugin-kv-key/v1", string(index), req.ExtensionID, version, []byte(req.Key))
	if err != nil {
		return PluginKVUpdate{}, err
	}
	valueCipher, valueNonce, valueKeyID, err := a6SealWithRoot(root, "plugin-kv-value/v1", string(index), req.ExtensionID, version, req.Value)
	if err != nil || valueKeyID != keyID {
		return PluginKVUpdate{}, ErrEncryptionUnavailable
	}
	return PluginKVUpdate{
		ExtensionID: req.ExtensionID, KeyHMAC: index, ExpectedVersion: req.ExpectedVersion, Version: version,
		KeyCiphertext: keyCipher, KeyNonce: keyNonce, ValueCiphertext: valueCipher, ValueNonce: valueNonce,
		EncryptionKeyID: keyID, ValueSize: int64(len(req.Value)), UpdatedAt: s.task5Now(),
	}, nil
}
