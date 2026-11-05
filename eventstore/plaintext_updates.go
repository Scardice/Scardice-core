package eventstore

import (
	"context"
	"strings"
)

// PrepareSecretUpdate encodes one plaintext secret for inclusion in a larger
// atomic UnitOfWork. Commit still owns version and publication checks.
func (s *GORMStore) PrepareSecretUpdate(ctx context.Context, req SecretPutRequest) (SecretUpdate, error) {
	if err := s.requireReady(ctx); err != nil {
		return SecretUpdate{}, err
	}
	if strings.TrimSpace(req.SecretRef) == "" || len(req.SecretRef) > MaxSecretRefBytes || strings.TrimSpace(req.EndpointID) == "" || strings.TrimSpace(req.AdapterID) == "" {
		return SecretUpdate{}, ErrInvalidMetadata
	}
	if len(req.Value) > MaxSecretBytes {
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
	return SecretUpdate{
		SecretRef: req.SecretRef, ExpectedVersion: req.ExpectedVersion, Version: rowVersion,
		EndpointID: req.EndpointID, AdapterID: req.AdapterID, SecretVersion: secretVersion,
		Value: append([]byte(nil), req.Value...), ValueSet: true, UpdatedAt: s.task5Now(),
	}, nil
}

// PreparePluginKVUpdate encodes one plaintext plugin value for inclusion in a
// larger atomic UnitOfWork. It is intended for callers that already own the
// optimistic version sequence.
func (s *GORMStore) PreparePluginKVUpdate(ctx context.Context, req PluginKVPutRequest) (PluginKVUpdate, error) {
	if err := s.requireReady(ctx); err != nil {
		return PluginKVUpdate{}, err
	}
	if req.ExtensionID == "" || len(req.ExtensionID) > MaxPluginExtensionBytes || len(req.Key) > MaxPluginKeyBytes || len(req.Value) > MaxPluginValueBytes {
		return PluginKVUpdate{}, ErrOversizeInput
	}
	version, err := nextVersion(req.ExpectedVersion)
	if err != nil {
		return PluginKVUpdate{}, err
	}
	return PluginKVUpdate{
		ExtensionID: req.ExtensionID, Key: req.Key, ExpectedVersion: req.ExpectedVersion, Version: version,
		Value: append([]byte(nil), req.Value...), UpdatedAt: s.task5Now(),
	}, nil
}
