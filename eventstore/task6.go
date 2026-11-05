package eventstore

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"
)

const (
	MaxSecretBytes          = 8 * 1024 * 1024
	MaxSecretRefBytes       = 512
	MaxSecretBatchLookups   = 100000
	secretBatchPageSize     = 200
	MaxPluginExtensionBytes = 255
	MaxPluginKeyBytes       = 1024
	MaxPluginValueBytes     = 8 * 1024 * 1024
	MaxPluginKeys           = 10000
	MaxPluginBytes          = 64 * 1024 * 1024
	MaxPluginScan           = 10000
	MaxPluginResults        = 1000
	MaxPluginResponseBytes  = 8 * 1024 * 1024

	supportedReadinessSchemaVersion uint32 = 2
)

func readinessFromDB(ctx context.Context, db *gorm.DB) (Readiness, error) {
	var row storeReadinessRow
	if err := db.WithContext(ctx).Where("singleton_id = ?", "default").First(&row).Error; err != nil {
		return Readiness{}, ErrReadinessQuarantined
	}
	r := Readiness{Mode: row.Mode, SchemaVersion: parseSchemaVersion(row.SchemaVersion), DatabaseIdentity: row.DatabaseIdentity, CompletedAt: timeOrZero(row.CompletedAt)}
	if err := validateReadinessValue(r); err != nil {
		return Readiness{}, err
	}
	return r, nil
}

func (s *GORMStore) GetReadiness(ctx context.Context) (Readiness, error) {
	if s == nil || s.db == nil || s.db.GORM() == nil {
		return Readiness{}, ErrReadinessInvalid
	}
	if ctx == nil {
		ctx = context.Background()
	}
	r, err := readinessFromDB(ctx, s.db.ReadGORM())
	if err != nil {
		return Readiness{}, err
	}
	if expected := strings.TrimSpace(s.db.databaseIdentity); expected != "" && r.DatabaseIdentity != expected {
		return Readiness{}, ErrReadinessQuarantined
	}
	return r, nil
}

// HasPersistentState is used only to select an offline migration source.
func (s *GORMStore) HasPersistentState(ctx context.Context) (bool, error) {
	if s == nil || s.db == nil || s.db.GORM() == nil {
		return false, ErrReadinessInvalid
	}
	for _, model := range schemaModels() {
		switch model.(type) {
		case *storeReadinessRow, *projectionControlRow, *eventGlobalSequenceRow:
			continue
		}
		var count int64
		if err := s.db.ReadGORM().WithContext(ctx).Model(model).Limit(1).Count(&count).Error; err != nil {
			return false, err
		}
		if count != 0 {
			return true, nil
		}
	}
	return false, nil
}

func parseSchemaVersion(v string) uint32 {
	n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}

func timeOrZero(v *time.Time) time.Time {
	if v == nil {
		return time.Time{}
	}
	return *v
}

func validateReadinessValue(r Readiness) error {
	if (r.Mode != "fresh" && r.Mode != "import") || r.SchemaVersion != supportedReadinessSchemaVersion ||
		strings.TrimSpace(r.DatabaseIdentity) == "" || (r.Mode == "import" && r.CompletedAt.IsZero()) {
		return ErrReadinessInvalid
	}
	return nil
}

func (s *GORMStore) requireReady(_ context.Context) error {
	if s == nil {
		return ErrReadinessInvalid
	}
	return s.initializationError()
}

func (s *GORMStore) SetReadiness(ctx context.Context, r Readiness) error {
	if err := validateReadinessValue(r); err != nil {
		return err
	}
	if s == nil || s.db == nil || s.db.GORM() == nil {
		return ErrReadinessInvalid
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if expected := strings.TrimSpace(s.db.databaseIdentity); expected != "" && r.DatabaseIdentity != expected {
		return ErrReadinessQuarantined
	}
	err := s.db.GORM().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var existing storeReadinessRow
		if err := locked(tx).Where("singleton_id = ?", "default").First(&existing).Error; err != nil {
			return ErrReadinessQuarantined
		}
		if existing.Mode == "import" && r.Mode != "import" {
			return ErrReadinessInvalid
		}
		var control projectionControlRow
		if err := locked(tx).Where("singleton_id = ?", "default").First(&control).Error; err != nil || control.PublicationState != "published" {
			return ErrReadinessQuarantined
		}
		return tx.Model(&storeReadinessRow{}).Where("singleton_id = ?", "default").
			Updates(map[string]any{"mode": r.Mode, "schema_version": strconv.FormatUint(uint64(r.SchemaVersion), 10), "database_identity": r.DatabaseIdentity, "completed_at": timePtr(r.CompletedAt)}).Error
	})
	if err != nil {
		return err
	}
	s.clearReadinessError()
	return nil
}

func (s *GORMStore) PutSecret(ctx context.Context, req SecretPutRequest) (SecretResolution, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.requireReady(ctx); err != nil {
		return SecretResolution{}, err
	}
	if strings.TrimSpace(req.SecretRef) == "" || len(req.SecretRef) > MaxSecretRefBytes || strings.TrimSpace(req.EndpointID) == "" || strings.TrimSpace(req.AdapterID) == "" {
		return SecretResolution{}, ErrInvalidMetadata
	}
	if len(req.Value) > MaxSecretBytes {
		return SecretResolution{}, ErrOversizeInput
	}
	var err error
	var observed adapterSecretRow
	observedFound := false
	query := rawStringQuery(s.db.GORM().WithContext(ctx), "secret_ref", req.SecretRef).Order("row_version DESC").First(&observed)
	if query.Error == nil {
		observedFound = true
	} else if !errors.Is(query.Error, gorm.ErrRecordNotFound) {
		return SecretResolution{}, ErrParticipantFailure
	}
	current := uint64(0)
	if observedFound {
		current = observed.RowVersion
		if current >= maxPersistedVersion || observed.SecretVersion >= maxPersistedVersion {
			return SecretResolution{}, ErrVersionExhausted
		}
	}
	if req.ExpectedVersion != 0 && req.ExpectedVersion != current {
		return SecretResolution{}, ErrParticipantConflict
	}
	if observedFound && (req.EndpointID != observed.EndpointID || req.AdapterID != observed.AdapterID) {
		return SecretResolution{}, ErrInvalidMetadata
	}
	version := req.SecretVersion
	if version == 0 {
		version = 1
		if observedFound {
			version, err = nextVersion(observed.SecretVersion)
			if err != nil {
				return SecretResolution{}, err
			}
		}
	} else if observedFound && version <= observed.SecretVersion {
		return SecretResolution{}, ErrParticipantConflict
	}
	if version >= maxPersistedVersion {
		return SecretResolution{}, ErrVersionExhausted
	}
	rowVersion, err := nextVersion(current)
	if err != nil {
		return SecretResolution{}, err
	}
	now := s.task5Now()
	tx := s.db.GORM().WithContext(ctx).Begin()
	if tx.Error != nil {
		return SecretResolution{}, ErrParticipantFailure
	}
	defer tx.Rollback()
	if err = s.lockParticipantPublication(ctx, tx); err != nil {
		return SecretResolution{}, err
	}
	var lockedLatest adapterSecretRow
	lockedQuery := rawStringQuery(locked(tx), "secret_ref", req.SecretRef).Order("row_version DESC").First(&lockedLatest)
	if observedFound {
		if lockedQuery.Error != nil || lockedLatest.RowVersion != observed.RowVersion ||
			lockedLatest.SecretVersion != observed.SecretVersion ||
			lockedLatest.EndpointID != observed.EndpointID || lockedLatest.AdapterID != observed.AdapterID ||
			!bytes.Equal(lockedLatest.Value, observed.Value) {
			return SecretResolution{}, ErrParticipantConflict
		}
	} else if lockedQuery.Error == nil {
		return SecretResolution{}, ErrParticipantConflict
	} else if !errors.Is(lockedQuery.Error, gorm.ErrRecordNotFound) {
		return SecretResolution{}, ErrParticipantFailure
	}
	row := adapterSecretRow{
		SecretRef: req.SecretRef, SecretVersion: version, EndpointID: req.EndpointID, AdapterID: req.AdapterID,
		AdapterType: "opaque", Value: bytes.Clone(req.Value), RowVersion: rowVersion, CreatedAt: now, UpdatedAt: now,
	}
	if err = tx.Create(&row).Error; err != nil {
		return SecretResolution{}, ErrParticipantConflict
	}
	if err = tx.Commit().Error; err != nil {
		return SecretResolution{}, ErrParticipantFailure
	}
	return SecretResolution{SecretRef: req.SecretRef, SecretVersion: version, Value: row.Value}, nil
}
func (s *GORMStore) ResolveSecret(ctx context.Context, ref string, version uint64) (SecretResolution, error) {
	return s.resolveSecret(ctx, ref, "", "", version)
}

func (s *GORMStore) ResolveSecretForOwner(ctx context.Context, endpointID, adapterID, ref string, version uint64) (SecretResolution, error) {
	if endpointID == "" || adapterID == "" {
		return SecretResolution{}, ErrNotFound
	}
	return s.resolveSecret(ctx, ref, endpointID, adapterID, version)
}

func (s *GORMStore) resolveSecret(ctx context.Context, ref, endpointID, adapterID string, version uint64) (SecretResolution, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.requireReady(ctx); err != nil {
		return SecretResolution{}, err
	}
	if ref == "" {
		return SecretResolution{}, ErrNotFound
	}
	if len(ref) > MaxSecretRefBytes {
		return SecretResolution{}, ErrInvalidMetadata
	}
	var row adapterSecretRow
	query := rawStringQuery(s.db.GORM().WithContext(ctx), "secret_ref", ref)
	if endpointID != "" {
		query = rawStringQuery(rawStringQuery(query, "endpoint_id", endpointID), "adapter_id", adapterID)
	}
	if version > 0 {
		query = query.Where("secret_version = ?", version)
	} else {
		query = query.Order("secret_version DESC")
	}
	queryErr := query.First(&row).Error
	if errors.Is(queryErr, gorm.ErrRecordNotFound) {
		return SecretResolution{}, ErrNotFound
	}
	if queryErr != nil {
		return SecretResolution{}, ErrParticipantFailure
	}
	if len(row.Value) > MaxSecretBytes {
		return SecretResolution{}, &OversizeError{Bound: "secret bytes", Limit: MaxSecretBytes, Actual: len(row.Value)}
	}
	value := row.Value
	err := s.db.GORM().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if lockErr := lockReadPublication(tx); lockErr != nil {
			return lockErr
		}
		var current adapterSecretRow
		if lockErr := rawStringQuery(lockedShared(tx), "secret_ref", row.SecretRef).Where("secret_version = ?", row.SecretVersion).Take(&current).Error; lockErr != nil {
			return ErrParticipantConflict
		}
		if current.RowVersion != row.RowVersion || current.EndpointID != row.EndpointID || current.AdapterID != row.AdapterID || !bytes.Equal(current.Value, row.Value) {
			return ErrParticipantConflict
		}
		return nil
	})
	if err != nil {
		clear(value)
		return SecretResolution{}, err
	}
	return SecretResolution{SecretRef: row.SecretRef, SecretVersion: row.SecretVersion, Value: value}, nil
}

func pluginValueUsageRows(rows []pluginKVRow) (int64, error) {
	var total int64
	for _, row := range rows {
		if len(row.Key) > MaxPluginKeyBytes {
			return 0, &OversizeError{Bound: "plugin key bytes", Limit: MaxPluginKeyBytes, Actual: len(row.Key)}
		}
		if len(row.Value) > MaxPluginValueBytes {
			return 0, &OversizeError{Bound: "plugin value bytes", Limit: MaxPluginValueBytes, Actual: len(row.Value)}
		}
		total += int64(len(row.Value))
		if total > MaxPluginBytes {
			return 0, ErrOversizeInput
		}
	}
	return total, nil
}

// validatePluginQuota checks the final namespace state while its transaction
// holds lockPluginQuota. Checking after all writes lets a batch reuse capacity
// released by deletes and overwrites regardless of key ordering.
func validatePluginQuota(tx *gorm.DB, extension string) error {
	var rows []pluginKVRow
	if err := rawStringQuery(tx, "extension_id", extension).Select("key", "value").Limit(MaxPluginKeys + 1).Find(&rows).Error; err != nil {
		return ErrParticipantFailure
	}
	if len(rows) > MaxPluginKeys {
		return &OversizeError{Bound: "plugin keys", Limit: MaxPluginKeys, Actual: len(rows)}
	}
	_, err := pluginValueUsageRows(rows)
	return err
}

func (s *GORMStore) lockMutationPublication(_ context.Context, tx *gorm.DB) error {
	if err := lockPublication(tx); err != nil {
		return err
	}
	var control projectionControlRow
	if err := locked(tx).Where("singleton_id = ?", "default").First(&control).Error; err != nil {
		return ErrParticipantFailure
	}
	if control.PublicationState != "published" {
		return ErrReadinessQuarantined
	}
	return nil
}

func (s *GORMStore) lockParticipantPublication(_ context.Context, tx *gorm.DB) error {
	return lockReadPublication(tx)
}

func lockReadPublication(tx *gorm.DB) error {
	if tx == nil {
		return ErrParticipantFailure
	}
	var readiness struct {
		SingletonID string `gorm:"column:singleton_id"`
	}
	if err := lockedShared(tx).Model(&storeReadinessRow{}).
		Select("singleton_id").
		Where("singleton_id = ?", "default").
		First(&readiness).Error; err != nil {
		return ErrParticipantFailure
	}
	var control projectionControlRow
	if err := lockedShared(tx).Where("singleton_id = ?", "default").First(&control).Error; err != nil {
		return ErrParticipantFailure
	}
	if control.PublicationState != "published" {
		return ErrReadinessQuarantined
	}
	return nil
}
func lockPublication(tx *gorm.DB) error {
	if tx.Name() == "sqlite" {
		q := tx.Exec("UPDATE store_readiness SET singleton_id = singleton_id WHERE singleton_id = ?", "default")
		if q.Error != nil || q.RowsAffected != 1 {
			return ErrParticipantFailure
		}
		return nil
	}
	var readiness struct {
		SingletonID string `gorm:"column:singleton_id"`
	}
	if err := locked(tx).Model(&storeReadinessRow{}).
		Select("singleton_id").
		Where("singleton_id = ?", "default").
		First(&readiness).Error; err != nil {
		return ErrParticipantFailure
	}
	return nil
}
func lockPluginQuota(tx *gorm.DB) error {
	return lockPublication(tx)
}

func (s *GORMStore) SetPluginKV(ctx context.Context, req PluginKVPutRequest) (PluginKVItem, error) {
	if err := s.requireReady(ctx); err != nil {
		return PluginKVItem{}, err
	}
	if req.ExtensionID == "" || len(req.ExtensionID) > MaxPluginExtensionBytes || len(req.Key) > MaxPluginKeyBytes || len(req.Value) > MaxPluginValueBytes {
		return PluginKVItem{}, ErrInvalidMetadata
	}
	namespace, err := pluginNamespaceKey(req.ExtensionID)
	if err != nil {
		return PluginKVItem{}, err
	}
	if err = s.ensurePluginRevisionHeads(ctx, req.ExtensionID, req.Key); err != nil {
		return PluginKVItem{}, err
	}
	var snapshotRows []pluginKVRow
	var keyHead, namespaceHead revisionHeadRow
	err = s.db.ReadSnapshot(ctx, func(snapshot *gorm.DB) error {
		if _, readErr := readDependencyControl(snapshot); readErr != nil {
			return readErr
		}
		keyResource := pluginKeyResource(namespace, req.Key)
		if readErr := revisionQuery(snapshot, keyResource.kind, keyResource.scope, keyResource.member).First(&keyHead).Error; readErr != nil {
			return ErrParticipantFailure
		}
		namespaceResource := pluginNamespaceResource(namespace)
		if readErr := revisionQuery(snapshot, namespaceResource.kind, namespaceResource.scope, namespaceResource.member).First(&namespaceHead).Error; readErr != nil {
			return ErrParticipantFailure
		}
		return rawStringQuery(snapshot, "extension_id", req.ExtensionID).Find(&snapshotRows).Error
	})
	if err != nil {
		return PluginKVItem{}, ErrParticipantFailure
	}
	var current uint64
	var found bool
	for _, existing := range snapshotRows {
		if existing.Key == req.Key {
			current, found = existing.RowVersion, true
			break
		}
	}
	if found != keyHead.Present {
		return PluginKVItem{}, ErrInvalidMetadata
	}
	if req.ExpectedVersion != 0 && req.ExpectedVersion != current {
		return PluginKVItem{}, ErrParticipantConflict
	}
	revisionPlan, err := s.prepareRevisionPlan(ctx, UnitOfWork{
		PluginKVReads:          []PluginKVReadExpectation{{Namespace: namespace, Key: req.Key, ExpectedRevision: keyHead.Revision, ExpectedExists: found}},
		PluginKVNamespaceReads: []PluginKVNamespaceReadExpectation{{Namespace: namespace, ExpectedRevision: namespaceHead.Revision}},
		PluginKVUpdates:        []PluginKVUpdate{{ExtensionID: req.ExtensionID, Key: req.Key}},
	})
	if err != nil {
		return PluginKVItem{}, err
	}
	tx := s.db.GORM().WithContext(ctx).Begin()
	if tx.Error != nil {
		return PluginKVItem{}, ErrParticipantFailure
	}
	defer tx.Rollback()
	if err := lockPluginQuota(tx); err != nil {
		return PluginKVItem{}, err
	}
	if err := s.lockParticipantPublication(ctx, tx); err != nil {
		return PluginKVItem{}, err
	}
	revisionStates, err := lockRevisionPlan(tx, revisionPlan)
	if err != nil {
		return PluginKVItem{}, err
	}
	var row pluginKVRow
	query := pluginQuery(locked(tx), req.ExtensionID, req.Key).First(&row)
	if errors.Is(query.Error, gorm.ErrRecordNotFound) {
		if found {
			return PluginKVItem{}, ErrParticipantConflict
		}
		current = 0
	} else if query.Error != nil {
		return PluginKVItem{}, ErrParticipantFailure
	} else if !found || row.RowVersion != current {
		return PluginKVItem{}, ErrParticipantConflict
	}
	version, err := nextVersion(current)
	if err != nil {
		return PluginKVItem{}, err
	}
	now := s.task5Now()
	row = pluginKVRow{ExtensionID: req.ExtensionID, Key: req.Key, Value: bytes.Clone(req.Value), RowVersion: version, CreatedAt: now, UpdatedAt: now}
	if current == 0 {
		query = tx.Create(&row)
	} else {
		query = pluginQuery(tx.Model(&pluginKVRow{}), req.ExtensionID, req.Key).Where("row_version = ?", current).Updates(map[string]any{"value": row.Value, "row_version": version, "updated_at": now})
	}
	if query.Error != nil || query.RowsAffected != 1 {
		return PluginKVItem{}, ErrParticipantConflict
	}
	if err = validatePluginQuota(tx, req.ExtensionID); err != nil {
		return PluginKVItem{}, err
	}
	if err = advanceRevisionPlan(tx, revisionPlan, revisionStates, now); err != nil {
		return PluginKVItem{}, err
	}
	if err = tx.Commit().Error; err != nil {
		return PluginKVItem{}, ErrParticipantFailure
	}
	return PluginKVItem{ExtensionID: req.ExtensionID, Key: req.Key, Value: bytes.Clone(req.Value), Version: version}, nil
}

func (s *GORMStore) decodePluginKVRow(_ context.Context, _ *gorm.DB, row pluginKVRow) (PluginKVItem, error) {
	if len(row.Key) > MaxPluginKeyBytes || len(row.Value) > MaxPluginValueBytes {
		return PluginKVItem{}, ErrOversizeInput
	}
	return PluginKVItem{ExtensionID: row.ExtensionID, Key: row.Key, Value: bytes.Clone(row.Value), Version: row.RowVersion}, nil
}

func (s *GORMStore) GetPluginKV(ctx context.Context, extension, key string) (PluginKVItem, error) {
	if err := s.requireReady(ctx); err != nil {
		return PluginKVItem{}, err
	}
	if len(extension) > MaxPluginExtensionBytes || len(key) > MaxPluginKeyBytes {
		return PluginKVItem{}, ErrOversizeInput
	}
	var row pluginKVRow
	err := pluginQuery(s.db.GORM().WithContext(ctx), extension, key).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return PluginKVItem{}, ErrPluginKVNotFound
	}
	if err != nil {
		return PluginKVItem{}, ErrParticipantFailure
	}
	return s.decodePluginKVRow(ctx, s.db.ReadGORM(), row)
}

func (s *GORMStore) DeletePluginKV(ctx context.Context, extension, key string, expected uint64) error {
	if err := s.requireReady(ctx); err != nil {
		return err
	}
	if extension == "" {
		return ErrInvalidMetadata
	}
	if len(extension) > MaxPluginExtensionBytes || len(key) > MaxPluginKeyBytes {
		return ErrOversizeInput
	}
	if _, err := pluginNamespaceKey(extension); err != nil {
		return err
	}
	if err := s.ensurePluginRevisionHeads(ctx, extension, key); err != nil {
		return err
	}
	revisionPlan, err := s.prepareRevisionPlan(ctx, UnitOfWork{PluginKVUpdates: []PluginKVUpdate{{ExtensionID: extension, Key: key, Deleted: true}}})
	if err != nil {
		return err
	}
	tx := s.db.GORM().WithContext(ctx).Begin()
	if tx.Error != nil {
		return ErrParticipantFailure
	}
	defer tx.Rollback()
	if err = lockPluginQuota(tx); err != nil {
		return err
	}
	if err = s.lockParticipantPublication(ctx, tx); err != nil {
		return err
	}
	revisionStates, err := lockRevisionPlan(tx, revisionPlan)
	if err != nil {
		return err
	}
	var row pluginKVRow
	err = pluginQuery(locked(tx), extension, key).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrPluginKVNotFound
	}
	if err != nil {
		return ErrParticipantFailure
	}
	if expected > 0 && expected != row.RowVersion {
		return ErrParticipantConflict
	}
	q := pluginQuery(tx, extension, key).Where("row_version = ?", row.RowVersion).Delete(&pluginKVRow{})
	if q.Error != nil || q.RowsAffected != 1 {
		return ErrParticipantConflict
	}
	if err = advanceRevisionPlan(tx, revisionPlan, revisionStates, s.task5Now()); err != nil {
		return err
	}
	if err = tx.Commit().Error; err != nil {
		return ErrParticipantFailure
	}
	return nil
}

func (s *GORMStore) ListPluginKV(ctx context.Context, req PluginKVListRequest) ([]PluginKVItem, error) {
	snapshot, err := s.ListPluginKVSnapshot(ctx, req)
	if err != nil {
		return nil, err
	}
	return snapshot.Items, nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var _ SecretRepository = (*GORMStore)(nil)
var _ SecretOwnerResolver = (*GORMStore)(nil)
var _ PluginKVRepository = (*GORMStore)(nil)
var _ ReadinessRepository = (*GORMStore)(nil)
