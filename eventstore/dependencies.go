package eventstore

import (
	"context"
	"errors"
	"sort"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	revisionKindPluginKey       = "plugin-key"
	revisionKindPluginNamespace = "plugin-namespace"
	revisionKindCatalog         = "catalog"
)

var errDependencyHeadMissing = errors.New("eventstore: dependency head missing")

type DependencySnapshot struct {
	ProjectionGeneration string
}

type ProjectionReadExpectation struct {
	Generation string
}
type StreamReadExpectation struct {
	Stream          StreamID
	ExpectedVersion uint64
}

type StreamSnapshot struct {
	Stream   StreamID
	Version  uint64
	Events   []Envelope
	Snapshot DependencySnapshot
}

type PluginKVReadExpectation struct {
	Namespace        string
	Key              string
	ExpectedRevision uint64
	ExpectedExists   bool
}

type PluginKVNamespaceReadExpectation struct {
	Namespace        string
	ExpectedRevision uint64
}

type PluginKVLookupSnapshot struct {
	Item              PluginKVItem
	Found             bool
	Namespace         string
	Key               string
	KeyRevision       uint64
	NamespaceRevision uint64
	Snapshot          DependencySnapshot
}

type PluginKVListSnapshot struct {
	Items             []PluginKVItem
	Namespace         string
	NamespaceRevision uint64
	Snapshot          DependencySnapshot
}
type CatalogReadExpectation struct {
	Catalog          string
	Owner            string
	ExpectedRevision uint64
}

type CatalogRevisionUpdate struct {
	Catalog          string
	Owner            string
	ExpectedRevision uint64
}

type CatalogRevisionSnapshot struct {
	Catalog  string
	Owner    string
	Revision uint64
	Snapshot DependencySnapshot
}

type ProjectionLookupSnapshot struct {
	Row           ProjectionRow
	Found         bool
	Stream        StreamID
	StreamVersion uint64
	Snapshot      DependencySnapshot
}

type CatalogProjectionListRequest struct {
	Catalog                 string
	Owner                   string
	ProjectionName          string
	RowKeyPrefix            string
	RowKeyStart             string
	RowKeyEnd               string
	AfterRowKey             string
	Limit                   int
	ExpectedCatalogRevision *uint64
	ExpectedSnapshot        *DependencySnapshot
}

type CatalogProjectionListSnapshot struct {
	Rows            []ProjectionRow
	Catalog         string
	Owner           string
	CatalogRevision uint64
	Snapshot        DependencySnapshot
	NextRowKey      string
	Done            bool
}

type StreamSnapshotRepository interface {
	LoadStreamSnapshot(ctx context.Context, stream StreamID, afterVersion uint64) (StreamSnapshot, error)
}

type ProjectionDependencyRepository interface {
	ReadProjectionDependency(ctx context.Context, projectionName, rowKey string, stream StreamID) (ProjectionLookupSnapshot, error)
	ListCatalogProjectionSnapshot(ctx context.Context, request CatalogProjectionListRequest) (CatalogProjectionListSnapshot, error)
}

type PluginKVSnapshotRepository interface {
	LookupPluginKVSnapshot(ctx context.Context, extension, key string) (PluginKVLookupSnapshot, error)
	ListPluginKVSnapshot(ctx context.Context, request PluginKVListRequest) (PluginKVListSnapshot, error)
}

type CatalogRevisionRepository interface {
	ReadCatalogRevision(ctx context.Context, catalog, owner string) (CatalogRevisionSnapshot, error)
}

type revisionResourceKey struct {
	kind   string
	scope  string
	member string
}

type revisionPlanItem struct {
	key                revisionResourceKey
	lookup             revisionLookup
	expectedSet        bool
	expectedRevision   uint64
	expectedPresentSet bool
	expectedPresent    bool
	write              bool
	nextPresent        bool
}

type revisionLockState struct {
	row revisionHeadRow
}

type streamPlanItem struct {
	stream   StreamID
	expected uint64
	write    bool
}

func dependencySnapshot(control projectionControlRow) DependencySnapshot {
	return DependencySnapshot{ProjectionGeneration: control.ActiveGeneration}
}

func readDependencyControl(tx *gorm.DB) (projectionControlRow, error) {
	return readPublishedProjectionControl(tx)
}

func lockedShared(db *gorm.DB) *gorm.DB {
	if db != nil && db.Name() != "sqlite" {
		return db.Clauses(clause.Locking{Strength: "SHARE"})
	}
	return db
}

func copyDigest(value []byte) []byte {
	if value == nil {
		return nil
	}
	return append([]byte(nil), value...)
}

func pluginKeyResource(namespace, key string) revisionResourceKey {
	return revisionResourceKey{kind: revisionKindPluginKey, scope: namespace, member: key}
}

func pluginNamespaceResource(namespace string) revisionResourceKey {
	return revisionResourceKey{kind: revisionKindPluginNamespace, scope: namespace}
}

func catalogResource(catalog, owner string) revisionResourceKey {
	return revisionResourceKey{kind: revisionKindCatalog, scope: owner, member: catalog}
}

func revisionRow(key revisionResourceKey, revision uint64, present bool, now time.Time) revisionHeadRow {
	return revisionHeadRow{Kind: key.kind, Scope: key.scope, Member: key.member, Revision: revision, Present: present, UpdatedAt: now}
}

func revisionKeyLess(a, b revisionResourceKey) bool {
	if a.kind != b.kind {
		return a.kind < b.kind
	}
	if a.scope != b.scope {
		return a.scope < b.scope
	}
	return a.member < b.member
}

func pluginNamespaceKey(extension string) (string, error) {
	if extension == "" || len(extension) > MaxPluginExtensionBytes {
		return "", ErrInvalidMetadata
	}
	return extension, nil
}

func catalogOwner(catalog, owner string) (string, error) {
	if catalog == "" || len(catalog) > 255 || owner == "" {
		return "", ErrInvalidMetadata
	}
	return owner, nil
}

func (s *GORMStore) withRevisionMaterialization(ctx context.Context, materialize func(*gorm.DB) error) error {
	if s == nil || s.db == nil || s.db.GORM() == nil {
		return ErrParticipantFailure
	}
	tx := s.db.GORM().WithContext(ctx).Begin()
	if tx.Error != nil {
		return ErrParticipantFailure
	}
	defer tx.Rollback()
	if err := s.lockMutationPublication(ctx, tx); err != nil {
		return err
	}
	if err := materialize(tx); err != nil {
		return err
	}

	if err := tx.Commit().Error; err != nil {
		return ErrParticipantFailure
	}
	return nil
}

func (s *GORMStore) materializeRevisionHead(tx *gorm.DB, key revisionResourceKey, revision uint64, present bool) error {
	lookup := revisionLookupFor(key)
	var existing revisionHeadRow
	err := lookup.query(tx).Select("id").Take(&existing).Error
	if err == nil {
		return nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrParticipantFailure
	}
	row := revisionRow(key, revision, present, s.task5Now())
	row.LookupDigest = lookup.digest
	if err := tx.Create(&row).Error; err != nil {
		return ErrParticipantFailure
	}
	return nil
}

func (s *GORMStore) revisionHeadExists(ctx context.Context, key revisionResourceKey) (bool, error) {
	if s == nil || s.db == nil || s.db.ReadGORM() == nil {
		return false, ErrParticipantFailure
	}
	var row revisionHeadRow
	err := revisionQuery(s.db.ReadGORM().WithContext(ctx).Select("kind"), key.kind, key.scope, key.member).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, nil
	}
	if err != nil {
		return false, ErrParticipantFailure
	}
	return true, nil
}

func (s *GORMStore) ensurePluginRevisionHeads(ctx context.Context, extension, key string) error {
	keyResource, namespaceResource := pluginKeyResource(extension, key), pluginNamespaceResource(extension)
	keyExists, err := s.revisionHeadExists(ctx, keyResource)
	if err != nil {
		return err
	}
	namespaceExists, err := s.revisionHeadExists(ctx, namespaceResource)
	if err != nil || (keyExists && namespaceExists) {
		return err
	}
	return s.withRevisionMaterialization(ctx, func(tx *gorm.DB) error {
		var count int64
		if err := pluginQuery(tx.Model(&pluginKVRow{}), extension, key).Count(&count).Error; err != nil {
			return ErrParticipantFailure
		}
		if err := s.materializeRevisionHead(tx, namespaceResource, 0, true); err != nil {
			return err
		}
		return s.materializeRevisionHead(tx, keyResource, 0, count != 0)
	})
}

func (s *GORMStore) ensurePluginNamespaceRevisionHead(ctx context.Context, namespace string) error {
	resource := pluginNamespaceResource(namespace)
	exists, err := s.revisionHeadExists(ctx, resource)
	if err != nil || exists {
		return err
	}
	return s.withRevisionMaterialization(ctx, func(tx *gorm.DB) error {
		return s.materializeRevisionHead(tx, resource, 0, true)
	})
}

func (s *GORMStore) ensureCatalogRevisionHead(ctx context.Context, catalog, owner string) error {
	resource := catalogResource(catalog, owner)
	exists, err := s.revisionHeadExists(ctx, resource)
	if err != nil || exists {
		return err
	}
	return s.withRevisionMaterialization(ctx, func(tx *gorm.DB) error {
		return s.materializeRevisionHead(tx, resource, 0, true)
	})
}
func (s *GORMStore) ensureStreamHead(ctx context.Context, stream StreamID) error {
	if stream.AggregateType == "" || stream.AggregateID == "" {
		return ErrInvalidEvent
	}
	if s == nil || s.db == nil || s.db.GORM() == nil {
		return ErrParticipantFailure
	}
	tx := s.db.GORM().WithContext(ctx).Begin()
	if tx.Error != nil {
		return ErrParticipantFailure
	}
	defer tx.Rollback()
	if err := s.lockMutationPublication(ctx, tx); err != nil {
		return err
	}
	head := aggregateHeadRow{AggregateType: stream.AggregateType, AggregateID: stream.AggregateID, UpdatedAt: s.task5Now()}
	if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&head).Error; err != nil {
		return ErrParticipantFailure
	}

	if err := tx.Commit().Error; err != nil {
		return ErrParticipantFailure
	}
	return nil
}

func domainRowsToEnvelopes(stream StreamID, rows []domainEventRow) ([]Envelope, error) {
	envelopes := make([]Envelope, 0, len(rows))
	for _, row := range rows {
		var checksum EventChecksum
		if len(row.Checksum) != len(checksum) {
			return nil, ErrChecksumMismatch
		}
		copy(checksum[:], row.Checksum)
		envelope := Envelope{
			Stream: stream, StreamVersion: row.AggregateVersion, GlobalPosition: row.GlobalPosition,
			EventID: row.EventID, EventType: row.EventType, SchemaVersion: row.SchemaVersion,
			Payload:  copyProjectionBytes(row.Payload),
			Metadata: Metadata{EventID: row.EventID, CommandID: row.CommandID, CorrelationID: row.CorrelationID, CausationID: row.CausationID, PrincipalID: row.PrincipalID, Producer: row.Producer, OccurredAtUnixNanoUTC: row.OccurredAtUnixNanoUTC, OccurredAtUnixNanoSet: true},
			Checksum: checksum,
		}
		verified, err := verifyEnvelopeChecksum(envelope)
		if err != nil {
			return nil, err
		}
		envelopes = append(envelopes, verified)
	}
	return envelopes, nil
}

func (s *GORMStore) readStreamSnapshot(ctx context.Context, stream StreamID, afterVersion uint64) (StreamSnapshot, error) {
	var result StreamSnapshot
	err := s.db.ReadSnapshot(ctx, func(tx *gorm.DB) error {
		control, err := readDependencyControl(tx)
		if err != nil {
			return err
		}
		var head aggregateHeadRow
		if err = tx.Where("aggregate_type = ? AND aggregate_id = ?", stream.AggregateType, stream.AggregateID).First(&head).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return errDependencyHeadMissing
			}
			return ErrParticipantFailure
		}
		var rows []domainEventRow
		if err = tx.Where("aggregate_type = ? AND aggregate_id = ? AND aggregate_version >= ?", stream.AggregateType, stream.AggregateID, afterVersion).Order("aggregate_version ASC").Find(&rows).Error; err != nil {
			return ErrParticipantFailure
		}
		events, err := domainRowsToEnvelopes(stream, rows)
		if err != nil {
			return err
		}
		result = StreamSnapshot{Stream: stream, Version: head.CurrentVersion, Events: events, Snapshot: dependencySnapshot(control)}
		return nil
	})
	return result, err
}

func (s *GORMStore) LoadStreamSnapshot(ctx context.Context, stream StreamID, afterVersion uint64) (StreamSnapshot, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s == nil || s.db == nil || s.db.GORM() == nil {
		return StreamSnapshot{}, ErrParticipantFailure
	}
	if stream.AggregateType == "" || stream.AggregateID == "" {
		return StreamSnapshot{}, ErrInvalidEvent
	}
	if err := s.requireReady(ctx); err != nil {
		return StreamSnapshot{}, err
	}
	result, err := s.readStreamSnapshot(ctx, stream, afterVersion)
	if !errors.Is(err, errDependencyHeadMissing) {
		return result, err
	}
	if err = s.ensureStreamHead(ctx, stream); err != nil {
		return StreamSnapshot{}, err
	}
	return s.readStreamSnapshot(ctx, stream, afterVersion)
}

func (s *GORMStore) readProjectionDependency(ctx context.Context, projectionName, rowKey string, stream StreamID) (ProjectionLookupSnapshot, error) {
	result := ProjectionLookupSnapshot{Stream: stream}
	err := s.db.ReadSnapshot(ctx, func(tx *gorm.DB) error {
		control, readErr := readDependencyControl(tx)
		if readErr != nil {
			return readErr
		}
		var head aggregateHeadRow
		if readErr = tx.Where("aggregate_type = ? AND aggregate_id = ?", stream.AggregateType, stream.AggregateID).First(&head).Error; readErr != nil {
			if errors.Is(readErr, gorm.ErrRecordNotFound) {
				return errDependencyHeadMissing
			}
			return ErrParticipantFailure
		}
		var row projectionReadModelRow
		readErr = tx.Where("projection_generation = ? AND projection_name = ? AND row_key = ?", control.ActiveGeneration, projectionName, rowKey).First(&row).Error
		if readErr != nil && !errors.Is(readErr, gorm.ErrRecordNotFound) {
			return ErrParticipantFailure
		}
		result.StreamVersion = head.CurrentVersion
		result.Snapshot = dependencySnapshot(control)
		if readErr == nil {
			result.Found = true
			result.Row = ProjectionRow{
				ProjectionGeneration: row.ProjectionGeneration,
				ProjectionName:       row.ProjectionName,
				RowKey:               row.RowKey,
				Payload:              projectionPayload(row),
				UpdatedAt:            row.UpdatedAt,
			}
		}
		return nil
	})
	return result, err
}

func (s *GORMStore) ReadProjectionDependency(ctx context.Context, projectionName, rowKey string, stream StreamID) (ProjectionLookupSnapshot, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s == nil || s.db == nil || s.db.GORM() == nil || projectionName == "" || rowKey == "" || stream.AggregateType == "" || stream.AggregateID == "" {
		return ProjectionLookupSnapshot{}, ErrInvalidMetadata
	}
	if err := s.requireReady(ctx); err != nil {
		return ProjectionLookupSnapshot{}, err
	}
	result, err := s.readProjectionDependency(ctx, projectionName, rowKey, stream)
	if !errors.Is(err, errDependencyHeadMissing) {
		return result, err
	}
	if err = s.ensureStreamHead(ctx, stream); err != nil {
		return ProjectionLookupSnapshot{}, err
	}
	return s.readProjectionDependency(ctx, projectionName, rowKey, stream)
}

func (s *GORMStore) ListCatalogProjectionSnapshot(ctx context.Context, request CatalogProjectionListRequest) (CatalogProjectionListSnapshot, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.requireReady(ctx); err != nil {
		return CatalogProjectionListSnapshot{}, err
	}
	pageRequest := ProjectionPageRequest{
		ProjectionName: request.ProjectionName,
		RowKeyPrefix:   request.RowKeyPrefix,
		RowKeyStart:    request.RowKeyStart,
		RowKeyEnd:      request.RowKeyEnd,
		Limit:          request.Limit,
	}
	if err := validateProjectionPageRequest(pageRequest); err != nil {
		return CatalogProjectionListSnapshot{}, err
	}
	if request.AfterRowKey != "" && (request.ExpectedCatalogRevision == nil || request.ExpectedSnapshot == nil) {
		return CatalogProjectionListSnapshot{}, ErrProjectionInvariant
	}
	if request.ExpectedSnapshot != nil && request.ExpectedSnapshot.ProjectionGeneration == "" {
		return CatalogProjectionListSnapshot{}, ErrProjectionInvariant
	}
	pageRequest.AfterRowKey = request.AfterRowKey
	owner, err := catalogOwner(request.Catalog, request.Owner)
	if err != nil {
		return CatalogProjectionListSnapshot{}, err
	}
	if err = s.ensureCatalogRevisionHead(ctx, request.Catalog, owner); err != nil {
		return CatalogProjectionListSnapshot{}, err
	}
	resource := catalogResource(request.Catalog, owner)
	var rows []projectionReadModelRow
	result := CatalogProjectionListSnapshot{Catalog: request.Catalog, Owner: owner}
	err = s.db.ReadSnapshot(ctx, func(tx *gorm.DB) error {
		control, readErr := readDependencyControl(tx)
		if readErr != nil {
			return readErr
		}
		var catalogHead revisionHeadRow
		if readErr = revisionQuery(tx, resource.kind, resource.scope, resource.member).First(&catalogHead).Error; readErr != nil {
			return ErrParticipantFailure
		}
		snapshot := projectionSnapshot(control)
		currentDependencySnapshot := dependencySnapshot(control)
		if request.ExpectedCatalogRevision != nil && catalogHead.Revision != *request.ExpectedCatalogRevision {
			return ErrParticipantConflict
		}
		if request.ExpectedSnapshot != nil && currentDependencySnapshot != *request.ExpectedSnapshot {
			return ErrParticipantConflict
		}
		if readErr = projectionPageQuery(tx, snapshot, pageRequest).Find(&rows).Error; readErr != nil {
			return ErrParticipantFailure
		}
		for _, row := range rows {
			if row.ProjectionGeneration != snapshot.Generation || row.ProjectionName != request.ProjectionName || row.RowKey == "" {
				return ErrProjectionInvariant
			}
		}
		result.CatalogRevision = catalogHead.Revision
		result.Snapshot = currentDependencySnapshot
		return nil
	})
	if err != nil {
		return CatalogProjectionListSnapshot{}, err
	}
	result.NextRowKey = request.AfterRowKey
	result.Done = len(rows) == 0
	result.Rows = make([]ProjectionRow, 0, len(rows))
	for _, row := range rows {
		result.Rows = append(result.Rows, ProjectionRow{
			ProjectionGeneration: row.ProjectionGeneration,
			ProjectionName:       row.ProjectionName,
			RowKey:               row.RowKey,
			Payload:              projectionPayload(row),
			UpdatedAt:            row.UpdatedAt,
		})
	}
	if len(rows) != 0 {
		result.NextRowKey = rows[len(rows)-1].RowKey
	}
	return result, nil
}

func (s *GORMStore) LookupPluginKVSnapshot(ctx context.Context, extension, key string) (PluginKVLookupSnapshot, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.requireReady(ctx); err != nil {
		return PluginKVLookupSnapshot{}, err
	}
	if extension == "" {
		return PluginKVLookupSnapshot{}, ErrInvalidMetadata
	}
	if len(extension) > MaxPluginExtensionBytes || len(key) > MaxPluginKeyBytes {
		return PluginKVLookupSnapshot{}, ErrOversizeInput
	}
	namespace, err := pluginNamespaceKey(extension)
	if err != nil {
		return PluginKVLookupSnapshot{}, err
	}
	if err = s.ensurePluginRevisionHeads(ctx, extension, key); err != nil {
		return PluginKVLookupSnapshot{}, err
	}
	var row pluginKVRow
	var found bool
	result := PluginKVLookupSnapshot{Namespace: namespace, Key: key}
	err = s.db.ReadSnapshot(ctx, func(tx *gorm.DB) error {
		control, readErr := readDependencyControl(tx)
		if readErr != nil {
			return readErr
		}
		var keyHead, namespaceHead revisionHeadRow
		if readErr = revisionQuery(tx, revisionKindPluginKey, namespace, key).First(&keyHead).Error; readErr != nil {
			return ErrParticipantFailure
		}
		if readErr = revisionQuery(tx, revisionKindPluginNamespace, namespace, "").First(&namespaceHead).Error; readErr != nil {
			return ErrParticipantFailure
		}
		queryErr := pluginQuery(tx, extension, key).First(&row).Error
		if queryErr != nil && !errors.Is(queryErr, gorm.ErrRecordNotFound) {
			return ErrParticipantFailure
		}
		found = queryErr == nil
		if found != keyHead.Present {
			return ErrInvalidMetadata
		}
		result.Found = found
		result.KeyRevision = keyHead.Revision
		result.NamespaceRevision = namespaceHead.Revision
		result.Snapshot = dependencySnapshot(control)
		return nil
	})
	if err != nil {
		return PluginKVLookupSnapshot{}, err
	}
	if !found {
		return result, nil
	}
	item, err := s.decodePluginKVRow(ctx, s.db.ReadGORM(), row)
	if err != nil {
		return PluginKVLookupSnapshot{}, err
	}
	if item.Key != key {
		return PluginKVLookupSnapshot{}, ErrInvalidMetadata
	}
	result.Item = item
	return result, nil
}

func (s *GORMStore) ListPluginKVSnapshot(ctx context.Context, req PluginKVListRequest) (PluginKVListSnapshot, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.requireReady(ctx); err != nil {
		return PluginKVListSnapshot{}, err
	}
	if req.ExtensionID == "" {
		return PluginKVListSnapshot{}, ErrInvalidMetadata
	}
	if len(req.ExtensionID) > MaxPluginExtensionBytes || len(req.Prefix) > MaxPluginKeyBytes {
		return PluginKVListSnapshot{}, ErrOversizeInput
	}
	limit := req.Limit
	if limit <= 0 || limit > MaxPluginResults {
		limit = MaxPluginResults
	}
	namespace, err := pluginNamespaceKey(req.ExtensionID)
	if err != nil {
		return PluginKVListSnapshot{}, err
	}
	if err = s.ensurePluginNamespaceRevisionHead(ctx, namespace); err != nil {
		return PluginKVListSnapshot{}, err
	}
	var rows []pluginKVRow
	result := PluginKVListSnapshot{Namespace: namespace}
	err = s.db.ReadSnapshot(ctx, func(tx *gorm.DB) error {
		control, readErr := readDependencyControl(tx)
		if readErr != nil {
			return readErr
		}
		var namespaceHead revisionHeadRow
		resource := pluginNamespaceResource(namespace)
		if readErr = revisionQuery(tx, resource.kind, resource.scope, resource.member).First(&namespaceHead).Error; readErr != nil {
			return ErrParticipantFailure
		}
		if readErr = orderPluginKeys(rawStringQuery(tx, "extension_id", req.ExtensionID)).Limit(MaxPluginScan + 1).Find(&rows).Error; readErr != nil {
			return ErrParticipantFailure
		}
		if len(rows) > MaxPluginScan {
			return ErrOversizeInput
		}
		result.NamespaceRevision = namespaceHead.Revision
		result.Snapshot = dependencySnapshot(control)
		return nil
	})
	if err != nil {
		return PluginKVListSnapshot{}, err
	}
	items := make([]PluginKVItem, 0, minInt(limit, len(rows)))
	responseBytes := 0
	for _, row := range rows {
		item, decodeErr := s.decodePluginKVRow(ctx, s.db.ReadGORM(), row)
		if decodeErr != nil {
			return PluginKVListSnapshot{}, decodeErr
		}
		if req.Prefix != "" && len(item.Key) >= len(req.Prefix) && item.Key[:len(req.Prefix)] != req.Prefix {
			continue
		}
		if req.Prefix != "" && len(item.Key) < len(req.Prefix) {
			continue
		}
		responseBytes += len(item.Key) + len(item.Value)
		if responseBytes > MaxPluginResponseBytes {
			return PluginKVListSnapshot{}, ErrOversizeInput
		}
		items = append(items, item)
		if len(items) >= limit {
			break
		}
	}
	result.Items = items
	return result, nil
}

func (s *GORMStore) ReadCatalogRevision(ctx context.Context, catalog, owner string) (CatalogRevisionSnapshot, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.requireReady(ctx); err != nil {
		return CatalogRevisionSnapshot{}, err
	}
	owner, err := catalogOwner(catalog, owner)
	if err != nil {
		return CatalogRevisionSnapshot{}, err
	}
	if err = s.ensureCatalogRevisionHead(ctx, catalog, owner); err != nil {
		return CatalogRevisionSnapshot{}, err
	}
	resource := catalogResource(catalog, owner)
	result := CatalogRevisionSnapshot{Catalog: catalog, Owner: owner}
	err = s.db.ReadSnapshot(ctx, func(tx *gorm.DB) error {
		control, readErr := readDependencyControl(tx)
		if readErr != nil {
			return readErr
		}
		var head revisionHeadRow
		if readErr = revisionQuery(tx, resource.kind, resource.scope, resource.member).First(&head).Error; readErr != nil {
			return ErrParticipantFailure
		}
		result.Revision = head.Revision
		result.Snapshot = dependencySnapshot(control)
		return nil
	})
	return result, err
}

func mergeRevisionExpectation(items map[revisionResourceKey]*revisionPlanItem, key revisionResourceKey, revision uint64, present *bool, write bool, nextPresent bool) error {
	item, ok := items[key]
	if !ok {
		item = &revisionPlanItem{key: key}
		items[key] = item
	}
	if item.expectedSet && item.expectedRevision != revision {
		return ErrParticipantConflict
	}
	item.expectedSet = true
	item.expectedRevision = revision
	if present != nil {
		if item.expectedPresentSet && item.expectedPresent != *present {
			return ErrParticipantConflict
		}
		item.expectedPresentSet = true
		item.expectedPresent = *present
	}
	if write {
		if item.write && item.nextPresent != nextPresent {
			return ErrParticipantConflict
		}
		item.write = true
		item.nextPresent = nextPresent
	}
	return nil
}

func mergeRevisionWriter(items map[revisionResourceKey]*revisionPlanItem, key revisionResourceKey, nextPresent bool) error {
	item, ok := items[key]
	if !ok {
		item = &revisionPlanItem{key: key}
		items[key] = item
	}
	if item.write && item.nextPresent != nextPresent {
		return ErrParticipantConflict
	}
	item.write = true
	item.nextPresent = nextPresent
	return nil
}

func (s *GORMStore) prepareRevisionPlan(ctx context.Context, work UnitOfWork) ([]revisionPlanItem, error) {
	items := make(map[revisionResourceKey]*revisionPlanItem)
	for _, read := range work.PluginKVReads {
		present := read.ExpectedExists
		if err := mergeRevisionExpectation(items, pluginKeyResource(read.Namespace, read.Key), read.ExpectedRevision, &present, false, false); err != nil {
			return nil, err
		}
	}
	for _, read := range work.PluginKVNamespaceReads {
		if err := mergeRevisionExpectation(items, pluginNamespaceResource(read.Namespace), read.ExpectedRevision, nil, false, false); err != nil {
			return nil, err
		}
	}
	for _, update := range work.PluginKVUpdates {
		namespace, err := pluginNamespaceKey(update.ExtensionID)
		if err != nil {
			return nil, err
		}
		if err := s.ensurePluginRevisionHeads(ctx, update.ExtensionID, update.Key); err != nil {
			return nil, err
		}
		if err := mergeRevisionWriter(items, pluginKeyResource(namespace, update.Key), !update.Deleted); err != nil {
			return nil, err
		}
		if err := mergeRevisionWriter(items, pluginNamespaceResource(namespace), true); err != nil {
			return nil, err
		}
	}
	for _, read := range work.CatalogReads {
		owner, err := catalogOwner(read.Catalog, read.Owner)
		if err != nil {
			return nil, err
		}
		if err := s.ensureCatalogRevisionHead(ctx, read.Catalog, owner); err != nil {
			return nil, err
		}
		if err := mergeRevisionExpectation(items, catalogResource(read.Catalog, owner), read.ExpectedRevision, nil, false, false); err != nil {
			return nil, err
		}
	}
	for _, update := range work.CatalogUpdates {
		owner, err := catalogOwner(update.Catalog, update.Owner)
		if err != nil {
			return nil, err
		}
		if err := s.ensureCatalogRevisionHead(ctx, update.Catalog, owner); err != nil {
			return nil, err
		}
		if err := mergeRevisionExpectation(items, catalogResource(update.Catalog, owner), update.ExpectedRevision, nil, true, true); err != nil {
			return nil, err
		}
	}
	plan := make([]revisionPlanItem, 0, len(items))
	for _, item := range items {
		item.lookup = revisionLookupFor(item.key)
		plan = append(plan, *item)
	}
	sort.Slice(plan, func(i, j int) bool { return revisionKeyLess(plan[i].key, plan[j].key) })
	return plan, nil
}

func lockRevisionPlan(tx *gorm.DB, plan []revisionPlanItem) (map[revisionResourceKey]revisionLockState, error) {
	states := make(map[revisionResourceKey]revisionLockState, len(plan))
	conflicts := make([]ParticipantConflict, 0)
	for _, item := range plan {
		var row revisionHeadRow
		query := lockedShared(tx)
		if item.write {
			query = locked(tx)
		}
		err := item.lookup.query(query).First(&row).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			conflicts = append(conflicts, ParticipantConflict{Table: tableRevisionHeads, Key: "<redacted>", ExpectedVersion: item.expectedRevision, CurrentVersion: 0})
			continue
		}
		if err != nil {
			return nil, ErrParticipantFailure
		}
		states[item.key] = revisionLockState{row: row}
		if (item.expectedSet && row.Revision != item.expectedRevision) ||
			(item.expectedPresentSet && row.Present != item.expectedPresent) {
			conflicts = append(conflicts, ParticipantConflict{Table: tableRevisionHeads, Key: "<redacted>", ExpectedVersion: item.expectedRevision, CurrentVersion: row.Revision})
		}
	}
	if len(conflicts) != 0 {
		return nil, &ParticipantConflictError{Conflicts: conflicts}
	}
	return states, nil
}

func advanceRevisionPlan(tx *gorm.DB, plan []revisionPlanItem, states map[revisionResourceKey]revisionLockState, now time.Time) error {
	for _, item := range plan {
		if !item.write {
			continue
		}
		state, ok := states[item.key]
		if !ok {
			return ErrParticipantFailure
		}
		next, err := nextVersion(state.row.Revision)
		if err != nil {
			return err
		}
		q := tx.Model(&revisionHeadRow{}).Where("id = ? AND revision = ?", state.row.ID, state.row.Revision).
			Updates(map[string]any{"revision": next, "present": item.nextPresent, "updated_at": now})
		if q.Error != nil {
			return ErrParticipantFailure
		}
		if q.RowsAffected != 1 {
			return &ParticipantConflictError{Conflicts: []ParticipantConflict{{Table: tableRevisionHeads, Key: "<redacted>", ExpectedVersion: state.row.Revision, CurrentVersion: state.row.Revision}}}
		}
	}
	return nil
}

func buildStreamPlan(work UnitOfWork) ([]streamPlanItem, error) {
	items := make(map[StreamID]streamPlanItem, len(work.StreamReads)+len(work.Streams))
	for _, read := range work.StreamReads {
		if existing, ok := items[read.Stream]; ok && existing.expected != read.ExpectedVersion {
			return nil, ErrConflict
		}
		items[read.Stream] = streamPlanItem{stream: read.Stream, expected: read.ExpectedVersion}
	}
	for _, appendStream := range work.Streams {
		if existing, ok := items[appendStream.Stream]; ok && existing.expected != appendStream.ExpectedVersion {
			return nil, ErrConflict
		}
		items[appendStream.Stream] = streamPlanItem{stream: appendStream.Stream, expected: appendStream.ExpectedVersion, write: true}
	}
	plan := make([]streamPlanItem, 0, len(items))
	for _, item := range items {
		plan = append(plan, item)
	}
	sort.Slice(plan, func(i, j int) bool { return streamLess(plan[i].stream, plan[j].stream) })
	return plan, nil
}

func lockStreamPlan(tx *gorm.DB, plan []streamPlanItem, now time.Time) (map[StreamID]uint64, error) {
	states := make(map[StreamID]uint64, len(plan))
	conflicts := make([]StreamConflict, 0)
	for _, item := range plan {
		var head aggregateHeadRow
		query := lockedShared(tx)
		if item.write {
			query = locked(tx)
		}
		q := query.Where("aggregate_type = ? AND aggregate_id = ?", item.stream.AggregateType, item.stream.AggregateID).First(&head)
		if errors.Is(q.Error, gorm.ErrRecordNotFound) && item.write {
			head = aggregateHeadRow{AggregateType: item.stream.AggregateType, AggregateID: item.stream.AggregateID, UpdatedAt: now}
			if q = tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&head); q.Error != nil {
				return nil, ErrParticipantFailure
			}
			if q.RowsAffected == 0 {
				if err := locked(tx).Where("aggregate_type = ? AND aggregate_id = ?", item.stream.AggregateType, item.stream.AggregateID).First(&head).Error; err != nil {
					return nil, ErrParticipantFailure
				}
			}
		} else if errors.Is(q.Error, gorm.ErrRecordNotFound) {
			conflicts = append(conflicts, StreamConflict{Stream: item.stream, ExpectedVersion: item.expected, CurrentVersion: 0})
			continue
		} else if q.Error != nil {
			return nil, ErrParticipantFailure
		}
		states[item.stream] = head.CurrentVersion
		if head.CurrentVersion != item.expected {
			conflicts = append(conflicts, StreamConflict{Stream: item.stream, ExpectedVersion: item.expected, CurrentVersion: head.CurrentVersion})
		}
	}
	if len(conflicts) != 0 {
		return nil, &ConflictError{Conflicts: conflicts}
	}
	return states, nil
}

func validateProjectionReads(control projectionControlRow, reads []ProjectionReadExpectation) error {
	for _, read := range reads {
		if control.ActiveGeneration != read.Generation {
			return &ParticipantConflictError{Conflicts: []ParticipantConflict{{Table: tableProjectionControl, Key: "<redacted>"}}}
		}
	}
	return nil
}

var _ StreamSnapshotRepository = (*GORMStore)(nil)
var _ ProjectionDependencyRepository = (*GORMStore)(nil)
var _ PluginKVSnapshotRepository = (*GORMStore)(nil)
var _ CatalogRevisionRepository = (*GORMStore)(nil)
