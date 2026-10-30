package eventsourcing

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"Scardice-core/eventstore"
	"Scardice-core/projectionset"
)

// SQLiteTarget imports into one new SQLite event database. A failed target is
// never reopened for another attempt; callers must choose a new path and
// identity. Sensitive plaintext is retained only for each encryption call;
// reopen verification uses a per-attempt in-memory HMAC key.
type SQLiteTarget struct {
	path            string
	publishPath     string
	databaseConfig  eventstore.DatabaseConfig
	activate        func(context.Context, string) error
	replaceDatabase func(string, string) error

	mu                            sync.Mutex
	identity                      string
	database                      *eventstore.Database
	store                         *eventstore.GORMStore
	versions                      map[eventstore.StreamID]uint64
	seenSecrets                   map[string]struct{}
	seenPluginKV                  map[pluginKVIdentity]struct{}
	seenLogImports                map[string][sha256.Size]byte
	records                       []targetRecord
	verificationKey               []byte
	relaxedSQLiteImportDurability bool
	deferredStoryLogIndexes       bool
}

type pluginKVIdentity struct {
	extensionID string
	key         string
}

type targetRecord struct {
	manifest          ManifestRecord
	eventID           string
	commandID         string
	correlationID     string
	sensitiveDigest   [sha256.Size]byte
	logSourcePrefix   string
	logDiceID         string
	logKind           eventstore.StoryLogImportKind
	logSemanticDigest []byte
}
type pendingStoryLogImport struct {
	record         eventstore.StoryLogImportRecord
	sourcePrefix   string
	semanticDigest []byte
}

func NewSQLiteTarget(path string, keySource eventstore.KeySource) *SQLiteTarget {
	clean := filepath.Clean(path)
	return &SQLiteTarget{
		path: clean,
		databaseConfig: eventstore.DatabaseConfig{
			Type:      "sqlite",
			DSN:       clean,
			KeySource: keySource,
		},
	}
}

// NewSQLitePublicationTarget imports into candidatePath, then atomically
// replaces activePath only after readiness and semantic validation succeed.
func NewSQLitePublicationTarget(candidatePath, activePath string, keySource eventstore.KeySource) *SQLiteTarget {
	target := NewSQLiteTarget(candidatePath, keySource)
	target.publishPath = filepath.Clean(activePath)
	return target
}

func (t *SQLiteTarget) AllowsReadinessIdentityReuse() bool {
	return t != nil && t.publishPath != ""
}

// NewRemoteSQLTarget imports into a caller-provisioned unique empty database
// or schema. activate switches the operator-owned active identity only after
// readiness commits and reopen validation have succeeded.
func NewRemoteSQLTarget(config eventstore.DatabaseConfig, activate func(context.Context, string) error) *SQLiteTarget {
	return &SQLiteTarget{
		databaseConfig: config,
		activate:       activate,
	}
}

func (t *SQLiteTarget) Initialize(ctx context.Context, identity string) error {
	if t == nil || t.databaseConfig.KeySource == nil {
		return ErrTargetRequired
	}
	dbType := strings.ToLower(strings.TrimSpace(t.databaseConfig.Type))
	if dbType != "sqlite" && dbType != "mysql" && dbType != "postgres" && dbType != "postgresql" {
		return ErrTargetRequired
	}
	if dbType != "sqlite" && t.activate == nil {
		return ErrPublication
	}
	if strings.TrimSpace(t.databaseConfig.DSN) == "" {
		return ErrTargetRequired
	}
	if dbType == "sqlite" && (strings.TrimSpace(t.path) == "" || t.path == ".") {
		return ErrTargetRequired
	}
	if strings.TrimSpace(identity) == "" || strings.ContainsAny(identity, "/\\\x00") {
		return ErrTargetIdentity
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.store != nil || t.identity != "" {
		return ErrTargetIdentity
	}
	if dbType == "sqlite" {
		if err := secureDestination(DefaultFileSystem(), filepath.Dir(t.path)); err != nil {
			return err
		}
		if t.publishPath != "" {
			if t.publishPath == "." || t.publishPath == t.path || filepath.Dir(t.publishPath) != filepath.Dir(t.path) {
				return ErrTargetIdentity
			}
			if info, statErr := os.Lstat(t.publishPath); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
				return ErrTargetIdentity
			} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
				return statErr
			}
		}
		for _, candidate := range []string{t.path + "-wal", t.path + "-shm"} {
			if _, statErr := os.Lstat(candidate); statErr == nil {
				return ErrTargetIdentity
			} else if !errors.Is(statErr, os.ErrNotExist) {
				return statErr
			}
		}
		reservation, reserveErr := os.OpenFile(t.path, os.O_CREATE|os.O_EXCL|os.O_RDWR, SnapshotFileMode)
		if errors.Is(reserveErr, os.ErrExist) {
			return ErrTargetIdentity
		}
		if reserveErr != nil {
			return reserveErr
		}
		if closeErr := reservation.Close(); closeErr != nil {
			return closeErr
		}
	}
	t.identity = identity
	if err := t.openLocked(ctx); err != nil {
		t.identity = ""
		return err
	}
	readiness, err := t.store.GetReadiness(ctx)
	if err != nil || readiness.Mode != string(ModeFresh) || readiness.DatabaseIdentity != identity {
		_ = t.closeLocked()
		t.identity = ""
		if err != nil {
			return err
		}
		return ErrValidation
	}
	var count int64
	if err := t.database.GORM().WithContext(ctx).Table("domain_events").Count(&count).Error; err != nil || count != 0 {
		_ = t.closeLocked()
		t.identity = ""
		if err != nil {
			return err
		}
		return ErrValidation
	}
	importedLogs, err := t.store.ListStoryLogImports(ctx, "", "")
	for index := range importedLogs {
		clear(importedLogs[index].SemanticDigest)
	}
	if err != nil || len(importedLogs) != 0 {
		_ = t.closeLocked()
		t.identity = ""
		if err != nil {
			return err
		}
		return ErrTargetIdentity
	}
	if dbType == "sqlite" && t.publishPath != "" {
		if err := t.relaxSQLiteImportDurabilityLocked(ctx); err != nil {
			_ = t.closeLocked()
			t.identity = ""
			return err
		}
		if err := t.deferStoryLogIndexesLocked(ctx); err != nil {
			_ = t.closeLocked()
			t.identity = ""
			return err
		}
	}
	t.verificationKey = make([]byte, sha256.Size)
	if _, err := rand.Read(t.verificationKey); err != nil {
		_ = t.closeLocked()
		t.identity = ""
		return err
	}
	t.versions = make(map[eventstore.StreamID]uint64)
	t.seenSecrets = make(map[string]struct{})
	t.seenPluginKV = make(map[pluginKVIdentity]struct{})
	t.records = nil
	t.seenLogImports = make(map[string][sha256.Size]byte)
	return nil
}

func (t *SQLiteTarget) ImportBatch(ctx context.Context, records []SourceRecord) error {
	if t == nil || len(records) == 0 {
		return ErrBatchLimit
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.store == nil {
		return ErrTargetRequired
	}
	if len(records) > MaxBatchRecords {
		return ErrBatchLimit
	}

	work := eventstore.UnitOfWork{}
	streamOrder := make([]eventstore.StreamID, 0, len(records))
	streamEvents := make(map[eventstore.StreamID][]eventstore.NewEvent)
	nextVersions := make(map[eventstore.StreamID]uint64)
	newSecrets := make(map[string]struct{})
	newPluginKV := make(map[pluginKVIdentity]struct{})
	newLogImports := make(map[string][sha256.Size]byte, len(records))
	pendingLogImports := make([]pendingStoryLogImport, 0, len(records))
	pendingLogBySource := make(map[string]int, len(records))
	logCandidates := make([]pendingStoryLogImport, 0, len(records))
	defer func() {
		for index := range pendingLogImports {
			clearLegacyStoryLogImport(&pendingLogImports[index].record)
			clear(pendingLogImports[index].semanticDigest)
		}
		for identity, digest := range newLogImports {
			clear(digest[:])
			newLogImports[identity] = digest
		}
	}()
	for _, record := range records {
		if err := validateSourceRecord(record); err != nil {
			return err
		}
		switch record.RecordType {
		case RecordTypeEvent:
			stream := eventstore.StreamID{AggregateType: record.Domain, AggregateID: record.Identity}
			expected, touched := nextVersions[stream]
			if !touched {
				expected = t.versions[stream]
				streamOrder = append(streamOrder, stream)
			}
			if record.Version != expected+1 {
				return ErrValidation
			}
			streamEvents[stream] = append(streamEvents[stream], eventstore.NewEvent{
				EventType: record.Kind, SchemaVersion: record.SchemaVersion,
				Payload: append([]byte(nil), record.Payload...), Metadata: importMetadata(record),
			})
			nextVersions[stream] = record.Version
		case RecordTypeSecret:
			if _, exists := t.seenSecrets[record.Identity]; exists || !record.Sensitive {
				return ErrValidation
			}
			if _, exists := newSecrets[record.Identity]; exists {
				return ErrValidation
			}
			update, err := t.store.PrepareSecretUpdate(ctx, eventstore.SecretPutRequest{
				SecretRef: record.Identity, EndpointID: record.Kind, AdapterID: record.Domain,
				SecretVersion: record.Version, Plaintext: record.Payload,
			})
			if err != nil {
				return err
			}
			work.SecretUpdates = append(work.SecretUpdates, update)
			newSecrets[record.Identity] = struct{}{}
		case RecordTypePluginKV:
			key := pluginKVIdentity{extensionID: record.Domain, key: record.Identity}
			if _, exists := t.seenPluginKV[key]; exists || record.Version != 1 || !record.Sensitive {
				return ErrValidation
			}
			if _, exists := newPluginKV[key]; exists {
				return ErrValidation
			}
			update, err := t.store.PreparePluginKVUpdate(ctx, eventstore.PluginKVPutRequest{
				ExtensionID: record.Domain, Key: record.Identity, Value: record.Payload,
			})
			if err != nil {
				return err
			}
			work.PluginKVUpdates = append(work.PluginKVUpdates, update)
			newPluginKV[key] = struct{}{}
		case RecordTypeLogArchive:
			if !record.Sensitive || record.Version != 1 || record.SchemaVersion != 1 {
				return ErrValidation
			}
			importRecord, err := decodeLegacyStoryLogImport(record)
			if err != nil {
				return err
			}
			sourcePrefix, ok := legacyStoryLogSourcePrefix(importRecord.SourceID)
			if !ok {
				clearLegacyStoryLogImport(&importRecord)
				return ErrValidation
			}
			logCandidates = append(logCandidates, pendingStoryLogImport{record: importRecord, sourcePrefix: sourcePrefix})
		default:
			return ErrValidation
		}
	}
	if len(logCandidates) != 0 {
		importRecords := make([]eventstore.StoryLogImportRecord, len(logCandidates))
		for index := range logCandidates {
			importRecords[index] = logCandidates[index].record
		}
		semanticDigests, err := t.store.StoryLogImportSemanticDigests(ctx, importRecords)
		if err != nil {
			for index := range logCandidates {
				clearLegacyStoryLogImport(&logCandidates[index].record)
			}
			return err
		}
		defer func() {
			for index := range logCandidates {
				clearLegacyStoryLogImport(&logCandidates[index].record)
			}
			for index := range semanticDigests {
				clear(semanticDigests[index])
			}
		}()
		for index, candidate := range logCandidates {
			semanticDigest := semanticDigests[index]
			if len(semanticDigest) != sha256.Size {
				return ErrValidation
			}
			var digest [sha256.Size]byte
			copy(digest[:], semanticDigest)
			priorDigest, alreadyImported := t.seenLogImports[candidate.record.SourceID]
			batchDigest, duplicateInBatch := newLogImports[candidate.record.SourceID]
			if alreadyImported && !hmac.Equal(priorDigest[:], digest[:]) ||
				duplicateInBatch && !hmac.Equal(batchDigest[:], digest[:]) {
				clear(digest[:])
				return ErrValidation
			}
			if duplicateInBatch {
				clear(digest[:])
				continue
			}
			work.LogImports = append(work.LogImports, candidate.record)
			newLogImports[candidate.record.SourceID] = digest
			clear(digest[:])
			candidate.semanticDigest = semanticDigest
			pendingLogImports = append(pendingLogImports, candidate)
			pendingLogBySource[candidate.record.SourceID] = len(pendingLogImports) - 1
		}
	}
	for _, stream := range streamOrder {
		work.Streams = append(work.Streams, eventstore.StreamAppend{
			Stream: stream, ExpectedVersion: t.versions[stream], Events: streamEvents[stream],
		})
	}
	if len(work.Streams) != 0 || len(work.SecretUpdates) != 0 || len(work.PluginKVUpdates) != 0 || len(work.LogImports) != 0 {
		if _, err := t.store.Commit(ctx, work); err != nil {
			return err
		}
	}
	for stream, version := range nextVersions {
		t.versions[stream] = version
	}
	for identity := range newSecrets {
		t.seenSecrets[identity] = struct{}{}
	}
	for identity := range newPluginKV {
		t.seenPluginKV[identity] = struct{}{}
	}
	for identity, digest := range newLogImports {
		t.seenLogImports[identity] = digest
	}
	for _, record := range records {
		stored := targetRecord{manifest: sourceManifestRecord(record)}
		if record.RecordType == RecordTypeEvent {
			metadata := importMetadata(record)
			stored.eventID = metadata.EventID
			stored.commandID = metadata.CommandID
			stored.correlationID = metadata.CorrelationID
		}
		if record.Sensitive && record.RecordType != RecordTypeLogArchive {
			stored.sensitiveDigest = sensitiveRecordDigest(t.verificationKey, record.Payload)
		}
		if record.RecordType == RecordTypeLogArchive {
			pendingIndex, ok := pendingLogBySource[record.Identity]
			if !ok || pendingIndex < 0 || pendingIndex >= len(pendingLogImports) {
				return ErrValidation
			}
			pending := pendingLogImports[pendingIndex]
			stored.logSourcePrefix = pending.sourcePrefix
			stored.logDiceID = pending.record.DiceID
			stored.logKind = pending.record.Kind
			stored.logSemanticDigest = append([]byte(nil), pending.semanticDigest...)
		}
		t.records = append(t.records, stored)
	}
	return nil
}

func (t *SQLiteTarget) Rebuild(ctx context.Context) (eventstore.RebuildResult, error) {
	if t == nil {
		return eventstore.RebuildResult{}, ErrTargetRequired
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.store == nil {
		return eventstore.RebuildResult{}, ErrTargetRequired
	}
	return t.store.Rebuild(ctx, eventstore.RebuildRequest{ProjectorVersion: projectionset.ProjectorVersion})
}

func (t *SQLiteTarget) ProjectionManifest(ctx context.Context) ([]byte, []byte, error) {
	if t == nil {
		return nil, nil, ErrTargetRequired
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.database == nil || t.database.GORM() == nil || strings.TrimSpace(t.identity) == "" {
		return nil, nil, ErrTargetRequired
	}
	var control struct {
		ActiveGeneration string
		PublicationState string
	}
	query := t.database.GORM().WithContext(ctx)
	if err := query.Table("projection_control").Select("active_generation", "publication_state").
		Where("singleton_id = ?", "default").Take(&control).Error; err != nil {
		return nil, nil, ErrValidation
	}
	if strings.TrimSpace(control.ActiveGeneration) == "" || control.PublicationState != "published" {
		return nil, nil, ErrValidation
	}
	var rows []struct {
		ProjectionName string
		RowKey         string
		Payload        []byte
	}
	if err := query.Table("projection_read_models").Select("projection_name", "row_key", "payload").
		Where("projection_generation = ?", control.ActiveGeneration).Find(&rows).Error; err != nil {
		return nil, nil, ErrValidation
	}
	if len(rows) > MaxManifestRecords {
		return nil, nil, ErrBatchLimit
	}
	manifest := SemanticManifest{Version: 1, SourceIdentity: t.identity, Records: make([]ManifestRecord, 0, len(rows))}
	for _, row := range rows {
		digest := sha256.Sum256(row.Payload)
		manifest.Records = append(manifest.Records, ManifestRecord{
			RecordType: RecordTypeProjection, Domain: row.ProjectionName, Identity: row.RowKey,
			Kind: "read-model", SchemaVersion: 1, ContentDigest: digest[:], Size: uint64(len(row.Payload)), Version: 1,
		})
	}
	return CanonicalManifest(manifest)
}

func (t *SQLiteTarget) Reopen(ctx context.Context) error {
	if t == nil {
		return ErrTargetRequired
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.identity == "" {
		return ErrTargetRequired
	}
	if err := t.restoreStoryLogIndexesLocked(ctx); err != nil {
		return err
	}
	if err := t.restoreSQLiteDurabilityLocked(ctx); err != nil {
		return err
	}
	if err := t.closeLocked(); err != nil {
		return err
	}
	if err := t.openLocked(ctx); err != nil {
		return err
	}
	return t.store.ValidateReadiness(ctx)
}

func (t *SQLiteTarget) Manifest(ctx context.Context) (SemanticManifest, error) {
	if t == nil {
		return SemanticManifest{}, ErrTargetRequired
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.store == nil {
		return SemanticManifest{}, ErrTargetRequired
	}
	defer func() {
		clear(t.verificationKey)
		t.verificationKey = nil
	}()
	type eventKey struct {
		aggregateType string
		aggregateID   string
		version       uint64
	}
	type secretKey struct {
		ref     string
		version uint64
	}
	type pluginKey struct {
		extension string
		key       string
	}
	expectedEvents := make(map[eventKey]targetRecord)
	expectedSecrets := make(map[secretKey]targetRecord)
	expectedPluginKV := make(map[pluginKey]targetRecord)
	for _, stored := range t.records {
		record := stored.manifest
		switch record.RecordType {
		case RecordTypeEvent:
			key := eventKey{aggregateType: record.Domain, aggregateID: record.Identity, version: record.Version}
			if record.Version == 0 {
				return SemanticManifest{}, fmt.Errorf("%w: imported event has zero version domain=%s", ErrValidation, record.Domain)
			}
			if _, exists := expectedEvents[key]; exists {
				return SemanticManifest{}, fmt.Errorf("%w: duplicate imported event domain=%s version=%d", ErrValidation, record.Domain, record.Version)
			}
			expectedEvents[key] = stored
		case RecordTypeSecret:
			key := secretKey{ref: record.Identity, version: record.Version}
			if _, exists := expectedSecrets[key]; exists {
				return SemanticManifest{}, fmt.Errorf("%w: duplicate imported secret version=%d", ErrValidation, record.Version)
			}
			expectedSecrets[key] = stored
		case RecordTypePluginKV:
			key := pluginKey{extension: record.Domain, key: record.Identity}
			if _, exists := expectedPluginKV[key]; exists {
				return SemanticManifest{}, fmt.Errorf("%w: duplicate imported plugin value version=%d", ErrValidation, record.Version)
			}
			expectedPluginKV[key] = stored
		case RecordTypeLogArchive:
		default:
			return SemanticManifest{}, fmt.Errorf("%w: unsupported imported record type %q", ErrValidation, record.RecordType)
		}
	}
	if err := t.store.VisitImportVerification(ctx, eventstore.ImportVerificationVisitor{
		Event: func(actual eventstore.ImportVerificationEvent) error {
			key := eventKey{aggregateType: actual.Stream.AggregateType, aggregateID: actual.Stream.AggregateID, version: actual.StreamVersion}
			expected, ok := expectedEvents[key]
			if !ok {
				return fmt.Errorf("%w: unexpected imported event domain=%s version=%d", ErrValidation, actual.Stream.AggregateType, actual.StreamVersion)
			}
			field := ""
			switch {
			case actual.EventID != expected.eventID:
				field = "event_id"
			case actual.CommandID != expected.commandID:
				field = "command_id"
			case actual.CorrelationID != expected.correlationID:
				field = "correlation_id"
			case actual.EventType != expected.manifest.Kind:
				field = "event_type"
			case actual.SchemaVersion != expected.manifest.SchemaVersion:
				field = "schema_version"
			case actual.PayloadSize != expected.manifest.Size:
				field = "payload_size"
			case !hmac.Equal(actual.PayloadDigest[:], expected.manifest.ContentDigest):
				field = "payload_digest"
			}
			if field != "" {
				return fmt.Errorf("%w: imported event readback mismatch field=%s domain=%s version=%d", ErrValidation, field, actual.Stream.AggregateType, actual.StreamVersion)
			}
			delete(expectedEvents, key)
			return nil
		},
		Secret: func(actual eventstore.ImportVerificationSecret) error {
			key := secretKey{ref: actual.SecretRef, version: actual.SecretVersion}
			expected, ok := expectedSecrets[key]
			if !ok {
				return fmt.Errorf("%w: unexpected imported secret version=%d", ErrValidation, actual.SecretVersion)
			}
			if actual.EndpointID != expected.manifest.Kind || actual.AdapterID != expected.manifest.Domain {
				return fmt.Errorf("%w: imported secret binding mismatch version=%d", ErrValidation, actual.SecretVersion)
			}
			digest := sensitiveRecordDigest(t.verificationKey, actual.Plaintext)
			if !hmac.Equal(digest[:], expected.sensitiveDigest[:]) {
				return fmt.Errorf("%w: imported secret digest mismatch version=%d", ErrValidation, actual.SecretVersion)
			}
			delete(expectedSecrets, key)
			return nil
		},
		PluginKV: func(actual eventstore.PluginKVItem) error {
			key := pluginKey{extension: actual.ExtensionID, key: actual.Key}
			expected, ok := expectedPluginKV[key]
			if !ok {
				return fmt.Errorf("%w: unexpected imported plugin value", ErrValidation)
			}
			if actual.Version != expected.manifest.Version {
				return fmt.Errorf("%w: imported plugin value version mismatch", ErrValidation)
			}
			digest := sensitiveRecordDigest(t.verificationKey, actual.Value)
			if !hmac.Equal(digest[:], expected.sensitiveDigest[:]) {
				return fmt.Errorf("%w: imported plugin value digest mismatch", ErrValidation)
			}
			delete(expectedPluginKV, key)
			return nil
		},
	}); err != nil {
		return SemanticManifest{}, fmt.Errorf("%w: verify imported target records: %w", ErrValidation, err)
	}
	if len(expectedEvents) != 0 || len(expectedSecrets) != 0 || len(expectedPluginKV) != 0 {
		return SemanticManifest{}, fmt.Errorf(
			"%w: imported target readback incomplete events=%d secrets=%d plugin_values=%d",
			ErrValidation, len(expectedEvents), len(expectedSecrets), len(expectedPluginKV),
		)
	}
	if err := t.validateStoryLogImportReadback(ctx); err != nil {
		return SemanticManifest{}, err
	}
	manifest := SemanticManifest{Version: 1, Records: make([]ManifestRecord, 0, len(t.records))}
	for _, stored := range t.records {
		manifest.Records = append(manifest.Records, stored.manifest)
	}
	for index := range t.records {
		if t.records[index].manifest.Sensitive {
			t.records[index].manifest.Identity = ""
			clear(t.records[index].sensitiveDigest[:])
		}
		clear(t.records[index].logSemanticDigest)
		t.records[index].logSemanticDigest = nil
		t.records[index].logSourcePrefix = ""
		t.records[index].logDiceID = ""
	}
	for sourceID, digest := range t.seenLogImports {
		clear(digest[:])
		t.seenLogImports[sourceID] = digest
	}
	t.seenLogImports = nil
	t.records = nil
	t.versions = nil
	t.seenSecrets = nil
	t.seenPluginKV = nil
	return manifest, nil
}

func (t *SQLiteTarget) validateStoryLogImportReadback(ctx context.Context) error {
	type scope struct {
		sourcePrefix string
		diceID       string
	}
	expected := make(map[scope]map[string]targetRecord)
	for _, stored := range t.records {
		if stored.manifest.RecordType != RecordTypeLogArchive {
			continue
		}
		if stored.manifest.Identity == "" || stored.logSourcePrefix == "" || stored.logDiceID == "" ||
			len(stored.logSemanticDigest) != sha256.Size {
			return ErrValidation
		}
		key := scope{sourcePrefix: stored.logSourcePrefix, diceID: stored.logDiceID}
		group := expected[key]
		if group == nil {
			group = make(map[string]targetRecord)
			expected[key] = group
		}
		if prior, exists := group[stored.manifest.Identity]; exists {
			if prior.logKind != stored.logKind || !hmac.Equal(prior.logSemanticDigest, stored.logSemanticDigest) {
				return ErrValidation
			}
			continue
		}
		group[stored.manifest.Identity] = stored
	}
	for key, group := range expected {
		expectedCount := len(group)
		seen := 0
		err := t.store.VisitStoryLogImports(ctx, key.sourcePrefix, key.diceID, func(receipt eventstore.StoryLogImportReceipt) error {
			if receipt.SourceID == "" || len(receipt.SemanticDigest) != sha256.Size {
				return fmt.Errorf("%w: imported story-log receipt is incomplete", ErrValidation)
			}
			stored, ok := group[receipt.SourceID]
			if !ok {
				return fmt.Errorf("%w: imported story-log receipt is unexpected or duplicated", ErrValidation)
			}
			if receipt.Kind != stored.logKind || !hmac.Equal(receipt.SemanticDigest, stored.logSemanticDigest) {
				return fmt.Errorf("%w: imported story-log receipt digest mismatch kind=%s", ErrValidation, receipt.Kind)
			}
			switch receipt.Kind {
			case eventstore.StoryLogImportSession, eventstore.StoryLogImportEntry:
				if receipt.ResourceID == 0 {
					return fmt.Errorf("%w: imported story-log resource is missing kind=%s", ErrValidation, receipt.Kind)
				}
			case eventstore.StoryLogImportState:
				if receipt.ResourceID != 0 {
					return fmt.Errorf("%w: imported story-log state has an unexpected resource", ErrValidation)
				}
			default:
				return fmt.Errorf("%w: imported story-log kind is invalid", ErrValidation)
			}
			delete(group, receipt.SourceID)
			seen++
			return nil
		})
		if err != nil {
			return fmt.Errorf("verify imported story-log readback: %w", err)
		}
		if seen != expectedCount || len(group) != 0 {
			return fmt.Errorf("%w: imported story-log readback incomplete expected=%d actual=%d", ErrValidation, expectedCount, seen)
		}
	}
	return nil
}

func (t *SQLiteTarget) GetReadiness(ctx context.Context) (eventstore.Readiness, error) {
	if t == nil {
		return eventstore.Readiness{}, ErrTargetRequired
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.store == nil {
		return eventstore.Readiness{}, ErrTargetRequired
	}
	return t.store.GetReadiness(ctx)
}

func (t *SQLiteTarget) SetReadiness(ctx context.Context, readiness eventstore.Readiness) error {
	if t == nil {
		return ErrTargetRequired
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.store == nil {
		return ErrTargetRequired
	}
	return t.store.SetReadiness(ctx, readiness)
}

// Publish makes a validated candidate active. A plain SQLite target has no
// separate publication path, while a remote target delegates the final
// operator-owned identity switch to activate.
func (t *SQLiteTarget) Publish(ctx context.Context) error {
	if t == nil {
		return ErrTargetRequired
	}
	t.mu.Lock()
	if t.store == nil || t.identity == "" {
		t.mu.Unlock()
		return ErrTargetRequired
	}
	if t.publishPath == "" {
		activate, identity := t.activate, t.identity
		databaseType := strings.ToLower(strings.TrimSpace(t.databaseConfig.Type))
		t.mu.Unlock()
		if databaseType == "sqlite" {
			return nil
		}
		if activate == nil {
			return ErrPublication
		}
		return activate(ctx, identity)
	}
	defer t.mu.Unlock()
	if strings.ToLower(strings.TrimSpace(t.databaseConfig.Type)) != "sqlite" {
		return ErrPublication
	}
	if err := t.closeLocked(); err != nil {
		return err
	}
	for _, sidecar := range []string{t.path + "-wal", t.path + "-shm"} {
		if _, err := os.Lstat(sidecar); err == nil {
			return ErrPublication
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	err := syncSQLiteDatabaseFile(t.path)
	if err != nil {
		return err
	}
	parentPath := filepath.Dir(t.publishPath)

	backupPath := t.publishPath + ".pre-import-" + t.identity
	hadActive := false
	if active, statErr := os.Lstat(t.publishPath); statErr == nil {
		if active.Mode()&os.ModeSymlink != 0 || !active.Mode().IsRegular() {
			return ErrPublication
		}
		hadActive = true
		if _, backupErr := os.Lstat(backupPath); !errors.Is(backupErr, os.ErrNotExist) {
			return ErrPublication
		}
		if err = os.Link(t.publishPath, backupPath); err != nil {
			return err
		}
		if err = syncSQLiteDatabaseFile(backupPath); err != nil {
			_ = os.Remove(backupPath)
			return err
		}
		if err = syncSQLiteDatabaseParent(parentPath); err != nil {
			_ = os.Remove(backupPath)
			return err
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	replace := t.replaceDatabase
	if replace == nil {
		replace = replaceSQLiteDatabase
	}
	rollback := func(publicationErr error) error {
		_ = t.closeLocked()
		var rollbackErr error
		if hadActive {
			rollbackErr = replace(backupPath, t.publishPath)
		} else if removeErr := os.Remove(t.publishPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			rollbackErr = removeErr
		}
		rollbackErr = errors.Join(rollbackErr, syncSQLiteDatabaseParent(parentPath))
		return errors.Join(publicationErr, rollbackErr)
	}
	if err = replace(t.path, t.publishPath); err != nil {
		if hadActive {
			err = errors.Join(err, os.Remove(backupPath), syncSQLiteDatabaseParent(parentPath))
		}
		return err
	}
	if err = syncSQLiteDatabaseParent(parentPath); err != nil {
		return rollback(err)
	}
	candidatePath := t.path
	t.path = t.publishPath
	t.databaseConfig.DSN = t.publishPath
	if err = t.openLocked(ctx); err != nil {
		t.path = candidatePath
		t.databaseConfig.DSN = candidatePath
		return rollback(err)
	}
	if hadActive {
		_ = os.Remove(backupPath)
		_ = syncSQLiteDatabaseParent(parentPath)
	}
	return nil
}

func syncSQLiteDatabaseFile(path string) error {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	return errors.Join(file.Sync(), file.Close())
}

func (t *SQLiteTarget) Close() error {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closeLocked()
}

func (t *SQLiteTarget) openLocked(ctx context.Context) error {
	dbType := strings.ToLower(strings.TrimSpace(t.databaseConfig.Type))
	if dbType == "sqlite" {
		if info, statErr := os.Lstat(t.path); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
			return ErrTargetIdentity
		} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			return statErr
		}
	}
	config := t.databaseConfig
	config.DatabaseIdentity = t.identity
	database, err := eventstore.OpenDatabase(ctx, config)
	if err != nil {
		return err
	}
	t.database = database
	t.store = eventstore.NewStore(database, projectionset.StoreOptions()...)
	if err := t.store.ValidateReadiness(ctx); err != nil {
		_ = t.closeLocked()
		return err
	}
	if dbType == "sqlite" {
		if err := secureSQLiteTargetFiles(t.path); err != nil {
			_ = t.closeLocked()
			return err
		}
	}
	return nil
}

var deferredStoryLogIndexDDL = []struct {
	drop   string
	create string
}{
	{
		drop:   "DROP INDEX IF EXISTS ix_story_log_entries_scope_session",
		create: "CREATE INDEX IF NOT EXISTS ix_story_log_entries_scope_session ON story_log_entries(scope_hmac, session_id)",
	},
	{
		drop:   "DROP INDEX IF EXISTS ix_story_log_entries_raw",
		create: "CREATE INDEX IF NOT EXISTS ix_story_log_entries_raw ON story_log_entries(scope_hmac, session_id, raw_msg_hmac)",
	},
	{
		drop:   "DROP INDEX IF EXISTS ix_story_log_entries_owner",
		create: "CREATE INDEX IF NOT EXISTS ix_story_log_entries_owner ON story_log_entries(owner_hmac)",
	},
	{
		drop:   "DROP INDEX IF EXISTS ix_story_log_import_owner",
		create: "CREATE INDEX IF NOT EXISTS ix_story_log_import_owner ON story_log_imports(owner_hmac, scope_hmac)",
	},
	{
		drop:   "DROP INDEX IF EXISTS ix_story_log_import_dice_identity",
		create: "CREATE INDEX IF NOT EXISTS ix_story_log_import_dice_identity ON story_log_imports(dice_hmac, identity_hmac)",
	},
}

func (t *SQLiteTarget) deferStoryLogIndexesLocked(ctx context.Context) error {
	if t.database == nil {
		return ErrTargetRequired
	}
	sqlDB := t.database.SQLDB()
	for _, index := range deferredStoryLogIndexDDL {
		if _, err := sqlDB.ExecContext(ctx, index.drop); err != nil {
			return fmt.Errorf("defer candidate story-log index: %w", err)
		}
	}
	t.deferredStoryLogIndexes = true
	return nil
}

func (t *SQLiteTarget) restoreStoryLogIndexesLocked(ctx context.Context) error {
	if !t.deferredStoryLogIndexes {
		return nil
	}
	if t.database == nil {
		return ErrTargetRequired
	}
	sqlDB := t.database.SQLDB()
	for _, index := range deferredStoryLogIndexDDL {
		if _, err := sqlDB.ExecContext(ctx, index.create); err != nil {
			return fmt.Errorf("restore candidate story-log index: %w", err)
		}
	}
	t.deferredStoryLogIndexes = false
	return nil
}

func (t *SQLiteTarget) relaxSQLiteImportDurabilityLocked(ctx context.Context) error {
	if t.database == nil {
		return ErrTargetRequired
	}
	sqlDB := t.database.SQLDB()
	for _, statement := range []string{
		"PRAGMA synchronous = OFF",
		"PRAGMA temp_store = MEMORY",
		"PRAGMA cache_size = -65536",
	} {
		if _, err := sqlDB.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	var synchronous int
	if err := sqlDB.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous); err != nil {
		return err
	}
	if synchronous != 0 {
		return fmt.Errorf("candidate SQLite synchronous mode is not OFF: %w", ErrValidation)
	}
	t.relaxedSQLiteImportDurability = true
	return nil
}

func (t *SQLiteTarget) restoreSQLiteDurabilityLocked(ctx context.Context) error {
	if !t.relaxedSQLiteImportDurability {
		return nil
	}
	if t.database == nil {
		return ErrTargetRequired
	}
	sqlDB := t.database.SQLDB()
	if _, err := sqlDB.ExecContext(ctx, "PRAGMA synchronous = FULL"); err != nil {
		return err
	}
	var busy, logFrames, checkpointed int
	if err := sqlDB.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &logFrames, &checkpointed); err != nil {
		return err
	}
	if busy != 0 || logFrames != checkpointed {
		return fmt.Errorf("candidate SQLite checkpoint is incomplete: %w", ErrValidation)
	}
	var synchronous int
	if err := sqlDB.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous); err != nil {
		return err
	}
	if synchronous != 2 {
		return fmt.Errorf("candidate SQLite synchronous mode is not FULL: %w", ErrValidation)
	}
	t.relaxedSQLiteImportDurability = false
	return nil
}

func (t *SQLiteTarget) closeLocked() error {
	store := t.store
	t.store = nil
	t.database = nil
	t.relaxedSQLiteImportDurability = false
	t.deferredStoryLogIndexes = false
	if store == nil {
		return nil
	}
	return store.Close()
}

func importMetadata(record SourceRecord) eventstore.Metadata {
	hash := sha256.New()
	_, _ = fmt.Fprintf(hash, "%s\x00%s\x00%s\x00%s\x00%d\x00%d", record.RecordType, record.Domain, record.Identity, record.Kind, record.SchemaVersion, record.Version)
	_, _ = hash.Write(record.ContentDigest)
	id := "import-" + hex.EncodeToString(hash.Sum(nil))
	commandID := id + "-command"
	correlationID := id + "-correlation"
	if record.EventID != "" {
		id = record.EventID
		commandID = record.CommandID
		correlationID = record.CorrelationID
	}
	return eventstore.Metadata{
		EventID: id, CommandID: commandID, CorrelationID: correlationID,
		Producer: "eventsourcing-importer", OccurredAtUnixNanoSet: true,
	}
}

func sensitiveRecordDigest(key, plaintext []byte) [sha256.Size]byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(plaintext)
	var digest [sha256.Size]byte
	copy(digest[:], mac.Sum(nil))
	return digest
}

func secureSQLiteTargetFiles(path string) error {
	for _, candidate := range []string{path, path + "-wal", path + "-shm"} {
		info, err := os.Lstat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return ErrTargetIdentity
		}
		if err := os.Chmod(candidate, SnapshotFileMode); err != nil {
			return err
		}
	}
	return nil
}
