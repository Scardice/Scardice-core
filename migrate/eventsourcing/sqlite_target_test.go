package eventsourcing

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"Scardice-core/core/groupstate"
	"Scardice-core/eventstore"
)

type sqliteTargetKeySource struct{}

func (sqliteTargetKeySource) IndexRootID(context.Context) (string, error) {
	return "index-v1", nil
}
func (sqliteTargetKeySource) IndexRootMaterial(context.Context) ([]byte, error) {
	return []byte("01234567890123456789012345678901"), nil
}
func (sqliteTargetKeySource) CurrentEncryptionRoot(context.Context) (eventstore.EncryptionRoot, error) {
	return eventstore.EncryptionRoot{ID: "root-v1", Material: []byte("abcdefghijklmnopqrstuvwxyz123456")}, nil
}
func (sqliteTargetKeySource) EncryptionRoot(context.Context, string) ([]byte, error) {
	return []byte("abcdefghijklmnopqrstuvwxyz123456"), nil
}

func TestSQLiteTargetImportsRebuildsAndVerifiesReopenedEvents(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "target.db")
	target := NewSQLiteTarget(path, sqliteTargetKeySource{})
	payload, marshalErr := json.Marshal(groupstate.NewGroupCreatedV1("dice-1", "QQ-Group:1", "group", 1))
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	stream := groupstate.GroupStream("dice-1", "QQ-Group:1")
	record := validSourceRecord(stream.AggregateType, stream.AggregateID, string(groupstate.EventGroupCreated), payload)
	record.SchemaVersion = groupstate.GroupEventSchemaVersion
	secret := []byte("legacy-access-token")
	pluginKey := "private-key"
	pluginValue := []byte("private-plugin-value")
	secretRecord := SourceRecord{
		RecordType: RecordTypeSecret, Domain: "onebot", Identity: "secret://endpoint-1/token", Kind: "endpoint-1",
		SchemaVersion: 1, Version: 1, Sensitive: true, Payload: secret, Size: uint64(len(secret)),
	}
	pluginRecord := SourceRecord{
		RecordType: RecordTypePluginKV, Domain: "extension-1", Identity: pluginKey, Kind: "value",
		SchemaVersion: 1, Version: 1, Sensitive: true, Payload: pluginValue, Size: uint64(len(pluginValue)),
	}
	if err := target.Initialize(ctx, "target-1"); err != nil {
		t.Fatal(err)
	}
	if err := target.ImportBatch(ctx, []SourceRecord{record, secretRecord, pluginRecord}); err != nil {
		t.Fatal(err)
	}
	if _, err := target.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	if err := target.Reopen(ctx); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != SnapshotFileMode {
		t.Fatalf("target mode = %v", info.Mode().Perm())
	}
	manifest, err := target.Manifest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Records) != 3 {
		t.Fatalf("manifest = %#v", manifest)
	}
	eventFound := false
	for _, item := range manifest.Records {
		if item.RecordType == RecordTypeEvent {
			eventFound = bytes.Equal(item.ContentDigest, record.ContentDigest) && item.Version == 1
		} else if len(item.ContentDigest) != 0 {
			t.Fatalf("sensitive digest persisted: %#v", item)
		}
	}
	if !eventFound {
		t.Fatalf("event missing from manifest: %#v", manifest)
	}
	for _, candidate := range []string{path, path + "-wal", path + "-shm"} {
		raw, readErr := os.ReadFile(candidate)
		if errors.Is(readErr, os.ErrNotExist) {
			continue
		}
		if readErr != nil {
			t.Fatal(readErr)
		}
		for _, plaintext := range [][]byte{secret, []byte(pluginKey), pluginValue} {
			if bytes.Contains(raw, plaintext) {
				t.Fatalf("%s contains sensitive plaintext %q", candidate, plaintext)
			}
		}
	}
	readiness, err := target.GetReadiness(ctx)
	if err != nil || readiness.Mode != "fresh" || readiness.DatabaseIdentity != "target-1" {
		t.Fatalf("readiness = %#v, err = %v", readiness, err)
	}
}

func TestSQLiteTargetPreservesEventMetadataAndReportsReadbackField(t *testing.T) {
	ctx := context.Background()
	target := NewSQLiteTarget(filepath.Join(t.TempDir(), "target.db"), sqliteTargetKeySource{})
	if err := target.Initialize(ctx, "metadata-target"); err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	record := validSourceRecord("metadata-test", "aggregate-1", "metadata.created", []byte(`{"ok":true}`))
	record.EventID = "event-preserved"
	record.CommandID = "command-preserved"
	record.CorrelationID = "correlation-preserved"
	if err := target.ImportBatch(ctx, []SourceRecord{record}); err != nil {
		t.Fatal(err)
	}
	if err := target.Reopen(ctx); err != nil {
		t.Fatal(err)
	}
	events, err := target.store.Load(ctx, eventstore.StreamID{AggregateType: record.Domain, AggregateID: record.Identity}, 1)
	if err != nil || len(events) != 1 {
		t.Fatalf("load imported event = %#v, err=%v", events, err)
	}
	if metadata := events[0].Metadata; metadata.EventID != record.EventID ||
		metadata.CommandID != record.CommandID || metadata.CorrelationID != record.CorrelationID {
		t.Fatalf("imported metadata = %#v", metadata)
	}

	target.records[0].commandID = "different-command"
	_, err = target.Manifest(ctx)
	if !errors.Is(err, ErrValidation) || !strings.Contains(err.Error(), "field=command_id") {
		t.Fatalf("metadata mismatch error = %v", err)
	}
}

func TestSQLiteTargetImportsEmptyPluginKey(t *testing.T) {
	ctx := context.Background()
	target := NewSQLiteTarget(filepath.Join(t.TempDir(), "target.db"), sqliteTargetKeySource{})
	if err := target.Initialize(ctx, "empty-plugin-key"); err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	value := []byte("[object Object]")
	record := SourceRecord{
		RecordType: RecordTypePluginKV, Domain: "legacy-extension", Kind: "value",
		SchemaVersion: 1, Version: 1, Sensitive: true, Payload: value, Size: uint64(len(value)),
	}
	if err := target.ImportBatch(ctx, []SourceRecord{record}); err != nil {
		t.Fatal(err)
	}
	item, err := target.store.GetPluginKV(ctx, record.Domain, "")
	if err != nil || item.Key != "" || !bytes.Equal(item.Value, value) {
		t.Fatalf("imported plugin item = %#v, err=%v", item, err)
	}
}

func TestSQLiteTargetRejectsExistingOrReusedTarget(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "target.db")
	first := NewSQLiteTarget(path, sqliteTargetKeySource{})
	if err := first.Initialize(ctx, "target-1"); err != nil {
		t.Fatal(err)
	}
	if err := first.Initialize(ctx, "target-1"); !errors.Is(err, ErrTargetIdentity) {
		t.Fatalf("same target retry err = %v", err)
	}
	second := NewSQLiteTarget(path, sqliteTargetKeySource{})
	if err := second.Initialize(ctx, "target-2"); !errors.Is(err, ErrTargetIdentity) {
		t.Fatalf("existing target err = %v", err)
	}
}

func TestSQLiteTargetRejectsWholeBatchWhenSecretConflicts(t *testing.T) {
	ctx := context.Background()
	target := NewSQLiteTarget(filepath.Join(t.TempDir(), "target.db"), sqliteTargetKeySource{})
	if err := target.Initialize(ctx, "target-1"); err != nil {
		t.Fatal(err)
	}
	secret := SourceRecord{
		RecordType: RecordTypeSecret, Domain: "onebot", Identity: "secret://endpoint-1/token", Kind: "endpoint-1",
		SchemaVersion: 1, Version: 1, Sensitive: true, Payload: []byte("first"), Size: uint64(len("first")),
	}
	if err := target.ImportBatch(ctx, []SourceRecord{secret}); err != nil {
		t.Fatal(err)
	}
	payload, marshalErr := json.Marshal(groupstate.NewGroupCreatedV1("dice-1", "QQ-Group:1", "group", 1))
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	stream := groupstate.GroupStream("dice-1", "QQ-Group:1")
	eventRecord := validSourceRecord(stream.AggregateType, stream.AggregateID, string(groupstate.EventGroupCreated), payload)
	eventRecord.SchemaVersion = groupstate.GroupEventSchemaVersion
	conflicting := secret
	conflicting.Payload = []byte("second")
	conflicting.Size = uint64(len(conflicting.Payload))
	if err := target.ImportBatch(ctx, []SourceRecord{eventRecord, conflicting}); !errors.Is(err, ErrValidation) {
		t.Fatalf("conflicting batch err = %v", err)
	}
	if _, err := target.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	if err := target.Reopen(ctx); err != nil {
		t.Fatal(err)
	}
	manifest, err := target.Manifest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Records) != 1 || manifest.Records[0].RecordType != RecordTypeSecret {
		t.Fatalf("partial batch persisted: %#v", manifest)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteTargetRejectsTamperedPersistedEvent(t *testing.T) {
	ctx := context.Background()
	target := NewSQLiteTarget(filepath.Join(t.TempDir(), "target.db"), sqliteTargetKeySource{})
	if err := target.Initialize(ctx, "target-1"); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(groupstate.NewGroupCreatedV1("dice-1", "QQ-Group:1", "group", 1))
	if err != nil {
		t.Fatal(err)
	}
	stream := groupstate.GroupStream("dice-1", "QQ-Group:1")
	record := validSourceRecord(stream.AggregateType, stream.AggregateID, string(groupstate.EventGroupCreated), payload)
	record.SchemaVersion = groupstate.GroupEventSchemaVersion
	if err := target.ImportBatch(ctx, []SourceRecord{record}); err != nil {
		t.Fatal(err)
	}
	if _, err := target.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	if err := target.Reopen(ctx); err != nil {
		t.Fatal(err)
	}
	if err := target.database.GORM().WithContext(ctx).Table("domain_events").Where("aggregate_type = ? AND aggregate_id = ?", stream.AggregateType, stream.AggregateID).Update("payload", []byte(`{"tampered":true}`)).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := target.Manifest(ctx); !errors.Is(err, ErrValidation) {
		t.Fatalf("tampered manifest err = %v", err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestImporterRunsAgainstRealSQLiteTargetWithoutChangingCurrentReadiness(t *testing.T) {
	ctx := context.Background()
	payload, marshalErr := json.Marshal(groupstate.NewGroupCreatedV1("dice-1", "QQ-Group:1", "group", 1))
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	stream := groupstate.GroupStream("dice-1", "QQ-Group:1")
	eventRecord := validSourceRecord(stream.AggregateType, stream.AggregateID, string(groupstate.EventGroupCreated), payload)
	eventRecord.SchemaVersion = groupstate.GroupEventSchemaVersion
	source := &sourceFake{inventory: SourceInventory{
		Kind: SourceKindLegacy, Identity: "legacy-1", LegacyOwnershipComplete: true,
		Metadata: SourceMetadata{Identity: "legacy-1"},
		Records: []SourceRecord{
			eventRecord,
			{
				RecordType: RecordTypeSecret, Domain: "onebot", Identity: "secret://endpoint-1/token", Kind: "endpoint-1",
				SchemaVersion: 1, Version: 1, Sensitive: true, Payload: []byte("source-secret"), Size: uint64(len("source-secret")),
			},
		},
	}}
	current := &readinessFake{value: eventstore.Readiness{Mode: "fresh", SchemaVersion: 1, DatabaseIdentity: "current", IndexRootID: "current-index"}}
	target := NewSQLiteTarget(filepath.Join(t.TempDir(), "target.db"), sqliteTargetKeySource{})
	result, runErr := NewImporter(ImporterOptions{
		Readiness: current, Source: source, Target: target,
		SnapshotRoot: filepath.Join(t.TempDir(), "snapshot"), TargetIdentity: "target-1",
	}).Run(ctx, Request{Mode: ModeImport})
	if runErr != nil {
		t.Fatal(runErr)
	}
	if len(current.sets) != 0 || result.TargetIdentity != "target-1" {
		t.Fatalf("current/result = %#v/%#v", current.sets, result)
	}
	if source.inventory.Records[1].Payload != nil {
		t.Fatal("source credential remained in importer memory")
	}
	if err := target.Reopen(ctx); err != nil {
		t.Fatal(err)
	}
	published, err := target.GetReadiness(ctx)
	if err != nil || published.Mode != "import" || published.DatabaseIdentity != "target-1" || !bytes.Equal(published.SourceManifestDigest, result.ManifestDigest) {
		t.Fatalf("published = %#v, err = %v", published, err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
}
func TestSQLitePublicationTargetRelaxesCandidateSyncOnlyUntilReopen(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	target := NewSQLitePublicationTarget(filepath.Join(root, "candidate.db"), filepath.Join(root, "active.db"), sqliteTargetKeySource{})
	if err := target.Initialize(ctx, "target-fast-import"); err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	var synchronous int
	if err := target.database.SQLDB().QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous); err != nil {
		t.Fatal(err)
	}
	if synchronous != 0 {
		t.Fatalf("candidate synchronous = %d, want OFF during isolated import", synchronous)
	}
	indexCount := func(table, name string) int {
		t.Helper()
		var count int
		if err := target.database.SQLDB().QueryRowContext(
			ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND tbl_name = ? AND name = ?",
			table, name,
		).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	if count := indexCount("story_log_entries", "ix_story_log_entries_scope_session"); count != 0 {
		t.Fatalf("deferred story-log index count = %d, want 0 during isolated import", count)
	}
	if err := target.Reopen(ctx); err != nil {
		t.Fatal(err)
	}
	if err := target.database.SQLDB().QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous); err != nil {
		t.Fatal(err)
	}
	if synchronous != 2 {
		t.Fatalf("reopened synchronous = %d, want FULL before publication", synchronous)
	}
	if count := indexCount("story_log_entries", "ix_story_log_entries_scope_session"); count != 1 {
		t.Fatalf("restored story-log index count = %d, want 1 before publication", count)
	}
}

func TestImporterPublishesSQLiteCandidateByAtomicRename(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	candidate := filepath.Join(root, "candidate.db")
	active := filepath.Join(root, "active.db")
	oldTarget := NewSQLiteTarget(active, sqliteTargetKeySource{})
	if err := oldTarget.Initialize(ctx, "target-atomic"); err != nil {
		t.Fatal(err)
	}
	if err := oldTarget.Close(); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(groupstate.NewGroupCreatedV1("dice-1", "QQ-Group:1", "group", 1))
	if err != nil {
		t.Fatal(err)
	}
	stream := groupstate.GroupStream("dice-1", "QQ-Group:1")
	record := validSourceRecord(stream.AggregateType, stream.AggregateID, string(groupstate.EventGroupCreated), payload)
	record.SchemaVersion = groupstate.GroupEventSchemaVersion
	source := &sourceFake{inventory: SourceInventory{
		Kind: SourceKindLegacy, Identity: "legacy-1", LegacyOwnershipComplete: true,
		Metadata: SourceMetadata{Identity: "legacy-1"}, Records: []SourceRecord{record},
	}}
	target := NewSQLitePublicationTarget(candidate, active, sqliteTargetKeySource{})
	result, err := NewImporter(ImporterOptions{
		Readiness: &readinessFake{value: eventstore.Readiness{Mode: "fresh", SchemaVersion: 1, DatabaseIdentity: "target-atomic", IndexRootID: "old-index"}},
		Source:    source, Target: target, SnapshotRoot: filepath.Join(root, "snapshot"), TargetIdentity: "target-atomic",
	}).Run(ctx, Request{Mode: ModeImport})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(candidate); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("candidate still exists: %v", err)
	}
	if _, err = os.Stat(active); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(active + ".pre-import-" + result.TargetIdentity); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("publication backup still exists: %v", err)
	}
	reopened := NewSQLiteTarget(active, sqliteTargetKeySource{})
	reopened.identity = result.TargetIdentity
	if err = reopened.openLocked(ctx); err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	readiness, err := reopened.GetReadiness(ctx)
	if err != nil || readiness.Mode != "import" || readiness.DatabaseIdentity != result.TargetIdentity {
		t.Fatalf("readiness=%#v err=%v", readiness, err)
	}
}

func TestImporterFailureAfterCandidateBatchLeavesActiveDatabaseUntouched(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	activePath := filepath.Join(root, "active.db")
	active := NewSQLiteTarget(activePath, sqliteTargetKeySource{})
	if err := active.Initialize(ctx, "target-atomic"); err != nil {
		t.Fatal(err)
	}
	if err := active.Close(); err != nil {
		t.Fatal(err)
	}
	activeBefore, err := os.ReadFile(activePath)
	if err != nil {
		t.Fatal(err)
	}

	records := make([]SourceRecord, 0, eventstore.MaxUnitOfWorkStreams+1)
	for index := range eventstore.MaxUnitOfWorkStreams + 1 {
		groupID := "QQ-Group:" + strconv.Itoa(index+1)
		payload, marshalErr := json.Marshal(groupstate.NewGroupCreatedV1("dice-1", groupID, groupID, int64(index+1)))
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		stream := groupstate.GroupStream("dice-1", groupID)
		record := validSourceRecord(stream.AggregateType, stream.AggregateID, string(groupstate.EventGroupCreated), payload)
		record.SchemaVersion = groupstate.GroupEventSchemaVersion
		records = append(records, record)
	}
	source := &sourceFake{inventory: SourceInventory{
		Kind: SourceKindLegacy, Identity: "legacy-atomic", LegacyOwnershipComplete: true,
		Metadata: SourceMetadata{Identity: "legacy-atomic"}, Records: records,
	}}
	importCalls := 0
	secondBatchFailure := errors.New("forced second candidate batch failure")
	result, err := NewImporter(ImporterOptions{
		Readiness: &readinessFake{value: eventstore.Readiness{
			Mode: "fresh", SchemaVersion: 1, DatabaseIdentity: "target-atomic", IndexRootID: "index-v1",
		}},
		Source: source,
		Target: NewSQLitePublicationTarget(
			filepath.Join(root, "candidate.db"),
			activePath,
			sqliteTargetKeySource{},
		),
		SnapshotRoot:   filepath.Join(root, "snapshot"),
		TargetIdentity: "target-atomic",
		FailureInjector: FailureFunc(func(stage string) error {
			if stage == "import" {
				importCalls++
				if importCalls == 2 {
					return secondBatchFailure
				}
			}
			return nil
		}),
	}).Run(ctx, Request{Mode: ModeImport})
	if !errors.Is(err, secondBatchFailure) || !errors.Is(err, ErrQuarantined) {
		t.Fatalf("second candidate batch error = %v", err)
	}
	if importCalls != 2 || result.Batches != 1 || result.QuarantineMarker == "" {
		t.Fatalf("candidate batches/calls/quarantine = %d/%d/%q", result.Batches, importCalls, result.QuarantineMarker)
	}
	activeAfter, err := os.ReadFile(activePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(activeBefore, activeAfter) {
		t.Fatal("active database changed after candidate import failure")
	}

	reopened := NewSQLiteTarget(activePath, sqliteTargetKeySource{})
	reopened.identity = "target-atomic"
	if err = reopened.openLocked(ctx); err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	readiness, err := reopened.GetReadiness(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if readiness.Mode != "fresh" || readiness.DatabaseIdentity != "target-atomic" {
		t.Fatalf("active readiness changed after candidate failure: %#v", readiness)
	}
}

func TestSQLitePublicationReplacementFailureLeavesActiveAvailable(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	active := filepath.Join(root, "active.db")
	oldTarget := NewSQLiteTarget(active, sqliteTargetKeySource{})
	if err := oldTarget.Initialize(ctx, "target-old"); err != nil {
		t.Fatal(err)
	}
	if err := oldTarget.Close(); err != nil {
		t.Fatal(err)
	}
	target := NewSQLitePublicationTarget(filepath.Join(root, "candidate.db"), active, sqliteTargetKeySource{})
	if err := target.Initialize(ctx, "target-new"); err != nil {
		t.Fatal(err)
	}
	replacementErr := errors.New("replacement failed")
	target.replaceDatabase = func(string, string) error { return replacementErr }
	if err := target.Publish(ctx); !errors.Is(err, replacementErr) {
		t.Fatalf("publish error = %v", err)
	}
	if _, err := os.Stat(active); err != nil {
		t.Fatalf("active database disappeared: %v", err)
	}
	reopened := NewSQLiteTarget(active, sqliteTargetKeySource{})
	reopened.identity = "target-old"
	if err := reopened.openLocked(ctx); err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	readiness, err := reopened.GetReadiness(ctx)
	if err != nil || readiness.DatabaseIdentity != "target-old" {
		t.Fatalf("active readiness = %#v, %v", readiness, err)
	}
}

func TestRemoteSQLTargetImportsPublishesAndReopens(t *testing.T) {
	tests := []struct {
		name, dbType, env string
	}{
		{name: "mysql", dbType: "mysql", env: "SCARDICE_EVENTSTORE_MYSQL_DSN"},
		{name: "postgres", dbType: "postgres", env: "SCARDICE_EVENTSTORE_POSTGRES_DSN"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dsn := os.Getenv(test.env)
			if dsn == "" {
				t.Skipf("%s is not configured", test.env)
			}
			ctx := context.Background()
			payload, marshalErr := json.Marshal(groupstate.NewGroupCreatedV1("dice-remote", "group-remote", "remote", 1))
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			stream := groupstate.GroupStream("dice-remote", "group-remote")
			record := validSourceRecord(stream.AggregateType, stream.AggregateID, string(groupstate.EventGroupCreated), payload)
			record.SchemaVersion = groupstate.GroupEventSchemaVersion
			source := &sourceFake{inventory: SourceInventory{
				Kind: SourceKindLegacy, Identity: "legacy-remote", LegacyOwnershipComplete: true,
				Metadata: SourceMetadata{Identity: "legacy-remote"}, Records: []SourceRecord{record},
			}}
			activated := ""
			target := NewRemoteSQLTarget(eventstore.DatabaseConfig{
				Type: test.dbType, DSN: dsn, KeySource: sqliteTargetKeySource{},
				AllowInsecureLoopback: true,
			}, func(_ context.Context, identity string) error {
				activated = identity
				return nil
			})
			result, err := NewImporter(ImporterOptions{
				Readiness: &readinessFake{value: eventstore.Readiness{Mode: "fresh", SchemaVersion: 1, DatabaseIdentity: "old", IndexRootID: "old-index"}},
				Source:    source, Target: target, SnapshotRoot: filepath.Join(t.TempDir(), "snapshot"),
				TargetIdentity: "target-" + test.name,
			}).Run(ctx, Request{Mode: ModeImport})
			if err != nil {
				t.Fatal(err)
			}
			if activated != result.TargetIdentity {
				t.Fatalf("activated=%q target=%q", activated, result.TargetIdentity)
			}
			if err = target.Reopen(ctx); err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			readiness, err := target.GetReadiness(ctx)
			if err != nil || readiness.Mode != "import" || readiness.DatabaseIdentity != result.TargetIdentity {
				t.Fatalf("readiness=%#v err=%v", readiness, err)
			}
		})
	}
}

func TestSQLiteTargetStoryLogImportRetriesAreIdempotent(t *testing.T) {
	ctx := context.Background()
	target := NewSQLiteTarget(filepath.Join(t.TempDir(), "logs.db"), sqliteTargetKeySource{})
	if err := target.Initialize(ctx, "log-import-retry"); err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	extra := "preserved extra"
	sourceID := legacyStoryLogSourceID("source-retry", "dice-1", "group-1", legacyLogImportSession, 7)
	record, err := legacyStoryLogSourceRecord(legacyStoryLogImportPayload{
		SourceID: sourceID, Kind: legacyLogImportSession, DiceID: "dice-1", GroupID: "group-1",
		Session: &legacyStoryLogSessionPayload{
			DiceID: "dice-1", GroupID: "group-1", Name: "session",
			CreatedAt: 100, UpdatedAt: 101, Extra: &extra,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for attempt := range 2 {
		if err := target.ImportBatch(ctx, []SourceRecord{record}); err != nil {
			t.Fatalf("attempt %d: %v", attempt+1, err)
		}
	}

	changed := "changed extra"
	conflict, err := legacyStoryLogSourceRecord(legacyStoryLogImportPayload{
		SourceID: sourceID, Kind: legacyLogImportSession, DiceID: "dice-1", GroupID: "group-1",
		Session: &legacyStoryLogSessionPayload{
			DiceID: "dice-1", GroupID: "group-1", Name: "session",
			CreatedAt: 100, UpdatedAt: 101, Extra: &changed,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := target.ImportBatch(ctx, []SourceRecord{conflict}); !errors.Is(err, ErrValidation) {
		t.Fatalf("conflicting retry error = %v", err)
	}
	if _, err := target.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	if err := target.Reopen(ctx); err != nil {
		t.Fatal(err)
	}
	manifest, err := target.Manifest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Records) != 2 {
		t.Fatalf("retry manifest record count = %d, want 2 source attempts", len(manifest.Records))
	}
	receipts, err := target.store.ListStoryLogImports(ctx, "legacy-story-log/v1/source-retry/", "dice-1")
	if err != nil || len(receipts) != 1 {
		t.Fatalf("retry archive receipts = %d, err=%v; want exactly one", len(receipts), err)
	}
	sessions, err := target.store.ListStoryLogs(ctx, "dice-1", "group-1")
	if err != nil || len(sessions) != 1 || sessions[0].Extra == nil || *sessions[0].Extra != extra {
		t.Fatalf("retry sessions = %#v, err=%v", sessions, err)
	}
}

func TestSQLiteTargetStoryLogFailureRollsBackOtherParticipants(t *testing.T) {
	ctx := context.Background()
	target := NewSQLiteTarget(filepath.Join(t.TempDir(), "atomic.db"), sqliteTargetKeySource{})
	if err := target.Initialize(ctx, "log-import-atomic"); err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	eventPayload, err := json.Marshal(groupstate.NewGroupCreatedV1("dice-1", "group-1", "group", 1))
	if err != nil {
		t.Fatal(err)
	}
	stream := groupstate.GroupStream("dice-1", "group-1")
	eventRecord := validSourceRecord(stream.AggregateType, stream.AggregateID, string(groupstate.EventGroupCreated), eventPayload)
	eventRecord.SchemaVersion = groupstate.GroupEventSchemaVersion
	secret := []byte("atomic-secret")
	secretRecord := SourceRecord{
		RecordType: RecordTypeSecret, Domain: "adapter", Identity: "secret://atomic/token", Kind: "endpoint",
		SchemaVersion: 1, Version: 1, Sensitive: true, Payload: secret, Size: uint64(len(secret)),
	}
	pluginValue := []byte("atomic-plugin-value")
	pluginRecord := SourceRecord{
		RecordType: RecordTypePluginKV, Domain: "atomic-extension", Identity: "key", Kind: "value",
		SchemaVersion: 1, Version: 1, Sensitive: true, Payload: pluginValue, Size: uint64(len(pluginValue)),
	}
	entrySourceID := legacyStoryLogSourceID("atomic-source", "dice-1", "group-1", legacyLogImportEntry, 12)
	missingSessionID := legacyStoryLogSourceID("atomic-source", "dice-1", "group-1", legacyLogImportSession, 4)
	logRecord, err := legacyStoryLogSourceRecord(legacyStoryLogImportPayload{
		SourceID: entrySourceID, Kind: legacyLogImportEntry, DiceID: "dice-1", GroupID: "group-1",
		SessionSourceID: missingSessionID,
		Entry: &legacyStoryLogEntryPayload{
			DiceID: "dice-1", GroupID: "group-1", LogName: "missing", Message: "must roll back",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := target.ImportBatch(ctx, []SourceRecord{eventRecord, secretRecord, pluginRecord, logRecord}); err == nil {
		t.Fatal("missing session unexpectedly committed")
	}

	events, err := target.store.Load(ctx, stream, 1)
	if err != nil || len(events) != 0 {
		t.Fatalf("events after failed import = %d, err=%v", len(events), err)
	}
	if _, err = target.store.ResolveSecret(ctx, secretRecord.Identity, secretRecord.Version); err == nil {
		t.Fatal("secret participant survived failed import")
	}
	if _, err = target.store.GetPluginKV(ctx, pluginRecord.Domain, pluginRecord.Identity); err == nil {
		t.Fatal("plugin participant survived failed import")
	}
	prefix, ok := legacyStoryLogSourcePrefix(entrySourceID)
	if !ok {
		t.Fatal("invalid test source identity")
	}
	receipts, err := target.store.ListStoryLogImports(ctx, prefix, "dice-1")
	if err != nil || len(receipts) != 0 {
		t.Fatalf("log imports after failed commit = %d, err=%v", len(receipts), err)
	}
}
