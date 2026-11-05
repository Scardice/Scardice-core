package eventsourcing

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"time"

	"Scardice-core/eventstore"
	"Scardice-core/migrate/eventsourcing/v1reader"
)

// ErrNotV1Store is returned when the database to convert is not an encrypted
// (v1) event store.
var ErrNotV1Store = errors.New("eventsourcing: not an encrypted v1 event store")

const v1ConvertLogBatch = 250

// V1ConvertOptions describes one conversion of an encrypted (v1) event store
// into the plaintext store. The v1 file is only read; it is kept as a backup
// next to the new database.
type V1ConvertOptions struct {
	// ActivePath is the v1 database (data/endpoint/events.db) and also where
	// the converted database is published.
	ActivePath string
	// KeysDir holds the v1 key files: index.key and roots/. KeyIndexPath and
	// KeyRootsDir override the two locations for installations that kept them
	// apart.
	KeysDir      string
	KeyIndexPath string
	KeyRootsDir  string
	// Identity is the database identity the converted database carries. It is
	// the configured identity, so the configuration needs no change.
	Identity string
	Now      func() time.Time
	// Progress receives one human-readable line per phase.
	Progress func(format string, args ...any)
	// Inject lets tests fail a named phase.
	Inject FailureInjector
}

// V1ConvertResult reports what was converted and what was left behind.
type V1ConvertResult struct {
	Identity   string
	BackupPath string

	Events                 int // newly constructed baseline facts, not old history
	Secrets                int // current secret references; each starts at version 1
	SecretVersions         int
	ReferencedSecrets      int
	OmittedSecrets         int // unreferenced owners retained only in the v1 backup
	PluginKV               int
	StorySessions          int
	StoryStates            int
	StoryEntries           int
	ManagementActivity     int
	LeftBehindQueueRows    int // inbox, outbox, operations, artifacts, execution receipts
	NonterminalOutboxRows  int
	LeftBehindStoryIntents int // pending replies tied to excluded outbox effects
	ProjectionRows         int
}

func (o V1ConvertOptions) progressf(format string, args ...any) {
	if o.Progress != nil {
		o.Progress(format, args...)
	}
}

func (o V1ConvertOptions) inject(stage string) error {
	if o.Inject == nil {
		return nil
	}
	return o.Inject.Inject(stage)
}

// ConvertV1 converts the encrypted event store at opts.ActivePath into a
// plaintext one and publishes it in place. It is all or nothing: every check
// runs against a separate candidate file, the v1 database is replaced only
// after they pass, and on any failure the v1 database is left as it was.
//
// The process that owns the database must be stopped.
func ConvertV1(ctx context.Context, opts V1ConvertOptions) (result V1ConvertResult, runErr error) {
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	if opts.ActivePath == "" {
		return result, ErrTargetRequired
	}
	active, err := filepath.Abs(opts.ActivePath)
	if err != nil {
		return result, err
	}
	if err := CheckUnfinishedV1Publication(active); err != nil {
		return result, err
	}
	if opts.Identity == "" {
		return result, ErrTargetIdentity
	}
	result.Identity = opts.Identity
	snapshot, proof, cleanup, err := snapshotV1SQLite(ctx, active)
	if err != nil {
		return result, err
	}
	scratchRemoved := false
	defer func() {
		if !scratchRemoved {
			runErr = errors.Join(runErr, cleanup())
		}
	}()
	format, err := v1reader.Detect(ctx, snapshot)
	if err != nil {
		return result, err
	}
	if format != v1reader.FormatV1Encrypted {
		return result, fmt.Errorf("%w: found %s", ErrNotV1Store, format)
	}
	indexPath, rootsDir := opts.KeyIndexPath, opts.KeyRootsDir
	if indexPath == "" {
		indexPath = filepath.Join(opts.KeysDir, "index.key")
	}
	if rootsDir == "" {
		rootsDir = filepath.Join(opts.KeysDir, "roots")
	}
	source, err := v1reader.Open(snapshot, v1reader.OpenKeys(indexPath, rootsDir))
	if err != nil {
		return result, err
	}
	sourceClosed := false
	defer func() {
		if !sourceClosed {
			runErr = errors.Join(runErr, source.Close())
		}
	}()
	mode, err := source.ReadinessMode(ctx)
	if err != nil {
		return result, err
	}
	if mode != string(ModeFresh) && mode != string(ModeImport) {
		return result, fmt.Errorf("%w: v1 readiness mode %q", ErrNotV1Store, mode)
	}
	identity, err := source.DatabaseIdentity(ctx)
	if err != nil {
		return result, err
	}
	if identity != opts.Identity {
		return result, fmt.Errorf("v1 database identity differs from configuration: %w", ErrTargetIdentity)
	}
	transients, err := source.Transients(ctx)
	if err != nil {
		return result, err
	}
	result.LeftBehindQueueRows, result.NonterminalOutboxRows, result.LeftBehindStoryIntents = transients.Rows, transients.NonterminalOutbox, transients.StoryIntents
	opts.progressf("不迁移瞬态记录 %d 条，其中非终态 outbox %d 条；另有未发送的 Story 回复意图 %d 条", transients.Rows, transients.NonterminalOutbox, transients.StoryIntents)
	rows, err := source.PublishedProjectionRows(ctx)
	if err != nil {
		return result, err
	}
	items, err := source.PluginKVs(ctx)
	if err != nil {
		return result, err
	}
	defer func(values []v1reader.PluginKV) {
		for i := range values {
			clear(values[i].Value)
		}
	}(items)
	rows, items, err = foldV1PluginConfig(rows, items)
	if err != nil {
		return result, err
	}
	baseline := newV1Baseline()
	if err = opts.inject("events"); err != nil {
		return result, err
	}
	for _, row := range rows {
		if err = baseline.addProjection(row); err != nil {
			return result, err
		}
	}
	defer func() { clearSensitiveSourceRecords(baseline.records) }()
	if err = opts.inject("secrets"); err != nil {
		return result, err
	}
	if err = baseline.addSecrets(ctx, source); err != nil {
		return result, err
	}
	for _, item := range items {
		baseline.records = append(baseline.records, SourceRecord{RecordType: RecordTypePluginKV, Domain: item.ExtensionID, Identity: item.Key, Kind: "value", SchemaVersion: 1, Version: 1, Sensitive: true, Payload: item.Value, Size: uint64(len(item.Value))})
	}
	result.PluginKV = len(items)
	for _, record := range baseline.records {
		switch record.RecordType {
		case RecordTypeEvent:
			result.Events++
		case RecordTypeSecret:
			result.Secrets++
		case RecordTypePluginKV, RecordTypeProjection, RecordTypeLogArchive:
			// These records do not contribute to the event or secret totals.
		}
	}
	result.SecretVersions = result.Secrets
	secretCount, err := source.SecretReferenceCount(ctx)
	if err != nil {
		return result, err
	}
	result.ReferencedSecrets = len(baseline.secretVersions)
	result.OmittedSecrets = secretCount - result.ReferencedSecrets
	if result.OmittedSecrets < 0 {
		return result, ErrValidation
	}
	opts.progressf("迁移当前引用的最新凭据/属性 %d 个；未引用旧 owner %d 个仅保留在备份", result.ReferencedSecrets, result.OmittedSecrets)
	now := opts.Now().UTC()
	stamp := now.Format("20060102T150405.000000000Z")
	candidate := active + ".import-" + stamp
	target := NewSQLitePublicationTarget(candidate, active)
	if err = opts.inject("initialize"); err != nil {
		return result, err
	}
	defer func() {
		if !target.published {
			runErr = errors.Join(runErr, target.discardCandidate())
		}
	}()
	if err = target.Initialize(ctx, opts.Identity); err != nil {
		return result, fmt.Errorf("initialize conversion target: %w", err)
	}
	batches, err := deterministicImportBatches(baseline.records)
	if err != nil {
		return result, err
	}
	defer clearSensitiveSourceRecordBatches(batches)
	for _, batch := range batches {
		if err = target.ImportBatch(ctx, batch); err != nil {
			return result, err
		}
	}
	expected := manifestFromSource(SourceInventory{Identity: opts.Identity, Records: baseline.records})
	sourceCanonical, sourceDigest, err := canonicalImportManifest(expected, MaxManifestBytes)
	if err != nil {
		return result, err
	}
	store, err := target.conversionStore()
	if err != nil {
		return result, err
	}
	archive := &v1ArchiveProof{}
	if err = opts.inject("story-log"); err != nil {
		return result, err
	}
	if err = convertV1StoryLog(ctx, opts, source, store, archive, &result); err != nil {
		return result, err
	}
	if err = convertV1Management(ctx, source, store, &result); err != nil {
		return result, err
	}
	if err = opts.inject("rebuild"); err != nil {
		return result, err
	}
	if _, err = target.Rebuild(ctx); err != nil {
		return result, fmt.Errorf("rebuild converted projections: %w", err)
	}
	if err = opts.inject("reopen"); err != nil {
		return result, err
	}
	if err = target.Reopen(ctx); err != nil {
		return result, err
	}
	if err = opts.inject("verify"); err != nil {
		return result, err
	}
	if err = compareV1Projections(ctx, baseline, target, &result); err != nil {
		return result, err
	}
	actual, err := target.Manifest(ctx)
	if err != nil {
		return result, err
	}
	actual.SourceIdentity = opts.Identity
	targetCanonical, targetDigest, err := canonicalImportManifest(actual, MaxManifestBytes)
	if err != nil {
		return result, err
	}
	if !bytes.Equal(sourceCanonical, targetCanonical) || !bytes.Equal(sourceDigest, targetDigest) {
		return result, fmt.Errorf("baseline records changed on target readback: %w", ErrValidation)
	}
	store, err = target.conversionStore()
	if err != nil {
		return result, err
	}
	if err = archive.verify(ctx, store); err != nil {
		return result, err
	}
	if err = compareV1Management(ctx, source, target); err != nil {
		return result, err
	}
	readiness := buildImportReadiness(opts.Identity, now)
	if err = PublishReadiness(ctx, target, readiness); err != nil {
		return result, err
	}
	if err = target.closeForPublication(ctx); err != nil {
		return result, err
	}
	if err = syncSQLiteDatabaseFile(candidate); err != nil {
		return result, err
	}
	sourceClosed = true
	if err = source.Close(); err != nil {
		return result, err
	}
	scratchRemoved = true
	if err = cleanup(); err != nil {
		return result, err
	}
	if err = opts.inject("publish"); err != nil {
		return result, err
	}
	backup, err := publishV1Candidate(ctx, opts, candidate, active, stamp, proof)
	if err != nil {
		return result, fmt.Errorf("activate converted database: %w", err)
	}
	target.published = true
	result.BackupPath = backup
	return result, nil
}

// --- Story log ---------------------------------------------------------------

type v1StorySessionJSON struct {
	DiceID     string  `json:"diceId"`
	GroupID    string  `json:"groupId"`
	Name       string  `json:"name"`
	UploadURL  string  `json:"uploadUrl,omitempty"`
	UploadTime int64   `json:"uploadTime,omitempty"`
	Extra      *string `json:"extra,omitempty"`
}

type v1StoryStateJSON struct {
	DiceID      string `json:"diceId"`
	GroupID     string `json:"groupId"`
	SessionID   uint64 `json:"sessionId"`
	Name        string `json:"name"`
	On          bool   `json:"on"`
	BaselineSeq int64  `json:"baselineSeq,omitempty"`
}

type v1StoryEntryJSON struct {
	DiceID      string          `json:"diceId"`
	GroupID     string          `json:"groupId"`
	LogName     string          `json:"logName"`
	Nickname    string          `json:"nickname"`
	IMUserID    string          `json:"imUserId"`
	Time        int64           `json:"time"`
	Message     string          `json:"message"`
	IsDice      bool            `json:"isDice"`
	CommandID   int64           `json:"commandId"`
	CommandInfo json.RawMessage `json:"commandInfo,omitempty"`
	RawMsgID    string          `json:"rawMsgId,omitempty"`
	UniformID   string          `json:"uniformId"`
	Seq         *int64          `json:"seq,omitempty"`
	Removed     *int            `json:"removed,omitempty"`
	ParentID    *int            `json:"parentId,omitempty"`
}

func v1StorySessionSource(id uint64) string { return fmt.Sprintf("v1/session/%d", id) }

func convertV1StoryLog(ctx context.Context, opts V1ConvertOptions, source *v1reader.Source, store *eventstore.GORMStore, proof *v1ArchiveProof, result *V1ConvertResult) error {
	sessions, err := source.StorySessions(ctx)
	if err != nil {
		return err
	}
	known := make(map[uint64]struct{}, len(sessions))
	var batch []eventstore.StoryLogImportRecord
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if _, importErr := store.ImportStoryLogBatch(ctx, batch); importErr != nil {
			return importErr
		}
		batch = batch[:0]
		return nil
	}
	push := func(record eventstore.StoryLogImportRecord) error {
		digest, err := store.StoryLogImportSemanticDigest(ctx, record)
		if err != nil {
			return err
		}
		proof.expected.add([]byte(record.SourceID), []byte(record.Kind), digest)
		batch = append(batch, record)
		if len(batch) >= v1ConvertLogBatch {
			return flush()
		}
		return nil
	}
	for _, row := range sessions {
		var private v1StorySessionJSON
		if err = json.Unmarshal(row.Plain, &private); err != nil {
			return fmt.Errorf("story session %d: %w", row.ID, err)
		}
		known[row.ID] = struct{}{}
		if err = push(eventstore.StoryLogImportRecord{
			SourceID: v1StorySessionSource(row.ID), Kind: eventstore.StoryLogImportSession, DiceID: private.DiceID, GroupID: private.GroupID,
			Session: &eventstore.StoryLogSession{
				DiceID: private.DiceID, GroupID: private.GroupID, Name: private.Name, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
				UploadURL: private.UploadURL, UploadTime: private.UploadTime, Extra: private.Extra,
			},
		}); err != nil {
			return fmt.Errorf("convert story sessions: %w", err)
		}
	}
	if err = flush(); err != nil {
		return fmt.Errorf("convert story sessions: %w", err)
	}
	result.StorySessions = len(sessions)

	err = source.StoryEntries(ctx, func(row v1reader.StoryRow) error {
		if _, ok := known[row.SessionID]; !ok {
			return fmt.Errorf("v1 Story entry %d references missing session %d: %w", row.ID, row.SessionID, ErrValidation)
		}
		var private v1StoryEntryJSON
		if err := json.Unmarshal(row.Plain, &private); err != nil {
			return fmt.Errorf("story entry %d: %w", row.ID, err)
		}
		result.StoryEntries++
		if result.StoryEntries%100000 == 0 {
			opts.progressf("已转换 Story 日志条目 %d", result.StoryEntries)
		}
		return push(eventstore.StoryLogImportRecord{
			SourceID: fmt.Sprintf("v1/entry/%d", row.ID), Kind: eventstore.StoryLogImportEntry, DiceID: private.DiceID, GroupID: private.GroupID,
			SessionSourceID: v1StorySessionSource(row.SessionID),
			Entry: &eventstore.StoryLogEntry{
				DiceID: private.DiceID, GroupID: private.GroupID, LogName: private.LogName, Nickname: private.Nickname,
				IMUserID: private.IMUserID, Time: private.Time, Message: private.Message, IsDice: private.IsDice,
				CommandID: private.CommandID, CommandInfo: private.CommandInfo, RawMsgID: private.RawMsgID,
				UniformID: private.UniformID, Seq: private.Seq, Removed: private.Removed, ParentID: private.ParentID,
			},
		})
	})
	if err != nil {
		return fmt.Errorf("convert story entries: %w", err)
	}
	if err = flush(); err != nil {
		return fmt.Errorf("convert story entries: %w", err)
	}

	states, err := source.StoryStates(ctx)
	if err != nil {
		return err
	}
	for index, row := range states {
		var private v1StoryStateJSON
		if err = json.Unmarshal(row.Plain, &private); err != nil {
			return fmt.Errorf("story state %d: %w", index, err)
		}
		record := eventstore.StoryLogImportRecord{
			SourceID: fmt.Sprintf("v1/state/%d", index), Kind: eventstore.StoryLogImportState, DiceID: private.DiceID, GroupID: private.GroupID,
			State: &eventstore.StoryLogState{
				DiceID: private.DiceID, GroupID: private.GroupID, Name: private.Name, On: private.On, BaselineSeq: private.BaselineSeq,
			},
		}
		if private.SessionID != 0 {
			if _, ok := known[private.SessionID]; !ok {
				return fmt.Errorf("v1 Story state references missing session %d: %w", private.SessionID, ErrValidation)
			}
		}
		if _, ok := known[private.SessionID]; ok && private.SessionID != 0 {
			record.SessionSourceID = v1StorySessionSource(private.SessionID)
		}
		if err = push(record); err != nil {
			return fmt.Errorf("convert story states: %w", err)
		}
	}
	if err = flush(); err != nil {
		return fmt.Errorf("convert story states: %w", err)
	}
	result.StoryStates = len(states)
	opts.progressf("Story 日志完成: 会话 %d,条目 %d,当前状态 %d；不迁移未发送回复意图 %d",
		result.StorySessions, result.StoryEntries, result.StoryStates, result.LeftBehindStoryIntents)
	return nil
}

func convertV1Management(ctx context.Context, source *v1reader.Source, store *eventstore.GORMStore, result *V1ConvertResult) error {
	activities, err := source.ManagementActivities(ctx)
	if err != nil {
		return err
	}
	for _, activity := range activities {
		if err = store.AppendManagementActivity(ctx, eventstore.ManagementActivity{
			ID: activity.ID, OccurredAt: time.UnixMilli(activity.OccurredAtUnixMilli).UTC(), Action: activity.Action, Label: activity.Label,
			Resource: activity.Resource, Status: activity.Status, HTTPStatus: activity.HTTPStatus, Actor: activity.Actor, SourceIP: activity.SourceIP,
		}); err != nil {
			return fmt.Errorf("convert management activity %q: %w", activity.ID, err)
		}
	}
	result.ManagementActivity = len(activities)
	return nil
}

// --- projection check ---------------------------------------------------------

// compareV1Projections compares source current state, with only the explicit
// baseline version/reference and transient endpoint resets applied, to actual
// rebuilt rows. Extra or unknown projections cannot silently disappear.
func compareV1Projections(ctx context.Context, baseline *v1Baseline, target *SQLiteTarget, result *V1ConvertResult) error {
	got, err := target.projectionRows(ctx)
	if err != nil {
		return err
	}
	if len(got) != len(baseline.projections) {
		return fmt.Errorf("baseline projection count source=%d target=%d: %w", len(baseline.projections), len(got), ErrValidation)
	}
	for _, row := range got {
		want, ok := baseline.projections[v1ProjectionKey{row.Name, row.RowKey}]
		if !ok || !sameJSON(want, row.Payload) {
			return fmt.Errorf("baseline current state differs in %s/%s: %w", row.Name, row.RowKey, ErrValidation)
		}
	}
	result.ProjectionRows = len(got)
	return nil
}

func sameJSON(a, b []byte) bool {
	var left, right any
	if decodeV1Projection(a, &left) != nil || decodeV1Projection(b, &right) != nil {
		return bytes.Equal(a, b)
	}
	return reflect.DeepEqual(left, right)
}

// --- target access -------------------------------------------------------------

func (t *SQLiteTarget) conversionStore() (*eventstore.GORMStore, error) {
	if t == nil {
		return nil, ErrTargetRequired
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.store == nil {
		return nil, ErrTargetRequired
	}
	return t.store, nil
}

type targetProjectionRow struct {
	Name    string
	RowKey  string
	Payload []byte
}

func (t *SQLiteTarget) projectionRows(ctx context.Context) ([]targetProjectionRow, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.database == nil || t.database.GORM() == nil {
		return nil, ErrTargetRequired
	}
	var control struct{ ActiveGeneration string }
	query := t.database.GORM().WithContext(ctx)
	if err := query.Table("projection_control").Select("active_generation").Where("singleton_id = ?", "default").Take(&control).Error; err != nil {
		return nil, ErrValidation
	}
	var rows []targetProjectionRow
	if err := query.Table("projection_read_models").Select("projection_name AS name", "row_key", "payload").
		Where("projection_generation = ? AND payload IS NOT NULL", control.ActiveGeneration).Find(&rows).Error; err != nil {
		return nil, ErrValidation
	}
	return rows, nil
}

// Migration-local fingerprints prove archived contents without storing runtime
// readiness manifests or retaining millions of entry payloads in memory.
type v1Digest struct {
	acc   [sha256.Size]byte
	count uint64
}

func (d *v1Digest) add(parts ...[]byte) {
	hash := sha256.New()
	var length [8]byte
	for _, part := range parts {
		binary.BigEndian.PutUint64(length[:], uint64(len(part)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write(part)
	}
	sum := hash.Sum(nil)
	for i := range sum {
		d.acc[i] ^= sum[i]
	}
	d.count++
}

type v1ArchiveProof struct{ expected v1Digest }

func (p *v1ArchiveProof) verify(ctx context.Context, store *eventstore.GORMStore) error {
	var actual v1Digest
	if err := store.VisitStoryLogImports(ctx, "v1/", "", func(row eventstore.StoryLogImportReceipt) error {
		actual.add([]byte(row.SourceID), []byte(row.Kind), row.SemanticDigest)
		return nil
	}); err != nil {
		return err
	}
	if actual != p.expected {
		return fmt.Errorf("story archive current contents changed on readback: %w", ErrValidation)
	}
	return nil
}

func compareV1Management(ctx context.Context, source *v1reader.Source, target *SQLiteTarget) error {
	expected, err := source.ManagementActivities(ctx)
	if err != nil {
		return err
	}
	var actual []v1reader.ManagementActivity
	if err := target.database.GORM().WithContext(ctx).Table("management_activities").
		Select("id", "occurred_at_unix_milli", "action", "label", "resource", "status", "http_status", "actor", "source_ip").
		Order("global_position").Find(&actual).Error; err != nil {
		return err
	}
	if len(actual) != len(expected) {
		return ErrValidation
	}
	for i := range actual {
		if actual[i] != expected[i] {
			return fmt.Errorf("management activity %q changed on readback: %w", expected[i].ID, ErrValidation)
		}
	}
	return nil
}
