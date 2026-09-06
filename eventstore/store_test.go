package eventstore

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
)

func TestCommitMultiStreamContiguousPositions(t *testing.T) {
	db, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "events.db")})
	if err != nil { t.Fatal(err) }
	defer db.Close()
	store := NewStore(db)
	work := UnitOfWork{Streams: []StreamAppend{
		{Stream: StreamID{AggregateType: "z", AggregateID: "1"}, Events: []NewEvent{{EventType: "a", SchemaVersion: 1, Payload: []byte(`{"n":1}`), Metadata: Metadata{EventID: "e1", CommandID: "c1", CorrelationID: "r1", OccurredAtUnixNanoUTC: 1, OccurredAtUnixNanoSet: true}}}},
		{Stream: StreamID{AggregateType: "a", AggregateID: "1"}, Events: []NewEvent{{EventType: "b", SchemaVersion: 1, Payload: []byte(`{"n":2}`), Metadata: Metadata{EventID: "e2", CommandID: "c2", CorrelationID: "r2", OccurredAtUnixNanoUTC: 1, OccurredAtUnixNanoSet: true}}}},
	}}
	result, err := store.Commit(context.Background(), work)
	if err != nil { t.Fatal(err) }
	if len(result.Events) != 2 || result.Events[0].GlobalPosition != 1 || result.Events[1].GlobalPosition != 2 { t.Fatalf("events = %#v", result.Events) }
	if result.Events[0].Stream != work.Streams[0].Stream || result.Events[1].Stream != work.Streams[1].Stream { t.Fatalf("caller order not preserved: %#v", result.Events) }
}

func TestCommitRejectsEmptyWork(t *testing.T) {
	if err := ValidateUnitOfWork(UnitOfWork{}); !errors.Is(err, ErrEmptyUnitOfWork) { t.Fatalf("err = %v", err) }
}

func testStore(t *testing.T) (*GORMStore, *Database) {
	t.Helper()
	db, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "events.db")})
	if err != nil { t.Fatal(err) }
	return NewStore(db, WithPayloadCodec(task5Codec{})), db
}

func TestCommitRejectsDuplicateAndOversize(t *testing.T) {
	stream := StreamID{"a", "duplicate"}
	duplicate := UnitOfWork{Streams: []StreamAppend{{Stream:stream}, {Stream:stream}}}
	if err := ValidateUnitOfWork(duplicate); !errors.Is(err, ErrDuplicateStream) { t.Fatalf("duplicate err = %v", err) }
	oversized := UnitOfWork{Streams: []StreamAppend{{Stream:StreamID{"a","oversize"}, Events:[]NewEvent{{EventType:"x",SchemaVersion:1,Payload:make([]byte,MaxEventPayloadBytes+1),Metadata:Metadata{EventID:"e",CommandID:"c",CorrelationID:"r",OccurredAtUnixNanoUTC:1,OccurredAtUnixNanoSet:true}}}}}}
	var bound *OversizeError
	if err := ValidateUnitOfWork(oversized); !errors.As(err, &bound) || bound.Bound != "event payload" { t.Fatalf("oversize err = %v", err) }
	if err := ValidateUnitOfWork(UnitOfWork{Operations: []OperationUpdate{{OperationID:"dup"}, {OperationID:"dup"}}}); !errors.Is(err, ErrDuplicateParticipant) { t.Fatalf("participant duplicate err = %v", err) }
	streams := make([]StreamAppend, MaxUnitOfWorkStreams+1); for i := range streams { streams[i].Stream=StreamID{"bound",strconv.Itoa(i)} }
	if err := ValidateUnitOfWork(UnitOfWork{Streams:streams}); err == nil { t.Fatal("stream bound accepted") } else if bound,ok:=err.(*OversizeError); !ok || bound.Bound!="unit of work streams" { t.Fatalf("stream bound err = %v",err) }
	events := make([]NewEvent, MaxUnitOfWorkEvents+1); for i := range events { events[i]=testEvent(strconv.Itoa(i)) }
	if err := ValidateUnitOfWork(UnitOfWork{Streams:[]StreamAppend{{Stream:StreamID{"bound","events"},Events:events}}}); err == nil { t.Fatal("event bound accepted") } else if bound,ok:=err.(*OversizeError); !ok || bound.Bound!="unit of work events" { t.Fatalf("event bound err = %v",err) }
	bytes := make([]NewEvent, 65); for i := range bytes { bytes[i]=testEvent(strconv.Itoa(i)); bytes[i].Payload=make([]byte,MaxEventPayloadBytes) }
	if err := ValidateUnitOfWork(UnitOfWork{Streams:[]StreamAppend{{Stream:StreamID{"bound","bytes"},Events:bytes}}}); err == nil { t.Fatal("byte bound accepted") } else if bound,ok:=err.(*OversizeError); !ok || bound.Bound!="unit of work encoded bytes" { t.Fatalf("byte bound err = %v",err) }
	participantBytes := UnitOfWork{Operations: []OperationUpdate{{OperationID:"oversized-participant", PrivateContextCiphertext:make([]byte, MaxUnitOfWorkBytes)}}}
	if err := ValidateUnitOfWork(participantBytes); err == nil { t.Fatal("participant byte bound accepted") } else if bound,ok:=err.(*OversizeError); !ok || bound.Bound!="unit of work encoded bytes" { t.Fatalf("participant byte bound err = %v",err) }
	nearBytes := make([]NewEvent, 64)
	for i := range nearBytes { nearBytes[i] = testEvent(strconv.Itoa(i)); nearBytes[i].Payload = make([]byte, MaxEventPayloadBytes) }
	if err := ValidateUnitOfWork(UnitOfWork{Streams: []StreamAppend{{Stream: StreamID{"bound", "metadata"}, Events: nearBytes}}}); err == nil { t.Fatal("metadata byte bound accepted") } else if bound,ok:=err.(*OversizeError); !ok || bound.Bound!="unit of work encoded bytes" { t.Fatalf("metadata byte bound err = %v",err) }
}

func testEvent(id string) NewEvent {
	return NewEvent{EventType: "changed", SchemaVersion: 1, Payload: []byte(`{"value":1}`), Metadata: Metadata{EventID:id, CommandID:"cmd-"+id, CorrelationID:"corr-"+id, OccurredAtUnixNanoUTC:1, OccurredAtUnixNanoSet:true}}
}

func TestMultiStreamConflictReturnsCompleteSet(t *testing.T) {
	store, db := testStore(t); defer db.Close()
	first := UnitOfWork{Streams: []StreamAppend{{Stream:StreamID{"a","1"}, Events:[]NewEvent{testEvent("c1")}}, {Stream:StreamID{"b","1"}, Events:[]NewEvent{testEvent("c2")}}}}
	if _, err := store.Commit(context.Background(), first); err != nil { t.Fatal(err) }
	_, err := store.Commit(context.Background(), UnitOfWork{Streams: []StreamAppend{{Stream:StreamID{"a","1"}, ExpectedVersion:0, Events:[]NewEvent{testEvent("c3")}}, {Stream:StreamID{"b","1"}, ExpectedVersion:0, Events:[]NewEvent{testEvent("c4")}}}})
	var conflict *ConflictError
	if !errors.As(err, &conflict) || len(conflict.Conflicts) != 2 { t.Fatalf("err = %#v", err) }
}

func TestLockOrderAndZeroStreamParticipant(t *testing.T) {
	store, db := testStore(t); defer db.Close()
	var locks []string
	store.SetLockObserver(func(name string) { locks = append(locks, name) })
	if _, err := store.Commit(context.Background(), UnitOfWork{Streams: []StreamAppend{{Stream:StreamID{"z","1"}, Events:[]NewEvent{testEvent("l1")}}, {Stream:StreamID{"a","1"}, Events:[]NewEvent{testEvent("l2")}}}}); err != nil { t.Fatal(err) }
	if len(locks) < 3 || locks[0] != tableProjectionControl || locks[len(locks)-1] != tableEventGlobalSequence { t.Fatalf("lock order = %#v", locks) }
	locks = nil
	if _, err := store.Commit(context.Background(), UnitOfWork{PluginKVUpdates: []PluginKVUpdate{{ExtensionID:"ext",KeyHMAC:[]byte("key"),KeyCiphertext:[]byte("k"),ValueCiphertext:[]byte("v")}}}); err != nil { t.Fatal(err) }
	for _, lock := range locks { if lock == tableEventGlobalSequence { t.Fatal("zero-event participant advanced global sequence") } }
}

func TestRollbackAfterProjectorFailure(t *testing.T) {
	store, db := testStore(t); defer db.Close()
	var projectorCalls int
	store.RegisterProjector(func(_ context.Context, tx *gorm.DB, _ []Envelope) error {
		projectorCalls++
		if err := tx.Create(&projectionReadModelRow{ProjectionGeneration:"test", ProjectionName:"test", RowKey:"row", Payload:[]byte("opaque"), UpdatedAt:time.Now().UTC()}).Error; err != nil { return err }
		return errors.New("opaque projector failure")
	})
	_, err := store.Commit(context.Background(), UnitOfWork{Streams: []StreamAppend{{Stream:StreamID{"a","1"}, Events:[]NewEvent{testEvent("rb1")}}}})
	if !errors.Is(err, ErrProjectorFailure) { t.Fatalf("err = %v", err) }
	var events int64
	if err := db.GORM().Model(&domainEventRow{}).Count(&events).Error; err != nil { t.Fatal(err) }
	if events != 0 { t.Fatalf("events after rollback = %d", events) }
	var projected int64
	if err := db.GORM().Model(&projectionReadModelRow{}).Count(&projected).Error; err != nil { t.Fatal(err) }
	if projected != 0 { t.Fatalf("projector row after rollback = %d", projected) }
	if projectorCalls != 1 { t.Fatalf("projector calls = %d", projectorCalls) }
}
func TestRollbackAfterParticipantFailure(t *testing.T) {
	store, db := testStore(t); defer db.Close()
	store.RegisterParticipant(func(_ context.Context, tx *gorm.DB, _ UnitOfWork) error {
		if err := tx.Create(&operationRow{OperationID:"hook-operation", Version:1, Kind:"hook", Status:"pending", PrincipalID:"hook", IdempotencyScope:"hook", IdempotencyKey:"hook", CreatedAt:time.Now().UTC(), UpdatedAt:time.Now().UTC()}).Error; err != nil { return err }
		if err := tx.Create(&projectionReadModelRow{ProjectionGeneration:"participant", ProjectionName:"participant", RowKey:"row", Payload:[]byte("opaque"), UpdatedAt:time.Now().UTC()}).Error; err != nil { return err }
		return errors.New("opaque participant failure")
	})
	_, err := store.Commit(context.Background(), UnitOfWork{Streams: []StreamAppend{{Stream:StreamID{"a","participant"}, Events:[]NewEvent{testEvent("part1")}}}})
	if !errors.Is(err, ErrParticipantFailure) { t.Fatalf("err = %v", err) }
	var events, projected, operations int64
	if err := db.GORM().Model(&domainEventRow{}).Count(&events).Error; err != nil { t.Fatal(err) }
	if err := db.GORM().Model(&projectionReadModelRow{}).Count(&projected).Error; err != nil { t.Fatal(err) }
	if err := db.GORM().Model(&operationRow{}).Count(&operations).Error; err != nil { t.Fatal(err) }
	if events != 0 || projected != 0 || operations != 0 { t.Fatalf("rollback events=%d projected=%d operations=%d", events, projected, operations) }
}

func TestChecksumVerificationOnLoad(t *testing.T) {
	store, db := testStore(t); defer db.Close()
	if _, err := store.Commit(context.Background(), UnitOfWork{Streams: []StreamAppend{{Stream:StreamID{"a","1"}, Events:[]NewEvent{testEvent("sum1")}}}}); err != nil { t.Fatal(err) }
	if err := db.GORM().Model(&domainEventRow{}).Where("event_id = ?", "sum1").Update("payload", []byte("tampered")).Error; err != nil { t.Fatal(err) }
	_, err := store.Load(context.Background(), StreamID{"a","1"}, 1)
	if !errors.Is(err, ErrChecksumMismatch) { t.Fatalf("err = %v", err) }
}

func TestCommitConcurrentWritersNoDeadlock(t *testing.T) {
	store, db := testStore(t); defer db.Close()
	left := UnitOfWork{Streams: []StreamAppend{{Stream:StreamID{"a","1"}, Events:[]NewEvent{testEvent("cw1")}}, {Stream:StreamID{"b","1"}, Events:[]NewEvent{testEvent("cw2")}}}}
	right := UnitOfWork{Streams: []StreamAppend{{Stream:StreamID{"b","1"}, Events:[]NewEvent{testEvent("cw3")}}, {Stream:StreamID{"a","1"}, Events:[]NewEvent{testEvent("cw4")}}}}
	results := make(chan error, 2)
	go func(){ _, err := store.Commit(context.Background(), left); results <- err }()
	go func(){ _, err := store.Commit(context.Background(), right); results <- err }()
	var committed, conflicts int
	for range 2 { if err := <-results; err == nil { committed++ } else if errors.Is(err, ErrConflict) { conflicts++ } else { t.Fatalf("writer err = %v", err) } }
	if committed != 1 || conflicts != 1 { t.Fatalf("committed=%d conflicts=%d", committed, conflicts) }
}

func TestZeroStreamParticipantUpdates(t *testing.T) {
	store, db := testStore(t); defer db.Close()
	work := UnitOfWork{
		Operations: []OperationUpdate{{OperationID:"op-zero", PrincipalID:"p-zero"}},
		ArtifactUpdates: []ArtifactUpdate{{ArtifactID:"art-zero",OperationID:"op-zero",OwnerPrincipalID:"p-zero",Ciphertext:[]byte("sealed:artifact"),Nonce:[]byte("nonce"),EncryptionKeyID:"test-key",Size:8,Status:"ready"}},
		SecretUpdates: []SecretUpdate{{SecretRef:"secret-zero", Ciphertext:[]byte("secret"), Nonce:[]byte("nonce")}},
		PluginKVUpdates: []PluginKVUpdate{{ExtensionID:"plugin-zero", KeyHMAC:[]byte("key-zero"), KeyCiphertext:[]byte("key"), ValueCiphertext:[]byte("value")}},
		InboxUpdates: []InboxUpdate{{InboxID:"inbox-zero",EndpointID:"endpoint-zero",ProviderEventKey:"provider-zero",LaneHMAC:[]byte("in-lane"),OrderingSequence:99,Status:InboxStatusPending,PayloadCiphertext:[]byte("in-payload"),PayloadNonce:[]byte("in-nonce"),ContentDigest:[]byte("in-digest"),DigestKeyID:"in-key",WorkflowID:"workflow-zero"}},
		Effects: []NewEffect{{EffectID:"effect-zero",EndpointID:"endpoint-zero",LaneHMAC:[]byte("out-lane"),OrderingSequence:99,EffectType:"send",RiskClass:RiskPreDispatchRetryable,Status:OutboxStatusPending,PayloadCiphertext:[]byte("out-payload"),PayloadNonce:[]byte("out-nonce"),ContentDigest:[]byte("out-digest"),DigestKeyID:"out-key"}},
		FenceUpdates: []SubjectFenceUpdate{{SubjectKey:[]byte("subject-zero"), Scope:"all", PurgeOperationID:"op-zero"}},
	}
	result, err := store.Commit(context.Background(), work)
	if err != nil { t.Fatal(err) }
	if len(result.Events) != 0 || len(result.ArtifactIDs) != 1 || len(result.SecretRefs) != 1 || len(result.PluginKVIndexes) != 1 || len(result.InboxIDs) != 1 || len(result.EffectIDs) != 1 || len(result.FenceKeys) != 1 { t.Fatalf("result = %#v", result) }
	var sequence eventGlobalSequenceRow
	if err := db.GORM().First(&sequence).Error; err != nil { t.Fatal(err) }
	if sequence.NextPosition != 1 { t.Fatalf("sequence advanced to %d", sequence.NextPosition) }
	if _, err := store.Commit(context.Background(), UnitOfWork{ArtifactUpdates: []ArtifactUpdate{{ArtifactID:"art-zero",ExpectedVersion:1,OperationID:"op-zero"}}}); err != nil { t.Fatalf("artifact CAS update: %v", err) }
	if _, err := store.Commit(context.Background(), UnitOfWork{Operations: []OperationUpdate{{OperationID:"op-zero", ExpectedVersion:1, Status:"running"}}}); err != nil { t.Fatalf("sparse operation update: %v", err) }
	if _, err := store.Commit(context.Background(), UnitOfWork{InboxUpdates: []InboxUpdate{{InboxID:"inbox-zero",ExpectedVersion:1,Status:InboxStatusPending}}}); err != nil { t.Fatalf("sparse inbox update: %v", err) }
	var inboxRow inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", "inbox-zero").First(&inboxRow).Error; err != nil { t.Fatal(err) }
	if inboxRow.Version != 2 || inboxRow.Status != InboxStatusPending || inboxRow.OrderingSequence != 1 || string(inboxRow.PayloadCiphertext) != "in-payload" || inboxRow.WorkflowID != "workflow-zero" { t.Fatalf("inbox sparse preservation = %#v", inboxRow) }
	if _, err := store.Commit(context.Background(), UnitOfWork{Effects: []NewEffect{{EffectID:"effect-zero",ExpectedVersion:1,Status:OutboxStatusPending}}}); err != nil { t.Fatalf("sparse effect update: %v", err) }
	var effectRow outboxEffectRow
	if err := db.GORM().Where("effect_id = ?", "effect-zero").First(&effectRow).Error; err != nil { t.Fatal(err) }
	if effectRow.Version != 2 || effectRow.Status != OutboxStatusPending || effectRow.OrderingSequence != 1 || string(effectRow.PayloadCiphertext) != "out-payload" || effectRow.RiskClass != RiskPreDispatchRetryable { t.Fatalf("effect sparse preservation = %#v", effectRow) }
	pluginResult, err := store.Commit(context.Background(), UnitOfWork{PluginKVUpdates: []PluginKVUpdate{{ExtensionID:"plugin-zero", KeyHMAC:[]byte("key-zero"), ExpectedVersion:1, ValueCiphertext:[]byte("value-2")}}})
	if err != nil { t.Fatalf("sparse plugin update: %v", err) }
	if len(pluginResult.PluginKVIndexes) != 1 || string(pluginResult.PluginKVIndexes[0]) != "key-zero" { t.Fatalf("plugin update result = %#v", pluginResult) }
	
	var operation operationRow
	if err := db.GORM().Where("operation_id = ?", "op-zero").First(&operation).Error; err != nil { t.Fatal(err) }
	if operation.Version != 2 || operation.PrincipalID != "p-zero" || operation.Status != "running" { t.Fatalf("operation preservation = %#v", operation) }
	if _, err := store.Commit(context.Background(), UnitOfWork{FenceUpdates: []SubjectFenceUpdate{{SubjectKey:[]byte("subject-zero"), Scope:"all", ExpectedVersion:1, ExpiresAt:time.Now().Add(time.Hour)}}}); err != nil { t.Fatalf("sparse fence update: %v", err) }
	if _, err := store.Commit(context.Background(), UnitOfWork{FenceUpdates: []SubjectFenceUpdate{{SubjectKey:[]byte("subject-zero"), Scope:"all", ExpectedVersion:2, Deleted:true}}}); err != nil { t.Fatalf("fence delete: %v", err) }
	deleteResult, err := store.Commit(context.Background(), UnitOfWork{SecretUpdates: []SecretUpdate{{SecretRef:"secret-zero", ExpectedVersion:1, Ciphertext:[]byte("secret-2"), Nonce:[]byte("nonce-2")}}, PluginKVUpdates: []PluginKVUpdate{{ExtensionID:"plugin-zero", KeyHMAC:[]byte("key-zero"), ExpectedVersion:2, Deleted:true}}})
	if err != nil { t.Fatalf("history/delete update: %v", err) }
	if len(deleteResult.PluginKVIndexes) != 1 || string(deleteResult.PluginKVIndexes[0]) != "key-zero" { t.Fatalf("plugin delete result = %#v", deleteResult) }
	var secretRows, pluginRows int64
	if err := db.GORM().Model(&adapterSecretRow{}).Where("secret_ref = ?", "secret-zero").Count(&secretRows).Error; err != nil { t.Fatal(err) }
	if err := db.GORM().Model(&pluginKVRow{}).Where("extension_id = ?", "plugin-zero").Count(&pluginRows).Error; err != nil { t.Fatal(err) }
	if secretRows != 2 || pluginRows != 0 { t.Fatalf("secret history=%d plugin rows=%d", secretRows, pluginRows) }
}
func TestParticipantConflictIsTypedAndRedacted(t *testing.T) {
	store, db := testStore(t); defer db.Close()
	if _, err := store.Commit(context.Background(), UnitOfWork{Operations: []OperationUpdate{{OperationID:"secret-operation", Status:"pending"}}}); err != nil { t.Fatal(err) }
	_, err := store.Commit(context.Background(), UnitOfWork{Operations: []OperationUpdate{{OperationID:"secret-operation", ExpectedVersion:0, Status:"running"}}})
	if !errors.Is(err, ErrParticipantConflict) { t.Fatalf("errors.Is participant conflict = %v", err) }
	if err == nil || strings.Contains(err.Error(), "secret-operation") { t.Fatalf("participant error leaked key: %v", err) }
}

func TestVersionExhaustionRejectsWithoutMutation(t *testing.T) {
	if _, err := nextVersion(maxUint64); !errors.Is(err, ErrVersionExhausted) { t.Fatalf("next version exhaustion = %v", err) }
	if err := participantVersion(maxUint64, maxUint64, maxUint64, tableOperations, "<redacted>"); !errors.Is(err, ErrVersionExhausted) { t.Fatalf("participant version exhaustion = %v", err) }
	if _, err := nextVersion(maxUint64 - 1); err != nil { t.Fatalf("penultimate version rejected: %v", err) }
}
