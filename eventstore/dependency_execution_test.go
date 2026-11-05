package eventstore

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"
)

func dependencyProjectionRead(snapshot DependencySnapshot) ProjectionReadExpectation {
	return ProjectionReadExpectation{Generation: snapshot.ProjectionGeneration}
}

type pluginQuotaSnapshotGateKey struct{}
type executionAdmissionLockGateKey struct{}

func TestReadDependencyConflictsOnlyWhenObservedStreamChanges(t *testing.T) {
	ctx := context.Background()

	t.Run("read A write B conflicts after A changes", func(t *testing.T) {
		store, database := testStore(t)
		defer database.Close()
		a := StreamID{AggregateType: "dependency", AggregateID: "a"}
		b := StreamID{AggregateType: "dependency", AggregateID: "b"}
		if _, err := store.Commit(ctx, UnitOfWork{Streams: []StreamAppend{{Stream: a, Events: []NewEvent{testEvent("dependency-a-1")}}}}); err != nil {
			t.Fatal(err)
		}
		snapshot, err := store.LoadStreamSnapshot(ctx, a, 0)
		if err != nil || snapshot.Version != 1 {
			t.Fatalf("snapshot = %+v, err = %v", snapshot, err)
		}
		if _, err = store.Commit(ctx, UnitOfWork{Streams: []StreamAppend{{Stream: a, ExpectedVersion: 1, Events: []NewEvent{testEvent("dependency-a-2")}}}}); err != nil {
			t.Fatal(err)
		}
		_, err = store.Commit(ctx, UnitOfWork{
			StreamReads:     []StreamReadExpectation{{Stream: a, ExpectedVersion: snapshot.Version}},
			ProjectionReads: []ProjectionReadExpectation{dependencyProjectionRead(snapshot.Snapshot)},
			Streams:         []StreamAppend{{Stream: b, Events: []NewEvent{testEvent("dependency-b-rejected")}}},
		})
		if !errors.Is(err, ErrConflict) {
			t.Fatalf("read conflict err = %v", err)
		}
		if events, loadErr := store.Load(ctx, b, 0); loadErr != nil || len(events) != 0 {
			t.Fatalf("rejected B write events = %#v, err = %v", events, loadErr)
		}
	})

	t.Run("unrelated write does not conflict", func(t *testing.T) {
		store, database := testStore(t)
		defer database.Close()
		a := StreamID{AggregateType: "dependency", AggregateID: "a"}
		b := StreamID{AggregateType: "dependency", AggregateID: "b"}
		c := StreamID{AggregateType: "dependency", AggregateID: "c"}
		if _, err := store.Commit(ctx, UnitOfWork{Streams: []StreamAppend{{Stream: a, Events: []NewEvent{testEvent("unrelated-a")}}}}); err != nil {
			t.Fatal(err)
		}
		snapshot, err := store.LoadStreamSnapshot(ctx, a, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = store.Commit(ctx, UnitOfWork{Streams: []StreamAppend{{Stream: c, Events: []NewEvent{testEvent("unrelated-c")}}}}); err != nil {
			t.Fatal(err)
		}
		if _, err = store.Commit(ctx, UnitOfWork{
			StreamReads:     []StreamReadExpectation{{Stream: a, ExpectedVersion: snapshot.Version}},
			ProjectionReads: []ProjectionReadExpectation{dependencyProjectionRead(snapshot.Snapshot)},
			Streams:         []StreamAppend{{Stream: b, Events: []NewEvent{testEvent("unrelated-b")}}},
		}); err != nil {
			t.Fatalf("unrelated write caused conflict: %v", err)
		}
	})
}

func TestAbsentStreamReadConflictsWithConcurrentCreate(t *testing.T) {
	store, database := testStore(t)
	defer database.Close()
	ctx := context.Background()
	absent := StreamID{AggregateType: "dependency", AggregateID: "absent"}
	other := StreamID{AggregateType: "dependency", AggregateID: "other"}
	snapshot, err := store.LoadStreamSnapshot(ctx, absent, 0)
	if err != nil || snapshot.Version != 0 || len(snapshot.Events) != 0 {
		t.Fatalf("absent snapshot = %+v, err = %v", snapshot, err)
	}
	if _, err = store.Commit(ctx, UnitOfWork{Streams: []StreamAppend{{Stream: absent, Events: []NewEvent{testEvent("absent-created")}}}}); err != nil {
		t.Fatal(err)
	}
	_, err = store.Commit(ctx, UnitOfWork{
		StreamReads:     []StreamReadExpectation{{Stream: absent, ExpectedVersion: 0}},
		ProjectionReads: []ProjectionReadExpectation{dependencyProjectionRead(snapshot.Snapshot)},
		Streams:         []StreamAppend{{Stream: other, Events: []NewEvent{testEvent("absent-other")}}},
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("absent/create race err = %v", err)
	}
}

func TestPluginNamespaceRevisionDetectsListPhantomAndDeletionABA(t *testing.T) {
	store, database := openPlainTestStore(t)
	defer database.Close()
	ctx := context.Background()
	listed, err := store.ListPluginKVSnapshot(ctx, PluginKVListRequest{ExtensionID: "dependency-plugin", Prefix: "role:"})
	if err != nil || len(listed.Items) != 0 || listed.NamespaceRevision != 0 {
		t.Fatalf("initial list = %+v, err = %v", listed, err)
	}
	item, err := store.SetPluginKV(ctx, PluginKVPutRequest{ExtensionID: "dependency-plugin", Key: "role:alice", Value: []byte("one")})
	if err != nil {
		t.Fatal(err)
	}
	if err = store.DeletePluginKV(ctx, "dependency-plugin", "role:alice", item.Version); err != nil {
		t.Fatal(err)
	}
	if _, err = store.SetPluginKV(ctx, PluginKVPutRequest{ExtensionID: "dependency-plugin", Key: "role:alice", Value: []byte("two")}); err != nil {
		t.Fatal(err)
	}
	_, err = store.Commit(ctx, UnitOfWork{
		PluginKVNamespaceReads: []PluginKVNamespaceReadExpectation{{Namespace: listed.Namespace, ExpectedRevision: listed.NamespaceRevision}},
		ProjectionReads:        []ProjectionReadExpectation{dependencyProjectionRead(listed.Snapshot)},
		Streams:                []StreamAppend{{Stream: StreamID{AggregateType: "dependency", AggregateID: "namespace-write"}, Events: []NewEvent{testEvent("namespace-rejected")}}},
	})
	if !errors.Is(err, ErrParticipantConflict) {
		t.Fatalf("namespace ABA err = %v", err)
	}
}

func TestPluginAbsentLookupRevisionDetectsCreate(t *testing.T) {
	store, database := openPlainTestStore(t)
	defer database.Close()
	ctx := context.Background()
	lookup, err := store.LookupPluginKVSnapshot(ctx, "dependency-plugin", "missing")
	if err != nil || lookup.Found || lookup.KeyRevision != 0 {
		t.Fatalf("lookup = %+v, err = %v", lookup, err)
	}
	if _, err = store.SetPluginKV(ctx, PluginKVPutRequest{ExtensionID: "dependency-plugin", Key: "missing", Value: []byte("created")}); err != nil {
		t.Fatal(err)
	}
	_, err = store.Commit(ctx, UnitOfWork{
		PluginKVReads: []PluginKVReadExpectation{{
			Namespace:        lookup.Namespace,
			Key:              lookup.Key,
			ExpectedRevision: lookup.KeyRevision,
			ExpectedExists:   false,
		}},
		ProjectionReads: []ProjectionReadExpectation{dependencyProjectionRead(lookup.Snapshot)},
		Streams:         []StreamAppend{{Stream: StreamID{AggregateType: "dependency", AggregateID: "key-write"}, Events: []NewEvent{testEvent("key-rejected")}}},
	})
	if !errors.Is(err, ErrParticipantConflict) {
		t.Fatalf("absent key/create race err = %v", err)
	}
}

func TestSetPluginKVRejectsStaleNamespaceQuotaSnapshot(t *testing.T) {
	store, database := openPlainTestStore(t)
	defer database.Close()
	const callbackName = "test:set-plugin-kv-namespace-snapshot-gate"
	observed := make(chan struct{})
	release := make(chan struct{})
	var observedOnce sync.Once
	if err := database.ReadGORM().Callback().Query().After("gorm:query").Register(callbackName, func(tx *gorm.DB) {
		if tx.Statement.Context.Value(pluginQuotaSnapshotGateKey{}) != true || tx.Statement.Table != tablePluginKV {
			return
		}
		observedOnce.Do(func() { close(observed) })
		<-release
	}); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := database.ReadGORM().Callback().Query().Remove(callbackName); err != nil {
			t.Errorf("remove plugin snapshot callback: %v", err)
		}
	}()
	type setResult struct {
		item PluginKVItem
		err  error
	}
	result := make(chan setResult, 1)
	staleCtx := context.WithValue(context.Background(), pluginQuotaSnapshotGateKey{}, true)
	go func() {
		item, err := store.SetPluginKV(staleCtx, PluginKVPutRequest{
			ExtensionID: "quota-race", Key: "stale", Value: []byte("stale"),
		})
		result <- setResult{item: item, err: err}
	}()
	<-observed
	winner, err := store.SetPluginKV(context.Background(), PluginKVPutRequest{
		ExtensionID: "quota-race", Key: "winner", Value: []byte("winner"),
	})
	if err != nil || winner.Version != 1 {
		t.Fatalf("concurrent namespace winner = %+v, err = %v", winner, err)
	}
	close(release)
	stale := <-result
	if !errors.Is(stale.err, ErrParticipantConflict) || stale.item.Version != 0 {
		t.Fatalf("stale namespace writer = %+v, err = %v", stale.item, stale.err)
	}
	lookup, err := store.LookupPluginKVSnapshot(context.Background(), "quota-race", "stale")
	if err != nil || lookup.Found {
		t.Fatalf("stale key escaped namespace conflict: %+v, err = %v", lookup, err)
	}
}

func TestCatalogRevisionIsScopedAndMonotonic(t *testing.T) {
	store, database := openPlainTestStore(t)
	defer database.Close()
	ctx := context.Background()
	alice, err := store.ReadCatalogRevision(ctx, "characters", "user:alice")
	if err != nil || alice.Revision != 0 {
		t.Fatalf("alice catalog = %+v, err = %v", alice, err)
	}
	bob, err := store.ReadCatalogRevision(ctx, "characters", "user:bob")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Commit(ctx, UnitOfWork{
		CatalogUpdates: []CatalogRevisionUpdate{{Catalog: alice.Catalog, Owner: alice.Owner, ExpectedRevision: alice.Revision}},
		Streams:        []StreamAppend{{Stream: StreamID{AggregateType: "character", AggregateID: "alice-one"}, Events: []NewEvent{testEvent("catalog-alice")}}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Commit(ctx, UnitOfWork{
		CatalogReads:    []CatalogReadExpectation{{Catalog: bob.Catalog, Owner: bob.Owner, ExpectedRevision: bob.Revision}},
		ProjectionReads: []ProjectionReadExpectation{dependencyProjectionRead(bob.Snapshot)},
		Streams:         []StreamAppend{{Stream: StreamID{AggregateType: "dependency", AggregateID: "bob-unrelated"}, Events: []NewEvent{testEvent("catalog-bob")}}},
	}); err != nil {
		t.Fatalf("other owner catalog caused conflict: %v", err)
	}
	_, err = store.Commit(ctx, UnitOfWork{
		CatalogReads:    []CatalogReadExpectation{{Catalog: alice.Catalog, Owner: alice.Owner, ExpectedRevision: alice.Revision}},
		ProjectionReads: []ProjectionReadExpectation{dependencyProjectionRead(alice.Snapshot)},
		Streams:         []StreamAppend{{Stream: StreamID{AggregateType: "dependency", AggregateID: "alice-stale"}, Events: []NewEvent{testEvent("catalog-stale")}}},
	})
	if !errors.Is(err, ErrParticipantConflict) {
		t.Fatalf("stale catalog err = %v", err)
	}
}

func TestProjectionDependencyLookupReturnsRowStreamAndSnapshotTogether(t *testing.T) {
	store, database := testStore(t)
	defer database.Close()
	ctx := context.Background()
	stream := StreamID{AggregateType: "character", AggregateID: "lookup-one"}
	if _, err := store.Commit(ctx, UnitOfWork{Streams: []StreamAppend{{Stream: stream, Events: []NewEvent{testEvent("projection-lookup")}}}}); err != nil {
		t.Fatal(err)
	}
	var control projectionControlRow
	if err := database.GORM().Where("singleton_id = ?", "default").First(&control).Error; err != nil {
		t.Fatal(err)
	}
	row := projectionReadModelRow{
		ProjectionGeneration: control.ActiveGeneration, ProjectionName: "characters", RowKey: "lookup-one",
	}
	if err := database.GORM().Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.ReadProjectionDependency(ctx, "characters", "lookup-one", stream)
	if err != nil || !snapshot.Found || snapshot.StreamVersion != 1 ||
		snapshot.Snapshot.ProjectionGeneration != control.ActiveGeneration ||
		!bytes.Equal(snapshot.Row.Payload, row.Payload) {
		t.Fatalf("projection dependency = %+v, err = %v", snapshot, err)
	}
}

func TestCatalogProjectionPageCarriesGuardsAndRejectsMixedSnapshot(t *testing.T) {
	store, database := openPlainTestStore(t)
	defer database.Close()
	ctx := context.Background()
	var control projectionControlRow
	if err := database.GORM().Where("singleton_id = ?", "default").First(&control).Error; err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"owner:alice:a", "owner:alice:b"} {
		row := projectionReadModelRow{
			ProjectionGeneration: control.ActiveGeneration, ProjectionName: "characters", RowKey: key,
		}
		if err := database.GORM().Create(&row).Error; err != nil {
			t.Fatal(err)
		}
	}
	first, err := store.ListCatalogProjectionSnapshot(ctx, CatalogProjectionListRequest{
		Catalog: "characters", Owner: "user:alice", ProjectionName: "characters", RowKeyPrefix: "owner:alice:", Limit: 1,
	})
	if err != nil || len(first.Rows) != 1 || first.Done || first.NextRowKey != first.Rows[0].RowKey ||
		first.CatalogRevision != 0 || first.Snapshot.ProjectionGeneration != control.ActiveGeneration {
		t.Fatalf("first catalog page = %+v, err = %v", first, err)
	}
	if _, err = store.Commit(ctx, UnitOfWork{CatalogUpdates: []CatalogRevisionUpdate{{
		Catalog: first.Catalog, Owner: first.Owner, ExpectedRevision: first.CatalogRevision,
	}}}); err != nil {
		t.Fatal(err)
	}
	expectedRevision := first.CatalogRevision
	expectedSnapshot := first.Snapshot
	_, err = store.ListCatalogProjectionSnapshot(ctx, CatalogProjectionListRequest{
		Catalog: "characters", Owner: "user:alice", ProjectionName: "characters", RowKeyPrefix: "owner:alice:",
		AfterRowKey: first.NextRowKey, Limit: 1, ExpectedCatalogRevision: &expectedRevision, ExpectedSnapshot: &expectedSnapshot,
	})
	if !errors.Is(err, ErrParticipantConflict) {
		t.Fatalf("mixed catalog snapshot err = %v", err)
	}
}

func TestReadDependenciesCountBytesButNotWriteStreamLimit(t *testing.T) {
	reads := make([]StreamReadExpectation, MaxUnitOfWorkStreams+1)
	for i := range reads {
		reads[i] = StreamReadExpectation{Stream: StreamID{AggregateType: "read", AggregateID: string(rune(i + 1))}}
	}
	if err := ValidateUnitOfWork(UnitOfWork{StreamReads: reads, Operations: []OperationUpdate{{OperationID: "read-count"}}}); err != nil {
		t.Fatalf("read count inherited write-stream bound: %v", err)
	}
	oversize := UnitOfWork{
		StreamReads: []StreamReadExpectation{{Stream: StreamID{AggregateType: "read", AggregateID: strings.Repeat("x", MaxUnitOfWorkBytes)}}},
		Operations:  []OperationUpdate{{OperationID: "read-bytes"}},
	}
	var bound *OversizeError
	if err := ValidateUnitOfWork(oversize); !errors.As(err, &bound) || bound.Bound != "unit of work encoded bytes" {
		t.Fatalf("read dependency byte bound err = %v", err)
	}
	stream := StreamID{AggregateType: "read", AggregateID: "same"}
	if err := ValidateUnitOfWork(UnitOfWork{
		StreamReads: []StreamReadExpectation{{Stream: stream, ExpectedVersion: 1}},
		Streams:     []StreamAppend{{Stream: stream, ExpectedVersion: 2, Events: []NewEvent{testEvent("mismatched-read-write")}}},
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("mismatched read/write expectation err = %v", err)
	}
}

func TestExecutionAdmissionDeduplicatesIdentityAndDigest(t *testing.T) {
	ctx := context.Background()
	clock := &outboxRecoveryClock{now: time.Unix(100, 0).UTC()}
	ids := &outboxRecoveryIDs{}
	store, database := openOutboxRecoveryStore(t, filepath.Join(t.TempDir(), "execution.db"), clock, ids, true)
	defer database.Close()
	digest := bytes.Repeat([]byte{0x41}, 32)
	largeDigest, err := store.ExecutionRequestDigest(ctx, make([]byte, 1024*1024+1))
	if err != nil || len(largeDigest) != 32 {
		t.Fatalf("normal-sized canonical execution input rejected: digest=%x err=%v", largeDigest, err)
	}
	first, err := store.AdmitExecution(ctx, ExecutionAdmissionRequest{Identity: "cron:daily:2026-10-30", RequestDigest: digest, LeaseOwner: "worker-a", LeaseDuration: time.Minute})
	if err != nil || !first.Admitted || first.Status != ExecutionStatusStarted || first.AttemptID == "" {
		t.Fatalf("first admission = %+v, err = %v", first, err)
	}
	duplicate, err := store.AdmitExecution(ctx, ExecutionAdmissionRequest{Identity: "cron:daily:2026-10-30", RequestDigest: digest, LeaseOwner: "worker-b", LeaseDuration: time.Minute})
	if err != nil || duplicate.Admitted || duplicate.AttemptID != first.AttemptID || duplicate.Version != first.Version {
		t.Fatalf("duplicate admission = %+v, err = %v", duplicate, err)
	}
	_, err = store.AdmitExecution(ctx, ExecutionAdmissionRequest{Identity: "cron:daily:2026-10-30", RequestDigest: bytes.Repeat([]byte{0x42}, 32), LeaseOwner: "worker-c", LeaseDuration: time.Minute})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("different digest admission err = %v", err)
	}
	var row executionReceiptRow
	if err = database.GORM().First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Identity != "cron:daily:2026-10-30" {
		t.Fatalf("receipt identity = %q, want plaintext identity", row.Identity)
	}
	concurrentDigest := bytes.Repeat([]byte{0x43}, 32)
	start := make(chan struct{})
	results := make(chan ExecutionReceipt, 2)
	errs := make(chan error, 2)
	var wait sync.WaitGroup
	for _, owner := range []string{"worker-d", "worker-e"} {
		wait.Add(1)
		go func(owner string) {
			defer wait.Done()
			<-start
			receipt, admissionErr := store.AdmitExecution(ctx, ExecutionAdmissionRequest{
				Identity: "cron:concurrent", RequestDigest: concurrentDigest, LeaseOwner: owner, LeaseDuration: time.Minute,
			})
			results <- receipt
			errs <- admissionErr
		}(owner)
	}
	close(start)
	wait.Wait()
	close(results)
	close(errs)
	for admissionErr := range errs {
		if admissionErr != nil {
			t.Fatalf("concurrent admission err = %v", admissionErr)
		}
	}
	admittedCount := 0
	attemptID := ""
	for receipt := range results {
		if receipt.Admitted {
			admittedCount++
		}
		if attemptID == "" {
			attemptID = receipt.AttemptID
		} else if receipt.AttemptID != attemptID {
			t.Fatalf("concurrent admissions attached different attempts: %q != %q", receipt.AttemptID, attemptID)
		}
	}
	if admittedCount != 1 {
		t.Fatalf("concurrent admitted hosts = %d, want 1", admittedCount)
	}
}

func TestExecutionAdmissionLeaseStartsAfterAdmissionLock(t *testing.T) {
	ctx := context.Background()
	clock := &outboxRecoveryClock{now: time.Unix(100, 0).UTC()}
	ids := &outboxRecoveryIDs{}
	store, database := openOutboxRecoveryStore(t, filepath.Join(t.TempDir(), "execution-delayed-admission.db"), clock, ids, true)
	defer database.Close()
	const identity = "cron:delayed-admission"
	identityKey := identity
	var err error
	if _, err = store.ensureExecutionAdmissionHead(ctx, identityKey); err != nil {
		t.Fatal(err)
	}
	const callbackName = "test:execution-admission-lock-gate"
	waiting := make(chan struct{})
	release := make(chan struct{})
	var waitingOnce sync.Once
	if err = database.GORM().Callback().Query().Before("gorm:query").Register(callbackName, func(tx *gorm.DB) {
		if tx.Statement.Context.Value(executionAdmissionLockGateKey{}) != true || tx.Statement.Table != tableRevisionHeads {
			return
		}
		waitingOnce.Do(func() { close(waiting) })
		<-release
	}); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := database.GORM().Callback().Query().Remove(callbackName); err != nil {
			t.Errorf("remove admission lock callback: %v", err)
		}
	}()
	type admissionResult struct {
		receipt ExecutionReceipt
		err     error
	}
	result := make(chan admissionResult, 1)
	admissionCtx := context.WithValue(ctx, executionAdmissionLockGateKey{}, true)
	go func() {
		receipt, admissionErr := store.AdmitExecution(admissionCtx, ExecutionAdmissionRequest{
			Identity: identity, RequestDigest: bytes.Repeat([]byte{0x47}, 32),
			LeaseOwner: "worker-delayed", LeaseDuration: time.Minute,
		})
		result <- admissionResult{receipt: receipt, err: admissionErr}
	}()
	<-waiting
	clock.Advance(2 * time.Minute)
	startedAt := clock.Now()
	close(release)
	admitted := <-result
	if admitted.err != nil || !admitted.receipt.Admitted {
		t.Fatalf("delayed admission = %+v, err = %v", admitted.receipt, admitted.err)
	}
	if !admitted.receipt.StartedAt.Equal(startedAt) ||
		!admitted.receipt.LeaseExpiresAt.Equal(startedAt.Add(time.Minute)) {
		t.Fatalf("lease was not based on post-lock time: %+v, want start=%v", admitted.receipt, startedAt)
	}
}

func TestExecutionOwnerCanTerminateLiveAttemptButForeignRecoveryCannot(t *testing.T) {
	ctx := context.Background()
	clock := &outboxRecoveryClock{now: time.Unix(100, 0).UTC()}
	ids := &outboxRecoveryIDs{}
	store, database := openOutboxRecoveryStore(t, filepath.Join(t.TempDir(), "execution-owner-recovery.db"), clock, ids, true)
	defer database.Close()
	digest := bytes.Repeat([]byte{0x49}, 32)
	admitted, err := store.AdmitExecution(ctx, ExecutionAdmissionRequest{
		Identity: "cron:live", RequestDigest: digest, LeaseOwner: "worker-a", LeaseDuration: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := ExecutionRecoveryRequest{
		Identity: "cron:live", RequestDigest: digest, AttemptID: admitted.AttemptID, ExpectedVersion: admitted.Version,
	}
	if _, err = store.RecoverExecution(ctx, request); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("foreign recovery stole live lease: %v", err)
	}
	request.LeaseOwner = "worker-b"
	request.LeaseEpoch = admitted.LeaseEpoch
	if _, err = store.RecoverExecution(ctx, request); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("wrong owner terminated live lease: %v", err)
	}
	request.LeaseOwner = admitted.LeaseOwner
	recovered, err := store.RecoverExecution(ctx, request)
	if err != nil || recovered.Status != ExecutionStatusAmbiguous || recovered.Version != admitted.Version+1 {
		t.Fatalf("owner recovery = %+v, err = %v", recovered, err)
	}
}

func TestExecutionRecoveryBeatsLateBusinessCommitAndRollsItBack(t *testing.T) {
	ctx := context.Background()
	clock := &outboxRecoveryClock{now: time.Unix(100, 0).UTC()}
	ids := &outboxRecoveryIDs{}
	store, database := openOutboxRecoveryStore(t, filepath.Join(t.TempDir(), "execution-race.db"), clock, ids, true)
	defer database.Close()
	digest := bytes.Repeat([]byte{0x51}, 32)
	admitted, err := store.AdmitExecution(ctx, ExecutionAdmissionRequest{Identity: "notification:one", RequestDigest: digest, LeaseOwner: "worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	recovered, err := store.RecoverExecution(ctx, ExecutionRecoveryRequest{
		Identity: "notification:one", RequestDigest: digest, AttemptID: admitted.AttemptID, ExpectedVersion: admitted.Version,
	})
	if err != nil || recovered.Status != ExecutionStatusAmbiguous || recovered.Version != admitted.Version+1 {
		t.Fatalf("recovery = %+v, err = %v", recovered, err)
	}
	business := StreamID{AggregateType: "dependency", AggregateID: "late-business"}
	_, err = store.Commit(ctx, UnitOfWork{
		Streams: []StreamAppend{{Stream: business, Events: []NewEvent{testEvent("late-business")}}},
		Execution: &ExecutionAttemptCommit{
			Identity: "notification:one", RequestDigest: digest, AttemptID: admitted.AttemptID,
			ExpectedVersion: admitted.Version, LeaseOwner: admitted.LeaseOwner, LeaseEpoch: admitted.LeaseEpoch,
		},
	})
	if !errors.Is(err, ErrParticipantConflict) {
		t.Fatalf("late commit err = %v", err)
	}
	if events, loadErr := store.Load(ctx, business, 0); loadErr != nil || len(events) != 0 {
		t.Fatalf("late business write escaped rollback: %#v, err = %v", events, loadErr)
	}
	lookup, err := store.LookupExecution(ctx, "notification:one")
	if err != nil || lookup.Status != ExecutionStatusAmbiguous {
		t.Fatalf("lookup after recovery = %+v, err = %v", lookup, err)
	}
	unknown, err := store.LookupExecution(ctx, "notification:missing")
	if err != nil || unknown.Status != ExecutionStatusUnknown {
		t.Fatalf("missing receipt is not unknown: %+v, err = %v", unknown, err)
	}
}
