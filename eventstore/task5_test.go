package eventstore

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"
)

type task5Clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *task5Clock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *task5Clock) Advance(d time.Duration) { c.mu.Lock(); c.now = c.now.Add(d); c.mu.Unlock() }

type task5Codec struct{}

func (task5Codec) Encrypt(_ context.Context, plaintext []byte) ([]byte, []byte, string, error) {
	return append([]byte("sealed:"), plaintext...), []byte("nonce"), "test-key", nil
}
func (task5Codec) Decrypt(_ context.Context, ciphertext, _ []byte, _ string) ([]byte, error) {
	const prefix = "sealed:"
	if len(ciphertext) < len(prefix) || string(ciphertext[:len(prefix)]) != prefix {
		return nil, errors.New("bad ciphertext")
	}
	return append([]byte(nil), ciphertext[len(prefix):]...), nil
}

type task5CorruptCodec struct {
	plaintext []byte
}

func (task5CorruptCodec) Encrypt(_ context.Context, plaintext []byte) ([]byte, []byte, string, error) {
	return append([]byte("sealed:"), plaintext...), []byte("nonce"), "test-key", nil
}
func (c task5CorruptCodec) Decrypt(_ context.Context, _ []byte, _ []byte, _ string) ([]byte, error) {
	return append([]byte(nil), c.plaintext...), nil
}

func task5Store(t *testing.T) (*GORMStore, *Database, *task5Clock) {
	t.Helper()
	db, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "task5.db")})
	if err != nil {
		t.Fatal(err)
	}
	clock := &task5Clock{now: time.Unix(100, 0).UTC()}
	return NewStore(db, WithClock(clock), WithPayloadCodec(task5Codec{})), db, clock
}
func TestQuarantineOutboxScrubsLeaseAndAppendsAuditedFailure(t *testing.T) {
	store, db, _ := task5Store(t)
	defer db.Close()
	ctx := context.Background()
	effect := task5Effect("quarantine-effect", "quarantine-lane")
	if _, err := store.AcceptOutbox(ctx, effect); err != nil {
		t.Fatal(err)
	}
	sourcePayload := []byte(`{"effectId":"quarantine-effect","operationId":"quarantine-operation","endpointId":"endpoint"}`)
	if _, err := store.Commit(ctx, UnitOfWork{
		Streams: []StreamAppend{{Stream: StreamID{AggregateType: "outbound-effect", AggregateID: effect.EffectID}, Events: []NewEvent{{
			EventType: "OutboundEffectRequestedV1", SchemaVersion: 1, Payload: sourcePayload,
			Metadata: Metadata{EventID: "source-event", CommandID: "source-command", CorrelationID: "source-correlation", PrincipalID: "source-principal", OccurredAt: time.Unix(100, 0).UTC()},
		}}}},
		Operations: []OperationUpdate{{OperationID: "quarantine-operation", ExpectedVersion: 0, Version: 1, Status: "pending", PrincipalID: "source-principal", ResourceID: effect.EffectID}},
	}); err != nil {
		t.Fatal(err)
	}
	lease, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "quarantine-worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Model(&storeReadinessRow{}).Where("singleton_id = ?", "default").Update("mode", "import").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.QuarantineOutbox(ctx, OutboxQuarantineRequest{
		EffectID: lease.Effect.EffectID, ExpectedVersion: lease.Effect.Version,
		WorkerID: lease.Effect.LeaseOwner, LeaseEpoch: lease.Effect.LeaseEpoch, AttemptID: lease.Effect.AttemptID,
		ErrorCode: "raw-token-/secret", Reason: "raw /path/token",
	}); err != nil {
		t.Fatal(err)
	}
	var outbox outboxEffectRow
	if err := db.GORM().Where("effect_id = ?", effect.EffectID).First(&outbox).Error; err != nil {
		t.Fatal(err)
	}
	if outbox.Status != OutboxStatusFailed || outbox.LeaseExpiry != nil || len(outbox.PayloadCiphertext) != 0 || len(outbox.PayloadNonce) != 0 {
		t.Fatalf("quarantined outbox = %#v", outbox)
	}
	if outbox.ErrorCode == "raw-token-/secret" || outbox.ResolutionReason == "raw /path/token" {
		t.Fatalf("quarantine retained raw diagnostic: %#v", outbox)
	}
	var operation operationRow
	if err := db.GORM().Where("operation_id = ?", "quarantine-operation").First(&operation).Error; err != nil {
		t.Fatal(err)
	}
	if operation.Status != "failed" || operation.Version != 2 || operation.ErrorCode == "" {
		t.Fatalf("quarantined operation = %#v", operation)
	}
	events, err := store.Load(ctx, StreamID{AggregateType: "outbound-effect", AggregateID: effect.EffectID}, 2)
	if err != nil || len(events) != 1 {
		t.Fatalf("quarantine result events=%#v err=%v", events, err)
	}
	var readiness storeReadinessRow
	if err := db.GORM().Where("singleton_id = ?", "default").First(&readiness).Error; err != nil {
		t.Fatal(err)
	}
	if readiness.TerminalGlobalPosition != events[0].GlobalPosition || readiness.TerminalProjectionPosition != events[0].GlobalPosition {
		t.Fatalf("import readiness terminals = global %d/projection %d, event %d", readiness.TerminalGlobalPosition, readiness.TerminalProjectionPosition, events[0].GlobalPosition)
	}
	if events[0].EventType != "OutboundEffectFailedV1" || string(events[0].Payload) == "" || string(events[0].Payload) == string(sourcePayload) {
		t.Fatalf("quarantine result event = %#v", events[0])
	}
	if bytes.Contains(events[0].Payload, []byte("raw-token")) || bytes.Contains(events[0].Payload, []byte("/path/token")) {
		t.Fatalf("quarantine event retained raw diagnostic: %s", events[0].Payload)
	}
}
func TestQuarantineOutboxAfterDispatchSettlesAmbiguous(t *testing.T) {
	store, db, _ := task5Store(t)
	defer db.Close()
	ctx := context.Background()
	effect := task5Effect("quarantine-dispatched", "quarantine-dispatched-lane")
	effect.RiskClass = RiskNonIdempotentAfterDispatch
	if _, err := store.AcceptOutbox(ctx, effect); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{
		Streams: []StreamAppend{{Stream: StreamID{AggregateType: "outbound-effect", AggregateID: effect.EffectID}, Events: []NewEvent{{
			EventType: "OutboundEffectRequestedV1", SchemaVersion: 1,
			Payload: []byte(`{"effectId":"quarantine-dispatched","operationId":"quarantine-dispatched-operation","endpointId":"endpoint"}`),
			Metadata: Metadata{EventID: "source-event", CommandID: "source-command", CorrelationID: "source-correlation", PrincipalID: "source-principal", OccurredAt: time.Unix(100, 0).UTC()},
		}}}},
		Operations: []OperationUpdate{{OperationID: "quarantine-dispatched-operation", ExpectedVersion: 0, Version: 1, Status: "pending", PrincipalID: "source-principal", ResourceID: effect.EffectID}},
	}); err != nil {
		t.Fatal(err)
	}
	lease, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "quarantine-worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	dispatched, err := store.MarkOutboxDispatched(ctx, OutboxDispatchRequest{EffectID: effect.EffectID, WorkerID: lease.Effect.LeaseOwner, LeaseEpoch: lease.Effect.LeaseEpoch, AttemptID: lease.Effect.AttemptID})
	if err != nil {
		t.Fatal(err)
	}
	req := OutboxQuarantineRequest{EffectID: effect.EffectID, ExpectedVersion: dispatched.Effect.Version, WorkerID: dispatched.Effect.LeaseOwner, LeaseEpoch: dispatched.Effect.LeaseEpoch, AttemptID: dispatched.Effect.AttemptID, ErrorCode: "terminal-persistence", Reason: "terminal persistence failed"}
	if _, err := store.QuarantineOutbox(ctx, req); err != nil {
		t.Fatal(err)
	}
	var outbox outboxEffectRow
	if err := db.GORM().Where("effect_id = ?", effect.EffectID).First(&outbox).Error; err != nil {
		t.Fatal(err)
	}
	if outbox.Status != OutboxStatusAmbiguous {
		t.Fatalf("quarantined dispatched outbox status = %q, want %q", outbox.Status, OutboxStatusAmbiguous)
	}
	var operation operationRow
	if err := db.GORM().Where("operation_id = ?", "quarantine-dispatched-operation").First(&operation).Error; err != nil {
		t.Fatal(err)
	}
	if operation.Status != "ambiguous" {
		t.Fatalf("quarantined dispatched operation status = %q, want ambiguous", operation.Status)
	}
	events, err := store.Load(ctx, StreamID{AggregateType: "outbound-effect", AggregateID: effect.EffectID}, 2)
	if err != nil || len(events) != 1 {
		t.Fatalf("quarantine events = %#v, err = %v", events, err)
	}
	if events[0].EventType != "OutboundEffectAmbiguousV1" {
		t.Fatalf("quarantine event type = %q, want OutboundEffectAmbiguousV1", events[0].EventType)
	}
	if _, err := store.QuarantineOutbox(ctx, req); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("stale quarantine err = %v, want stale lease", err)
	}
}

func TestPreDispatchRequeueRequiresNarrowLeaseAPI(t *testing.T) {
	store, db, _ := task5Store(t)
	defer db.Close()
	effect := task5Effect("pre-requeue", "lane-pre")
	effect.RiskClass = RiskNonIdempotentAfterDispatch
	if _, err := store.AcceptOutbox(context.Background(), effect); err != nil {
		t.Fatal(err)
	}
	lease, err := store.ClaimOutbox(context.Background(), OutboxClaimRequest{WorkerID: "worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	dispatched, err := store.MarkOutboxDispatched(context.Background(), OutboxDispatchRequest{EffectID: lease.Effect.EffectID, WorkerID: lease.Effect.LeaseOwner, LeaseEpoch: lease.Effect.LeaseEpoch, AttemptID: lease.Effect.AttemptID})
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Commit(context.Background(), UnitOfWork{Effects: []NewEffect{{EffectID: dispatched.Effect.EffectID, ExpectedVersion: dispatched.Effect.Version, Version: dispatched.Effect.Version + 1, Status: OutboxStatusPending, LeaseOwner: dispatched.Effect.LeaseOwner, LeaseEpoch: dispatched.Effect.LeaseEpoch, AttemptID: dispatched.Effect.AttemptID}}})
	if !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("generic pending transition err=%v", err)
	}
	result, err := store.RequeuePreDispatch(context.Background(), OutboxPreDispatchRequeueRequest{EffectID: dispatched.Effect.EffectID, WorkerID: dispatched.Effect.LeaseOwner, LeaseEpoch: dispatched.Effect.LeaseEpoch, AttemptID: dispatched.Effect.AttemptID, RetryCount: 1, NextAttemptAt: time.Now().Add(time.Minute)})
	if err != nil || result.Version != dispatched.Effect.Version+1 {
		t.Fatalf("narrow requeue result=%#v err=%v", result, err)
	}
	if _, err := store.RequeuePreDispatch(context.Background(), OutboxPreDispatchRequeueRequest{EffectID: dispatched.Effect.EffectID, WorkerID: dispatched.Effect.LeaseOwner, LeaseEpoch: dispatched.Effect.LeaseEpoch, AttemptID: dispatched.Effect.AttemptID}); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("stale requeue err=%v", err)
	}
}

func task5Inbox(id, provider, lane string) InboxUpdate {
	return InboxUpdate{InboxID: id, EndpointID: "endpoint", ProviderEventKey: provider, LaneHMAC: []byte(lane), Status: InboxStatusPending, PayloadCiphertext: []byte("ciphertext"), PayloadNonce: []byte("nonce"), DigestKeyID: "digest-key"}
}

func task5Effect(id, lane string) NewEffect {
	return NewEffect{EffectID: id, EndpointID: "endpoint", LaneHMAC: []byte(lane), EffectType: "send", RiskClass: RiskPreDispatchRetryable, Status: OutboxStatusPending, PayloadCiphertext: []byte("ciphertext"), PayloadNonce: []byte("nonce"), DigestKeyID: "digest-key"}
}

func TestInboxAcceptanceDedupeAndLaneAllocation(t *testing.T) {
	store, db, _ := task5Store(t)
	defer db.Close()
	first, err := store.AcceptInbox(context.Background(), task5Inbox("inbox-1", "provider-1", "lane-1"))
	if err != nil {
		t.Fatal(err)
	}
	if first.OrderingSequence != 1 || first.Deduplicated {
		t.Fatalf("first result = %#v", first)
	}
	second, err := store.AcceptInbox(context.Background(), task5Inbox("different-id", "provider-1", "lane-1"))
	if err != nil {
		t.Fatal(err)
	}
	if !second.Deduplicated || second.OrderingSequence != 1 || len(second.InboxIDs) != 1 || second.InboxIDs[0] != "inbox-1" {
		t.Fatalf("dedupe result = %#v", second)
	}
	third, err := store.AcceptInbox(context.Background(), task5Inbox("inbox-2", "provider-2", "lane-1"))
	if err != nil {
		t.Fatal(err)
	}
	if third.OrderingSequence != 2 {
		t.Fatalf("caller sequence bypassed allocation: %#v", third)
	}
}

func TestInboxOrderingAndResolution(t *testing.T) {
	store, db, _ := task5Store(t)
	defer db.Close()
	if _, err := store.AcceptInbox(context.Background(), task5Inbox("inbox-1", "p1", "lane")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptInbox(context.Background(), task5Inbox("inbox-2", "p2", "lane")); err != nil {
		t.Fatal(err)
	}
	first, err := store.ClaimInbox(context.Background(), InboxClaimRequest{WorkerID: "worker", LeaseDuration: time.Minute})
	if err != nil || first.Update.InboxID != "inbox-1" {
		t.Fatalf("first claim = %#v err=%v", first, err)
	}
	if _, err := store.ClaimInbox(context.Background(), InboxClaimRequest{WorkerID: "other", LeaseDuration: time.Minute}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("predecessor claim err=%v", err)
	}
	started := InboxUpdate{InboxID: first.Update.InboxID, ExpectedVersion: first.Update.Version, Status: InboxStatusCallbackStarted, LeaseOwner: first.Update.LeaseOwner, LeaseEpoch: first.Update.LeaseEpoch, AttemptID: first.Update.AttemptID}
	if _, err := store.UpdateInbox(context.Background(), started); err != nil {
		t.Fatal(err)
	}
	ambiguous := started
	ambiguous.ExpectedVersion = 3
	ambiguous.Status = InboxStatusAmbiguous
	if _, err := store.UpdateInbox(context.Background(), ambiguous); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimInbox(context.Background(), InboxClaimRequest{WorkerID: "other", LeaseDuration: time.Minute}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ambiguous predecessor claim err=%v", err)
	}
	if _, err := store.ResolveInbox(context.Background(), InboxResolutionRequest{InboxID: "inbox-1", ExpectedVersion: 4, Resolution: InboxResolutionConfirmedConsumed, PrincipalID: "operator", Reason: "verified"}); err != nil {
		t.Fatal(err)
	}
	second, err := store.ClaimInbox(context.Background(), InboxClaimRequest{WorkerID: "other", LeaseDuration: time.Minute})
	if err != nil || second.Update.InboxID != "inbox-2" {
		t.Fatalf("resolved successor claim = %#v err=%v", second, err)
	}
	var row inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", "inbox-1").First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if len(row.PayloadCiphertext) != 0 || len(row.PayloadNonce) != 0 {
		t.Fatal("terminal inbox payload was not scrubbed")
	}
}

func TestOutboxLeaseDispatchCompletionAndStale(t *testing.T) {
	store, db, _ := task5Store(t)
	defer db.Close()
	if _, err := store.AcceptOutbox(context.Background(), task5Effect("effect-1", "lane")); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimOutbox(context.Background(), OutboxClaimRequest{WorkerID: "worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	dispatched, err := store.MarkOutboxDispatched(context.Background(), OutboxDispatchRequest{EffectID: claimed.Effect.EffectID, WorkerID: "worker", LeaseEpoch: claimed.Effect.LeaseEpoch, AttemptID: claimed.Effect.AttemptID})
	if err != nil {
		t.Fatal(err)
	}
	if dispatched.Effect.Status != OutboxStatusDispatched || dispatched.Effect.AttemptID == claimed.Effect.AttemptID {
		t.Fatalf("dispatch marker = %#v", dispatched)
	}
	if _, err := store.CompleteOutbox(context.Background(), OutboxCompletionRequest{EffectID: "effect-1", WorkerID: "stale", LeaseEpoch: claimed.Effect.LeaseEpoch, AttemptID: claimed.Effect.AttemptID, Status: OutboxStatusSucceeded, ResultCode: "ok"}); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("stale completion err=%v", err)
	}
	completion := OutboxCompletionRequest{EffectID: "effect-1", WorkerID: "worker", LeaseEpoch: dispatched.Effect.LeaseEpoch, AttemptID: dispatched.Effect.AttemptID, Status: OutboxStatusSucceeded, ResultCode: "ok"}
	if _, err := store.CompleteOutbox(context.Background(), completion); err != nil {
		t.Fatal(err)
	}
	if result, err := store.CompleteOutbox(context.Background(), completion); err != nil || !result.Idempotent {
		t.Fatalf("terminal completion idempotence = %#v err=%v", result, err)
	}
	var row outboxEffectRow
	if err := db.GORM().Where("effect_id = ?", "effect-1").First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != OutboxStatusSucceeded || len(row.PayloadCiphertext) != 0 || len(row.PayloadNonce) != 0 {
		t.Fatalf("terminal outbox row = %#v", row)
	}
}

func TestArtifactCodecBoundAndOneWinner(t *testing.T) {
	store, db, clock := task5Store(t)
	defer db.Close()
	if _, err := store.Commit(context.Background(), UnitOfWork{Operations: []OperationUpdate{{OperationID: "op-1", PrincipalID: "principal"}}}); err != nil {
		t.Fatal(err)
	}
	_, err := store.PutArtifact(context.Background(), ArtifactPutRequest{ArtifactID: "artifact-1", OperationID: "op-1", OwnerPrincipalID: "principal", Plaintext: []byte("secret"), TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.ConsumeArtifact(context.Background(), ArtifactConsumeRequest{ArtifactID: "artifact-1"})
	if err != nil || string(got.Plaintext) != "secret" {
		t.Fatalf("consume = %#v err=%v", got, err)
	}
	var consumed operationArtifactRow
	if err := db.GORM().Where("artifact_id = ?", "artifact-1").First(&consumed).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeArtifact(context.Background(), ArtifactConsumeRequest{ArtifactID: "artifact-1"}); !errors.Is(err, ErrArtifactGone) {
		t.Fatalf("losing consume err=%v", err)
	}
	var row operationArtifactRow
	if err := db.GORM().Where("artifact_id = ?", "artifact-1").First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Version != consumed.Version {
		t.Fatalf("losing consume mutated version from %d to %d", consumed.Version, row.Version)
	}
	if len(row.Ciphertext) != 0 || len(row.Nonce) != 0 {
		t.Fatal("artifact ciphertext was not scrubbed")
	}
	if _, err := store.PutArtifact(context.Background(), ArtifactPutRequest{ArtifactID: "too-large", OperationID: "op-1", Plaintext: make([]byte, MaxArtifactBytes+1)}); !errors.Is(err, ErrOversizeInput) {
		t.Fatalf("size bound err=%v", err)
	}
	if _, err := store.PutArtifact(context.Background(), ArtifactPutRequest{ArtifactID: "artifact-2", OperationID: "op-1", Plaintext: []byte("expired"), TTL: time.Minute}); err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	if _, err := store.ConsumeArtifact(context.Background(), ArtifactConsumeRequest{ArtifactID: "artifact-2"}); !errors.Is(err, ErrArtifactGone) {
		t.Fatalf("expired consume err=%v", err)
	}
}
func TestTask5ConsumeArtifactCommitErrorNeverReturnsPlaintext(t *testing.T) {
	store, db, _ := task5Store(t)
	defer db.Close()
	ctx := context.Background()
	if _, err := store.Commit(ctx, UnitOfWork{Operations: []OperationUpdate{{OperationID: "artifact-commit-error-op", PrincipalID: "owner"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutArtifact(ctx, ArtifactPutRequest{
		ArtifactID:       "artifact-commit-error",
		OperationID:      "artifact-commit-error-op",
		OwnerPrincipalID: "owner",
		Plaintext:        []byte("secret"),
	}); err != nil {
		t.Fatal(err)
	}
	const callbackName = "task5_test_rollback_consume_artifact"
	if err := db.GORM().Callback().Update().After("gorm:update").Register(callbackName, func(tx *gorm.DB) {
		if tx.Statement.Table == "operation_artifacts" {
			tx.Rollback()
		}
	}); err != nil {
		t.Fatal(err)
	}
	defer db.GORM().Callback().Update().Remove(callbackName)
	result, err := store.ConsumeArtifact(ctx, ArtifactConsumeRequest{ArtifactID: "artifact-commit-error"})
	if err == nil {
		t.Fatal("consume unexpectedly succeeded after forced commit failure")
	}
	if !reflect.DeepEqual(result, ArtifactResult{}) {
		t.Fatalf("commit-error consume returned plaintext/result: %#v", result)
	}
	var row operationArtifactRow
	if err := db.GORM().Where("artifact_id = ?", "artifact-commit-error").First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != "available" || len(row.Ciphertext) == 0 || len(row.Nonce) == 0 {
		t.Fatalf("commit-error consume mutated artifact: %#v", row)
	}
}
func TestTask5LeaseCommitErrorsReturnZeroLease(t *testing.T) {
	{
		store, db, _ := task5Store(t)
		defer db.Close()
		if _, err := store.AcceptInbox(context.Background(), task5Inbox("commit-error-claim-inbox", "commit-error-provider", "commit-error-lane")); err != nil {
			t.Fatal(err)
		}
		const callbackName = "task5_test_rollback_claim_inbox"
		if err := db.GORM().Callback().Update().After("gorm:update").Register(callbackName, func(tx *gorm.DB) {
			if tx.Statement.Table == tableInboxMessages {
				tx.Rollback()
			}
		}); err != nil {
			t.Fatal(err)
		}
		lease, err := store.ClaimInbox(context.Background(), InboxClaimRequest{WorkerID: "worker"})
		_ = db.GORM().Callback().Update().Remove(callbackName)
		if err == nil || !reflect.DeepEqual(lease, InboxLease{}) {
			t.Fatalf("claim inbox commit error lease=%#v err=%v", lease, err)
		}
	}
	{
		store, db, _ := task5Store(t)
		defer db.Close()
		if _, err := store.AcceptOutbox(context.Background(), task5Effect("commit-error-claim-effect", "commit-error-claim-lane")); err != nil {
			t.Fatal(err)
		}
		const callbackName = "task5_test_rollback_claim_outbox"
		if err := db.GORM().Callback().Update().After("gorm:update").Register(callbackName, func(tx *gorm.DB) {
			if tx.Statement.Table == tableOutboxEffects {
				tx.Rollback()
			}
		}); err != nil {
			t.Fatal(err)
		}
		lease, err := store.ClaimOutbox(context.Background(), OutboxClaimRequest{WorkerID: "worker"})
		_ = db.GORM().Callback().Update().Remove(callbackName)
		if err == nil || !reflect.DeepEqual(lease, OutboxLease{}) {
			t.Fatalf("claim outbox commit error lease=%#v err=%v", lease, err)
		}
	}
	{
		store, db, _ := task5Store(t)
		defer db.Close()
		if _, err := store.AcceptOutbox(context.Background(), task5Effect("commit-error-renew-effect", "commit-error-renew-lane")); err != nil {
			t.Fatal(err)
		}
		claimed, err := store.ClaimOutbox(context.Background(), OutboxClaimRequest{WorkerID: "worker"})
		if err != nil {
			t.Fatal(err)
		}
		const callbackName = "task5_test_rollback_renew_outbox"
		if err := db.GORM().Callback().Update().After("gorm:update").Register(callbackName, func(tx *gorm.DB) {
			if tx.Statement.Table == tableOutboxEffects {
				tx.Rollback()
			}
		}); err != nil {
			t.Fatal(err)
		}
		lease, err := store.RenewOutbox(context.Background(), OutboxRenewRequest{EffectID: claimed.Effect.EffectID, WorkerID: claimed.Effect.LeaseOwner, LeaseEpoch: claimed.Effect.LeaseEpoch, AttemptID: claimed.Effect.AttemptID, LeaseDuration: time.Minute})
		_ = db.GORM().Callback().Update().Remove(callbackName)
		if err == nil || !reflect.DeepEqual(lease, OutboxLease{}) {
			t.Fatalf("renew outbox commit error lease=%#v err=%v", lease, err)
		}
	}
	{
		store, db, _ := task5Store(t)
		defer db.Close()
		if _, err := store.AcceptOutbox(context.Background(), task5Effect("commit-error-mark-effect", "commit-error-mark-lane")); err != nil {
			t.Fatal(err)
		}
		claimed, err := store.ClaimOutbox(context.Background(), OutboxClaimRequest{WorkerID: "worker"})
		if err != nil {
			t.Fatal(err)
		}
		const callbackName = "task5_test_rollback_mark_outbox"
		if err := db.GORM().Callback().Update().After("gorm:update").Register(callbackName, func(tx *gorm.DB) {
			if tx.Statement.Table == tableOutboxEffects {
				tx.Rollback()
			}
		}); err != nil {
			t.Fatal(err)
		}
		lease, err := store.MarkOutboxDispatched(context.Background(), OutboxDispatchRequest{EffectID: claimed.Effect.EffectID, WorkerID: claimed.Effect.LeaseOwner, LeaseEpoch: claimed.Effect.LeaseEpoch, AttemptID: claimed.Effect.AttemptID})
		_ = db.GORM().Callback().Update().Remove(callbackName)
		if err == nil || !reflect.DeepEqual(lease, OutboxLease{}) {
			t.Fatalf("mark outbox commit error lease=%#v err=%v", lease, err)
		}
	}
}

func TestInboxConcurrentAcceptanceAllocatesUniqueSequences(t *testing.T) {
	store, db, _ := task5Store(t)
	defer db.Close()
	const count = 12
	errs := make(chan error, count)
	var wg sync.WaitGroup
	for i := range count {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			u := task5Inbox("concurrent-"+strconv.Itoa(i), "provider-"+strconv.Itoa(i), "shared-lane")
			_, err := store.AcceptInbox(context.Background(), u)
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var rows []inboxMessageRow
	if err := db.GORM().Where("lane_hmac = ?", []byte("shared-lane")).Order("ordering_sequence ASC").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != count {
		t.Fatalf("rows = %d, want %d", len(rows), count)
	}
	for i, row := range rows {
		if row.OrderingSequence != uint64(i+1) {
			t.Fatalf("sequence[%d] = %d", i, row.OrderingSequence)
		}
	}
}

func TestInboxPayloadExpiryScrubsWithoutUnblockingRetry(t *testing.T) {
	store, db, clock := task5Store(t)
	defer db.Close()
	expiry := clock.Now().Add(time.Minute)
	u := task5Inbox("expiry-inbox", "expiry-provider", "expiry-lane")
	u.PayloadExpiresAt = expiry
	if _, err := store.AcceptInbox(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimInbox(context.Background(), InboxClaimRequest{WorkerID: "worker", LeaseDuration: time.Minute}); err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	if _, err := store.ClaimInbox(context.Background(), InboxClaimRequest{WorkerID: "worker", LeaseDuration: time.Minute}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("expired claim err = %v", err)
	}
	var row inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", "expiry-inbox").First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != InboxStatusLeased || len(row.PayloadCiphertext) != 0 || len(row.PayloadNonce) != 0 {
		t.Fatalf("expired row = %#v", row)
	}
}

func TestOutboxNonIdempotentDispatchExpiryBecomesAmbiguous(t *testing.T) {
	store, db, clock := task5Store(t)
	defer db.Close()
	effect := task5Effect("ambiguous-effect", "ambiguous-lane")
	effect.RiskClass = RiskNonIdempotentAfterDispatch
	effect.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptOutbox(context.Background(), effect); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimOutbox(context.Background(), OutboxClaimRequest{WorkerID: "worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	dispatched, err := store.MarkOutboxDispatched(context.Background(), OutboxDispatchRequest{EffectID: claimed.Effect.EffectID, WorkerID: "worker", LeaseEpoch: claimed.Effect.LeaseEpoch, AttemptID: claimed.Effect.AttemptID})
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	if _, err := store.ClaimOutbox(context.Background(), OutboxClaimRequest{WorkerID: "other", LeaseDuration: time.Minute}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("ambiguous claim err = %v", err)
	}
	var row outboxEffectRow
	if err := db.GORM().Where("effect_id = ?", effect.EffectID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != OutboxStatusAmbiguous {
		t.Fatalf("status = %q, want %q", row.Status, OutboxStatusAmbiguous)
	}
	if _, err := store.ResolveOutbox(context.Background(), OutboxResolutionRequest{EffectID: effect.EffectID, ExpectedVersion: dispatched.Effect.Version + 1, Resolution: OutboxResolutionSucceeded, PrincipalID: "operator", Reason: "provider checked"}); err != nil {
		t.Fatal(err)
	}
}

func TestTask5PersistedVersionWidthOverflowFailsClosed(t *testing.T) {
	store, db, _ := task5Store(t)
	defer db.Close()
	effect := task5Effect("persisted-width-effect", "persisted-width-lane")
	if _, err := store.AcceptOutbox(context.Background(), effect); err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Model(&outboxEffectRow{}).Where("effect_id = ?", effect.EffectID).Update("version", maxPersistedVersion).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimOutbox(context.Background(), OutboxClaimRequest{WorkerID: "worker", LeaseDuration: time.Minute}); !errors.Is(err, ErrVersionExhausted) {
		t.Fatalf("persisted outbox version overflow err=%v", err)
	}
	inbox := task5Inbox("persisted-width-inbox", "persisted-width-inbox-provider", "persisted-width-inbox-lane")
	if _, err := store.AcceptInbox(context.Background(), inbox); err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Model(&inboxMessageRow{}).Where("inbox_id = ?", inbox.InboxID).Update("lease_epoch", maxPersistedVersion).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimInbox(context.Background(), InboxClaimRequest{WorkerID: "worker", LeaseDuration: time.Minute}); !errors.Is(err, ErrVersionExhausted) {
		t.Fatalf("persisted inbox lease epoch overflow err=%v", err)
	}
	laneInbox := task5Inbox("persisted-width-lane-inbox", "persisted-width-lane-provider", "persisted-width-lane")
	if _, err := store.AcceptInbox(context.Background(), laneInbox); err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Model(&laneHeadRow{}).Where("kind = ? AND lane_hmac = ?", "inbox", laneInbox.LaneHMAC).Update("next_sequence", maxPersistedVersion).Error; err != nil {
		t.Fatal(err)
	}
	laneInbox.InboxID = "persisted-width-lane-inbox-2"
	laneInbox.ProviderEventKey = "persisted-width-lane-provider-2"
	if _, err := store.AcceptInbox(context.Background(), laneInbox); !errors.Is(err, ErrVersionExhausted) {
		t.Fatalf("persisted lane sequence overflow err=%v", err)
	}
}

func TestArtifactFailsClosedWithoutCodec(t *testing.T) {
	db, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "no-codec.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := NewStore(db, WithClock(&task5Clock{now: time.Unix(100, 0).UTC()}))
	if _, err := store.Commit(context.Background(), UnitOfWork{Operations: []OperationUpdate{{OperationID: "no-codec-op", PrincipalID: "principal"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutArtifact(context.Background(), ArtifactPutRequest{ArtifactID: "no-codec-artifact", OperationID: "no-codec-op", Plaintext: []byte("secret")}); !errors.Is(err, ErrEncryptionUnavailable) {
		t.Fatalf("without codec err = %v", err)
	}
	var rows int64
	if err := db.GORM().Model(&operationArtifactRow{}).Where("artifact_id = ?", "no-codec-artifact").Count(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatal("failed encryption left an artifact row")
	}
}

func TestTask5UnitOfWorkParticipantsUseLaneInvariants(t *testing.T) {
	store, db, _ := task5Store(t)
	defer db.Close()
	work := UnitOfWork{InboxUpdates: []InboxUpdate{{
		InboxID: "uow-inbox", EndpointID: "endpoint", ProviderEventKey: "uow-provider",
		LaneHMAC: []byte("uow-lane"), OrderingSequence: 99, Status: InboxStatusPending,
		PayloadCiphertext: []byte("cipher"), PayloadNonce: []byte("nonce"), DigestKeyID: "uow-key",
	}}}
	result, err := store.Commit(context.Background(), work)
	if err != nil {
		t.Fatal(err)
	}
	if result.OrderingSequence != 1 {
		t.Fatalf("uow sequence = %d, want 1", result.OrderingSequence)
	}
	var row inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", "uow-inbox").First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.OrderingSequence != 1 || row.Status != InboxStatusPending {
		t.Fatalf("uow row = %#v", row)
	}
}
func TestTask5UnitOfWorkRejectsInvalidIngressParticipants(t *testing.T) {
	store, db, _ := task5Store(t)
	defer db.Close()
	badInbox := task5Inbox("bad-uow-inbox", "bad-uow-provider", "bad-uow-lane")
	badInbox.Status = InboxStatusCallbackStarted
	if _, err := store.Commit(context.Background(), UnitOfWork{InboxUpdates: []InboxUpdate{badInbox}}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("invalid inbox participant err = %v", err)
	}
	goodInbox, err := store.AcceptInbox(context.Background(), task5Inbox("good-inbox", "good-provider", "bad-uow-lane"))
	if err != nil || goodInbox.OrderingSequence != 1 {
		t.Fatalf("lane after rejected inbox = %#v err=%v", goodInbox, err)
	}
	badEffect := task5Effect("bad-uow-effect", "bad-uow-effect-lane")
	badEffect.RiskClass = "high"
	if _, err := store.Commit(context.Background(), UnitOfWork{Effects: []NewEffect{badEffect}}); !errors.Is(err, ErrInvalidRiskClass) {
		t.Fatalf("invalid effect participant err = %v", err)
	}
	goodEffect, err := store.AcceptOutbox(context.Background(), task5Effect("good-effect", "bad-uow-effect-lane"))
	if err != nil || goodEffect.OrderingSequence != 1 {
		t.Fatalf("lane after rejected effect = %#v err=%v", goodEffect, err)
	}
}
func TestTask5UOWExistingIngressIdentityIsImmutable(t *testing.T) {
	store, db, _ := task5Store(t)
	defer db.Close()
	ctx := context.Background()
	if _, err := store.AcceptInbox(ctx, task5Inbox("uow-identity-inbox", "uow-identity-provider", "uow-identity-lane")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{{InboxID: "uow-identity-inbox", ExpectedVersion: 1, EndpointID: "forged"}}}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("inbox identity mutation err = %v", err)
	}
	if _, err := store.AcceptOutbox(ctx, task5Effect("uow-identity-effect", "uow-identity-effect-lane")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{Effects: []NewEffect{{EffectID: "uow-identity-effect", ExpectedVersion: 1, EndpointID: "forged"}}}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("effect identity mutation err = %v", err)
	}
}

func TestTask5LeaseMutationsRejectExpiredAttempt(t *testing.T) {
	store, db, clock := task5Store(t)
	defer db.Close()
	if _, err := store.AcceptInbox(context.Background(), task5Inbox("expired-lease-inbox", "expired-lease-provider", "expired-lease-lane")); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimInbox(context.Background(), InboxClaimRequest{WorkerID: "worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	update := InboxUpdate{InboxID: claimed.Update.InboxID, ExpectedVersion: claimed.Update.Version, Status: InboxStatusCallbackStarted, LeaseOwner: claimed.Update.LeaseOwner, LeaseEpoch: claimed.Update.LeaseEpoch, AttemptID: claimed.Update.AttemptID}
	if _, err := store.UpdateInbox(context.Background(), update); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("expired inbox mutation err = %v", err)
	}
	if _, err := store.AcceptOutbox(context.Background(), task5Effect("expired-lease-effect", "expired-lease-outbox-lane")); err != nil {
		t.Fatal(err)
	}
	outbox, err := store.ClaimOutbox(context.Background(), OutboxClaimRequest{WorkerID: "worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	if _, err := store.RenewOutbox(context.Background(), OutboxRenewRequest{EffectID: outbox.Effect.EffectID, WorkerID: outbox.Effect.LeaseOwner, LeaseEpoch: outbox.Effect.LeaseEpoch, AttemptID: outbox.Effect.AttemptID, LeaseDuration: time.Minute}); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("expired outbox renew err = %v", err)
	}
}
func TestTask5ExpiredLeasedMutationScrubsBeforeStaleLease(t *testing.T) {
	store, db, clock := task5Store(t)
	defer db.Close()
	ctx := context.Background()
	inbox := task5Inbox("expired-observed-inbox", "expired-observed-provider", "expired-observed-lane")
	inbox.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptInbox(ctx, inbox); err != nil {
		t.Fatal(err)
	}
	inboxLease, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "expired-worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	effect := task5Effect("expired-observed-effect", "expired-observed-lane")
	effect.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptOutbox(ctx, effect); err != nil {
		t.Fatal(err)
	}
	effectLease, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "expired-worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	if _, err := store.UpdateInbox(ctx, InboxUpdate{InboxID: inboxLease.Update.InboxID, ExpectedVersion: inboxLease.Update.Version, Status: InboxStatusCallbackStarted, LeaseOwner: inboxLease.Update.LeaseOwner, LeaseEpoch: inboxLease.Update.LeaseEpoch, AttemptID: inboxLease.Update.AttemptID}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("expired inbox mutation err = %v", err)
	}
	if _, err := store.RenewOutbox(ctx, OutboxRenewRequest{EffectID: effectLease.Effect.EffectID, WorkerID: effectLease.Effect.LeaseOwner, LeaseEpoch: effectLease.Effect.LeaseEpoch, AttemptID: effectLease.Effect.AttemptID, LeaseDuration: time.Minute}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("expired outbox renewal err = %v", err)
	}
	var inboxRow inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", inbox.InboxID).First(&inboxRow).Error; err != nil {
		t.Fatal(err)
	}
	if len(inboxRow.PayloadCiphertext) != 0 || len(inboxRow.PayloadNonce) != 0 {
		t.Fatal("expired inbox payload was not scrubbed")
	}
	var effectRow outboxEffectRow
	if err := db.GORM().Where("effect_id = ?", effect.EffectID).First(&effectRow).Error; err != nil {
		t.Fatal(err)
	}
	if len(effectRow.PayloadCiphertext) != 0 || len(effectRow.PayloadNonce) != 0 {
		t.Fatal("expired outbox payload was not scrubbed")
	}
}
func TestTask5ExpiredRowsPrecedeVersionConflicts(t *testing.T) {
	store, db, clock := task5Store(t)
	defer db.Close()
	ctx := context.Background()
	inbox := task5Inbox("expired-version-inbox", "expired-version-provider", "expired-version-inbox-lane")
	inbox.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptInbox(ctx, inbox); err != nil {
		t.Fatal(err)
	}
	effect := task5Effect("expired-version-effect", "expired-version-effect-lane")
	effect.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptOutbox(ctx, effect); err != nil {
		t.Fatal(err)
	}
	resolveInbox := task5Inbox("expired-version-resolve-inbox", "expired-version-resolve-provider", "expired-version-resolve-inbox-lane")
	resolveInbox.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptInbox(ctx, resolveInbox); err != nil {
		t.Fatal(err)
	}
	resolveEffect := task5Effect("expired-version-resolve-effect", "expired-version-resolve-effect-lane")
	resolveEffect.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptOutbox(ctx, resolveEffect); err != nil {
		t.Fatal(err)
	}
	uowInbox := task5Inbox("expired-version-uow-inbox", "expired-version-uow-provider", "expired-version-uow-inbox-lane")
	uowInbox.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptInbox(ctx, uowInbox); err != nil {
		t.Fatal(err)
	}
	uowEffect := task5Effect("expired-version-uow-effect", "expired-version-uow-effect-lane")
	uowEffect.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptOutbox(ctx, uowEffect); err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	if _, err := store.UpdateInbox(ctx, InboxUpdate{InboxID: inbox.InboxID, ExpectedVersion: 99, Status: InboxStatusPending}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("expired inbox version err = %v", err)
	}
	if _, err := store.UpdateOutbox(ctx, NewEffect{EffectID: effect.EffectID, ExpectedVersion: 99, Status: OutboxStatusPending}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("expired outbox version err = %v", err)
	}
	if _, err := store.ResolveInbox(ctx, InboxResolutionRequest{InboxID: resolveInbox.InboxID, ExpectedVersion: 99, Resolution: InboxResolutionRetry, PrincipalID: "operator", Reason: "expired"}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("expired inbox resolution version err = %v", err)
	}
	if _, err := store.ResolveOutbox(ctx, OutboxResolutionRequest{EffectID: resolveEffect.EffectID, ExpectedVersion: 99, Resolution: OutboxResolutionRetry, PrincipalID: "operator", Reason: "expired"}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("expired outbox resolution version err = %v", err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{{InboxID: uowInbox.InboxID, ExpectedVersion: 99, Status: InboxStatusPending}}}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("expired UoW inbox version err = %v", err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{Effects: []NewEffect{{EffectID: uowEffect.EffectID, ExpectedVersion: 99, Status: OutboxStatusPending}}}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("expired UoW outbox version err = %v", err)
	}
	for _, table := range []string{"inbox_messages", "outbox_effects"} {
		var count int64
		if err := db.GORM().Table(table).Where("(payload_ciphertext IS NOT NULL AND length(payload_ciphertext) > 0) OR (payload_nonce IS NOT NULL AND length(payload_nonce) > 0)").Count(&count).Error; err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("expired %s payloads remain: %d", table, count)
		}
	}
}

func TestTask5OutboxAcceptanceDedupeDoesNotAdvanceLane(t *testing.T) {
	store, db, _ := task5Store(t)
	defer db.Close()
	first, err := store.AcceptOutbox(context.Background(), task5Effect("dedupe-effect", "dedupe-lane"))
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := store.AcceptOutbox(context.Background(), task5Effect("dedupe-effect", "dedupe-lane"))
	if err != nil {
		t.Fatal(err)
	}
	if !duplicate.Deduplicated || duplicate.OrderingSequence != first.OrderingSequence {
		t.Fatalf("duplicate result = %#v", duplicate)
	}
	second, err := store.AcceptOutbox(context.Background(), task5Effect("dedupe-effect-2", "dedupe-lane"))
	if err != nil {
		t.Fatal(err)
	}
	if second.OrderingSequence != 2 {
		t.Fatalf("lane after duplicate = %d", second.OrderingSequence)
	}
}

func TestTask5ArtifactParticipantBoundsAndStatus(t *testing.T) {
	store, db, _ := task5Store(t)
	defer db.Close()
	if _, err := store.Commit(context.Background(), UnitOfWork{Operations: []OperationUpdate{{OperationID: "artifact-uow-op"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(context.Background(), UnitOfWork{ArtifactUpdates: []ArtifactUpdate{{ArtifactID: "oversize-uow-artifact", OperationID: "artifact-uow-op", Size: MaxArtifactBytes + 1, Ciphertext: []byte("cipher"), Nonce: []byte("nonce"), Status: "available"}}}); !errors.Is(err, ErrOversizeInput) {
		t.Fatalf("oversize participant err = %v", err)
	}
	if _, err := store.Commit(context.Background(), UnitOfWork{ArtifactUpdates: []ArtifactUpdate{{ArtifactID: "invalid-uow-artifact", OperationID: "artifact-uow-op", Size: 1, Ciphertext: []byte("cipher"), Nonce: []byte("nonce"), Status: "consumed"}}}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("invalid artifact participant err = %v", err)
	}
}
func TestTask5UOWArtifactExpiryScrubsOnObservedExpiry(t *testing.T) {
	store, db, clock := task5Store(t)
	defer db.Close()
	ctx := context.Background()
	if _, err := store.Commit(ctx, UnitOfWork{Operations: []OperationUpdate{{OperationID: "uow-expiring-artifact-op", PrincipalID: "uow-expiring-owner"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{ArtifactUpdates: []ArtifactUpdate{
		{
			ArtifactID: "uow-expiring-artifact", OperationID: "uow-expiring-artifact-op", OwnerPrincipalID: "uow-expiring-owner",
			Size: 3, Ciphertext: []byte("sealed:abc"), Nonce: []byte("nonce"), EncryptionKeyID: "test-key",
			ExpiresAt: clock.Now().Add(time.Minute),
		},
		{
			ArtifactID: "uow-expiring-artifact-2", OperationID: "uow-expiring-artifact-op", OwnerPrincipalID: "uow-expiring-owner",
			Size: 3, Ciphertext: []byte("sealed:def"), Nonce: []byte("nonce"), EncryptionKeyID: "test-key",
			ExpiresAt: clock.Now().Add(time.Minute),
		},
		{
			ArtifactID: "uow-expiring-artifact-consumed", OperationID: "uow-expiring-artifact-op", OwnerPrincipalID: "uow-expiring-owner",
			Size: 3, Ciphertext: []byte("sealed:ghi"), Nonce: []byte("nonce"), EncryptionKeyID: "test-key",
			ExpiresAt: clock.Now().Add(time.Minute),
		},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeArtifact(ctx, ArtifactConsumeRequest{ArtifactID: "uow-expiring-artifact-consumed"}); err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	if _, err := store.Commit(ctx, UnitOfWork{ArtifactUpdates: []ArtifactUpdate{
		{ArtifactID: "uow-expiring-artifact", ExpectedVersion: 1},
		{ArtifactID: "uow-expiring-artifact-2", ExpectedVersion: 1},
		{ArtifactID: "uow-expiring-artifact-consumed", ExpectedVersion: 2},
	}}); !errors.Is(err, ErrArtifactGone) {
		t.Fatalf("expired artifact participant err = %v", err)
	}
	var row operationArtifactRow
	if err := db.GORM().Where("artifact_id = ?", "uow-expiring-artifact").First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != "expired" || len(row.Ciphertext) != 0 || len(row.Nonce) != 0 {
		t.Fatalf("expired artifact row = %#v", row)
	}
	var consumed operationArtifactRow
	if err := db.GORM().Where("artifact_id = ?", "uow-expiring-artifact-consumed").First(&consumed).Error; err != nil {
		t.Fatal(err)
	}
	if consumed.Status != "consumed" || len(consumed.Ciphertext) != 0 || len(consumed.Nonce) != 0 || consumed.Version != 2 {
		t.Fatalf("consumed artifact row = %#v", consumed)
	}
	var second operationArtifactRow
	if err := db.GORM().Where("artifact_id = ?", "uow-expiring-artifact-2").First(&second).Error; err != nil {
		t.Fatal(err)
	}
	if second.Status != "expired" || len(second.Ciphertext) != 0 || len(second.Nonce) != 0 {
		t.Fatalf("second expired artifact row = %#v", second)
	}
}

func TestTask5ConsumeArtifactRejectsCorruptCodecPlaintext(t *testing.T) {
	store, db, _ := task5Store(t)
	defer db.Close()
	ctx := context.Background()
	if _, err := store.Commit(ctx, UnitOfWork{Operations: []OperationUpdate{{OperationID: "corrupt-artifact-op", PrincipalID: "corrupt-owner"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutArtifact(ctx, ArtifactPutRequest{ArtifactID: "corrupt-artifact", OperationID: "corrupt-artifact-op", OwnerPrincipalID: "corrupt-owner", Plaintext: []byte("secret")}); err != nil {
		t.Fatal(err)
	}
	store.codec = task5CorruptCodec{plaintext: []byte("wrong")}
	if _, err := store.ConsumeArtifact(ctx, ArtifactConsumeRequest{ArtifactID: "corrupt-artifact"}); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("corrupt artifact codec err = %v", err)
	}
}
func TestInboxIngressRejectsPayloadTTLBypass(t *testing.T) {
	store, db, clock := task5Store(t)
	defer db.Close()
	update := task5Inbox("ttl-inbox", "ttl-provider", "ttl-lane")
	update.PayloadExpiresAt = clock.Now().Add(InboxPayloadTTL + time.Second)
	if _, err := store.AcceptInbox(context.Background(), update); !errors.Is(err, ErrInvalidTTL) {
		t.Fatalf("inbox ttl err = %v", err)
	}
	expired := task5Inbox("ttl-expired-inbox", "ttl-expired-provider", "ttl-expired-lane")
	expired.PayloadExpiresAt = clock.Now().Add(-time.Second)
	if _, err := store.AcceptInbox(context.Background(), expired); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("expired inbox ttl err = %v", err)
	}
}

func TestOutboxIngressRejectsPayloadTTLBypass(t *testing.T) {
	store, db, clock := task5Store(t)
	defer db.Close()
	effect := task5Effect("ttl-effect", "ttl-lane")
	expired := task5Effect("ttl-expired-effect", "ttl-expired-lane")
	expired.PayloadExpiresAt = clock.Now().Add(-time.Second)
	if _, err := store.AcceptOutbox(context.Background(), expired); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("expired outbox ttl err = %v", err)
	}
	effect.PayloadExpiresAt = clock.Now().Add(InboxPayloadTTL + time.Second)
	if _, err := store.AcceptOutbox(context.Background(), effect); !errors.Is(err, ErrInvalidTTL) {
		t.Fatalf("outbox ttl err = %v", err)
	}
}

func TestInboxCallbackExpiryScrubsWithoutUnblockingRetry(t *testing.T) {
	store, db, clock := task5Store(t)
	defer db.Close()
	update := task5Inbox("callback-expired", "callback-provider", "callback-lane")
	update.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptInbox(context.Background(), update); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimInbox(context.Background(), InboxClaimRequest{WorkerID: "worker", LeaseDuration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	callback := InboxUpdate{InboxID: claimed.Update.InboxID, ExpectedVersion: claimed.Update.Version, Status: InboxStatusCallbackStarted, LeaseOwner: claimed.Update.LeaseOwner, LeaseEpoch: claimed.Update.LeaseEpoch, AttemptID: claimed.Update.AttemptID}
	if _, err := store.UpdateInbox(context.Background(), callback); err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	if _, err := store.ClaimInbox(context.Background(), InboxClaimRequest{WorkerID: "other", LeaseDuration: time.Minute}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("callback expiry err = %v", err)
	}
	var row inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", update.InboxID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != InboxStatusCallbackStarted || len(row.PayloadCiphertext) != 0 || len(row.PayloadNonce) != 0 {
		t.Fatalf("callback expiry row = %#v", row)
	}
	if _, err := store.ResolveInbox(context.Background(), InboxResolutionRequest{
		InboxID: row.InboxID, ExpectedVersion: row.Version, Resolution: InboxResolutionSkip,
		PrincipalID: "operator", Reason: "callback expired",
	}); err != nil {
		t.Fatalf("callback expiry resolve err = %v", err)
	}
	if err := db.GORM().Where("inbox_id = ?", row.InboxID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != InboxStatusSkipped {
		t.Fatalf("callback expiry resolved status = %q", row.Status)
	}
}

func TestOutboxDispatchedExpiryScrubsBeforeAmbiguity(t *testing.T) {
	store, db, clock := task5Store(t)
	defer db.Close()
	effect := task5Effect("dispatched-expired", "dispatched-expired-lane")
	effect.RiskClass = RiskNonIdempotentAfterDispatch
	effect.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptOutbox(context.Background(), effect); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimOutbox(context.Background(), OutboxClaimRequest{WorkerID: "worker", LeaseDuration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkOutboxDispatched(context.Background(), OutboxDispatchRequest{EffectID: effect.EffectID, WorkerID: claimed.Effect.LeaseOwner, LeaseEpoch: claimed.Effect.LeaseEpoch, AttemptID: claimed.Effect.AttemptID}); err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	if _, err := store.ClaimOutbox(context.Background(), OutboxClaimRequest{WorkerID: "other", LeaseDuration: time.Minute}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("dispatched expiry err = %v", err)
	}
	var row outboxEffectRow
	if err := db.GORM().Where("effect_id = ?", effect.EffectID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != OutboxStatusAmbiguous || len(row.PayloadCiphertext) != 0 || len(row.PayloadNonce) != 0 || row.ScrubbedAt == nil {
		t.Fatalf("dispatched expiry row = %#v", row)
	}
}
func TestOutboxLeaseExpiryScrubsDispatchedNonIdempotentPayload(t *testing.T) {
	store, db, clock := task5Store(t)
	defer db.Close()
	ctx := context.Background()
	effect := task5Effect("lease-only-scrub", "lease-only-scrub-lane")
	effect.RiskClass = RiskNonIdempotentAfterDispatch
	effect.PayloadExpiresAt = clock.Now().Add(5 * time.Minute)
	if _, err := store.AcceptOutbox(ctx, effect); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	dispatched, err := store.MarkOutboxDispatched(ctx, OutboxDispatchRequest{
		EffectID: effect.EffectID,
		WorkerID: claimed.Effect.LeaseOwner,
		LeaseEpoch: claimed.Effect.LeaseEpoch,
		AttemptID: claimed.Effect.AttemptID,
	})
	if err != nil {
		t.Fatal(err)
	}
	blocked := task5Effect("lease-only-scrub-followup", "lease-only-scrub-lane")
	if _, err := store.AcceptOutbox(ctx, blocked); err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	if _, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "other", LeaseDuration: time.Minute}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("lease-only expiry claim err = %v", err)
	}
	var row outboxEffectRow
	if err := db.GORM().Where("effect_id = ?", effect.EffectID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Version != dispatched.Effect.Version+1 || row.Status != OutboxStatusAmbiguous || row.LeaseOwner != "" || row.LeaseEpoch != 0 || row.AttemptID != "" || row.LeaseExpiry != nil || len(row.PayloadCiphertext) != 0 || len(row.PayloadNonce) != 0 || row.ScrubbedAt == nil {
		t.Fatalf("lease-only expiry row = %#v", row)
	}
	if _, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "third", LeaseDuration: time.Minute}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ambiguous lane claim err = %v", err)
	}
}
func TestOutboxUpdateDispatchedExpiryScrubs(t *testing.T) {
	store, db, clock := task5Store(t)
	defer db.Close()
	ctx := context.Background()
	effect := task5Effect("update-dispatched-expired", "update-dispatched-expired-lane")
	effect.RiskClass = RiskProviderIdempotent
	effect.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptOutbox(ctx, effect); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "worker", LeaseDuration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	dispatched, err := store.MarkOutboxDispatched(ctx, OutboxDispatchRequest{EffectID: effect.EffectID, WorkerID: claimed.Effect.LeaseOwner, LeaseEpoch: claimed.Effect.LeaseEpoch, AttemptID: claimed.Effect.AttemptID})
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	if _, err := store.UpdateOutbox(ctx, NewEffect{EffectID: effect.EffectID, ExpectedVersion: dispatched.Effect.Version, Status: OutboxStatusAmbiguous, LeaseOwner: dispatched.Effect.LeaseOwner, LeaseEpoch: dispatched.Effect.LeaseEpoch, AttemptID: dispatched.Effect.AttemptID}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("dispatched update expiry err = %v", err)
	}
	var row outboxEffectRow
	if err := db.GORM().Where("effect_id = ?", effect.EffectID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != OutboxStatusDispatched || len(row.PayloadCiphertext) != 0 || len(row.PayloadNonce) != 0 {
		t.Fatalf("dispatched update expiry row = %#v", row)
	}
}
func TestTask5StrictIngressAndParticipantContracts(t *testing.T) {
	store, db, _ := task5Store(t)
	defer db.Close()
	ctx := context.Background()

	inbox := task5Inbox("strict-inbox", "strict-provider", "strict-lane")
	inbox.ContentDigest = []byte("strict-digest")
	if _, err := store.AcceptInbox(ctx, inbox); err != nil {
		t.Fatal(err)
	}
	conflicting := inbox
	conflicting.PayloadCiphertext = []byte("different")
	conflicting.ContentDigest = []byte("different-digest")
	if _, err := store.AcceptInbox(ctx, conflicting); !errors.Is(err, ErrConflict) {
		t.Fatalf("inbox content conflict err = %v", err)
	}
	invalidOutbox := task5Effect("strict-effect", "strict-outbox-lane")
	invalidOutbox.Status = OutboxStatusLeased
	if _, err := store.AcceptOutbox(ctx, invalidOutbox); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("non-pending outbox acceptance err = %v", err)
	}
	pendingLease := InboxUpdate{InboxID: inbox.InboxID, ExpectedVersion: 1, Status: InboxStatusPending, LeaseOwner: "forged", LeaseEpoch: 1, AttemptID: "forged-attempt"}
	if _, err := store.UpdateInbox(ctx, pendingLease); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("pending inbox lease injection err = %v", err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{{InboxID: inbox.InboxID, Resolution: InboxResolutionRetry, ExpectedVersion: 1}}}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("uow inbox resolution err = %v", err)
	}
	effect := task5Effect("strict-uow-effect", "strict-uow-lane")
	if _, err := store.AcceptOutbox(ctx, effect); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{Effects: []NewEffect{{EffectID: effect.EffectID, Status: OutboxStatusSucceeded, ExpectedVersion: 1}}}); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("uow outbox terminal transition err = %v", err)
	}

	if _, err := store.UpdateOutbox(ctx, NewEffect{EffectID: effect.EffectID, Status: OutboxStatusLeased, ExpectedVersion: 1}); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("forged outbox lease transition err = %v", err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{
		Operations: []OperationUpdate{{OperationID: "artifact-uow-roundtrip", PrincipalID: "artifact-owner"}},
		ArtifactUpdates: []ArtifactUpdate{{
			ArtifactID: "artifact-uow-roundtrip", OperationID: "artifact-uow-roundtrip",
			Size: 3, Ciphertext: []byte("sealed:abc"), Nonce: []byte("nonce"), EncryptionKeyID: "artifact-key",
			Status: "ready",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	artifact, err := store.ConsumeArtifact(ctx, ArtifactConsumeRequest{ArtifactID: "artifact-uow-roundtrip"})
	if err != nil {
		t.Fatal(err)
	}
	if string(artifact.Plaintext) != "abc" || artifact.OwnerPrincipalID != "artifact-owner" {
		t.Fatalf("artifact roundtrip = %#v", artifact)
	}
}
func TestOutboxObservedExpiryMarksNonIdempotentDispatchAmbiguous(t *testing.T) {
	store, db, clock := task5Store(t)
	defer db.Close()
	ctx := context.Background()
	effect := task5Effect("observed-expired-nonidempotent", "observed-expired-nonidempotent-lane")
	effect.RiskClass = RiskNonIdempotentAfterDispatch
	effect.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptOutbox(ctx, effect); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "observed-expired-worker", LeaseDuration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	dispatched, err := store.MarkOutboxDispatched(ctx, OutboxDispatchRequest{EffectID: effect.EffectID, WorkerID: claimed.Effect.LeaseOwner, LeaseEpoch: claimed.Effect.LeaseEpoch, AttemptID: claimed.Effect.AttemptID})
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	if _, err := store.UpdateOutbox(ctx, NewEffect{EffectID: effect.EffectID, ExpectedVersion: dispatched.Effect.Version, Status: OutboxStatusAmbiguous, LeaseOwner: dispatched.Effect.LeaseOwner, LeaseEpoch: dispatched.Effect.LeaseEpoch, AttemptID: dispatched.Effect.AttemptID}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("non-idempotent observed expiry err = %v", err)
	}
	var row outboxEffectRow
	if err := db.GORM().Where("effect_id = ?", effect.EffectID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != OutboxStatusAmbiguous || row.LeaseExpiry != nil || len(row.PayloadCiphertext) != 0 || len(row.PayloadNonce) != 0 {
		t.Fatalf("non-idempotent observed expiry row = %#v", row)
	}
	version := row.Version
	if _, err := store.UpdateOutbox(ctx, NewEffect{EffectID: effect.EffectID, ExpectedVersion: version, Status: OutboxStatusPending}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("ambiguous replay err = %v", err)
	}
	var replay outboxEffectRow
	if err := db.GORM().Where("effect_id = ?", effect.EffectID).First(&replay).Error; err != nil {
		t.Fatal(err)
	}
	if replay.Version != version {
		t.Fatalf("ambiguous replay changed version from %d to %d", version, replay.Version)
	}
}
func TestTask5StableDedupeAfterScrubAndLeaseRequiredTransitions(t *testing.T) {
	store, db, _ := task5Store(t)
	defer db.Close()
	ctx := context.Background()

	inbox := task5Inbox("stable-inbox", "stable-provider", "stable-lane")
	inbox.ContentDigest = []byte("stable-digest")
	if _, err := store.AcceptInbox(ctx, inbox); err != nil {
		t.Fatal(err)
	}
	inboxLease, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	failedInbox := InboxUpdate{InboxID: inboxLease.Update.InboxID, ExpectedVersion: inboxLease.Update.Version, Status: InboxStatusFailed, LeaseOwner: inboxLease.Update.LeaseOwner, LeaseEpoch: inboxLease.Update.LeaseEpoch, AttemptID: inboxLease.Update.AttemptID}
	if _, err := store.UpdateInbox(ctx, failedInbox); err != nil {
		t.Fatal(err)
	}
	terminalInboxUpdate := failedInbox
	terminalInboxUpdate.ExpectedVersion = 3
	terminalInboxUpdate.PrincipalID = "attacker"
	if _, err := store.UpdateInbox(ctx, terminalInboxUpdate); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("terminal inbox generic update err = %v", err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{{InboxID: inbox.InboxID, Status: InboxStatusFailed, ExpectedVersion: 3}}}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("terminal inbox participant update err = %v", err)
	}
	replayInbox := inbox
	replayInbox.PayloadCiphertext = []byte("re-encrypted")
	if result, err := store.AcceptInbox(ctx, replayInbox); err != nil || !result.Deduplicated {
		t.Fatalf("scrubbed inbox replay = %#v err=%v", result, err)
	}
	conflictingInbox := replayInbox
	conflictingInbox.ContentDigest = []byte("different-digest")
	if _, err := store.AcceptInbox(ctx, conflictingInbox); !errors.Is(err, ErrConflict) {
		t.Fatalf("scrubbed inbox digest conflict err = %v", err)
	}

	effect := task5Effect("stable-effect", "stable-effect-lane")
	effect.ContentDigest = []byte("stable-effect-digest")
	if _, err := store.AcceptOutbox(ctx, effect); err != nil {
		t.Fatal(err)
	}
	outboxLease, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	dispatched, err := store.MarkOutboxDispatched(ctx, OutboxDispatchRequest{EffectID: effect.EffectID, WorkerID: outboxLease.Effect.LeaseOwner, LeaseEpoch: outboxLease.Effect.LeaseEpoch, AttemptID: outboxLease.Effect.AttemptID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CompleteOutbox(ctx, OutboxCompletionRequest{EffectID: effect.EffectID, WorkerID: outboxLease.Effect.LeaseOwner, LeaseEpoch: outboxLease.Effect.LeaseEpoch, AttemptID: dispatched.Effect.AttemptID, Status: OutboxStatusSucceeded, ResultCode: "ok"}); err != nil {
		t.Fatal(err)
	}
	terminalEffectUpdate := effect
	terminalEffectUpdate.ExpectedVersion = 4
	terminalEffectUpdate.Status = OutboxStatusSucceeded
	terminalEffectUpdate.ResultCode = "rewritten"
	if _, err := store.UpdateOutbox(ctx, terminalEffectUpdate); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("terminal outbox generic update err = %v", err)
	}
	replayEffect := effect
	replayEffect.PayloadCiphertext = []byte("re-encrypted")
	if result, err := store.AcceptOutbox(ctx, replayEffect); err != nil || !result.Deduplicated {
		t.Fatalf("scrubbed outbox replay = %#v err=%v", result, err)
	}
	conflictingEffect := replayEffect
	conflictingEffect.ContentDigest = []byte("different-effect-digest")
	if _, err := store.AcceptOutbox(ctx, conflictingEffect); !errors.Is(err, ErrConflict) {
		t.Fatalf("scrubbed outbox digest conflict err = %v", err)
	}
}
func TestTask5PublicIngressRejectsImmutableFieldsAndVersions(t *testing.T) {
	store, db, _ := task5Store(t)
	defer db.Close()
	ctx := context.Background()
	inbox := task5Inbox("public-immutable-inbox", "public-immutable-provider", "public-immutable-lane")
	if _, err := store.AcceptInbox(ctx, inbox); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptInbox(ctx, InboxUpdate{InboxID: "new-inbox", EndpointID: "endpoint", ProviderEventKey: "provider", LaneHMAC: []byte("lane"), Version: 1, PayloadCiphertext: []byte("sealed"), PayloadNonce: []byte("nonce"), DigestKeyID: "key"}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("accept inbox version err = %v", err)
	}
	if _, err := store.UpdateInbox(ctx, InboxUpdate{InboxID: inbox.InboxID, ExpectedVersion: 1, Status: InboxStatusPending, PayloadCiphertext: []byte("sealed")}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("update inbox payload err = %v", err)
	}
	if _, err := store.UpdateInbox(ctx, InboxUpdate{InboxID: inbox.InboxID, ExpectedVersion: 1, Version: 9, Status: InboxStatusPending}); !errors.Is(err, ErrParticipantConflict) {
		t.Fatalf("update inbox version err = %v", err)
	}
	if _, err := store.UpdateInbox(ctx, InboxUpdate{InboxID: inbox.InboxID, ExpectedVersion: 1, Status: InboxStatusPending, Resolution: InboxResolutionRetry}); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("update inbox resolution metadata err = %v", err)
	}
	effect := task5Effect("public-immutable-effect", "public-immutable-effect-lane")
	if _, err := store.AcceptOutbox(ctx, effect); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptOutbox(ctx, NewEffect{EffectID: "new-effect", EndpointID: "endpoint", LaneHMAC: []byte("lane"), EffectType: "send", RiskClass: RiskPreDispatchRetryable, Version: 1, PayloadCiphertext: []byte("sealed"), PayloadNonce: []byte("nonce"), DigestKeyID: "key"}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("accept outbox version err = %v", err)
	}
	if _, err := store.UpdateOutbox(ctx, NewEffect{EffectID: effect.EffectID, ExpectedVersion: 1, Status: OutboxStatusPending, EndpointID: "forged"}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("update outbox endpoint err = %v", err)
	}
	if _, err := store.UpdateOutbox(ctx, NewEffect{EffectID: effect.EffectID, ExpectedVersion: 1, Version: 9, Status: OutboxStatusPending}); !errors.Is(err, ErrParticipantConflict) {
		t.Fatalf("update outbox version err = %v", err)
	}
}
func TestTask5PublicUpdateCannotCompleteDispatchedEffect(t *testing.T) {
	store, db, _ := task5Store(t)
	defer db.Close()
	ctx := context.Background()
	effect := task5Effect("public-dispatched-completion", "public-dispatched-completion-lane")
	if _, err := store.AcceptOutbox(ctx, effect); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "public-dispatched-worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	dispatched, err := store.MarkOutboxDispatched(ctx, OutboxDispatchRequest{EffectID: effect.EffectID, WorkerID: claimed.Effect.LeaseOwner, LeaseEpoch: claimed.Effect.LeaseEpoch, AttemptID: claimed.Effect.AttemptID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateOutbox(ctx, NewEffect{EffectID: effect.EffectID, ExpectedVersion: dispatched.Effect.Version, Status: OutboxStatusSucceeded, LeaseOwner: dispatched.Effect.LeaseOwner, LeaseEpoch: dispatched.Effect.LeaseEpoch, AttemptID: dispatched.Effect.AttemptID}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("dispatched generic completion err = %v", err)
	}
}

func TestTask5PendingTerminationAndNonceBound(t *testing.T) {
	store, db, _ := task5Store(t)
	defer db.Close()
	ctx := context.Background()

	inbox := task5Inbox("pending-termination-inbox", "pending-termination-provider", "pending-termination-lane")
	if _, err := store.AcceptInbox(ctx, inbox); err != nil {
		t.Fatal(err)
	}
	failedInbox := InboxUpdate{InboxID: inbox.InboxID, Status: InboxStatusFailed, ExpectedVersion: 1}
	if _, err := store.UpdateInbox(ctx, failedInbox); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("pending inbox termination err = %v", err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{{InboxID: inbox.InboxID, Status: InboxStatusFailed, ExpectedVersion: 1}}}); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("pending inbox participant termination err = %v", err)
	}

	effect := task5Effect("pending-termination-effect", "pending-termination-effect-lane")
	if _, err := store.AcceptOutbox(ctx, effect); err != nil {
		t.Fatal(err)
	}
	failedEffect := NewEffect{EffectID: effect.EffectID, Status: OutboxStatusFailed, ExpectedVersion: 1}
	if _, err := store.UpdateOutbox(ctx, failedEffect); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("pending outbox termination err = %v", err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{Effects: []NewEffect{{EffectID: effect.EffectID, Status: OutboxStatusFailed, ExpectedVersion: 1}}}); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("pending outbox participant termination err = %v", err)
	}

	invalidNonce := task5Inbox("nonce-bound", "nonce-bound-provider", "nonce-bound-lane")
	invalidNonce.PayloadNonce = make([]byte, task5NonceLimit+1)
	if _, err := store.AcceptInbox(ctx, invalidNonce); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("nonce bound err = %v", err)
	}
}
func TestTask5ArtifactUnsupportedCodecFailsClosed(t *testing.T) {
	store, db, _ := task5Store(t)
	defer db.Close()
	store.codec = struct{}{}
	ctx := context.Background()
	if _, err := store.Commit(ctx, UnitOfWork{Operations: []OperationUpdate{{OperationID: "artifact-unsupported-op", PrincipalID: "owner"}}}); err != nil {
		t.Fatal(err)
	}
	_, err := store.Commit(ctx, UnitOfWork{ArtifactUpdates: []ArtifactUpdate{{
		ArtifactID: "artifact-unsupported", OperationID: "artifact-unsupported-op", Size: 3,
		Ciphertext: []byte("sealed:abc"), Nonce: []byte("nonce"), EncryptionKeyID: "artifact-key",
	}}})
	if !errors.Is(err, ErrEncryptionUnavailable) {
		t.Fatalf("unsupported artifact codec err = %v", err)
	}
}
func TestTask5ParticipantVersionContract(t *testing.T) {
	store, db, _ := task5Store(t)
	defer db.Close()
	ctx := context.Background()

	inbox := task5Inbox("participant-version-inbox", "participant-version-provider", "participant-version-lane")
	inbox.Version = 2
	if _, err := store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{inbox}}); !errors.Is(err, ErrParticipantConflict) {
		t.Fatalf("new inbox supplied version err = %v", err)
	}
	inbox.Version = 1
	inbox.ExpectedVersion = 9
	if _, err := store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{inbox}}); !errors.Is(err, ErrParticipantConflict) {
		t.Fatalf("new inbox expected version err = %v", err)
	}
	inbox.ExpectedVersion = 0
	if _, err := store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{inbox}}); err != nil {
		t.Fatalf("new inbox version 1: %v", err)
	}
	replayInbox := inbox
	replayInbox.Version = 0
	if result, err := store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{replayInbox}}); err != nil || !result.Deduplicated || !result.Idempotent {
		t.Fatalf("existing inbox full replay = %#v err=%v", result, err)
	}
	oversizedInboxReplay := replayInbox
	oversizedInboxReplay.PayloadCiphertext = make([]byte, task5PayloadLimit+1)
	var bound *OversizeError
	if _, err := store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{oversizedInboxReplay}}); !errors.As(err, &bound) {
		t.Fatalf("oversized inbox replay err = %v", err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{{InboxID: inbox.InboxID, ExpectedVersion: 1, Version: 3, Status: InboxStatusPending}}}); !errors.Is(err, ErrParticipantConflict) {
		t.Fatalf("existing inbox supplied version err = %v", err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{{InboxID: inbox.InboxID, ExpectedVersion: 1, Version: 2, Status: InboxStatusPending}}}); err != nil {
		t.Fatalf("existing inbox version 2: %v", err)
	}

	effect := task5Effect("participant-version-effect", "participant-version-effect-lane")
	effect.Version = 2
	if _, err := store.Commit(ctx, UnitOfWork{Effects: []NewEffect{effect}}); !errors.Is(err, ErrParticipantConflict) {
		t.Fatalf("new effect supplied version err = %v", err)
	}
	effect.Version = 1
	effect.ExpectedVersion = 9
	if _, err := store.Commit(ctx, UnitOfWork{Effects: []NewEffect{effect}}); !errors.Is(err, ErrParticipantConflict) {
		t.Fatalf("new effect expected version err = %v", err)
	}
	effect.ExpectedVersion = 0
	if _, err := store.Commit(ctx, UnitOfWork{Effects: []NewEffect{effect}}); err != nil {
		t.Fatalf("new effect version 1: %v", err)
	}
	replayEffect := effect
	replayEffect.Version = 0
	if result, err := store.Commit(ctx, UnitOfWork{Effects: []NewEffect{replayEffect}}); err != nil || !result.Deduplicated || !result.Idempotent {
		t.Fatalf("existing effect full replay = %#v err=%v", result, err)
	}
	oversizedEffectReplay := replayEffect
	oversizedEffectReplay.PayloadCiphertext = make([]byte, task5PayloadLimit+1)
	bound = nil
	if _, err := store.Commit(ctx, UnitOfWork{Effects: []NewEffect{oversizedEffectReplay}}); !errors.As(err, &bound) {
		t.Fatalf("oversized effect replay err = %v", err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{Effects: []NewEffect{{EffectID: effect.EffectID, ExpectedVersion: 1, Version: 3, Status: OutboxStatusPending}}}); !errors.Is(err, ErrParticipantConflict) {
		t.Fatalf("existing effect supplied version err = %v", err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{Effects: []NewEffect{{EffectID: effect.EffectID, ExpectedVersion: 1, Version: 2, Status: OutboxStatusPending}}}); err != nil {
		t.Fatalf("existing effect version 2: %v", err)
	}
	effectLease, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "participant-version-worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{Effects: []NewEffect{{EffectID: effect.EffectID, ExpectedVersion: effectLease.Effect.Version, RetryCount: 9, Version: effectLease.Effect.Version + 1}}}); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("sparse leased effect without identity err = %v", err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{Effects: []NewEffect{{EffectID: effect.EffectID, ExpectedVersion: effectLease.Effect.Version, RetryCount: 9, Version: effectLease.Effect.Version + 1, LeaseOwner: effectLease.Effect.LeaseOwner, LeaseEpoch: effectLease.Effect.LeaseEpoch, AttemptID: effectLease.Effect.AttemptID}}}); err != nil {
		t.Fatalf("sparse leased effect with identity: %v", err)
	}

	if _, err := store.Commit(ctx, UnitOfWork{Operations: []OperationUpdate{{OperationID: "participant-version-operation", PrincipalID: "participant-version-principal"}}}); err != nil {
		t.Fatal(err)
	}
	artifact := ArtifactUpdate{ArtifactID: "participant-version-artifact", OperationID: "participant-version-operation", OwnerPrincipalID: "participant-version-principal", Size: 8, Ciphertext: []byte("sealed:artifact"), Nonce: []byte("nonce"), EncryptionKeyID: "test-key"}
	artifact.Version = 2
	if _, err := store.Commit(ctx, UnitOfWork{ArtifactUpdates: []ArtifactUpdate{artifact}}); !errors.Is(err, ErrParticipantConflict) {
		t.Fatalf("new artifact supplied version err = %v", err)
	}
	artifact.Version = 1
	if _, err := store.Commit(ctx, UnitOfWork{ArtifactUpdates: []ArtifactUpdate{artifact}}); err != nil {
		t.Fatalf("new artifact version 1: %v", err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{ArtifactUpdates: []ArtifactUpdate{{ArtifactID: artifact.ArtifactID, ExpectedVersion: 1, Version: 3}}}); !errors.Is(err, ErrParticipantConflict) {
		t.Fatalf("existing artifact supplied version err = %v", err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{ArtifactUpdates: []ArtifactUpdate{{ArtifactID: artifact.ArtifactID, ExpectedVersion: 1, Version: 2}}}); err != nil {
		t.Fatalf("existing artifact version 2: %v", err)
	}
}
func TestTask5UOWCallbackStartedTimestamp(t *testing.T) {
	store, db, _ := task5Store(t)
	defer db.Close()
	ctx := context.Background()
	inbox := task5Inbox("uow-callback-started", "uow-callback-provider", "uow-callback-lane")
	if _, err := store.AcceptInbox(ctx, inbox); err != nil {
		t.Fatal(err)
	}
	lease, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "uow-callback-worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{{InboxID: inbox.InboxID, ExpectedVersion: lease.Update.Version, Version: lease.Update.Version + 1, Status: InboxStatusCallbackStarted, LeaseOwner: lease.Update.LeaseOwner, LeaseEpoch: lease.Update.LeaseEpoch, AttemptID: lease.Update.AttemptID}}}); err != nil {
		t.Fatal(err)
	}
	var row inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", inbox.InboxID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.CallbackStartedAt == nil || row.Status != InboxStatusCallbackStarted {
		t.Fatalf("callback-started participant row = %#v", row)
	}
}
func TestTask5UOWExpiryScrubsBeforeError(t *testing.T) {
	store, db, clock := task5Store(t)
	defer db.Close()
	ctx := context.Background()

	inbox := task5Inbox("uow-expired-inbox", "uow-expired-provider", "uow-expired-lane")
	inbox.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptInbox(ctx, inbox); err != nil {
		t.Fatal(err)
	}
	inboxLease, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "uow-expiry-worker", LeaseDuration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	if _, err := store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{{InboxID: inbox.InboxID, ExpectedVersion: inboxLease.Update.Version, Version: inboxLease.Update.Version + 1, Status: InboxStatusCallbackStarted, LeaseOwner: inboxLease.Update.LeaseOwner, LeaseEpoch: inboxLease.Update.LeaseEpoch, AttemptID: inboxLease.Update.AttemptID}}}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("uow callback expiry err = %v", err)
	}
	var inboxRow inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", inbox.InboxID).First(&inboxRow).Error; err != nil {
		t.Fatal(err)
	}
	if len(inboxRow.PayloadCiphertext) != 0 || len(inboxRow.PayloadNonce) != 0 {
		t.Fatalf("uow inbox expiry retained payload: %#v", inboxRow)
	}

	effect := task5Effect("uow-expired-effect", "uow-expired-effect-lane")
	effect.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptOutbox(ctx, effect); err != nil {
		t.Fatal(err)
	}
	effectLease, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "uow-expiry-worker", LeaseDuration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	if _, err := store.Commit(ctx, UnitOfWork{Effects: []NewEffect{{EffectID: effect.EffectID, ExpectedVersion: effectLease.Effect.Version, Version: effectLease.Effect.Version + 1, Status: OutboxStatusPending, LeaseOwner: effectLease.Effect.LeaseOwner, LeaseEpoch: effectLease.Effect.LeaseEpoch, AttemptID: effectLease.Effect.AttemptID}}}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("uow pending expiry err = %v", err)
	}
	var effectRow outboxEffectRow
	if err := db.GORM().Where("effect_id = ?", effect.EffectID).First(&effectRow).Error; err != nil {
		t.Fatal(err)
	}
	if len(effectRow.PayloadCiphertext) != 0 || len(effectRow.PayloadNonce) != 0 {
		t.Fatalf("uow effect expiry retained payload: %#v", effectRow)
	}

	ambiguous := task5Effect("uow-expired-ambiguous", "uow-expired-ambiguous-lane")
	ambiguous.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptOutbox(ctx, ambiguous); err != nil {
		t.Fatal(err)
	}
	ambiguousLease, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "uow-expiry-worker", LeaseDuration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	if _, err := store.Commit(ctx, UnitOfWork{Effects: []NewEffect{{EffectID: ambiguous.EffectID, ExpectedVersion: ambiguousLease.Effect.Version, Version: ambiguousLease.Effect.Version + 1, Status: OutboxStatusAmbiguous, LeaseOwner: ambiguousLease.Effect.LeaseOwner, LeaseEpoch: ambiguousLease.Effect.LeaseEpoch, AttemptID: ambiguousLease.Effect.AttemptID}}}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("uow ambiguous expiry err = %v", err)
	}
	effectRow = outboxEffectRow{}
	if err := db.GORM().Where("effect_id = ?", ambiguous.EffectID).First(&effectRow).Error; err != nil {
		t.Fatalf("query ambiguous effect %q err=%v", ambiguous.EffectID, err)
	}
	if len(effectRow.PayloadCiphertext) != 0 || len(effectRow.PayloadNonce) != 0 {
		t.Fatalf("uow ambiguous expiry retained payload: %#v", effectRow)
	}
}
func TestTask5PublicExpiredReplayScrubsBeforeDedupe(t *testing.T) {
	store, db, clock := task5Store(t)
	defer db.Close()
	ctx := context.Background()
	inbox := task5Inbox("expired-replay-inbox", "expired-replay-provider", "expired-replay-inbox-lane")
	inbox.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptInbox(ctx, inbox); err != nil {
		t.Fatal(err)
	}
	effect := task5Effect("expired-replay-effect", "expired-replay-effect-lane")
	effect.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptOutbox(ctx, effect); err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	sameInbox := inbox
	sameInbox.PayloadExpiresAt = clock.Now().Add(-time.Minute)
	if _, err := store.AcceptInbox(ctx, sameInbox); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("same expired inbox replay err = %v", err)
	}
	changedInbox := inbox
	changedInbox.PayloadExpiresAt = time.Time{}
	changedInbox.PayloadCiphertext = []byte("changed")
	if _, err := store.AcceptInbox(ctx, changedInbox); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed expired inbox replay err = %v", err)
	}
	sameEffect := effect
	sameEffect.PayloadExpiresAt = clock.Now().Add(-time.Minute)
	if _, err := store.AcceptOutbox(ctx, sameEffect); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("same expired outbox replay err = %v", err)
	}
	changedEffect := effect
	changedEffect.PayloadExpiresAt = time.Time{}
	changedEffect.PayloadCiphertext = []byte("changed")
	if _, err := store.AcceptOutbox(ctx, changedEffect); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed expired outbox replay err = %v", err)
	}
	var inboxRow inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", inbox.InboxID).First(&inboxRow).Error; err != nil {
		t.Fatal(err)
	}
	if len(inboxRow.PayloadCiphertext) != 0 || len(inboxRow.PayloadNonce) != 0 {
		t.Fatal("expired inbox replay retained payload")
	}
	var effectRow outboxEffectRow
	if err := db.GORM().Where("effect_id = ?", effect.EffectID).First(&effectRow).Error; err != nil {
		t.Fatal(err)
	}
	if len(effectRow.PayloadCiphertext) != 0 || len(effectRow.PayloadNonce) != 0 {
		t.Fatal("expired outbox replay retained payload")
	}
}
func TestTask5UOWExpiredInitialDedupePrecedesReplay(t *testing.T) {
	store, db, clock := task5Store(t)
	defer db.Close()
	ctx := context.Background()
	inbox := task5Inbox("uow-dedupe-expired-inbox", "uow-dedupe-expired-provider", "uow-dedupe-expired-lane")
	inbox.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptInbox(ctx, inbox); err != nil {
		t.Fatal(err)
	}
	effect := task5Effect("uow-dedupe-expired-effect", "uow-dedupe-expired-effect-lane")
	effect.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptOutbox(ctx, effect); err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	replayInbox := task5Inbox("uow-dedupe-expired-new-id", inbox.ProviderEventKey, string(inbox.LaneHMAC))
	replayInbox.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{replayInbox}}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("uow expired inbox dedupe err = %v", err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{Effects: []NewEffect{effect}}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("uow expired effect dedupe err = %v", err)
	}
	var inboxRow inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", inbox.InboxID).First(&inboxRow).Error; err != nil {
		t.Fatal(err)
	}
	if len(inboxRow.PayloadCiphertext) != 0 || len(inboxRow.PayloadNonce) != 0 {
		t.Fatal("uow expired inbox dedupe retained payload")
	}
	var effectRow outboxEffectRow
	if err := db.GORM().Where("effect_id = ?", effect.EffectID).First(&effectRow).Error; err != nil {
		t.Fatal(err)
	}
	if len(effectRow.PayloadCiphertext) != 0 || len(effectRow.PayloadNonce) != 0 {
		t.Fatal("uow expired effect dedupe retained payload")
	}
}
