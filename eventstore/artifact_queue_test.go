package eventstore

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"gorm.io/gorm"
)

func TestArtifactBoundsAndSingleConsumption(t *testing.T) {
	store, db, clock := openQueueTestStore(t)
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
	if string(row.Data) != "secret" {
		t.Fatal("consumed artifact bytes changed unexpectedly")
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

func TestStandaloneEmptyArtifactRoundTripAndSingleConsumption(t *testing.T) {
	for _, data := range [][]byte{nil, {}} {
		t.Run(fmt.Sprintf("nil-%t", data == nil), func(t *testing.T) {
			store, db, clock := openQueueTestStore(t)
			defer db.Close()
			ctx := context.Background()
			if _, err := store.Commit(ctx, UnitOfWork{Operations: []OperationUpdate{{OperationID: "empty-op", PrincipalID: "owner"}}}); err != nil {
				t.Fatal(err)
			}
			put := ArtifactPutRequest{ArtifactID: "empty", OperationID: "empty-op", OwnerPrincipalID: "other", Plaintext: data, TTL: time.Minute}
			if _, err := store.PutArtifact(ctx, put); !errors.Is(err, ErrInvalidMetadata) {
				t.Fatalf("empty artifact accepted the wrong owner: %v", err)
			}
			put.OwnerPrincipalID = "owner"
			created, err := store.PutArtifact(ctx, put)
			if err != nil || created.ArtifactID != "empty" || created.Size != 0 || !created.ExpiresAt.Equal(clock.Now().Add(time.Minute)) {
				t.Fatalf("empty artifact put=%+v err=%v", created, err)
			}
			if _, err := store.ConsumeArtifact(ctx, ArtifactConsumeRequest{ArtifactID: "empty", OwnerPrincipalID: "other"}); !errors.Is(err, ErrArtifactOwner) {
				t.Fatalf("empty artifact owner check=%v", err)
			}
			got, err := store.ConsumeArtifact(ctx, ArtifactConsumeRequest{ArtifactID: "empty", OwnerPrincipalID: "owner"})
			if err != nil || got.ArtifactID != "empty" || got.OperationID != "empty-op" || got.OwnerPrincipalID != "owner" || got.Size != 0 || len(got.Plaintext) != 0 || !got.ConsumedAt.Equal(clock.Now()) {
				t.Fatalf("empty artifact consume=%+v err=%v", got, err)
			}
			if _, err := store.ConsumeArtifact(ctx, ArtifactConsumeRequest{ArtifactID: "empty", OwnerPrincipalID: "owner"}); !errors.Is(err, ErrArtifactGone) {
				t.Fatalf("empty artifact consumed twice: %v", err)
			}
			put.ArtifactID = "expired-empty"
			if _, err := store.PutArtifact(ctx, put); err != nil {
				t.Fatal(err)
			}
			clock.Advance(time.Minute)
			if _, err := store.ConsumeArtifact(ctx, ArtifactConsumeRequest{ArtifactID: "expired-empty", OwnerPrincipalID: "owner"}); !errors.Is(err, ErrArtifactGone) {
				t.Fatalf("empty artifact expiry=%v", err)
			}
		})
	}
}

func TestConsumeArtifactEvaluatesExpiryAfterLockedRead(t *testing.T) {
	for _, tc := range []struct {
		name    string
		delay   time.Duration
		expired bool
	}{
		{name: "expiry while acquiring lock", delay: time.Minute, expired: true},
		{name: "consumption timestamp after lock", delay: 30 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, db, clock := openQueueTestStore(t)
			defer db.Close()
			ctx := context.Background()
			if _, err := store.Commit(ctx, UnitOfWork{Operations: []OperationUpdate{{OperationID: "locked-expiry-op", PrincipalID: "owner"}}}); err != nil {
				t.Fatal(err)
			}
			if _, err := store.PutArtifact(ctx, ArtifactPutRequest{
				ArtifactID: "locked-expiry", OperationID: "locked-expiry-op", OwnerPrincipalID: "owner",
				Plaintext: []byte("secret"), TTL: time.Minute,
			}); err != nil {
				t.Fatal(err)
			}
			const callbackName = "artifact_test_advance_clock_after_locked_read"
			reads := 0
			if err := db.GORM().Callback().Query().After("gorm:query").Register(callbackName, func(tx *gorm.DB) {
				if tx.Statement.Table == tableOperationArtifacts {
					reads++
					if reads == 2 {
						clock.Advance(tc.delay)
					}
				}
			}); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := db.GORM().Callback().Query().Remove(callbackName); err != nil {
					t.Errorf("remove artifact query callback: %v", err)
				}
			}()
			result, err := store.ConsumeArtifact(ctx, ArtifactConsumeRequest{ArtifactID: "locked-expiry", OwnerPrincipalID: "owner"})
			if tc.expired {
				if !errors.Is(err, ErrArtifactGone) || !reflect.DeepEqual(result, ArtifactResult{}) {
					t.Fatalf("expired locked artifact returned result=%+v err=%v", result, err)
				}
			} else if err != nil || string(result.Plaintext) != "secret" || !result.ConsumedAt.Equal(clock.Now()) {
				t.Fatalf("locked artifact consumed with stale timestamp: result=%+v now=%v err=%v", result, clock.Now(), err)
			}
			var row operationArtifactRow
			if err := db.GORM().Where("artifact_id = ?", "locked-expiry").Take(&row).Error; err != nil {
				t.Fatal(err)
			}
			if tc.expired {
				if row.Status != "available" || row.Version != 1 || row.ConsumedAt != nil {
					t.Fatalf("expiry after locking mutated artifact: %+v", row)
				}
			} else if row.ConsumedAt == nil || !row.ConsumedAt.Equal(clock.Now()) {
				t.Fatalf("persisted consumption timestamp=%v now=%v", row.ConsumedAt, clock.Now())
			}
		})
	}
}

func TestConsumeArtifactCommitErrorNeverReturnsPlaintext(t *testing.T) {
	store, db, _ := openQueueTestStore(t)
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
	defer func() {
		if removeErr := db.GORM().Callback().Update().Remove(callbackName); removeErr != nil {
			t.Errorf("remove update callback: %v", removeErr)
		}
	}()
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
	if row.Status != "available" || string(row.Data) != "secret" {
		t.Fatalf("commit-error consume mutated artifact: %#v", row)
	}
}
func TestArtifactParticipantBoundsAndStatus(t *testing.T) {
	store, db, _ := openQueueTestStore(t)
	defer db.Close()
	if _, err := store.Commit(context.Background(), UnitOfWork{Operations: []OperationUpdate{{OperationID: "artifact-uow-op"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(context.Background(), UnitOfWork{ArtifactUpdates: []ArtifactUpdate{{ArtifactID: "oversize-uow-artifact", OperationID: "artifact-uow-op", Size: MaxArtifactBytes + 1, Data: []byte("oversize"), Status: "available"}}}); !errors.Is(err, ErrOversizeInput) {
		t.Fatalf("oversize participant err = %v", err)
	}
	if _, err := store.Commit(context.Background(), UnitOfWork{ArtifactUpdates: []ArtifactUpdate{{ArtifactID: "invalid-uow-artifact", OperationID: "artifact-uow-op", Size: 1, Data: []byte("body"), Status: "consumed"}}}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("invalid artifact participant err = %v", err)
	}
}
