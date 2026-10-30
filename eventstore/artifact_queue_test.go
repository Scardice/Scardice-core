package eventstore

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"gorm.io/gorm"
)

func TestArtifactCodecBoundAndOneWinner(t *testing.T) {
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
	if row.Status != "available" || len(row.Ciphertext) == 0 || len(row.Nonce) == 0 {
		t.Fatalf("commit-error consume mutated artifact: %#v", row)
	}
}
func TestArtifactFailsClosedWithoutCodec(t *testing.T) {
	db, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "no-codec.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := NewStore(db, WithClock(&queueTestClock{now: time.Unix(100, 0).UTC()}))
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
func TestArtifactParticipantBoundsAndStatus(t *testing.T) {
	store, db, _ := openQueueTestStore(t)
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
func TestUOWArtifactExpiryScrubsOnObservedExpiry(t *testing.T) {
	store, db, clock := openQueueTestStore(t)
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
func TestConsumeArtifactRejectsCorruptCodecPlaintext(t *testing.T) {
	store, db, _ := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()
	if _, err := store.Commit(ctx, UnitOfWork{Operations: []OperationUpdate{{OperationID: "corrupt-artifact-op", PrincipalID: "corrupt-owner"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutArtifact(ctx, ArtifactPutRequest{ArtifactID: "corrupt-artifact", OperationID: "corrupt-artifact-op", OwnerPrincipalID: "corrupt-owner", Plaintext: []byte("secret")}); err != nil {
		t.Fatal(err)
	}
	store.codec = corruptQueueTestCodec{plaintext: []byte("wrong")}
	if _, err := store.ConsumeArtifact(ctx, ArtifactConsumeRequest{ArtifactID: "corrupt-artifact"}); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("corrupt artifact codec err = %v", err)
	}
}
func TestArtifactUnsupportedCodecFailsClosed(t *testing.T) {
	store, db, _ := openQueueTestStore(t)
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
