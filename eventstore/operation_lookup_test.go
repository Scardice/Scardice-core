package eventstore

import (
	"context"
	"errors"
	"testing"
)

func TestGetOperationByIdempotencyScopesPrincipalAndHidesPayload(t *testing.T) {
	store, db := testStore(t)
	defer db.Close()
	ctx := context.Background()
	if _, err := store.Commit(ctx, UnitOfWork{Operations: []OperationUpdate{{OperationID: "lookup-op-a", PrincipalID: "principal-a", ResourceID: "effect-a", IdempotencyScope: "outbound", IdempotencyKey: "command-1", RequestDigest: []byte("digest-a")}}}); err != nil { t.Fatal(err) }
	view, err := store.GetOperationByIdempotency(ctx, "principal-a", "outbound", "command-1")
	if err != nil || view.OperationID != "lookup-op-a" || view.ResourceID != "effect-a" || string(view.RequestDigest) != "digest-a" { t.Fatalf("view=%#v err=%v", view, err) }
	if _, err := store.GetOperationByIdempotency(ctx, "principal-b", "outbound", "command-1"); !errors.Is(err, ErrNotFound) { t.Fatalf("cross-principal lookup err=%v", err) }
}
