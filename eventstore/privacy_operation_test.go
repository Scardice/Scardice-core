package eventstore

import (
	"context"
	"testing"
)

func TestPrivacyOperationContextIsEncryptedAndCASed(t *testing.T) {
	store, db, _ := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	subject := []byte("01234567890123456789012345678901")
	private := PrivacyOperationContext{GroupID: "group-secret", DiceIDs: []string{"dice"}, Scopes: []string{"group_record"}, Cursor: "42", Phase: "delete"}
	if err := store.PrivacyCreateOperation(ctx, "privacy-op", subject, private); err != nil {
		t.Fatal(err)
	}
	view, loaded, err := store.PrivacyLoadOperation(ctx, "privacy-op")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.GroupID != private.GroupID || loaded.Cursor != private.Cursor || view.Version != 1 {
		t.Fatalf("view=%+v private=%+v", view, loaded)
	}
	if _, err := store.PrivacyUpdateOperation(ctx, "privacy-op", 1, private, "running"); err != nil {
		t.Fatal(err)
	}
	if err := store.PrivacyScrubOperation(ctx, "privacy-op", 2); err != nil {
		t.Fatal(err)
	}
	var row operationRow
	if err := db.GORM().Where("operation_id = ?", "privacy-op").First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if len(row.PrivateContext) != 0 || len(row.PrivateNonce) != 0 || row.PrivateKeyID != "" {
		t.Fatalf("private context not scrubbed")
	}
}
