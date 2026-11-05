package eventstore

import (
	"context"
	"errors"
	"testing"
)

func secretVersion(ref string, secret, row uint64, text string) SecretVersionImport {
	return SecretVersionImport{SecretRef: ref, EndpointID: "endpoint", AdapterID: "adapter", SecretVersion: secret, RowVersion: row, Value: []byte(text)}
}

func TestImportSecretVersionsKeepsRowVersionEqualToPlaceInTheChain(t *testing.T) {
	ctx := context.Background()
	store, db := openPlainTestStore(t)
	defer db.Close()

	// References are interleaved, as a table read in storage order delivers them,
	// and a chain may continue in a later call.
	if err := store.ImportSecretVersions(ctx, []SecretVersionImport{
		secretVersion("login", 1, 1, "one"), secretVersion("sheet", 1, 1, "only"), secretVersion("login", 2, 2, "two"),
		secretVersion("gappy", 1, 1, "a"), secretVersion("gappy", 5, 2, "b"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.ImportSecretVersions(ctx, []SecretVersionImport{secretVersion("login", 3, 3, "three")}); err != nil {
		t.Fatalf("continuing a stored chain: %v", err)
	}

	for _, want := range []struct {
		ref     string
		version uint64
		text    string
	}{{"login", 1, "one"}, {"login", 2, "two"}, {"login", 3, "three"}, {"sheet", 1, "only"}, {"gappy", 5, "b"}} {
		got, err := store.ResolveSecret(ctx, want.ref, want.version)
		if err != nil || string(got.Value) != want.text {
			t.Fatalf("%s v%d = %q, err=%v, want %q", want.ref, want.version, got.Value, err, want.text)
		}
	}
	var gappyRows []adapterSecretRow
	if err := rawStringQuery(db.GORM(), "secret_ref", "gappy").Order("row_version").Find(&gappyRows).Error; err != nil {
		t.Fatal(err)
	}
	if len(gappyRows) != 2 || gappyRows[1].RowVersion != 2 || gappyRows[1].SecretVersion != 5 {
		t.Fatalf("gappy rows = %+v", gappyRows)
	}

	// The application's next write names the newest row it read.
	update, err := store.PrepareSecretUpdate(ctx, SecretPutRequest{SecretRef: "login", EndpointID: "endpoint", AdapterID: "adapter", ExpectedVersion: 3, Value: []byte("four")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Commit(ctx, UnitOfWork{SecretUpdates: []SecretUpdate{update}}); err != nil {
		t.Fatalf("write after the imported chain: %v", err)
	}
}

func TestImportSecretVersionsRejectsABrokenChainAndLeavesNothingBehind(t *testing.T) {
	ctx := context.Background()
	store, db := openPlainTestStore(t)
	defer db.Close()
	if err := store.ImportSecretVersions(ctx, []SecretVersionImport{secretVersion("existing", 1, 1, "x")}); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name     string
		versions []SecretVersionImport
		want     error
	}{
		{"chain must start at row version 1", []SecretVersionImport{secretVersion("fresh", 1, 2, "x")}, ErrParticipantConflict},
		{"a row version cannot be skipped", []SecretVersionImport{secretVersion("fresh", 1, 1, "x"), secretVersion("fresh", 2, 3, "x")}, ErrParticipantConflict},
		{"it must continue the stored chain", []SecretVersionImport{secretVersion("fresh", 1, 1, "x"), secretVersion("existing", 2, 1, "x")}, ErrParticipantConflict},
		{"secret versions must increase", []SecretVersionImport{secretVersion("fresh", 2, 1, "x"), secretVersion("fresh", 2, 2, "x")}, ErrParticipantConflict},
		{"a version is needed", []SecretVersionImport{secretVersion("fresh", 0, 1, "x")}, ErrInvalidMetadata},
		{"a row version is needed", []SecretVersionImport{secretVersion("fresh", 1, 0, "x")}, ErrInvalidMetadata},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := store.ImportSecretVersions(ctx, tc.versions); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			var count int64
			if err := rawStringQuery(db.GORM().Table("adapter_secrets"), "secret_ref", "fresh").Count(&count).Error; err != nil || count != 0 {
				t.Fatalf("%d rows of the rejected import were left behind (err=%v)", count, err)
			}
		})
	}
}
