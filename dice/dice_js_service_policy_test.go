package dice

import (
	"sync"
	"testing"

	"Scardice-core/dice/sealpack"
)

func TestJSNetworkAuthorizeUsesCurrentSealPackPermissions(t *testing.T) {
	pkgID := "author/network"
	instance := &sealpack.Instance{
		Manifest: &sealpack.Manifest{
			Package:     sealpack.PackageInfo{ID: pkgID},
			Permissions: sealpack.Permissions{Network: false},
		},
		InstallPath:  t.TempDir(),
		UserDataPath: t.TempDir(),
	}
	d := &Dice{
		JsCurrentPlugin: &ExtInfo{Source: &JsScriptInfo{PackageID: pkgID}},
		PackageManager: &PackageManager{
			lock:     &sync.RWMutex{},
			packages: map[string]*sealpack.Instance{pkgID: instance},
		},
	}
	if err := jsNetworkAuthorize(d, "https://example.test"); err == nil {
		t.Fatal("jsNetworkAuthorize() error = nil, want permission denial")
	}

	instance.Manifest.Permissions.Network = true
	if err := jsNetworkAuthorize(d, "https://example.test"); err != nil {
		t.Fatalf("jsNetworkAuthorize(allowed) error = %v", err)
	}

	d.JsCurrentPlugin = nil
	if err := jsNetworkAuthorize(d, "https://example.test"); err != nil {
		t.Fatalf("jsNetworkAuthorize(core) error = %v", err)
	}
}

func TestJSFilesystemAuthorizeUsesCurrentSealPackPermissions(t *testing.T) {
	pkgID := "author/files"
	instance := &sealpack.Instance{
		Manifest: &sealpack.Manifest{
			Package:     sealpack.PackageInfo{ID: pkgID},
			Permissions: sealpack.Permissions{FileRead: []string{"data/*"}, FileWrite: []string{"_userdata/*"}},
		},
		InstallPath:  t.TempDir(),
		UserDataPath: t.TempDir(),
	}
	d := &Dice{
		JsCurrentPlugin: &ExtInfo{Source: &JsScriptInfo{PackageID: pkgID}},
		PackageManager: &PackageManager{
			lock:     &sync.RWMutex{},
			packages: map[string]*sealpack.Instance{pkgID: instance},
		},
	}
	if err := jsFilesystemAuthorize(d, "data://ok.txt", false); err != nil {
		t.Fatalf("jsFilesystemAuthorize(read) error = %v", err)
	}
	if err := jsFilesystemAuthorize(d, "data://ok.txt", true); err == nil {
		t.Fatal("jsFilesystemAuthorize(write data) error = nil, want permission denial")
	}
	if err := jsFilesystemAuthorize(d, "_userdata/ok.txt", true); err != nil {
		t.Fatalf("jsFilesystemAuthorize(write userdata) error = %v", err)
	}
}
