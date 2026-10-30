package dice

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"Scardice-core/utils/jsengine"
	"Scardice-core/utils/jsengine/native"
)

type runtimeArchiveTestEntry struct {
	name     string
	data     []byte
	typeflag byte
	linkname string
}

func testRuntimeRequirements() jsengine.RuntimeRequirements {
	return jsengine.RuntimeRequirements{
		RequiredCapabilities: jsengine.CapabilityScript | jsengine.CapabilityHostObject |
			jsengine.CapabilityHostFunction | jsengine.CapabilityContextPropagation,
		RequireContextPropagation: true,
	}
}

func testRuntimeManifest(id, libraryName string) []byte {
	return testRuntimeManifestWithABIMajors(id, libraryName, 1, 1)
}

func testRuntimeManifestWithABIMajors(id, libraryName string, runtimeABI, hostABI uint32) []byte {
	return []byte(fmt.Sprintf(`{
		"schema":1,"id":%q,"name":"Test Runtime","version":"1.0.0","language":"C++","author":"test",
		"runtimeAbi":{"major":%d},"hostAbi":{"major":%d},
		"libraries":{%q:%q},"capabilities":%d,"extensions":[".js"]
	}`, id, runtimeABI, hostABI, runtime.GOOS+"-"+runtime.GOARCH, libraryName, uint64(testRuntimeRequirements().RequiredCapabilities)))
}

func makeTarGzRuntimeArchive(t *testing.T, entries ...runtimeArchiveTestEntry) []byte {
	t.Helper()
	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, entry := range entries {
		typeflag := entry.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		header := &tar.Header{Name: entry.name, Typeflag: typeflag, Mode: 0o777, Size: int64(len(entry.data)), Linkname: entry.linkname}
		if typeflag == tar.TypeDir || typeflag == tar.TypeSymlink || typeflag == tar.TypeLink {
			header.Size = 0
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if typeflag == tar.TypeReg && len(entry.data) > 0 {
			if _, err := tarWriter.Write(entry.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func validRuntimeTarGz(t *testing.T) []byte {
	t.Helper()
	return makeTarGzRuntimeArchive(t,
		runtimeArchiveTestEntry{name: "quickjs/", typeflag: tar.TypeDir},
		runtimeArchiveTestEntry{name: "quickjs/runtime.json", data: testRuntimeManifest("quickjs", "libquickjs.so")},
		runtimeArchiveTestEntry{name: "quickjs/libquickjs.so", data: []byte("not a loadable library; discovery must remain lazy")},
	)
}

func validRuntimeZip(t *testing.T) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, contents := range map[string][]byte{
		"quickjs/runtime.json":  testRuntimeManifest("quickjs", "libquickjs.so"),
		"quickjs/libquickjs.so": []byte("not a loadable library; discovery must remain lazy"),
	} {
		file, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(contents); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func makeZipRuntimeArchive(t *testing.T, entries ...runtimeArchiveTestEntry) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, entry := range entries {
		file, err := writer.Create(entry.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestJSRuntimePackageStoreStagesThenAppliesInstallAndUninstall(t *testing.T) {
	store, err := newJSRuntimePackageStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	change, err := store.StageInstall(bytes.NewReader(validRuntimeTarGz(t)), nil, testRuntimeRequirements())
	if err != nil {
		t.Fatal(err)
	}
	if change.ID != "quickjs" || change.Action != "install" || change.Version != "1.0.0" {
		t.Fatalf("pending install = %+v", change)
	}
	if _, err := os.Stat(filepath.Join(store.activeRoot, "quickjs")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runtime became active before restart: stat error = %v", err)
	}
	pending, err := store.PendingChanges()
	if err != nil || len(pending) != 1 || pending[0].ID != "quickjs" {
		t.Fatalf("pending changes = %+v, error = %v", pending, err)
	}

	if err := store.ApplyPending(testRuntimeRequirements()); err != nil {
		t.Fatal(err)
	}
	candidates, err := native.Discover(store.activeRoot)
	if err != nil || len(candidates) != 1 || candidates[0].Manifest.ID != "quickjs" {
		t.Fatalf("active runtime candidates = %+v, error = %v", candidates, err)
	}
	pending, err = store.PendingChanges()
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending changes after install = %+v, error = %v", pending, err)
	}

	if _, err := store.StageUninstall("quickjs"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(store.activeRoot, "quickjs", "runtime.json")); err != nil {
		t.Fatalf("uninstall changed active package before restart: %v", err)
	}
	if err := store.ApplyPending(testRuntimeRequirements()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(store.activeRoot, "quickjs")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("active package still exists after applying uninstall: %v", err)
	}
	if err := store.ApplyPending(testRuntimeRequirements()); err != nil {
		t.Fatalf("reapplying empty pending state: %v", err)
	}
}

func TestJSRuntimePackageStoreAcceptsZipWithoutLoadingProvider(t *testing.T) {
	store, err := newJSRuntimePackageStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	change, err := store.StageInstall(bytes.NewReader(validRuntimeZip(t)), nil, testRuntimeRequirements())
	if err != nil {
		t.Fatal(err)
	}
	if change.ID != "quickjs" || change.Action != "install" {
		t.Fatalf("pending install = %+v", change)
	}
	if _, err := os.Stat(filepath.Join(store.activeRoot, "quickjs")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("zip install became active before restart: %v", err)
	}
}

func TestJSRuntimePackageStoreRejectsUnsafeOrInvalidArchives(t *testing.T) {
	manifest := testRuntimeManifest("quickjs", "libquickjs.so")
	tests := []struct {
		name    string
		archive []byte
	}{
		{
			name: "path traversal",
			archive: makeTarGzRuntimeArchive(t,
				runtimeArchiveTestEntry{name: "quickjs/runtime.json", data: manifest},
				runtimeArchiveTestEntry{name: "quickjs/../../escape", data: []byte("outside")},
			),
		},
		{
			name: "symlink",
			archive: makeTarGzRuntimeArchive(t,
				runtimeArchiveTestEntry{name: "quickjs/runtime.json", data: manifest},
				runtimeArchiveTestEntry{name: "quickjs/libquickjs.so", typeflag: tar.TypeSymlink, linkname: "/tmp/escape"},
			),
		},
		{
			name: "multiple roots",
			archive: makeTarGzRuntimeArchive(t,
				runtimeArchiveTestEntry{name: "quickjs/runtime.json", data: manifest},
				runtimeArchiveTestEntry{name: "quickjs/libquickjs.so", data: []byte("library")},
				runtimeArchiveTestEntry{name: "other/runtime.json", data: testRuntimeManifest("other", "libother.so")},
			),
		},
		{
			name: "missing native library",
			archive: makeTarGzRuntimeArchive(t,
				runtimeArchiveTestEntry{name: "quickjs/runtime.json", data: testRuntimeManifest("quickjs", "missing.so")},
			),
		},
		{
			name: "duplicate tar directory entry",
			archive: makeTarGzRuntimeArchive(t,
				runtimeArchiveTestEntry{name: "quickjs/", typeflag: tar.TypeDir},
				runtimeArchiveTestEntry{name: "quickjs/", typeflag: tar.TypeDir},
				runtimeArchiveTestEntry{name: "quickjs/runtime.json", data: manifest},
				runtimeArchiveTestEntry{name: "quickjs/libquickjs.so", data: []byte("library")},
			),
		},
		{
			name: "duplicate zip directory entry",
			archive: makeZipRuntimeArchive(t,
				runtimeArchiveTestEntry{name: "quickjs/"},
				runtimeArchiveTestEntry{name: "quickjs/"},
				runtimeArchiveTestEntry{name: "quickjs/runtime.json", data: manifest},
				runtimeArchiveTestEntry{name: "quickjs/libquickjs.so", data: []byte("library")},
			),
		},
		{
			name: "duplicate tar file entry",
			archive: makeTarGzRuntimeArchive(t,
				runtimeArchiveTestEntry{name: "quickjs/runtime.json", data: manifest},
				runtimeArchiveTestEntry{name: "quickjs/runtime.json", data: manifest},
				runtimeArchiveTestEntry{name: "quickjs/libquickjs.so", data: []byte("library")},
			),
		},
		{
			name: "duplicate zip file entry",
			archive: makeZipRuntimeArchive(t,
				runtimeArchiveTestEntry{name: "quickjs/runtime.json", data: manifest},
				runtimeArchiveTestEntry{name: "quickjs/runtime.json", data: manifest},
				runtimeArchiveTestEntry{name: "quickjs/libquickjs.so", data: []byte("library")},
			),
		},
		{
			name: "unsupported runtime ABI",
			archive: makeTarGzRuntimeArchive(t,
				runtimeArchiveTestEntry{name: "quickjs/runtime.json", data: testRuntimeManifestWithABIMajors("quickjs", "libquickjs.so", 2, 1)},
				runtimeArchiveTestEntry{name: "quickjs/libquickjs.so", data: []byte("library")},
			),
		},
		{
			name: "unsupported host ABI",
			archive: makeTarGzRuntimeArchive(t,
				runtimeArchiveTestEntry{name: "quickjs/runtime.json", data: testRuntimeManifestWithABIMajors("quickjs", "libquickjs.so", 1, 2)},
				runtimeArchiveTestEntry{name: "quickjs/libquickjs.so", data: []byte("library")},
			),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, err := newJSRuntimePackageStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.StageInstall(bytes.NewReader(test.archive), nil, testRuntimeRequirements()); !errors.Is(err, ErrInvalidJSRuntimeArchive) {
				t.Fatalf("StageInstall error = %v, want invalid archive", err)
			}
			pending, err := store.PendingChanges()
			if err != nil || len(pending) != 0 {
				t.Fatalf("pending changes after rejection = %+v, error = %v", pending, err)
			}
		})
	}
}

func TestJSRuntimePackageStoreEnforcesCompressedAndExpandedLimits(t *testing.T) {
	store, err := newJSRuntimePackageStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store.limits.maxArchiveBytes = 8
	if _, err := store.StageInstall(bytes.NewReader([]byte("123456789")), nil, testRuntimeRequirements()); !errors.Is(err, ErrJSRuntimeArchiveTooLarge) {
		t.Fatalf("oversized compressed archive error = %v, want too-large", err)
	}

	store, err = newJSRuntimePackageStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store.limits.maxExpandedBytes = 8
	if _, err := store.StageInstall(bytes.NewReader(validRuntimeTarGz(t)), nil, testRuntimeRequirements()); !errors.Is(err, ErrJSRuntimeArchiveTooLarge) {
		t.Fatalf("oversized expanded archive error = %v, want too-large", err)
	}
}

func TestDiceRuntimeManagerAppliesPendingPackageWithoutLoadingIt(t *testing.T) {
	t.Setenv("SCARDICE_QUICKJS_PACKAGE", "")
	d := &Dice{BaseConfig: BaseConfig{DataDir: t.TempDir()}}
	manager := NewJSRuntimeManagerForDice(d)
	d.jsRuntimeManager = manager
	if _, err := d.StageJSRuntimeArchive(bytes.NewReader(validRuntimeTarGz(t))); err != nil {
		t.Fatal(err)
	}

	restartedManager := NewJSRuntimeManagerForDice(d)
	status, ok := restartedManager.Status("quickjs")
	if !ok || !status.Installed || !status.Managed || status.Loaded {
		t.Fatalf("managed runtime status after restart = ok:%v %+v", ok, status)
	}
}

func TestJSRuntimePackageStoreRevalidatesABIWhileApplyingPendingInstall(t *testing.T) {
	store, err := newJSRuntimePackageStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.StageInstall(bytes.NewReader(validRuntimeTarGz(t)), nil, testRuntimeRequirements()); err != nil {
		t.Fatal(err)
	}
	stagedPath := filepath.Join(store.installRoot, "quickjs")
	if err := os.WriteFile(filepath.Join(stagedPath, "runtime.json"), testRuntimeManifestWithABIMajors("quickjs", "libquickjs.so", 1, 2), 0o644); err != nil {
		t.Fatal(err)
	}
	_, digest, err := readJSRuntimeManifest(stagedPath)
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	state, err := store.loadPendingLocked()
	if err != nil {
		store.mu.Unlock()
		t.Fatal(err)
	}
	if len(state.Changes) != 1 {
		store.mu.Unlock()
		t.Fatalf("pending records = %+v, want one install", state.Changes)
	}
	state.Changes[0].ManifestSHA256 = digest
	err = store.writePendingLocked(state)
	store.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	if err := store.ApplyPending(testRuntimeRequirements()); !errors.Is(err, ErrInvalidJSRuntimePending) {
		t.Fatalf("ApplyPending error = %v, want invalid pending state", err)
	}
	if _, err := os.Stat(filepath.Join(store.activeRoot, "quickjs")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ABI-incompatible package became active: %v", err)
	}
	pending, err := store.PendingChanges()
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending state after rejected apply = %+v, error = %v", pending, err)
	}
}

func TestJSRuntimeManagementReadDoesNotApplyPendingInstallWhenJSIsDisabled(t *testing.T) {
	t.Setenv("SCARDICE_QUICKJS_PACKAGE", "")
	d := &Dice{BaseConfig: BaseConfig{DataDir: t.TempDir()}}
	d.Config.JsEnable = false
	d.jsRuntimeManager = NewJSRuntimeManagerForDice(d)
	if _, err := d.StageJSRuntimeArchive(bytes.NewReader(validRuntimeTarGz(t))); err != nil {
		t.Fatal(err)
	}
	d.jsRuntimeManager = nil

	pending, err := d.JSRuntimePendingChanges()
	if err != nil || len(pending) != 1 || pending[0].Action != "install" {
		t.Fatalf("pending changes after management read = %+v, error = %v", pending, err)
	}
	if _, err := os.Stat(filepath.Join(d.BaseConfig.DataDir, "js-runtimes", "active", "quickjs")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("management read applied the pending install: %v", err)
	}
}

func TestJSRuntimePackageStoreRejectsExistingAndPendingRuntimeIDs(t *testing.T) {
	archive := validRuntimeTarGz(t)
	store, err := newJSRuntimePackageStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	descriptors := []jsengine.Descriptor{{ID: "quickjs"}}
	if _, err := store.StageInstall(bytes.NewReader(archive), descriptors, testRuntimeRequirements()); !errors.Is(err, ErrJSRuntimePackageExists) {
		t.Fatalf("existing runtime error = %v, want installed-package conflict", err)
	}

	store, err = newJSRuntimePackageStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.StageInstall(bytes.NewReader(archive), nil, testRuntimeRequirements()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.StageInstall(bytes.NewReader(archive), nil, testRuntimeRequirements()); !errors.Is(err, ErrJSRuntimePackagePending) {
		t.Fatalf("duplicate pending runtime error = %v, want pending conflict", err)
	}
}

func TestJSRuntimePackageStoreRecoversInstallStagedBeforePendingState(t *testing.T) {
	dataDir := t.TempDir()
	store, err := newJSRuntimePackageStore(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.StageInstall(bytes.NewReader(validRuntimeTarGz(t)), nil, testRuntimeRequirements()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(store.pendingFile); err != nil {
		t.Fatal(err)
	}

	restarted, err := newJSRuntimePackageStore(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.ApplyPending(testRuntimeRequirements()); err != nil {
		t.Fatal(err)
	}
	candidates, err := native.Discover(restarted.activeRoot)
	if err != nil || len(candidates) != 1 || candidates[0].Manifest.ID != "quickjs" {
		t.Fatalf("recovered active package = %+v, error = %v", candidates, err)
	}
}

func TestJSRuntimePackageStoreRejectsSymlinkedStoreRoot(t *testing.T) {
	dataDir := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dataDir, "js-runtimes")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := newJSRuntimePackageStore(dataDir); !errors.Is(err, ErrJSRuntimeStoreUnavailable) {
		t.Fatalf("store creation error = %v, want unsafe-store rejection", err)
	}
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("store initialization wrote through symlink: %v", entries)
	}
}

func TestDiceCannotUninstallRuntimeReferencedByRoutingConfig(t *testing.T) {
	t.Setenv("SCARDICE_QUICKJS_PACKAGE", "")
	d := &Dice{BaseConfig: BaseConfig{DataDir: t.TempDir()}}
	d.jsRuntimeManager = NewJSRuntimeManagerForDice(d)
	if _, err := d.StageJSRuntimeArchive(bytes.NewReader(validRuntimeTarGz(t))); err != nil {
		t.Fatal(err)
	}
	d.jsRuntimeManager = NewJSRuntimeManagerForDice(d)
	d.Config.JsEngine = "quickjs"
	if _, err := d.StageJSRuntimeUninstall("quickjs"); !errors.Is(err, ErrJSRuntimeInUse) {
		t.Fatalf("uninstall error = %v, want runtime-in-use", err)
	}
	d.Config.JsEngine = "goja"
	d.Config.JsRuntimeRoutes = map[string]string{"author/example": "quickjs"}
	if _, err := d.StageJSRuntimeUninstall("quickjs"); !errors.Is(err, ErrJSRuntimeInUse) {
		t.Fatalf("routed uninstall error = %v, want runtime-in-use", err)
	}
	d.Config.JsRuntimeRoutes = nil
	if _, err := d.StageJSRuntimeUninstall("quickjs"); err != nil {
		t.Fatalf("uninstall after removing references: %v", err)
	}
	for _, tc := range []struct {
		name            string
		defaultRuntime  string
		extensionRoutes map[string]string
	}{
		{name: "global default", defaultRuntime: "quickjs"},
		{name: "package route", defaultRuntime: "goja", extensionRoutes: map[string]string{"author/example": "quickjs"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := d.SetJSRuntimeConfig(context.Background(), tc.defaultRuntime, tc.extensionRoutes); !errors.Is(err, ErrInvalidJSRuntimeConfig) {
				t.Fatalf("route to runtime with pending uninstall error = %v, want invalid runtime config", err)
			}
		})
	}
}
