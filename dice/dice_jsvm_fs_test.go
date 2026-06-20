package dice

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func newTestFsDice(t *testing.T) *Dice {
	t.Helper()
	return &Dice{
		BaseConfig: BaseConfig{DataDir: t.TempDir()},
		JsCurrentPlugin: &ExtInfo{
			Name: "fsTest",
		},
	}
}

func TestJsFsResolveDataPathRejectsTraversalAndPlatformAmbiguity(t *testing.T) {
	d := newTestFsDice(t)
	badPaths := []string{
		"data://..",
		"data://../example.json",
		"data://a/../../example.json",
		"data:///etc/passwd",
		"data://C:/Windows/win.ini",
		"data://c:/Windows/win.ini",
		"data://..\\example.json",
		"data://C:\\Windows\\win.ini",
	}
	for _, path := range badPaths {
		if _, err := jsFsResolveAbsolute(d, path); err == nil {
			t.Fatalf("expected %q to be rejected", path)
		}
	}
}

func TestJsFsResolveDataPathStaysInsideBase(t *testing.T) {
	d := newTestFsDice(t)
	resolved, err := jsFsResolveAbsolute(d, "data://nested/example.json")
	if err != nil {
		t.Fatalf("resolve data path: %v", err)
	}
	base := filepath.Join(d.BaseConfig.DataDir, "extensions", "fsTest", "data")
	if err := jsFsEnsureInsideBase(resolved.base, resolved.abs); err != nil {
		t.Fatalf("resolved path should stay inside base: %v", err)
	}
	if resolved.base != filepath.Clean(base) && resolved.base != mustAbs(t, base) {
		t.Fatalf("unexpected resolved base: %s", resolved.base)
	}
}

func TestJsFsDataPathRejectsSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated permissions on some Windows hosts")
	}
	d := newTestFsDice(t)
	base := filepath.Join(d.BaseConfig.DataDir, "extensions", "fsTest", "data")
	outside := t.TempDir()
	if err := os.MkdirAll(base, 0755); err != nil {
		t.Fatalf("create data base: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("secret"), 0644); err != nil {
		t.Fatalf("create outside file: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(base, "link")); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	readTarget, resolveErr := jsFsResolveAbsolute(d, "data://link/secret.txt")
	if resolveErr != nil {
		t.Fatalf("lexical resolve should pass before symlink validation: %v", resolveErr)
	}
	if err := jsFsEnsureExistingDataTargetInside(readTarget); err == nil {
		t.Fatal("expected symlinked read target outside data base to be rejected")
	}

	writeTarget, err := jsFsResolveAbsolute(d, "data://link/new.txt")
	if err != nil {
		t.Fatalf("lexical resolve should pass before parent symlink validation: %v", err)
	}
	if err := jsFsEnsureDataParentInside(writeTarget); err == nil {
		t.Fatal("expected symlinked write parent outside data base to be rejected")
	}
}

func mustAbs(t *testing.T, path string) string {
	t.Helper()
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("abs %s: %v", path, err)
	}
	return abs
}
