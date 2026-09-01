package dice

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"Scardice-core/utils/jsengine"
	"Scardice-core/utils/jsengine/native"
)

func TestJSRuntimeManagerRegistersBuiltinGojaAndResolvesIt(t *testing.T) {
	manager := NewJSRuntimeManager(t.TempDir())

	status, ok := manager.Status(jsengine.EngineGoja)
	if !ok {
		t.Fatal("Goja status is missing")
	}
	if !status.Builtin || !status.Installed || status.Loaded {
		t.Fatalf("unexpected Goja status: %+v", status)
	}

	loop, err := manager.Resolve(context.Background(), jsengine.EngineGoja, jsengine.RuntimeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if loop.Engine() != jsengine.EngineGoja {
		t.Fatalf("resolved Goja loop engine = %q", loop.Engine())
	}
	if err := loop.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestJSRuntimeManagerQuickJSMissingPackageIsExplicitAndDoesNotFallback(t *testing.T) {
	manager := NewJSRuntimeManager(t.TempDir())

	_, err := manager.Resolve(context.Background(), "quickjs", jsengine.RuntimeOptions{})
	if err == nil {
		t.Fatal("Resolve(quickjs) unexpectedly succeeded without a runtime package")
	}
	if !errors.Is(err, native.ErrMissingLibrary) {
		t.Fatalf("Resolve(quickjs) error = %v, want native.ErrMissingLibrary", err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "quickjs") {
		t.Fatalf("Resolve(quickjs) diagnostic = %q, want engine ID", err)
	}
	status, ok := manager.Status("quickjs")
	if !ok || status.Loaded || status.Error == "" {
		t.Fatalf("missing QuickJS status did not retain failure: ok=%v status=%+v", ok, status)
	}
}

func TestJSRuntimeManagerReportsDiscoveredMetadataWithoutLoading(t *testing.T) {
	root := t.TempDir()
	packageDir := filepath.Join(root, "quickjs")
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := fmt.Sprintf(`{
		"schema": 1,
		"id": "quickjs",
		"name": "QuickJS native provider",
		"version": "0.7.7",
		"language": "C++",
		"runtimeAbi": {"major": 1, "minMinor": 0},
		"hostAbi": {"major": 1, "minMinor": 0},
		"libraries": {"%s": "libquickjs.so"},
		"capabilities": 3
	}`, runtime.GOOS+"-"+runtime.GOARCH)
	if err := os.WriteFile(filepath.Join(packageDir, "runtime.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}

	manager := NewJSRuntimeManager(root)
	status, ok := manager.Status("quickjs")
	if !ok {
		t.Fatal("QuickJS status is missing")
	}
	if !status.Installed || status.Loaded || status.Builtin {
		t.Fatalf("unexpected QuickJS status: %+v", status)
	}
	if status.Version != "0.7.7" || status.ABI != "1.0" {
		t.Fatalf("metadata status = %+v", status)
	}
	if status.Path != filepath.Join(packageDir, "libquickjs.so") {
		t.Fatalf("library path = %q", status.Path)
	}
	if len(status.Capabilities) != 2 || status.Capabilities[0] != "script" || status.Capabilities[1] != "commonjs" {
		t.Fatalf("capabilities = %#v", status.Capabilities)
	}
}

func TestJSRuntimeManagerResolvesInstalledQuickJS(t *testing.T) {
	root := os.Getenv("SCARDICE_QUICKJS_PACKAGE")
	if root == "" {
		t.Skip("SCARDICE_QUICKJS_PACKAGE is not set")
	}

	manager := NewJSRuntimeManager(root)
	loop, err := manager.Resolve(context.Background(), "quickjs", jsengine.RuntimeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = loop.Close() })

	if err := loop.Run(func(runtime jsengine.Runtime) error {
		value, err := runtime.RunString("manager.js", "40 + 2")
		if err != nil {
			return err
		}
		got, err := value.ExportPrimitive()
		if err != nil {
			return err
		}
		if got != int64(42) {
			return fmt.Errorf("QuickJS manager result = %#v", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	status, ok := manager.Status("quickjs")
	if !ok || !status.Loaded || status.Version != "0.7.7" {
		t.Fatalf("loaded QuickJS status = ok=%v %+v", ok, status)
	}
}
