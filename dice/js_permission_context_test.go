package dice

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dop251/goja"
	"go.uber.org/zap"

	"Scardice-core/dice/sealpack"
	"Scardice-core/utils/jsengine"
	gojaengine "Scardice-core/utils/jsengine/goja"
)

func newPermissionTestDice(t *testing.T, packageID string, permissions sealpack.Permissions) *Dice {
	t.Helper()
	instance := &sealpack.Instance{
		Manifest: &sealpack.Manifest{
			Package:     sealpack.PackageInfo{ID: packageID},
			Permissions: permissions,
		},
		InstallPath:  t.TempDir(),
		UserDataPath: t.TempDir(),
	}
	d := &Dice{
		Logger: zap.NewNop().Sugar(),
		BaseConfig: BaseConfig{
			DataDir: t.TempDir(),
		},
		PackageManager: &PackageManager{
			lock:     &sync.RWMutex{},
			packages: map[string]*sealpack.Instance{packageID: instance},
		},
		ImSession: &IMSession{
			ServiceAtNew: new(SyncMap[string, *GroupInfo]),
			EndPoints:    []*EndPointInfo{},
		},
		DirtyGroups:  new(SyncMap[string, int64]),
		AttrsManager: &AttrsManager{},
		ExtRegistry:  new(SyncMap[string, *ExtInfo]),
	}
	d.PackageManager.parent = d
	return d
}

func TestJsLoadScriptRawUsesScriptPermissionContext(t *testing.T) {
	const packageID = "author/top-level-permission"
	d := newPermissionTestDice(t, packageID, sealpack.Permissions{FileRead: []string{"data/*"}})
	scriptPath := filepath.Join(t.TempDir(), "permission.js")
	if err := os.WriteFile(scriptPath, []byte(`fs.writeFile("data://blocked.txt", "blocked");`), 0o600); err != nil {
		t.Fatal(err)
	}

	script := &JsScriptInfo{
		Name:      "top-level-permission",
		PackageID: packageID,
		Filename:  scriptPath,
		Enable:    true,
	}
	t.Cleanup(func() {
		if d.ExtLoopManager != nil {
			d.ExtLoopManager.SetLoop(nil)
		}
	})
	d.JsLoadScriptRaw(script)

	if script.ErrText == "" || !strings.Contains(script.ErrText, "file_write") {
		t.Fatalf("script error = %q, want file_write permission denial", script.ErrText)
	}
	blockedPath := filepath.Join(d.BaseConfig.DataDir, "extensions", script.Name, "data", "blocked.txt")
	if _, err := os.Stat(blockedPath); !os.IsNotExist(err) {
		t.Fatalf("blocked file stat error = %v, file should not be created", err)
	}
}

func TestJSNetworkPermissionContextSurvivesTimerAndPromise(t *testing.T) {
	const packageID = "author/async-network-permission"
	d := newPermissionTestDice(t, packageID, sealpack.Permissions{})
	rawLoop := startFsTestLoop(t)
	engineLoop := gojaengine.WrapEventLoop(rawLoop)
	context := &jsExecutionContext{Script: &JsScriptInfo{PackageID: packageID}}

	runFsLoopSync(t, rawLoop, func(vm *goja.Runtime) {
		if err := vm.Set("networkDenied", func() bool {
			return jsNetworkAuthorizeWithContext(d, jsExecutionContextFor(engineLoop), "https://example.test") != nil
		}); err != nil {
			t.Fatal(err)
		}
	})
	if err := jsengine.RunWithContext(engineLoop, context, func(runtime jsengine.Runtime) error {
		_, err := runtime.RunString("permission.js", `
			globalThis.__permissionResults = [];
			globalThis.__permissionDone = false;
			function checkNetworkPermission() {
				globalThis.__permissionResults.push(networkDenied());
				if (globalThis.__permissionResults.length === 2) {
					globalThis.__permissionDone = true;
				}
			}
			setTimeout(checkNetworkPermission, 0);
			Promise.resolve().then(checkNetworkPermission);
		`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	waitFsLoopBool(t, rawLoop, "__permissionDone")
	if result := fsLoopString(t, rawLoop, "__permissionResults"); result != "true,true" {
		t.Fatalf("permission results = %q, want true,true", result)
	}
}

func TestJSFilesystemPermissionContextSurvivesAsyncService(t *testing.T) {
	const packageID = "author/async-filesystem-permission"
	d := newPermissionTestDice(t, packageID, sealpack.Permissions{FileRead: []string{"data/*"}})
	rawLoop := startFsTestLoop(t)
	engineLoop := gojaengine.WrapEventLoop(rawLoop)
	context := &jsExecutionContext{Plugin: &ExtInfo{
		Name:   "async-filesystem-permission",
		Source: &JsScriptInfo{PackageID: packageID},
	}}

	runFsLoopSync(t, rawLoop, func(vm *goja.Runtime) {
		jsFsEnable(vm, d, rawLoop, engineLoop)
	})
	if err := jsengine.RunWithContext(engineLoop, context, func(runtime jsengine.Runtime) error {
		_, err := runtime.RunString("async-permission.js", `
			globalThis.__permissionDone = false;
			globalThis.__permissionError = "";
			fs.promises.writeFile("data://blocked.txt", "blocked").then(
				() => { globalThis.__permissionError = "allowed"; globalThis.__permissionDone = true; },
				error => { globalThis.__permissionError = String(error); globalThis.__permissionDone = true; }
			);
		`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	waitFsLoopBool(t, rawLoop, "__permissionDone")
	errText := fsLoopString(t, rawLoop, "__permissionError")
	if !strings.Contains(errText, "file_write") {
		t.Fatalf("async filesystem error = %q, want file_write permission denial", errText)
	}
	blockedPath := filepath.Join(d.BaseConfig.DataDir, "extensions", "async-filesystem-permission", "data", "blocked.txt")
	if _, err := os.Stat(blockedPath); !os.IsNotExist(err) {
		t.Fatalf("blocked file stat error = %v, file should not be created", err)
	}
}

func TestNativeQuickJSFilesystemPermissionContextSurvivesAsyncService(t *testing.T) {
	if os.Getenv("SCARDICE_RUNTIME_ROOT") == "" && os.Getenv("SCARDICE_QUICKJS_PACKAGE") == "" {
		t.Skip("native QuickJS package is not configured")
	}
	const packageID = "author/native-async-filesystem-permission"
	const extensionName = "native-async-filesystem-permission"
	d := newPermissionTestDice(t, packageID, sealpack.Permissions{FileRead: []string{"data/*"}})
	d.Config.JsEngine = "quickjs"
	dataDir := filepath.Join(d.BaseConfig.DataDir, "extensions", extensionName, "data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "fixture.txt"), []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if d.ExtLoopManager != nil {
			d.ExtLoopManager.SetLoop(nil)
		}
	})

	d.JsInit()
	loop, err := d.ExtLoopManager.GetLoop(d.ExtLoopManager.version)
	if err != nil {
		t.Fatal(err)
	}
	context := &jsExecutionContext{Plugin: &ExtInfo{
		Name:   extensionName,
		Source: &JsScriptInfo{PackageID: packageID},
	}}
	if err := jsengine.RunWithContext(loop, context, func(runtime jsengine.Runtime) error {
		_, err := runtime.RunString("native-async-permission.js", `
			globalThis.__permissionResults = [];
			globalThis.__permissionDone = false;
			function attempt(label) {
				fs.promises.readFile("data://fixture.txt").then(() => {
					return fs.promises.writeFile("data://" + label + ".txt", "blocked");
				}).then(() => {
					globalThis.__permissionResults.push(label + ":allowed");
				}, error => {
					globalThis.__permissionResults.push(label + ":" + String(error));
				}).then(() => {
					if (globalThis.__permissionResults.length === 2) {
						globalThis.__permissionDone = true;
					}
				});
			}
			Promise.resolve().then(() => attempt("promise"));
			setTimeout(() => attempt("timer"), 0);
		`)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	var results any
	for attempt := 0; attempt < 200; attempt++ {
		if err := loop.Run(func(runtime jsengine.Runtime) error {
			var err error
			if runtime.Get("__permissionDone").ToBoolean() {
				value, valueErr := runtime.RunString("native-permission-result.js", "JSON.stringify(__permissionResults)")
				if valueErr != nil {
					return valueErr
				}
				results, err = value.ExportPrimitive()
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if result, ok := results.(string); ok &&
			strings.Contains(result, "promise:") &&
			strings.Contains(result, "timer:") &&
			strings.Count(result, "permission-denied") == 2 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	result, ok := results.(string)
	if !ok || !strings.Contains(result, "promise:") || !strings.Contains(result, "timer:") ||
		strings.Count(result, "permission-denied") != 2 {
		t.Fatalf("native permission results = %#v, want promise and timer writes denied", results)
	}
	for _, label := range []string{"promise", "timer"} {
		if _, err := os.Stat(filepath.Join(dataDir, label+".txt")); !os.IsNotExist(err) {
			t.Fatalf("native %s write stat error = %v, file should not be created", label, err)
		}
	}
}
