package dice //nolint:testpackage

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/dop251/goja"
	"go.uber.org/zap"

	"Scardice-core/utils/jsengine"
)

type countingDiceSource struct {
	values []uint64
	index  int
}

func (s *countingDiceSource) Uint64() uint64 {
	if len(s.values) == 0 {
		return 0
	}
	if s.index >= len(s.values) {
		return s.values[len(s.values)-1]
	}
	v := s.values[s.index]
	s.index++
	return v
}

func TestJsInit_WhenExtLoopManagerNil_DoesNotPanic(t *testing.T) {
	d := &Dice{
		Logger: zap.NewNop().Sugar(),
		BaseConfig: BaseConfig{
			DataDir: t.TempDir(),
		},
		ImSession: &IMSession{
			ServiceAtNew: new(SyncMap[string, *GroupInfo]),
			EndPoints:    []*EndPointInfo{},
		},
		DirtyGroups:  new(SyncMap[string, int64]),
		AttrsManager: &AttrsManager{},
	}

	// 模拟“调用 shutdown 后重启”：JsEnable=false 且 ExtLoopManager 尚未初始化。
	d.Config.JsEnable = false
	d.ExtLoopManager = nil

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("JsInit should not panic when ExtLoopManager is nil, got: %v", r)
		}
		// 清理后台任务，避免测试进程残留 goroutine
		if d.JsScriptCron != nil {
			d.JsScriptCron.Stop()
			d.JsScriptCron = nil
		}
		if d.ExtLoopManager != nil {
			// JsInit 在独立 goroutine 里调用 StartInForeground，running 标记要等该
			// goroutine 实际跑起来才置位；若此时直接 Terminate，Stop 会因 running=false
			// 立即返回，随后启动的循环便再也不会退出。先等循环执行一个任务，确保
			// Terminate 能真正等待其结束。
			if loop, _ := d.ExtLoopManager.CurrentLoop(); loop != nil {
				if err := loop.Run(func(jsengine.Runtime) error { return nil }); err != nil {
					t.Errorf("JS 事件循环未在预期时间内启动: %v", err)
				}
			}
			d.ExtLoopManager.SetLoop(nil)
		}
	}()

	d.JsInit()

	if d.ExtLoopManager == nil {
		t.Fatalf("expected ExtLoopManager to be initialized")
	}
	if !d.Config.JsEnable {
		t.Fatalf("expected JsEnable to be true after JsInit")
	}
}

func TestJsScriptTaskRunWithoutActiveLoopReturnsWithoutPanic(t *testing.T) {
	for _, test := range []struct {
		name    string
		manager *JsLoopManager
	}{
		{name: "nil manager"},
		{name: "nil loop", manager: NewJsLoopManager()},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.name == "nil loop" {
				test.manager.SetLoop(nil)
			}
			d := &Dice{
				ExtLoopManager: test.manager,
				Logger:         zap.NewNop().Sugar(),
			}
			called := false
			task := &JsScriptTask{
				dice:   d,
				ext:    &ExtInfo{Name: "task-test"},
				lock:   &sync.Mutex{},
				logger: d.Logger,
				task: func(JsScriptTaskCtx) {
					called = true
				},
			}
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("JsScriptTask.run panicked: %v", recovered)
				}
			}()
			task.run()
			if called {
				t.Fatal("task callback ran without an active loop")
			}
		})
	}
}

func TestJsInit_QuickJSStartsNativeHost(t *testing.T) {
	if os.Getenv("SCARDICE_RUNTIME_ROOT") == "" && os.Getenv("SCARDICE_QUICKJS_PACKAGE") == "" {
		t.Skip("native QuickJS package is not configured")
	}
	d := &Dice{
		Logger: zap.NewNop().Sugar(),
		BaseConfig: BaseConfig{
			DataDir: t.TempDir(),
		},
		ImSession: &IMSession{
			ServiceAtNew: new(SyncMap[string, *GroupInfo]),
			EndPoints:    []*EndPointInfo{},
		},
		DirtyGroups:  new(SyncMap[string, int64]),
		AttrsManager: &AttrsManager{},
	}
	d.Config.JsEngine = "quickjs"
	t.Cleanup(func() {
		if d.ExtLoopManager != nil {
			d.ExtLoopManager.SetLoop(nil)
		}
	})

	d.JsInit()

	if !d.Config.JsEnable {
		if d.jsRuntimeManager != nil {
			status, ok := d.jsRuntimeManager.Status("quickjs")
			t.Fatalf("native QuickJS initialization left JS disabled: status=%+v ok=%v", status, ok)
		}
		t.Fatal("QuickJS initialization left JS disabled")
	}
	if d.ExtLoopManager == nil {
		t.Fatalf("native QuickJS initialization did not create a loop manager")
	}
	loop, err := d.ExtLoopManager.GetLoop(d.ExtLoopManager.version)
	if err != nil {
		t.Fatal(err)
	}
	if loop == nil || loop.Engine() != "quickjs" {
		t.Fatalf("engine loop = %#v", loop)
	}

	if err := loop.Run(func(runtime jsengine.Runtime) error {
		value, err := runtime.RunString("quickjs-init-test.js", `
			const result = seal.ext.newCmdExecuteResult(true);
			typeof seal.getVersion === "function" &&
			typeof seal.ext.new === "function" &&
			typeof seal.ext.registerStringConfig === "function" &&
			seal.ext.new("QuickJS Host Test", "test", "1.0.0").name === "QuickJS Host Test" &&
			result.solved === true
		`)
		if err != nil {
			return err
		}
		if !value.ToBoolean() {
			t.Fatal("native QuickJS Host API is incomplete")
		}
		return nil
	}); err != nil {

		t.Fatal(err)
	}
}
func TestJsInit_QuickJSInstallsNativeConsoleService(t *testing.T) {
	if os.Getenv("SCARDICE_RUNTIME_ROOT") == "" && os.Getenv("SCARDICE_QUICKJS_PACKAGE") == "" {
		t.Skip("native QuickJS package is not configured")
	}
	dataDir := t.TempDir()
	fetchServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte(`{"message":"native fetch"}`))
	}))
	t.Cleanup(fetchServer.Close)
	fixtureDir := filepath.Join(dataDir, "extensions", "native-fs-test", "data")
	if err := os.MkdirAll(fixtureDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixtureDir, "fixture.txt"), []byte("native fs"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := &Dice{
		Logger: zap.NewNop().Sugar(),
		BaseConfig: BaseConfig{
			DataDir: dataDir,
		},
		ImSession: &IMSession{
			ServiceAtNew: new(SyncMap[string, *GroupInfo]),
			EndPoints:    []*EndPointInfo{},
		},
		DirtyGroups:  new(SyncMap[string, int64]),
		AttrsManager: &AttrsManager{},
	}
	d.Config.JsEngine = "quickjs"
	t.Cleanup(func() {
		if d.ExtLoopManager != nil {
			d.ExtLoopManager.SetLoop(nil)
		}
	})

	d.JsInit()
	if !d.Config.JsEnable || d.JsPrinter == nil {
		status, ok := d.jsRuntimeManagerInstance().Status("quickjs")
		t.Fatalf("native QuickJS initialization did not enable the console service: status=%+v ok=%v", status, ok)
	}
	loop, err := d.ExtLoopManager.GetLoop(d.ExtLoopManager.version)
	if err != nil {
		t.Fatal(err)
	}

	d.JsPrinter.RecordStart()
	if err := jsengine.RunWithContext(loop, &jsExecutionContext{Plugin: &ExtInfo{Name: "native-fs-test"}}, func(runtime jsengine.Runtime) error {
		value, err := runtime.RunString("native-console.js", `
			console.log("log", 1);
			console.info("info");
			console.debug("debug");
			console.warn("warn");
			console.error("error");
			const random = crypto.getRandomValues(new Uint8Array(4));
			if (!(random instanceof Uint8Array) || random.length !== 4) {
				throw new Error("crypto service unavailable");
			}
			globalThis.nativeFsResult = undefined;
			fs.writeFileSync("data://sync.txt", "sync fs");
			if (fs.readFileSync("data://sync.txt", { encoding: "utf8" }) !== "sync fs") {
				throw new Error("synchronous filesystem service unavailable");
			}
			fs.promises.readFile("data://fixture.txt", { encoding: "utf8" }).then(value => {
				return fs.promises.writeFile("data://async.txt", value + " async");
			}).then(() => {
				return fs.promises.readFile("data://async.txt", { encoding: "utf8" });
			}).then(value => {
				globalThis.nativeFsResult = value;
			}, error => {
				globalThis.nativeFsResult = "error:" + String(error);
			});
			globalThis.nativeFetchResult = undefined;
			fetch(`+strconv.Quote(fetchServer.URL)+`).then(response => {
				return response.json().then(value => ({
					status: response.status,
					ok: response.ok,
					message: value.message
				}));
			}).then(value => {
				globalThis.nativeFetchResult = value;
			}, error => {
				globalThis.nativeFetchResult = "error:" + String(error);
			});
			globalThis.nativeTimerResult = "pending";
			setTimeout(() => { globalThis.nativeTimerResult = "native timer"; }, 5);
			true
		`)
		if err != nil {
			return err
		}
		if !value.ToBoolean() {
			t.Fatal("native console script returned false")
		}
		module, err := runtime.LoadCommonJS("console-module.js", `module.exports = require("console") === console`)
		if err != nil {
			return err
		}
		if !module.ToBoolean() {
			t.Fatal("require(\"console\") did not return the global console")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	var timerResult any
	for attempt := 0; attempt < 100; attempt++ {
		time.Sleep(time.Millisecond)
		if err := loop.Run(func(runtime jsengine.Runtime) error {
			var err error
			timerResult, err = runtime.Get("nativeTimerResult").ExportPrimitive()
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if timerResult == "native timer" {
			break
		}
	}
	if timerResult != "native timer" {
		t.Fatalf("native timer result = %#v, want %q", timerResult, "native timer")
	}
	var filesystemResult any
	for attempt := 0; attempt < 100; attempt++ {
		if err := loop.Run(func(runtime jsengine.Runtime) error {
			var err error
			filesystemResult, err = runtime.Get("nativeFsResult").ExportPrimitive()
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if filesystemResult == "native fs async" {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if filesystemResult != "native fs async" {
		t.Fatalf("native filesystem result = %#v, want %q", filesystemResult, "native fs async")
	}
	var fetchResult any
	for attempt := 0; attempt < 100; attempt++ {
		if err := loop.Run(func(runtime jsengine.Runtime) error {
			value, err := runtime.RunString("native-fetch-observe.js", "JSON.stringify(nativeFetchResult)")
			if err != nil {
				return err
			}
			fetchResult, err = value.ExportPrimitive()
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if fetchResult == `{"status":200,"ok":true,"message":"native fetch"}` {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if fetchResult != `{"status":200,"ok":true,"message":"native fetch"}` {
		t.Fatalf("native fetch result = %#v", fetchResult)
	}
	if got, want := d.JsPrinter.RecordEnd(), []string{"log 1", "info", "debug", "warn", "error"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("native console records = %#v, want %#v", got, want)
	}
}
func TestJsLoadScriptRaw_NativeQuickJSExecutesAndRegistersPlugin(t *testing.T) {
	if os.Getenv("SCARDICE_RUNTIME_ROOT") == "" && os.Getenv("SCARDICE_QUICKJS_PACKAGE") == "" {
		t.Skip("native QuickJS package is not configured")
	}
	dataDir := t.TempDir()
	scriptPath := filepath.Join(dataDir, "native-quickjs-plugin.js")
	if err := os.WriteFile(scriptPath, []byte(`
		const ext = seal.ext.new("Native QuickJS Plugin Test", "test", "1.0.0");
		seal.ext.register(ext);
	`), 0o600); err != nil {
		t.Fatal(err)
	}
	d := &Dice{
		Logger: zap.NewNop().Sugar(),
		BaseConfig: BaseConfig{
			DataDir: dataDir,
		},
		ImSession: &IMSession{
			ServiceAtNew: new(SyncMap[string, *GroupInfo]),
			EndPoints:    []*EndPointInfo{},
		},
		DirtyGroups:  new(SyncMap[string, int64]),
		AttrsManager: &AttrsManager{},
		ExtRegistry:  new(SyncMap[string, *ExtInfo]),
	}
	d.Config.JsEngine = "quickjs"
	t.Cleanup(func() {
		if d.ExtLoopManager != nil {
			d.ExtLoopManager.SetLoop(nil)
		}
	})
	d.JsInit()
	if !d.Config.JsEnable {
		t.Fatal("native QuickJS initialization failed")
	}

	script := &JsScriptInfo{
		Name:     "Native QuickJS Plugin Test",
		Author:   "test",
		Version:  "1.0.0",
		Enable:   true,
		Filename: scriptPath,
	}
	d.JsLoadScriptRaw(script)
	if script.ErrText != "" {
		t.Fatalf("native QuickJS rejected plugin: %s", script.ErrText)
	}
	if ext, ok := d.JsExtRegistry.Load(script.Name); !ok || ext == nil {
		t.Fatal("native QuickJS did not register its extension")
	}
}

func TestJsInit_QuickJSDoesNotFallbackWithoutNativePackage(t *testing.T) {
	if os.Getenv("SCARDICE_RUNTIME_ROOT") != "" || os.Getenv("SCARDICE_QUICKJS_PACKAGE") != "" {
		t.Skip("native QuickJS package is configured")
	}
	d := &Dice{
		Logger: zap.NewNop().Sugar(),
		BaseConfig: BaseConfig{
			DataDir: t.TempDir(),
		},
		ImSession: &IMSession{
			ServiceAtNew: new(SyncMap[string, *GroupInfo]),
			EndPoints:    []*EndPointInfo{},
		},
		DirtyGroups:  new(SyncMap[string, int64]),
		AttrsManager: &AttrsManager{},
	}
	d.Config.JsEngine = "quickjs"

	d.JsInit()

	if d.Config.JsEnable {
		t.Fatal("QuickJS was enabled without an installed native provider")
	}
	if d.ExtLoopManager == nil {
		t.Fatal("QuickJS initialization did not create a loop manager")
	}
	if loop, _ := d.ExtLoopManager.CurrentLoop(); loop != nil {
		t.Fatal("QuickJS initialization retained a loop after provider failure")
	}
}

func TestJsLoadScriptRaw_NativeQuickJSRejectsPathESMImport(t *testing.T) {
	if os.Getenv("SCARDICE_RUNTIME_ROOT") == "" && os.Getenv("SCARDICE_QUICKJS_PACKAGE") == "" {
		t.Skip("native QuickJS package is not configured")
	}
	dataDir := t.TempDir()
	scriptPath := filepath.Join(dataDir, "quickjs-blocked-import.js")
	if err := os.WriteFile(scriptPath, []byte(`import "./blocked-helper.js";`), 0o600); err != nil {
		t.Fatal(err)
	}

	d := &Dice{
		Logger: zap.NewNop().Sugar(),
		BaseConfig: BaseConfig{
			DataDir: dataDir,
		},
		ImSession: &IMSession{
			ServiceAtNew: new(SyncMap[string, *GroupInfo]),
			EndPoints:    []*EndPointInfo{},
		},
		DirtyGroups:  new(SyncMap[string, int64]),
		AttrsManager: &AttrsManager{},
		ExtRegistry:  new(SyncMap[string, *ExtInfo]),
	}
	d.Config.JsEngine = "quickjs"
	d.JsInit()
	t.Cleanup(func() {
		if d.ExtLoopManager != nil {
			d.ExtLoopManager.SetLoop(nil)
		}
	})
	if !d.Config.JsEnable {
		t.Fatal("native QuickJS initialization failed")
	}

	script := &JsScriptInfo{
		Name:     "QuickJS Blocked Import",
		Enable:   true,
		Filename: scriptPath,
	}
	d.JsLoadScriptRaw(script)

	if script.ErrText == "" {
		t.Fatal("path-backed ESM import unexpectedly succeeded")
	}
	if script.Enable {
		t.Fatal("path-backed ESM import remained enabled")
	}
	if _, ok := d.JsExtRegistry.Load(script.Name); ok {
		t.Fatal("path-backed ESM import registered an extension")
	}
}

func TestJsInit_BindsGojaRandSourceToGlobalRandSource(t *testing.T) {
	src := &countingDiceSource{values: []uint64{1 << 63}}
	installGlobalDiceSourceState(t, completeSourceMap(
		sourceOverride{mode: DiceRandomModePCG, src: src},
	), nil)
	if _, err := globalRandSource.SetActive(DiceRandomModePCG); err != nil {
		t.Fatalf("activate pcg source: %v", err)
	}
	d := &Dice{
		Logger: zap.NewNop().Sugar(),
		Config: NewConfig(nil),
	}
	if d.Logger == nil {
		t.Fatal("expected logger to be initialized")
	}
	d.Config.DiceRandomMode = string(DiceRandomModePCG)

	vm := goja.New()
	vm.SetRandSource(func() float64 {
		return float64(globalRandSource.Uint64()>>11) / (1 << 53)
	})
	var got float64
	var runErr error
	value, err := vm.RunString("Math.random()")
	if err != nil {
		runErr = err
	} else {
		got = value.ToFloat()
	}
	if runErr != nil {
		t.Fatalf("Math.random() error = %v", runErr)
	}

	want := float64((uint64(1)<<63)>>11) / (1 << 53)
	if got != want {
		t.Fatalf("Math.random() = %.16f, want %.16f", got, want)
	}

	if src.index != 1 {
		t.Fatalf("system dice source consumed %d values, want 1", src.index)
	}
}
