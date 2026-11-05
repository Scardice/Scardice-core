package dice //nolint:testpackage

import (
	"encoding/json"
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

func newJSVMTestDice(t *testing.T, dataDir string) *Dice {
	t.Helper()
	if dataDir == "" {
		dataDir = t.TempDir()
	}
	d, _ := newCanonicalTestDice(t)
	d.Logger = zap.NewNop().Sugar()
	d.BaseConfig.DataDir = dataDir
	updateCanonicalTestConfig(t, d, func(config *Config) { config.DataDir = dataDir })
	return d
}

func TestJsInit_WhenExtLoopManagerNil_DoesNotPanic(t *testing.T) {
	d := newJSVMTestDice(t, "")

	// 模拟运行时管理器尚未初始化但期望配置已启用。
	updateCanonicalTestConfig(t, d, func(config *Config) { config.JsEnable = true })
	d.ExtLoopManager = nil

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("JsInit should not panic when ExtLoopManager is nil, got: %v", r)
		}
		// 清理后台任务，避免测试进程残留 goroutine
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
	if config := d.Config(); config == nil || !config.JsEnable {
		t.Fatalf("expected configured JsEnable to remain true after JsInit")
	}

	if d.JsScriptCron == nil {
		t.Fatal("expected JS script cron scheduler to be initialized")
	}
	if d.JsScriptCronLock == nil {
		t.Fatal("expected JS script cron lock to be initialized")
	}
	triggered := make(chan struct{}, 1)
	task := JsScriptTask{
		taskType: "cron",
		cron:     d.JsScriptCron,
		cronExpr: "@every 1ms",
		lock:     d.JsScriptCronLock,
		logger:   d.Logger,
		task: func(JsScriptTaskCtx) {
			select {
			case triggered <- struct{}{}:
			default:
			}
		},
	}
	if !task.On() {
		t.Fatal("register JS script cron task")
	}
	defer task.Off()
	select {
	case <-triggered:
	case <-time.After(time.Second):
		t.Fatal("JS script cron scheduler did not execute a registered task")
	}
	d.ExtLoopManager.SetLoop(nil)
	if d.JsScriptCron != nil || d.JsScriptCronLock != nil {
		t.Fatal("stopping the JS runtime did not release the script cron scheduler")
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
			d := newJSVMTestDice(t, "")
			d.ExtLoopManager = test.manager
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
	d := newJSVMTestDice(t, "")
	updateCanonicalTestConfig(t, d, func(config *Config) {
		config.JsEngine = "quickjs"
		config.JsEnable = true
	})
	t.Cleanup(func() {
		if d.ExtLoopManager != nil {
			d.ExtLoopManager.SetLoop(nil)
		}
	})

	d.JsInit()

	if config := d.Config(); config == nil || !config.JsEnable {
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
	d := newJSVMTestDice(t, dataDir)
	updateCanonicalTestConfig(t, d, func(config *Config) {
		config.JsEngine = "quickjs"
		config.JsEnable = true
	})
	t.Cleanup(func() {
		if d.ExtLoopManager != nil {
			d.ExtLoopManager.SetLoop(nil)
		}
	})

	d.JsInit()
	if config := d.Config(); config == nil || !config.JsEnable || d.JsPrinter == nil {
		status, ok := d.jsRuntimeManagerInstance().Status("quickjs")
		t.Fatalf("native QuickJS initialization did not enable the console service: status=%+v ok=%v", status, ok)
	}
	loop, err := d.ExtLoopManager.GetLoop(d.ExtLoopManager.version)
	if err != nil {
		t.Fatal(err)
	}

	completed := make(chan string, 1)
	d.JsPrinter.RecordStart()
	if err := jsengine.RunWithContext(loop, &jsExecutionContext{Plugin: &ExtInfo{Name: "native-fs-test"}}, func(runtime jsengine.Runtime) error {
		if err := runtime.Bind("nativeServicesDone", func(result string) { completed <- result }); err != nil {
			return err
		}
		_, err := runtime.RunString("native-console.js", `
			console.log("log", 1);
			console.info("info");
			console.debug("debug");
			console.warn("warn");
			console.error("error");
			const random = crypto.getRandomValues(new Uint8Array(4));
			if (!(random instanceof Uint8Array) || random.length !== 4) {
				throw new Error("crypto service unavailable");
			}
			fs.writeFileSync("data://sync.txt", "sync fs");
			if (fs.readFileSync("data://sync.txt", { encoding: "utf8" }) !== "sync fs") {
				throw new Error("synchronous filesystem service unavailable");
			}
			const nativeFs = fs.promises.readFile("data://fixture.txt", { encoding: "utf8" }).then(value => {
				return fs.promises.writeFile("data://async.txt", value + " async");
			}).then(() => {
				return fs.promises.readFile("data://async.txt", { encoding: "utf8" });
			});
			const nativeFetch = fetch(`+strconv.Quote(fetchServer.URL)+`).then(response => {
				return response.json().then(value => ({
					status: response.status,
					ok: response.ok,
					message: value.message
				}));
			});
			const nativeTimer = new Promise(resolve => setTimeout(() => resolve("native timer"), 5));
			Promise.all([nativeFs, nativeFetch, nativeTimer]).then(
				([filesystem, fetch, timer]) => nativeServicesDone(JSON.stringify({filesystem, fetch, timer})),
				error => nativeServicesDone(JSON.stringify({error: String(error)}))
			);
		`)
		if err != nil {
			return err
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

	select {
	case raw := <-completed:
		var result struct {
			Filesystem string
			Fetch      struct {
				Status  int
				OK      bool
				Message string
			}
			Timer string
			Error string
		}
		if err := json.Unmarshal([]byte(raw), &result); err != nil {
			t.Fatal(err)
		}
		if result.Error != "" {
			t.Fatalf("native services failed: %s", result.Error)
		}
		if result.Filesystem != "native fs async" || result.Timer != "native timer" ||
			result.Fetch.Status != http.StatusOK || !result.Fetch.OK || result.Fetch.Message != "native fetch" {
			t.Fatalf("native service results = %+v", result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("native filesystem, fetch, and timer operations did not complete")
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
	d := newJSVMTestDice(t, dataDir)
	updateCanonicalTestConfig(t, d, func(config *Config) {
		config.JsEngine = "quickjs"
		config.JsEnable = true
	})
	t.Cleanup(func() {
		if d.ExtLoopManager != nil {
			d.ExtLoopManager.SetLoop(nil)
		}
	})
	d.JsInit()
	if config := d.Config(); config == nil || !config.JsEnable {
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
	d := newJSVMTestDice(t, "")
	updateCanonicalTestConfig(t, d, func(config *Config) {
		config.JsEngine = "quickjs"
		config.JsEnable = true
	})

	d.JsInit()

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

	d := newJSVMTestDice(t, dataDir)
	updateCanonicalTestConfig(t, d, func(config *Config) {
		config.JsEngine = "quickjs"
		config.JsEnable = true
	})
	d.JsInit()
	t.Cleanup(func() {
		if d.ExtLoopManager != nil {
			d.ExtLoopManager.SetLoop(nil)
		}
	})
	if config := d.Config(); config == nil || !config.JsEnable {
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
	d, _ := newCanonicalTestDice(t)
	d.Logger = zap.NewNop().Sugar()
	if d.Logger == nil {
		t.Fatal("expected logger to be initialized")
	}
	updateCanonicalTestConfig(t, d, func(config *Config) {
		config.DiceRandomMode = string(DiceRandomModePCG)
	})

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
