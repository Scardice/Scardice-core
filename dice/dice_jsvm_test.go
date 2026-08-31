package dice //nolint:testpackage

import (
	"os"
	"path/filepath"
	"testing"

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

func TestJsInit_QuickJSStartsExperimentalHost(t *testing.T) {
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
		t.Fatal("QuickJS-Go initialization left JS disabled")
	}
	if d.ExtLoopManager == nil {
		t.Fatal("QuickJS-Go initialization did not create a loop manager")
	}
	loop, err := d.ExtLoopManager.GetLoop(d.ExtLoopManager.version)
	if err != nil {
		t.Fatal(err)
	}
	if loop == nil || loop.Engine() != jsengine.EngineQuickJS {
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
			t.Fatal("QuickJS-Go Host API is incomplete")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestJsLoadScriptRaw_QuickJSExecutesAndRegistersPlugin(t *testing.T) {
	dataDir := t.TempDir()
	scriptPath := filepath.Join(dataDir, "quickjs-plugin.js")
	if err := os.WriteFile(scriptPath, []byte(`
		import { Buffer } from "buffer";
		import { subtle } from "crypto";
		const util = await import("util");
		const fs = require("fs");
		if (Buffer.from("ok").toString() !== "ok") throw new Error("buffer unavailable");
		if (typeof subtle.digest !== "function") throw new Error("crypto unavailable");
		if (util.format("%s:%d", "ok", 7) !== "ok:7") throw new Error("util unavailable");
		if (typeof fs.promises.readFile !== "function") throw new Error("fs unavailable");
		const ext = seal.ext.new("QuickJS Plugin Test", "test", "1.0.0");
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
	script := &JsScriptInfo{
		Name:     "QuickJS Plugin Test",
		Author:   "test",
		Version:  "1.0.0",
		Enable:   true,
		Filename: scriptPath,
	}
	d.JsLoadScriptRaw(script)

	if script.ErrText != "" {
		t.Fatalf("QuickJS-Go rejected plugin: %s", script.ErrText)
	}
	ext, ok := d.JsExtRegistry.Load("QuickJS Plugin Test")
	if !ok || ext == nil {
		t.Fatal("QuickJS-Go plugin did not register its extension")
	}
	if ext.Name != "QuickJS Plugin Test" {
		t.Fatalf("extension name = %q", ext.Name)
	}
}

func TestJsLoadScriptRaw_QuickJSRejectsPathESMImport(t *testing.T) {
	dataDir := t.TempDir()
	scriptPath := filepath.Join(dataDir, "quickjs-blocked-import.js")
	if err := os.WriteFile(scriptPath, []byte(`import "./blocked-helper.js";`), 0o600); err != nil {
		t.Fatal(err)
	}

	d := newQuickJSNodeTestDice(t)
	d.BaseConfig.DataDir = dataDir
	d.JsInit()
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
