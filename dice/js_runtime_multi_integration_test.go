package dice

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"

	"Scardice-core/utils/jsengine"
)

func TestJsLoadScriptRawRoutesExplicitScriptsAcrossRuntimeLoops(t *testing.T) {
	if os.Getenv("SCARDICE_RUNTIME_ROOT") == "" && os.Getenv("SCARDICE_QUICKJS_PACKAGE") == "" {
		t.Skip("native QuickJS package is not configured")
	}
	dataDir := t.TempDir()
	gojaPath := filepath.Join(dataDir, "goja-routed.js")
	quickJSPath := filepath.Join(dataDir, "quickjs-routed.js")
	gojaSource := "// ==UserScript==\n// @name Goja Routed Plugin\n// @runtime goja:Scardice\n// ==/UserScript==\nglobalThis.__scardiceGojaMarker = \"goja\";\nconst ext = seal.ext.new(\"Goja Routed Plugin\", \"test\", \"1.0.0\"); seal.ext.register(ext);\n"
	quickJSSource := "// ==UserScript==\n// @name QuickJS Routed Plugin\n// @runtime quickjs:Scardice\n// ==/UserScript==\nif (typeof globalThis.__scardiceGojaMarker !== \"undefined\") throw new Error(\"cross-runtime global leaked\");\nconst ext = seal.ext.new(\"QuickJS Routed Plugin\", \"test\", \"1.0.0\"); seal.ext.register(ext);\n"
	if err := os.WriteFile(gojaPath, []byte(gojaSource), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(quickJSPath, []byte(quickJSSource), 0o600); err != nil {
		t.Fatal(err)
	}
	d := &Dice{
		Logger:     zap.NewNop().Sugar(),
		BaseConfig: BaseConfig{DataDir: dataDir},
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
		t.Fatal("QuickJS initialization failed")
	}

	gojaInfo, err := d.JsParseMeta(gojaPath, time.Now(), []byte(gojaSource), false)
	if err != nil {
		t.Fatal(err)
	}
	quickJSInfo, err := d.JsParseMeta(quickJSPath, time.Now(), []byte(quickJSSource), false)
	if err != nil {
		t.Fatal(err)
	}
	d.JsLoadScriptRaw(gojaInfo)
	d.JsLoadScriptRaw(quickJSInfo)
	if gojaInfo.ErrText != "" || quickJSInfo.ErrText != "" {
		t.Fatalf("routed script errors: Goja=%q QuickJS=%q", gojaInfo.ErrText, quickJSInfo.ErrText)
	}
	gojaExt, ok := d.JsExtRegistry.Load(gojaInfo.Name)
	if !ok || gojaExt == nil {
		t.Fatal("Goja-routed extension was not registered")
	}
	quickJSExt, ok := d.JsExtRegistry.Load(quickJSInfo.Name)
	if !ok || quickJSExt == nil {
		t.Fatal("QuickJS-routed extension was not registered")
	}
	gojaLoop, err := d.ExtLoopManager.GetLoop(gojaExt.JSLoopVersion)
	if err != nil {
		t.Fatal(err)
	}
	quickJSLoop, err := d.ExtLoopManager.GetLoop(quickJSExt.JSLoopVersion)
	if err != nil {
		t.Fatal(err)
	}
	if gojaLoop.Engine() != jsengine.EngineGoja || quickJSLoop.Engine() != "quickjs" {
		t.Fatalf("routed engines = Goja:%q QuickJS:%q", gojaLoop.Engine(), quickJSLoop.Engine())
	}
	if gojaExt.JSLoopVersion == quickJSExt.JSLoopVersion {
		t.Fatal("different explicit runtimes unexpectedly share a loop generation")
	}
}
