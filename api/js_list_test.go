package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"Scardice-core/dice"
)

func TestJsListReportsRuntimeExtensionNamesBySourceScript(t *testing.T) {
	t.Setenv(adminAuthBypassEnv, "1")
	previousDice := myDice
	t.Cleanup(func() { myDice = previousDice })

	script := &dice.JsScriptInfo{Name: "脚本元数据名", Filename: "data/scripts/plugin.js"}
	extensions := new(dice.SyncMap[string, *dice.ExtInfo])
	extensions.Store("runtime-extension-z", &dice.ExtInfo{
		Name:   "runtime-extension-z",
		Source: &dice.JsScriptInfo{Filename: script.Filename},
	})
	extensions.Store("runtime-extension-a", &dice.ExtInfo{
		Name:   "runtime-extension-a",
		Source: &dice.JsScriptInfo{Filename: script.Filename},
	})
	extensions.Store("other-script-extension", &dice.ExtInfo{
		Name:   "other-script-extension",
		Source: &dice.JsScriptInfo{Filename: "data/scripts/other.js"},
	})
	myDice = &dice.Dice{
		Config:             dice.Config{JsConfig: dice.JsConfig{JsEnable: true}},
		JsScriptList:       []*dice.JsScriptInfo{script},
		JsExtRegistry:      extensions,
		JsBuiltinDigestSet: map[string]bool{},
	}

	e := echo.New()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/sd-api/js/list", nil)
	if err := jsList(e.NewContext(request, recorder)); err != nil {
		t.Fatalf("jsList returned error: %v", err)
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}

	var scripts []struct {
		Name           string   `json:"name"`
		ExtensionNames []string `json:"extensionNames"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &scripts); err != nil {
		t.Fatalf("decode jsList response: %v", err)
	}
	if len(scripts) != 1 || scripts[0].Name != script.Name {
		t.Fatalf("scripts = %#v, want one entry for %q", scripts, script.Name)
	}
	want := []string{"runtime-extension-a", "runtime-extension-z"}
	if !slices.Equal(scripts[0].ExtensionNames, want) {
		t.Fatalf("extensionNames = %v, want %v", scripts[0].ExtensionNames, want)
	}
}

func TestJsListReportsMemoryOnlyForRunningScriptsByRuntime(t *testing.T) {
	t.Setenv(adminAuthBypassEnv, "1")
	previousDice := myDice
	t.Cleanup(func() { myDice = previousDice })

	myDice = &dice.Dice{
		Config: dice.Config{JsConfig: dice.JsConfig{JsEnable: true}},
		JsScriptList: []*dice.JsScriptInfo{
			{Name: "disabled", Filename: "data/scripts/disabled.js", RuntimeID: "goja"},
			{Name: "unloaded", Filename: "data/scripts/unloaded.js", Enable: true},
			{Name: "quick", Filename: "data/scripts/quick.js", Enable: true, RuntimeID: "quickjs"},
			{Name: "goja", Filename: "data/scripts/goja.js", Enable: true, RuntimeID: "goja"},
		},
		JsExtRegistry:      new(dice.SyncMap[string, *dice.ExtInfo]),
		JsBuiltinDigestSet: map[string]bool{},
	}

	e := echo.New()
	recorder := httptest.NewRecorder()
	if err := jsList(e.NewContext(httptest.NewRequest(http.MethodGet, "/sd-api/js/list", nil), recorder)); err != nil {
		t.Fatal(err)
	}
	var scripts []struct {
		Name   string        `json:"name"`
		Memory *jsMemoryView `json:"memory"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &scripts); err != nil {
		t.Fatal(err)
	}
	status := make(map[string]string, len(scripts))
	for _, script := range scripts {
		if script.Memory == nil {
			status[script.Name] = "null"
		} else {
			status[script.Name] = script.Memory.Status
		}
	}
	// No Goja runtime has been swept in this Dice yet.
	want := map[string]string{"disabled": "null", "unloaded": "null", "quick": "unsupported", "goja": "pending"}
	for name, wantStatus := range want {
		if status[name] != wantStatus {
			t.Fatalf("memory status of %s = %q, want %q (all: %v)", name, status[name], wantStatus, status)
		}
	}
}

func TestJsMemoryForMapsTheSweptStatByScriptFile(t *testing.T) {
	sweptAt := time.UnixMilli(1_800_000_000_000)
	heap := map[string]dice.JSHeapStat{"a.js": {
		Script:      "a.js",
		Total:       dice.JSHeapAmount{Objects: 130, Bytes: 9000},
		Object:      dice.JSHeapAmount{Objects: 128, Bytes: 4000},
		ArrayBuffer: dice.JSHeapAmount{Objects: 2, Bytes: 5000},
		Large:       dice.JSHeapAmount{Objects: 1, Bytes: 4096},
		Samples:     2,
	}}
	running := func(file string) *dice.JsScriptInfo {
		return &dice.JsScriptInfo{Filename: file, Enable: true, RuntimeID: "goja"}
	}
	got := jsMemoryFor(running("a.js"), heap, sweptAt)
	if got.Status != "ok" || got.Objects != 130 || got.Bytes != 9000 || got.Object.Objects != 128 ||
		got.ArrayBuffer.Bytes != 5000 || got.Large.Bytes != 4096 || got.Samples != 2 || got.SweptAt != sweptAt.UnixMilli() {
		t.Fatalf("memory view = %+v", got)
	}
	// A swept plugin that keeps nothing alive is measured as zero, not unknown.
	if idle := jsMemoryFor(running("idle.js"), heap, sweptAt); idle.Status != "ok" || idle.Bytes != 0 || idle.SweptAt == 0 {
		t.Fatalf("idle plugin = %+v", idle)
	}
}
