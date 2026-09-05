package dice

import (
	"context"
	"testing"

	"github.com/dop251/goja"
	"go.uber.org/zap"

	"Scardice-core/utils/jsengine"
)

func TestScriptRuntimeFallbackPreservesExistingLoop(t *testing.T) {
	d := &Dice{Logger: zap.NewNop().Sugar(), ExtLoopManager: NewJsLoopManager()}
	manager := NewJSRuntimeManagerForDice(d)
	d.jsRuntimeManager = manager
	loop, err := manager.Resolve(context.Background(), jsengine.EngineGoja, jsengine.RuntimeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	version := d.ExtLoopManager.SetLoop(loop)
	t.Cleanup(func() {
		d.ExtLoopManager.SetLoop(nil)
	})
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		return runtime.Set("existingPluginState", 42)
	}); err != nil {
		t.Fatal(err)
	}

	descriptor := jsengine.Descriptor{ID: "unavailable", Name: "Unavailable", Author: "Author", Extensions: []string{".js"}}
	registerScriptSelectionCandidate(t, manager, descriptor)
	manager.providers[descriptor.ID] = scriptSelectionProvider{descriptor: descriptor}
	source := "// ==UserScript==\n// @runtime unavailable:Author\n// ==/UserScript==\n"
	selected, _, err := manager.ParseUserScript("fallback.js", source)
	if err != nil {
		t.Fatal(err)
	}
	info := &JsScriptInfo{Filename: "fallback.js", RuntimeID: string(selected)}
	resolved, generation, err := d.ensureJSScriptLoop(info, source)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != loop || generation != version || info.RuntimeID != "goja" {
		t.Fatalf("fallback did not reuse the existing runtime: loop=%v generation=%d engine=%s", resolved, generation, info.RuntimeID)
	}
	if err := resolved.Run(func(runtime jsengine.Runtime) error {
		state, err := runtime.Get("existingPluginState").ExportPrimitive()
		if err == nil && state != int64(42) {
			t.Errorf("existing plugin state = %v, want 42", state)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyPreprocessRunsOnce(t *testing.T) {
	d := &Dice{Logger: zap.NewNop().Sugar(), ExtLoopManager: NewJsLoopManager()}
	d.Config.JsEnable = true
	manager := NewJSRuntimeManagerForDice(d)
	loop, err := manager.Resolve(context.Background(), jsengine.EngineGoja, jsengine.RuntimeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	version := d.ExtLoopManager.SetLoop(loop)
	t.Cleanup(func() {
		d.ExtLoopManager.SetLoop(nil)
	})
	calls := 0
	ext := &ExtInfo{IsJsExt: true, JSLoopVersion: version,
		OnMessagePreprocess: func(*MsgContext, *Message) goja.Value {
			calls++
			return goja.Undefined()
		},
	}
	ext.CallOnMessagePreprocess(d, &MsgContext{}, &Message{})
	if calls != 1 {
		t.Fatalf("one message invoked the legacy callback %d times", calls)
	}
}
