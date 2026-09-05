package dice

import (
	"os"
	"testing"

	"Scardice-core/utils/jsengine"
)

type scriptRecordingLoop struct {
	engine  jsengine.EngineID
	entries []jsengine.Entry
}

func (l *scriptRecordingLoop) Engine() jsengine.EngineID { return l.engine }
func (l *scriptRecordingLoop) Descriptor() jsengine.Descriptor {
	return jsengine.Descriptor{ID: l.engine}
}
func (l *scriptRecordingLoop) Run(fn func(jsengine.Runtime) error) error { return fn(nil) }
func (l *scriptRecordingLoop) LoadEntry(entry jsengine.Entry) error {
	l.entries = append(l.entries, entry)
	return nil
}
func (l *scriptRecordingLoop) Close() error { return nil }

func TestJsLoadScriptRawUsesSelectedRuntimeLoop(t *testing.T) {
	scriptPath := t.TempDir() + "/plugin.alpha"
	source := "// ==UserScript==\n// @name alpha\n// @runtime runtime-alpha:Author\n// ==/UserScript==\n42\n"
	if err := os.WriteFile(scriptPath, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}

	manager := NewJSRuntimeManager(t.TempDir())
	descriptor := jsengine.Descriptor{ID: "runtime-alpha", Name: "Alpha", Author: "Author", Extensions: []string{".alpha"}}
	registerScriptSelectionCandidate(t, manager, descriptor)
	manager.providers[descriptor.ID] = scriptSelectionProvider{descriptor: descriptor}

	loop := &scriptRecordingLoop{engine: descriptor.ID}
	dice := &Dice{ExtLoopManager: NewJsLoopManager(), jsRuntimeManager: manager}
	dice.ExtLoopManager.SetLoop(loop)
	info := &JsScriptInfo{Name: "alpha", Filename: scriptPath, Enable: true}
	dice.JsLoadScriptRaw(info)

	if info.ErrText != "" {
		t.Fatalf("script load failed: %s", info.ErrText)
	}
	if info.RuntimeID != string(descriptor.ID) {
		t.Fatalf("selected runtime ID = %q, want %q", info.RuntimeID, descriptor.ID)
	}
	if len(loop.entries) != 1 || loop.entries[0].Source != source {
		t.Fatalf("loaded entries = %#v", loop.entries)
	}
}
