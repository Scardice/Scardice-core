package dice

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"

	"Scardice-core/utils/jsengine"
)

type scriptSelectionProvider struct {
	descriptor jsengine.Descriptor
}

func (p scriptSelectionProvider) Descriptor() jsengine.Descriptor { return p.descriptor }

func (p scriptSelectionProvider) Open(context.Context, jsengine.RuntimeOptions) (jsengine.Loop, error) {
	return nil, errors.New("selection test provider does not open loops")
}

func registerScriptSelectionCandidate(t *testing.T, manager *JSRuntimeManager, descriptor jsengine.Descriptor) {
	t.Helper()
	if err := manager.registry.RegisterCandidate(jsengine.RuntimeManifest{
		ID: descriptor.ID, Name: descriptor.Name, Version: descriptor.Version,
		Language: descriptor.Language, Author: descriptor.Author,
		Extensions: descriptor.Extensions, Path: descriptor.Path,
	}); err != nil {
		t.Fatal(err)
	}
	manager.refreshStatuses()
}

func registerScriptSelectionProvider(t *testing.T, manager *JSRuntimeManager, provider jsengine.Provider) {
	t.Helper()
	descriptor := provider.Descriptor()
	if err := manager.registry.RegisterCandidate(jsengine.RuntimeManifest{
		ID: descriptor.ID, Name: descriptor.Name, Version: descriptor.Version,
		Language: descriptor.Language, Author: descriptor.Author,
		Capabilities: descriptor.Capabilities, Extensions: descriptor.Extensions, Path: descriptor.Path,
		Load: func() (jsengine.Provider, error) {
			return provider, nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	manager.refreshStatuses()
}

func TestJSRuntimeManagerSelectsFirstRuntimeBySuffixOrder(t *testing.T) {
	manager := NewJSRuntimeManager(t.TempDir())
	registerScriptSelectionCandidate(t, manager, jsengine.Descriptor{
		ID: "runtime-first", Author: "first", Extensions: []string{".demo"},
	})
	registerScriptSelectionCandidate(t, manager, jsengine.Descriptor{
		ID: "runtime-second", Author: "second", Extensions: []string{".demo"},
	})

	got, err := manager.SelectScriptRuntime("plugin.demo", "source")
	if err != nil {
		t.Fatal(err)
	}
	if got != "runtime-first" {
		t.Fatalf("suffix runtime = %q, want runtime-first", got)
	}
}

func TestJSRuntimeManagerUsesExplicitCandidatesAndParser(t *testing.T) {
	manager := NewJSRuntimeManager(t.TempDir())
	descriptor := jsengine.Descriptor{ID: "runtime-alpha", Name: "Alpha", Author: "Author", Extensions: []string{".alpha"}}
	registerScriptSelectionCandidate(t, manager, descriptor)

	source := "// ==UserScript==\n// @name parsed-by-core\n// @runtime runtime-alpha:Author\n// ==/UserScript==\n"
	id, metadata, err := manager.ParseUserScript("plugin.alpha", source)
	if err != nil {
		t.Fatal(err)
	}
	if id != descriptor.ID || metadata.Name != "parsed-by-core" {
		t.Fatalf("selected runtime = %q, metadata = %#v", id, metadata)
	}

	got, err := manager.SelectScriptRuntime("plugin.alpha", "// ==UserScript==\n// @runtime missing:none,runtime-alpha:Author\n// ==/UserScript==")
	if err != nil {
		t.Fatal(err)
	}
	if got != descriptor.ID {
		t.Fatalf("explicit fallback runtime = %q, want %q", got, descriptor.ID)
	}
}

func TestJSRuntimeManagerSeparatesSelectionFromOpenFallback(t *testing.T) {
	manager := NewJSRuntimeManager(t.TempDir())
	registerScriptSelectionCandidate(t, manager, jsengine.Descriptor{
		ID: "missing-runtime", Author: "Missing", Extensions: []string{".js"},
	})
	source := "// ==UserScript==\n// @name fallback\n// @runtime missing-runtime:Missing\n// ==/UserScript==\n"
	id, metadata, err := manager.ParseUserScript("plugin.js", source)
	if err != nil {
		t.Fatal(err)
	}
	if id != "missing-runtime" || metadata.Name != "fallback" {
		t.Fatalf("metadata selection = %q %#v, want missing-runtime", id, metadata)
	}

	resolvedID, loop, err := manager.ResolveScript(context.Background(), "plugin.js", source, jsengine.RuntimeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer loop.Close()
	if resolvedID != jsengine.EngineGoja {
		t.Fatalf("resolved fallback runtime = %q, want Goja", resolvedID)
	}
}

func TestJSRuntimeManagerRejectsUnsupportedScriptSuffix(t *testing.T) {
	manager := NewJSRuntimeManager(t.TempDir())
	if _, err := manager.SelectScriptRuntime("plugin.unsupported", "source"); err == nil {
		t.Fatal("unsupported suffix unexpectedly selected a runtime")
	}
}

func TestJSRuntimeManagerRejectsInvalidCommonMetadata(t *testing.T) {
	manager := NewJSRuntimeManager(t.TempDir())
	source := "// ==UserScript==\n// @runtime quickjs\n// ==/UserScript==\n"
	_, _, err := manager.ParseUserScript("plugin.js", source)
	if err == nil {
		t.Fatal("invalid runtime metadata unexpectedly accepted")
	}
}

func TestJSMetadataCacheInvalidatesWhenProviderIsInstalled(t *testing.T) {
	previousDir := jsCacheDir
	jsCacheDir = t.TempDir()
	t.Cleanup(func() { jsCacheDir = previousDir })
	manager := NewJSRuntimeManager(t.TempDir())
	source := "// ==UserScript==\n// @runtime alpha:Author\n// ==/UserScript==\n"
	id, _, err := manager.ParseUserScript("plugin.js", source)
	if err != nil {
		t.Fatal(err)
	}
	saveJsMetaCache(&jsMetaCache{Version: jsMetaCacheVersion, RuntimeKey: manager.scriptMetadataCacheKey(),
		Files: map[string]jsMetaCacheEntry{"plugin.js": {Meta: jsMetaInfo{RuntimeID: string(id)}}},
	})
	if cache := loadJsMetaCache(manager.scriptMetadataCacheKey()); cache == nil || cache.Files["plugin.js"].Meta.RuntimeID != "goja" {
		t.Fatal("unchanged providers should reuse the cached Goja selection")
	}

	descriptor := jsengine.Descriptor{ID: "alpha", Name: "Alpha", Author: "Author", Extensions: []string{".alpha"}}
	registerScriptSelectionProvider(t, manager, scriptSelectionProvider{descriptor: descriptor})
	if cache := loadJsMetaCache(manager.scriptMetadataCacheKey()); cache != nil {
		t.Fatal("new provider reused a stale runtime selection")
	}
	id, _, err = manager.ParseUserScript("plugin.js", source)
	if err != nil || id != "alpha" {
		t.Fatalf("fresh selection = %q, %v; want alpha", id, err)
	}
}

func TestJSMetadataCacheInvalidatesWhenMissingLibraryAppears(t *testing.T) {
	previousDir := jsCacheDir
	jsCacheDir = t.TempDir()
	t.Cleanup(func() { jsCacheDir = previousDir })
	manager := NewJSRuntimeManager(t.TempDir())
	library := filepath.Join(t.TempDir(), "runtime.so")
	registerScriptSelectionCandidate(t, manager, jsengine.Descriptor{
		ID: "alpha", Name: "Alpha", Author: "Author", Extensions: []string{".alpha"}, Path: library,
	})
	saveJsMetaCache(&jsMetaCache{Version: jsMetaCacheVersion, RuntimeKey: manager.scriptMetadataCacheKey()})
	if cache := loadJsMetaCache(manager.scriptMetadataCacheKey()); cache == nil {
		t.Fatal("unchanged missing-library state should reuse the cache")
	}
	if err := os.WriteFile(library, []byte("installed library"), 0o600); err != nil {
		t.Fatal(err)
	}
	if cache := loadJsMetaCache(manager.scriptMetadataCacheKey()); cache != nil {
		t.Fatal("installing the library without changing its manifest reused the cache")
	}
}

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
	registerScriptSelectionProvider(t, manager, scriptSelectionProvider{descriptor: descriptor})

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
	registerScriptSelectionProvider(t, manager, scriptSelectionProvider{descriptor: descriptor})
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
