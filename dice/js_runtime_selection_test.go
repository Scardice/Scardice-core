package dice

import (
	"Scardice-core/utils/jsengine"
	"context"
	"errors"
	"testing"
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
