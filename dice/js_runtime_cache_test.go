package dice

import (
	"os"
	"path/filepath"
	"testing"

	"Scardice-core/utils/jsengine"
)

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
	registerScriptSelectionCandidate(t, manager, descriptor)
	manager.providers[descriptor.ID] = scriptSelectionProvider{descriptor: descriptor}
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
