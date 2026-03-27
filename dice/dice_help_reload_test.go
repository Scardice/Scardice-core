package dice

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestHelpManagerStartupReloadRemovesDeletedHelpDocFromExistingIndex(t *testing.T) {
	root := switchToTempWorkdir(t)

	const (
		keepRelPath   = "testgroup/keep.json"
		removeRelPath = "testgroup/remove.json"
		keepTitle     = "startup-keep-entry-9f8c0a5a"
		removeTitle   = "startup-remove-entry-4f7d13bf"
	)

	writeTestHelpDocFile(t, root, keepRelPath, map[string]string{keepTitle: "keep content"})
	removePath := writeTestHelpDocFile(t, root, removeRelPath, map[string]string{removeTitle: "remove content"})

	manager1 := &HelpManager{EngineType: BleveSearch}
	manager1.Load(CmdMapCls{}, nil)
	t.Cleanup(manager1.Close)

	total, items := manager1.GetHelpItemPage(1, 200, "", "", "", "")
	if countHelpItemsFromFile(items, "remove.json") != 1 {
		t.Fatalf("initial load should expose helpdoc remove.json exactly once in paged items, total=%d count=%d", total, countHelpItemsFromFile(items, "remove.json"))
	}

	manifest, err := loadHelpIndexManifest()
	if err != nil {
		t.Fatalf("load manifest after initial load: %v", err)
	}
	if !manifestHasPath(manifest.Files, removeRelPath) {
		t.Fatalf("initial manifest missing %q", removeRelPath)
	}

	manager1.Close()

	if removeErr := os.Remove(removePath); removeErr != nil {
		t.Fatalf("remove helpdoc %q: %v", removePath, removeErr)
	}

	manager2 := &HelpManager{EngineType: BleveSearch}
	manager2.Load(CmdMapCls{}, nil)
	t.Cleanup(manager2.Close)

	total, items = manager2.GetHelpItemPage(1, 200, "", "", "", "")
	if countHelpItemsFromFile(items, "remove.json") != 0 {
		t.Fatalf("deleted helpdoc file remove.json should be removed from existing index, total=%d count=%d", total, countHelpItemsFromFile(items, "remove.json"))
	}

	if countHelpItemsFromFile(items, "keep.json") != 1 {
		t.Fatalf("unchanged helpdoc file keep.json should remain indexed, total=%d count=%d", total, countHelpItemsFromFile(items, "keep.json"))
	}

	if helpDocTreeHasName(manager2.HelpDocTree, "remove.json") {
		t.Fatalf("deleted helpdoc file should not remain in HelpDocTree")
	}
	if !helpDocTreeHasName(manager2.HelpDocTree, "keep.json") {
		t.Fatalf("existing helpdoc file should remain in HelpDocTree")
	}

	manifest, err = loadHelpIndexManifest()
	if err != nil {
		t.Fatalf("load manifest after reload: %v", err)
	}
	if manifestHasPath(manifest.Files, removeRelPath) {
		t.Fatalf("reloaded manifest still contains deleted file %q", removeRelPath)
	}
	if !manifestHasPath(manifest.Files, keepRelPath) {
		t.Fatalf("reloaded manifest should still contain %q", keepRelPath)
	}

	cachePath := filepath.Join(root, helpDocParsedCacheDir, helpDocCacheKey(filepath.Join("data/helpdoc", filepath.FromSlash(removeRelPath)))+".gob.zst")
	if _, err := os.Stat(cachePath); !os.IsNotExist(err) {
		t.Fatalf("reloaded parsed cache should remove deleted file cache %q, err=%v", cachePath, err)
	}
}

func TestBuildHelpIndexManifestFingerprintIncludesBuiltinAndExtHelp(t *testing.T) {
	root := switchToTempWorkdir(t)
	_ = root

	builtin1 := CmdMapCls{
		"foo": {
			Help: "foo help v1",
		},
	}
	builtin2 := CmdMapCls{
		"foo": {
			Help: "foo help v2",
		},
	}

	ext1 := []*ExtInfo{{
		Name:    "sample",
		Author:  "tester",
		Version: "1.0.0",
		CmdMap: CmdMapCls{
			"bar": {
				Help: "bar help v1",
			},
		},
		GetDescText: func(i *ExtInfo) string {
			return "desc v1"
		},
	}}
	ext2 := []*ExtInfo{{
		Name:    "sample",
		Author:  "tester",
		Version: "1.0.0",
		CmdMap: CmdMapCls{
			"bar": {
				Help: "bar help v2",
			},
		},
		GetDescText: func(i *ExtInfo) string {
			return "desc v2"
		},
	}}

	manifestBuiltinV1 := buildHelpIndexManifest(BleveSearch, builtin1, ext1)
	manifestBuiltinV2 := buildHelpIndexManifest(BleveSearch, builtin2, ext1)
	if manifestBuiltinV1.Fingerprint == manifestBuiltinV2.Fingerprint {
		t.Fatalf("builtin help changes should change help index fingerprint")
	}

	manifestExtV1 := buildHelpIndexManifest(BleveSearch, builtin1, ext1)
	manifestExtV2 := buildHelpIndexManifest(BleveSearch, builtin1, ext2)
	if manifestExtV1.Fingerprint == manifestExtV2.Fingerprint {
		t.Fatalf("ext help changes should change help index fingerprint")
	}
}

func switchToTempWorkdir(t *testing.T) string {
	t.Helper()

	root := t.TempDir()
	t.Chdir(root)

	if err := os.MkdirAll(filepath.Join(root, "data", "helpdoc"), 0o755); err != nil {
		t.Fatalf("mkdir data/helpdoc: %v", err)
	}

	return root
}

func writeTestHelpDocFile(t *testing.T, root, relPath string, items map[string]string) string {
	t.Helper()

	fullPath := filepath.Join(root, "data", "helpdoc", filepath.FromSlash(relPath))
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(fullPath), err)
	}

	payload := map[string]any{
		"mod":     "test-pack",
		"author":  "test",
		"brief":   "test",
		"comment": "test",
		"helpdoc": items,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal helpdoc %s: %v", relPath, err)
	}
	if err := os.WriteFile(fullPath, data, 0o644); err != nil {
		t.Fatalf("write helpdoc %s: %v", relPath, err)
	}
	return fullPath
}

func manifestHasPath(files []helpDocFileInfo, want string) bool {
	for _, file := range files {
		if file.Path == want {
			return true
		}
	}
	return false
}

func helpDocTreeHasName(tree []*HelpDoc, want string) bool {
	for _, node := range tree {
		if helpDocNodeHasName(node, want) {
			return true
		}
	}
	return false
}

func helpDocNodeHasName(node *HelpDoc, want string) bool {
	if node == nil {
		return false
	}
	if node.Name == want {
		return true
	}
	for _, child := range node.Children {
		if helpDocNodeHasName(child, want) {
			return true
		}
	}
	return false
}

func countHelpItemsFromFile(items HelpTextVos, fileName string) int {
	count := 0
	for _, item := range items {
		if filepath.Base(item.From) == fileName {
			count++
		}
	}
	return count
}
