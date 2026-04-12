package dice

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
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

func TestHelpIndexReuseIgnoresGeneratedHelpFingerprint(t *testing.T) {
	root := switchToTempWorkdir(t)
	_ = root

	manifestV1, err := buildHelpIndexManifest(BleveSearch)
	if err != nil {
		t.Fatalf("build manifest v1: %v", err)
	}
	manifestV2, err := buildHelpIndexManifest(BleveSearch)
	if err != nil {
		t.Fatalf("build manifest v2: %v", err)
	}
	if manifestV1.Fingerprint != manifestV2.Fingerprint {
		t.Fatalf("stable index mechanism should produce stable fingerprint")
	}
	manifestV1.Fingerprint = "legacy-dynamic-fingerprint"
	if !canReuseHelpIndex(&manifestV1, &manifestV2) {
		t.Fatalf("help index reuse should not depend on generated help fingerprint")
	}
}

func TestHelpManagerReuseRefreshesGeneratedHelpDocs(t *testing.T) {
	root := switchToTempWorkdir(t)
	_ = root

	builtin1 := CmdMapCls{
		"generated-refresh-test": {
			Help: "generated help v1",
		},
	}
	builtin2 := CmdMapCls{
		"generated-refresh-test": {
			Help: "generated help v2",
		},
	}

	manager1 := &HelpManager{EngineType: BleveSearch}
	manager1.Load(builtin1, nil)
	manager1.Close()

	manager2 := &HelpManager{EngineType: BleveSearch}
	manager2.Load(builtin2, nil)
	t.Cleanup(manager2.Close)

	_, items := manager2.GetHelpItemPage(1, 200, "", HelpBuiltinGroup, "", "")
	var matches []HelpTextVo
	for _, item := range items {
		if item.Title == "generated-refresh-test" {
			matches = append(matches, item)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("generated help should be refreshed without duplicates, count=%d items=%v", len(matches), matches)
	}
	if matches[0].Content != "generated help v2" {
		t.Fatalf("generated help content = %q, want updated content", matches[0].Content)
	}
}

func TestHelpManagerIncrementalRefreshUsesContentHash(t *testing.T) {
	root := switchToTempWorkdir(t)

	const (
		relPath = "hashgroup/same-size.json"
		title   = "hash-refresh-entry"
	)
	fixedTime := time.Unix(1700000000, 0)
	fullPath := writeRawTestHelpDocFile(t, root, relPath, `{"mod":"test-pack","helpdoc":{"hash-refresh-entry":"alpha"}}`)
	if err := os.Chtimes(fullPath, fixedTime, fixedTime); err != nil {
		t.Fatalf("set initial mtime: %v", err)
	}

	manager1 := &HelpManager{EngineType: BleveSearch}
	manager1.Load(CmdMapCls{}, nil)
	manager1.Close()

	fullPath = writeRawTestHelpDocFile(t, root, relPath, `{"mod":"test-pack","helpdoc":{"hash-refresh-entry":"bravo"}}`)
	if err := os.Chtimes(fullPath, fixedTime, fixedTime); err != nil {
		t.Fatalf("set updated mtime: %v", err)
	}

	manager2 := &HelpManager{EngineType: BleveSearch}
	manager2.Load(CmdMapCls{}, nil)
	t.Cleanup(manager2.Close)

	_, items := manager2.GetHelpItemPage(1, 200, "", "hashgroup", "", "")
	var matches []HelpTextVo
	for _, item := range items {
		if item.Title == title {
			matches = append(matches, item)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("hash-refreshed helpdoc should have one item, count=%d items=%v", len(matches), matches)
	}
	if matches[0].Content != "bravo" {
		t.Fatalf("hash-refreshed content = %q, want bravo", matches[0].Content)
	}
}

func TestHelpManagerReuseDoesNotTrustLowerManifestTotalID(t *testing.T) {
	root := switchToTempWorkdir(t)

	const (
		relPath = "idgroup/keep.json"
		title   = "id-stable-entry"
	)
	writeTestHelpDocFile(t, root, relPath, map[string]string{title: "stable content"})

	manager1 := &HelpManager{EngineType: BleveSearch}
	manager1.Load(CmdMapCls{"generated-id-test": {Help: "generated v1"}}, nil)
	manager1.Close()

	manifest, err := loadHelpIndexManifest()
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	manifest.TotalID = 0
	if err := writeHelpIndexManifest(*manifest); err != nil {
		t.Fatalf("write manifest with lower total id: %v", err)
	}

	manager2 := &HelpManager{EngineType: BleveSearch}
	manager2.Load(CmdMapCls{"generated-id-test": {Help: "generated v2"}}, nil)
	t.Cleanup(manager2.Close)

	_, items := manager2.GetHelpItemPage(1, 200, "", "", "", "")
	if countHelpItemsFromFile(items, "keep.json") != 1 {
		t.Fatalf("reused index should not overwrite existing helpdoc file item, items=%v", items)
	}
	generatedCount := 0
	for _, item := range items {
		if item.Title == "generated-id-test" {
			generatedCount++
			if item.Content != "generated v2" {
				t.Fatalf("generated content = %q, want generated v2", item.Content)
			}
		}
	}
	if generatedCount != 1 {
		t.Fatalf("generated help should be refreshed once, count=%d items=%v", generatedCount, items)
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

func writeRawTestHelpDocFile(t *testing.T, root, relPath, payload string) string {
	t.Helper()

	fullPath := filepath.Join(root, "data", "helpdoc", filepath.FromSlash(relPath))
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(fullPath), err)
	}
	if err := os.WriteFile(fullPath, []byte(payload), 0o644); err != nil {
		t.Fatalf("write raw helpdoc %s: %v", relPath, err)
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
