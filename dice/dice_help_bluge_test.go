package dice

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestBlugeMigrationInvalidatesHelpIndexAndParsedCaches(t *testing.T) {
	// Given / When / Then
	if helpIndexSchemaVersion != 4 {
		t.Fatalf("help index schema version = %d, want 4", helpIndexSchemaVersion)
	}
	if helpDocParsedCacheVersion != 4 {
		t.Fatalf("parsed help cache version = %d, want 4", helpDocParsedCacheVersion)
	}
}

func TestHelpManagerColdStartRebuildsFromSourceAndIgnoresLegacyIndex(t *testing.T) {
	// Given
	root := switchToTempWorkdir(t)
	const (
		relPath     = "cold/source.json"
		sourceTitle = "cold-source-entry-31f8b2"
		legacyTitle = "legacy-cache-entry-97a04c"
	)
	writeTestHelpDocFile(t, root, relPath, map[string]string{sourceTitle: "authoritative source content"})
	legacyIndexDir := filepath.Join(root, "data", ".cache", "helpdoc", "index")
	if err := os.MkdirAll(legacyIndexDir, 0o755); err != nil {
		t.Fatalf("create legacy index directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(legacyIndexDir, "index_meta.json"), []byte(`{"title":"`+legacyTitle+`"}`), 0o600); err != nil {
		t.Fatalf("write legacy index sentinel: %v", err)
	}

	// When
	manager := &HelpManager{EngineType: BlugeSearch}
	manager.Load(nil, CmdMapCls{}, nil)
	t.Cleanup(manager.Close)
	sourceResult, sourceTotal, _, _, sourceErr := manager.searchEngine.Search(nil, sourceTitle, true, 10, 1, "")
	legacyResult, legacyTotal, _, _, legacyErr := manager.searchEngine.Search(nil, legacyTitle, true, 10, 1, "")

	// Then
	if sourceErr != nil {
		t.Fatalf("search authoritative source: %v", sourceErr)
	}
	if sourceTotal != 1 || len(sourceResult.Hits) != 1 {
		t.Fatalf("source search total/hits = %d/%d, want 1/1", sourceTotal, len(sourceResult.Hits))
	}
	if legacyErr != nil {
		t.Fatalf("search legacy sentinel: %v", legacyErr)
	}
	if legacyTotal != 0 || len(legacyResult.Hits) != 0 {
		t.Fatalf("legacy search total/hits = %d/%d, want 0/0", legacyTotal, len(legacyResult.Hits))
	}
}

func TestHelpManagerPageIDsResolveStoredItems(t *testing.T) {
	// Given
	root := switchToTempWorkdir(t)
	writeTestHelpDocFile(t, root, "mapping/items.json", map[string]string{
		"mapping-first":  "first content",
		"mapping-second": "second content",
	})
	manager := &HelpManager{EngineType: BlugeSearch}
	manager.Load(nil, CmdMapCls{}, nil)
	t.Cleanup(manager.Close)

	// When
	total, pageItems := manager.GetHelpItemPage(1, 200, "", "mapping", "", "")

	// Then
	if total != 2 || len(pageItems) != 2 {
		t.Fatalf("mapped page total/items = %d/%d, want 2/2", total, len(pageItems))
	}
	for _, pageItem := range pageItems {
		if pageItem.ID <= 0 {
			t.Fatalf("paged item has invalid numeric ID: %#v", pageItem)
		}
		lookupTotal, lookupItems := manager.GetHelpItemPage(1, 1, strconv.Itoa(pageItem.ID), "", "", "")
		if lookupTotal != 1 || len(lookupItems) != 1 {
			t.Fatalf("lookup ID %d total/items = %d/%d, want 1/1", pageItem.ID, lookupTotal, len(lookupItems))
		}
		if lookupItems[0].Title != pageItem.Title {
			t.Fatalf("lookup ID %d title = %q, want %q", pageItem.ID, lookupItems[0].Title, pageItem.Title)
		}
	}
}
