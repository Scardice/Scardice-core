package docengine

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func newTestBlugeSearchEngine(t *testing.T) *BlugeSearchEngine {
	t.Helper()

	previousIndexDir := indexDir
	indexDir = filepath.Join(t.TempDir(), "index")
	t.Cleanup(func() {
		indexDir = previousIndexDir
	})

	engine, err := NewBlugeSearchEngine()
	if err != nil {
		t.Fatalf("create Bluge search engine: %v", err)
	}
	t.Cleanup(engine.Close)
	return engine
}

func TestBlugeDocEngineIgnoresLegacyIndexContents(t *testing.T) {
	// Given
	previousIndexDir := indexDir
	indexDir = filepath.Join(t.TempDir(), "index")
	t.Cleanup(func() {
		indexDir = previousIndexDir
	})
	if err := os.MkdirAll(indexDir, 0o755); err != nil {
		t.Fatalf("create legacy index directory: %v", err)
	}
	legacyMarker := filepath.Join(indexDir, "index_meta.json")
	if err := os.WriteFile(legacyMarker, []byte(`{"title":"legacy-only-entry"}`), 0o600); err != nil {
		t.Fatalf("write legacy index marker: %v", err)
	}

	// When
	engine, err := NewBlugeSearchEngine()
	if err != nil {
		t.Fatalf("create Bluge search engine: %v", err)
	}
	t.Cleanup(engine.Close)

	// Then
	if !engine.IndexFreshlyCreated() {
		t.Fatal("legacy index should force a fresh Bluge index")
	}
	ids, err := engine.ListAllDocumentIDs()
	if err != nil {
		t.Fatalf("list rebuilt index documents: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("rebuilt index contains %d legacy documents, want 0", len(ids))
	}
	if _, err := os.Stat(legacyMarker); !os.IsNotExist(err) {
		t.Fatalf("legacy index marker was retained: %v", err)
	}
}

func TestBlugeDocEnginePreservesNumericLookupMapping(t *testing.T) {
	// Given
	engine := newTestBlugeSearchEngine(t)
	for _, item := range []HelpTextItem{
		{Group: "rules", From: "first.json", Title: "first-entry", Content: "first", PackageName: "test"},
		{Group: "rules", From: "second.json", Title: "second-entry", Content: "second", PackageName: "test"},
	} {
		if _, err := engine.AddItem(item); err != nil {
			t.Fatalf("add help item: %v", err)
		}
	}
	if err := engine.AddItemApply(true); err != nil {
		t.Fatalf("apply help items: %v", err)
	}

	// When
	result, total, _, _, err := engine.Search(nil, "second-entry", true, 10, 1, "")
	if err != nil {
		t.Fatalf("search help item: %v", err)
	}
	pageTotal, pageItems, err := engine.PaginateDocuments(10, 1, "", "", "")
	if err != nil {
		t.Fatalf("paginate help items: %v", err)
	}

	// Then
	if total != 1 || len(result.Hits) != 1 {
		t.Fatalf("search total/hits = %d/%d, want 1/1", total, len(result.Hits))
	}
	if _, err := strconv.Atoi(result.Hits[0].ID); err != nil {
		t.Fatalf("search ID %q is not numeric", result.Hits[0].ID)
	}
	if pageTotal != 2 || len(pageItems) != 2 {
		t.Fatalf("page total/items = %d/%d, want 2/2", pageTotal, len(pageItems))
	}
	for _, item := range pageItems {
		if item.InternalID == "" {
			t.Fatal("paged help item has no internal ID")
		}
		stored, err := engine.GetItemByInternalID(item.InternalID)
		if err != nil {
			t.Fatalf("lookup paged item %q: %v", item.InternalID, err)
		}
		if stored.Title != item.Title {
			t.Fatalf("stored title = %q, want %q", stored.Title, item.Title)
		}
	}
}

func TestBlugeDocEngineReopensCurrentIndex(t *testing.T) {
	// Given
	previousIndexDir := indexDir
	indexDir = filepath.Join(t.TempDir(), "index")
	t.Cleanup(func() {
		indexDir = previousIndexDir
	})
	first, err := NewBlugeSearchEngine()
	if err != nil {
		t.Fatalf("create first Bluge search engine: %v", err)
	}
	if _, err = first.AddItem(HelpTextItem{Title: "persisted-entry", Content: "persisted"}); err != nil {
		t.Fatalf("add persisted help item: %v", err)
	}
	if err = first.AddItemApply(true); err != nil {
		t.Fatalf("apply persisted help item: %v", err)
	}
	wantIDs, err := first.ListAllDocumentIDs()
	if err != nil {
		t.Fatalf("list first index documents: %v", err)
	}
	first.Close()

	// When
	second, err := NewBlugeSearchEngine()
	if err != nil {
		t.Fatalf("reopen Bluge search engine: %v", err)
	}
	t.Cleanup(second.Close)
	gotIDs, err := second.ListAllDocumentIDs()
	if err != nil {
		t.Fatalf("list reopened index documents: %v", err)
	}

	// Then
	if second.IndexFreshlyCreated() {
		t.Fatal("current Bluge index was treated as incompatible")
	}
	if len(gotIDs) != 1 || gotIDs[0] != wantIDs[0] {
		t.Fatalf("reopened document IDs = %v, want %v", gotIDs, wantIDs)
	}
}

func TestBlugeDocEngineRebuildsOldSchemaWithoutTranslatingDocuments(t *testing.T) {
	// Given
	previousIndexDir := indexDir
	indexDir = filepath.Join(t.TempDir(), "index")
	t.Cleanup(func() {
		indexDir = previousIndexDir
	})
	first, err := NewBlugeSearchEngine()
	if err != nil {
		t.Fatalf("create first Bluge search engine: %v", err)
	}
	if _, err = first.AddItem(HelpTextItem{Title: "old-schema-entry", Content: "old"}); err != nil {
		t.Fatalf("add old-schema help item: %v", err)
	}
	if err = first.AddItemApply(true); err != nil {
		t.Fatalf("apply old-schema help item: %v", err)
	}
	first.Close()
	if err = os.WriteFile(filepath.Join(indexDir, indexSchemaFile), []byte("0"), 0o600); err != nil {
		t.Fatalf("write old schema marker: %v", err)
	}

	// When
	second, err := NewBlugeSearchEngine()
	if err != nil {
		t.Fatalf("open old-schema index: %v", err)
	}
	t.Cleanup(second.Close)
	ids, err := second.ListAllDocumentIDs()
	if err != nil {
		t.Fatalf("list rebuilt index documents: %v", err)
	}

	// Then
	if !second.IndexFreshlyCreated() {
		t.Fatal("old-schema index should be rebuilt")
	}
	if len(ids) != 0 {
		t.Fatalf("rebuilt index contains %d translated documents, want 0", len(ids))
	}
}
