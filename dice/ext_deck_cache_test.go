package dice

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCleanupStaleDeckParseCachesRemovesDeletedFiles(t *testing.T) {
	root := switchToTempWorkdir(t)

	keepPath := filepath.Join(root, "data", "decks", "keep.json")
	removePath := filepath.Join(root, "data", "decks", "remove.json")
	if err := os.MkdirAll(filepath.Dir(keepPath), 0o755); err != nil {
		t.Fatalf("mkdir decks dir: %v", err)
	}
	if err := os.WriteFile(keepPath, []byte(`{"_title":["keep"],"table":["a"]}`), 0o644); err != nil {
		t.Fatalf("write keep deck: %v", err)
	}
	if err := os.WriteFile(removePath, []byte(`{"_title":["remove"],"table":["b"]}`), 0o644); err != nil {
		t.Fatalf("write remove deck: %v", err)
	}

	if err := os.MkdirAll(deckParseCacheDir, 0o755); err != nil {
		t.Fatalf("mkdir deck cache dir: %v", err)
	}
	keepCache := deckParseCachePath("data/decks/keep.json")
	removeCache := deckParseCachePath("data/decks/remove.json")
	if err := os.WriteFile(keepCache, []byte("keep"), 0o644); err != nil {
		t.Fatalf("write keep cache: %v", err)
	}
	if err := os.WriteFile(removeCache, []byte("remove"), 0o644); err != nil {
		t.Fatalf("write remove cache: %v", err)
	}

	cleanupStaleDeckParseCaches([]string{"data/decks/keep.json"})

	if _, err := os.Stat(keepCache); err != nil {
		t.Fatalf("keep cache should remain: %v", err)
	}
	if _, err := os.Stat(removeCache); !os.IsNotExist(err) {
		t.Fatalf("remove cache should be deleted, err=%v", err)
	}
}
