package dice

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
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

func TestDeckParseCacheUsesContentHash(t *testing.T) {
	root := switchToTempWorkdir(t)
	deckPath := filepath.Join(root, "data", "decks", "same-size.json")
	if err := os.MkdirAll(filepath.Dir(deckPath), 0o755); err != nil {
		t.Fatalf("mkdir decks dir: %v", err)
	}

	fixedTime := time.Unix(1700000000, 0)
	writeRawDeckFile(t, deckPath, `{"_title":["deck"],"table":["alpha"]}`)
	if err := os.Chtimes(deckPath, fixedTime, fixedTime); err != nil {
		t.Fatalf("set initial mtime: %v", err)
	}

	d := &Dice{Logger: zap.NewNop().Sugar()}
	DeckTryParse(d, filepath.ToSlash(filepath.Join("data", "decks", "same-size.json")))
	if len(d.DeckList) != 1 {
		t.Fatalf("initial deck parse count = %d", len(d.DeckList))
	}

	writeRawDeckFile(t, deckPath, `{"_title":["deck"],"table":["bravo"]}`)
	if err := os.Chtimes(deckPath, fixedTime, fixedTime); err != nil {
		t.Fatalf("set updated mtime: %v", err)
	}

	d.DeckList = nil
	DeckTryParse(d, filepath.ToSlash(filepath.Join("data", "decks", "same-size.json")))
	if len(d.DeckList) != 1 {
		t.Fatalf("updated deck parse count = %d", len(d.DeckList))
	}
	items := d.DeckList[0].DeckItems["table"]
	if len(items) != 1 || items[0] != "bravo" {
		t.Fatalf("deck cache should refresh by content hash, got %#v", items)
	}
}

func TestDeckParseCacheStoresAndReusesHash(t *testing.T) {
	root := switchToTempWorkdir(t)
	deckPath := filepath.Join(root, "data", "decks", "reuse.json")
	if err := os.MkdirAll(filepath.Dir(deckPath), 0o755); err != nil {
		t.Fatalf("mkdir decks dir: %v", err)
	}
	writeRawDeckFile(t, deckPath, `{"_title":["deck"],"table":["cached"]}`)

	d := &Dice{Logger: zap.NewNop().Sugar()}
	fn := filepath.ToSlash(filepath.Join("data", "decks", "reuse.json"))
	DeckTryParse(d, fn)
	if len(d.DeckList) != 1 {
		t.Fatalf("initial deck parse count = %d", len(d.DeckList))
	}

	cachePath := deckParseCachePath(fn)
	var cache deckParseCache
	if err := loadGobCacheFile(cachePath, &cache); err != nil {
		t.Fatalf("load deck parse cache: %v", err)
	}
	if cache.Hash == "" {
		t.Fatalf("deck parse cache should store content hash")
	}

	st, err := os.Stat(fn)
	if err != nil {
		t.Fatalf("stat deck file: %v", err)
	}
	cached, ok := loadDeckParseCache(fn, st)
	if !ok {
		t.Fatalf("unchanged deck should reuse parse cache")
	}
	items := cached.DeckItems["table"]
	if len(items) != 1 || items[0] != "cached" {
		t.Fatalf("cached deck items = %#v", cached.DeckItems)
	}
}

func TestDecksDetectReuseLogsOnlyChangedFiles(t *testing.T) {
	root := switchToTempWorkdir(t)
	keepPath := filepath.Join(root, "data", "decks", "keep.json")
	changePath := filepath.Join(root, "data", "decks", "change.json")
	if err := os.MkdirAll(filepath.Dir(keepPath), 0o755); err != nil {
		t.Fatalf("mkdir decks dir: %v", err)
	}
	writeRawDeckFile(t, keepPath, `{"_title":["keep"],"table":["keep"]}`)
	writeRawDeckFile(t, changePath, `{"_title":["change"],"table":["old"]}`)

	core, logs := observer.New(zapcore.InfoLevel)
	d := &Dice{Logger: zap.New(core).Sugar()}
	if reuse := DecksDetect(d); reuse {
		t.Fatalf("first deck detect should not reuse index")
	}

	writeRawDeckFile(t, changePath, `{"_title":["change"],"table":["new"]}`)
	d.DeckList = nil
	logs.TakeAll()
	if reuse := DecksDetect(d); !reuse {
		t.Fatalf("second deck detect should reuse index")
	}

	messages := observedMessages(logs.All())
	if !messagesContain(messages, "[牌堆] 尝试复用索引并进行增量更新") {
		t.Fatalf("reuse log missing, messages=%v", messages)
	}
	if !messagesContain(messages, "[牌堆] 增量更新进度: 更新 data/decks/change.json") {
		t.Fatalf("changed file update log missing, messages=%v", messages)
	}
	if messagesContain(messages, "[牌堆] 增量更新进度: 更新 data/decks/keep.json") {
		t.Fatalf("unchanged cached file should not be logged, messages=%v", messages)
	}
	if messagesContain(messages, "牌堆加载进度: data/decks/keep.json") {
		t.Fatalf("reuse path should not print full load progress for unchanged files, messages=%v", messages)
	}
	if !messagesContain(messages, "[牌堆] 增量更新完成，变更: true") {
		t.Fatalf("incremental completion log missing, messages=%v", messages)
	}
	if !messagesContain(messages, "[牌堆] 复用现有索引完成，共计加载牌堆数量:") {
		t.Fatalf("reuse completion summary missing, messages=%v", messages)
	}
}

func observedMessages(entries []observer.LoggedEntry) []string {
	messages := make([]string, 0, len(entries))
	for _, entry := range entries {
		messages = append(messages, entry.Message)
	}
	return messages
}

func messagesContain(messages []string, part string) bool {
	for _, message := range messages {
		if strings.Contains(message, part) {
			return true
		}
	}
	return false
}

func writeRawDeckFile(t *testing.T, path string, payload string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(payload), 0o644); err != nil {
		t.Fatalf("write deck file %s: %v", path, err)
	}
}
