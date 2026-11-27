package logger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUIWriterHistoryPagination(t *testing.T) {
	dir := t.TempDir()
	writer := NewUIWriter()
	writer.SetLogLimit(50) // 内存只留 50 条，验证历史仍能读到全部 250 条
	writer.EnableHistory(filepath.Join(dir, "ui.log"))
	t.Cleanup(writer.CloseHistory)

	for i := 1; i <= 250; i++ {
		writer.append(&LogItem{Level: "info", TS: float64(1000 + i), Msg: fmt.Sprintf("log-%03d", i)})
	}

	first, hasMore, err := writer.ReadHistory(HistoryQuery{BeforeSeq: math.MaxInt64, Limit: 100})
	if err != nil {
		t.Fatalf("read first page: %v", err)
	}
	assertHistorySeqs(t, first, 151, 250)
	if !hasMore {
		t.Fatal("first page should have more")
	}

	second, hasMore, err := writer.ReadHistory(HistoryQuery{BeforeSeq: first[0].Seq, Limit: 100})
	if err != nil {
		t.Fatalf("read second page: %v", err)
	}
	assertHistorySeqs(t, second, 51, 150)
	if !hasMore {
		t.Fatal("second page should have more")
	}

	third, hasMore, err := writer.ReadHistory(HistoryQuery{BeforeSeq: second[0].Seq, Limit: 100})
	if err != nil {
		t.Fatalf("read third page: %v", err)
	}
	assertHistorySeqs(t, third, 1, 50)
	if hasMore {
		t.Fatal("third page should not have more")
	}
}

func TestUIWriterHistoryFilters(t *testing.T) {
	dir := t.TempDir()
	writer := NewUIWriter()
	writer.EnableHistory(filepath.Join(dir, "ui.log"))
	t.Cleanup(writer.CloseHistory)

	writer.append(&LogItem{Level: "info", TS: 10, Msg: "alpha"})
	writer.append(&LogItem{Level: "warn", TS: 20, Msg: "beta"})
	writer.append(&LogItem{Level: "error", TS: 30, Msg: "gamma"})
	writer.append(&LogItem{Level: "error", TS: 40, Msg: "delta"})

	items, _, err := writer.ReadHistory(HistoryQuery{
		BeforeSeq: math.MaxInt64,
		Limit:     10,
		Levels:    map[string]struct{}{"error": {}},
		StartTS:   25,
		EndTS:     45,
		Keyword:   "gam",
	})
	if err != nil {
		t.Fatalf("read filtered history: %v", err)
	}
	if len(items) != 1 || items[0].Msg != "gamma" {
		t.Fatalf("filtered items = %+v, want gamma", items)
	}

	items, _, err = writer.ReadHistory(HistoryQuery{
		BeforeSeq: math.MaxInt64,
		Limit:     10,
		Keyword:   "DELTA",
	})
	if err != nil {
		t.Fatalf("read keyword history: %v", err)
	}
	if len(items) != 1 || items[0].Msg != "delta" {
		t.Fatalf("keyword items = %+v, want delta", items)
	}
}

func TestUIWriterHistoryReadsRotatedFiles(t *testing.T) {
	dir := t.TempDir()
	backupPath := filepath.Join(dir, "ui-"+time.Now().Add(-time.Hour).Format("2006-01-02T15-04-05.000")+".log")
	currentPath := filepath.Join(dir, "ui.log")

	backupItems := make([]LogItem, 0, 5)
	for i := 1; i <= 5; i++ {
		backupItems = append(backupItems, LogItem{Level: "info", TS: float64(i), Msg: fmt.Sprintf("backup-%d", i), Seq: int64(i)})
	}
	currentItems := make([]LogItem, 0, 5)
	for i := 6; i <= 10; i++ {
		currentItems = append(currentItems, LogItem{Level: "info", TS: float64(i), Msg: fmt.Sprintf("current-%d", i), Seq: int64(i)})
	}
	writeHistoryLines(t, backupPath, backupItems)
	writeHistoryLines(t, currentPath, currentItems)

	writer := NewUIWriter()
	writer.EnableHistory(currentPath)
	t.Cleanup(writer.CloseHistory)

	writer.append(&LogItem{Level: "info", TS: 11, Msg: "new"})
	if writer.seq != 11 {
		t.Fatalf("seq after restart = %d, want 11", writer.seq)
	}

	items, _, err := writer.ReadHistory(HistoryQuery{BeforeSeq: math.MaxInt64, Limit: 20})
	if err != nil {
		t.Fatalf("read rotated history: %v", err)
	}
	assertHistorySeqs(t, items, 1, 11)
}

func TestUIWriterHistorySeqContinuesAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ui.log")

	first := NewUIWriter()
	first.EnableHistory(path)
	first.append(&LogItem{Level: "info", TS: 1, Msg: "one"})
	first.append(&LogItem{Level: "info", TS: 2, Msg: "two"})
	first.append(&LogItem{Level: "info", TS: 3, Msg: "three"})
	first.CloseHistory()

	second := NewUIWriter()
	second.EnableHistory(path)
	t.Cleanup(second.CloseHistory)
	second.append(&LogItem{Level: "info", TS: 4, Msg: "four"})

	if second.seq != 4 {
		t.Fatalf("seq after restart = %d, want 4", second.seq)
	}
	items, _, err := second.ReadHistory(HistoryQuery{BeforeSeq: math.MaxInt64, Limit: 10})
	if err != nil {
		t.Fatalf("read history after restart: %v", err)
	}
	assertHistorySeqs(t, items, 1, 4)
}

func TestUIWriterWritePersistsHistory(t *testing.T) {
	dir := t.TempDir()
	writer := NewUIWriter()
	writer.EnableHistory(filepath.Join(dir, "ui.log"))
	t.Cleanup(writer.CloseHistory)

	payload := []byte(`{"level":"warn","module":"main","time":"2026-11-22T21:19:24.986+0800","msg":"hello"}`)
	if _, err := writer.Write(payload); err != nil {
		t.Fatalf("write log: %v", err)
	}

	snapshot := writer.Snapshot()
	if len(snapshot) != 1 || snapshot[0].Level != "warn" || snapshot[0].Seq != 1 {
		t.Fatalf("snapshot = %+v, want one warn item with seq 1", snapshot)
	}

	items, _, err := writer.ReadHistory(HistoryQuery{BeforeSeq: math.MaxInt64, Limit: 10})
	if err != nil {
		t.Fatalf("read persisted history: %v", err)
	}
	if len(items) != 1 || items[0].Msg != "hello" || items[0].Seq != 1 {
		t.Fatalf("persisted items = %+v, want hello with seq 1", items)
	}
}

func assertHistorySeqs(t *testing.T, items []*LogItem, first, last int64) {
	t.Helper()
	if len(items) == 0 {
		t.Fatalf("history is empty, want seq %d..%d", first, last)
	}
	if items[0].Seq != first || items[len(items)-1].Seq != last {
		t.Fatalf("history seq range = %d..%d, want %d..%d", items[0].Seq, items[len(items)-1].Seq, first, last)
	}
	for i := 1; i < len(items); i++ {
		if items[i].Seq != items[i-1].Seq+1 {
			t.Fatalf("history seq not contiguous at %d: %d after %d", i, items[i].Seq, items[i-1].Seq)
		}
	}
}

func writeHistoryLines(t *testing.T, path string, items []LogItem) {
	t.Helper()
	var buf bytes.Buffer
	for _, item := range items {
		data, err := json.Marshal(item)
		if err != nil {
			t.Fatalf("marshal history item: %v", err)
		}
		buf.Write(data)
		buf.WriteByte('\n')
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write history file: %v", err)
	}
}
