package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/labstack/echo/v4"

	"Scardice-core/dice"
	"Scardice-core/logger"
)

func TestLogHistoryPaginationAndFilters(t *testing.T) {
	previousDice := myDice
	t.Cleanup(func() { myDice = previousDice })
	t.Chdir(t.TempDir())
	if err := os.Mkdir("data", 0o755); err != nil {
		t.Fatalf("create data directory: %v", err)
	}

	historyPath := filepath.Join("data", "ui.log")
	items := []logger.LogItem{
		{Level: "info", TS: 10, Msg: "alpha", Seq: 1},
		{Level: "warn", TS: 20, Msg: "beta", Seq: 2},
		{Level: "error", TS: 30, Msg: "gamma", Seq: 3},
		{Level: "error", TS: 40, Msg: "delta", Seq: 4},
		{Level: "info", TS: 50, Msg: "epsilon", Seq: 5},
	}
	var raw []byte
	for _, item := range items {
		line, err := json.Marshal(item)
		if err != nil {
			t.Fatalf("marshal log item: %v", err)
		}
		raw = append(raw, line...)
		raw = append(raw, '\n')
	}
	if err := os.WriteFile(historyPath, raw, 0o644); err != nil {
		t.Fatalf("write history file: %v", err)
	}

	writer := logger.NewUIWriter()
	writer.EnableHistory(historyPath)
	t.Cleanup(writer.CloseHistory)

	manager := &dice.DiceManager{}
	manager.AccessTokens.Store("log-history-token", true)
	myDice = &dice.Dice{Parent: manager, LogWriter: writer}
	manager.Dice = []*dice.Dice{myDice}

	first := callLogHistory(t, "/sd-api/log/history?limit=2", "log-history-token")
	if len(first.Items) != 2 || first.Items[0].Seq != 4 || first.Items[1].Seq != 5 {
		t.Fatalf("first page seqs = %v, want [4 5]", historySeqs(first.Items))
	}
	if !first.HasMore || first.NextBeforeSeq != 4 {
		t.Fatalf("first page hasMore=%v next=%d, want true/4", first.HasMore, first.NextBeforeSeq)
	}

	second := callLogHistory(t, "/sd-api/log/history?limit=2&beforeSeq=4", "log-history-token")
	if len(second.Items) != 2 || second.Items[0].Seq != 2 || second.Items[1].Seq != 3 {
		t.Fatalf("second page seqs = %v, want [2 3]", historySeqs(second.Items))
	}

	filtered := callLogHistory(t, "/sd-api/log/history?levels=error&startTs=25&endTs=35", "log-history-token")
	if len(filtered.Items) != 1 || filtered.Items[0].Msg != "gamma" {
		t.Fatalf("filtered items = %+v, want gamma", filtered.Items)
	}

	keyword := callLogHistory(t, "/sd-api/log/history?q=DELTA", "log-history-token")
	if len(keyword.Items) != 1 || keyword.Items[0].Msg != "delta" {
		t.Fatalf("keyword items = %+v, want delta", keyword.Items)
	}
}

func TestLogHistoryRejectsUnauthorized(t *testing.T) {
	previousDice := myDice
	t.Cleanup(func() { myDice = previousDice })
	manager := &dice.DiceManager{}
	myDice = &dice.Dice{Parent: manager, LogWriter: logger.NewUIWriter()}
	manager.Dice = []*dice.Dice{myDice}

	e := echo.New()
	request := httptest.NewRequest(http.MethodGet, "/sd-api/log/history", nil)
	recorder := httptest.NewRecorder()
	if err := logHistory(e.NewContext(request, recorder)); err != nil {
		t.Fatalf("call log history: %v", err)
	}
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", recorder.Code)
	}
}

func callLogHistory(t *testing.T, target, token string) logHistoryResponse {
	t.Helper()
	e := echo.New()
	request := httptest.NewRequest(http.MethodGet, target, nil)
	request.Header.Set("Token", token)
	recorder := httptest.NewRecorder()
	if err := logHistory(e.NewContext(request, recorder)); err != nil {
		t.Fatalf("call log history %s: %v", target, err)
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("log history %s status = %d, want 200", target, recorder.Code)
	}
	var response logHistoryResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode log history response: %v", err)
	}
	return response
}

func historySeqs(items []*logger.LogItem) []int64 {
	seqs := make([]int64, 0, len(items))
	for _, item := range items {
		seqs = append(seqs, item.Seq)
	}
	return seqs
}
