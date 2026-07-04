package api //nolint:testpackage

import (
	"encoding/json"
	"net/http"
	"testing"

	"Scardice-core/dice"
)

func TestJsReloadStatusReturnsProgressSnapshot(t *testing.T) {
	oldMyDice, oldDM := myDice, dm
	testDice := &dice.Dice{}
	manager := &dice.DiceManager{Dice: []*dice.Dice{testDice}}
	const token = "test-token"
	manager.AccessTokens.Store(token, true)
	testDice.Parent = manager
	myDice, dm = testDice, manager
	t.Cleanup(func() {
		myDice, dm = oldMyDice, oldDM
	})

	testDice.BeginJsReloadProgress("开始重载 JS 环境")
	testDice.UpdateJsReloadProgress("loading", "正在加载 JS 插件：2/5", 2, 5, 69, "demo")

	rec := performReplyAPIRequest(t, http.MethodGet, "/sd-api/js/reload/status", "", token, jsReloadStatus)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var resp dice.JsReloadProgress
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal response error = %v", err)
	}
	if !resp.Running || resp.Stage != "loading" || resp.Current != 2 || resp.Total != 5 || resp.Percentage != 69 || resp.ScriptName != "demo" {
		t.Fatalf("response = %#v, want loading progress snapshot", resp)
	}
}

func TestJsReloadStatusRequiresAuth(t *testing.T) {
	oldMyDice, oldDM := myDice, dm
	testDice := &dice.Dice{}
	manager := &dice.DiceManager{Dice: []*dice.Dice{testDice}}
	testDice.Parent = manager
	myDice, dm = testDice, manager
	t.Cleanup(func() {
		myDice, dm = oldMyDice, oldDM
	})

	rec := performReplyAPIRequest(t, http.MethodGet, "/sd-api/js/reload/status", "", "bad-token", jsReloadStatus)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}
