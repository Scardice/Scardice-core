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
)

func TestHelpDocReloadAPIReflectsDeletedHelpDoc(t *testing.T) {
	root := switchAPIToTempWorkdir(t)

	const (
		keepRelPath   = "api-group/keep.json"
		removeRelPath = "api-group/remove.json"
		keepTitle     = "api-reload-keep-entry-88f742d5"
		removeTitle   = "api-reload-remove-entry-3d61f1aa"
		token         = "test-token"
	)

	writeAPIHelpDocFile(t, root, keepRelPath, map[string]string{keepTitle: "keep content"})
	removePath := writeAPIHelpDocFile(t, root, removeRelPath, map[string]string{removeTitle: "remove content"})

	manager := &dice.DiceManager{HelpDocEngineType: int(dice.BleveSearch)}
	manager.AccessTokens.Store(token, true)
	testDice := &dice.Dice{
		Parent: manager,
		Config: dice.Config{},
		CmdMap: dice.CmdMapCls{},
	}
	manager.Dice = []*dice.Dice{testDice}

	oldMyDice, oldDM := myDice, dm
	myDice, dm = testDice, manager
	t.Cleanup(func() {
		if manager.Help != nil {
			manager.Help.Close()
		}
		myDice = oldMyDice
		dm = oldDM
	})

	manager.InitHelp()

	total, items := manager.Help.GetHelpItemPage(1, 200, "", "", "", "")
	if countHelpItemsFromFile(items, "remove.json") != 1 {
		t.Fatalf("initial load should expose helpdoc remove.json exactly once in paged items, total=%d count=%d", total, countHelpItemsFromFile(items, "remove.json"))
	}

	if err := os.Remove(removePath); err != nil {
		t.Fatalf("remove helpdoc %q: %v", removePath, err)
	}

	e := echo.New()

	reloadReq := httptest.NewRequest(http.MethodPost, "/helpdoc/reload", nil)
	reloadReq.Header.Set("token", token)
	reloadRec := httptest.NewRecorder()
	if err := helpDocReload(e.NewContext(reloadReq, reloadRec)); err != nil {
		t.Fatalf("helpDocReload returned error: %v", err)
	}
	if reloadRec.Code != http.StatusOK {
		t.Fatalf("helpDocReload status = %d, want %d", reloadRec.Code, http.StatusOK)
	}

	var reloadResp struct {
		Result bool `json:"result"`
	}
	if err := json.Unmarshal(reloadRec.Body.Bytes(), &reloadResp); err != nil {
		t.Fatalf("decode reload response: %v", err)
	}
	if !reloadResp.Result {
		t.Fatalf("helpDocReload should return result=true, body=%s", reloadRec.Body.String())
	}

	treeReq := httptest.NewRequest(http.MethodGet, "/helpdoc/tree", nil)
	treeReq.Header.Set("token", token)
	treeRec := httptest.NewRecorder()
	if err := helpDocTree(e.NewContext(treeReq, treeRec)); err != nil {
		t.Fatalf("helpDocTree returned error: %v", err)
	}
	if treeRec.Code != http.StatusOK {
		t.Fatalf("helpDocTree status = %d, want %d", treeRec.Code, http.StatusOK)
	}

	var treeResp struct {
		Result bool            `json:"result"`
		Data   []*dice.HelpDoc `json:"data"`
	}
	if err := json.Unmarshal(treeRec.Body.Bytes(), &treeResp); err != nil {
		t.Fatalf("decode tree response: %v", err)
	}
	if !treeResp.Result {
		t.Fatalf("helpDocTree should return result=true, body=%s", treeRec.Body.String())
	}
	if helpDocTreeHasName(treeResp.Data, "remove.json") {
		t.Fatalf("tree response still contains deleted helpdoc")
	}
	if !helpDocTreeHasName(treeResp.Data, "keep.json") {
		t.Fatalf("tree response should still contain existing helpdoc")
	}

	total, items = manager.Help.GetHelpItemPage(1, 200, "", "", "", "")
	if countHelpItemsFromFile(items, "remove.json") != 0 {
		t.Fatalf("deleted helpdoc file remove.json should be removed from index after API reload, total=%d count=%d", total, countHelpItemsFromFile(items, "remove.json"))
	}

	if countHelpItemsFromFile(items, "keep.json") != 1 {
		t.Fatalf("existing helpdoc file keep.json should remain after API reload, total=%d count=%d", total, countHelpItemsFromFile(items, "keep.json"))
	}
}

func switchAPIToTempWorkdir(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	root := t.TempDir()
	if err := os.Chdir(root); err != nil {
		t.Fatalf("chdir to temp dir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(wd); err != nil {
			t.Fatalf("restore workdir: %v", err)
		}
	})

	if err := os.MkdirAll(filepath.Join(root, "data", "helpdoc"), 0o755); err != nil {
		t.Fatalf("mkdir data/helpdoc: %v", err)
	}

	return root
}

func writeAPIHelpDocFile(t *testing.T, root, relPath string, items map[string]string) string {
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

func helpDocTreeHasName(tree []*dice.HelpDoc, want string) bool {
	for _, node := range tree {
		if helpDocNodeHasName(node, want) {
			return true
		}
	}
	return false
}

func helpDocNodeHasName(node *dice.HelpDoc, want string) bool {
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

func countHelpItemsFromFile(items dice.HelpTextVos, fileName string) int {
	count := 0
	for _, item := range items {
		if filepath.Base(item.From) == fileName {
			count++
		}
	}
	return count
}
