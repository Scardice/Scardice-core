package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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

	manager := &dice.DiceManager{HelpDocEngineType: int(dice.BlugeSearch)}
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
	reloadReq.Header.Set("Token", token)
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
	treeReq.Header.Set("Token", token)
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

func TestHelpDocReadAPIsWaitForManagerReplacement(t *testing.T) {
	root := switchAPIToTempWorkdir(t)
	writeAPIHelpDocFile(t, root, "api-group/startup.json", map[string]string{"startup-entry": "ready"})

	const token = "helpdoc-read-lock-test"
	manager := &dice.DiceManager{HelpDocEngineType: int(dice.BlugeSearch)}
	manager.AccessTokens.Store(token, true)
	testDice := &dice.Dice{Parent: manager, Config: dice.Config{}, CmdMap: dice.CmdMapCls{}}
	manager.Dice = []*dice.Dice{testDice}

	oldMyDice, oldDM := myDice, dm
	myDice, dm = testDice, manager
	t.Cleanup(func() {
		if manager.Help != nil {
			manager.Help.Close()
		}
		myDice, dm = oldMyDice, oldDM
	})

	manager.InitHelp()
	if manager.Help == nil {
		t.Fatal("initial help load did not publish a manager")
	}
	if err := manager.WithHelpDocManagerWrite(func(help *dice.HelpManager) error {
		help.Config = &dice.HelpConfig{Aliases: map[string][]string{
			"startup-alias": {"startup.json"},
		}}
		return nil
	}); err != nil {
		t.Fatalf("set test HelpDoc config: %v", err)
	}

	locked := make(chan struct{})
	release := make(chan struct{})
	writerDone := make(chan error, 1)
	writerFinished := make(chan struct{})
	var releaseOnce sync.Once
	releaseWriter := func() {
		releaseOnce.Do(func() { close(release) })
	}
	defer func() {
		releaseWriter()
		<-writerFinished
	}()
	go func() {
		defer close(writerFinished)
		writerDone <- manager.WithHelpDocManagerWrite(func(help *dice.HelpManager) error {
			manager.IsHelpReloading.Store(true)
			manager.Help = nil
			close(locked)
			<-release
			manager.Help = help
			manager.IsHelpReloading.Store(false)
			return nil
		})
	}()
	<-locked
	e := echo.New()
	statusReq := httptest.NewRequest(http.MethodGet, "/helpdoc/status", nil)
	statusRec := httptest.NewRecorder()
	if err := helpDocStatus(e.NewContext(statusReq, statusRec)); err != nil {
		t.Fatalf("helpDocStatus returned an error: %v", err)
	}
	var statusBody struct {
		Result  bool `json:"result"`
		Loading bool `json:"loading"`
	}
	if err := json.Unmarshal(statusRec.Body.Bytes(), &statusBody); err != nil {
		t.Fatalf("decode helpdoc status response: %v", err)
	}
	if !statusBody.Result || !statusBody.Loading {
		t.Fatalf("helpDocStatus = %s, want result=true and loading=true", statusRec.Body.String())
	}

	type response struct {
		name string
		code int
		body []byte
		err  error
	}
	results := make(chan response, 3)
	started := make(chan struct{}, 3)
	go func() {
		started <- struct{}{}
		req := httptest.NewRequest(http.MethodGet, "/helpdoc/tree", nil)
		req.Header.Set("Token", token)
		rec := httptest.NewRecorder()
		err := helpDocTree(e.NewContext(req, rec))
		results <- response{name: "tree", code: rec.Code, body: rec.Body.Bytes(), err: err}
	}()
	go func() {
		started <- struct{}{}
		req := httptest.NewRequest(http.MethodPost, "/helpdoc/textitem/get_page", strings.NewReader(`{"pageNum":1,"pageSize":100}`))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		err := helpGetTextItemPage(e.NewContext(req, rec))
		results <- response{name: "page", code: rec.Code, body: rec.Body.Bytes(), err: err}
	}()
	go func() {
		started <- struct{}{}
		req := httptest.NewRequest(http.MethodGet, "/helpdoc/config", nil)
		rec := httptest.NewRecorder()
		err := helpGetConfig(e.NewContext(req, rec))
		results <- response{name: "config", code: rec.Code, body: rec.Body.Bytes(), err: err}
	}()
	<-started
	<-started
	<-started

	early := false
	select {
	case <-results:
		early = true
	case <-time.After(50 * time.Millisecond):
	}
	releaseWriter()
	if err := <-writerDone; err != nil {
		t.Fatalf("release HelpManager writer: %v", err)
	}

	seen := make(map[string]bool, 3)
	for range 3 {
		select {
		case got := <-results:
			if got.err != nil {
				t.Fatalf("%s handler returned an error: %v", got.name, got.err)
			}
			if got.code != http.StatusOK {
				t.Fatalf("%s status = %d, want %d", got.name, got.code, http.StatusOK)
			}
			switch got.name {
			case "tree":
				var body struct {
					Result bool            `json:"result"`
					Data   []*dice.HelpDoc `json:"data"`
				}
				if err := json.Unmarshal(got.body, &body); err != nil {
					t.Fatalf("decode tree response: %v", err)
				}
				if !body.Result || !helpDocTreeHasName(body.Data, "startup.json") {
					t.Fatalf("tree response does not include the loaded help doc: %s", got.body)
				}
			case "page":
				var body struct {
					Result bool `json:"result"`
					Data   []struct {
						From string `json:"from"`
					} `json:"data"`
				}
				if err := json.Unmarshal(got.body, &body); err != nil {
					t.Fatalf("decode text-item response: %v", err)
				}
				found := false
				for _, item := range body.Data {
					if filepath.Base(item.From) == "startup.json" {
						found = true
						break
					}
				}
				if !body.Result || !found {
					t.Fatalf("text-item response does not include the loaded help doc: %s", got.body)
				}
			case "config":
				var body dice.HelpConfig
				if err := json.Unmarshal(got.body, &body); err != nil {
					t.Fatalf("decode helpdoc config response: %v", err)
				}
				aliases := body.Aliases["startup-alias"]
				if len(aliases) != 1 || aliases[0] != "startup.json" {
					t.Fatalf("config response lost the loaded HelpDoc configuration: %s", got.body)
				}
			}
			seen[got.name] = true
		case <-time.After(5 * time.Second):
			t.Fatal("HelpDoc read handlers did not finish after manager replacement")
		}
	}
	if early {
		t.Fatal("HelpDoc read handler returned while the manager was being replaced")
	}
	if !seen["tree"] || !seen["page"] || !seen["config"] {
		t.Fatalf("missing responses: %#v", seen)
	}
}

func switchAPIToTempWorkdir(t *testing.T) string {
	t.Helper()

	root := t.TempDir()
	t.Chdir(root)

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
