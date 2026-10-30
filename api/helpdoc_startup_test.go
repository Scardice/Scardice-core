package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"Scardice-core/dice"
	"Scardice-core/eventstore"
	"Scardice-core/projectionset"
	"Scardice-core/utils/jsengine"
)

const (
	helpStartupBeforeReloadMarker = "help-startup-before-reload-gate"
	helpStartupAfterReloadMarker  = "help-startup-after-reload-gate"
	helpStartupScriptDoneMarker   = "help-startup-script-done"
	helpStartupAPIToken           = "help-startup-ordering-test"
)

type helpStartupHTTPLogSyncer struct {
	beforeReloadReached chan struct{}
	releaseBeforeReload chan struct{}
	afterReloadReached  chan struct{}
	releaseAfterReload  chan struct{}
	scriptDone          chan struct{}
	helpLoads           chan struct{}
	beforeOnce          sync.Once
	afterOnce           sync.Once
	doneOnce            sync.Once
	releaseBeforeOnce   sync.Once
	releaseAfterOnce    sync.Once
}

func newHelpStartupHTTPLogSyncer() *helpStartupHTTPLogSyncer {
	return &helpStartupHTTPLogSyncer{
		beforeReloadReached: make(chan struct{}),
		releaseBeforeReload: make(chan struct{}),
		afterReloadReached:  make(chan struct{}),
		releaseAfterReload:  make(chan struct{}),
		scriptDone:          make(chan struct{}),
		helpLoads:           make(chan struct{}, 4),
	}
}

func (s *helpStartupHTTPLogSyncer) Write(p []byte) (int, error) {
	switch {
	case bytes.Contains(p, []byte(helpStartupBeforeReloadMarker)):
		s.beforeOnce.Do(func() {
			close(s.beforeReloadReached)
			<-s.releaseBeforeReload
		})
	case bytes.Contains(p, []byte(helpStartupAfterReloadMarker)):
		s.afterOnce.Do(func() {
			close(s.afterReloadReached)
			<-s.releaseAfterReload
		})
	case bytes.Contains(p, []byte(helpStartupScriptDoneMarker)):
		s.doneOnce.Do(func() { close(s.scriptDone) })
	}
	if bytes.Contains(p, []byte("帮助文档异步加载结束")) {
		select {
		case s.helpLoads <- struct{}{}:
		default:
		}
	}
	return len(p), nil
}

func (*helpStartupHTTPLogSyncer) Sync() error { return nil }

func (s *helpStartupHTTPLogSyncer) releaseGates() {
	s.releaseBeforeOnce.Do(func() { close(s.releaseBeforeReload) })
	s.releaseAfterOnce.Do(func() { close(s.releaseAfterReload) })
}

type helpStartupWaitContext struct {
	context.Context
	reached chan struct{}
	once    sync.Once
}

func (c *helpStartupWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { c.reached <- struct{}{} })
	return c.Context.Done()
}

type helpStartupHTTPResult struct {
	status int
	body   []byte
	err    error
}

type pendingHelpTreeRequest struct {
	results chan helpStartupHTTPResult
	early   *helpStartupHTTPResult
}

const helpStartupHTTPChildEnv = "SCARDICE_HELP_STARTUP_HTTP_FIXTURE"

func TestHelpDocHTTPWaitsForInitialStartupPublication(t *testing.T) {
	if root := os.Getenv(helpStartupHTTPChildEnv); root != "" {
		runHelpDocHTTPStartupScenario(t, root)
		return
	}

	root := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHelpDocHTTPWaitsForInitialStartupPublication$")
	command.Env = append(os.Environ(), helpStartupHTTPChildEnv+"="+root)
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("bounded HTTP startup fixture exceeded 30s and was terminated: %s", output)
	}
	if err != nil {
		t.Fatalf("HTTP startup fixture failed: %v\n%s", err, output)
	}
}

func runHelpDocHTTPStartupScenario(t *testing.T, root string) {
	t.Chdir(root)
	const startupScript = `// ==UserScript==
// @name Help startup readiness fixture
// ==/UserScript==
seal.inst.config.jsEnable = false;
console.log("help-startup-before-reload-gate");
seal.inst.parent.reloadHelp();
console.log("help-startup-after-reload-gate");
const ext = seal.ext.new("startup-help-fixture", "test", "1.0.0");
seal.ext.register(ext);
console.log("help-startup-script-done");
`
	scriptsDir := filepath.Join(root, "data", "default", "scripts")
	if err := os.MkdirAll(scriptsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scriptsDir, "eventstore-startup.js"), []byte(startupScript), 0o600); err != nil {
		t.Fatal(err)
	}

	logSyncer := newHelpStartupHTTPLogSyncer()
	core := zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), logSyncer, zapcore.DebugLevel)
	restoreLogger := zap.ReplaceGlobals(zap.New(core))
	t.Cleanup(restoreLogger)

	ctx := context.Background()
	database, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(root, "events.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	store := eventstore.NewStore(database, projectionset.StoreOptions()...)
	runtime := &dice.Dice{
		BaseConfig:    dice.BaseConfig{Name: "default", DataDir: filepath.Join("data", "default")},
		DurableStore:  store,
		ContainerMode: true,
	}
	runtime.Config = dice.NewConfig(runtime)
	runtime.Config.BaseConfig = runtime.BaseConfig
	runtime.Config.JsEnable = false
	manager := &dice.DiceManager{Dice: []*dice.Dice{runtime}, HelpDocEngineType: int(dice.BlugeSearch)}
	if err := manager.InitializeRuntime(); err != nil {
		t.Fatal(err)
	}
	if err := manager.PrepareEventSourcedState(ctx); err != nil {
		t.Fatal(err)
	}
	runtime.AdvancedConfig.ExposeDangerousSealInst = true
	runtime.Config.JsEnable = true
	manager.AccessTokens.Store(helpStartupAPIToken, true)

	oldMyDice, oldDM := myDice, dm
	myDice, dm = runtime, manager
	server := echo.New()
	waitReached := make(chan struct{}, 4)
	server.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if c.Request().URL.Path == "/helpdoc/tree" {
				observed := &helpStartupWaitContext{Context: c.Request().Context(), reached: waitReached}
				c.SetRequest(c.Request().WithContext(observed))
			}
			return next(c)
		}
	})
	server.GET("/helpdoc/status", helpDocStatus)
	server.GET("/helpdoc/tree", helpDocTree)
	httpServer := httptest.NewServer(server)

	t.Cleanup(func() {
		httpServer.Close()
		logSyncer.releaseGates()
		runtime.WaitStartupJsLoaded()
		if runtime.ExtLoopManager != nil {
			if loop, _ := runtime.ExtLoopManager.CurrentLoop(); loop != nil {
				if err := loop.Run(func(jsengine.Runtime) error { return nil }); err != nil {
					t.Errorf("JS event loop did not start: %v", err)
				}
			}
			runtime.ExtLoopManager.SetLoop(nil)
		}
		manager.WaitNamesLoaded()
		if runtime.AttrsManager != nil {
			runtime.AttrsManager.Stop()
		}
		if runtime.Cron != nil {
			runtime.Cron.Stop()
		}
		if manager.Cron != nil {
			manager.Cron.Stop()
		}
		var help *dice.HelpManager
		if err := manager.WithHelpDocManagerRead(func(current *dice.HelpManager) error {
			help = current
			return nil
		}); err != nil {
			t.Errorf("read HelpDoc manager during cleanup: %v", err)
		}
		if help != nil {
			help.Close()
		}
		_ = store.Close()
		_ = database.Close()
		myDice, dm = oldMyDice, oldDM
	})

	manager.InitDice(nil)
	waitHelpStartupEvent(t, logSyncer.beforeReloadReached, "startup script before explicit ReloadHelp")

	statusBeforeReload, err := getHelpStartupHTTPStatus(t, httpServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	treeBeforeReload := beginHelpStartupTreeRequest(t, httpServer.URL, waitReached)
	cancelContext, cancelTreeRequest := context.WithCancel(context.Background())
	canceledTree := beginHelpStartupTreeRequestContext(t, httpServer.URL, waitReached, cancelContext)
	cancelTreeRequest()
	canceledResult := awaitHelpStartupTreeRequest(t, canceledTree)
	if !errors.Is(canceledResult.err, context.Canceled) {
		t.Errorf("cancelled startup tree request result = %#v, want context cancellation without waiting for startup", canceledResult)
	}
	logSyncer.releaseBeforeOnce.Do(func() { close(logSyncer.releaseBeforeReload) })

	waitHelpStartupEvent(t, logSyncer.afterReloadReached, "startup script after explicit ReloadHelp")
	statusAfterReload, err := getHelpStartupHTTPStatus(t, httpServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	treeAfterReload := beginHelpStartupTreeRequest(t, httpServer.URL, waitReached)
	logSyncer.releaseAfterOnce.Do(func() { close(logSyncer.releaseAfterReload) })

	waitHelpStartupEvent(t, logSyncer.scriptDone, "startup script completion")
	runtime.WaitStartupJsLoaded()
	for range 2 {
		waitHelpStartupEvent(t, logSyncer.helpLoads, "explicit and initial HelpDoc loads")
	}

	firstTree := resolveHelpStartupTreeRequest(t, treeBeforeReload)
	secondTree := resolveHelpStartupTreeRequest(t, treeAfterReload)
	finalStatus, err := getHelpStartupHTTPStatus(t, httpServer.URL)
	if err != nil {
		t.Fatal(err)
	}

	if !statusBeforeReload.Loading {
		t.Errorf("startup HelpDoc status before explicit reload = %s, want loading=true", statusBeforeReload.Body)
	}
	if !statusAfterReload.Loading {
		t.Errorf("startup HelpDoc status after explicit reload = %s, want initial load still pending", statusAfterReload.Body)
	}
	if !statusAfterReload.Result {
		t.Errorf("startup HelpDoc status after explicit reload = %s, want result=true", statusAfterReload.Body)
	}
	if treeBeforeReload.early != nil {
		t.Errorf("tree returned before initial HelpDoc publication: HTTP %d %s", treeBeforeReload.early.status, treeBeforeReload.early.body)
	}
	if treeAfterReload.early != nil {
		t.Errorf("tree exposed a partial index after explicit ReloadHelp: HTTP %d %s", treeAfterReload.early.status, treeAfterReload.early.body)
	}
	if firstTree.status != http.StatusOK || secondTree.status != http.StatusOK {
		t.Errorf("final tree responses status = %d, %d; want HTTP 200", firstTree.status, secondTree.status)
	}
	for i, result := range []helpStartupHTTPResult{firstTree, secondTree} {
		var body struct {
			Result bool            `json:"result"`
			Data   []*dice.HelpDoc `json:"data"`
		}
		if err := json.Unmarshal(result.body, &body); err != nil {
			t.Errorf("decode final tree response %d: %v; body=%s", i+1, err, result.body)
			continue
		}
		if !body.Result {
			t.Errorf("final tree response %d = %s, want result=true", i+1, result.body)
		}
	}
	var indexedExtension bool
	if err := manager.WithHelpDocManagerRead(func(help *dice.HelpManager) error {
		if help == nil {
			return nil
		}
		_, items := help.GetHelpItemPage(1, 1000, "", "", "", "")
		for _, item := range items {
			if item.Title == "startup-help-fixture" {
				indexedExtension = true
			}
		}
		return nil
	}); err != nil {
		t.Errorf("read final HelpDoc index: %v", err)
	}
	if !indexedExtension {
		t.Error("final HelpDoc index did not include the extension registered after explicit ReloadHelp")
	}
	if finalStatus.Loading {
		t.Errorf("final HelpDoc status = %s, want loading=false", finalStatus.Body)
	}
	if !finalStatus.Result {
		t.Errorf("final HelpDoc status = %s, want result=true", finalStatus.Body)
	}
}

type helpStartupStatusResponse struct {
	Result  bool            `json:"result"`
	Loading bool            `json:"loading"`
	Body    json.RawMessage `json:"-"`
}

func getHelpStartupHTTPStatus(t *testing.T, baseURL string) (helpStartupStatusResponse, error) {
	t.Helper()
	response, err := http.Get(baseURL + "/helpdoc/status")
	if err != nil {
		return helpStartupStatusResponse{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return helpStartupStatusResponse{}, err
	}
	var status helpStartupStatusResponse
	if err := json.Unmarshal(body, &status); err != nil {
		return status, err
	}
	status.Body = append(status.Body[:0], body...)
	return status, nil
}

func beginHelpStartupTreeRequest(t *testing.T, baseURL string, waitReached <-chan struct{}) pendingHelpTreeRequest {
	return beginHelpStartupTreeRequestContext(t, baseURL, waitReached, context.Background())
}

func beginHelpStartupTreeRequestContext(t *testing.T, baseURL string, waitReached <-chan struct{}, ctx context.Context) pendingHelpTreeRequest {
	t.Helper()
	results := make(chan helpStartupHTTPResult, 1)
	go func() {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/helpdoc/tree", nil)
		if err != nil {
			results <- helpStartupHTTPResult{err: err}
			return
		}
		request.Header.Set("Token", helpStartupAPIToken)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			results <- helpStartupHTTPResult{err: err}
			return
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		results <- helpStartupHTTPResult{status: response.StatusCode, body: body, err: err}
	}()

	select {
	case <-waitReached:
		return pendingHelpTreeRequest{results: results}
	case result := <-results:
		return pendingHelpTreeRequest{early: &result}
	case <-time.After(10 * time.Second):
		t.Fatal("HelpDoc tree request neither waited for initial publication nor returned")
		return pendingHelpTreeRequest{results: results}
	}
}

func resolveHelpStartupTreeRequest(t *testing.T, request pendingHelpTreeRequest) helpStartupHTTPResult {
	t.Helper()
	result := awaitHelpStartupTreeRequest(t, request)
	if result.err != nil {
		t.Fatalf("HelpDoc tree HTTP request failed: %v", result.err)
	}
	return result
}

func awaitHelpStartupTreeRequest(t *testing.T, request pendingHelpTreeRequest) helpStartupHTTPResult {
	t.Helper()
	if request.early != nil {
		return *request.early
	}
	select {
	case result := <-request.results:
		return result
	case <-time.After(10 * time.Second):
		t.Fatal("HelpDoc tree request did not finish after startup completed or was cancelled")
		return helpStartupHTTPResult{}
	}
}

func waitHelpStartupEvent(t *testing.T, event <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-event:
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}
