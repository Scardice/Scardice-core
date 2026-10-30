package api //nolint:testpackage

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.uber.org/zap"

	"Scardice-core/dice"
	"Scardice-core/utils/jsengine"
	gojaengine "Scardice-core/utils/jsengine/goja"
)

func newJSExecDice(t *testing.T) (*dice.Dice, string) {
	t.Helper()

	oldMyDice, oldDM := myDice, dm
	testDice := &dice.Dice{
		Logger: zap.NewNop().Sugar(),
		BaseConfig: dice.BaseConfig{
			DataDir: t.TempDir(),
		},
		ImSession:    &dice.IMSession{ServiceAtNew: new(dice.SyncMap[string, *dice.GroupInfo])},
		DirtyGroups:  new(dice.SyncMap[string, int64]),
		AttrsManager: &dice.AttrsManager{},
		ExtRegistry:  new(dice.SyncMap[string, *dice.ExtInfo]),
	}
	testDice.Config.JsEngine = string(jsengine.EngineGoja)
	manager := &dice.DiceManager{Dice: []*dice.Dice{testDice}}
	const token = "js-api-token"
	manager.AccessTokens.Store(token, true)
	testDice.Parent = manager
	myDice, dm = testDice, manager
	t.Cleanup(func() {
		if testDice.ExtLoopManager != nil {
			testDice.ExtLoopManager.SetLoop(nil)
		}
		myDice, dm = oldMyDice, oldDM
	})
	testDice.JsInit()
	return testDice, token
}

func TestJSExecUsesConfiguredEngineLoop(t *testing.T) {
	_, token := newJSExecDice(t)
	rec := performReplyAPIRequest(t, http.MethodPost, "/sd-api/js/execute", `{"value":"console.log('configured api'); return 42;"}`, token, jsExec)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var response struct {
		Result  bool     `json:"result"`
		Ret     float64  `json:"ret"`
		Outputs []string `json:"outputs"`
		Err     *string  `json:"err"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.Result || response.Ret != 42 || response.Err != nil {
		t.Fatalf("response = %#v", response)
	}
	if len(response.Outputs) != 1 || response.Outputs[0] != "configured api" {
		t.Fatalf("outputs = %#v", response.Outputs)
	}
}

func TestJSExecReturnsNullForScriptWithoutReturnValue(t *testing.T) {
	_, token := newJSExecDice(t)
	rec := performReplyAPIRequest(t, http.MethodPost, "/sd-api/js/execute", `{"value":"console.log('no return');"}`, token, jsExec)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var response struct {
		Result  bool     `json:"result"`
		Ret     any      `json:"ret"`
		Outputs []string `json:"outputs"`
		Err     *string  `json:"err"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.Result || response.Ret != nil || response.Err != nil {
		t.Fatalf("response = %#v", response)
	}
	if len(response.Outputs) != 1 || response.Outputs[0] != "no return" {
		t.Fatalf("outputs = %#v", response.Outputs)
	}
}

func TestJSExecProvidesCommonJSRequire(t *testing.T) {
	_, token := newJSExecDice(t)

	rec := performReplyAPIRequest(t, http.MethodPost, "/sd-api/js/execute", `{"value":"const fs = require('fs'); return typeof fs.promises.readFile;"}`, token, jsExec)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var response struct {
		Result bool    `json:"result"`
		Ret    string  `json:"ret"`
		Err    *string `json:"err"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.Result || response.Ret != "function" || response.Err != nil {
		t.Fatalf("response = %#v", response)
	}
}

func TestJSExecRejectsConfiguredEngineMismatch(t *testing.T) {
	testDice, token := newJSExecDice(t)
	testDice.Config.JsEngine = "quickjs"
	rec := performReplyAPIRequest(t, http.MethodPost, "/sd-api/js/execute", `{"value":"return 42;"}`, token, jsExec)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var response struct {
		Err *string `json:"err"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Err == nil {
		t.Fatalf("response = %s", rec.Body.String())
	}
}

func TestExportJSAPIValueRejectsInvalidValues(t *testing.T) {
	if _, err := exportJSAPIValue(nil); !errors.Is(err, jsengine.ErrPrimitiveExportUnsupported) {
		t.Fatalf("nil value error = %v, want unsupported primitive export", err)
	}

	loop := gojaengine.New()
	defer loop.Close()

	err := loop.Run(func(runtime jsengine.Runtime) error {
		value, err := runtime.RunString("api.js", "({ answer: 42 })")
		if err != nil {
			return err
		}
		_, err = exportJSAPIValue(value)
		if !errors.Is(err, jsengine.ErrPrimitiveExportUnsupported) {
			t.Fatalf("error = %v, want unsupported primitive export", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
func TestJSRuntimeStatusExposesProviderDiagnostics(t *testing.T) {
	_, token := newJSExecDice(t)

	rec := performReplyAPIRequest(t, http.MethodGet, "/sd-api/js/runtime/status", "", token, jsRuntimeStatus)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var response struct {
		Runtimes []dice.JSRuntimeStatus `json:"runtimes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Runtimes) == 0 {
		t.Fatalf("response = %#v, want builtin provider diagnostics", response)
	}
	gojaStatus := response.Runtimes[0]
	if gojaStatus.ID != "goja" || !gojaStatus.Builtin || !gojaStatus.Installed || !gojaStatus.Loaded {
		t.Fatalf("Goja status = %+v", gojaStatus)
	}
}

func TestJSRuntimeStatusExposesDiscoveryError(t *testing.T) {
	root := t.TempDir()
	packageDir := filepath.Join(root, "broken")
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packageDir, "runtime.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SCARDICE_RUNTIME_ROOT", root)
	_, token := newJSExecDice(t)

	rec := performReplyAPIRequest(t, http.MethodGet, "/sd-api/js/runtime/status", "", token, jsRuntimeStatus)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var response struct {
		DiscoveryError string `json:"discoveryError"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.DiscoveryError == "" {
		t.Fatalf("response = %s, want discovery error", rec.Body.String())
	}
}
func TestJSDisablePersistsAcrossHydrationAndReload(t *testing.T) {
	workDir := t.TempDir()
	t.Chdir(workDir)
	server, _, runtime, store := newDiceConfigDurableHandlerTest(t)
	dataDir, err := filepath.Rel(workDir, runtime.BaseConfig.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	runtime.BaseConfig.DataDir = dataDir
	runtime.Config.DataDir = dataDir
	closeRuntime := func(instance *dice.Dice) {
		if instance.JsScriptCron != nil {
			instance.JsScriptCron.Stop()
		}
		if instance.ExtLoopManager != nil {
			instance.ExtLoopManager.SetLoop(nil)
		}
	}
	t.Cleanup(func() { closeRuntime(runtime) })
	server.Use(middleware.Recover())
	runtime.Logger = zap.NewNop().Sugar()
	runtime.Config.JsEngine = "goja"
	runtime.Config.JsEnable = true
	runtime.ConfigManager = dice.NewConfigManager(filepath.Join(runtime.BaseConfig.DataDir, "plugin-configs.json"))
	runtime.ConfigManager.SetOwner(runtime)
	runtime.ExtRegistry = new(dice.SyncMap[string, *dice.ExtInfo])

	const pluginName = "UIE2E Local Goja Plugin"
	scriptDir := filepath.Join(runtime.BaseConfig.DataDir, "scripts")
	if err := os.MkdirAll(scriptDir, 0o700); err != nil {
		t.Fatal(err)
	}
	scriptPath := filepath.Join(scriptDir, "uie2e-local-goja-plugin.js")
	source := `// ==UserScript==
// @name UIE2E Local Goja Plugin
// @author local fixture
// @version 1.0.0
// ==/UserScript==
const ext = seal.ext.new("UIE2E Local Goja Plugin", "test", "1.0.0");
ext.onMessagePreprocess = function(_ctx, _msg) {
  console.log("js-disable-hook-marker");
  return null;
};
seal.ext.register(ext);
`
	if err := os.WriteFile(scriptPath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	runtime.JsReload()
	if !jsDisableHookRuns(runtime, pluginName) {
		ext, ok := runtime.JsExtRegistry.Load(pluginName)
		var script *dice.JsScriptInfo
		if len(runtime.JsScriptList) > 0 {
			script = runtime.JsScriptList[0]
		}
		t.Fatalf("Goja plugin hook did not execute before disable; script=%+v, extensionFound=%v, extension=%#v", script, ok, ext)
	}

	tcpServer := httptest.NewServer(server)
	defer tcpServer.Close()
	request := func(server *httptest.Server, method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		req, err := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Token", "dice-config-owner-token")
		if body != "" {
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		}
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		responseBody, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		recorder := httptest.NewRecorder()
		recorder.Code = response.StatusCode
		_, _ = recorder.Body.Write(responseBody)
		return recorder
	}
	disabled := request(tcpServer, http.MethodPost, "/sd-api/js/disable", `{"name":"UIE2E Local Goja Plugin"}`)
	if disabled.Code != http.StatusOK {
		t.Fatalf("disable status = %d, body = %s", disabled.Code, disabled.Body.String())
	}
	listed := request(tcpServer, http.MethodGet, "/sd-api/js/list", "")
	if listed.Code != http.StatusOK {
		t.Fatalf("list after disable status = %d, body = %s", listed.Code, listed.Body.String())
	}
	var scripts []struct {
		Name   string `json:"name"`
		Enable bool   `json:"enable"`
	}
	if err := json.Unmarshal(listed.Body.Bytes(), &scripts); err != nil {
		t.Fatal(err)
	}
	if len(scripts) != 1 || scripts[0].Name != pluginName || scripts[0].Enable {
		t.Fatalf("scripts after disable = %#v", scripts)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("close durable event store before restart: %v", err)
	}
	store = reopenDiceConfigDurableTestStore(t, runtime)

	restarted := &dice.Dice{
		BaseConfig:   runtime.BaseConfig,
		DurableStore: store,
		Logger:       zap.NewNop().Sugar(),
	}
	restartedManager := &dice.DiceManager{
		EventSourcedMode: true,
		Dice:             []*dice.Dice{restarted},
	}
	restarted.Parent = restartedManager
	if err := restartedManager.RestoreEventSourcedManager(context.Background(), store); err != nil {
		t.Fatalf("restore restarted manager: %v", err)
	}
	if err := restartedManager.PrepareEventSourcedState(context.Background()); err != nil {
		t.Fatalf("hydrate restarted runtime: %v", err)
	}
	restartedManager.AccessTokens.Store("dice-config-owner-token", true)
	restarted.ConfigManager = dice.NewConfigManager(filepath.Join(restarted.BaseConfig.DataDir, "plugin-configs.json"))
	restarted.ConfigManager.SetOwner(restarted)
	restarted.ExtRegistry = new(dice.SyncMap[string, *dice.ExtInfo])

	t.Cleanup(func() { closeRuntime(restarted) })
	restarted.JsReload()
	if jsDisableHookRuns(restarted, pluginName) {
		t.Fatal("disabled Goja plugin hook executed after hydration and reload")
	}

	restartedServer := echo.New()
	restartedServer.Use(middleware.Recover())
	Bind(restartedServer, restartedManager)
	restartedTCPServer := httptest.NewServer(restartedServer)
	defer restartedTCPServer.Close()
	reloadedList := request(restartedTCPServer, http.MethodGet, "/sd-api/js/list", "")
	if reloadedList.Code != http.StatusOK {
		t.Fatalf("list after database reopen and reload status = %d, body = %s", reloadedList.Code, reloadedList.Body.String())
	}
	scripts = nil
	if err := json.Unmarshal(reloadedList.Body.Bytes(), &scripts); err != nil {
		t.Fatal(err)
	}
	if len(scripts) != 1 || scripts[0].Name != pluginName || scripts[0].Enable {
		t.Fatalf("scripts after database reopen and reload = %#v", scripts)
	}
	enabled := request(restartedTCPServer, http.MethodPost, "/sd-api/js/enable", `{"name":"UIE2E Local Goja Plugin"}`)
	if enabled.Code != http.StatusOK {
		t.Fatalf("enable status = %d, body = %s", enabled.Code, enabled.Body.String())
	}
	restarted.JsReload()
	if !jsDisableHookRuns(restarted, pluginName) {
		t.Fatal("Goja plugin hook did not execute after re-enable and reload")
	}
}

func jsDisableHookRuns(runtime *dice.Dice, pluginName string) bool {
	ext, ok := runtime.JsExtRegistry.Load(pluginName)
	if !ok || ext == nil || ext.OnMessagePreprocess == nil {
		return false
	}
	runtime.JsPrinter.RecordStart()
	ext.CallOnMessagePreprocess(runtime, &dice.MsgContext{Dice: runtime}, &dice.Message{})
	return strings.Contains(strings.Join(runtime.JsPrinter.RecordEnd(), "\n"), "js-disable-hook-marker")
}
