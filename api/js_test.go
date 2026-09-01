package api //nolint:testpackage

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

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
		ImSession: &dice.IMSession{
			ServiceAtNew: new(dice.SyncMap[string, *dice.GroupInfo]),
			EndPoints:    []*dice.EndPointInfo{},
		},
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

func TestExportJSAPIValueRejectsObjects(t *testing.T) {
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
