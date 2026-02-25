package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"Scardice-core/dice"
	"Scardice-core/dice/jsengine"
	"Scardice-core/logger"
)

type mockJsExecQuickJSEngine struct {
	lastCode string
}

func (m *mockJsExecQuickJSEngine) Name() jsengine.EngineName { return jsengine.EngineQuickJS }
func (m *mockJsExecQuickJSEngine) Init(context.Context, jsengine.Config) error {
	return nil
}
func (m *mockJsExecQuickJSEngine) Dispose() error { return nil }
func (m *mockJsExecQuickJSEngine) Eval(code string) error {
	m.lastCode = code
	return nil
}
func (m *mockJsExecQuickJSEngine) Require(string) error                   { return nil }
func (m *mockJsExecQuickJSEngine) RegisterHostAPI(jsengine.HostAPI) error { return nil }
func (m *mockJsExecQuickJSEngine) Reset() error                           { return nil }
func (m *mockJsExecQuickJSEngine) EvalWithResult(code string) (any, error) {
	m.lastCode = code
	return 1, nil
}

func setupJsEngineAPITest(t *testing.T) (string, func()) {
	t.Helper()

	oldMyDice := myDice
	oldDM := dm

	manager := &dice.DiceManager{}
	manager.AccessTokens = dice.SyncMap[string, bool]{}
	token := "test-token"
	manager.AccessTokens.Store(token, true)

	d := &dice.Dice{
		Parent: manager,
		Logger: logger.M(),
		BaseConfig: dice.BaseConfig{
			DataDir: t.TempDir(),
		},
		AttrsManager: &dice.AttrsManager{},
		ImSession:    &dice.IMSession{},
	}

	myDice = d
	dm = manager

	return token, func() {
		myDice = oldMyDice
		dm = oldDM
	}
}

func newJSONContext(e *echo.Echo, method string, path string, token string, body string) (echo.Context, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set("token", token)
	rec := httptest.NewRecorder()
	return e.NewContext(req, rec), rec
}

func TestJsEngineGetDefaultToGoja(t *testing.T) {
	token, cleanup := setupJsEngineAPITest(t)
	defer cleanup()

	e := echo.New()
	ctx, rec := newJSONContext(e, http.MethodGet, "/sd-api/js/engine", token, "")

	err := jsEngineGet(ctx)
	if err != nil {
		t.Fatalf("jsEngineGet 返回错误: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码错误: %d", rec.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应解析失败: %v", err)
	}
	if resp["engine"] != "goja" {
		t.Fatalf("默认引擎应为 goja，实际为: %v", resp["engine"])
	}
	if _, ok := resp["effectiveEngine"]; !ok {
		t.Fatalf("缺少字段 effectiveEngine")
	}
	if _, ok := resp["fallbackReason"]; !ok {
		t.Fatalf("缺少字段 fallbackReason")
	}
}

func TestJsEngineSetInvalidEngine(t *testing.T) {
	token, cleanup := setupJsEngineAPITest(t)
	defer cleanup()

	e := echo.New()
	ctx, rec := newJSONContext(e, http.MethodPost, "/sd-api/js/engine", token, `{"engine":"invalid"}`)

	err := jsEngineSet(ctx)
	if err != nil {
		t.Fatalf("jsEngineSet 返回错误: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("状态码错误: %d", rec.Code)
	}
}

func TestJsEngineSetSuccessNoReloadWhenJsDisabled(t *testing.T) {
	token, cleanup := setupJsEngineAPITest(t)
	defer cleanup()

	e := echo.New()
	ctx, rec := newJSONContext(e, http.MethodPost, "/sd-api/js/engine", token, `{"engine":"quickjs"}`)

	err := jsEngineSet(ctx)
	if err != nil {
		t.Fatalf("jsEngineSet 返回错误: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码错误: %d", rec.Code)
	}

	if myDice.Config.JsEngine != "quickjs" {
		t.Fatalf("引擎未更新，实际值: %s", myDice.Config.JsEngine)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应解析失败: %v", err)
	}
	if resp["reloaded"] != false {
		t.Fatalf("未启用JS时不应触发重载，实际: %v", resp["reloaded"])
	}
}

func TestJsEngineSetNoChange(t *testing.T) {
	token, cleanup := setupJsEngineAPITest(t)
	defer cleanup()
	myDice.Config.JsEngine = "goja"
	myDice.JsEngineEffective = "goja"

	e := echo.New()
	ctx, rec := newJSONContext(e, http.MethodPost, "/sd-api/js/engine", token, `{"engine":"goja"}`)

	err := jsEngineSet(ctx)
	if err != nil {
		t.Fatalf("jsEngineSet 返回错误: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码错误: %d", rec.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应解析失败: %v", err)
	}
	if resp["changed"] != false {
		t.Fatalf("重复设置应返回 changed=false，实际: %v", resp["changed"])
	}
}

func TestJsEngineSetRetryWhenConfigMatchesButEffectiveDiffers(t *testing.T) {
	token, cleanup := setupJsEngineAPITest(t)
	defer cleanup()
	myDice.Config.JsEngine = "quickjs"
	myDice.JsEngineEffective = "goja"

	e := echo.New()
	ctx, rec := newJSONContext(e, http.MethodPost, "/sd-api/js/engine", token, `{"engine":"quickjs"}`)

	err := jsEngineSet(ctx)
	if err != nil {
		t.Fatalf("jsEngineSet 返回错误: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码错误: %d", rec.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应解析失败: %v", err)
	}
	if resp["changed"] != true {
		t.Fatalf("配置与生效不一致时应允许重试并返回 changed=true，实际: %v", resp["changed"])
	}
}

func TestJsEngineSetConflictWhenReloadLocked(t *testing.T) {
	token, cleanup := setupJsEngineAPITest(t)
	defer cleanup()
	myDice.Config.JsEnable = true

	locked := myDice.JsReloadLock.TryLock()
	if !locked {
		t.Fatalf("预置锁失败")
	}
	defer myDice.JsReloadLock.Unlock()

	e := echo.New()
	ctx, rec := newJSONContext(e, http.MethodPost, "/sd-api/js/engine", token, `{"engine":"quickjs"}`)

	err := jsEngineSet(ctx)
	if err != nil {
		t.Fatalf("jsEngineSet 返回错误: %v", err)
	}
	if rec.Code != http.StatusConflict {
		t.Fatalf("状态码错误: %d", rec.Code)
	}
}

func TestJsExecQuickJSDoesNotMutateGlobalCommonJS(t *testing.T) {
	token, cleanup := setupJsEngineAPITest(t)
	defer cleanup()

	myDice.Config.JsEnable = true
	myDice.JsEngineEffective = "quickjs"
	engine := &mockJsExecQuickJSEngine{}
	myDice.ScriptEngine = engine

	e := echo.New()
	ctx, rec := newJSONContext(e, http.MethodPost, "/sd-api/js/execute", token, `{"value":"return 1"}`)

	err := jsExec(ctx)
	if err != nil {
		t.Fatalf("jsExec 返回错误: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码错误: %d", rec.Code)
	}

	if strings.Contains(engine.lastCode, "globalThis.exports") ||
		strings.Contains(engine.lastCode, "globalThis.module") ||
		strings.Contains(engine.lastCode, "globalThis.require") {
		t.Fatalf("QuickJS jsExec 不应修改 globalThis CommonJS 符号，实际脚本: %s", engine.lastCode)
	}
	if !strings.Contains(engine.lastCode, "return eval(__sd_code);") {
		t.Fatalf("QuickJS jsExec 应保留 eval completion value，实际脚本: %s", engine.lastCode)
	}
	if !strings.Contains(engine.lastCode, "new Function(\"exports\", \"require\", \"module\", __sd_code)") {
		t.Fatalf("QuickJS jsExec 应兼容顶层 return 脚本，实际脚本: %s", engine.lastCode)
	}
}
