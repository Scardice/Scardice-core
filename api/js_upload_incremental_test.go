package api //nolint:testpackage

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/labstack/echo/v4"

	"Scardice-core/dice"
	"Scardice-core/utils/jsengine"
)

type jsUploadTestResponse struct {
	Result      bool     `json:"result"`
	Incremental bool     `json:"incremental"`
	NeedReload  bool     `json:"needReload"`
	Reason      string   `json:"reason"`
	Loaded      []string `json:"loaded"`
	Rejected    []struct {
		Name   string `json:"name"`
		Reason string `json:"reason"`
	} `json:"rejected"`
}

func uploadJSPlugin(t *testing.T, token, filename, source string) jsUploadTestResponse {
	t.Helper()
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	part, err := form.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = part.Write([]byte(source)); err != nil {
		t.Fatal(err)
	}
	if err = form.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/sd-api/js/upload", &body)
	req.Header.Set(echo.HeaderContentType, form.FormDataContentType())
	req.Header.Set("Token", token)
	rec := httptest.NewRecorder()
	if err = jsUpload(echo.New().NewContext(req, rec)); err != nil {
		t.Fatalf("jsUpload error = %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var response jsUploadTestResponse
	if err = json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("response %q: %v", rec.Body.String(), err)
	}
	return response
}

func uploadTestPlugin(name, marker string) string {
	return "// ==UserScript==\n// @name " + name + "\n// @author Tester\n// @version 1.0.0\n// ==/UserScript==\n" +
		"globalThis." + marker + " = (globalThis." + marker + " || 0) + 1;\n" +
		"seal.ext.register(seal.ext.new(\"" + name + "\", \"Tester\", \"1.0.0\"));\n"
}

func jsGlobalForTest(t *testing.T, d *dice.Dice, expression string) any {
	t.Helper()
	loop, _ := d.ExtLoopManager.CurrentLoop()
	var out any
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		value, err := runtime.RunString("probe.js", expression)
		if err != nil {
			return err
		}
		out = value.Export()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestJSUploadLoadsBrandNewPluginWithoutAskingForReload(t *testing.T) {
	testDice, token := newJSExecDice(t)
	if err := os.MkdirAll(filepath.Join(testDice.BaseConfig.DataDir, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}

	fresh := uploadJSPlugin(t, token, "fresh.js", uploadTestPlugin("UploadFresh", "__uploadRuns"))
	if !fresh.Incremental || fresh.NeedReload || len(fresh.Loaded) != 1 || fresh.Loaded[0] != "UploadFresh" {
		t.Fatalf("brand-new upload response = %+v", fresh)
	}
	if _, registered := testDice.JsExtRegistry.Load("UploadFresh"); !registered {
		t.Fatal("the uploaded plugin was not loaded into the running runtime")
	}

	// 覆盖已有文件属于更新：仍然要求手动重载，并且不能重复执行已加载的插件。
	overwritten := uploadJSPlugin(t, token, "fresh.js", uploadTestPlugin("UploadFresh", "__uploadRuns"))
	if overwritten.Incremental || !overwritten.NeedReload || overwritten.Reason == "" {
		t.Fatalf("overwrite response = %+v", overwritten)
	}
	if runs := jsGlobalForTest(t, testDice, `globalThis.__uploadRuns`); runs != int64(1) {
		t.Fatalf("the overwrite re-ran the loaded plugin: %v", runs)
	}
}

func TestJSUploadStillAsksForReloadWhenJSIsOff(t *testing.T) {
	testDice, token := newJSExecDice(t)
	if err := os.MkdirAll(filepath.Join(testDice.BaseConfig.DataDir, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	testDice.Config.JsEnable = false

	response := uploadJSPlugin(t, token, "later.js", uploadTestPlugin("UploadLater", "__laterRuns"))
	if response.Incremental || !response.NeedReload {
		t.Fatalf("response with JS disabled = %+v", response)
	}
	if _, err := os.Stat(filepath.Join(testDice.BaseConfig.DataDir, "scripts", "later.js")); err != nil {
		t.Fatalf("the uploaded file was not saved: %v", err)
	}
}
