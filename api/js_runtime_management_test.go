package api //nolint:testpackage

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"Scardice-core/dice"
	"Scardice-core/utils/jsengine"
)

func TestJSRuntimeManagementRequiresAuthentication(t *testing.T) {
	_, _ = newJSExecDice(t)
	rec := performReplyAPIRequest(t, http.MethodGet, "/sd-api/js/runtime/management", "", "", jsRuntimeManagementGet)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

func TestJSRuntimeManagementReturnsDefaultsAndStatuses(t *testing.T) {
	d, token := newJSExecDice(t)
	rec := performReplyAPIRequest(t, http.MethodGet, "/sd-api/js/runtime/management", "", token, jsRuntimeManagementGet)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var response struct {
		Runtimes        []dice.JSRuntimeStatus `json:"runtimes"`
		DefaultRuntime  string                 `json:"defaultRuntime"`
		ExtensionRoutes map[string]string      `json:"extensionRoutes"`
		DiscoveryError  string                 `json:"discoveryError"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.DefaultRuntime != d.Config.JsEngine {
		t.Fatalf("default runtime = %q, want %q", response.DefaultRuntime, d.Config.JsEngine)
	}
	if len(response.Runtimes) == 0 || response.Runtimes[0].ID != "goja" {
		t.Fatalf("runtime statuses = %+v, want Goja first", response.Runtimes)
	}
}

func TestJSRuntimeConfigSetPersistsGlobalAndExtensionDefaults(t *testing.T) {
	d, token := newJSExecDice(t)
	body := `{"defaultRuntime":"goja","extensionRoutes":{"author/example":"goja"}}`
	rec := performReplyAPIRequest(t, http.MethodPost, "/sd-api/js/runtime/config", body, token, jsRuntimeConfigSet)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if d.Config.JsEngine != "goja" || d.Config.JsRuntimeRoutes["author/example"] != "goja" {
		t.Fatalf("saved runtime config = default %q routes %#v", d.Config.JsEngine, d.Config.JsRuntimeRoutes)
	}
}

func TestJSRuntimeConfigSetRejectsUnknownRuntimeWithoutChangingConfig(t *testing.T) {
	d, token := newJSExecDice(t)
	body := `{"defaultRuntime":"not-installed","extensionRoutes":{"author/example":"goja"}}`
	rec := performReplyAPIRequest(t, http.MethodPost, "/sd-api/js/runtime/config", body, token, jsRuntimeConfigSet)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if d.Config.JsEngine != "goja" || len(d.Config.JsRuntimeRoutes) != 0 {
		t.Fatalf("invalid request changed runtime config: default %q routes %#v", d.Config.JsEngine, d.Config.JsRuntimeRoutes)
	}
}
func makeJSRuntimeArchiveForAPITest(t *testing.T) []byte {
	t.Helper()
	capabilities := jsengine.CapabilityScript | jsengine.CapabilityHostObject |
		jsengine.CapabilityHostFunction | jsengine.CapabilityContextPropagation
	manifest := []byte(fmt.Sprintf(`{
		"schema":1,"id":"quickjs","name":"QuickJS Test","version":"1.0.0","language":"C++","author":"test",
		"runtimeAbi":{"major":1},"hostAbi":{"major":1},
		"libraries":{%q:"libquickjs.so"},"capabilities":%d,"extensions":[".js"]
	}`, runtime.GOOS+"-"+runtime.GOARCH, uint64(capabilities)))
	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, entry := range []struct {
		name string
		data []byte
	}{
		{name: "quickjs/runtime.json", data: manifest},
		{name: "quickjs/libquickjs.so", data: []byte("metadata-only test library")},
	} {
		if err := tarWriter.WriteHeader(&tar.Header{Name: entry.name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(entry.data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestJSRuntimeInstallAndUninstallRemainPendingUntilRestart(t *testing.T) {
	t.Setenv("SCARDICE_QUICKJS_PACKAGE", "")
	d, token := newJSExecDice(t)
	archive := makeJSRuntimeArchiveForAPITest(t)
	rec := performReplyAPIRequest(t, http.MethodPost, "/sd-api/js/runtime/install", string(archive), token, jsRuntimeInstall)
	if rec.Code != http.StatusOK {
		t.Fatalf("install status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var installResponse struct {
		Result        bool                        `json:"result"`
		PendingChange dice.JSRuntimePendingChange `json:"pendingChange"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &installResponse); err != nil {
		t.Fatal(err)
	}
	if !installResponse.Result || installResponse.PendingChange.ID != "quickjs" || installResponse.PendingChange.Action != "install" {
		t.Fatalf("install response = %+v", installResponse)
	}
	activePackage := filepath.Join(d.BaseConfig.DataDir, "js-runtimes", "active", "quickjs")
	if _, err := os.Stat(activePackage); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("package became active before restart: %v", err)
	}

	rec = performReplyAPIRequest(t, http.MethodGet, "/sd-api/js/runtime/management", "", token, jsRuntimeManagementGet)
	if rec.Code != http.StatusOK {
		t.Fatalf("management status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var management struct {
		PendingChanges []dice.JSRuntimePendingChange `json:"pendingChanges"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &management); err != nil {
		t.Fatal(err)
	}
	if len(management.PendingChanges) != 1 || management.PendingChanges[0].Action != "install" {
		t.Fatalf("pending changes after upload = %+v", management.PendingChanges)
	}

	restartedDice := &dice.Dice{Logger: d.Logger, BaseConfig: d.BaseConfig, Config: d.Config, Parent: d.Parent}
	myDice = restartedDice
	restartedManager := dice.NewJSRuntimeManagerForDice(restartedDice)
	statuses := restartedManager.Statuses()
	foundManaged := false
	for _, status := range statuses {
		if status.ID == "quickjs" {
			foundManaged = status.Installed && status.Managed && !status.Loaded
		}
	}
	if !foundManaged {
		t.Fatalf("managed runtime missing after restart: %+v", statuses)
	}

	rec = performReplyAPIRequest(t, http.MethodPost, "/sd-api/js/runtime/uninstall", `{"id":"quickjs"}`, token, jsRuntimeUninstall)
	if rec.Code != http.StatusOK {
		t.Fatalf("uninstall status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(activePackage, "runtime.json")); err != nil {
		t.Fatalf("uninstall removed package before restart: %v", err)
	}
	rec = performReplyAPIRequest(t, http.MethodGet, "/sd-api/js/runtime/management", "", token, jsRuntimeManagementGet)
	if rec.Code != http.StatusOK {
		t.Fatalf("management after uninstall status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &management); err != nil {
		t.Fatal(err)
	}
	if len(management.PendingChanges) != 1 || management.PendingChanges[0].Action != "uninstall" {
		t.Fatalf("pending changes after uninstall = %+v", management.PendingChanges)
	}
}

func TestJSRuntimeInstallRequiresAuthenticationAndValidArchive(t *testing.T) {
	_, token := newJSExecDice(t)
	rec := performReplyAPIRequest(t, http.MethodPost, "/sd-api/js/runtime/install", "invalid", "", jsRuntimeInstall)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unauthenticated install status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	rec = performReplyAPIRequest(t, http.MethodPost, "/sd-api/js/runtime/install", "invalid", token, jsRuntimeInstall)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid archive status = %d, want %d; body = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}
