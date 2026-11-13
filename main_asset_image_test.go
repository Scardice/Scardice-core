package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/labstack/echo/v4"

	"Scardice-core/dice"
)

// runAssetImageHandler 在临时工作目录中启动 handler 并返回一次请求的响应。
// 返回 (statusCode, body)。
func runAssetImageHandler(t *testing.T, token string, reqPath string) (int, string) {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)

	imgDir := filepath.Join("data", "images")
	_ = os.MkdirAll(imgDir, 0o755)
	_ = os.WriteFile(filepath.Join(imgDir, "foo.png"), []byte("fake-png"), 0o644)

	// symlink PoC: data/images/evil-link -> /etc
	_ = os.Symlink("/etc", filepath.Join(imgDir, "evil-link"))

	dm := &dice.DiceManager{AssetImageToken: token}
	e := echo.New()
	registerAssetImageRoute(e, dm)

	req := httptest.NewRequest(http.MethodGet, reqPath, nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	body, _ := io.ReadAll(rec.Result().Body)
	return rec.Code, string(body)
}

func TestAssetImageHandler_ValidTokenValidFile(t *testing.T) {
	code, _ := runAssetImageHandler(t, "validtoken123", "/assets-img/validtoken123/images/foo.png")
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
}

func TestAssetImageHandler_WrongToken(t *testing.T) {
	// Medium #9: token 错误返回 404，不泄露存在性
	code, _ := runAssetImageHandler(t, "validtoken123", "/assets-img/wrongtoken/images/foo.png")
	if code != http.StatusNotFound {
		t.Fatalf("expected 404 for wrong token, got %d", code)
	}
}

func TestAssetImageHandler_PathTraversal(t *testing.T) {
	code, _ := runAssetImageHandler(t, "validtoken123", "/assets-img/validtoken123/../../../etc/passwd")
	if code != http.StatusNotFound {
		t.Fatalf("expected 404 for traversal, got %d", code)
	}
}

func TestAssetImageHandler_SymlinkTraversalRejected(t *testing.T) {
	// Critical #1 PoC: data/images/evil-link -> /etc, 请求 evil-link/passwd 应被 EvalSymlinks 拦截
	code, _ := runAssetImageHandler(t, "validtoken123", "/assets-img/validtoken123/images/evil-link/passwd")
	if code != http.StatusNotFound {
		t.Fatalf("expected 404 for symlink traversal, got %d", code)
	}
}

func TestAssetImageHandler_FileNotExistInData(t *testing.T) {
	// 文件不在 data/ 内（或不存在）返回 404
	code, _ := runAssetImageHandler(t, "validtoken123", "/assets-img/validtoken123/nonexistent.log")
	if code != http.StatusNotFound {
		t.Fatalf("expected 404 for nonexistent file, got %d", code)
	}
}

// TestAssetImageConstant_MaxSize 锁定 main 包常量 onebotAssetMaxSize 与 dice 包一致。
func TestAssetImageConstant_MaxSize(t *testing.T) {
	if onebotAssetMaxSize != dice.OnebotAssetMaxSize {
		t.Errorf("onebotAssetMaxSize=%d != dice.OnebotAssetMaxSize=%d",
			onebotAssetMaxSize, dice.OnebotAssetMaxSize)
	}
}
