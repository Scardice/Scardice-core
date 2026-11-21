package dice

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lonelyevil/kook"
)

// TestKookAbortServeBeforeSetSession_1121fix1 锁定：Serve 在创建 session 之后、
// setSession 之前 panic 时，IntentSession 还是 nil，但 serving 必须被清掉，
// 不能永久卡在 “already running”。
func TestKookAbortServeBeforeSetSession_1121fix1(t *testing.T) {
	ep := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{Enable: true, State: StateConnecting}}
	pa := &PlatformAdapterKook{EndPoint: ep}
	pa.serving = true
	pa.serveToken = 7

	pa.abortServeAfterPanic(7, &kook.Session{})

	if pa.serving {
		t.Fatal("serving must be cleared after a panic before setSession")
	}
	if ep.Enable || ep.State != StateConnectionFailed {
		t.Fatalf("endpoint = (enable=%v, state=%d), want disabled/failed", ep.Enable, ep.State)
	}
}

// TestKookAbortServeStaleToken_1121fix1 锁定：旧 Serve 的 panic 清理不能用
// 旧代次覆盖新 Serve 的状态。
func TestKookAbortServeStaleToken_1121fix1(t *testing.T) {
	ep := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{Enable: true, State: StateConnected}}
	pa := &PlatformAdapterKook{EndPoint: ep}
	pa.serving = true
	pa.serveToken = 9

	pa.abortServeAfterPanic(7, &kook.Session{})

	if !pa.serving || !ep.Enable || ep.State != StateConnected {
		t.Fatalf("stale panic cleanup clobbered state: serving=%v enable=%v state=%d",
			pa.serving, ep.Enable, ep.State)
	}
}

// TestKookClearSessionInvalidatesServeToken_1121fix1 锁定：禁用/替换会话时
// 必须推进 serveToken，让尚未走到 setSession 的旧 Serve 在后续检查失败。
func TestKookClearSessionInvalidatesServeToken_1121fix1(t *testing.T) {
	session := &kook.Session{}
	pa := &PlatformAdapterKook{IntentSession: session, serving: true, serveToken: 3}

	if !pa.clearSessionIf(session) {
		t.Fatal("clearSessionIf must clear the current session")
	}
	if pa.IntentSession != nil || pa.serving {
		t.Fatal("session/serving not cleared")
	}
	if pa.serveToken != 4 {
		t.Fatalf("serveToken = %d, want 4", pa.serveToken)
	}
}

// TestKookClearResumeStateGuard_1121fix1 锁定：有新会话时不能删除快照；
// 真正空闲时才删除。清除调用必须和 save 一样受 resumeStateMu 保护。
func TestKookClearResumeStateGuard_1121fix1(t *testing.T) {
	dir := t.TempDir()
	ep := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{RelWorkDir: dir}}
	pa := &PlatformAdapterKook{EndPoint: ep}
	path := filepath.Join(dir, kookResumeStateFileName)
	if err := os.WriteFile(path, []byte(`{"session_id":"old"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	pa.IntentSession = &kook.Session{}
	pa.clearKookResumeState()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("snapshot must be kept while a session exists: %v", err)
	}

	pa.IntentSession = nil
	pa.clearKookResumeState()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("snapshot must be removed when idle, err=%v", err)
	}
}
