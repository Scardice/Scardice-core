//nolint:testpackage
package dice

import (
	"os"
	"testing"

	"github.com/lonelyevil/kook"
)

// TestKookClearResumeStateSkipsWhenSessionActive_1114 锁定迟到清理的归属：
// 用户快速禁用→启用后，旧 Serve/DoRelogin 不能删掉新会话刚写入的 resume 快照。
func TestKookClearResumeStateSkipsWhenSessionActive_1114(t *testing.T) {
	pa := &PlatformAdapterKook{}
	ep := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{RelWorkDir: t.TempDir()}}
	pa.EndPoint = ep
	path := pa.resumeStatePath()
	if path == "" {
		t.Fatal("resume state path is empty")
	}
	if err := os.WriteFile(path, []byte(`{"sessionID":"new"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	pa.IntentSession = &kook.Session{}
	pa.clearKookResumeState()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("resume file must survive while a new session is active: %v", err)
	}

	pa.IntentSession = nil
	pa.clearKookResumeState()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("resume file should be removed when no session is active, err=%v", err)
	}
}
