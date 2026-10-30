package dice

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// `.log end` answers at once and uploads in the background. The command's
// message context is released as soon as the command returns, so the upload has
// to report under a context of its own. Reusing the released one made
// VarSetValue panic inside the upload goroutine, which nothing recovers: the
// whole process died, and even without the panic the link was never sent.
func TestLogEndUploadReportsTheLinkAfterTheCommandHasReturned(t *testing.T) {
	d, ep, adapter, cleanup := newExecuteNewTestDice(t)
	defer cleanup()

	mockDB := newLogAliasTestDB(t)
	d.DBOperator = mockDB
	d.BaseConfig.DataDir = t.TempDir()

	const groupID = "UI-Group:9101"
	const logName = "after-return"
	_, _ = newQuitCommandTestContext(t, d, ep, "QQ:9001", groupID, "LogEndGroup")
	group, ok := d.ImSession.ServiceAtNew.Load(groupID)
	if !ok {
		t.Fatal("group fixture missing")
	}
	group.LogCurName, group.LogOn = logName, true
	appendTestLog(t, mockDB, groupID, logName)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"url":"https://example.com/uploaded-story"}`))
	}))
	defer server.Close()
	oldBackends := BackendUrls
	BackendUrls = []string{server.URL}
	t.Cleanup(func() { BackendUrls = oldBackends })

	d.ImSession.ExecuteNew(ep, newGroupMsg(groupID, "QQ:9001", ".log end"))

	if _, ok := adapter.waitForMsg(3 * time.Second); !ok {
		t.Fatal("no reply to .log end")
	}
	uploaded, ok := adapter.waitForMsg(5 * time.Second)
	if !ok {
		t.Fatal("the upload finished without telling the group where the log is")
	}
	if !strings.Contains(uploaded, "https://example.com/uploaded-story") {
		t.Fatalf("upload reply = %q, want it to carry the uploaded log's link", uploaded)
	}
}
