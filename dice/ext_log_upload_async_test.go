package dice

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"Scardice-core/dice/service"
	"Scardice-core/eventstore"
	"Scardice-core/model"
)

// `.log end` answers at once and uploads in the background. The command's
// message context is released as soon as the command returns, so the upload has
// to report under a context of its own. Reusing the released one made
// VarSetValue panic inside the upload goroutine, which nothing recovers: the
// whole process died, and even without the panic the link was never sent.
func TestLogEndUploadReportsTheLinkAfterTheCommandHasReturned(t *testing.T) {
	d, ep, adapter, cleanup := newExecuteNewTestDice(t)
	defer cleanup()

	store, ok := d.DurableStore.(*eventstore.GORMStore)
	if !ok {
		t.Fatal("canonical fixture store is unavailable")
	}
	repository := service.NewEventStoreLogRepository(store, d.BaseConfig.Name)
	d.DBOperator = nil
	d.LogRepository = repository

	const groupID = "UI-Group:9101"
	const logName = "after-return"
	logID, err := repository.GetOrCreate(groupID, logName)
	if err != nil {
		t.Fatal(err)
	}
	if err = repository.AppendByID(groupID, logID, &model.LogOneItem{
		Nickname: "Tester", IMUserID: "QQ:9001", Message: "fixture",
	}); err != nil {
		t.Fatal(err)
	}
	stateRepository, ok := repository.(service.LogStateRepository)
	if !ok {
		t.Fatal("event-store log repository does not expose canonical state")
	}
	if err = stateRepository.SetState(groupID, service.LogState{ID: logID, Name: logName, On: true}); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"url":"https://example.com/uploaded-story"}`))
	}))
	defer server.Close()
	oldBackends := BackendUrls
	BackendUrls = []string{server.URL}
	t.Cleanup(func() { BackendUrls = oldBackends })

	executeNewAndWaitForCanonicalCommit(t, d, ep, newGroupMsg(groupID, "QQ:9001", ".log end"))

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
