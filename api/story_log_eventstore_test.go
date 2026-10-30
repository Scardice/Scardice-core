package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"Scardice-core/dice"
	"Scardice-core/dice/service"
	"Scardice-core/eventstore"
	"Scardice-core/model"
)

const storyEventStoreTestToken = "story-eventstore-test-token"

func newStoryEventStoreFixture(t *testing.T) (*dice.Dice, *eventstore.GORMStore) {
	t.Helper()
	ctx := context.Background()
	database, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{
		Type: "sqlite", DSN: filepath.Join(t.TempDir(), "story-api.db"),
		KeySource: endpointAPITestKeySource{}, DatabaseIdentity: "story-api-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	store := eventstore.NewStore(database, eventstore.WithKeySource(endpointAPITestKeySource{}))
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "story-api-test", IndexRootID: "api-test-index-v1",
		EncryptionRootIDs: []string{"api-test-root-v1"}, SourceManifestDigest: make([]byte, 32),
		TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	manager := &dice.DiceManager{}
	d := &dice.Dice{BaseConfig: dice.BaseConfig{Name: "story-api-dice"}, Parent: manager}
	d.LogRepository = service.NewEventStoreLogRepository(store, d.BaseConfig.Name)
	previousDice := myDice
	myDice = d
	t.Cleanup(func() { myDice = previousDice })
	manager.AccessTokens.Store(storyEventStoreTestToken, true)
	return d, store
}

func seedStoryEventStoreLog(t *testing.T, store *eventstore.GORMStore) (eventstore.StoryLogSession, string, string) {
	t.Helper()
	const groupID, name = "story-api-group", "story-api-session"
	ctx := context.Background()
	session, err := store.CreateStoryLog(ctx, "story-api-dice", groupID, name)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AppendStoryLogEntry(ctx, eventstore.StoryLogEntry{
		DiceID: "story-api-dice", GroupID: groupID, LogName: name, Nickname: "Tester", IMUserID: "user-1",
		Time: 100, Message: "stored story line", RawMsgID: "raw-1", UniformID: "uniform-1",
	}); err != nil {
		t.Fatal(err)
	}
	return session, groupID, name
}

func TestStoryGetInfoReadsEventStoreRepository(t *testing.T) {
	_, store := newStoryEventStoreFixture(t)
	session, _, _ := seedStoryEventStoreLog(t, store)
	recorder := httptest.NewRecorder()
	ctx := echo.New().NewContext(httptest.NewRequest(http.MethodGet, "/sd-api/story/info", nil), recorder)
	if err := storyGetInfo(ctx); err != nil {
		t.Fatalf("storyGetInfo() error = %v", err)
	}
	var got []int
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode Story info: %v", err)
	}
	want := []int{int(session.ID), 1, 1, 1}
	if len(got) != len(want) {
		t.Fatalf("Story info=%v want=%v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Story info=%v want=%v", got, want)
		}
	}
}

func TestStoryGetLogPageReadsEventStoreRepository(t *testing.T) {
	_, store := newStoryEventStoreFixture(t)
	_, groupID, name := seedStoryEventStoreLog(t, store)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/sd-api/story/logs/page?pageNum=1&pageSize=10&groupId="+groupID+"&name="+name, nil)
	request.Header.Set("Token", storyEventStoreTestToken)
	ctx := echo.New().NewContext(request, recorder)
	if err := storyGetLogPage(ctx); err != nil {
		t.Fatalf("storyGetLogPage() error = %v", err)
	}
	var got struct {
		Result   bool             `json:"result"`
		Total    int              `json:"total"`
		PageSize int              `json:"pageSize"`
		Data     []*model.LogInfo `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode Story page: %v", err)
	}
	if !got.Result || got.Total != 1 || got.PageSize != 1 || len(got.Data) != 1 || got.Data[0].Name != name || got.Data[0].GroupID != groupID {
		t.Fatalf("Story page=%+v", got)
	}
}

func TestStoryGetItemsAndItemPageReadEventStoreRepository(t *testing.T) {
	_, store := newStoryEventStoreFixture(t)
	_, groupID, name := seedStoryEventStoreLog(t, store)
	for _, test := range []struct {
		name string
		run  func(echo.Context) error
	}{
		{name: "legacy items", run: storyGetItems},
		{name: "item page", run: storyGetItemPage},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/sd-api/story/items?groupId="+groupID+"&name="+name+"&logName="+name+"&pageNum=1&pageSize=10", nil)
			request.Header.Set("Token", storyEventStoreTestToken)
			ctx := echo.New().NewContext(request, recorder)
			if err := test.run(ctx); err != nil {
				t.Fatalf("handler error = %v", err)
			}
			var rows []*model.LogOneItem
			if err := json.Unmarshal(recorder.Body.Bytes(), &rows); err != nil {
				t.Fatalf("decode Story items: %v", err)
			}
			if len(rows) != 1 || rows[0].Message != "stored story line" || rows[0].RawMsgID != "raw-1" {
				t.Fatalf("Story items=%+v", rows)
			}
		})
	}
}

func TestStoryDeleteRemovesEventStoreRepositorySession(t *testing.T) {
	_, store := newStoryEventStoreFixture(t)
	_, groupID, name := seedStoryEventStoreLog(t, store)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodDelete, "/sd-api/story/log?groupId="+groupID+"&name="+name, nil)
	request.Header.Set("Token", storyEventStoreTestToken)
	ctx := echo.New().NewContext(request, recorder)
	if err := storyDelLog(ctx); err != nil {
		t.Fatalf("storyDelLog() error = %v", err)
	}
	if recorder.Code != http.StatusOK || recorder.Body.String() != "true\n" {
		t.Fatalf("Story delete response status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	entries, err := store.GetStoryLogEntries(context.Background(), "story-api-dice", groupID, name)
	if err != nil || len(entries) != 0 {
		t.Fatalf("deleted Story entries=%+v error=%v, want no entries", entries, err)
	}
}

func TestStoryEventStoreQueriesAndDeleteStayWithinDiceAndGroupScope(t *testing.T) {
	_, store := newStoryEventStoreFixture(t)
	ctx := context.Background()
	const (
		diceID       = "story-api-dice"
		groupID      = "story-api-group"
		otherGroupID = "story-api-other-group"
		otherDiceID  = "story-api-other-dice"
		sessionName  = "shared-session-name"
	)
	seed := func(targetDice, targetGroup, message string, timestamp int64) {
		t.Helper()
		if _, err := store.CreateStoryLog(ctx, targetDice, targetGroup, sessionName); err != nil {
			t.Fatal(err)
		}
		if err := store.AppendStoryLogEntry(ctx, eventstore.StoryLogEntry{
			DiceID: targetDice, GroupID: targetGroup, LogName: sessionName,
			Nickname: "Tester", IMUserID: targetDice + "-user", Time: timestamp, Message: message,
		}); err != nil {
			t.Fatal(err)
		}
	}
	seed(diceID, groupID, "target-later", 20)
	if err := store.AppendStoryLogEntry(ctx, eventstore.StoryLogEntry{
		DiceID: diceID, GroupID: groupID, LogName: sessionName,
		Nickname: "Tester", IMUserID: diceID + "-user", Time: 10, Message: "target-earlier",
	}); err != nil {
		t.Fatal(err)
	}
	seed(diceID, otherGroupID, "other-group-entry", 15)
	seed(otherDiceID, groupID, "other-dice-entry", 12)

	infoRecorder := httptest.NewRecorder()
	infoCtx := echo.New().NewContext(httptest.NewRequest(http.MethodGet, "/sd-api/story/info", nil), infoRecorder)
	if err := storyGetInfo(infoCtx); err != nil {
		t.Fatalf("storyGetInfo() error = %v", err)
	}
	var info []int
	if err := json.Unmarshal(infoRecorder.Body.Bytes(), &info); err != nil {
		t.Fatalf("decode Story info: %v", err)
	}
	if len(info) != 4 || info[2] != 2 || info[3] != 3 {
		t.Fatalf("Story info=%v, want only current dice's 2 sessions and 3 entries", info)
	}

	pageRequest := httptest.NewRequest(http.MethodGet, "/sd-api/story/logs/page?pageNum=1&pageSize=10", nil)
	pageRequest.Header.Set("Token", storyEventStoreTestToken)
	pageRecorder := httptest.NewRecorder()
	pageCtx := echo.New().NewContext(pageRequest, pageRecorder)
	if err := storyGetLogPage(pageCtx); err != nil {
		t.Fatalf("storyGetLogPage() error = %v", err)
	}
	var page struct {
		Result bool             `json:"result"`
		Total  int              `json:"total"`
		Data   []*model.LogInfo `json:"data"`
	}
	if err := json.Unmarshal(pageRecorder.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode Story log page: %v", err)
	}
	if !page.Result || page.Total != 2 || len(page.Data) != 2 {
		t.Fatalf("Story page=%+v, want only current dice's two same-named sessions", page)
	}
	groups := map[string]bool{}
	for _, session := range page.Data {
		if session.Name != sessionName {
			t.Fatalf("unexpected Story session: %+v", session)
		}
		groups[session.GroupID] = true
	}
	if !groups[groupID] || !groups[otherGroupID] {
		t.Fatalf("Story page groups=%v, want both current-dice groups", groups)
	}

	for _, test := range []struct {
		pageNum, wantTimestamp int
		wantMessage            string
	}{
		{pageNum: 1, wantTimestamp: 10, wantMessage: "target-earlier"},
		{pageNum: 2, wantTimestamp: 20, wantMessage: "target-later"},
	} {
		request := httptest.NewRequest(http.MethodGet, "/sd-api/story/items/page?pageNum="+strconv.Itoa(test.pageNum)+"&pageSize=1&groupId="+groupID+"&logName="+sessionName, nil)
		request.Header.Set("Token", storyEventStoreTestToken)
		recorder := httptest.NewRecorder()
		pageCtx := echo.New().NewContext(request, recorder)
		if err := storyGetItemPage(pageCtx); err != nil {
			t.Fatalf("storyGetItemPage(page=%d) error = %v", test.pageNum, err)
		}
		var items []*model.LogOneItem
		if err := json.Unmarshal(recorder.Body.Bytes(), &items); err != nil {
			t.Fatalf("decode Story item page: %v", err)
		}
		if len(items) != 1 || items[0].Time != int64(test.wantTimestamp) || items[0].Message != test.wantMessage {
			t.Fatalf("Story item page=%d rows=%+v", test.pageNum, items)
		}
	}

	deleteRecorder := httptest.NewRecorder()
	deleteRequest := httptest.NewRequest(http.MethodDelete, "/sd-api/story/log?groupId="+groupID+"&name="+sessionName, nil)
	deleteRequest.Header.Set("Token", storyEventStoreTestToken)
	deleteCtx := echo.New().NewContext(deleteRequest, deleteRecorder)
	if err := storyDelLog(deleteCtx); err != nil || deleteRecorder.Code != http.StatusOK {
		t.Fatalf("storyDelLog() status=%d err=%v", deleteRecorder.Code, err)
	}
	currentDiceLogs, err := store.ListStoryLogs(ctx, diceID, otherGroupID)
	if err != nil || len(currentDiceLogs) != 1 {
		t.Fatalf("deleting current-dice target group affected other group: sessions=%+v err=%v", currentDiceLogs, err)
	}
	otherDiceLogs, err := store.ListStoryLogs(ctx, otherDiceID, groupID)
	if err != nil || len(otherDiceLogs) != 1 {
		t.Fatalf("deleting current-dice target affected other dice: sessions=%+v err=%v", otherDiceLogs, err)
	}
}

func TestStoryLogCheckRejectsUnauthenticatedRequests(t *testing.T) {
	newStoryEventStoreFixture(t)
	request := httptest.NewRequest(http.MethodPost, "/sd-api/story/check", nil)
	recorder := httptest.NewRecorder()
	if err := storyCheckLog(echo.New().NewContext(request, recorder)); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("unauthenticated recovery status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
