package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"Scardice-core/dice"
	"Scardice-core/dice/service"
	"Scardice-core/eventstore"
	"Scardice-core/projectionset"
)

func TestDiceExecRequestDistinguishesUnlimitedFromOmittedSplitLength(t *testing.T) {
	for _, test := range []struct {
		name         string
		body         string
		wantProvided bool
		wantLength   int
	}{
		{
			name:         "explicit unlimited",
			body:         `{"message":"test","messageType":"group","messageSplitLen":0}`,
			wantProvided: true,
			wantLength:   0,
		},
		{
			name: "legacy request omits split length",
			body: `{"message":"test","messageType":"private"}`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/sd-api/dice/exec", strings.NewReader(test.body))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			ctx := echo.New().NewContext(req, httptest.NewRecorder())
			var got diceExecRequest
			if err := ctx.Bind(&got); err != nil {
				t.Fatalf("bind DiceExec request: %v", err)
			}
			if got.Message != "test" {
				t.Fatalf("message = %q, want test", got.Message)
			}
			if !test.wantProvided {
				if got.MessageSplitLen != nil {
					t.Fatalf("omitted split length bound as %d, want nil", *got.MessageSplitLen)
				}
				return
			}
			if got.MessageSplitLen == nil || *got.MessageSplitLen != test.wantLength {
				t.Fatalf("messageSplitLen = %v, want %d", got.MessageSplitLen, test.wantLength)
			}
		})
	}
}

func TestResolveDiceExecIdentity(t *testing.T) {
	for _, test := range []struct {
		name    string
		req     diceExecRequest
		want    diceExecIdentity
		wantErr bool
	}{
		{
			name: "legacy private request keeps UI:1001",
			req:  diceExecRequest{MessageType: "private"},
			want: diceExecIdentity{messageType: "private", userID: "UI:1001", nickname: "User"},
		},
		{
			name: "legacy group request keeps owner in UI-Group:2001",
			req:  diceExecRequest{MessageType: "group"},
			want: diceExecIdentity{
				messageType: "group", userID: "UI:1002", nickname: "User",
				groupID: "UI-Group:2001", groupName: "UI-Group 2001", groupRole: "owner",
			},
		},
		{
			name: "sandbox member speaks in a custom group",
			req: diceExecRequest{
				MessageType: "group", UserID: "UI:alice", Nickname: " 爱丽丝 ",
				GroupID: "UI-Group:trpg", GroupRole: "member",
			},
			want: diceExecIdentity{
				messageType: "group", userID: "UI:alice", nickname: "爱丽丝",
				groupID: "UI-Group:trpg", groupName: "Group trpg", groupRole: "member",
			},
		},
		{
			name: "private request ignores group fields",
			req:  diceExecRequest{MessageType: "private", UserID: "UI:bob", GroupID: "UI-Group:x", GroupRole: "admin"},
			want: diceExecIdentity{messageType: "private", userID: "UI:bob", nickname: "User"},
		},
		{name: "foreign platform user is rejected", req: diceExecRequest{UserID: "QQ:10001"}, wantErr: true},
		{name: "separator injection is rejected", req: diceExecRequest{UserID: "UI:1:2"}, wantErr: true},
		{name: "foreign group is rejected", req: diceExecRequest{MessageType: "group", GroupID: "QQ-Group:1"}, wantErr: true},
		{name: "unknown role is rejected", req: diceExecRequest{MessageType: "group", GroupRole: "god"}, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := resolveDiceExecIdentity(test.req)
			if test.wantErr {
				if err == nil {
					t.Fatalf("identity = %#v, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolve identity: %v", err)
			}
			if got != test.want {
				t.Fatalf("identity = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestDiceExecArchivesDistinctSyntheticIncomingMessages(t *testing.T) {
	const (
		groupID = "UI-Group:2001"
		logName = "api-ui-exec-test"
		marker  = "same UI marker"
	)

	ctx := context.Background()
	root := t.TempDir()
	const databaseIdentity = "api-ui-exec-test"
	database, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{
		Type: "sqlite", DSN: filepath.Join(root, "events.db"),
		KeySource: endpointAPITestKeySource{}, DatabaseIdentity: databaseIdentity,
	})
	if err != nil {
		t.Fatalf("open EventStore database: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	store := eventstore.NewStore(database,
		append(projectionset.StoreOptions(), eventstore.WithKeySource(endpointAPITestKeySource{}))...,
	)
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: databaseIdentity,
		IndexRootID: "api-test-index-v1", EncryptionRootIDs: []string{"api-test-root-v1"},
		SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32),
		CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatalf("set EventStore readiness: %v", err)
	}

	d := &dice.Dice{
		BaseConfig:   dice.BaseConfig{Name: databaseIdentity, DataDir: filepath.Join(root, "dice")},
		DurableStore: store,
	}
	d.LogRepository = service.NewEventStoreLogRepository(store, d.BaseConfig.Name)
	manager := &dice.DiceManager{Dice: []*dice.Dice{d}}
	d.Parent = manager
	previousDice, previousManager := myDice, dm
	t.Cleanup(func() {
		myDice = previousDice
		dm = previousManager
		uiExecLastAt.Lock()
		uiExecLastAt.byConversation = map[string]int64{}
		uiExecLastAt.Unlock()
	})
	myDice = d

	if err := manager.InitializeRuntime(); err != nil {
		t.Fatalf("initialize EventStore runtime: %v", err)
	}
	manager.AccessTokens.Store(uiAPIContractToken, true)
	t.Cleanup(func() {
		manager.WaitNamesLoaded()
		d.WaitStartupJsLoaded()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := manager.WaitForHelpDocStartup(ctx); err != nil {
			t.Errorf("wait for help-doc startup: %v", err)
		}
		if err := manager.WithHelpDocManagerWriteContext(ctx, func(help *dice.HelpManager) error {
			if help != nil {
				help.Close()
			}
			return nil
		}); err != nil {
			t.Errorf("close help-doc manager: %v", err)
		}
		if d.AttrsManager != nil {
			d.AttrsManager.Stop()
		}
		if d.Cron != nil {
			d.Cron.Stop()
		}
		if manager.Cron != nil {
			manager.Cron.Stop()
		}
	})
	if err := manager.PrepareEventSourcedState(ctx); err != nil {
		t.Fatalf("prepare EventStore runtime: %v", err)
	}
	d.Config.JsEnable = false
	manager.InitDice(nil)
	manager.JustForTest = true
	if len(manager.Dice) == 0 || manager.Dice[0] != d {
		t.Fatalf("runtime instances = %#v, want the EventStore Dice", manager.Dice)
	}

	session, err := store.CreateStoryLog(ctx, d.BaseConfig.Name, groupID, logName)
	if err != nil {
		t.Fatalf("create EventStore log session: %v", err)
	}
	if err := store.SetStoryLogState(ctx, eventstore.StoryLogState{
		DiceID: d.BaseConfig.Name, GroupID: groupID, SessionID: session.ID, Name: logName, On: true,
	}); err != nil {
		t.Fatalf("activate EventStore log session: %v", err)
	}

	group := &dice.GroupInfo{
		Active: true, GroupID: groupID, GroupName: "UI-Group 2001",
		DiceIDActiveMap: new(dice.SyncMap[string, bool]),
	}
	group.DiceIDActiveMap.Store("UI:1000", true)
	group.SetLogState(session.ID, logName, true)
	group.ExtActive(d.ExtFind("log", false))
	d.ImSession.ServiceAtNew.Store(groupID, group)
	if d.CmdMap["r"] == nil || !dice.CommandCheckPrefix(".r 1d1", d.CommandPrefix, "UI") {
		t.Fatalf("runtime is not ready for a UI roll command: prefix=%#v rollCommand=%t", d.CommandPrefix, d.CmdMap["r"] != nil)
	}
	uiExecLastAt.Lock()
	uiExecLastAt.byConversation = map[string]int64{}
	uiExecLastAt.Unlock()
	e := echo.New()
	Bind(e, manager)
	replyCursor := d.UIEndpoint.Adapter.(*dice.PlatformAdapterHTTP).RecentMessagesSince("").Cursor
	var lastPost time.Time
	postExec := func(message string) {
		t.Helper()
		if wait := time.Until(lastPost.Add(81 * time.Millisecond)); !lastPost.IsZero() && wait > 0 {
			time.Sleep(wait)
		}
		body, err := json.Marshal(struct {
			Message     string `json:"message"`
			MessageType string `json:"messageType"`
		}{Message: message, MessageType: "group"})
		if err != nil {
			t.Fatalf("marshal execution request: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/sd-api/dice/exec", strings.NewReader(string(body)))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set("Token", uiAPIContractToken)
		recorder := httptest.NewRecorder()
		e.ServeHTTP(recorder, req)
		lastPost = time.Now()
		if recorder.Code != http.StatusOK || recorder.Body.String() != "\"ok\"\n" {
			t.Fatalf("DiceExec response = %d %q, want 200 \"ok\"", recorder.Code, recorder.Body.String())
		}
	}
	postExec(marker)
	postExec(marker)
	postExec(".r 1d1")

	itemsURL := "/sd-api/story/items?" + url.Values{
		"groupId": []string{groupID},
		"name":    []string{logName},
	}.Encode()
	deadline := time.Now().Add(5 * time.Second)
	var items []struct {
		Message  string `json:"message"`
		IsDice   bool   `json:"isDice"`
		RawMsgID string `json:"rawMsgId"`
	}
	for {
		req := httptest.NewRequest(http.MethodGet, itemsURL, nil)
		req.Header.Set("Token", uiAPIContractToken)
		recorder := httptest.NewRecorder()
		e.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusOK {
			t.Fatalf("story items response = %d %q, want 200", recorder.Code, recorder.Body.String())
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &items); err != nil {
			t.Fatalf("decode story items: %v", err)
		}
		if len(items) >= 4 {
			break
		}
		if !time.Now().Before(deadline) {
			recentReq := httptest.NewRequest(http.MethodGet, "/sd-api/dice/recentMessage", nil)
			recentReq.Header.Set("Token", uiAPIContractToken)
			recentRecorder := httptest.NewRecorder()
			e.ServeHTTP(recentRecorder, recentReq)
			t.Fatalf("story items = %#v, want two incoming markers and a roll command/reply; recent messages=%s", items, recentRecorder.Body.String())
		}
		time.Sleep(10 * time.Millisecond)
	}

	markerIDs := make(map[string]struct{}, 2)
	markerCount := 0
	rollCommandArchived := false
	rollReplyArchived := false
	for _, item := range items {
		if item.Message == marker && !item.IsDice {
			markerCount++
			markerIDs[item.RawMsgID] = struct{}{}
		}
		if item.Message == ".r 1d1" && !item.IsDice && item.RawMsgID != "" {
			rollCommandArchived = true
		}
		if item.IsDice && item.Message != "" {
			rollReplyArchived = true
		}
	}
	if markerCount != 2 || len(markerIDs) != 2 {
		t.Fatalf("archived identical markers = %d entries with %d IDs, want two non-dice entries with distinct IDs", markerCount, len(markerIDs))
	}
	if _, ok := markerIDs[""]; ok {
		t.Fatal("an archived marker has an empty raw message ID")
	}
	if !rollCommandArchived || !rollReplyArchived {
		t.Fatalf("roll archive: incoming command=%t outgoing bot reply=%t, want both", rollCommandArchived, rollReplyArchived)
	}

	recentDeadline := time.Now().Add(5 * time.Second)
	var batch dice.HTTPMessageBatch
	for {
		req := httptest.NewRequest(http.MethodGet, "/sd-api/dice/recentMessage?cursor="+url.QueryEscape(replyCursor), nil)
		req.Header.Set("Token", uiAPIContractToken)
		recorder := httptest.NewRecorder()
		e.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusOK {
			t.Fatalf("recent message response = %d %q, want 200", recorder.Code, recorder.Body.String())
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &batch); err != nil {
			t.Fatalf("decode recent messages: %v", err)
		}
		if len(batch.Messages) > 0 {
			break
		}
		if !time.Now().Before(recentDeadline) {
			t.Fatal("UI endpoint did not expose the .r 1d1 bot response")
		}
		time.Sleep(10 * time.Millisecond)
	}
	foundGroupReply := false
	for _, reply := range batch.Messages {
		if reply.UID == groupID && reply.MessageType == "group" && strings.TrimSpace(reply.Message) != "" {
			foundGroupReply = true
			break
		}
	}
	if !foundGroupReply {
		t.Fatalf("recent UI messages = %#v, want non-empty group reply to .r 1d1", batch.Messages)
	}
}
