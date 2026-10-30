package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"github.com/labstack/echo/v4"

	"Scardice-core/dice"
)

func TestDiceRecentMessageHTTPReadersDoNotConsumeEachOthersReplies(t *testing.T) {
	t.Setenv(adminAuthBypassEnv, "")
	t.Setenv(adminOriginRateLimitBypassEnv, "")
	if testWebUIAuthBypassEnabled() {
		t.Fatal("test Web UI authentication bypass is enabled")
	}

	previousDice, previousManager := myDice, dm
	t.Cleanup(func() { myDice, dm = previousDice, previousManager })

	const token = "recent-message-contract-token"
	manager := &dice.DiceManager{}
	manager.AccessTokens.Store(token, true)
	runtime := &dice.Dice{Parent: manager}
	session := &dice.IMSession{Parent: runtime}
	adapter := &dice.PlatformAdapterHTTP{}
	endpoint := &dice.EndPointInfo{Adapter: adapter}
	endpoint.Session = session
	adapter.EndPoint = endpoint
	runtime.UIEndpoint = endpoint
	manager.Dice = []*dice.Dice{runtime}
	myDice, dm = runtime, manager

	e := echo.New()
	Bind(e, manager)
	server := httptest.NewServer(e)
	t.Cleanup(server.Close)

	type replyBatch struct {
		Cursor    string                   `json:"cursor"`
		Messages  []dice.HTTPSimpleMessage `json:"messages"`
		Truncated bool                     `json:"truncated"`
	}
	client := server.Client()
	getRecentMessages := func(cursor string) replyBatch {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, server.URL+"/sd-api/dice/recentMessage?cursor="+url.QueryEscape(cursor), nil)
		if err != nil {
			t.Fatalf("create recent-message request: %v", err)
		}
		req.Header.Set("Token", token)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET recentMessage: %v", err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read recentMessage response: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("recentMessage status = %d, body %q; want 200", resp.StatusCode, body)
		}
		var got replyBatch
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("decode recentMessage response %q: %v", body, err)
		}
		if got.Messages == nil || got.Cursor == "" {
			t.Fatalf("recentMessage response = %q, want a cursor and messages array", body)
		}
		return got
	}

	adapter.SendToGroup(nil, "UI-Group:2001", "reply before opening page", "")
	startA, startB := getRecentMessages(""), getRecentMessages("")
	if len(startA.Messages) != 0 || len(startB.Messages) != 0 || startA.Truncated || startB.Truncated {
		t.Fatalf("new pages replayed earlier history: A=%#v B=%#v", startA, startB)
	}

	adapter.SendToPerson(nil, "UI:1001", "private reply", "")
	adapter.SendToGroup(nil, "UI-Group:2002", "delegated group reply", "")
	want := []dice.HTTPSimpleMessage{
		{UID: "UI:1001", Message: "private reply", MessageType: "private"},
		{UID: "UI-Group:2002", Message: "delegated group reply", MessageType: "group"},
	}
	a, b := getRecentMessages(startA.Cursor), getRecentMessages(startB.Cursor)
	if !reflect.DeepEqual(a.Messages, want) || !reflect.DeepEqual(b.Messages, want) || a.Truncated || b.Truncated {
		t.Fatalf("readers did not both receive replies: A=%#v B=%#v want=%#v", a, b, want)
	}
	// A lost HTTP response can be requested again without losing its replies.
	if retry := getRecentMessages(startA.Cursor); !reflect.DeepEqual(retry, a) {
		t.Fatalf("retry = %#v, want identical batch %#v", retry, a)
	}
	if next := getRecentMessages(a.Cursor); len(next.Messages) != 0 || next.Truncated {
		t.Fatalf("acknowledged cursor replayed replies: %#v", next)
	}
	adapter.SendToGroup(nil, "UI-Group:2002", "next reply", "")
	for _, cursor := range []string{a.Cursor, b.Cursor} {
		next := getRecentMessages(cursor)
		if len(next.Messages) != 1 || next.Messages[0].Message != "next reply" || next.Truncated {
			t.Fatalf("reader failed to advance independently: %#v", next)
		}
	}
}
