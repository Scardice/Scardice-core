package api

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"Scardice-core/dice"
)

func TestBanConfigSetPersistsNotificationInterval(t *testing.T) {
	// Given
	previousDice := myDice
	t.Cleanup(func() { myDice = previousDice })
	manager := &dice.DiceManager{}
	manager.AccessTokens.Store("task5-token", true)
	myDice = &dice.Dice{
		Parent: manager,
		Config: dice.Config{BanConfig: dice.BanConfig{BanList: &dice.BanListInfo{}}},
	}
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/ban/config", strings.NewReader(`{"banNotifyIntervalMinutes":-1}`))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set("Token", "task5-token")
	rec := httptest.NewRecorder()

	// When
	err := banConfigSet(e.NewContext(req, rec))

	// Then
	if err != nil {
		t.Fatalf("set ban config: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("ban config status = %d, want %d", rec.Code, http.StatusOK)
	}
	if myDice.Config.BanList.BanNotifyIntervalMinutes != -1 {
		t.Fatalf("ban notification interval = %d, want -1", myDice.Config.BanList.BanNotifyIntervalMinutes)
	}
}
func TestBanMapListReadsRuntimeItemsWithoutDatabaseOperator(t *testing.T) {
	previousDice := myDice
	t.Cleanup(func() { myDice = previousDice })

	manager := &dice.DiceManager{}
	manager.AccessTokens.Store("ban-list-token", true)
	banList := &dice.BanListInfo{}
	banList.Init()
	banList.Map.Store("QQ:12345", &dice.BanListInfoItem{
		ID: "QQ:12345", Name: "member", Rank: dice.BanRankBanned, Score: 200, BanUpdatedAt: 20,
		Reasons: []string{"manual ban"},
	})
	banList.Map.Store("QQ:00001", &dice.BanListInfoItem{
		ID: "QQ:00001", Name: "trusted", Rank: dice.BanRankTrusted, BanUpdatedAt: 10,
	})
	myDice = &dice.Dice{
		Parent: manager,
		Config: dice.Config{BanConfig: dice.BanConfig{BanList: banList}},
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/sd-api/banconfig/list", nil)
	req.Header.Set("Token", "ban-list-token")
	rec := httptest.NewRecorder()

	if err := banMapList(e.NewContext(req, rec)); err != nil {
		t.Fatalf("list ban records: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("ban list status = %d, want %d; body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var got []dice.BanListInfoItem
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode ban list response: %v", err)
	}
	if len(got) != 2 || got[0].ID != "QQ:12345" || got[0].Rank != dice.BanRankBanned || got[1].ID != "QQ:00001" || got[1].Rank != dice.BanRankTrusted {
		t.Fatalf("ban list = %#v, want newest update first", got)
	}
}

func TestBanMapListReturnsEmptyArrayWithoutDatabaseOperator(t *testing.T) {
	previousDice := myDice
	t.Cleanup(func() { myDice = previousDice })

	manager := &dice.DiceManager{}
	manager.AccessTokens.Store("ban-list-token", true)
	banList := &dice.BanListInfo{}
	banList.Init()
	myDice = &dice.Dice{Parent: manager, Config: dice.Config{BanConfig: dice.BanConfig{BanList: banList}}}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/sd-api/banconfig/list", nil)
	req.Header.Set("Token", "ban-list-token")
	rec := httptest.NewRecorder()
	if err := banMapList(e.NewContext(req, rec)); err != nil {
		t.Fatalf("list empty ban records: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("empty list status = %d, want %d; body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var got []dice.BanListInfoItem
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode empty ban list response: %v", err)
	}
	if got == nil || len(got) != 0 {
		t.Fatalf("empty ban list = %#v, want an empty array", got)
	}
}

func TestBanMapAddAndDeleteWorkWithoutDatabaseOperator(t *testing.T) {
	previousDice, previousManager := myDice, dm
	t.Cleanup(func() {
		myDice, dm = previousDice, previousManager
	})

	manager := &dice.DiceManager{}
	manager.AccessTokens.Store("ban-list-token", true)
	dm = manager
	runtime := &dice.Dice{Parent: manager}
	banList := &dice.BanListInfo{Parent: runtime}
	banList.Init()
	runtime.Config.BanList = banList
	myDice = runtime

	e := echo.New()
	addRequest := httptest.NewRequest(http.MethodPost, "/sd-api/banconfig/map_add_one", strings.NewReader(
		`{"ID":"QQ:54321","Rank":-30,"Name":"member","Reasons":["manual ban"]}`,
	))
	addRequest.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	addRequest.Header.Set("Token", "ban-list-token")
	addResponse := httptest.NewRecorder()
	if err := banMapAddOne(e.NewContext(addRequest, addResponse)); err != nil {
		t.Fatalf("add ban item: %v", err)
	}
	if addResponse.Code != http.StatusOK {
		t.Fatalf("add status = %d, want %d; body = %s", addResponse.Code, http.StatusOK, addResponse.Body.String())
	}
	item, exists := banList.GetByID("QQ:54321")
	if !exists || item.Rank != dice.BanRankBanned || item.Name != "member" {
		t.Fatalf("added item = %#v, exists = %v", item, exists)
	}

	deleteRequest := httptest.NewRequest(http.MethodPost, "/sd-api/banconfig/map_delete_one", strings.NewReader(`{"ID":"QQ:54321"}`))
	deleteRequest.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	deleteRequest.Header.Set("Token", "ban-list-token")
	deleteResponse := httptest.NewRecorder()
	if err := banMapDeleteOne(e.NewContext(deleteRequest, deleteResponse)); err != nil {
		t.Fatalf("delete ban item: %v", err)
	}
	if deleteResponse.Code != http.StatusOK {
		t.Fatalf("delete status = %d, want %d; body = %s", deleteResponse.Code, http.StatusOK, deleteResponse.Body.String())
	}
	if item, exists = banList.GetByID("QQ:54321"); exists {
		t.Fatalf("deleted item remains in runtime map: %#v", item)
	}
}

func TestBanMapAddSupportsEveryBanRank(t *testing.T) {
	previousDice, previousManager := myDice, dm
	t.Cleanup(func() {
		myDice, dm = previousDice, previousManager
	})

	manager := &dice.DiceManager{}
	manager.AccessTokens.Store("ban-list-token", true)
	dm = manager
	runtime := &dice.Dice{Parent: manager}
	banList := &dice.BanListInfo{Parent: runtime}
	banList.Init()
	runtime.Config.BanList = banList
	myDice = runtime

	tests := []struct {
		id        string
		rank      dice.BanRankType
		wantScore int64
	}{
		{id: "QQ:banned", rank: dice.BanRankBanned, wantScore: banList.ThresholdBan},
		{id: "QQ:warn", rank: dice.BanRankWarn, wantScore: banList.ThresholdWarn},
		{id: "QQ:trusted", rank: dice.BanRankTrusted},
		{id: "QQ:normal", rank: dice.BanRankNormal},
		{id: "QQ:transition", rank: dice.BanRankBanned, wantScore: banList.ThresholdBan},
		{id: "QQ:transition", rank: dice.BanRankNormal},
	}
	e := echo.New()
	for _, tt := range tests {
		body, err := json.Marshal(&dice.BanListInfoItem{ID: tt.id, Name: "member", Rank: tt.rank, Reasons: []string{"manual change"}})
		if err != nil {
			t.Fatalf("encode %s request: %v", tt.id, err)
		}
		request := httptest.NewRequest(http.MethodPost, "/sd-api/banconfig/map_add_one", bytes.NewReader(body))
		request.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		request.Header.Set("Token", "ban-list-token")
		response := httptest.NewRecorder()
		if err = banMapAddOne(e.NewContext(request, response)); err != nil {
			t.Fatalf("add %s: %v", tt.id, err)
		}
		if response.Code != http.StatusOK {
			t.Fatalf("add %s status = %d, want %d; body = %s", tt.id, response.Code, http.StatusOK, response.Body.String())
		}
		item, ok := banList.GetByID(tt.id)
		if !ok || item.Rank != tt.rank || item.Score != tt.wantScore || item.Name != "member" {
			t.Fatalf("%s item = %#v, exists = %v", tt.id, item, ok)
		}
	}
}

func TestBanImportAndExportWorkWithoutDatabaseOperator(t *testing.T) {
	previousDice, previousManager := myDice, dm
	t.Cleanup(func() {
		myDice, dm = previousDice, previousManager
	})

	manager := &dice.DiceManager{}
	manager.AccessTokens.Store("ban-list-token", true)
	dm = manager
	runtime := &dice.Dice{Parent: manager}
	banList := &dice.BanListInfo{Parent: runtime}
	banList.Init()
	runtime.Config.BanList = banList
	myDice = runtime

	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	part, err := form.CreateFormFile("file", "ban-list.json")
	if err != nil {
		t.Fatalf("create import form: %v", err)
	}
	if _, err = io.WriteString(part, `[{"ID":"QQ:98765","name":"trusted","rank":30,"reasons":["manual trust"],"places":[],"times":[]}]`); err != nil {
		t.Fatalf("write import data: %v", err)
	}
	if err = form.Close(); err != nil {
		t.Fatalf("close import form: %v", err)
	}

	e := echo.New()
	importRequest := httptest.NewRequest(http.MethodPost, "/sd-api/banconfig/import", &body)
	importRequest.Header.Set(echo.HeaderContentType, form.FormDataContentType())
	importRequest.Header.Set("Token", "ban-list-token")
	importResponse := httptest.NewRecorder()
	if err = banImport(e.NewContext(importRequest, importResponse)); err != nil {
		t.Fatalf("import ban list: %v", err)
	}
	if importResponse.Code != http.StatusOK {
		t.Fatalf("import status = %d, want %d; body = %s", importResponse.Code, http.StatusOK, importResponse.Body.String())
	}
	item, exists := banList.GetByID("QQ:98765")
	if !exists || item.Rank != dice.BanRankTrusted || len(item.Reasons) != 1 || item.Reasons[0] != "manual trust（来自导入）" {
		t.Fatalf("imported item = %#v, exists = %v", item, exists)
	}

	exportRequest := httptest.NewRequest(http.MethodGet, "/sd-api/banconfig/export", nil)
	exportRequest.Header.Set("Token", "ban-list-token")
	exportResponse := httptest.NewRecorder()
	if err = banExport(e.NewContext(exportRequest, exportResponse)); err != nil {
		t.Fatalf("export ban list: %v", err)
	}
	if exportResponse.Code != http.StatusOK {
		t.Fatalf("export status = %d, want %d; body = %s", exportResponse.Code, http.StatusOK, exportResponse.Body.String())
	}
	var exported []dice.BanListInfoItem
	if err = json.Unmarshal(exportResponse.Body.Bytes(), &exported); err != nil {
		t.Fatalf("decode exported ban list: %v", err)
	}
	if len(exported) != 1 || exported[0].ID != "QQ:98765" || exported[0].Rank != dice.BanRankTrusted {
		t.Fatalf("exported items = %#v", exported)
	}
}
