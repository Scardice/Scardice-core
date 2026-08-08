package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/sealdice/botgo/dto"

	"Scardice-core/dice"
)

type officialQQHandlerResponse struct {
	Result   bool   `json:"result"`
	TestOnly bool   `json:"testOnly"`
	UserID   string `json:"userId"`
	UIN      string `json:"uin"`
	Nickname string `json:"nickname"`
	Exists   bool   `json:"exists"`
	Err      string `json:"err"`
}

type officialQQHandlerEffects struct {
	saveCalls  int
	startCalls int
	started    *dice.EndPointInfo
}

func setupOfficialQQHandlerTest(t *testing.T, endpoints []*dice.EndPointInfo) (*dice.Dice, *officialQQHandlerEffects) {
	t.Helper()

	manager := &dice.DiceManager{}
	manager.AccessTokens.Store("official-qq-test-token", true)
	session := &dice.IMSession{EndPoints: endpoints}
	testDice := &dice.Dice{Parent: manager, ImSession: session}
	session.Parent = testDice
	manager.Dice = []*dice.Dice{testDice}

	previousDice, previousManager := myDice, dm
	previousMe := officialQQMe
	previousSave := officialQQSave
	previousStart := officialQQStart
	t.Cleanup(func() {
		myDice, dm = previousDice, previousManager
		officialQQMe = previousMe
		officialQQSave = previousSave
		officialQQStart = previousStart
	})
	myDice, dm = testDice, manager

	effects := &officialQQHandlerEffects{}
	officialQQSave = func(*dice.Dice) {
		effects.saveCalls++
	}
	officialQQStart = func(_ *dice.Dice, endpoint *dice.EndPointInfo) {
		effects.startCalls++
		effects.started = endpoint
	}
	return testDice, effects
}

func requestAddOfficialQQ(t *testing.T, body string) (*httptest.ResponseRecorder, officialQQHandlerResponse) {
	t.Helper()

	e := echo.New()
	request := httptest.NewRequest(http.MethodPost, "/sd-api/im_connections/addOfficialQQ", strings.NewReader(body))
	request.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	request.Header.Set("Token", "official-qq-test-token")
	recorder := httptest.NewRecorder()

	if err := ImConnectionsAddOfficialQQ(e.NewContext(request, recorder)); err != nil {
		t.Fatalf("ImConnectionsAddOfficialQQ() error = %v", err)
	}
	var response officialQQHandlerResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return recorder, response
}

func Test_ImConnectionsAddOfficialQQ_returns_verified_identity_without_mutation_when_test_only(t *testing.T) {
	// Given
	testDice, effects := setupOfficialQQHandlerTest(t, nil)
	officialQQMe = func(ctx context.Context, adapter *dice.PlatformAdapterOfficialQQ) (*dto.User, error) {
		if adapter.AppID != 12345 || adapter.Token != "submitted-token" || adapter.AppSecret != "submitted-secret" {
			t.Fatal("temporary adapter did not receive request-local credentials")
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("Me context has no deadline")
		}
		return &dto.User{ID: "bot-open-id", Username: "Verified Bot"}, nil
	}

	// When
	recorder, response := requestAddOfficialQQ(t, `{"appID":12345,"token":"submitted-token","appSecret":"submitted-secret","onlyQQGuild":true,"testOnly":true}`)

	// Then
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if !response.Result || !response.TestOnly || response.UserID != "OpenQQ:bot-open-id" || response.UIN != "bot-open-id" || response.Nickname != "Verified Bot" || response.Exists {
		t.Fatalf("response = %#v", response)
	}
	if len(testDice.ImSession.EndPoints) != 0 || effects.saveCalls != 0 || effects.startCalls != 0 || testDice.LastUpdatedTime != 0 {
		t.Fatalf("test-only side effects: endpoints=%d save=%d start=%d updated=%d", len(testDice.ImSession.EndPoints), effects.saveCalls, effects.startCalls, testDice.LastUpdatedTime)
	}
}

func Test_ImConnectionsAddOfficialQQ_reports_existing_verified_identity_without_mutation_when_test_only(t *testing.T) {
	// Given
	existing := dice.NewOfficialQQConnItem(999, "", "", false)
	existing.UserID = "OpenQQ:duplicate-open-id"
	existing.Nickname = "Existing Bot"
	testDice, effects := setupOfficialQQHandlerTest(t, []*dice.EndPointInfo{existing})
	officialQQMe = func(context.Context, *dice.PlatformAdapterOfficialQQ) (*dto.User, error) {
		return &dto.User{ID: "duplicate-open-id", Username: "Verified Duplicate"}, nil
	}

	// When
	_, response := requestAddOfficialQQ(t, `{"appID":12345,"token":"submitted-token","appSecret":"submitted-secret","testOnly":true}`)

	// Then
	if !response.Result || !response.TestOnly || !response.Exists || response.UserID != "OpenQQ:duplicate-open-id" || response.UIN != "duplicate-open-id" || response.Nickname != "Verified Duplicate" {
		t.Fatalf("response = %#v", response)
	}
	if len(testDice.ImSession.EndPoints) != 1 || testDice.ImSession.EndPoints[0] != existing || effects.saveCalls != 0 || effects.startCalls != 0 || testDice.LastUpdatedTime != 0 {
		t.Fatalf("duplicate test side effects: endpoints=%d save=%d start=%d updated=%d", len(testDice.ImSession.EndPoints), effects.saveCalls, effects.startCalls, testDice.LastUpdatedTime)
	}
}

func Test_ImConnectionsAddOfficialQQ_returns_api_error_without_mutation_when_test_only_me_fails(t *testing.T) {
	// Given
	testDice, effects := setupOfficialQQHandlerTest(t, nil)
	officialQQMe = func(context.Context, *dice.PlatformAdapterOfficialQQ) (*dto.User, error) {
		return nil, errors.New("Me unavailable")
	}

	// When
	_, response := requestAddOfficialQQ(t, `{"appID":12345,"token":"submitted-token","appSecret":"submitted-secret","testOnly":true}`)

	// Then
	if response.Result || response.Err != "official QQ connection test failed" {
		t.Fatalf("response = %#v", response)
	}
	if len(testDice.ImSession.EndPoints) != 0 || effects.saveCalls != 0 || effects.startCalls != 0 || testDice.LastUpdatedTime != 0 {
		t.Fatalf("failed test side effects: endpoints=%d save=%d start=%d updated=%d", len(testDice.ImSession.EndPoints), effects.saveCalls, effects.startCalls, testDice.LastUpdatedTime)
	}
}

func Test_ImConnectionsAddOfficialQQ_preserves_add_save_and_start_when_not_test_only(t *testing.T) {
	// Given
	testDice, effects := setupOfficialQQHandlerTest(t, nil)
	officialQQMe = func(context.Context, *dice.PlatformAdapterOfficialQQ) (*dto.User, error) {
		t.Fatal("non-test add called Me synchronously")
		return nil, errors.New("non-test add must not call Me")
	}

	// When
	_, response := requestAddOfficialQQ(t, `{"appID":12345,"token":"submitted-token","appSecret":"submitted-secret","onlyQQGuild":true,"testOnly":false}`)

	// Then
	if !response.Result || response.TestOnly || response.Err != "" {
		t.Fatalf("response = %#v", response)
	}
	if len(testDice.ImSession.EndPoints) != 1 || effects.saveCalls != 1 || effects.startCalls != 1 || effects.started != testDice.ImSession.EndPoints[0] || testDice.LastUpdatedTime == 0 {
		t.Fatalf("non-test side effects: endpoints=%d save=%d start=%d updated=%d", len(testDice.ImSession.EndPoints), effects.saveCalls, effects.startCalls, testDice.LastUpdatedTime)
	}
	adapter := testDice.ImSession.EndPoints[0].Adapter.(*dice.PlatformAdapterOfficialQQ)
	if adapter.AppID != 12345 || adapter.Token != "submitted-token" || adapter.AppSecret != "submitted-secret" || !adapter.OnlyQQGuild {
		t.Fatal("non-test endpoint did not retain the submitted configuration")
	}
}
