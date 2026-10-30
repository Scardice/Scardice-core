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
	previousProbe := officialQQProbe
	previousSave := officialQQSave
	previousStart := officialQQStart
	t.Cleanup(func() {
		myDice, dm = previousDice, previousManager
		officialQQProbe = previousProbe
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
	officialQQProbe = func(ctx context.Context, appID, appSecret string) (*dice.OfficialQQAccountProbeResult, error) {
		if appID != "12345" || appSecret != "submitted-secret" {
			t.Fatalf("probe received appID=%q appSecret=%q", appID, appSecret)
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("probe context has no deadline")
		}
		return &dice.OfficialQQAccountProbeResult{UIN: "bot-uin", BotID: "bot-open-id", Nickname: "Verified Bot"}, nil
	}

	// When
	recorder, response := requestAddOfficialQQ(t, `{"appID":12345,"token":"submitted-token","appSecret":"submitted-secret","onlyQQGuild":true,"testOnly":true}`)

	// Then
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if !response.Result || !response.TestOnly || response.UserID != "OpenQQ:bot-uin" || response.UIN != "bot-uin" || response.Nickname != "Verified Bot" || response.Exists {
		t.Fatalf("response = %#v", response)
	}
	if len(testDice.ImSession.EndPoints) != 0 || effects.saveCalls != 0 || effects.startCalls != 0 || testDice.LastUpdatedTime != 0 {
		t.Fatalf("test-only side effects: endpoints=%d save=%d start=%d updated=%d", len(testDice.ImSession.EndPoints), effects.saveCalls, effects.startCalls, testDice.LastUpdatedTime)
	}
}

func Test_ImConnectionsAddOfficialQQ_reports_existing_verified_identity_without_mutation_when_test_only(t *testing.T) {
	// Given
	existing := dice.NewOfficialQQConnItem("999", "", "", false)
	existing.UserID = "OpenQQ:duplicate-uin"
	existing.Nickname = "Existing Bot"
	testDice, effects := setupOfficialQQHandlerTest(t, []*dice.EndPointInfo{existing})
	officialQQProbe = func(context.Context, string, string) (*dice.OfficialQQAccountProbeResult, error) {
		return &dice.OfficialQQAccountProbeResult{UIN: "duplicate-uin", Nickname: "Verified Duplicate"}, nil
	}

	// When
	_, response := requestAddOfficialQQ(t, `{"appID":12345,"token":"submitted-token","appSecret":"submitted-secret","testOnly":true}`)

	// Then
	if !response.Result || !response.TestOnly || !response.Exists || response.UserID != "OpenQQ:duplicate-uin" || response.UIN != "duplicate-uin" || response.Nickname != "Verified Duplicate" {
		t.Fatalf("response = %#v", response)
	}
	if len(testDice.ImSession.EndPoints) != 1 || testDice.ImSession.EndPoints[0] != existing || effects.saveCalls != 0 || effects.startCalls != 0 || testDice.LastUpdatedTime != 0 {
		t.Fatalf("duplicate test side effects: endpoints=%d save=%d start=%d updated=%d", len(testDice.ImSession.EndPoints), effects.saveCalls, effects.startCalls, testDice.LastUpdatedTime)
	}
}

func Test_ImConnectionsAddOfficialQQ_returns_api_error_without_mutation_when_probe_fails(t *testing.T) {
	// Given
	testDice, effects := setupOfficialQQHandlerTest(t, nil)
	officialQQProbe = func(context.Context, string, string) (*dice.OfficialQQAccountProbeResult, error) {
		return nil, errors.New("probe unavailable")
	}

	// When
	_, response := requestAddOfficialQQ(t, `{"appID":12345,"token":"submitted-token","appSecret":"submitted-secret","testOnly":true}`)

	// Then
	if response.Result || response.Err != "probe unavailable" {
		t.Fatalf("response = %#v", response)
	}
	if len(testDice.ImSession.EndPoints) != 0 || effects.saveCalls != 0 || effects.startCalls != 0 || testDice.LastUpdatedTime != 0 {
		t.Fatalf("failed test side effects: endpoints=%d save=%d start=%d updated=%d", len(testDice.ImSession.EndPoints), effects.saveCalls, effects.startCalls, testDice.LastUpdatedTime)
	}
}

func Test_ImConnectionsAddOfficialQQ_preserves_add_save_and_start_when_not_test_only(t *testing.T) {
	// Given
	testDice, effects := setupOfficialQQHandlerTest(t, nil)
	officialQQProbe = func(context.Context, string, string) (*dice.OfficialQQAccountProbeResult, error) {
		return &dice.OfficialQQAccountProbeResult{UIN: "123456789", BotID: "bot-open-id", Nickname: "Verified Bot"}, nil
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
	if adapter.AppID.String() != "12345" || adapter.Token != "submitted-token" || adapter.AppSecret != "submitted-secret" || !adapter.OnlyQQGuild || adapter.UIN != "123456789" {
		t.Fatal("non-test endpoint did not retain the submitted configuration")
	}
	if testDice.ImSession.EndPoints[0].UserID != "OpenQQ:123456789" {
		t.Fatalf("endpoint UserID = %q", testDice.ImSession.EndPoints[0].UserID)
	}
}

func Test_ImConnectionsAddOfficialQQ_rejects_duplicate_uin_when_not_test_only(t *testing.T) {
	// Given
	existing := dice.NewOfficialQQConnItem("999", "", "known-uin", false)
	existing.UserID = "OpenQQ:known-uin"
	testDice, effects := setupOfficialQQHandlerTest(t, []*dice.EndPointInfo{existing})
	officialQQProbe = func(context.Context, string, string) (*dice.OfficialQQAccountProbeResult, error) {
		return &dice.OfficialQQAccountProbeResult{UIN: "known-uin", Nickname: "Duplicate"}, nil
	}

	// When
	_, response := requestAddOfficialQQ(t, `{"appID":12345,"appSecret":"submitted-secret","testOnly":false}`)

	// Then
	if response.Result || !strings.Contains(response.Err, "已存在") {
		t.Fatalf("response = %#v", response)
	}
	if len(testDice.ImSession.EndPoints) != 1 || effects.saveCalls != 0 || effects.startCalls != 0 {
		t.Fatalf("duplicate add side effects: endpoints=%d save=%d start=%d", len(testDice.ImSession.EndPoints), effects.saveCalls, effects.startCalls)
	}
}
