package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"

	"Scardice-core/dice"
)

func storyAPIDiceWithoutLegacyDatabase(t *testing.T) *dice.Dice {
	t.Helper()
	previousDice := myDice
	manager := &dice.DiceManager{}
	testDice := &dice.Dice{Parent: manager}
	myDice = testDice
	t.Cleanup(func() { myDice = previousDice })
	return testDice
}

func TestStoryGetInfoWithoutLogRepositoryReturnsUnavailable(t *testing.T) {
	storyAPIDiceWithoutLegacyDatabase(t)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/sd-api/story/info", nil)
	ctx := echo.New().NewContext(request, recorder)

	if err := storyGetInfo(ctx); err != nil {
		t.Fatalf("storyGetInfo() error = %v", err)
	}
	if recorder.Code != http.StatusServiceUnavailable || recorder.Body.Len() == 0 {
		t.Fatalf("storyGetInfo() status=%d body=%q, want explicit unavailable response", recorder.Code, recorder.Body.String())
	}
}

func TestStoryGetLogPageWithoutLogRepositoryReturnsUnavailable(t *testing.T) {
	testDice := storyAPIDiceWithoutLegacyDatabase(t)
	const token = "story-test-token"
	testDice.Parent.AccessTokens.Store(token, true)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/sd-api/story/logs/page?pageNum=1&pageSize=20", nil)
	request.Header.Set("Token", token)
	ctx := echo.New().NewContext(request, recorder)

	if err := storyGetLogPage(ctx); err != nil {
		t.Fatalf("storyGetLogPage() error = %v", err)
	}
	if recorder.Code != http.StatusServiceUnavailable || recorder.Body.Len() == 0 {
		t.Fatalf("storyGetLogPage() status=%d body=%q, want explicit unavailable response", recorder.Code, recorder.Body.String())
	}
}
