package api

import (
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
	req.Header.Set("token", "task5-token")
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
