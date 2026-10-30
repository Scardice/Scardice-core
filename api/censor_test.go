package api

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"Scardice-core/dice"
	"Scardice-core/dice/censor"
)

func TestCensorEncodedDetailsHandlerConfigRoundTrip(t *testing.T) {
	// Given
	previousDice := myDice
	t.Cleanup(func() { myDice = previousDice })
	myDice = &dice.Dice{}
	myDice.Config.CensorHandlers = make(map[censor.Level]uint8)

	// When
	setLevelHandlers(censor.Warning, []string{"SendWarning", "SendEncodedDetails"})
	got := getLevelConfig(
		censor.Warning,
		map[censor.Level]int{
			censor.Ignore:  0,
			censor.Notice:  0,
			censor.Caution: 0,
			censor.Warning: 1,
			censor.Danger:  0,
		},
		myDice.Config.CensorHandlers,
		map[censor.Level]int{
			censor.Ignore:  0,
			censor.Notice:  0,
			censor.Caution: 0,
			censor.Warning: 100,
			censor.Danger:  0,
		},
	)

	// Then
	if !slices.Contains(got.Handlers, "SendEncodedDetails") {
		t.Fatalf("encoded details handler missing after config round trip: %v", got.Handlers)
	}
}
func TestCensorLogPageUnavailableStates(t *testing.T) {
	previousDice, previousManager := myDice, dm
	t.Cleanup(func() {
		myDice = previousDice
		dm = previousManager
	})

	manager := &dice.DiceManager{}
	manager.AccessTokens.Store("censor-log-token", true)
	dm = manager
	myDice = &dice.Dice{Parent: manager}
	myDice.Config.EnableCensor = true

	for _, test := range []struct {
		name         string
		censor       *dice.CensorManager
		wantCode     string
		wantBody     []string
		wantHTTPCode int
	}{
		{name: "manager not initialized", wantCode: "censor_runtime_unavailable", wantHTTPCode: http.StatusServiceUnavailable},
		{name: "legacy log storage absent", censor: &dice.CensorManager{}, wantBody: []string{`"result":true`, `"data":[]`, `"total":0`}, wantHTTPCode: http.StatusOK},
	} {
		t.Run(test.name, func(t *testing.T) {
			myDice.CensorManager = test.censor
			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, "/sd-api/censor/logs/page?pageNum=1&pageSize=10", nil)
			req.Header.Set("Token", "censor-log-token")
			rec := httptest.NewRecorder()

			if err := censorGetLogPage(e.NewContext(req, rec)); err != nil {
				t.Fatalf("get censor logs: %v", err)
			}
			if rec.Code != test.wantHTTPCode {
				t.Fatalf("status = %d, want %d; body = %s", rec.Code, test.wantHTTPCode, rec.Body.String())
			}
			if test.wantCode != "" && !strings.Contains(rec.Body.String(), `"code":"`+test.wantCode+`"`) {
				t.Fatalf("response lacks %q: %s", test.wantCode, rec.Body.String())
			}
			for _, fragment := range test.wantBody {
				if !strings.Contains(rec.Body.String(), fragment) {
					t.Fatalf("response lacks %q: %s", fragment, rec.Body.String())
				}
			}
		})
	}
}
