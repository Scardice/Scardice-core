package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"Scardice-core/dice"
)

func TestBanRoutesRejectUnauthenticatedRequests(t *testing.T) {
	t.Setenv(adminAuthBypassEnv, "")
	previousDice, previousManager := myDice, dm
	t.Cleanup(func() { myDice, dm = previousDice, previousManager })

	manager := &dice.DiceManager{}
	runtime := &dice.Dice{Parent: manager}
	banList := &dice.BanListInfo{Parent: runtime}
	banList.Init()
	banList.Map.Store("QQ:existing", &dice.BanListInfoItem{ID: "QQ:existing", Rank: dice.BanRankBanned})
	runtime.Config.BanList = banList
	myDice, dm = runtime, manager

	tests := []struct {
		name    string
		handler echo.HandlerFunc
		body    string
		id      string
		present bool
	}{
		{name: "add", handler: banMapAddOne, body: `{"ID":"QQ:unauthorized","Rank":-30}`, id: "QQ:unauthorized"},
		{name: "delete", handler: banMapDeleteOne, body: `{"ID":"QQ:existing"}`, id: "QQ:existing", present: true},
		{name: "list", handler: banMapList, id: "QQ:existing", present: true},
		{name: "export", handler: banExport, id: "QQ:existing", present: true},
		{name: "import", handler: banImport, id: "QQ:existing", present: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/sd-api/banconfig/map_"+test.name+"_one", strings.NewReader(test.body))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			if err := test.handler(echo.New().NewContext(req, rec)); err != nil {
				t.Fatalf("handler error: %v", err)
			}
			if rec.Code != http.StatusForbidden {
				t.Fatalf("unauthorized status = %d, want %d; body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
			}
			_, exists := banList.GetByID(test.id)
			if exists != test.present {
				t.Fatalf("item %q exists=%v, want %v", test.id, exists, test.present)
			}
		})
	}
}
