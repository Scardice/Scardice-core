package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"

	"Scardice-core/dice"
)

func newPProfTestEcho(t *testing.T) (*echo.Echo, string) {
	t.Helper()

	previousDice, previousManager := myDice, dm
	manager := &dice.DiceManager{}
	testDice := &dice.Dice{Parent: manager}
	manager.Dice = []*dice.Dice{testDice}
	const token = "task9-token"
	manager.AccessTokens.Store(token, true)

	e := echo.New()
	Bind(e, manager)
	t.Cleanup(func() {
		myDice, dm = previousDice, previousManager
	})
	return e, token
}

func TestPProfRoutesRejectUnauthenticatedRequests(t *testing.T) {
	// Given
	e, _ := newPProfTestEcho(t)
	paths := []string{
		"/sd-api/debug/pprof",
		"/sd-api/debug/pprof/",
		"/sd-api/debug/pprof/cmdline",
		"/sd-api/debug/pprof/profile",
		"/sd-api/debug/pprof/symbol",
		"/sd-api/debug/pprof/trace",
		"/sd-api/debug/pprof/allocs",
		"/sd-api/debug/pprof/block",
		"/sd-api/debug/pprof/goroutine",
		"/sd-api/debug/pprof/heap",
		"/sd-api/debug/pprof/mutex",
		"/sd-api/debug/pprof/threadcreate",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			// When
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)

			// Then
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
			}
		})
	}
}

func TestPProfRoutesServeIndexAndNamedProfileWhenAuthenticated(t *testing.T) {
	// Given
	e, token := newPProfTestEcho(t)
	paths := []string{
		"/sd-api/debug/pprof/",
		"/sd-api/debug/pprof/profile?seconds=1",
		"/sd-api/debug/pprof/goroutine?debug=1",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Header.Set("Token", token)
			rec := httptest.NewRecorder()

			// When
			e.ServeHTTP(rec, req)

			// Then
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusOK, rec.Body.String())
			}
			if rec.Body.Len() == 0 {
				t.Fatal("response body is empty")
			}
		})
	}
}
