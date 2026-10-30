package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func TestWebUICORSAuthorizationPreflightRequiresOriginRateLimitBypass(t *testing.T) {
	tests := []struct {
		name              string
		value             *string
		wantAuthorization bool
	}{
		{name: "unset", wantAuthorization: false},
		{name: "zero", value: stringPointer("0"), wantAuthorization: false},
		{name: "non-exact", value: stringPointer("true"), wantAuthorization: false},
		{name: "padded one", value: stringPointer(" 1 "), wantAuthorization: false},
		{name: "exact one", value: stringPointer("1"), wantAuthorization: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value == nil {
				unsetWebUICORSEnv(t, "SCARDICE_TEST_WEBUI_ORIGIN_RATE_LIMIT_BYPASS")
			} else {
				t.Setenv("SCARDICE_TEST_WEBUI_ORIGIN_RATE_LIMIT_BYPASS", *tt.value)
			}

			e := echo.New()
			e.Use(middleware.CORSWithConfig(webUICORSConfig()))
			e.OPTIONS("/api", func(c echo.Context) error { return c.NoContent(http.StatusNoContent) })

			req := httptest.NewRequest(http.MethodOptions, "/api", nil)
			req.Header.Set(echo.HeaderOrigin, "https://webui.example")
			req.Header.Set("Access-Control-Request-Method", http.MethodGet)
			req.Header.Set("Access-Control-Request-Headers", "authorization")
			recorder := httptest.NewRecorder()
			e.ServeHTTP(recorder, req)

			if recorder.Code != http.StatusNoContent {
				t.Fatalf("preflight status = %d, want %d", recorder.Code, http.StatusNoContent)
			}
			if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "*" {
				t.Fatalf("Access-Control-Allow-Origin = %q, want unchanged wildcard", got)
			}
			gotAuthorization := containsHeaderValue(recorder.Header().Get("Access-Control-Allow-Headers"), "authorization")
			if gotAuthorization != tt.wantAuthorization {
				t.Fatalf("preflight allows Authorization = %v, want %v; Allow-Headers=%q", gotAuthorization, tt.wantAuthorization, recorder.Header().Get("Access-Control-Allow-Headers"))
			}
		})
	}
}

func containsHeaderValue(header, value string) bool {
	for _, candidate := range strings.Split(header, ",") {
		if strings.EqualFold(strings.TrimSpace(candidate), value) {
			return true
		}
	}
	return false
}

func unsetWebUICORSEnv(t *testing.T, key string) {
	t.Helper()
	t.Setenv(key, "")
	if err := os.Unsetenv(key); err != nil {
		t.Fatal(err)
	}
}

func stringPointer(value string) *string {
	return &value
}
