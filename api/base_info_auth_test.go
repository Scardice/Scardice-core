package api

import (
	"net/http"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestBaseInfoRequiresRegisteredWebUISession(t *testing.T) {
	t.Setenv(adminAuthBypassEnv, "0")
	t.Setenv(adminOriginRateLimitBypassEnv, "0")
	setupEndpointAPITest(t)

	cases := []struct {
		name          string
		authorization string
		token         string
		wantStatus    int
	}{
		{
			name:          "registered WebUI session",
			authorization: "Bearer " + endpointAPITestSessionToken,
			token:         endpointAPITestSessionToken,
			wantStatus:    http.StatusOK,
		},
		{
			name:          "standalone admin secret",
			authorization: "Bearer api-test-secret",
			token:         "api-test-secret",
			wantStatus:    http.StatusForbidden,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			ctx, recorder := endpointAPIContext(http.MethodGet, "/sd-api/baseInfo", "")
			ctx.Request().Header.Set(echo.HeaderAuthorization, tt.authorization)
			ctx.Request().Header.Set("Token", tt.token)
			if err := baseInfo(ctx); err != nil {
				t.Fatal(err)
			}
			if recorder.Code != tt.wantStatus {
				t.Fatalf("baseInfo status=%d body=%s, want %d", recorder.Code, recorder.Body.String(), tt.wantStatus)
			}
		})
	}
}
