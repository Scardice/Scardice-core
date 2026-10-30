package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"Scardice-core/dice"
)

func TestTestWebUIBypassEnvironmentRequiresExactOne(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "unset", want: false},
		{name: "empty", value: "", want: false},
		{name: "zero", value: "0", want: false},
		{name: "true", value: "true", want: false},
		{name: "padded one", value: " 1 ", want: false},
		{name: "other numeric", value: "01", want: false},
		{name: "exact one", value: "1", want: true},
	}

	for _, bypass := range []struct {
		name    string
		env     string
		enabled func() bool
	}{
		{name: "authentication", env: adminAuthBypassEnv, enabled: testWebUIAuthBypassEnabled},
		{name: "origin and rate limit", env: adminOriginRateLimitBypassEnv, enabled: WebUIOriginRateLimitBypassEnabled},
	} {
		t.Run(bypass.name, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					if tt.name == "unset" {
						unsetTestEnvironmentVariable(t, bypass.env)
					} else {
						t.Setenv(bypass.env, tt.value)
					}
					if got := bypass.enabled(); got != tt.want {
						t.Fatalf("enabled() = %v, want %v for %q", got, tt.want, tt.value)
					}
				})
			}
		})
	}
}

func unsetTestEnvironmentVariable(t *testing.T, key string) {
	t.Helper()
	t.Setenv(key, "")
	if err := os.Unsetenv(key); err != nil {
		t.Fatal(err)
	}
}

func TestDoAuthTestBypassAcceptsMissingEmptyAndArbitraryToken(t *testing.T) {
	setupWebUIBypassAuthState(t)
	t.Setenv(adminAuthBypassEnv, "1")

	for _, path := range []string{"/", "/?token=", "/?token=random-token"} {
		ctx, _ := webUIBypassContext(path)
		if !doAuth(ctx) {
			t.Errorf("doAuth(%q) = false with credential bypass enabled", path)
		}
	}
	for _, token := range []string{"", "random-token"} {
		ctx, _ := webUIBypassContext("/")
		ctx.Request().Header.Set("Token", token)
		if !doAuth(ctx) {
			t.Errorf("doAuth with header token %q = false with credential bypass enabled", token)
		}
	}
}

func TestWebUIBypassesDefaultOffKeepBothAuthPathsProtected(t *testing.T) {
	setupWebUIBypassAuthState(t)
	unsetTestEnvironmentVariable(t, adminAuthBypassEnv)
	unsetTestEnvironmentVariable(t, adminOriginRateLimitBypassEnv)

	legacyCtx, _ := webUIBypassContext("/")
	if doAuth(legacyCtx) {
		t.Fatal("doAuth() accepted missing credentials with bypass unset")
	}
	adminCtx, _ := webUIBypassContext("/")
	if _, err := adminPrincipal(adminCtx); !errors.Is(err, errAdminUnauthorized) {
		t.Fatalf("adminPrincipal() without credentials error = %v, want %v", err, errAdminUnauthorized)
	}

	legacyCtx, _ = webUIBypassContext("/")
	legacyCtx.Request().Header.Set("Token", "valid-test-session")
	if !doAuth(legacyCtx) {
		t.Fatal("doAuth() rejected a valid token with bypass unset")
	}
	adminCtx, _ = webUIBypassContext("/")
	adminCtx.Request().Header.Set(echo.HeaderAuthorization, "Bearer valid-test-session")
	if principal, err := adminPrincipal(adminCtx); err != nil || principal != "test-webui-admin" {
		t.Fatalf("adminPrincipal() with valid credentials: principal=%q err=%v", principal, err)
	}
}

func TestAdminPrincipalAuthBypassAcceptsAnyCredentialAndKeepsIdentity(t *testing.T) {
	setupWebUIBypassAuthState(t)
	t.Setenv(adminAuthBypassEnv, "1")
	t.Setenv(adminOriginRateLimitBypassEnv, "1")

	cases := []struct {
		name   string
		path   string
		header []string
	}{
		{name: "missing", path: "/"},
		{name: "empty", path: "/", header: []string{""}},
		{name: "arbitrary", path: "/", header: []string{"not-a-bearer-token"}},
		{name: "bearer arbitrary", path: "/", header: []string{"Bearer random-token"}},
		{name: "query token", path: "/?token=random-token"},
		{name: "query access token", path: "/?access_token=random-token"},
		{name: "duplicate", path: "/", header: []string{"Bearer random-token", "anything"}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			ctx, _ := webUIBypassContext(tt.path)
			for _, value := range tt.header {
				ctx.Request().Header.Add(echo.HeaderAuthorization, value)
			}
			principal, err := adminPrincipal(ctx)
			if err != nil {
				t.Fatalf("adminPrincipal() error = %v", err)
			}
			if principal != "test-webui-admin" {
				t.Fatalf("adminPrincipal() = %q, want stable configured principal", principal)
			}
		})
	}
}

func TestAdminAuthBypassDoesNotBypassOriginOrRateLimit(t *testing.T) {
	setupWebUIBypassAuthState(t)
	t.Setenv(adminAuthBypassEnv, "1")
	t.Setenv(adminOriginRateLimitBypassEnv, "0")
	_, limiter, err := currentAdminAuth()
	if err != nil {
		t.Fatalf("currentAdminAuth() error = %v", err)
	}
	limitTime := time.Unix(1, 0)
	limiter.now = func() time.Time { return limitTime }

	badOrigin, _ := webUIBypassContext("/")
	badOrigin.Request().Header.Set(echo.HeaderOrigin, "https://evil.example")
	if _, err := adminPrincipal(badOrigin); !errors.Is(err, errAdminOrigin) {
		t.Fatalf("adminPrincipal() error for disallowed origin = %v, want %v", err, errAdminOrigin)
	}

	for i := range 30 {
		ctx, _ := webUIBypassContext("/")
		if principal, err := adminPrincipal(ctx); err != nil || principal != "test-webui-admin" {
			t.Fatalf("request %d before burst limit: principal=%q err=%v", i+1, principal, err)
		}
	}
	ctx, _ := webUIBypassContext("/")
	if _, err := adminPrincipal(ctx); !errors.Is(err, errAdminRateLimit) {
		t.Fatalf("request past limiter burst error = %v, want %v", err, errAdminRateLimit)
	}
}

func TestLegacyAuthBypassOriginPolicyIsIndependent(t *testing.T) {
	setupWebUIBypassAuthState(t)
	t.Setenv(adminAuthBypassEnv, "1")
	t.Setenv(adminOriginRateLimitBypassEnv, "0")

	evilOrigin, _ := webUIBypassContext("/")
	evilOrigin.Request().Header.Set(echo.HeaderOrigin, "https://evil.example")
	if doAuth(evilOrigin) {
		t.Fatal("doAuth() accepted an evil Origin with only the credential bypass enabled")
	}
	if _, err := adminPrincipal(evilOrigin); !errors.Is(err, errAdminOrigin) {
		t.Fatalf("adminPrincipal() with evil Origin error = %v, want %v", err, errAdminOrigin)
	}

	sameOrigin, _ := webUIBypassContext("/")
	sameOrigin.Request().Header.Set(echo.HeaderOrigin, "http://example.com")
	if !doAuth(sameOrigin) {
		t.Fatal("doAuth() rejected same-origin request with credential bypass enabled")
	}
	if _, err := adminPrincipal(sameOrigin); err != nil {
		t.Fatalf("adminPrincipal() rejected same-origin request: %v", err)
	}
	noOrigin, _ := webUIBypassContext("/")
	if !doAuth(noOrigin) {
		t.Fatal("doAuth() rejected request without Origin with credential bypass enabled")
	}
	if _, err := adminPrincipal(noOrigin); err != nil {
		t.Fatalf("adminPrincipal() rejected request without Origin: %v", err)
	}

	noOriginCrossSite, _ := webUIBypassContext("/")
	noOriginCrossSite.Request().Header.Set("Sec-Fetch-Site", "cross-site")
	if doAuth(noOriginCrossSite) {
		t.Fatal("doAuth() accepted a cross-site Fetch Metadata request without Origin")
	}
	if _, err := adminPrincipal(noOriginCrossSite); !errors.Is(err, errAdminOrigin) {
		t.Fatalf("adminPrincipal() with cross-site Fetch Metadata error = %v, want %v", err, errAdminOrigin)
	}

	fetchSiteSameOrigin, _ := webUIBypassContext("/")
	fetchSiteSameOrigin.Request().Header.Set("Sec-Fetch-Site", "same-origin")
	if !doAuth(fetchSiteSameOrigin) {
		t.Fatal("doAuth() rejected a same-origin Fetch Metadata request without Origin")
	}
	if _, err := adminPrincipal(fetchSiteSameOrigin); err != nil {
		t.Fatalf("adminPrincipal() rejected same-origin Fetch Metadata request: %v", err)
	}

	t.Setenv(adminOriginRateLimitBypassEnv, "1")
	if !doAuth(evilOrigin) {
		t.Fatal("doAuth() rejected evil Origin when both bypasses are enabled")
	}
	if _, err := adminPrincipal(evilOrigin); err != nil {
		t.Fatalf("adminPrincipal() rejected evil Origin when both bypasses are enabled: %v", err)
	}
	if !doAuth(noOriginCrossSite) {
		t.Fatal("doAuth() rejected cross-site Fetch Metadata when both bypasses are enabled")
	}
	if _, err := adminPrincipal(noOriginCrossSite); err != nil {
		t.Fatalf("adminPrincipal() rejected cross-site Fetch Metadata when both bypasses are enabled: %v", err)
	}
}

func TestAdminOriginAllowlistAcceptsConfiguredAndRejectsUnlistedOrigins(t *testing.T) {
	for _, tt := range []struct {
		name       string
		authBypass bool
	}{
		{name: "credentials required"},
		{name: "test auth bypass", authBypass: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			setupWebUIBypassAuthState(t)
			if tt.authBypass {
				t.Setenv(adminAuthBypassEnv, "1")
			} else {
				t.Setenv(adminAuthBypassEnv, "0")
			}
			t.Setenv(adminOriginRateLimitBypassEnv, "0")
			t.Setenv(adminOriginsEnv, "https://webui.example")

			ctx, _ := webUIBypassContext("/")
			ctx.Request().Host = "admin.example"
			ctx.Request().Header.Set(echo.HeaderOrigin, "https://webui.example")
			ctx.Request().Header.Set("Sec-Fetch-Site", "cross-site")
			if !tt.authBypass {
				ctx.Request().Header.Set(echo.HeaderAuthorization, "Bearer valid-test-session")
			}

			if err := requireAdmin(ctx); err != nil {
				t.Fatalf("requireAdmin() rejected configured cross-origin request: %v", err)
			}
			if principal := adminPrincipalFromContext(ctx); principal != "test-webui-admin" {
				t.Fatalf("adminPrincipalFromContext() = %q, want configured principal", principal)
			}

			unlisted, _ := webUIBypassContext("/")
			unlisted.Request().Host = "admin.example"
			unlisted.Request().Header.Set(echo.HeaderOrigin, "https://evil.example")
			if !tt.authBypass {
				unlisted.Request().Header.Set(echo.HeaderAuthorization, "Bearer valid-test-session")
			}
			if _, err := adminPrincipal(unlisted); !errors.Is(err, errAdminOrigin) {
				t.Fatalf("adminPrincipal() accepted unlisted origin: err=%v", err)
			}
		})
	}
}

func TestAdminOriginRateLimitBypassKeepsCredentialCheckAndBypassesBoundaries(t *testing.T) {
	setupWebUIBypassAuthState(t)
	t.Setenv(adminAuthBypassEnv, "0")
	t.Setenv(adminOriginRateLimitBypassEnv, "1")

	missing, _ := webUIBypassContext("/")
	missing.Request().Header.Set(echo.HeaderOrigin, "https://evil.example")
	if _, err := adminPrincipal(missing); !errors.Is(err, errAdminUnauthorized) {
		t.Fatalf("adminPrincipal() without credentials error = %v, want %v", err, errAdminUnauthorized)
	}

	badCredential, _ := webUIBypassContext("/")
	badCredential.Request().Header.Set(echo.HeaderAuthorization, "Bearer random-token")
	badCredential.Request().Header.Set(echo.HeaderOrigin, "https://evil.example")
	if _, err := adminPrincipal(badCredential); !errors.Is(err, errAdminUnauthorized) {
		t.Fatalf("adminPrincipal() with invalid credentials error = %v, want %v", err, errAdminUnauthorized)
	}

	for i := range 35 {
		ctx, _ := webUIBypassContext("/")
		ctx.Request().Header.Set(echo.HeaderAuthorization, "Bearer valid-test-session")
		ctx.Request().Header.Set(echo.HeaderOrigin, "https://evil.example")
		principal, err := adminPrincipal(ctx)
		if err != nil || principal != "test-webui-admin" {
			t.Fatalf("request %d with origin/rate bypass: principal=%q err=%v", i+1, principal, err)
		}
	}
}

func TestPreInfoExposesTestWebUIBypassFlags(t *testing.T) {
	setupWebUIBypassAuthState(t)
	t.Setenv(adminAuthBypassEnv, "1")
	t.Setenv(adminOriginRateLimitBypassEnv, "true")

	ctx, recorder := webUIBypassContext("/sd-api/preInfo")
	if err := preInfo(ctx); err != nil {
		t.Fatal(err)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode preInfo response: %v", err)
	}
	if body["testWebUIAuthBypass"] != true {
		t.Fatalf("testWebUIAuthBypass = %v, want true", body["testWebUIAuthBypass"])
	}
	if body["testWebUIOriginRateLimitBypass"] != false {
		t.Fatalf("testWebUIOriginRateLimitBypass = %v, want false", body["testWebUIOriginRateLimitBypass"])
	}
}

func setupWebUIBypassAuthState(t *testing.T) {
	t.Helper()
	previousDice, previousManager := myDice, dm
	manager := &dice.DiceManager{}
	manager.AccessTokens.Store("valid-test-session", true)
	myDice = &dice.Dice{Parent: manager}
	dm = manager
	t.Setenv(adminPrincipalEnv, "test-webui-admin")
	t.Setenv(adminOriginsEnv, "")
	ResetAdminAuthForTests()
	t.Cleanup(func() {
		ResetAdminAuthForTests()
		myDice, dm = previousDice, previousManager
	})
}

func webUIBypassContext(path string) (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	return e.NewContext(request, recorder), recorder
}
