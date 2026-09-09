package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"golang.org/x/time/rate"
)

const (
	adminTokenEnv          = "SCARDICE_ADMIN_TOKEN"
	adminPrincipalEnv      = "SCARDICE_ADMIN_PRINCIPAL_ID"
	adminOriginsEnv        = "SCARDICE_ADMIN_ORIGINS"
	adminMaxBodyBytes      = 1 << 20
	adminRequestTimeout    = 30 * time.Second
	adminLimiterIdle       = 15 * time.Minute
	adminLimiterEntryLimit = 4096
)

var (
	errAdminUnavailable  = errors.New("admin authentication is not configured")
	errAdminUnauthorized = errors.New("admin authentication failed")
	errAdminOrigin       = errors.New("admin origin is not allowed")
	errAdminRateLimit    = errors.New("admin rate limit exceeded")
)

type adminAuthConfig struct {
	principal string
	secret    []byte
	origins   map[string]struct{}
}

type adminLimiterEntry struct {
	limiter *rate.Limiter
	usedAt  time.Time
}

type adminLimiter struct {
	mu      sync.Mutex
	entries map[string]adminLimiterEntry
	now     func() time.Time
}

func newAdminLimiter() *adminLimiter {
	return &adminLimiter{entries: make(map[string]adminLimiterEntry), now: time.Now}
}

func (l *adminLimiter) allow(key string) bool {
	if l == nil || strings.TrimSpace(key) == "" {
		return false
	}
	now := l.now().UTC()
	l.mu.Lock()
	defer l.mu.Unlock()
	for existing, entry := range l.entries {
		if now.Sub(entry.usedAt) >= adminLimiterIdle {
			delete(l.entries, existing)
		}
	}
	entry, ok := l.entries[key]
	if !ok {
		if len(l.entries) >= adminLimiterEntryLimit {
			return false
		}
		entry = adminLimiterEntry{limiter: rate.NewLimiter(rate.Limit(10), 30)}
	}
	entry.usedAt = now
	l.entries[key] = entry
	return entry.limiter.AllowN(now, 1)
}

var adminAuthState = struct {
	sync.RWMutex
	config  adminAuthConfig
	loaded  bool
	limiter *adminLimiter
}{limiter: newAdminLimiter()}

// ConfigureAdminAuth installs the credential used by the new endpoint API.
// The secret is retained only in process memory and is never persisted.
func ConfigureAdminAuth(principalID, secret string, origins []string) error {
	principalID = strings.TrimSpace(principalID)
	secret = strings.TrimSpace(secret)
	if principalID == "" {
		principalID = "local-admin"
	}
	if secret == "" || strings.ContainsAny(secret, "\r\n") {
		return errAdminUnavailable
	}
	allowed, err := normalizeAdminOrigins(origins)
	if err != nil {
		return err
	}
	adminAuthState.Lock()
	adminAuthState.config = adminAuthConfig{principal: principalID, secret: []byte(secret), origins: allowed}
	adminAuthState.loaded = true
	adminAuthState.limiter = newAdminLimiter()
	adminAuthState.Unlock()
	return nil
}

// ResetAdminAuthForTests clears process-local credentials. It is intentionally
// exported so API contract tests can restore global state without touching env.
func ResetAdminAuthForTests() {
	adminAuthState.Lock()
	for i := range adminAuthState.config.secret {
		adminAuthState.config.secret[i] = 0
	}
	adminAuthState.config = adminAuthConfig{}
	adminAuthState.loaded = false
	adminAuthState.limiter = newAdminLimiter()
	adminAuthState.Unlock()
}

func currentAdminAuth() (adminAuthConfig, *adminLimiter, error) {
	adminAuthState.RLock()
	if adminAuthState.loaded {
		config := adminAuthConfig{principal: adminAuthState.config.principal, secret: append([]byte(nil), adminAuthState.config.secret...), origins: cloneStringSet(adminAuthState.config.origins)}
		limiter := adminAuthState.limiter
		adminAuthState.RUnlock()
		return config, limiter, nil
	}
	adminAuthState.RUnlock()

	secret := os.Getenv(adminTokenEnv)
	if strings.TrimSpace(secret) == "" {
		return adminAuthConfig{}, nil, errAdminUnavailable
	}
	principal := strings.TrimSpace(os.Getenv(adminPrincipalEnv))
	if principal == "" {
		principal = "local-admin"
	}
	var origins []string
	if raw := strings.TrimSpace(os.Getenv(adminOriginsEnv)); raw != "" {
		origins = strings.Split(raw, ",")
	}
	if _, err := normalizeAdminOrigins(origins); err != nil {
		return adminAuthConfig{}, nil, err
	}
	if err := ConfigureAdminAuth(principal, secret, origins); err != nil {
		return adminAuthConfig{}, nil, err
	}
	adminAuthState.RLock()
	config := adminAuthConfig{principal: adminAuthState.config.principal, secret: append([]byte(nil), adminAuthState.config.secret...), origins: cloneStringSet(adminAuthState.config.origins)}
	limiter := adminAuthState.limiter
	adminAuthState.RUnlock()
	return config, limiter, nil
}

func cloneStringSet(source map[string]struct{}) map[string]struct{} {
	if len(source) == 0 {
		return nil
	}
	copySet := make(map[string]struct{}, len(source))
	for key := range source {
		copySet[key] = struct{}{}
	}
	return copySet
}

func normalizeAdminOrigins(origins []string) (map[string]struct{}, error) {
	allowed := make(map[string]struct{}, len(origins))
	for _, origin := range origins {
		origin = strings.TrimSpace(origin)
		if origin == "" {
			continue
		}
		normalized, err := normalizeAdminOrigin(origin)
		if err != nil {
			return nil, err
		}
		allowed[normalized] = struct{}{}
	}
	return allowed, nil
}

func normalizeAdminOrigin(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" && parsed.Path != "/" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errAdminOrigin
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", errAdminOrigin
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return "", errAdminOrigin
	}
	port := parsed.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = net.JoinHostPort(host, "")
	}
	return scheme + "://" + host, nil
}

func requestOrigin(r *http.Request) (string, error) {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwarded := r.Header.Values("X-Forwarded-Proto"); len(forwarded) == 1 && strings.TrimSpace(forwarded[0]) != "" {
		candidate := strings.ToLower(strings.TrimSpace(forwarded[0]))
		if candidate != "http" && candidate != "https" {
			return "", errAdminOrigin
		}
		scheme = candidate
	} else if len(r.Header.Values("X-Forwarded-Proto")) > 1 {
		return "", errAdminOrigin
	}
	return normalizeAdminOrigin(scheme + "://" + r.Host)
}

func adminPrincipal(c echo.Context) (string, error) {
	if c == nil || c.Request() == nil {
		return "", errAdminUnauthorized
	}
	query := c.Request().URL.Query()
	if _, ok := query["token"]; ok {
		return "", errAdminUnauthorized
	}
	if _, ok := query["access_token"]; ok {
		return "", errAdminUnauthorized
	}
	headerValues := c.Request().Header.Values(echo.HeaderAuthorization)
	if len(headerValues) != 1 {
		return "", errAdminUnauthorized
	}
	parts := strings.Fields(headerValues[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" || strings.ContainsAny(parts[1], ",\r\n") {
		return "", errAdminUnauthorized
	}
	config, limiter, err := currentAdminAuth()
	if err != nil {
		return "", err
	}
	candidate := []byte(parts[1])
	if subtle.ConstantTimeCompare(candidate, config.secret) != 1 {
		return "", errAdminUnauthorized
	}
	if originValues := c.Request().Header.Values(echo.HeaderOrigin); len(originValues) > 0 {
		if len(originValues) != 1 || originValues[0] == "" {
			return "", errAdminOrigin
		}
		normalized, normalizeErr := normalizeAdminOrigin(originValues[0])
		if normalizeErr != nil {
			return "", normalizeErr
		}
		if _, ok := config.origins[normalized]; !ok {
			sameOrigin, sameErr := requestOrigin(c.Request())
			if sameErr != nil || normalized != sameOrigin {
				return "", errAdminOrigin
			}
		}
	}
	key := config.principal + "\x00" + clientIP(c.Request())
	if !limiter.allow(key) {
		return "", errAdminRateLimit
	}
	return config.principal, nil
}

func authenticateAdmin(c echo.Context) (string, error) {
	principal, err := adminPrincipal(c)
	if err != nil {
		return "", err
	}
	c.Set(adminPrincipalContextKey, principal)
	_ = adminRequestID(c)
	return principal, nil
}

func requireAdmin(c echo.Context) error {
	_, err := authenticateAdmin(c)
	if err == nil {
		return nil
	}
	return adminAuthHTTPError(c, err)
}

func clientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

// requireAdminAuth is intentionally separate from doAuth: new routes do not
// accept query tokens, legacy private headers, or the mutable access-token map.
func requireAdminAuth(c echo.Context) bool {
	_, err := authenticateAdmin(c)
	return err == nil
}

const adminPrincipalContextKey = "admin-principal"

func adminPrincipalFromContext(c echo.Context) string {
	if c == nil {
		return ""
	}
	value, _ := c.Get(adminPrincipalContextKey).(string)
	return value
}

func adminRequestID(c echo.Context) string {
	if c == nil || c.Request() == nil {
		return ""
	}
	requestID := strings.TrimSpace(c.Request().Header.Get("X-Request-ID"))
	if requestID == "" {
		requestID = uuid.NewString()
		c.Request().Header.Set("X-Request-ID", requestID)
	}
	if len(requestID) > 256 || strings.ContainsAny(requestID, "\r\n") {
		return "invalid-request-id"
	}
	return requestID
}

func withAdminContext(c echo.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(c.Request().Context(), adminRequestTimeout)
	c.SetRequest(c.Request().WithContext(ctx))
	return ctx, cancel
}

func limitAdminBody(c echo.Context) {
	if c == nil || c.Request() == nil || c.Request().Body == nil {
		return
	}
	c.Request().Body = http.MaxBytesReader(c.Response(), c.Request().Body, adminMaxBodyBytes)
}
