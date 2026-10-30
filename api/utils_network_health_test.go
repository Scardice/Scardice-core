package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sync/atomic"
	"testing"

	"Scardice-core/dice"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

func TestNetworkHealthCheckerKeepsSharedCheckRunningWhenOverlappingWaiterCanceled(t *testing.T) {
	// Given
	var calls atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	want := networkHealthResult{
		Total:     1,
		Ok:        []string{"qq"},
		Targets:   []networkHealthTarget{{Target: "qq", Ok: true}},
		Timestamp: 123,
	}
	checker := networkHealthChecker{
		run: func() networkHealthResult {
			if calls.Add(1) == 1 {
				close(started)
			}
			<-release
			return want
		},
	}
	firstResult := make(chan networkHealthResult, 1)
	firstErr := make(chan error, 1)
	go func() {
		result, err := checker.check(context.Background())
		firstResult <- result
		firstErr <- err
	}()
	<-started

	// When
	canceledContext, cancel := context.WithCancel(context.Background())
	cancel()
	_, canceledErr := checker.check(canceledContext)
	close(release)

	// Then
	if !errors.Is(canceledErr, context.Canceled) {
		t.Fatalf("canceled waiter error = %v, want context.Canceled", canceledErr)
	}
	if err := <-firstErr; err != nil {
		t.Fatalf("shared check returned error: %v", err)
	}
	if got := <-firstResult; !reflect.DeepEqual(got, want) {
		t.Fatalf("shared result = %#v, want %#v", got, want)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("network check ran %d times, want 1", got)
	}
}

func TestNetworkHealthCheckerHandlePreservesResponseShapeWhenCheckCompletes(t *testing.T) {
	// Given
	want := networkHealthResult{
		Total: 6,
		Ok:    []string{"qq"},
		Targets: []networkHealthTarget{
			{Target: "qq", Ok: true, Duration: 42, StatusCode: http.StatusUnauthorized},
		},
		Timestamp: 456,
	}
	checker := networkHealthChecker{run: func() networkHealthResult { return want }}
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/utils/check_network_health", nil)
	rec := httptest.NewRecorder()

	// When
	err := checker.handle(e.NewContext(req, rec))

	// Then
	if err != nil {
		t.Fatalf("network health handler returned error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("network health status = %d, want %d", rec.Code, http.StatusOK)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode network health response keys: %v", err)
	}
	for _, key := range []string{"result", "total", "ok", "targets", "timestamp"} {
		if _, exists := raw[key]; !exists {
			t.Fatalf("network health response is missing %q: %s", key, rec.Body.String())
		}
	}
	if len(raw) != 5 {
		t.Fatalf("network health response keys = %v, want only result, total, ok, targets, timestamp", raw)
	}
	var body struct {
		Result    bool                  `json:"result"`
		Total     int                   `json:"total"`
		Ok        []string              `json:"ok"`
		Targets   []networkHealthTarget `json:"targets"`
		Timestamp int64                 `json:"timestamp"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode network health response: %v", err)
	}
	if !body.Result || body.Total != want.Total || body.Timestamp != want.Timestamp {
		t.Fatalf("network health response metadata = %#v, want result=true total=%d timestamp=%d", body, want.Total, want.Timestamp)
	}
	if !reflect.DeepEqual(body.Ok, want.Ok) || !reflect.DeepEqual(body.Targets, want.Targets) {
		t.Fatalf("network health response data = %#v, want ok=%#v targets=%#v", body, want.Ok, want.Targets)
	}
}

func TestNetworkHealthCheckerHandleSerializesNoSuccessfulTargetsAsEmptyArray(t *testing.T) {
	checker := networkHealthChecker{
		run: func() networkHealthResult {
			return networkHealthResult{
				Total: 6,
				Targets: []networkHealthTarget{
					{Target: "qq", Ok: false},
					{Target: "kook", Ok: false},
					{Target: "discord", Ok: false},
					{Target: "telegram", Ok: false},
					{Target: "dingtalk", Ok: false},
					{Target: "slack", Ok: false},
				},
			}
		},
	}
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/utils/check_network_health", nil)
	rec := httptest.NewRecorder()

	if err := checker.handle(e.NewContext(req, rec)); err != nil {
		t.Fatalf("network health handler returned error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("network health status = %d, want %d", rec.Code, http.StatusOK)
	}
	var body struct {
		Ok []string `json:"ok"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode network health response: %v", err)
	}
	if body.Ok == nil {
		t.Fatalf("network health ok must be an empty array when no targets pass: %s", rec.Body.String())
	}
	if len(body.Ok) != 0 {
		t.Fatalf("network health ok = %v, want no successful targets", body.Ok)
	}
}

func TestCheckHTTPConnectivityTreatsUnauthorizedResponseAsReachable(t *testing.T) {
	setNetworkHealthTestLogger(t)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	result := checkHTTPConnectivity(networkHealthHTTPClient(http.DefaultTransport), server.URL)
	if !result.Ok {
		t.Fatal("HTTP 401 response must count as network reachable")
	}
	if result.StatusCode != http.StatusUnauthorized {
		t.Fatalf("HTTP status = %d, want %d", result.StatusCode, http.StatusUnauthorized)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("reachable endpoint received %d requests, want no retry after its first HTTP response", got)
	}
	if result.Duration <= 0 {
		t.Fatalf("HTTP response duration = %s, want positive latency", result.Duration)
	}
}

func TestCheckHTTPConnectivityRetriesInitialNetworkFailureOnce(t *testing.T) {
	setNetworkHealthTestLogger(t)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Errorf("hijack initial connection: %v", err)
				return
			}
			_ = connection.Close()
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	result := checkHTTPConnectivity(networkHealthHTTPClient(http.DefaultTransport), server.URL)
	if !result.Ok || result.StatusCode != http.StatusUnauthorized {
		t.Fatalf("retry result = %#v, want reachable HTTP 401", result)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("endpoint received %d requests, want initial failure plus one retry", got)
	}
}

func TestCheckHTTPConnectivityStopsAfterFailedRetry(t *testing.T) {
	setNetworkHealthTestLogger(t)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		connection, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack failing connection: %v", err)
			return
		}
		_ = connection.Close()
	}))
	defer server.Close()

	result := checkHTTPConnectivity(networkHealthHTTPClient(http.DefaultTransport), server.URL)
	if result.Ok || result.StatusCode != 0 {
		t.Fatalf("failed retry result = %#v, want unreachable without an HTTP response", result)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("endpoint received %d requests, want at most two attempts", got)
	}
}

func TestCheckHTTPConnectivityRetryGetsFreshTimeout(t *testing.T) {
	setNetworkHealthTestLogger(t)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			<-r.Context().Done()
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	result := checkHTTPConnectivity(networkHealthHTTPClient(http.DefaultTransport), server.URL)
	if !result.Ok || result.StatusCode != http.StatusUnauthorized {
		t.Fatalf("retry after timeout = %#v, want a fresh attempt reaching HTTP 401", result)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("endpoint received %d requests, want a timeout followed by one retry", got)
	}
}

const telegramBotAPIProbePath = "/bot000000000:INVALID_NETWORK_HEALTH_PROBE/getMe"

func TestCheckHTTPConnectivityDoesNotFollowRedirectToAnotherSite(t *testing.T) {
	setNetworkHealthTestLogger(t)
	var redirectedRequests atomic.Int32
	redirected := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectedRequests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer redirected.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirected.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	result := checkHTTPConnectivity(networkHealthHTTPClient(http.DefaultTransport), source.URL)
	if !result.Ok {
		t.Fatal("HTTP redirect response must count as network reachable")
	}
	if result.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("HTTP status = %d, want %d", result.StatusCode, http.StatusTemporaryRedirect)
	}
	if result.Duration <= 0 {
		t.Fatalf("HTTP response duration = %s, want positive latency", result.Duration)
	}
	if got := redirectedRequests.Load(); got != 0 {
		t.Fatalf("redirect destination received %d requests, want none", got)
	}
}

func TestTelegramNetworkHealthProbeUsesBotAPIInsteadOfWebsiteRedirect(t *testing.T) {
	setNetworkHealthTestLogger(t)
	var websiteRequests atomic.Int32
	var apiRequests atomic.Int32
	var introRequests atomic.Int32

	introduction := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		introRequests.Add(1)
		w.Header().Set("Content-Type", "text/html")
		_, err := w.Write([]byte("<html>Telegram bot introduction</html>"))
		if err != nil {
			t.Errorf("write introduction page: %v", err)
		}
	}))
	defer introduction.Close()

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			websiteRequests.Add(1)
			http.Redirect(w, r, introduction.URL, http.StatusFound)
		case telegramBotAPIProbePath:
			apiRequests.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, err := w.Write([]byte(`{"ok":false,"error_code":401,"description":"Unauthorized: invalid token specified"}`))
			if err != nil {
				t.Errorf("write Bot API response: %v", err)
			}
		default:
			t.Errorf("unexpected Telegram probe path %q", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer api.Close()

	destination, err := url.Parse(api.URL)
	if err != nil {
		t.Fatalf("parse Telegram API test URL: %v", err)
	}
	client := networkHealthHTTPClient(networkHealthTestRoundTripper{
		destination:  destination,
		roundTripper: http.DefaultTransport,
	})

	var endpoint string
	for _, target := range networkHealthTargetSpecs {
		if target.target == "telegram" {
			endpoint = target.url
			break
		}
	}
	if endpoint == "" {
		t.Fatal("Telegram network health target is missing")
	}

	result := checkHTTPConnectivity(client, endpoint)
	if !result.Ok || result.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Telegram API probe result = %#v, want reachable Bot API HTTP 401", result)
	}
	if got := apiRequests.Load(); got != 1 {
		t.Errorf("Bot API received %d requests, want exactly one", got)
	}
	if got := websiteRequests.Load(); got != 0 {
		t.Errorf("Telegram website received %d requests, want none", got)
	}
	if got := introRequests.Load(); got != 0 {
		t.Errorf("Telegram introduction page received %d requests, want none", got)
	}
}

func TestCheckHTTPConnectivityReportsNetworkFailureUnreachable(t *testing.T) {
	setNetworkHealthTestLogger(t)
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := server.URL
	server.Close()

	result := checkHTTPConnectivity(networkHealthHTTPClient(http.DefaultTransport), url)
	if result.Ok {
		t.Fatal("network failure without an HTTP response must be unreachable")
	}
	if result.StatusCode != 0 {
		t.Fatalf("network failure status = %d, want 0 for no HTTP response", result.StatusCode)
	}
	if result.Duration <= 0 {
		t.Fatalf("network failure duration = %s, want positive latency", result.Duration)
	}
}

func TestCheckHTTPConnectivityReportsTimeoutUnreachable(t *testing.T) {
	setNetworkHealthTestLogger(t)
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	result := checkHTTPConnectivity(networkHealthHTTPClient(http.DefaultTransport), server.URL)
	if result.Ok {
		t.Fatal("timeout without an HTTP response must be unreachable")
	}
	if result.StatusCode != 0 {
		t.Fatalf("timeout status = %d, want 0 for no HTTP response", result.StatusCode)
	}
}

func TestRunNetworkHealthCheckKeepsAllTargetsAfterOneNetworkFailure(t *testing.T) {
	setNetworkHealthTestLogger(t)

	statusCodes := map[string]int{
		"api.sgroup.qq.com": http.StatusUnauthorized,
		"www.kookapp.cn":    http.StatusForbidden,
		"api.telegram.org":  http.StatusUnauthorized,
		"api.dingtalk.com":  http.StatusServiceUnavailable,
		"slack.com":         http.StatusTooManyRequests,
	}
	expectedPaths := map[string]string{
		"api.sgroup.qq.com": "/users/@me",
		"www.kookapp.cn":    "/api/v3/channel/view",
		"discord.com":       "/api/v10/gateway",
		"api.telegram.org":  telegramBotAPIProbePath,
		"api.dingtalk.com":  "/v1.0/gateway/connections/open",
		"slack.com":         "/api/api.test",
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("request method = %s, want GET", r.Method)
		}
		if authorization := r.Header.Get("Authorization"); authorization != "" {
			t.Errorf("probe sent Authorization header %q", authorization)
		}
		if got, want := r.URL.Path, expectedPaths[r.Host]; got != want {
			t.Errorf("request path for %s = %q, want %q", r.Host, got, want)
		}
		statusCode, exists := statusCodes[r.Host]
		if !exists {
			t.Errorf("unexpected request host %q", r.Host)
			statusCode = http.StatusInternalServerError
		}
		w.WriteHeader(statusCode)
	}))
	defer server.Close()
	destination, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse local server URL: %v", err)
	}
	client := networkHealthHTTPClient(networkHealthTestRoundTripper{
		destination:  destination,
		failedHost:   "discord.com",
		roundTripper: http.DefaultTransport,
	})

	result := runNetworkHealthCheckWithClient(client)
	wantTargets := []struct {
		target     string
		ok         bool
		statusCode int
	}{
		{target: "qq", ok: true, statusCode: http.StatusUnauthorized},
		{target: "kook", ok: true, statusCode: http.StatusForbidden},
		{target: "discord", ok: false, statusCode: 0},
		{target: "telegram", ok: true, statusCode: http.StatusUnauthorized},
		{target: "dingtalk", ok: true, statusCode: http.StatusServiceUnavailable},
		{target: "slack", ok: true, statusCode: http.StatusTooManyRequests},
	}
	if result.Total != len(wantTargets) {
		t.Fatalf("network health total = %d, want %d", result.Total, len(wantTargets))
	}
	if len(result.Targets) != len(wantTargets) {
		t.Fatalf("network health returned %d targets, want %d: %#v", len(result.Targets), len(wantTargets), result.Targets)
	}
	var wantOK []string
	for i, want := range wantTargets {
		got := result.Targets[i]
		if got.Target != want.target || got.Ok != want.ok || got.StatusCode != want.statusCode {
			t.Errorf("target[%d] = %#v, want target=%q ok=%t statusCode=%d", i, got, want.target, want.ok, want.statusCode)
		}
		if got.Duration <= 0 {
			t.Errorf("target[%d] duration = %s, want positive latency", i, got.Duration)
		}
		if want.ok {
			wantOK = append(wantOK, want.target)
		}
	}
	if !reflect.DeepEqual(result.Ok, wantOK) {
		t.Errorf("successful targets = %v, want %v", result.Ok, wantOK)
	}
}

type networkHealthTestRoundTripper struct {
	destination  *url.URL
	failedHost   string
	roundTripper http.RoundTripper
}

func (transport networkHealthTestRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Host == transport.failedHost {
		return nil, errors.New("test network failure")
	}
	forwarded := request.Clone(request.Context())
	forwardedURL := *request.URL
	forwardedURL.Scheme = transport.destination.Scheme
	forwardedURL.Host = transport.destination.Host
	forwarded.URL = &forwardedURL
	forwarded.Host = request.URL.Host
	return transport.roundTripper.RoundTrip(forwarded)
}

func setNetworkHealthTestLogger(t *testing.T) {
	t.Helper()
	previousDice := myDice
	myDice = &dice.Dice{Logger: zap.NewNop().Sugar()}
	t.Cleanup(func() {
		myDice = previousDice
	})
}
