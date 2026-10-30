package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"

	"Scardice-core/dice"
	"Scardice-core/endpoint"
	"Scardice-core/eventstore"
)

const activityTestToken = "activity-session-secret"

type activityTestItem struct {
	ID         string `json:"id"`
	OccurredAt int64  `json:"occurredAt"`
	Action     string `json:"action"`
	Label      string `json:"label"`
	Resource   string `json:"resource"`
	Status     string `json:"status"`
	HTTPStatus int    `json:"httpStatus"`
	Actor      string `json:"actor"`
	SourceIP   string `json:"sourceIP"`
}

type activityTestResponse struct {
	Result    bool               `json:"result"`
	Items     []activityTestItem `json:"items"`
	Timestamp int64              `json:"timestamp"`
	Message   string             `json:"message"`
}

type activityAPIFixture struct {
	dsn       string
	db        *eventstore.Database
	store     *eventstore.GORMStore
	service   *endpoint.Service
	manager   *dice.DiceManager
	runtime   *dice.Dice
	databases []*eventstore.Database
}

func newActivityAPIFixture(t *testing.T) *activityAPIFixture {
	t.Helper()
	t.Setenv("SCARDICE_ADMIN_TOKEN", "activity-admin-secret")
	t.Setenv("SCARDICE_ADMIN_PRINCIPAL_ID", "activity-admin-principal")
	t.Setenv("SCARDICE_ADMIN_ORIGINS", "")
	ResetAdminAuthForTests()

	previousDice, previousManager := myDice, dm
	fixture := &activityAPIFixture{dsn: filepath.Join(t.TempDir(), "activity-events.db")}
	t.Cleanup(func() {
		registerEndpointApplication(nil)
		myDice, dm = previousDice, previousManager
		ResetAdminAuthForTests()
		for _, database := range fixture.databases {
			_ = database.Close()
		}
	})
	fixture.openDatabase(t)

	registry := endpoint.NewRegistry()
	if err := registry.Register(endpointAPIDescriptor{}); err != nil {
		t.Fatal(err)
	}
	fixture.service = endpoint.NewService(fixture.store, registry)
	if fixture.service.InitError != nil {
		t.Fatal(fixture.service.InitError)
	}
	registerEndpointApplication(&endpointAPITestApplication{service: fixture.service})

	fixture.manager = &dice.DiceManager{}
	fixture.manager.AccessTokens.Store(activityTestToken, true)
	fixture.runtime = &dice.Dice{
		BaseConfig:   dice.BaseConfig{Name: "activity-api-test"},
		Parent:       fixture.manager,
		DurableStore: fixture.store,
		Logger:       zap.NewNop().Sugar(),
	}
	fixture.manager.Dice = []*dice.Dice{fixture.runtime}
	fixture.manager.AccessTokens.Store("api-test-ui-session", true)
	myDice, dm = fixture.runtime, fixture.manager
	return fixture
}

func (f *activityAPIFixture) openDatabase(t *testing.T) {
	t.Helper()
	database, err := eventstore.OpenDatabase(context.Background(), eventstore.DatabaseConfig{
		Type: "sqlite", DSN: f.dsn, KeySource: endpointAPITestKeySource{}, DatabaseIdentity: "activity-api-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	f.databases = append(f.databases, database)
	f.db = database
	f.store = eventstore.NewStore(database)
}

func (f *activityAPIFixture) bind() *echo.Echo {
	f.runtime.DurableStore = f.store
	f.manager.Dice = []*dice.Dice{f.runtime}
	e := echo.New()
	e.HideBanner = true
	Bind(e, f.manager)
	return e
}

func activityRequest(e *echo.Echo, method, path, body, remoteAddr, token string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.RemoteAddr = remoteAddr
	if token != "" {
		request.Header.Set("Token", token)
	}
	request.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	e.ServeHTTP(recorder, request)
	return recorder
}

func decodeActivityResponse(t *testing.T, response *httptest.ResponseRecorder) activityTestResponse {
	t.Helper()
	var result activityTestResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode activity response (status %d): %v; body=%s", response.Code, err, response.Body.String())
	}
	return result
}

func TestActivityCaptureHTTPAuthClassificationIPPrivacyAndReopen(t *testing.T) {
	fixture := newActivityAPIFixture(t)
	e := fixture.bind()

	// Activity listing is protected with the same UI session auth as the legacy
	// management routes. Neither an anonymous write attempt nor an authenticated
	// read-only preview belongs in this feed.
	if got := activityRequest(e, http.MethodGet, "/sd-api/activity/recent", "", "192.0.2.5:4000", ""); got.Code != http.StatusForbidden {
		t.Fatalf("anonymous activity list status=%d body=%s", got.Code, got.Body.String())
	}
	empty := activityRequest(e, http.MethodGet, "/sd-api/activity/recent", "", "192.0.2.5:4000", activityTestToken)
	if empty.Code != http.StatusOK || !strings.Contains(empty.Body.String(), `"items":[]`) {
		t.Fatalf("empty activity response must expose an empty array: status=%d body=%s", empty.Code, empty.Body.String())
	}
	if got := activityRequest(e, http.MethodPost, "/sd-api/dice/public/set", `{"config":{},"selected":[]}`, "192.0.2.5:4000", ""); got.Code != http.StatusForbidden {
		t.Fatalf("anonymous mutation status=%d body=%s", got.Code, got.Body.String())
	}
	if got := activityRequest(e, http.MethodPost, "/sd-api/configs/customText/preview-refresh", `{}`, "192.0.2.5:4000", activityTestToken); got.Code != http.StatusOK {
		t.Fatalf("authenticated preview status=%d body=%s", got.Code, got.Body.String())
	}

	// The actual registered API handler produces HTTP 200 with result:false on
	// malformed business input. That remains a failed operation, without its
	// body/error details being retained. A successful mutation must be captured
	// independently of its request/response data.
	requestSecret := "activity-request-private-value"
	querySecret := "activity-query-private-value"
	forwardedSpoof := "203.0.113.77"
	failure := httptest.NewRecorder()
	failureRequest := httptest.NewRequest(http.MethodPost,
		"/sd-api/dice/public/set?ignored="+querySecret,
		strings.NewReader(`{"config":"`+requestSecret+`"}`))
	failureRequest.RemoteAddr = "198.51.100.21:4321"
	failureRequest.Header.Set("Token", activityTestToken)
	failureRequest.Header.Set("X-Forwarded-For", forwardedSpoof)
	failureRequest.Header.Set("X-Real-IP", "203.0.113.78")
	failureRequest.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	e.ServeHTTP(failure, failureRequest)
	if failure.Code != http.StatusOK {
		t.Fatalf("business failure status=%d body=%s", failure.Code, failure.Body.String())
	}
	failureBody := decodeActivityResponse(t, failure)
	if failureBody.Result {
		t.Fatalf("malformed public settings were not reported as a business failure: %s", failure.Body.String())
	}

	success := activityRequest(e, http.MethodPost, "/sd-api/dice/public/set?ignored="+querySecret,
		`{"config":{},"selected":[]}`, "198.51.100.21:4321", activityTestToken)
	if success.Code != http.StatusOK {
		t.Fatalf("successful mutation status=%d body=%s", success.Code, success.Body.String())
	}

	// HTTP errors on recognized mutations remain failed even without a
	// result:false body. The invalid runtime choice is not retained.
	httpFailure := activityRequest(e, http.MethodPost, "/sd-api/js/runtime/config",
		`{"defaultRuntime":"activity-uninstalled-runtime"}`, "198.51.100.21:4321", activityTestToken)
	if httpFailure.Code != http.StatusBadRequest {
		t.Fatalf("invalid runtime config status=%d body=%s", httpFailure.Code, httpFailure.Body.String())
	}
	// A real authenticated asynchronous management endpoint returns HTTP 202;
	// it must be reported as accepted rather than completed success.
	acceptedBody := `{"adapterKey":"fake","config":{"version":1,"payload":{"channel":"activity-test"}}}`
	accepted := httptest.NewRecorder()
	acceptedRequest := httptest.NewRequest(http.MethodPost, "/sd-api/endpoints", strings.NewReader(acceptedBody))
	acceptedRequest.RemoteAddr = "[2001:db8:1234:5678:90ab:cdef:1234:5678]:7711"
	acceptedRequest.Header.Set(echo.HeaderAuthorization, "Bearer api-test-ui-session")
	acceptedRequest.Header.Set("Idempotency-Key", "activity-capture-create")
	acceptedRequest.Header.Set("X-Forwarded-For", "2001:db8::bad")
	acceptedRequest.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	e.ServeHTTP(accepted, acceptedRequest)
	if accepted.Code != http.StatusAccepted {
		t.Fatalf("accepted endpoint mutation status=%d body=%s", accepted.Code, accepted.Body.String())
	}

	listRecorder := activityRequest(e, http.MethodGet, "/sd-api/activity/recent?limit=10&ignored="+querySecret, "", "192.0.2.5:4000", activityTestToken)
	if listRecorder.Code != http.StatusOK {
		t.Fatalf("recent activity status=%d body=%s", listRecorder.Code, listRecorder.Body.String())
	}
	list := decodeActivityResponse(t, listRecorder)
	if list.Timestamp <= 0 {
		t.Fatalf("activity envelope timestamp is not Unix milliseconds: %#v", list)
	}
	if !list.Result || len(list.Items) != 4 {
		t.Fatalf("recent activity result=%v items=%d body=%s", list.Result, len(list.Items), listRecorder.Body.String())
	}
	if list.Items[0].Status != "accepted" || list.Items[0].HTTPStatus != http.StatusAccepted || list.Items[0].Resource != "/sd-api/endpoints" {
		t.Fatalf("HTTP 202 operation was not represented as accepted: %#v", list.Items[0])
	}
	if list.Items[1].Status != "failed" || list.Items[1].HTTPStatus != http.StatusBadRequest || list.Items[1].Resource != "/sd-api/js/runtime/config" {
		t.Fatalf("HTTP error operation was not represented as failed: %#v", list.Items[1])
	}
	if list.Items[2].Status != "succeeded" || list.Items[2].HTTPStatus != http.StatusOK || list.Items[2].Resource != "/sd-api/dice/public/set" {
		t.Fatalf("successful management operation mismatch: %#v", list.Items[2])
	}
	if list.Items[3].Status != "failed" || list.Items[3].HTTPStatus != http.StatusOK || list.Items[3].Resource != "/sd-api/dice/public/set" {
		t.Fatalf("HTTP 200 business failure was not represented as failed: %#v", list.Items[3])
	}
	if list.Items[2].SourceIP != "198.51.100.21" || list.Items[3].SourceIP != "198.51.100.21" {
		t.Fatalf("IPv4 source IP trusted forwarded headers or retained port: %#v", list.Items)
	}
	if list.Items[0].SourceIP != "2001:db8:1234:5678:90ab:cdef:1234:5678" {
		t.Fatalf("IPv6 source IP was not preserved in full: %q", list.Items[0].SourceIP)
	}
	for _, item := range list.Items {
		if item.ID == "" || item.OccurredAt <= 0 || item.Action == "" || item.Label == "" || item.Actor == "" || item.SourceIP == "" {
			t.Fatalf("required activity metadata missing: %#v", item)
		}
		if item.Resource != "/sd-api/endpoints" && item.Resource != "/sd-api/dice/public/set" && item.Resource != "/sd-api/js/runtime/config" {
			t.Fatalf("resource was not canonical: %#v", item)
		}
	}
	serialized := listRecorder.Body.String()
	for _, secret := range []string{activityTestToken, "api-test-ui-session", "activity-admin-secret", requestSecret, querySecret, "activity-test", "activity-uninstalled-runtime", "203.0.113.77", "203.0.113.78", "2001:db8::bad"} {
		if strings.Contains(serialized, secret) {
			t.Fatalf("activity feed retained secret/private request data %q: %s", secret, serialized)
		}
	}

	// The consumer limit is bounded and newest-first, with stable order across
	// repeated reads. A smaller requested limit returns only the newest rows.
	limitedRecorder := activityRequest(e, http.MethodGet, "/sd-api/activity/recent?limit=2", "", "192.0.2.5:4000", activityTestToken)
	limited := decodeActivityResponse(t, limitedRecorder)
	if len(limited.Items) != 2 || limited.Items[0].ID != list.Items[0].ID || limited.Items[1].ID != list.Items[1].ID {
		t.Fatalf("limit=2 did not return newest items: full=%#v limited=%#v", list.Items, limited.Items)
	}
	for index := range len(list.Items) - 1 {
		if list.Items[index].OccurredAt < list.Items[index+1].OccurredAt {
			t.Fatalf("activity list is not newest-first: %#v", list.Items)
		}
	}

	// Closing and reopening the existing event database must preserve the real
	// feed for a separately rebound client/API instance.
	if err := fixture.db.Close(); err != nil {
		t.Fatal(err)
	}
	fixture.openDatabase(t)
	reopened := fixture.bind()
	reopenedRecorder := activityRequest(reopened, http.MethodGet, "/sd-api/activity/recent?limit=10", "", "192.0.2.5:4000", activityTestToken)
	if reopenedRecorder.Code != http.StatusOK {
		t.Fatalf("activity listing after reopen status=%d body=%s", reopenedRecorder.Code, reopenedRecorder.Body.String())
	}
	reopenedItems := decodeActivityResponse(t, reopenedRecorder).Items
	if len(reopenedItems) != len(list.Items) {
		t.Fatalf("activity records did not survive database reopen: before=%d after=%d", len(list.Items), len(reopenedItems))
	}
	for index := range list.Items {
		if list.Items[index] != reopenedItems[index] {
			t.Fatalf("reopened activity item[%d] changed: before=%#v after=%#v", index, list.Items[index], reopenedItems[index])
		}
	}
}

func TestActivityRecentDefaultAndMaximumLimit(t *testing.T) {
	fixture := newActivityAPIFixture(t)
	e := fixture.bind()
	for index := range 105 {
		body := `{"config":{},"selected":[{"id":"activity-group-` + strconv.Itoa(index) + `"}]}`
		response := activityRequest(e, http.MethodPost, "/sd-api/dice/public/set", body, "198.51.100.8:8181", activityTestToken)
		if response.Code != http.StatusOK {
			t.Fatalf("mutation %d status=%d body=%s", index, response.Code, response.Body.String())
		}
	}

	defaultResponse := activityRequest(e, http.MethodGet, "/sd-api/activity/recent", "", "198.51.100.8:8181", activityTestToken)
	defaultItems := decodeActivityResponse(t, defaultResponse).Items
	if len(defaultItems) != 20 {
		t.Fatalf("default activity limit got %d items, want 20", len(defaultItems))
	}
	for index := range len(defaultItems) - 1 {
		if defaultItems[index].OccurredAt < defaultItems[index+1].OccurredAt {
			t.Fatalf("activity items were not newest-first at index %d: %d then %d", index, defaultItems[index].OccurredAt, defaultItems[index+1].OccurredAt)
		}
	}

	maximumResponse := activityRequest(e, http.MethodGet, "/sd-api/activity/recent?limit=1000", "", "198.51.100.8:8181", activityTestToken)
	maximumItems := decodeActivityResponse(t, maximumResponse).Items
	if len(maximumItems) != 100 {
		t.Fatalf("requested limit above maximum should return 100 records, got %d", len(maximumItems))
	}
}

func TestActivityCaptureReportedBusinessFailures(t *testing.T) {
	for _, test := range []struct {
		name, path, body, status string
		jsRuntime                bool
	}{
		{"reply_creation_rejected", "/sd-api/configs/custom_reply/file_new", `{"filename":""}`, "failed", false},
		{"unsupported_vm_setting", "/sd-api/dice/config/vm-version-set", `[{"type":"unsupported","value":"v2"}]`, "failed", false},
		{"script_exception", "/sd-api/js/execute", `{"value":"throw new Error('activity-test-error');"}`, "failed", true},
		{"script_success", "/sd-api/js/execute", `{"value":"return 42;"}`, "succeeded", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newActivityAPIFixture(t)
			if test.jsRuntime {
				runtime, _ := newJSExecDice(t)
				fixture.runtime, fixture.manager = runtime, runtime.Parent
				fixture.manager.AccessTokens.Store(activityTestToken, true)
			}
			e := fixture.bind()
			response := activityRequest(e, http.MethodPost, test.path, test.body, "198.51.100.10:4321", activityTestToken)
			if response.Code != http.StatusOK {
				t.Fatalf("management response status=%d body=%s", response.Code, response.Body.String())
			}
			var body struct {
				Success   *bool    `json:"success"`
				Result    bool     `json:"result"`
				Err       *string  `json:"err"`
				FailTypes []string `json:"failTypes"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			switch test.name {
			case "reply_creation_rejected":
				if body.Success == nil || *body.Success {
					t.Fatalf("reply rejection missing: %s", response.Body.String())
				}
			case "unsupported_vm_setting":
				if !body.Result || len(body.FailTypes) != 1 || body.FailTypes[0] != "unsupported" {
					t.Fatalf("VM rejection missing: %s", response.Body.String())
				}
			case "script_exception":
				if !body.Result || body.Err == nil || *body.Err == "" {
					t.Fatalf("script failure missing: %s", response.Body.String())
				}
			case "script_success":
				if !body.Result || body.Err != nil {
					t.Fatalf("script did not succeed: %s", response.Body.String())
				}
			}
			list := decodeActivityResponse(t, activityRequest(e, http.MethodGet, "/sd-api/activity/recent", "", "198.51.100.10:4321", activityTestToken))
			if len(list.Items) != 1 || list.Items[0].Status != test.status || list.Items[0].Resource != test.path {
				t.Fatalf("operation status must be %q for %s, got %#v", test.status, test.path, list.Items)
			}
		})
	}
}
