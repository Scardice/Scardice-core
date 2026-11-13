package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestNetworkHealthCheckerKeepsSharedCheckRunningWhenOverlappingWaiterCanceled(t *testing.T) {
	// Given
	var calls atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	want := networkHealthResult{
		Total:     1,
		Ok:        []string{"seal"},
		Targets:   []networkHealthTarget{{Target: "seal", Ok: true}},
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
		Total:     5,
		Ok:        []string{"seal"},
		Targets:   []networkHealthTarget{{Target: "seal", Ok: true, Duration: 42}},
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
