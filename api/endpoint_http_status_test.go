package api

import (
	"errors"
	"testing"

	"Scardice-core/adapterapi"
	"Scardice-core/endpoint"
)

func TestPureEndpointHTTPStatus(t *testing.T) {
	cases := []struct { name string; err error; want int }{
		{"invalid config", adapterapi.ErrInvalidConfig, 400},
		{"conflict", endpoint.ErrCommandConflict, 409},
		{"stale", endpoint.ErrStaleExpectedVersion, 409},
		{"missing", endpoint.ErrNotFound, 404},
		{"infrastructure", errors.New("database unavailable"), 503},
	}
	for _, tc := range cases { t.Run(tc.name, func(t *testing.T) { if got := pureEndpointHTTPStatus(tc.err); got != tc.want { t.Fatalf("status = %d, want %d", got, tc.want) } }) }
}
