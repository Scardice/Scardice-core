package emitter

import (
	"errors"
	"strings"
	"testing"

	"Scardice-core/adapterapi"
)

func TestRawJSONRejectsInvalidRequestsBeforeTransport(t *testing.T) {
	prefix, suffix := `{"action":"vendor.call","params":{"text":"`, `"}}`
	atInputLimit := prefix + strings.Repeat("x", adapterapi.MaxProtocolJSONBytes-len(prefix)-len(suffix)) + suffix
	escapingExpansion := prefix + strings.Repeat("<", adapterapi.MaxProtocolJSONBytes/5) + suffix
	for _, test := range []struct {
		name, raw string
	}{
		{"non-object", `[]`},
		{"missing-action", `{"params":{}}`},
		{"blank-action", `{"action":" "}`},
		{"echo-expansion", atInputLimit},
		{"escaping-expansion", escapingExpansion},
	} {
		t.Run(test.name, func(t *testing.T) {
			// No connection exists: validation must classify the input before I/O.
			_, err := (&emitterSocket{}).RawJSON(t.Context(), []byte(test.raw))
			if !errors.Is(err, ErrInvalidRawRequest) || !errors.Is(err, adapterapi.ErrInvalidContract) {
				t.Fatalf("request error = %v, want deterministic invalid-request classification", err)
			}
		})
	}
}
