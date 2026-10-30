package adapterapi

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
)

const MaxProtocolJSONBytes = 256 * 1024

// ValidateProtocolJSON checks the transport envelope without interpreting or
// rewriting provider-specific fields. Strings preserve exact JSON in durable DTOs.
func ValidateProtocolJSON(raw string) error {
	if len(raw) == 0 || len(raw) > MaxProtocolJSONBytes || !utf8.ValidString(raw) {
		return fmt.Errorf("%w: protocol JSON size or encoding", ErrInvalidContract)
	}
	trimmed := strings.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' || !json.Valid([]byte(raw)) {
		return fmt.Errorf("%w: protocol JSON must be an object", ErrInvalidContract)
	}
	return nil
}

// AdapterEvent accompanies a normalized fact, or travels through the optional
// endpoint-only port when there is no conversation. API responses are not events.
type AdapterEvent struct {
	Protocol string `json:"protocol"`
	Type     string `json:"type"`
	RawJSON  string `json:"rawJson"`
}

func (event AdapterEvent) Validate() error {
	if !validOptionalIdentifier(event.Protocol) || event.Protocol == "" ||
		!validOptionalIdentifier(event.Type) || event.Type == "" {
		return fmt.Errorf("%w: adapter event protocol or type", ErrInvalidContract)
	}
	return ValidateProtocolJSON(event.RawJSON)
}

// AdapterEventCorePort is optional. Endpoint-only events are ephemeral and do
// not fabricate conversation/player state merely to enter the durable inbox.
type AdapterEventCorePort interface {
	HandleAdapterEvent(ctx context.Context, event AdapterEvent) (IngressReceipt, error)
}

// AdapterCallRequest is an immediate protocol call, not a read-only query or a
// durable effect. Zero Generation selects the current worker; Supervisor fences
// nonzero generations. Calls are never automatically retried.
type AdapterCallRequest struct {
	EndpointID EndpointID
	Generation uint64
	RawJSON    string
}

func (request AdapterCallRequest) Validate() error {
	if !request.EndpointID.Valid() {
		return fmt.Errorf("%w: protocol call endpoint", ErrInvalidContract)
	}
	return ValidateProtocolJSON(request.RawJSON)
}

type AdapterCallResult struct {
	RawJSON string
}

func (result AdapterCallResult) Validate() error {
	return ValidateProtocolJSON(result.RawJSON)
}

// AdapterCallRuntime is implemented by adapters which support native requests.
// Protocol-level failures remain responses; transport/lifecycle failures are errors.
type AdapterCallRuntime interface {
	CallAPI(ctx context.Context, request AdapterCallRequest) (AdapterCallResult, error)
}
