package dice

import (
	"context"

	"Scardice-core/adapterapi"
)

// ProviderCallPort is the supervisor-owned immediate protocol call boundary.
// It is deliberately separate from read-only ProviderQuery and durable outbox.
type ProviderCallPort interface {
	CallAPI(context.Context, adapterapi.AdapterCallRequest) (adapterapi.AdapterCallResult, error)
}
