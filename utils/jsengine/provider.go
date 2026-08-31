package jsengine

import (
	"context"
	"encoding/json"
)

// RuntimeOptions controls creation of a runtime loop. OptionsJSON is an
// optional engine-neutral JSON payload forwarded to the selected provider.
// Providers decide which options they support.
type RuntimeOptions struct {
	OptionsJSON json.RawMessage
}

// Provider describes and opens one JavaScript runtime implementation.
type Provider interface {
	Descriptor() Descriptor
	Open(context.Context, RuntimeOptions) (Loop, error)
}
