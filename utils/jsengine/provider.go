package jsengine

import (
	"context"
	"encoding/json"
)

// RuntimeOptions carries provider-specific creation payloads in namespaces.
// Providers must read only the payload under their normalized EngineID.
type RuntimeOptions struct {
	Providers map[EngineID]json.RawMessage
}

// PayloadFor returns the payload owned by provider id.
func (o RuntimeOptions) PayloadFor(id EngineID) json.RawMessage {
	if len(o.Providers) == 0 {
		return nil
	}
	return o.Providers[NormalizeEngineID(string(id))]
}

// Provider describes and opens one JavaScript runtime implementation.
type Provider interface {
	Descriptor() Descriptor
	Open(context.Context, RuntimeOptions) (Loop, error)
}
