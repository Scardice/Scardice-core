package jsengine

import "context"

// RuntimeOptions controls creation of a runtime loop. It is intentionally
// engine-neutral; providers may add options in later, provider-owned layers.
type RuntimeOptions struct{}

// Provider describes and opens one JavaScript runtime implementation.
type Provider interface {
	Descriptor() Descriptor
	Open(context.Context, RuntimeOptions) (Loop, error)
}
