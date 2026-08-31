// Package goja provides the explicit builtin Goja provider registration.
package goja

import (
	"context"

	"Scardice-core/utils/jsengine"
	adapter "Scardice-core/utils/jsengine/goja"
)

type provider struct{}

// Provider returns the builtin Goja provider. The core registry deliberately
// does not import this package; applications register it explicitly.
func Provider() jsengine.Provider {
	return provider{}
}

func (provider) Descriptor() jsengine.Descriptor {
	return jsengine.Descriptor{
		ID:      jsengine.EngineGoja,
		Name:    "Goja",
		Version: "builtin",
		Language: "Go",
		Capabilities: jsengine.CapabilityScript.With(
			jsengine.CapabilityCommonJS,
			jsengine.CapabilityHostObject,
			jsengine.CapabilityHostFunction,
		),
		Builtin: true,
	}
}

func (provider) Open(_ context.Context, _ jsengine.RuntimeOptions) (jsengine.Loop, error) {
	return adapter.New(), nil
}
