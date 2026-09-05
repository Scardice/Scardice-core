// Package goja provides the explicit builtin Goja provider registration.
package goja

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

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
		ID:         jsengine.EngineGoja,
		Name:       "Goja",
		Version:    "builtin",
		Language:   "Go",
		Author:     "Scardice",
		Extensions: []string{".js", ".ts"},
		Capabilities: jsengine.CapabilityScript.With(
			jsengine.CapabilityCommonJS,
			jsengine.CapabilityHostObject,
			jsengine.CapabilityHostFunction,
			jsengine.CapabilityContextPropagation,
		),
		Builtin: true,
	}
}

func (provider) Open(_ context.Context, options jsengine.RuntimeOptions) (jsengine.Loop, error) {
	if err := validateOptions(options.PayloadFor(jsengine.EngineGoja)); err != nil {
		return nil, err
	}
	return adapter.New(), nil
}

func validateOptions(raw json.RawMessage) error {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil
	}
	if raw[0] != '{' {
		return fmt.Errorf("goja: unsupported runtime options: expected a JSON object")
	}

	var options map[string]json.RawMessage
	if err := json.Unmarshal(raw, &options); err != nil {
		return fmt.Errorf("goja: unsupported runtime options: invalid JSON: %w", err)
	}
	if len(options) != 0 {
		return fmt.Errorf("goja: unsupported runtime options: Goja has no provider-specific options")
	}
	return nil
}
