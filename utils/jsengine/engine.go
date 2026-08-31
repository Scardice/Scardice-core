// Package jsengine defines the JavaScript runtime abstractions used by Dice.
package jsengine

import (
	"fmt"
	"strings"
)

// EngineID identifies a JavaScript engine implementation.
type EngineID string

const (
	// EngineGoja is the established default runtime.
	EngineGoja EngineID = "goja"
	// EngineQuickJS selects the buke/quickjs-go runtime.
	EngineQuickJS EngineID = "quickjs"
)

// NormalizeEngineID trims surrounding whitespace and applies the registry's
// canonical lower-case spelling.
func NormalizeEngineID(raw string) EngineID {
	return EngineID(strings.ToLower(strings.TrimSpace(raw)))
}

// ParseEngineID validates a configured engine identifier. An empty value keeps
// persisted configurations from before engine selection on the Goja runtime.
//
// This legacy parser remains intentionally compatible with existing callers;
// provider discovery and resolution are owned by Registry.
func ParseEngineID(raw string) (EngineID, error) {
	switch id := NormalizeEngineID(raw); id {
	case "", EngineGoja:
		return EngineGoja, nil
	case EngineQuickJS:
		return EngineQuickJS, nil
	default:
		return "", fmt.Errorf("unsupported JavaScript engine %q", raw)
	}
}
