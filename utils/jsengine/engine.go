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

// ParseEngineID validates a configured engine identifier. An empty value keeps
// persisted configurations from before engine selection on the Goja runtime.
func ParseEngineID(raw string) (EngineID, error) {
	switch EngineID(strings.TrimSpace(raw)) {
	case "", EngineGoja:
		return EngineGoja, nil
	case EngineQuickJS:
		return EngineQuickJS, nil
	default:
		return "", fmt.Errorf("unsupported JavaScript engine %q", raw)
	}
}
