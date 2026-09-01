// Package jsengine defines the JavaScript runtime abstractions used by Dice.
package jsengine

import "strings"

// EngineID identifies a JavaScript engine implementation.
type EngineID string

const (
	// EngineGoja is the established default runtime.
	EngineGoja EngineID = "goja"
)

// NormalizeEngineID trims surrounding whitespace and applies the registry's
// canonical lower-case spelling.
func NormalizeEngineID(raw string) EngineID {
	return EngineID(strings.ToLower(strings.TrimSpace(raw)))
}
