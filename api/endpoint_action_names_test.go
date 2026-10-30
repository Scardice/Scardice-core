package api

import (
	"testing"

	"Scardice-core/adapterapi"
)

// An endpoint reports the actions it supports by name; an action without a
// name would surface to clients as an empty string.
func TestEveryAdapterActionHasAUniqueExternalName(t *testing.T) {
	seen := map[string]adapterapi.ActionKind{}
	for kind := adapterapi.ActionKind(1); kind.Valid(); kind++ {
		name := actionName(kind)
		if name == "" {
			t.Errorf("action kind %d has no external name", kind)
			continue
		}
		if previous, duplicate := seen[name]; duplicate {
			t.Errorf("action kinds %d and %d share the name %q", previous, kind, name)
		}
		seen[name] = kind
	}
	if len(seen) == 0 {
		t.Fatal("no action kinds were enumerated")
	}
}
