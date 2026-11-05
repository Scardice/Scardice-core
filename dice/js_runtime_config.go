package dice

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"Scardice-core/utils/jsengine"
)

var ErrInvalidJSRuntimeConfig = errors.New("invalid JavaScript runtime configuration")

// SetJSRuntimeConfig validates and persists the default and package-specific
// runtime choices without opening any provider.
func (d *Dice) SetJSRuntimeConfig(ctx context.Context, defaultRuntime string, extensionRoutes map[string]string) error {
	if d == nil {
		return fmt.Errorf("%w: Dice is unavailable", ErrInvalidJSRuntimeConfig)
	}
	manager := d.jsRuntimeManagerInstance()
	defaultID := jsengine.NormalizeEngineID(defaultRuntime)
	if defaultID == "" {
		defaultID = jsengine.EngineGoja
	}
	if status, ok := manager.Status(defaultID); !ok || !status.Installed {
		return fmt.Errorf("%w: runtime %q is not installed", ErrInvalidJSRuntimeConfig, defaultID)
	}
	pending, err := d.JSRuntimePendingChanges()
	if err != nil {
		return err
	}
	pendingUninstalls := make(map[string]struct{}, len(pending))
	for _, change := range pending {
		if change.Action == jsRuntimeActionUninstall {
			pendingUninstalls[change.ID] = struct{}{}
		}
	}
	if _, ok := pendingUninstalls[string(defaultID)]; ok {
		return fmt.Errorf("%w: runtime %q has a pending uninstall", ErrInvalidJSRuntimeConfig, defaultID)
	}
	routes := make(map[string]string, len(extensionRoutes))
	for extensionID, runtimeID := range extensionRoutes {
		if extensionID == "" || len(extensionID) > 255 || strings.TrimSpace(extensionID) != extensionID {
			return fmt.Errorf("%w: invalid extension package ID %q", ErrInvalidJSRuntimeConfig, extensionID)
		}
		runtimeID = strings.TrimSpace(runtimeID)
		if runtimeID == "" {
			continue
		}
		id := jsengine.NormalizeEngineID(runtimeID)
		if id == "" {
			return fmt.Errorf("%w: invalid runtime ID for extension %q", ErrInvalidJSRuntimeConfig, extensionID)
		}
		if status, ok := manager.Status(id); !ok || !status.Installed {
			return fmt.Errorf("%w: runtime %q for extension %q is not installed", ErrInvalidJSRuntimeConfig, id, extensionID)
		}
		if _, ok := pendingUninstalls[string(id)]; ok {
			return fmt.Errorf("%w: runtime %q for extension %q has a pending uninstall", ErrInvalidJSRuntimeConfig, id, extensionID)
		}
		routes[extensionID] = string(id)
	}
	if len(routes) == 0 {
		routes = nil
	}
	updated, _ := d.ConfigEditSnapshot()
	updated.JsEngine = string(defaultID)
	updated.JsRuntimeRoutes = routes
	return d.DurableCommitConfigSnapshot(ctx, updated, updated.CommandPrefix, updated.DiceMasters, nil)
}

// JSRuntimeConfig returns a consistent copy of the runtime routing settings.
func (d *Dice) JSRuntimeConfig() (string, map[string]string) {
	if d == nil {
		return string(jsengine.EngineGoja), nil
	}
	view := d.Config()
	if view == nil {
		return string(jsengine.EngineGoja), nil
	}
	return string(d.configuredJSEngine()), cloneJSRuntimeRoutes(view.JsRuntimeRoutes)
}
