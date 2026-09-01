package dice

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"Scardice-core/utils/jsengine"
	builtin "Scardice-core/utils/jsengine/builtin/goja"
	"Scardice-core/utils/jsengine/native"
)

// JSRuntimeStatus is a diagnostic snapshot for one registered JavaScript
// provider. Native candidates are metadata-only until Resolve opens one.
type JSRuntimeStatus struct {
	ID           string   `json:"id"`
	Installed    bool     `json:"installed"`
	Loaded       bool     `json:"loaded"`
	Builtin      bool     `json:"builtin"`
	Version      string   `json:"version"`
	ABI          string   `json:"abi"`
	Path         string   `json:"path"`
	Capabilities []string `json:"capabilities"`
	Error        string   `json:"error,omitempty"`
}

// JSRuntimeManager owns provider discovery and lazy loading for one Dice.
// Builtin Goja is always registered; external providers are discovered from
// runtime packages and are never loaded unless explicitly selected.
type JSRuntimeManager struct {
	mu       sync.RWMutex
	registry jsengine.Registry
	loader   *native.Loader

	providers      map[jsengine.EngineID]jsengine.Provider
	statuses       map[jsengine.EngineID]JSRuntimeStatus
	discoveryError string
}

// NewJSRuntimeManager creates a manager rooted at root. An empty root uses
// SCARDICE_RUNTIME_ROOT, then SCARDICE_QUICKJS_PACKAGE, then the executable's
// runtimes directory. A package directory containing runtime.json is accepted
// as a convenience for focused integration tests.
func NewJSRuntimeManager(root string) *JSRuntimeManager {
	if strings.TrimSpace(root) == "" {
		root = os.Getenv("SCARDICE_RUNTIME_ROOT")
	}
	if strings.TrimSpace(root) == "" {
		root = os.Getenv("SCARDICE_QUICKJS_PACKAGE")
	}
	root = normalizeRuntimeRoot(root)

	registry := jsengine.NewRegistry()
	manager := &JSRuntimeManager{
		registry:  registry,
		loader:    native.NewLoader(root),
		providers: make(map[jsengine.EngineID]jsengine.Provider),
		statuses:  make(map[jsengine.EngineID]JSRuntimeStatus),
	}
	if err := registry.RegisterBuiltin(builtin.Provider()); err != nil {
		manager.statuses[jsengine.EngineGoja] = JSRuntimeStatus{
			ID:    string(jsengine.EngineGoja),
			Error: err.Error(),
		}
	} else {
		manager.providers[jsengine.EngineGoja] = builtin.Provider()
	}
	if err := manager.loader.RegisterCandidates(registry); err != nil {
		manager.discoveryError = err.Error()
	}
	manager.refreshStatuses()
	return manager
}

// NewJSRuntimeManagerForDice installs the application-aware builtin Goja
// provider while keeping external provider discovery identical to the generic
// manager.
func NewJSRuntimeManagerForDice(d *Dice) *JSRuntimeManager {
	manager := NewJSRuntimeManager("")
	manager.providers[jsengine.EngineGoja] = &diceGojaProvider{dice: d}
	return manager
}
func (d *Dice) jsRuntimeManagerInstance() *JSRuntimeManager {
	if d.jsRuntimeManager == nil {
		d.jsRuntimeManager = NewJSRuntimeManagerForDice(d)
	}
	return d.jsRuntimeManager
}

func (d *Dice) disableJSRuntime(err error) {
	(&d.Config).JsEnable = false
	if d.Logger != nil {
		d.Logger.Errorf("JS runtime 初始化失败: %v", err)
	}
}

func normalizeRuntimeRoot(root string) string {
	root = strings.TrimSpace(root)
	if root == "" {
		return root
	}
	manifest := filepath.Join(root, "runtime.json")
	if info, err := os.Stat(manifest); err == nil && !info.IsDir() {
		// A package root may itself contain the runtime package as `quickjs/`
		// (the distribution layout), while an explicitly selected package
		// directory contains the library next to its manifest.
		if info, err := os.Stat(filepath.Join(root, "quickjs", "runtime.json")); err == nil && !info.IsDir() {
			return root
		}
		return filepath.Dir(root)
	}
	return root
}

func (m *JSRuntimeManager) Resolve(ctx context.Context, id jsengine.EngineID, options jsengine.RuntimeOptions) (jsengine.Loop, error) {
	if m == nil {
		return nil, fmt.Errorf("resolve JavaScript runtime %q: %w", id, jsengine.ErrProviderNotFound)
	}
	id = normalizeRequestedEngine(id)

	// Provider discovery and lazy loading mutate shared registry state. Keep
	// the lock through Open so concurrent diagnostics never observe a partial
	// provider registration.
	m.mu.Lock()
	defer m.mu.Unlock()

	provider, err := m.resolveProvider(id)
	if err != nil {
		m.recordError(id, err)
		return nil, fmt.Errorf("resolve JavaScript runtime %q: %w", id, err)
	}
	loop, err := provider.Open(ctx, options)
	if err != nil {
		m.recordError(id, err)
		return nil, fmt.Errorf("open JavaScript runtime %q: %w", id, err)
	}
	status := m.statuses[id]
	status.Loaded = true
	status.Error = ""
	m.statuses[id] = status
	return loop, nil
}

func normalizeRequestedEngine(id jsengine.EngineID) jsengine.EngineID {
	id = jsengine.NormalizeEngineID(string(id))
	if id == "" {
		return jsengine.EngineGoja
	}
	return id
}

func (m *JSRuntimeManager) resolveProvider(id jsengine.EngineID) (jsengine.Provider, error) {
	if provider := m.providers[id]; provider != nil {
		return provider, nil
	}
	if _, err := m.registry.Resolve(id); err != nil {
		// Registry candidates are metadata-only; load the selected candidate on
		// demand and retain the loaded provider for subsequent reloads.
		provider, loadErr := m.loader.Load(string(id))
		if loadErr != nil {
			return nil, loadErr
		}
		m.providers[id] = provider
		m.updateDescriptor(provider.Descriptor(), true)
		return provider, nil
	}
	return nil, fmt.Errorf("%w: engine ID %q is registered without a provider", jsengine.ErrProviderNotFound, id)
}

// Status returns a copy of one provider diagnostic snapshot.
func (m *JSRuntimeManager) Status(id jsengine.EngineID) (JSRuntimeStatus, bool) {
	if m == nil {
		return JSRuntimeStatus{}, false
	}
	id = normalizeRequestedEngine(id)
	m.mu.RLock()
	defer m.mu.RUnlock()
	status, ok := m.statuses[id]
	if !ok {
		return JSRuntimeStatus{ID: string(id)}, false
	}
	status.Capabilities = append([]string(nil), status.Capabilities...)
	return status, true
}

// Statuses returns registration-order provider diagnostics.
func (m *JSRuntimeManager) Statuses() []JSRuntimeStatus {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	descriptors := m.registry.Descriptors()
	statuses := make([]JSRuntimeStatus, 0, len(descriptors))
	for _, descriptor := range descriptors {
		id := normalizeRequestedEngine(descriptor.ID)
		status := m.statuses[id]
		status.Capabilities = append([]string(nil), status.Capabilities...)
		statuses = append(statuses, status)
	}
	return statuses
}

// JSRuntimeStatuses returns provider diagnostics without opening any runtime.
func (d *Dice) JSRuntimeStatuses() []JSRuntimeStatus {
	if d == nil {
		return nil
	}
	return d.jsRuntimeManagerInstance().Statuses()
}

func (m *JSRuntimeManager) refreshStatuses() {
	for _, descriptor := range m.registry.Descriptors() {
		m.updateDescriptor(descriptor, false)
	}
}

func (m *JSRuntimeManager) updateDescriptor(descriptor jsengine.Descriptor, loaded bool) {
	id := normalizeRequestedEngine(descriptor.ID)
	status := m.statuses[id]
	status.ID = string(id)
	status.Installed = descriptor.Builtin || descriptor.Path != ""
	status.Loaded = status.Loaded || loaded
	status.Builtin = descriptor.Builtin
	status.Version = descriptor.Version
	status.ABI = fmt.Sprintf("%d.%d", descriptor.ABIMajor, descriptor.ABIMinor)
	status.Path = descriptor.Path
	status.Capabilities = capabilityNames(descriptor.Capabilities)
	m.statuses[id] = status
}

func (m *JSRuntimeManager) recordError(id jsengine.EngineID, err error) {
	id = normalizeRequestedEngine(id)
	status := m.statuses[id]
	status.ID = string(id)
	if status.Error == "" || !errors.Is(err, native.ErrMissingLibrary) {
		status.Error = err.Error()
	}
	m.statuses[id] = status
}

func capabilityNames(set jsengine.CapabilitySet) []string {
	capabilities := []struct {
		name string
		set  jsengine.CapabilitySet
	}{
		{"script", jsengine.CapabilityScript},
		{"commonjs", jsengine.CapabilityCommonJS},
		{"esm", jsengine.CapabilityESM},
		{"promise", jsengine.CapabilityPromise},
		{"timers", jsengine.CapabilityTimers},
		{"hostObject", jsengine.CapabilityHostObject},
		{"hostFunction", jsengine.CapabilityHostFunction},
		{"asyncHostService", jsengine.CapabilityAsyncHostService},
		{"sourceLocation", jsengine.CapabilitySourceLocation},
	}
	result := make([]string, 0, len(capabilities))
	for _, capability := range capabilities {
		if set.Has(capability.set) {
			result = append(result, capability.name)
		}
	}
	return result
}
