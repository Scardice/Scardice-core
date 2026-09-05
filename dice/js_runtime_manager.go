package dice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	Author       string   `json:"author"`
	ABI          string   `json:"abi"`
	Path         string   `json:"path"`
	Capabilities []string `json:"capabilities"`
	Extensions   []string `json:"extensions"`
	Error        string   `json:"error,omitempty"`
}

// JSRuntimeManager owns provider discovery and lazy loading for one Dice.
// Builtin Goja is always registered; external providers are loaded on explicit
// selection or when their declared suffix wins automatic script routing.
type JSRuntimeManager struct {
	mu       sync.RWMutex
	registry jsengine.Registry
	loader   *native.Loader

	providers      map[jsengine.EngineID]jsengine.Provider
	statuses       map[jsengine.EngineID]JSRuntimeStatus
	discoveryError string
	requirements   jsengine.RuntimeRequirements
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
// manager. It also installs Dice's host admission profile, which is stricter
// than the generic engine-neutral provider contract.
func NewJSRuntimeManagerForDice(d *Dice) *JSRuntimeManager {
	manager := NewJSRuntimeManager("")
	manager.providers[jsengine.EngineGoja] = &diceGojaProvider{dice: d}
	manager.requirements = jsengine.RuntimeRequirements{
		RequiredCapabilities: jsengine.CapabilityScript |
			jsengine.CapabilityHostObject |
			jsengine.CapabilityHostFunction,
		RequireContextPropagation: true,
	}
	return manager
}
func (d *Dice) jsRuntimeManagerInstance() *JSRuntimeManager {
	if d.jsRuntimeManager == nil {
		d.jsRuntimeManager = NewJSRuntimeManagerForDice(d)
	}
	return d.jsRuntimeManager
}

// scriptMetadataCacheKey binds parsed metadata to provider order, identity and
// library availability. Installing a previously missing library also invalidates
// metadata parsed by a fallback provider.
func (m *JSRuntimeManager) scriptMetadataCacheKey() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	digest := sha256.New()
	encoder := json.NewEncoder(digest)
	for _, descriptor := range m.registry.Descriptors() {
		_ = encoder.Encode(descriptor)
		if descriptor.Path == "" {
			continue
		}
		if info, err := os.Stat(descriptor.Path); err == nil {
			_ = encoder.Encode([]int64{info.Size(), info.ModTime().UnixNano(), int64(info.Mode())})
		} else {
			_ = encoder.Encode(err.Error())
		}
	}
	return hex.EncodeToString(digest.Sum(nil))
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
	descriptor := provider.Descriptor()
	if err := m.requirements.ValidateDescriptor(descriptor); err != nil {
		m.recordError(id, err)
		return nil, fmt.Errorf("admit JavaScript runtime %q: %w", id, err)
	}
	loop, err := provider.Open(ctx, options)
	if err != nil {
		m.recordError(id, err)
		return nil, fmt.Errorf("open JavaScript runtime %q: %w", id, err)
	}
	if err := m.requirements.ValidateLoop(loop); err != nil {
		_ = loop.Close()
		m.recordError(id, err)
		return nil, fmt.Errorf("admit JavaScript runtime %q loop: %w", id, err)
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

type scriptRuntimePlan struct {
	explicit    bool
	explicitIDs []jsengine.EngineID
	suffixID    jsengine.EngineID
	extension   string
}

func (m *JSRuntimeManager) buildScriptRuntimePlan(filename, source string) (scriptRuntimePlan, error) {
	if m == nil {
		return scriptRuntimePlan{}, fmt.Errorf("JavaScript runtime manager is unavailable")
	}
	descriptors := m.registry.Descriptors()
	plan := scriptRuntimePlan{
		extension: jsengine.NormalizeExtension(filepath.Ext(filename)),
	}
	hint, hasHint := jsengine.UserScriptRuntimeHint(source)
	if hasHint {
		plan.explicit = true
		if strings.TrimSpace(hint) == "" {
			return plan, fmt.Errorf("script %q declares an empty @runtime", filename)
		}
		selectors, err := jsengine.ParseRuntimeSelectors(hint)
		if err != nil {
			return plan, fmt.Errorf("script %q: %w", filename, err)
		}
		for _, selector := range selectors {
			for _, descriptor := range descriptors {
				id := normalizeRequestedEngine(descriptor.ID)
				if id != selector.ID || descriptor.Author != selector.Author {
					continue
				}
				if !containsRuntimeID(plan.explicitIDs, id) {
					plan.explicitIDs = append(plan.explicitIDs, id)
				}
				break
			}
		}
	}
	if plan.extension != "" {
		for _, descriptor := range descriptors {
			id := normalizeRequestedEngine(descriptor.ID)
			for _, extension := range descriptor.Extensions {
				if jsengine.NormalizeExtension(extension) == plan.extension {
					plan.suffixID = id
					return plan, nil
				}
			}
		}
	}
	return plan, nil
}

func containsRuntimeID(ids []jsengine.EngineID, want jsengine.EngineID) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// SelectScriptRuntime selects a runtime from @runtime and then from the
// filename suffix. Suffix collisions use registration/discovery order.
func (m *JSRuntimeManager) SelectScriptRuntime(filename, source string) (jsengine.EngineID, error) {
	if m == nil {
		return "", fmt.Errorf("JavaScript runtime manager is unavailable")
	}
	m.mu.RLock()
	plan, err := m.buildScriptRuntimePlan(filename, source)
	m.mu.RUnlock()
	if err != nil {
		return "", err
	}
	if len(plan.explicitIDs) > 0 {
		return plan.explicitIDs[0], nil
	}
	if plan.suffixID != "" {
		return plan.suffixID, nil
	}
	if plan.explicit {
		return "", fmt.Errorf("script %q: no declared runtime is available and suffix %q is unsupported", filename, plan.extension)
	}
	return "", fmt.Errorf("script %q: no runtime declares suffix %q", filename, plan.extension)
}

// SupportsScriptExtension reports whether at least one registered runtime
// declares the filename suffix.
func (m *JSRuntimeManager) SupportsScriptExtension(filename string) bool {
	if m == nil {
		return false
	}
	extension := jsengine.NormalizeExtension(filepath.Ext(filename))
	if extension == "" {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, descriptor := range m.registry.Descriptors() {
		for _, supported := range descriptor.Extensions {
			if jsengine.NormalizeExtension(supported) == extension {
				return true
			}
		}
	}
	return false
}

// ParseUserScript parses the common UserScript metadata format and selects a
// registered runtime independently of provider implementation details.
func (m *JSRuntimeManager) ParseUserScript(filename, source string) (jsengine.EngineID, jsengine.UserScriptMetadata, error) {
	if m == nil {
		return "", jsengine.UserScriptMetadata{}, fmt.Errorf("JavaScript runtime manager is unavailable")
	}
	metadata, err := jsengine.ParseUserScript(source)
	if err != nil {
		return "", jsengine.UserScriptMetadata{}, fmt.Errorf("script %q: parse UserScript metadata: %w", filename, err)
	}
	id, err := m.SelectScriptRuntime(filename, source)
	if err != nil {
		return "", jsengine.UserScriptMetadata{}, err
	}
	return id, metadata, nil
}

// ResolveScript opens the first usable explicit runtime and falls back to the
// suffix-selected runtime when all explicit candidates are unavailable.
func (m *JSRuntimeManager) ResolveScript(
	ctx context.Context,
	filename string,
	source string,
	options jsengine.RuntimeOptions,
) (jsengine.EngineID, jsengine.Loop, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	return m.resolveScript(filename, source, func(id jsengine.EngineID) (jsengine.Loop, error) {
		return m.Resolve(ctx, id, options)
	})
}

// resolveScript applies routing order while letting the owner reuse live loops.
func (m *JSRuntimeManager) resolveScript(filename, source string, resolve func(jsengine.EngineID) (jsengine.Loop, error)) (jsengine.EngineID, jsengine.Loop, error) {
	if m == nil {
		return "", nil, fmt.Errorf("JavaScript runtime manager is unavailable")
	}
	m.mu.RLock()
	plan, err := m.buildScriptRuntimePlan(filename, source)
	m.mu.RUnlock()
	if err != nil {
		return "", nil, err
	}
	var lastErr error
	attempted := make(map[jsengine.EngineID]struct{})
	for _, id := range plan.explicitIDs {
		attempted[id] = struct{}{}
		loop, resolveErr := resolve(id)
		if resolveErr == nil {
			return id, loop, nil
		}
		lastErr = resolveErr
	}
	if plan.suffixID != "" {
		if _, alreadyTried := attempted[plan.suffixID]; !alreadyTried {
			loop, resolveErr := resolve(plan.suffixID)
			if resolveErr == nil {
				return plan.suffixID, loop, nil
			}
			lastErr = resolveErr
		}
	}
	if lastErr != nil {
		return "", nil, fmt.Errorf("script %q: no usable runtime: %w", filename, lastErr)
	}
	if plan.explicit {
		return "", nil, fmt.Errorf("script %q: no declared runtime is available and suffix %q is unsupported", filename, plan.extension)
	}
	return "", nil, fmt.Errorf("script %q: no runtime declares suffix %q", filename, plan.extension)
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
	status.Extensions = append([]string(nil), status.Extensions...)
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
		status.Extensions = append([]string(nil), status.Extensions...)
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
	status.Author = descriptor.Author
	status.ABI = fmt.Sprintf("%d.%d", descriptor.ABIMajor, descriptor.ABIMinor)
	status.Path = descriptor.Path
	status.Capabilities = capabilityNames(descriptor.Capabilities)
	status.Extensions = append([]string(nil), descriptor.Extensions...)
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
		{"hostService", jsengine.CapabilityHostService},
		{"contextPropagation", jsengine.CapabilityContextPropagation},
	}
	result := make([]string, 0, len(capabilities))
	for _, capability := range capabilities {
		if set.Has(capability.set) {
			result = append(result, capability.name)
		}
	}
	return result
}
