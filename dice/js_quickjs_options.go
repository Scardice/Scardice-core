package dice

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"Scardice-core/utils/jsengine"
)

const (
	defaultQuickJSMemoryLimitMiB  uint64 = 256
	defaultQuickJSGCThresholdMiB  uint64 = 64
	defaultQuickJSMaxStackSizeKiB uint64 = 1024
)

const quickJSOptionsVersion uint32 = 1
const (
	quickJSMaxMemoryBytes   uint64 = 1 << 40
	quickJSMaxStackBytes    uint64 = 1 << 30
	quickJSMaxTimeoutMillis uint64 = 24 * 60 * 60 * 1000
)

var (
	ErrQuickJSOptionsOverflow   = errors.New("QuickJS options value overflows its serialized unit")
	ErrQuickJSOptionsOutOfRange = errors.New("QuickJS options value is out of range")
)

// QuickJSRuntimeOptionsPayload is the stable, provider-neutral runtime payload.
// Byte values are serialized after converting the user-facing MiB/KiB units.
type QuickJSRuntimeOptionsPayload struct {
	MemoryLimitBytes       uint64 `json:"memoryLimitBytes"`
	GCThresholdBytes       uint64 `json:"gcThresholdBytes"`
	MaxStackSizeBytes      uint64 `json:"maxStackSizeBytes"`
	ExecutionTimeoutMillis uint64 `json:"executionTimeoutMillis"`
}

type QuickJSFetchPolicyOptions struct {
	MaxConcurrent    uint64 `json:"maxConcurrent"`
	MaxResponseBytes uint64 `json:"maxResponseBytes"`
}

type QuickJSWebSocketPolicyOptions struct {
	MaxConnections  uint64 `json:"maxConnections"`
	MaxMessageBytes uint64 `json:"maxMessageBytes"`
}

type QuickJSFilesystemPolicyOptions struct {
	MaxReadBytes  uint64 `json:"maxReadBytes"`
	MaxWriteBytes uint64 `json:"maxWriteBytes"`
}

type QuickJSPBKDF2PolicyOptions struct {
	MaxIterations  uint64 `json:"maxIterations"`
	MaxOutputBytes uint64 `json:"maxOutputBytes"`
}

// QuickJSPolicyOptionsPayload is metadata for shared services. The native
// provider validates but does not enforce these fields; service adapters own
// their enforcement.
type QuickJSPolicyOptionsPayload struct {
	Fetch      QuickJSFetchPolicyOptions      `json:"fetch"`
	WebSocket  QuickJSWebSocketPolicyOptions  `json:"websocket"`
	Filesystem QuickJSFilesystemPolicyOptions `json:"filesystem"`
	PBKDF2     QuickJSPBKDF2PolicyOptions     `json:"pbkdf2"`
}

// QuickJSOptionsPayload is the versioned JSON contract passed to native
// providers. Its field order is intentional so serialized payloads are stable.
type QuickJSOptionsPayload struct {
	Version  uint32                       `json:"version"`
	Runtime  QuickJSRuntimeOptionsPayload `json:"runtime"`
	Services QuickJSPolicyOptionsPayload  `json:"services"`
}

func quickJSMiBBytes(value, fallback uint64) (uint64, error) {
	if value == 0 {
		return fallback, nil
	}
	if value > math.MaxUint64/(1024*1024) {
		return 0, fmt.Errorf("%w: %d MiB", ErrQuickJSOptionsOverflow, value)
	}
	return value * 1024 * 1024, nil
}

func quickJSKiBBytes(value, fallback uint64) (uint64, error) {
	if value == 0 {
		return fallback, nil
	}
	if value > math.MaxUint64/1024 {
		return 0, fmt.Errorf("%w: %d KiB", ErrQuickJSOptionsOverflow, value)
	}
	return value * 1024, nil
}

func quickJSSecondsMillis(value uint64) (uint64, error) {
	if value == 0 {
		return 0, nil
	}
	if value > math.MaxUint64/1000 {
		return 0, fmt.Errorf("%w: %d seconds", ErrQuickJSOptionsOverflow, value)
	}
	return value * 1000, nil
}

// BuildQuickJSOptionsPayload converts JsConfig using explicit defaults and
// units. Runtime zero values select the legacy defaults; service zero values
// mean unlimited. A GC threshold at or above the memory limit is clamped to a
// quarter of the memory limit, matching the in-process adapter.
func BuildQuickJSOptionsPayload(config JsConfig) (QuickJSOptionsPayload, error) {
	memory, err := quickJSMiBBytes(config.QuickJSMemoryLimitMiB, defaultQuickJSMemoryLimitMiB*1024*1024)
	if err != nil {
		return QuickJSOptionsPayload{}, err
	}
	gc, err := quickJSMiBBytes(config.QuickJSGCThresholdMiB, defaultQuickJSGCThresholdMiB*1024*1024)
	if err != nil {
		return QuickJSOptionsPayload{}, err
	}
	if gc >= memory {
		gc = memory / 4
	}
	stack, err := quickJSKiBBytes(config.QuickJSMaxStackSizeKiB, defaultQuickJSMaxStackSizeKiB*1024)
	if err != nil {
		return QuickJSOptionsPayload{}, err
	}
	timeout, err := quickJSSecondsMillis(config.QuickJSExecuteTimeoutSeconds)
	if err != nil {
		return QuickJSOptionsPayload{}, err
	}
	fetchResponse, err := quickJSPolicyMiBBytes(config.QuickJSMaxFetchResponseMiB)
	if err != nil {
		return QuickJSOptionsPayload{}, err
	}
	websocketMessage, err := quickJSPolicyMiBBytes(config.QuickJSMaxWebSocketMessageMiB)
	if err != nil {
		return QuickJSOptionsPayload{}, err
	}
	filesystemRead, err := quickJSPolicyMiBBytes(config.QuickJSMaxFilesystemReadMiB)
	if err != nil {
		return QuickJSOptionsPayload{}, err
	}
	filesystemWrite, err := quickJSPolicyMiBBytes(config.QuickJSMaxFilesystemWriteMiB)
	if err != nil {
		return QuickJSOptionsPayload{}, err
	}
	if memory > quickJSMaxMemoryBytes || gc > quickJSMaxMemoryBytes || stack > quickJSMaxStackBytes ||
		timeout > quickJSMaxTimeoutMillis ||
		config.QuickJSMaxFetchConcurrent > quickJSMaxMemoryBytes ||
		config.QuickJSMaxWebSocketConnections > quickJSMaxMemoryBytes ||
		config.QuickJSMaxPBKDF2Iterations > quickJSMaxMemoryBytes ||
		config.QuickJSMaxPBKDF2OutputBytes > quickJSMaxMemoryBytes ||
		fetchResponse > quickJSMaxMemoryBytes || websocketMessage > quickJSMaxMemoryBytes ||
		filesystemRead > quickJSMaxMemoryBytes || filesystemWrite > quickJSMaxMemoryBytes {
		return QuickJSOptionsPayload{}, ErrQuickJSOptionsOutOfRange
	}
	return QuickJSOptionsPayload{
		Version: quickJSOptionsVersion,
		Runtime: QuickJSRuntimeOptionsPayload{
			MemoryLimitBytes: memory, GCThresholdBytes: gc,
			MaxStackSizeBytes: stack, ExecutionTimeoutMillis: timeout,
		},
		Services: QuickJSPolicyOptionsPayload{
			Fetch: QuickJSFetchPolicyOptions{
				MaxConcurrent:    config.QuickJSMaxFetchConcurrent,
				MaxResponseBytes: fetchResponse,
			},
			WebSocket: QuickJSWebSocketPolicyOptions{
				MaxConnections:  config.QuickJSMaxWebSocketConnections,
				MaxMessageBytes: websocketMessage,
			},
			Filesystem: QuickJSFilesystemPolicyOptions{
				MaxReadBytes:  filesystemRead,
				MaxWriteBytes: filesystemWrite,
			},
			PBKDF2: QuickJSPBKDF2PolicyOptions{
				MaxIterations:  config.QuickJSMaxPBKDF2Iterations,
				MaxOutputBytes: config.QuickJSMaxPBKDF2OutputBytes,
			},
		},
	}, nil
}

func quickJSPolicyMiBBytes(value uint64) (uint64, error) {
	if value == 0 {
		return 0, nil
	}
	if value > math.MaxUint64/(1024*1024) {
		return 0, fmt.Errorf("%w: %d MiB", ErrQuickJSOptionsOverflow, value)
	}
	return value * 1024 * 1024, nil
}

func cloneJSRuntimeOptions(options map[string]json.RawMessage) map[string]json.RawMessage {
	if options == nil {
		return nil
	}
	cloned := make(map[string]json.RawMessage, len(options))
	for id, payload := range options {
		cloned[id] = append(json.RawMessage(nil), payload...)
	}
	return cloned
}

// BuildQuickJSRuntimeOptions returns the configured QuickJS namespace. The
// generic payload wins; legacy fields are converted only when it is absent.
func BuildQuickJSRuntimeOptions(config JsConfig) (jsengine.RuntimeOptions, error) {
	options, _, err := buildRuntimeOptionsForEngine("quickjs", config)
	return options, err
}

func buildLegacyQuickJSRuntimeOptions(config JsConfig) (jsengine.RuntimeOptions, error) {
	payload, err := BuildQuickJSOptionsPayload(config)
	if err != nil {
		return jsengine.RuntimeOptions{}, err
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return jsengine.RuntimeOptions{}, fmt.Errorf("marshal QuickJS options: %w", err)
	}
	providers := make(map[jsengine.EngineID]json.RawMessage, 1)
	providers["quickjs"] = encoded
	return jsengine.RuntimeOptions{Providers: providers}, nil
}

func buildRuntimeOptionsForEngine(engine jsengine.EngineID, config JsConfig) (jsengine.RuntimeOptions, bool, error) {
	engine = jsengine.NormalizeEngineID(string(engine))
	var payload json.RawMessage
	found := false
	for configuredID, configuredPayload := range config.JsRuntimeOptions {
		if jsengine.NormalizeEngineID(configuredID) != engine {
			continue
		}
		if found {
			return jsengine.RuntimeOptions{}, false, fmt.Errorf("duplicate runtime options namespace %q", engine)
		}
		payload = append(payload[:0], configuredPayload...)
		found = true
	}
	if found {
		providers := make(map[jsengine.EngineID]json.RawMessage, 1)
		providers[engine] = payload
		return jsengine.RuntimeOptions{Providers: providers}, true, nil
	}
	if engine == "quickjs" {
		options, err := buildLegacyQuickJSRuntimeOptions(config)
		return options, false, err
	}
	return jsengine.RuntimeOptions{}, false, nil
}

func BuildRuntimeOptionsForEngine(engine jsengine.EngineID, config JsConfig) (jsengine.RuntimeOptions, error) {
	options, _, err := buildRuntimeOptionsForEngine(engine, config)
	return options, err
}

func hasLegacyQuickJSRuntimeOptions(config JsConfig) bool {
	return config.QuickJSMemoryLimitMiB != 0 ||
		config.QuickJSGCThresholdMiB != 0 ||
		config.QuickJSMaxStackSizeKiB != 0 ||
		config.QuickJSExecuteTimeoutSeconds != 0 ||
		config.QuickJSMaxFetchConcurrent != 0 ||
		config.QuickJSMaxFetchResponseMiB != 0 ||
		config.QuickJSMaxWebSocketConnections != 0 ||
		config.QuickJSMaxWebSocketMessageMiB != 0 ||
		config.QuickJSMaxFilesystemReadMiB != 0 ||
		config.QuickJSMaxFilesystemWriteMiB != 0 ||
		config.QuickJSMaxPBKDF2Iterations != 0 ||
		config.QuickJSMaxPBKDF2OutputBytes != 0
}

func (d *Dice) runtimeOptionsForEngine(engine jsengine.EngineID) (jsengine.RuntimeOptions, error) {
	engine = jsengine.NormalizeEngineID(string(engine))
	options, generic, err := buildRuntimeOptionsForEngine(engine, d.Config.JsConfig)
	if err == nil && generic && engine == "quickjs" && hasLegacyQuickJSRuntimeOptions(d.Config.JsConfig) && d.Logger != nil {
		d.Logger.Warn("jsRuntimeOptions.quickjs overrides legacy QuickJS options")
	}
	return options, err
}

func (d *Dice) quickJSRuntimeOptions() (jsengine.RuntimeOptions, error) {
	return d.runtimeOptionsForEngine("quickjs")
}
