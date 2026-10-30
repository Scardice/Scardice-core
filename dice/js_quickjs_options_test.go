package dice

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"testing"

	"Scardice-core/utils/jsengine"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"gopkg.in/yaml.v3"
)

func TestBuildQuickJSRuntimeOptionsSerializesAllFields(t *testing.T) {
	config := JsConfig{
		QuickJSMemoryLimitMiB:          128,
		QuickJSGCThresholdMiB:          32,
		QuickJSMaxStackSizeKiB:         512,
		QuickJSExecuteTimeoutSeconds:   3,
		QuickJSMaxFetchConcurrent:      2,
		QuickJSMaxFetchResponseMiB:     4,
		QuickJSMaxWebSocketConnections: 5,
		QuickJSMaxWebSocketMessageMiB:  6,
		QuickJSMaxFilesystemReadMiB:    7,
		QuickJSMaxFilesystemWriteMiB:   8,
		QuickJSMaxPBKDF2Iterations:     9,
		QuickJSMaxPBKDF2OutputBytes:    10,
	}
	options, err := BuildQuickJSRuntimeOptions(config)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"version":1,"runtime":{"memoryLimitBytes":134217728,"gcThresholdBytes":33554432,"maxStackSizeBytes":524288,"executionTimeoutMillis":3000},"services":{"fetch":{"maxConcurrent":2,"maxResponseBytes":4194304},"websocket":{"maxConnections":5,"maxMessageBytes":6291456},"filesystem":{"maxReadBytes":7340032,"maxWriteBytes":8388608},"pbkdf2":{"maxIterations":9,"maxOutputBytes":10}}}`
	if got := string(options.PayloadFor("quickjs")); got != want {
		t.Fatalf("QuickJS payload = %s, want %s", got, want)
	}
}

func TestBuildRuntimeOptionsForEnginePassesGenericPayloadUnchanged(t *testing.T) {
	raw := json.RawMessage(` { "opaque": [1, 2, 3] } `)
	options, err := BuildRuntimeOptionsForEngine("custom", JsConfig{
		JsRuntimeOptions: map[string]json.RawMessage{"CUSTOM": raw},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := options.PayloadFor("custom"); !bytes.Equal(got, raw) {
		t.Fatalf("custom payload = %q, want %q", got, raw)
	}
}

func TestBuildRuntimeOptionsForEngineGenericQuickJSOverridesLegacy(t *testing.T) {
	raw := json.RawMessage(`{"ownedBy":"provider"}`)
	options, err := BuildRuntimeOptionsForEngine("quickjs", JsConfig{
		JsRuntimeOptions:      map[string]json.RawMessage{"quickjs": raw},
		QuickJSMemoryLimitMiB: math.MaxUint64,
	})
	if err != nil {
		t.Fatalf("generic QuickJS payload interpreted as legacy options: %v", err)
	}
	if got := options.PayloadFor("quickjs"); !bytes.Equal(got, raw) {
		t.Fatalf("QuickJS payload = %q, want %q", got, raw)
	}
}

func TestRuntimeOptionsForEngineWarnsWhenGenericQuickJSOverridesLegacy(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	dice := &Dice{
		Config: Config{JsConfig: JsConfig{
			JsRuntimeOptions:      map[string]json.RawMessage{"quickjs": json.RawMessage(`{"ownedBy":"provider"}`)},
			QuickJSMemoryLimitMiB: 256,
		}},
		Logger: zap.New(core).Sugar(),
	}
	if _, err := dice.runtimeOptionsForEngine(" QuickJS "); err != nil {
		t.Fatal(err)
	}
	if logs.Len() != 1 {
		t.Fatalf("warning count = %d, want 1", logs.Len())
	}
}

func TestJsConfigYAMLDecodesGenericRuntimeOptions(t *testing.T) {
	var config JsConfig
	if err := yaml.Unmarshal([]byte(`
jsRuntimeOptions:
  quickjs:
    memoryLimitMiB: 384
`), &config); err != nil {
		t.Fatal(err)
	}
	var payload struct {
		MemoryLimitMiB uint64 `json:"memoryLimitMiB"`
	}
	if err := json.Unmarshal(config.JsRuntimeOptions["quickjs"], &payload); err != nil {
		t.Fatal(err)
	}
	if payload.MemoryLimitMiB != 384 {
		t.Fatalf("memoryLimitMiB = %d, want 384", payload.MemoryLimitMiB)
	}
	encoded, err := yaml.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip JsConfig
	if err := yaml.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if got := string(roundTrip.JsRuntimeOptions["quickjs"]); got != string(config.JsRuntimeOptions["quickjs"]) {
		t.Fatalf("round-trip payload = %s, want %s", got, config.JsRuntimeOptions["quickjs"])
	}
}

func TestBuildQuickJSRuntimeOptionsUsesDefaultsAndUnlimitedPolicy(t *testing.T) {
	options, err := BuildQuickJSRuntimeOptions(JsConfig{})
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Version uint32 `json:"version"`
		Runtime struct {
			Memory  uint64 `json:"memoryLimitBytes"`
			GC      uint64 `json:"gcThresholdBytes"`
			Stack   uint64 `json:"maxStackSizeBytes"`
			Timeout uint64 `json:"executionTimeoutMillis"`
		} `json:"runtime"`
		Services map[string]map[string]uint64 `json:"services"`
	}
	if err := json.Unmarshal(options.PayloadFor("quickjs"), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Version != 1 || payload.Runtime.Memory != 256*1024*1024 || payload.Runtime.GC != 64*1024*1024 || payload.Runtime.Stack != 1024*1024 || payload.Runtime.Timeout != 0 {
		t.Fatalf("defaults = %#v", payload)
	}
	for service, fields := range payload.Services {
		for field, value := range fields {
			if value != 0 {
				t.Fatalf("%s.%s = %d, want unlimited zero", service, field, value)
			}
		}
	}
}

func TestBuildQuickJSRuntimeOptionsRejectsOverflowAndKeepsSecretsOut(t *testing.T) {
	_, err := BuildQuickJSRuntimeOptions(JsConfig{QuickJSMemoryLimitMiB: math.MaxUint64})
	if !errors.Is(err, ErrQuickJSOptionsOverflow) {
		t.Fatalf("overflow error = %v, want %v", err, ErrQuickJSOptionsOverflow)
	}
	options, err := BuildQuickJSRuntimeOptions(JsConfig{QuickJSMemoryLimitMiB: 1})
	if err != nil {
		t.Fatal(err)
	}
	payloadBytes := options.PayloadFor("quickjs")
	if len(payloadBytes) == 0 || string(payloadBytes) == "null" {
		t.Fatal("empty options payload")
	}
	for _, secret := range []string{"password", "token", "secret", "mailPassword"} {
		if bytes.Contains(payloadBytes, []byte(secret)) {
			t.Fatalf("serialized options contain secret-like key %q", secret)
		}
	}
}

func TestBuildQuickJSRuntimeOptionsRejectsRuntimeOutOfRange(t *testing.T) {
	_, err := BuildQuickJSRuntimeOptions(JsConfig{QuickJSExecuteTimeoutSeconds: math.MaxUint64/1000 + 1})
	if !errors.Is(err, ErrQuickJSOptionsOverflow) {
		t.Fatalf("timeout overflow error = %v, want %v", err, ErrQuickJSOptionsOverflow)
	}
}
func TestBuildQuickJSRuntimeOptionsRejectsPolicyByteOverflow(t *testing.T) {
	tests := []struct {
		name   string
		config JsConfig
	}{
		{"fetch response", JsConfig{QuickJSMaxFetchResponseMiB: math.MaxUint64}},
		{"websocket message", JsConfig{QuickJSMaxWebSocketMessageMiB: math.MaxUint64}},
		{"filesystem read", JsConfig{QuickJSMaxFilesystemReadMiB: math.MaxUint64}},
		{"filesystem write", JsConfig{QuickJSMaxFilesystemWriteMiB: math.MaxUint64}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := BuildQuickJSRuntimeOptions(tt.config)
			if !errors.Is(err, ErrQuickJSOptionsOverflow) {
				t.Fatalf("overflow error = %v, want %v", err, ErrQuickJSOptionsOverflow)
			}
		})
	}
}

func TestDiceQuickJSRuntimeOptionsUsesEngineNeutralContract(t *testing.T) {
	dice := &Dice{Config: Config{JsConfig: JsConfig{QuickJSMemoryLimitMiB: 2}}}
	options, err := dice.quickJSRuntimeOptions()
	if err != nil {
		t.Fatal(err)
	}
	if len(options.PayloadFor("quickjs")) == 0 {
		t.Fatal("Dice quickjs options omitted payload")
	}
	var _ = options
}
func TestRuntimeOptionsForEngineIgnoresQuickJSFieldsForGoja(t *testing.T) {
	options, err := BuildRuntimeOptionsForEngine(jsengine.EngineGoja, JsConfig{QuickJSMemoryLimitMiB: math.MaxUint64})
	if err != nil {
		t.Fatalf("BuildRuntimeOptionsForEngine(goja) error = %v", err)
	}
	if payload := options.PayloadFor(jsengine.EngineGoja); len(payload) != 0 {
		t.Fatalf("Goja payload = %q, want empty", payload)
	}
}
func TestBuildQuickJSOptionsAllowsFilesystemLimitsAboveLegacySyncCapacity(t *testing.T) {
	payload, err := BuildQuickJSOptionsPayload(JsConfig{
		QuickJSMaxFilesystemReadMiB:  17,
		QuickJSMaxFilesystemWriteMiB: 17,
	})
	if err != nil {
		t.Fatalf("filesystem limits above legacy capacity error = %v", err)
	}
	if payload.Services.Filesystem.MaxReadBytes != 17*1024*1024 ||
		payload.Services.Filesystem.MaxWriteBytes != 17*1024*1024 {
		t.Fatalf("filesystem limits = %#v, want 17 MiB", payload.Services.Filesystem)
	}
}

func TestBuildQuickJSOptionsRejectsFilesystemLimitAboveRuntimeMemory(t *testing.T) {
	_, err := BuildQuickJSOptionsPayload(JsConfig{QuickJSMaxFilesystemReadMiB: (1 << 20) + 1})
	if !errors.Is(err, ErrQuickJSOptionsOutOfRange) {
		t.Fatalf("filesystem limit error = %v, want %v", err, ErrQuickJSOptionsOutOfRange)
	}
}
