package dice

import (
	"testing"

	"Scardice-core/utils/jsengine"
	quickjsadapter "Scardice-core/utils/jsengine/quickjs"
	"gopkg.in/yaml.v3"
)

func TestConfiguredJSEngine(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    jsengine.EngineID
		wantErr bool
	}{
		{name: "legacy config defaults to Goja", want: jsengine.EngineGoja},
		{name: "accepts quickjs", raw: "quickjs", want: jsengine.EngineQuickJS},
		{name: "rejects invalid", raw: "v8", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &Dice{Config: Config{JsConfig: JsConfig{JsEngine: tt.raw}}}
			got, err := d.configuredJSEngine()
			if tt.wantErr {
				if err == nil {
					t.Fatal("configuredJSEngine() error = nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("configuredJSEngine() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("configuredJSEngine() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestConfiguredJSEngine_ReadsManualYAML(t *testing.T) {
	var config JsConfig
	if err := yaml.Unmarshal([]byte("jsEngine: quickjs\n"), &config); err != nil {
		t.Fatal(err)
	}
	d := &Dice{Config: Config{JsConfig: config}}
	engine, err := d.configuredJSEngine()
	if err != nil {
		t.Fatal(err)
	}
	if engine != jsengine.EngineQuickJS {
		t.Fatalf("configuredJSEngine() = %q, want %q", engine, jsengine.EngineQuickJS)
	}
}

func TestQuickJSRuntimeLimitsUseDefaultsForLegacyConfig(t *testing.T) {
	dice := &Dice{}

	got := dice.quickJSRuntimeLimits()
	want := quickjsadapter.RuntimeLimits{
		MemoryLimit:  256 * 1024 * 1024,
		GCThreshold:  64 * 1024 * 1024,
		MaxStackSize: 1024 * 1024,
	}
	if got != want {
		t.Fatalf("quickJSRuntimeLimits() = %#v, want %#v", got, want)
	}
}

func TestQuickJSRuntimeLimitsConvertConfiguredUnits(t *testing.T) {
	dice := &Dice{Config: Config{JsConfig: JsConfig{
		QuickJSMemoryLimitMiB:  128,
		QuickJSGCThresholdMiB:  32,
		QuickJSMaxStackSizeKiB: 512,
	}}}

	got := dice.quickJSRuntimeLimits()
	want := quickjsadapter.RuntimeLimits{
		MemoryLimit:  128 * 1024 * 1024,
		GCThreshold:  32 * 1024 * 1024,
		MaxStackSize: 512 * 1024,
	}
	if got != want {
		t.Fatalf("quickJSRuntimeLimits() = %#v, want %#v", got, want)
	}
}

func TestQuickJSRuntimeLimitsKeepsGCBelowMemoryLimit(t *testing.T) {
	dice := &Dice{Config: Config{JsConfig: JsConfig{
		QuickJSMemoryLimitMiB: 8,
		QuickJSGCThresholdMiB: 16,
	}}}

	got := dice.quickJSRuntimeLimits()
	if got.MemoryLimit != 8*1024*1024 {
		t.Fatalf("MemoryLimit = %d, want %d", got.MemoryLimit, 8*1024*1024)
	}
	if got.GCThreshold != 2*1024*1024 {
		t.Fatalf("GCThreshold = %d, want %d", got.GCThreshold, 2*1024*1024)
	}
}
