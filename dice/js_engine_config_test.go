package dice

import (
	"testing"

	"gopkg.in/yaml.v3"

	"Scardice-core/utils/jsengine"
)

func newJSConfigReadTestDice(config JsConfig) *Dice {
	d := &Dice{}
	view := newDefaultConfigReadView(d)
	view.config.JsConfig = config
	d.configView.Store(view)
	return d
}

func TestConfiguredJSEngine(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want jsengine.EngineID
	}{
		{name: "legacy config defaults to Goja", want: jsengine.EngineGoja},
		{name: "accepts quickjs provider ID", raw: "quickjs", want: "quickjs"},
		{name: "accepts dynamic provider IDs", raw: "v8", want: "v8"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := newJSConfigReadTestDice(JsConfig{JsEngine: tt.raw})
			if got := d.configuredJSEngine(); got != tt.want {
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
	d := newJSConfigReadTestDice(config)
	engine := d.configuredJSEngine()
	if engine != "quickjs" {
		t.Fatalf("configuredJSEngine() = %q, want quickjs", engine)
	}
}
