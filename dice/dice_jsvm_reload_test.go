package dice

import "testing"

func TestShouldQuickJSSoftResetOnReload(t *testing.T) {
	tests := []struct {
		name            string
		configEngine    string
		effectiveEngine string
		hasScriptEngine bool
		want            bool
	}{
		{
			name:            "quickjs_to_quickjs_with_engine",
			configEngine:    "quickjs",
			effectiveEngine: "quickjs",
			hasScriptEngine: true,
			want:            true,
		},
		{
			name:            "quickjs_to_quickjs_without_engine",
			configEngine:    "quickjs",
			effectiveEngine: "quickjs",
			hasScriptEngine: false,
			want:            false,
		},
		{
			name:            "switch_from_quickjs_to_goja",
			configEngine:    "goja",
			effectiveEngine: "quickjs",
			hasScriptEngine: true,
			want:            false,
		},
		{
			name:            "quickjs_config_but_effective_goja",
			configEngine:    "quickjs",
			effectiveEngine: "goja",
			hasScriptEngine: true,
			want:            false,
		},
		{
			name:            "empty_config_defaults_to_goja",
			configEngine:    "",
			effectiveEngine: "quickjs",
			hasScriptEngine: true,
			want:            false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldQuickJSSoftResetOnReload(tc.configEngine, tc.effectiveEngine, tc.hasScriptEngine)
			if got != tc.want {
				t.Fatalf("结果不符合预期: got=%v want=%v", got, tc.want)
			}
		})
	}
}
