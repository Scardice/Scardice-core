package jsengine

import "testing"

func TestNormalizeEngineID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want EngineID
	}{
		{name: "empty", want: ""},
		{name: "canonical goja", raw: "goja", want: "goja"},
		{name: "canonical quickjs", raw: " QUICKJS ", want: "quickjs"},
		{name: "unknown providers remain dynamic", raw: " V8 ", want: "v8"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := NormalizeEngineID(tt.raw); got != tt.want {
				t.Fatalf("NormalizeEngineID() = %q, want %q", got, tt.want)
			}
		})
	}
}
