package api

import "testing"

func TestShouldReloadDangerousAPIState(t *testing.T) {
	tests := []struct {
		name       string
		jsEnabled  bool
		runtimeOn  bool
		desiredOn  bool
		wantReload bool
	}{
		{
			name:       "no js no reload",
			jsEnabled:  false,
			runtimeOn:  true,
			desiredOn:  false,
			wantReload: false,
		},
		{
			name:       "turn on reloads",
			jsEnabled:  true,
			runtimeOn:  false,
			desiredOn:  true,
			wantReload: true,
		},
		{
			name:       "turn off reloads even if config already mutated in memory",
			jsEnabled:  true,
			runtimeOn:  true,
			desiredOn:  false,
			wantReload: true,
		},
		{
			name:       "state already matches no reload",
			jsEnabled:  true,
			runtimeOn:  false,
			desiredOn:  false,
			wantReload: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldReloadDangerousAPIState(tt.jsEnabled, tt.runtimeOn, tt.desiredOn)
			if got != tt.wantReload {
				t.Fatalf("shouldReloadDangerousAPIState(%v, %v, %v) = %v, want %v", tt.jsEnabled, tt.runtimeOn, tt.desiredOn, got, tt.wantReload)
			}
		})
	}
}
