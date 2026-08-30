package jsengine

import "testing"

func TestParseEngineID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		raw     string
		want    EngineID
		wantErr bool
	}{
		{name: "defaults to Goja", want: EngineGoja},
		{name: "accepts Goja", raw: "goja", want: EngineGoja},
		{name: "accepts QuickJS-Go", raw: "quickjs", want: EngineQuickJS},
		{name: "rejects unknown engine", raw: "v8", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseEngineID(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatal("ParseEngineID() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseEngineID() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("ParseEngineID() = %q, want %q", got, tt.want)
			}
		})
	}
}
