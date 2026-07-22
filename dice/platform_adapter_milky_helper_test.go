package dice

import (
	"encoding/json"
	"testing"
)

func Test_GenerateMilkyConfig_returns_yogurt_config_when_mode_is_yogurt(t *testing.T) {
	// Given
	ep := &EndPointInfo{
		EndPointInfoBase: EndPointInfoBase{UserID: "QQ:123456"},
		Adapter: &PlatformAdapterMilky{
			BuiltInMode: "yogurt",
		},
	}

	// When
	conf := GenerateMilkyConfig(3210, "https://sign.example", "token-value", ep)

	// Then
	if conf == nil {
		t.Fatal("expected yogurt config, got nil")
	}

	var parsed struct {
		Protocol struct {
			Uin        int    `json:"uin"`
			SignAPIURL string `json:"signApiUrl"`
		} `json:"protocol"`
		Milky struct {
			HTTP struct {
				Port        int    `json:"port"`
				AccessToken string `json:"accessToken"`
			} `json:"http"`
		} `json:"milky"`
	}
	if err := json.Unmarshal(conf, &parsed); err != nil {
		t.Fatalf("expected valid yogurt JSON config: %v", err)
	}
	if parsed.Protocol.Uin != 123456 {
		t.Fatalf("expected uin 123456, got %d", parsed.Protocol.Uin)
	}
	if parsed.Protocol.SignAPIURL != "https://sign.example" {
		t.Fatalf("expected sign URL to be substituted, got %q", parsed.Protocol.SignAPIURL)
	}
	if parsed.Milky.HTTP.Port != 3210 {
		t.Fatalf("expected port 3210, got %d", parsed.Milky.HTTP.Port)
	}
	if parsed.Milky.HTTP.AccessToken != "token-value" {
		t.Fatalf("expected access token to be substituted, got %q", parsed.Milky.HTTP.AccessToken)
	}
}

func Test_GenerateMilkyConfig_returns_nil_when_mode_is_unknown(t *testing.T) {
	// Given
	ep := &EndPointInfo{
		EndPointInfoBase: EndPointInfoBase{UserID: "QQ:123456"},
		Adapter: &PlatformAdapterMilky{
			BuiltInMode: "unknown",
		},
	}

	// When
	conf := GenerateMilkyConfig(3210, "https://sign.example", "token-value", ep)

	// Then
	if conf != nil {
		t.Fatalf("expected nil config for unknown mode, got %q", string(conf))
	}
}

func Test_getMilkyBuiltInSignals_returns_mode_specific_signals(t *testing.T) {
	tests := []struct {
		name string
		mode string
		want milkyBuiltInSignals
	}{
		{
			name: "lagrangeV2 preserves existing signals",
			mode: "lagrangeV2",
			want: milkyBuiltInSignals{
				qrcode:        "Fetch QrCode Success",
				online:        "successfully logged in",
				qrcodeExpired: "QrCode State: 17",
			},
		},
		{
			name: "yogurt uses yogurt stdout signals",
			mode: "yogurt",
			want: milkyBuiltInSignals{
				qrcode:        "二维码文件已保存",
				online:        "已上线",
				qrcodeExpired: "二维码已过期",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// When
			got := getMilkyBuiltInSignals(tt.mode)

			// Then
			if got != tt.want {
				t.Fatalf("expected %#v, got %#v", tt.want, got)
			}
		})
	}
}

func Test_milkyBuiltInConfigFileName_returns_mode_specific_file_name(t *testing.T) {
	tests := []struct {
		name string
		mode string
		want string
	}{
		{name: "lagrangeV2 uses appsettings jsonc", mode: "lagrangeV2", want: "appsettings.jsonc"},
		{name: "yogurt uses config json", mode: "yogurt", want: "config.json"},
		{name: "unknown uses empty file name", mode: "unknown", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// When
			got := milkyBuiltInConfigFileName(tt.mode)

			// Then
			if got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}
