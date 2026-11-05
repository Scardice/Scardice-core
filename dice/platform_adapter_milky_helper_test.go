package dice

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"Scardice-core/endpoint"
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
				qrcode:                  "Fetch QrCode Success",
				qrcodeWaitingForScan:    "Fetch QrCode Success",
				qrcodeWaitingForConfirm: "QrCode State: 53",
				qrcodeCancelled:         "QrCode State: 54",
				online:                  "successfully logged in",
				qrcodeExpired:           "QrCode State: 17",
			},
		},
		{
			name: "yogurt uses yogurt stdout signals",
			mode: "yogurt",
			want: milkyBuiltInSignals{
				qrcode:                  "二维码文件已保存",
				qrcodeWaitingForScan:    "二维码状态：WAITING_FOR_SCAN",
				qrcodeWaitingForConfirm: "二维码状态：WAITING_FOR_CONFIRMATION",
				qrcodeCancelled:         "用户取消了登录",
				online:                  "已上线",
				qrcodeExpired:           "二维码已过期",
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

func Test_getMilkyBuiltInLoginStateFromLine_returns_qrcode_state(t *testing.T) {
	tests := []struct {
		name string
		mode string
		line string
		want MilkyLoginState
	}{
		{
			name: "yogurt waiting for scan",
			mode: "yogurt",
			line: "23:34:10 DEBUG o.n.a.Bot 二维码状态：WAITING_FOR_SCAN (48)",
			want: MilkyLoginStateQRWaitingForScan,
		},
		{
			name: "yogurt waiting for confirmation",
			mode: "yogurt",
			line: "23:35:20 DEBUG o.n.a.Bot 二维码状态：WAITING_FOR_CONFIRMATION (53)",
			want: MilkyLoginStateQRWaitingForConfirm,
		},
		{
			name: "yogurt cancelled status",
			mode: "yogurt",
			line: "23:35:27 DEBUG o.n.a.Bot 二维码状态：CANCELLED (54)",
			want: MilkyLoginStateCancelled,
		},
		{
			name: "yogurt cancelled exception",
			mode: "yogurt",
			line: "kotlin.IllegalStateException: 用户取消了登录",
			want: MilkyLoginStateCancelled,
		},
		{
			name: "yogurt code expired status",
			mode: "yogurt",
			line: "01:00:38 DEBUG o.n.a.Bot 二维码状态：CODE_EXPIRED (17)",
			want: MilkyLoginStateCodeExpired,
		},
		{
			name: "lagrange expired code",
			mode: "lagrangeV2",
			line: "QrCode State: 17",
			want: MilkyLoginStateCodeExpired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getMilkyBuiltInLoginStateFromLine(tt.line, getMilkyBuiltInSignals(tt.mode))

			if got != tt.want {
				t.Fatalf("expected %d, got %d", tt.want, got)
			}
		})
	}
}

type milkyTerminalLifecyclePort struct {
	disabled endpoint.Command
	err      error
}

func (port *milkyTerminalLifecyclePort) Execute(_ context.Context, command endpoint.Command) (endpoint.Result, error) {
	if command.Kind == endpoint.CommandDisable {
		port.disabled = command
	}
	return endpoint.Result{}, port.err
}

func Test_applyMilkyBuiltInLoginTerminalState_disables_canonical_endpoint(t *testing.T) {
	port := &milkyTerminalLifecyclePort{}
	d := &Dice{EndpointLifecycle: port}
	pa := &PlatformAdapterMilky{
		BuiltInLoginState: MilkyLoginStateQRWaitingForConfirm,
		QrCodeData:        []byte("qr"),
	}
	ep := &EndPointInfo{
		EndPointInfoBase: EndPointInfoBase{
			ID:     "milky-terminal-endpoint",
			Enable: true,
			State:  StateConnecting,
		},
		Adapter: pa,
	}

	if err := applyMilkyBuiltInLoginTerminalState(d, ep, MilkyLoginStateCancelled); err != nil {
		t.Fatal(err)
	}

	if pa.BuiltInLoginState != MilkyLoginStateCancelled {
		t.Fatalf("expected cancelled state, got %d", pa.BuiltInLoginState)
	}
	if pa.QrCodeData != nil {
		t.Fatal("expected QR data to be cleared")
	}
	if port.disabled.Kind != endpoint.CommandDisable || port.disabled.Type != endpoint.CommandDisable {
		t.Fatalf("disable command kind=%q type=%q", port.disabled.Kind, port.disabled.Type)
	}
	if port.disabled.EndpointID != "milky-terminal-endpoint" {
		t.Fatalf("disable command endpoint=%q", port.disabled.EndpointID)
	}
	if port.disabled.CommandID == "" || port.disabled.CommandID != port.disabled.ID || port.disabled.CommandID != port.disabled.CorrelationID {
		t.Fatalf("disable command identity=%+v", port.disabled)
	}
	if !ep.Enable || ep.State != StateConnecting {
		t.Fatalf("compatibility endpoint was mutated: enable=%v state=%d", ep.Enable, ep.State)
	}
}

func Test_applyMilkyBuiltInLoginTerminalState_propagates_disable_failure(t *testing.T) {
	disableErr := errors.New("disable failed")
	port := &milkyTerminalLifecyclePort{err: disableErr}
	d := &Dice{EndpointLifecycle: port}
	pa := &PlatformAdapterMilky{QrCodeData: []byte("qr")}
	ep := &EndPointInfo{
		EndPointInfoBase: EndPointInfoBase{ID: "milky-terminal-endpoint"},
		Adapter:          pa,
	}

	err := applyMilkyBuiltInLoginTerminalState(d, ep, MilkyLoginStateCodeExpired)
	if !errors.Is(err, disableErr) {
		t.Fatalf("disable error=%v, want %v", err, disableErr)
	}
	if pa.BuiltInLoginState != MilkyLoginStateCodeExpired || pa.QrCodeData != nil {
		t.Fatalf("terminal state was not retained: state=%d qr=%v", pa.BuiltInLoginState, pa.QrCodeData)
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
