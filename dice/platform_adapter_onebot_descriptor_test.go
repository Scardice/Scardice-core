package dice

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"Scardice-core/adapterapi"
)

func TestOnebotDescriptorConfigValidationMatrix(t *testing.T) {
	d := OnebotDescriptor{}
	tests := []struct {
		name string
		raw  string
		ok   bool
	}{
		{name: "client ws", raw: `{"mode":"client","url":"ws://127.0.0.1:6700","token":{"secretRef":"onebot-token","version":1}}`, ok: true},
		{name: "client wss secure by default", raw: `{"mode":"client","url":"wss://bot.example/ws","token":{"secretRef":"onebot-token","version":2}}`, ok: true},
		{name: "client wss explicit insecure", raw: `{"mode":"client","url":"wss://bot.example/ws","insecureSkipVerify":true,"token":{"secretRef":"onebot-token","version":3}}`, ok: true},
		{name: "reverse ipv4 loopback", raw: `{"mode":"server","listenAddress":"127.0.0.1:6700","token":{"secretRef":"onebot-token","version":1}}`, ok: true},
		{name: "reverse ipv6 loopback", raw: `{"mode":"server","listenAddress":"[::1]:6700","token":{"secretRef":"onebot-token","version":1}}`, ok: true},
		{name: "reverse hostname with token", raw: `{"mode":"server","listenAddress":"localhost:6700","token":{"secretRef":"onebot-token","version":1}}`, ok: true},
		{name: "userinfo rejected", raw: `{"mode":"client","url":"ws://user:pass@bot.example/ws","token":{"secretRef":"onebot-token","version":1}}`, ok: false},
		{name: "fragment rejected", raw: `{"mode":"client","url":"ws://bot.example/ws#fragment","token":{"secretRef":"onebot-token","version":1}}`, ok: false},
		{name: "control rejected", raw: "{\"mode\":\"client\",\"url\":\"ws://bot.example/\\u0001\",\"token\":{\"secretRef\":\"onebot-token\",\"version\":1}}", ok: false},
		{name: "empty host rejected", raw: `{"mode":"client","url":"ws:///path","token":{"secretRef":"onebot-token","version":1}}`, ok: false},
		{name: "trailing port colon rejected", raw: `{"mode":"client","url":"ws://bot.example:"}`, ok: false},
		{name: "extra port colon rejected", raw: `{"mode":"client","url":"ws://bot.example:1:2"}`, ok: false},
		{name: "malformed port rejected", raw: `{"mode":"client","url":"ws://bot.example:notaport/ws","token":{"secretRef":"onebot-token","version":1}}`, ok: false},
		{name: "unknown field rejected", raw: `{"mode":"client","url":"ws://bot.example","password":"raw-token"}`, ok: false},
		{name: "wrong type rejected", raw: `{"mode":123,"url":"ws://bot.example"}`, ok: false},
		{name: "client URL aliases conflict", raw: `{"mode":"client","url":"ws://bot-a.example","connectUrl":"ws://bot-b.example"}`, ok: false},
		{name: "reverse listen aliases conflict", raw: `{"mode":"server","listenAddress":"127.0.0.1:6700","reverseUrl":"127.0.0.1:6701","token":{"secretRef":"onebot-token","version":1}}`, ok: false},
		{name: "friend ignore aliases conflict", raw: `{"mode":"client","url":"ws://bot.example","ignoreFriendRequest":true,"ignore_friend_request":false}`, ok: false},
		{name: "explicit friend policy conflicts with ignore bool", raw: `{"mode":"client","url":"ws://bot.example","friendRequestPolicy":"accept","ignoreFriendRequest":true}`, ok: false},
		{name: "token version aliases conflict at zero", raw: `{"mode":"client","url":"ws://bot.example","token":{"secretRef":"onebot-token","version":1},"tokenSecretVersion":0}`, ok: false},
		{name: "null friend camel rejected", raw: `{"mode":"client","url":"ws://bot.example","ignoreFriendRequest":null}`, ok: false},
		{name: "null friend legacy rejected", raw: `{"mode":"client","url":"ws://bot.example","ignore_friend_request":null}`, ok: false},
		{name: "null token version rejected", raw: `{"mode":"client","url":"ws://bot.example","tokenSecretVersion":null}`, ok: false},
		{name: "isolated token version rejected", raw: `{"mode":"client","url":"ws://bot.example","tokenSecretVersion":1}`, ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := d.ValidateConfig(context.Background(), json.RawMessage(tt.raw))
			if tt.ok && err != nil {
				t.Fatalf("ValidateConfig() error = %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatalf("ValidateConfig() accepted invalid config: %#v", got)
			}
		})
	}
}

func TestOnebotDescriptorCanonicalRedactsTokenMaterial(t *testing.T) {
	d := OnebotDescriptor{}
	validated, err := d.ValidateConfig(context.Background(), json.RawMessage(`{"mode":"client","url":"ws://bot.example:6700/ws","reverseSuffix":"/socket","accountHint":"123","friendRequestPolicy":"ignore","imageAssetBaseUrl":"https://assets.example/","token":{"secretRef":"onebot-token","version":7}}`))
	if err != nil {
		t.Fatal(err)
	}
	if validated.Version != d.ConfigVersion() {
		t.Fatalf("validated version = %d, want %d", validated.Version, d.ConfigVersion())
	}
	if len(validated.SecretRefs) != 1 || validated.SecretRefs[0] != (adapterapi.SecretRef{Ref: "onebot-token", Version: 7}) {
		t.Fatalf("secret refs = %#v", validated.SecretRefs)
	}
	canonical := string(validated.Canonical)
	if strings.Contains(canonical, "password") || strings.Contains(canonical, "secret") && strings.Contains(canonical, "material") {
		t.Fatalf("canonical config leaked token material: %s", canonical)
	}
	if !strings.Contains(canonical, `"secretRef":"onebot-token"`) || !strings.Contains(canonical, `"version":7`) {
		t.Fatalf("canonical config omitted redacted token reference: %s", canonical)
	}
	if !strings.Contains(canonical, `"insecureSkipVerify":false`) {
		t.Fatalf("canonical config omitted secure TLS default: %s", canonical)
	}
}

func TestOnebotDescriptorActionsAndConstructionArePure(t *testing.T) {
	d := OnebotDescriptor{}
	validated, err := d.ValidateConfig(context.Background(), json.RawMessage(`{"mode":"client","url":"ws://bot.example:6700","token":{"secretRef":"onebot-token","version":1}}`))
	if err != nil {
		t.Fatal(err)
	}
	if actions := d.SupportedActions(validated); actions.Has(adapterapi.ActionKindRequestQRCode) || actions.Has(adapterapi.ActionKindSubmitSMS) || actions.Has(adapterapi.ActionKindValidateCredentials) {
		t.Fatalf("unexpected interactive actions: %#v", actions)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runtime, err := d.NewRuntime(adapterapi.RuntimeInit{EndpointID: "endpoint-1", Generation: 1, DesiredVersion: 1, Config: validated})
	if err != nil {
		t.Fatal(err)
	}
	if runtime == nil {
		t.Fatal("NewRuntime returned nil runtime")
	}
	if got := runtime.Capabilities(); got != adapterapi.CapabilityLifecycle|adapterapi.CapabilityInbound|adapterapi.CapabilityOutbound|adapterapi.CapabilityActions|adapterapi.CapabilityRichMessages {
		t.Fatalf("runtime capabilities = %#v, want lifecycle+inbound+outbound+actions+rich messages", got)
	}
	if err := runtime.Stop(ctx); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Stop(canceled context) = %v", err)
	}
}
