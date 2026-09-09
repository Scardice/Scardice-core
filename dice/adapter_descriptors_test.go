package dice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"Scardice-core/adapterapi"
	"Scardice-core/endpoint"
)

func TestAdapterDescriptorRegistryHasStableKeys(t *testing.T) {
	descriptors := NewAdapterDescriptors()
	want := []adapterapi.AdapterKey{
		"gocq", "lagrange", "walleq", "red", "official_qq", "satori", "milky", "discord", "kook",
		"telegram", "slack", "dodo", "dingtalk", "minecraft", "sealchat", "http", "pureonebot",
	}
	if len(descriptors) != len(want) {
		t.Fatalf("descriptor count = %d, want %d", len(descriptors), len(want))
	}
	registry := endpoint.NewRegistry()
	for i, descriptor := range descriptors {
		if descriptor == nil {
			t.Fatalf("descriptor %d is nil", i)
		}
		if got := descriptor.Key(); got != want[i] {
			t.Fatalf("descriptor %d key = %q, want %q", i, got, want[i])
		}
		if err := registry.Register(descriptor); err != nil {
			t.Fatalf("register %q: %v", descriptor.Key(), err)
		}
	}
	if _, ok := registry.Lookup(context.Background(), "pureonebot"); !ok {
		t.Fatal("registry did not expose pureonebot")
	}
	if got := len(AllAdapterDescriptors()); got != len(descriptors) {
		t.Fatal("compatibility registry returned a different descriptor count")
	}
}

func TestCompatDescriptorsAcceptCanonicalProviderConfig(t *testing.T) {
	for _, descriptor := range NewAdapterDescriptors() {
		if descriptor.Key() == adapterapi.AdapterKey("pureonebot") {
			continue
		}
		config, err := descriptor.ValidateConfig(context.Background(), json.RawMessage(`{"url":"https://example.com","token":{"secretRef":"provider-token","version":1}}`))
		if err != nil {
			t.Fatalf("%s rejected provider config: %v", descriptor.Key(), err)
		}
		if err := config.Validate(); err != nil {
			t.Fatalf("%s returned invalid config: %v", descriptor.Key(), err)
		}
	}
}
func TestCompatDescriptorCanonicalizesAndRedactsSecrets(t *testing.T) {

	descriptor := descriptorForAdapterKey(t, "discord")
	raw := json.RawMessage(`{"timeoutSeconds":30,"token":{"secretRef":"discord-token","version":7},"url":"https://example.com/api"}`)
	validated, err := descriptor.ValidateConfig(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := validated.Validate(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(validated.Canonical, json.RawMessage(`{"timeoutSeconds":30,"token":{"secretRef":"discord-token","version":7},"url":"https://example.com/api"}`)) {
		t.Fatalf("canonical = %s", validated.Canonical)
	}
	if len(validated.SecretRefs) != 1 || validated.SecretRefs[0] != (adapterapi.SecretRef{Ref: "discord-token", Version: 7}) {
		t.Fatalf("secret refs = %#v", validated.SecretRefs)
	}
	if strings.Contains(string(validated.Canonical), "super-secret") {
		t.Fatal("secret bytes were persisted in canonical config")
	}
}

func TestCompatDescriptorValidatesNestedSignServerSecrets(t *testing.T) {
	descriptor := descriptorForAdapterKey(t, "gocq")
	raw := json.RawMessage(`{"signServerConfig":{"signServers":[{"url":"https://sign.example","key":{"secretRef":"signServer.0.key","version":1},"authorization":{"secretRef":"signServer.0.authorization","version":1}}],"signServerTimeout":60}}`)
	validated, err := descriptor.ValidateConfig(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := validated.Validate(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(validated.Canonical), "plaintext") {
		t.Fatal("nested sign-server secret leaked into canonical config")
	}
	wantRefs := map[adapterapi.SecretRef]bool{
		{Ref: "signServer.0.key", Version: 1}:           true,
		{Ref: "signServer.0.authorization", Version: 1}: true,
	}
	if len(validated.SecretRefs) != len(wantRefs) {
		t.Fatalf("secret refs = %#v", validated.SecretRefs)
	}
	for _, ref := range validated.SecretRefs {
		if !wantRefs[ref] {
			t.Fatalf("unexpected nested secret ref %#v", ref)
		}
	}
}

func TestCompatDescriptorRejectsUnsafeConfig(t *testing.T) {
	descriptor := descriptorForAdapterKey(t, "discord")
	cases := []string{
		`{"url":"file:///tmp/adapter"}`,
		`{"url":"https://user:password@example.com"}`,
		"{\"url\":\"https://example.com/line\nfeed\"}",
		`{"version":"v\n1"}`,
		`{"unexpected":true}`,
		`{"token":"super-secret"}`,
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			if _, err := descriptor.ValidateConfig(context.Background(), json.RawMessage(raw)); err == nil {
				t.Fatal("unsafe or unknown configuration was accepted")
			}
		})
	}
}

func TestCompatRuntimeIsTruthfulAndStopsIdempotently(t *testing.T) {
	descriptor := descriptorForAdapterKey(t, "discord")
	validated, err := descriptor.ValidateConfig(context.Background(), json.RawMessage(`{"url":"wss://example.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := descriptor.NewRuntime(adapterapi.RuntimeInit{
		EndpointID:     "compat-endpoint",
		Generation:     1,
		DesiredVersion: 1,
		Config:         validated,
		Secrets:        noCallSecretResolver{},
		ResourceRoot:   "/path-that-must-not-be-opened",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runtime.Run(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled run error = %v", err)
	}
	if got := runtime.Capabilities(); got != adapterapi.CapabilityLifecycle {
		t.Fatalf("capabilities = %#v, want lifecycle only", got)
	}
	result := runtime.Execute(context.Background(), adapterapi.OutboundEffect{})
	if result.Outcome != adapterapi.EffectUnsupported || result.Code != "provider_unavailable" {
		t.Fatalf("execute result = %#v", result)
	}
	report := runtime.Diagnostics(context.Background())
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(report.Entries) == 0 || report.Entries[0].Code != "provider_unavailable" {
		t.Fatalf("diagnostics = %#v", report)
	}
	if err := runtime.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Run(context.Background(), nil); !errors.Is(err, ErrAdapterProviderUnavailable) {
		t.Fatalf("run error = %v", err)
	}
}

func descriptorForAdapterKey(t *testing.T, key adapterapi.AdapterKey) adapterapi.Descriptor {
	t.Helper()
	for _, descriptor := range NewAdapterDescriptors() {
		if descriptor.Key() == key {
			return descriptor
		}
	}
	t.Fatalf("descriptor %q not found", key)
	return nil
}

type noCallSecretResolver struct{}

func (noCallSecretResolver) Resolve(context.Context, adapterapi.SecretRef) (adapterapi.SecretValue, error) {
	panic("compat runtime constructor attempted to resolve a secret")
}
