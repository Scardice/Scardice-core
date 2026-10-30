package adapterapi

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type contractRuntime struct{}

func (contractRuntime) Run(context.Context, CorePort) error { return nil }
func (contractRuntime) Stop(context.Context) error          { return nil }
func (contractRuntime) Capabilities() CapabilitySet         { return CapabilityInbound | CapabilityLifecycle }
func (contractRuntime) Execute(context.Context, OutboundEffect) EffectResult {
	return UnsupportedResult("not-advertised")
}
func (contractRuntime) Diagnostics(context.Context) DiagnosticReport { return DiagnosticReport{} }

type contractPort struct{}

func (contractPort) HandleInbound(context.Context, InboundMessage) (IngressReceipt, error) {
	return IngressReceipt{Outcome: IngressAccepted}, nil
}
func (contractPort) ReportObservation(context.Context, LifecycleObservation) error { return nil }

type contractSecrets struct{}

func (contractSecrets) Resolve(context.Context, SecretRef) (SecretValue, error) {
	return SecretValue{Version: 1}, nil
}

type contractDescriptor struct{ constructed int }

func (d *contractDescriptor) Key() AdapterKey       { return "fake" }
func (d *contractDescriptor) ConfigVersion() uint16 { return 1 }
func (d *contractDescriptor) ValidateConfig(ctx context.Context, raw json.RawMessage) (ValidatedConfig, error) {
	if err := ctx.Err(); err != nil {
		return ValidatedConfig{}, err
	}
	canonical, err := CanonicalizeJSON(raw)
	if err != nil {
		return ValidatedConfig{}, err
	}
	return ValidatedConfig{Version: 1, Canonical: canonical}, nil
}
func (d *contractDescriptor) SupportedActions(ValidatedConfig) ActionSet {
	return ActionSet(0).With(ActionKindRequestQRCode, ActionKindValidateCredentials)
}
func (d *contractDescriptor) Capabilities(ValidatedConfig) CapabilitySet {
	return CapabilityLifecycle | CapabilityActions
}
func (d *contractDescriptor) NewRuntime(RuntimeInit) (AdapterRuntime, error) {
	d.constructed++
	return contractRuntime{}, nil
}

var (
	_ AdapterRuntime = contractRuntime{}
	_ CorePort       = contractPort{}
	_ SecretResolver = contractSecrets{}
	_ Descriptor     = (*contractDescriptor)(nil)
)

func TestAdapterInterfacesAndDescriptorConstructionContract(t *testing.T) {
	ctx := context.Background()
	descriptor := &contractDescriptor{}
	config, err := descriptor.ValidateConfig(ctx, json.RawMessage(`{"token":"secret","n":1}`))
	if err != nil {
		t.Fatalf("ValidateConfig: %v", err)
	}
	if got, want := string(config.Canonical), `{"n":1,"token":"secret"}`; got != want {
		t.Fatalf("canonical config = %q, want %q", got, want)
	}
	if descriptor.constructed != 0 {
		t.Fatal("config validation constructed a runtime")
	}
	runtime, err := descriptor.NewRuntime(RuntimeInit{
		EndpointID:     EndpointID("endpoint-1"),
		Generation:     3,
		DesiredVersion: 4,
		Config:         config,
		Secrets:        contractSecrets{},
	})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	if runtime == nil || descriptor.constructed != 1 {
		t.Fatalf("runtime construction = %#v, calls=%d", runtime, descriptor.constructed)
	}
	if got := descriptor.SupportedActions(config); !got.Has(ActionKindRequestQRCode) || got.Has(ActionKindGenerateConfigArtifact) {
		t.Fatalf("unexpected action set %#v", got)
	}
}

func TestEffectOutcomesAreClassifiedAndNotNoOp(t *testing.T) {
	results := []EffectResult{
		SucceededResult("provider-1"),
		UnsupportedResult("missing-capability"),
		RetryableResult("rate-limited", "retry later"),
		TerminalResult("invalid-target", "target rejected"),
		AmbiguousResult("timeout-after-send", "delivery is unknown"),
	}
	seen := make(map[EffectOutcome]bool)
	for _, result := range results {
		if err := result.Validate(); err != nil {
			t.Fatalf("result %#v: %v", result, err)
		}
		if result.Outcome == EffectOutcomeInvalid || seen[result.Outcome] {
			t.Fatalf("unclassified or duplicate outcome: %#v", result)
		}
		seen[result.Outcome] = true
	}
	if len(seen) != 5 {
		t.Fatalf("outcomes = %v", seen)
	}
	if (EffectResult{}).Validate() == nil {
		t.Fatal("zero EffectResult was accepted as a no-op")
	}
}

func TestArtifactResultIsEphemeralSensitiveAndRedactedFromJSON(t *testing.T) {
	artifact := NewArtifactResult("application/octet-stream", "login.qr", []byte("secret-bytes"))
	if err := artifact.Validate(); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) == "" || containsBytes(encoded, []byte("secret-bytes")) {
		t.Fatalf("artifact bytes leaked through JSON: %s", encoded)
	}
	if !artifact.Sensitive || !artifact.Ephemeral {
		t.Fatal("artifact markers were not set")
	}
	copiedBytes := append([]byte(nil), artifact.Bytes...)
	copiedBytes[0] = 'X'
	if string(artifact.Bytes) != "secret-bytes" {
		t.Fatal("artifact constructor did not isolate byte ownership")
	}
}

func containsBytes(haystack, needle []byte) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if reflect.DeepEqual(haystack[i:i+len(needle)], needle) {
			return true
		}
	}
	return false
}

func TestDiagnosticsRequireExplicitRedactionAndBounds(t *testing.T) {
	report := DiagnosticReport{Entries: []DiagnosticEntry{{
		Severity: DiagnosticWarning,
		Code:     "auth.challenge",
		Message:  "provider requested a challenge",
		Fields:   []DiagnosticField{RedactedDiagnosticField("token")},
	}}}
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
	if report.Entries[0].Fields[0].Value != "[REDACTED]" || !report.Entries[0].Fields[0].Redacted {
		t.Fatal("diagnostic field was not visibly redacted")
	}
	unredacted := report
	unredacted.Entries[0].Fields = []DiagnosticField{{Key: "token", Value: "plaintext", Redacted: true}}
	if !errors.Is(unredacted.Validate(), ErrInvalidContract) {
		t.Fatal("invalid redaction was accepted")
	}
}

func TestGenerationFenceCannotBeSelectedInInboundOrObservation(t *testing.T) {
	inboundType := reflect.TypeOf(InboundMessage{})
	observationType := reflect.TypeOf(LifecycleObservation{})
	for _, typ := range []reflect.Type{inboundType, observationType} {
		for _, forbidden := range []string{"Generation", "DesiredVersion", "EndpointID"} {
			if _, ok := typ.FieldByName(forbidden); ok {
				t.Fatalf("%s unexpectedly contains caller-selectable fence %s", typ.Name(), forbidden)
			}
		}
	}
}

func TestInboundMessageRequiresExplicitKindAndConversationKind(t *testing.T) {
	message := InboundMessage{
		ProviderEventID: "provider-event", Kind: InboundKindMessage,
		ConversationKind: ConversationKindDirect, Sender: "user", Conversation: "direct", Target: "direct",
	}
	if err := message.Validate(); err != nil {
		t.Fatalf("explicit direct conversation rejected: %v", err)
	}
	message.Kind = InboundKindInvalid
	if !errors.Is(message.Validate(), ErrInvalidContract) {
		t.Fatal("missing inbound kind was accepted")
	}
	message.Kind = InboundKindMessage
	message.ConversationKind = ConversationKindInvalid
	if !errors.Is(message.Validate(), ErrInvalidContract) {
		t.Fatal("missing conversation kind was accepted")
	}
}

func TestInboundSenderRoleIsClosed(t *testing.T) {
	message := InboundMessage{Kind: InboundKindMessage, ConversationKind: ConversationKindGroup}
	for _, role := range []string{"", "member", "admin", "owner"} {
		message.SenderRole = role
		if err := message.Validate(); err != nil {
			t.Fatalf("valid role %q rejected: %v", role, err)
		}
	}
	message.SenderRole = "master"
	if !errors.Is(message.Validate(), ErrInvalidContract) {
		t.Fatal("provider must not be able to introduce a core-only privilege role")
	}
}

func TestOptionalTypedIDsAndIdentifierBoundsAreValidated(t *testing.T) {
	inbound := InboundMessage{
		ProviderEventID: ProviderEventID("provider-event"),
		Kind:            InboundKindMessage,
		MessageID:       MessageID("bad id"),
	}
	if !errors.Is(inbound.Validate(), ErrInvalidContract) {
		t.Fatal("invalid optional inbound MessageID was accepted")
	}
	if _, err := NewEndpointID(strings.Repeat("x", MaxIdentifierBytes+1)); !errors.Is(err, ErrInvalidID) {
		t.Fatal("oversized identifier was accepted")
	}
	if _, err := NewEndpointID(string([]byte{0xff})); !errors.Is(err, ErrInvalidID) {
		t.Fatal("invalid UTF-8 identifier was accepted")
	}

	observation := LifecycleObservation{
		Kind:       LifecycleObservationState,
		State:      ObservedStateConnected,
		ProviderID: PrincipalID("bad id"),
	}
	if !errors.Is(observation.Validate(), ErrInvalidContract) {
		t.Fatal("invalid optional lifecycle ProviderID was accepted")
	}

	artifact := NewArtifactResult("application/octet-stream", "output.bin", []byte("bytes"))
	artifact.ID = ArtifactID("bad id")
	if err := (ValidatedConfig{Version: 1, Canonical: json.RawMessage(`{}`), SecretRefs: make([]SecretRef, MaxSecretRefs+1)}).Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatal("oversized secret reference list was accepted")
	}
	if err := (ValidatedConfig{Version: 1, Canonical: json.RawMessage(strings.Repeat("x", MaxConfigBytes+1))}).Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatal("oversized canonical config was accepted")
	}
	if _, err := CanonicalizeJSON(json.RawMessage(strings.Repeat("x", MaxConfigBytes+1))); !errors.Is(err, ErrInvalidConfig) {
		t.Fatal("CanonicalizeJSON parsed oversized input before rejecting it")
	}
	if !errors.Is(artifact.Validate(), ErrInvalidContract) {
		t.Fatal("invalid optional artifact ID was accepted")
	}

	effect := OutboundEffect{ID: EffectID("effect-1"), Kind: EffectKindMessage, Target: ConversationID("bad id")}
	if !errors.Is(effect.Validate(), ErrInvalidContract) {
		t.Fatal("invalid optional effect Target was accepted")
	}
	effect.Target = ""
	effect.ReplyTo = MessageID("bad id")
	if !errors.Is(effect.Validate(), ErrInvalidContract) {
		t.Fatal("invalid optional effect ReplyTo was accepted")
	}
	if err := (EffectResult{Outcome: EffectSucceeded, ProviderID: "bad id"}).Validate(); !errors.Is(err, ErrInvalidContract) {
		t.Fatal("invalid optional effect ProviderID was accepted")
	}
	receipt := IngressReceipt{Outcome: IngressAccepted, InboxID: "bad id"}
	if !errors.Is(receipt.Validate(), ErrInvalidContract) {
		t.Fatal("invalid optional ingress InboxID was accepted")
	}
	inbound.Segments = []InboundSegment{{Kind: "text", ProviderID: "bad id"}}
	if !errors.Is(inbound.Validate(), ErrInvalidContract) {
		t.Fatal("invalid optional inbound segment ProviderID was accepted")
	}
}
