// Package contracttest provides black-box adapter descriptor/runtime checks for provider tests.
package contracttest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"Scardice-core/adapterapi"
)

// Case supplies a provider-specific configuration and lifecycle exercise to
// the shared descriptor/runtime contract.
type Case struct {
	NewDescriptor                func() adapterapi.Descriptor
	Config                       json.RawMessage
	Init                         adapterapi.RuntimeInit
	SecretValues                 []string
	RequireOwnedResourceManifest bool
	Exercise                     func(context.Context, adapterapi.AdapterRuntime, *CorePort) error
}

// CorePort records normalized runtime callbacks and acknowledges ingress only
// after retaining an independent copy of the DTO.
type CorePort struct {
	mu           sync.Mutex
	observations []adapterapi.LifecycleObservation
	inbound      []adapterapi.InboundMessage
	updates      chan adapterapi.LifecycleObservation
}

func newCorePort() *CorePort {
	return &CorePort{updates: make(chan adapterapi.LifecycleObservation, 64)}
}

func (port *CorePort) HandleInbound(_ context.Context, message adapterapi.InboundMessage) (adapterapi.IngressReceipt, error) {
	port.mu.Lock()
	port.inbound = append(port.inbound, message)
	port.mu.Unlock()
	return adapterapi.IngressReceipt{Outcome: adapterapi.IngressAccepted}, nil
}

func (port *CorePort) ReportObservation(_ context.Context, observation adapterapi.LifecycleObservation) error {
	port.mu.Lock()
	port.observations = append(port.observations, observation)
	port.mu.Unlock()
	select {
	case port.updates <- observation:
		return nil
	default:
		return errors.New("adapter contract: observation buffer exhausted")
	}
}

// WaitForObservation waits for one declared lifecycle state without relying on
// sleeps, so provider exercises can establish readiness deterministically.
func (port *CorePort) WaitForObservation(state adapterapi.ObservedState, timeout time.Duration) (adapterapi.LifecycleObservation, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case observation := <-port.updates:
			if observation.State == state {
				return observation, nil
			}
		case <-timer.C:
			return adapterapi.LifecycleObservation{}, fmt.Errorf("adapter contract: timed out waiting for state %d", state)
		}
	}
}

type secretResolver struct {
	mu       sync.Mutex
	values   [][]byte
	resolved int
}

func (resolver *secretResolver) Resolve(_ context.Context, ref adapterapi.SecretRef) (adapterapi.SecretValue, error) {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	resolver.resolved++
	value := []byte("contract-secret")
	if len(resolver.values) > 0 {
		value = append([]byte(nil), resolver.values[(resolver.resolved-1)%len(resolver.values)]...)
	}
	return adapterapi.SecretValue{Bytes: value, Version: ref.Version}, nil
}

func (resolver *secretResolver) count() int {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	return resolver.resolved
}

// Verify enforces the black-box requirements shared by every provider:
// canonical validation, inert construction, valid capability/action/diagnostic
// DTOs, secret-free reports, an optional canonical cleanup manifest, and a
// provider-owned lifecycle exercise over a recording CorePort.
func Verify(t testing.TB, test Case) {
	t.Helper()
	if test.NewDescriptor == nil {
		t.Fatal("adapter contract: descriptor factory is required")
	}
	descriptor := test.NewDescriptor()
	if descriptor == nil || !descriptor.Key().Valid() || descriptor.ConfigVersion() == 0 {
		t.Fatal("adapter contract: descriptor identity is invalid")
	}
	config, err := descriptor.ValidateConfig(context.Background(), append(json.RawMessage(nil), test.Config...))
	if err != nil {
		t.Fatalf("adapter contract: validate config: %v", err)
	}
	if config.Version != descriptor.ConfigVersion() {
		t.Fatalf("adapter contract: config version = %d, want %d", config.Version, descriptor.ConfigVersion())
	}
	if validateErr := config.Validate(); validateErr != nil {
		t.Fatalf("adapter contract: validated config: %v", validateErr)
	}
	assertSecretFree(t, config.Canonical, test.SecretValues)
	if actions := descriptor.SupportedActions(config); !actions.Valid() {
		t.Fatalf("adapter contract: invalid action set %#x", actions)
	}

	init := test.Init
	init.Config = config.Clone()
	resolver := &secretResolver{values: stringsToBytes(test.SecretValues)}
	init.Secrets = resolver
	runtime, err := descriptor.NewRuntime(init)
	if err != nil {
		t.Fatalf("adapter contract: new runtime: %v", err)
	}
	if runtime == nil {
		t.Fatal("adapter contract: descriptor returned nil runtime")
	}
	if resolver.count() != 0 {
		t.Fatal("adapter contract: runtime resolved a secret during construction")
	}
	if capabilities := runtime.Capabilities(); !capabilities.Valid() {
		t.Fatalf("adapter contract: invalid capability set %#x", capabilities)
	}
	if test.RequireOwnedResourceManifest {
		manifestRuntime, ok := runtime.(adapterapi.OwnedResourceManifestRuntime)
		if !ok {
			t.Fatal("adapter contract: runtime does not declare owned resources")
		}
		manifest := manifestRuntime.OwnedResources()
		if validateErr := manifest.Validate(); validateErr != nil {
			t.Fatalf("adapter contract: owned resources: %v", validateErr)
		}
		encoded, marshalErr := json.Marshal(manifest)
		if marshalErr != nil {
			t.Fatalf("adapter contract: encode owned resources: %v", marshalErr)
		}
		assertSecretFree(t, encoded, test.SecretValues)
	}
	if test.Exercise != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if exerciseErr := test.Exercise(ctx, runtime, newCorePort()); exerciseErr != nil {
			t.Fatalf("adapter contract: lifecycle exercise: %v", exerciseErr)
		}
	}
	if validateErr := runtime.Diagnostics(context.Background()).Validate(); validateErr != nil {
		t.Fatalf("adapter contract: diagnostics: %v", validateErr)
	}
	encodedDiagnostics, err := json.Marshal(runtime.Diagnostics(context.Background()))
	if err != nil {
		t.Fatalf("adapter contract: encode diagnostics: %v", err)
	}
	assertSecretFree(t, encodedDiagnostics, test.SecretValues)
}

func stringsToBytes(values []string) [][]byte {
	result := make([][]byte, 0, len(values))
	for _, value := range values {
		if value != "" {
			result = append(result, []byte(value))
		}
	}
	return result
}

func assertSecretFree(t testing.TB, value []byte, secrets []string) {
	t.Helper()
	for _, secret := range secrets {
		if secret != "" && strings.Contains(string(value), secret) {
			t.Fatalf("adapter contract: secret %q leaked through boundary", secret)
		}
	}
}
