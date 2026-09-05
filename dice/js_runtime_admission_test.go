package dice

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"Scardice-core/utils/jsengine"
	"Scardice-core/utils/jsengine/services"
)

var diceRuntimeAdmissionCapabilities = jsengine.CapabilityScript

type admissionTestLoop struct {
	descriptor    jsengine.Descriptor
	closed        int
	registry      *services.Registry
	closeOrderErr error
}

func (l *admissionTestLoop) Engine() jsengine.EngineID              { return l.descriptor.ID }
func (l *admissionTestLoop) Descriptor() jsengine.Descriptor        { return l.descriptor }
func (l *admissionTestLoop) Run(func(jsengine.Runtime) error) error { return nil }
func (l *admissionTestLoop) LoadEntry(jsengine.Entry) error         { return nil }
func (l *admissionTestLoop) Close() error {
	l.closed++
	if l.registry != nil {
		probe := &admissionTestService{}
		if err := l.registry.Register(probe); !errors.Is(err, services.ErrRegistryClosed) {
			l.closeOrderErr = fmt.Errorf("service registry was not closed before loop: %w", err)
		}
	}
	return l.closeOrderErr
}

type admissionTestProvider struct {
	descriptor jsengine.Descriptor
	opened     *bool
	loop       jsengine.Loop
}

func (p admissionTestProvider) Descriptor() jsengine.Descriptor { return p.descriptor }
func (p admissionTestProvider) Open(context.Context, jsengine.RuntimeOptions) (jsengine.Loop, error) {
	*p.opened = true
	return p.loop, nil
}

type admissionTestService struct{}

func (admissionTestService) Definition() services.Definition {
	return services.Definition{Name: "admission-test", Operations: []services.OperationID{1}}
}
func (admissionTestService) Invoke(services.Call) (services.Response, error) {
	return services.Response{Status: services.StatusOK}, nil
}

func diceRuntimeRequirements() jsengine.RuntimeRequirements {
	return jsengine.RuntimeRequirements{
		RequiredCapabilities:      diceRuntimeAdmissionCapabilities,
		RequireContextPropagation: true,
	}
}

func TestJSRuntimeManagerRejectsProviderBeforeOpen(t *testing.T) {
	opened := false
	provider := admissionTestProvider{
		descriptor: jsengine.Descriptor{ID: "missing-context", Capabilities: jsengine.CapabilityScript},
		opened:     &opened,
	}
	manager := NewJSRuntimeManager(t.TempDir())
	manager.providers[provider.descriptor.ID] = provider
	manager.requirements = diceRuntimeRequirements()

	_, err := manager.Resolve(context.Background(), provider.descriptor.ID, jsengine.RuntimeOptions{})
	if !errors.Is(err, jsengine.ErrRuntimeRequirements) {
		t.Fatalf("Resolve() error = %v, want runtime requirements error", err)
	}
	if opened {
		t.Fatal("provider opened before admission succeeded")
	}
}

func TestJSRuntimeManagerRejectsOpenedLoopWithoutContextInterface(t *testing.T) {
	opened := false
	loop := &admissionTestLoop{descriptor: jsengine.Descriptor{
		ID:           "missing-context-interface",
		Capabilities: diceRuntimeAdmissionCapabilities | jsengine.CapabilityContextPropagation,
	}}
	provider := admissionTestProvider{
		descriptor: loop.descriptor,
		opened:     &opened,
		loop:       loop,
	}
	manager := NewJSRuntimeManager(t.TempDir())
	manager.providers[provider.descriptor.ID] = provider
	manager.requirements = diceRuntimeRequirements()

	_, err := manager.Resolve(context.Background(), provider.descriptor.ID, jsengine.RuntimeOptions{})
	if !errors.Is(err, jsengine.ErrRuntimeRequirements) {
		t.Fatalf("Resolve() error = %v, want runtime requirements error", err)
	}
	if !opened || loop.closed != 1 {
		t.Fatalf("provider opened=%v, loop closes=%d; want true and 1", opened, loop.closed)
	}
}

func TestJSRuntimeInstanceClosesRegistriesBeforeLoopOnce(t *testing.T) {
	registry := services.NewRegistry()
	loop := &admissionTestLoop{
		descriptor: jsengine.Descriptor{ID: "owned"},
		registry:   registry,
	}
	instance := newJSRuntimeInstance(loop, registry)

	if err := instance.Close(); err != nil {
		t.Fatal(err)
	}
	if loop.closed != 1 || loop.closeOrderErr != nil {
		t.Fatalf("loop closed=%d, close order error=%v; want one close after registry", loop.closed, loop.closeOrderErr)
	}
	if err := instance.Close(); err != nil {
		t.Fatal(err)
	}
	if loop.closed != 1 {
		t.Fatalf("loop closed=%d after repeated instance close, want 1", loop.closed)
	}
}
