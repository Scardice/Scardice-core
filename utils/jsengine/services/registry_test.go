package services_test

import (
	"errors"
	"testing"
	"time"

	"Scardice-core/dice/sealpack"
	"Scardice-core/utils/jsengine"
	"Scardice-core/utils/jsengine/services"
)

type testService struct {
	definition services.Definition
	called     bool
}

func (s *testService) Definition() services.Definition { return s.definition }
func (s *testService) Invoke(call services.Call) (services.Response, error) {
	s.called = true
	return services.Response{Status: services.StatusOK, String: call.Request.String}, nil
}

type testInstaller struct {
	owner     string
	defs      []services.Definition
	installed bool
	closed    int
}

func (i *testInstaller) Owner() string                      { return i.owner }
func (i *testInstaller) Definitions() []services.Definition { return i.defs }
func (i *testInstaller) Install() error                     { i.installed = true; return nil }
func (i *testInstaller) Close() error                       { i.closed++; return nil }

func TestRegistryRejectsDuplicateAndReportsMissingService(t *testing.T) {
	registry := services.NewRegistry()
	first := &testService{definition: services.Definition{
		Name:       services.Console,
		Operations: []services.OperationID{services.OpConsoleLog},
	}}
	if err := registry.Register(first); err != nil {
		t.Fatalf("Register(first) error = %v", err)
	}
	if err := registry.Register(&testService{definition: first.definition}); !errors.Is(err, services.ErrDuplicateService) {
		t.Fatalf("Register(duplicate) error = %v, want ErrDuplicateService", err)
	}
	if _, err := registry.Lookup(services.Filesystem); !errors.Is(err, services.ErrServiceNotFound) {
		t.Fatalf("Lookup(missing) error = %v, want ErrServiceNotFound", err)
	}
	if got := registry.Names(); len(got) != 1 || got[0] != services.Console {
		t.Fatalf("Names() = %#v, want [console]", got)
	}
}

func TestRegistryEnforcesPermissionDeadlineAndCancellation(t *testing.T) {
	registry := services.NewRegistry()
	service := &testService{definition: services.Definition{
		Name:       services.Filesystem,
		Operations: []services.OperationID{services.OpFilesystemReadFile},
	}}
	if err := registry.Register(service); err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	denied, err := registry.Invoke(services.Call{Request: services.Request{
		Service:   services.Filesystem,
		Operation: services.OpFilesystemReadFile,
		String:    "secret.txt",
	}})
	if !errors.Is(err, services.ErrPermissionDenied) || denied.Status != services.StatusPermissionDenied {
		t.Fatalf("Invoke(denied) = %#v, %v; want permission denied", denied, err)
	}
	policy := services.Policy{Sandbox: sealpack.NewSandbox("pkg", &sealpack.Permissions{
		FileRead: []string{"**"},
	}, base, t.TempDir())}
	if _, err := registry.Invoke(services.Call{Request: services.Request{
		Service:   services.Filesystem,
		Operation: services.OpFilesystemReadFile,
		String:    "secret.txt",
	}, Policy: policy}); err != nil {
		t.Fatalf("Invoke(permission) error = %v", err)
	}
	if !service.called {
		t.Fatal("service was not invoked after policy check")
	}
	deadline := time.Now().Add(-time.Second)
	if _, err := registry.Invoke(services.Call{Request: services.Request{
		Service:   services.Filesystem,
		Operation: services.OpFilesystemReadFile,
	}, Policy: policy, Deadline: deadline}); !errors.Is(err, services.ErrDeadlineExceeded) {
		t.Fatalf("Invoke(deadline) error = %v, want ErrDeadlineExceeded", err)
	}
	cancel := make(chan struct{})
	close(cancel)
	if _, err := registry.Invoke(services.Call{Request: services.Request{
		Service:   services.Filesystem,
		Operation: services.OpFilesystemReadFile,
	}, Policy: policy, Cancellation: cancel}); !errors.Is(err, services.ErrCancelled) {
		t.Fatalf("Invoke(cancel) error = %v, want ErrCancelled", err)
	}
}

func TestRegistryInstallationOwnsServicesAndClosesExactlyOnce(t *testing.T) {
	registry := services.NewRegistry()
	installer := &testInstaller{
		owner: "goja",
		defs: []services.Definition{{
			Name:       services.Console,
			Operations: []services.OperationID{services.OpConsoleLog},
		}},
	}
	installation, err := registry.Install(installer)
	if err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	if !installer.installed || installation.Owner() != "goja" {
		t.Fatalf("installation = %#v, installed = %v", installation, installer.installed)
	}
	if _, err := registry.Lookup(services.Console); err != nil {
		t.Fatalf("Lookup(installed) error = %v", err)
	}
	if err := installation.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := installation.Close(); err != nil {
		t.Fatalf("Close(second) error = %v", err)
	}
	if installer.closed != 1 {
		t.Fatalf("installer closed %d times, want 1", installer.closed)
	}
	if _, err := registry.Lookup(services.Console); !errors.Is(err, services.ErrServiceNotFound) {
		t.Fatalf("Lookup(after close) error = %v, want ErrServiceNotFound", err)
	}
}

func TestRegistryReturnsUnsupportedForAdapterOnlyService(t *testing.T) {
	registry := services.NewRegistry()
	installer := &testInstaller{
		owner: "goja",
		defs: []services.Definition{{
			Name:       services.StructuredClone,
			Operations: []services.OperationID{services.OpStructuredClone},
			Adapter:    "goja",
		}},
	}
	if _, err := registry.Install(installer); err != nil {
		t.Fatal(err)
	}
	_, err := registry.Invoke(services.Call{Request: services.Request{
		Service:   services.StructuredClone,
		Operation: services.OpStructuredClone,
	}})
	if !errors.Is(err, services.ErrUnsupported) {
		t.Fatalf("Invoke(adapter-only) error = %v, want ErrUnsupported", err)
	}
}

func TestNativeDescriptorDoesNotAdvertiseServices(t *testing.T) {
	descriptor := jsengine.Descriptor{ID: "quickjs"}
	if got := services.Advertised(descriptor); len(got) != 0 {
		t.Fatalf("Advertised(native) = %#v, want empty", got)
	}
	if err := services.RequireNativeService(descriptor, services.Fetch); !errors.Is(err, services.ErrUnsupported) {
		t.Fatalf("RequireNativeService() error = %v, want ErrUnsupported", err)
	}
}
