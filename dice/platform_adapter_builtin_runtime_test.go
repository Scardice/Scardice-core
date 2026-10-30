package dice

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"Scardice-core/adapterapi"
)

func TestBuiltinProcessRuntimeStartsStopsProcessAndServesQRCode(t *testing.T) {
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reservation.Addr().String()
	_ = reservation.Close()

	workDir := t.TempDir()
	qrPath := filepath.Join(workDir, "qrcode.png")
	env := append(os.Environ(),
		"SCARDICE_BUILTIN_TEST_CHILD=1",
		"SCARDICE_BUILTIN_TEST_ADDRESS="+address,
		"SCARDICE_BUILTIN_TEST_QR="+qrPath,
	)
	transport := &builtinProcessTestTransport{}
	runtime := newBuiltinProcessRuntime(
		adapterapi.RuntimeInit{
			EndpointID:     adapterapi.EndpointID("builtin-process-test"),
			Generation:     1,
			DesiredVersion: 1,
		},
		adapterapi.CapabilityLifecycle|adapterapi.CapabilityInbound|adapterapi.CapabilityOutbound|adapterapi.CapabilityActions,
		func(context.Context) (builtinProcessLaunch, error) {
			return builtinProcessLaunch{
				Command:          strconv.Quote(os.Args[0]) + " -test.run=TestBuiltinProcessChild",
				WorkDir:          workDir,
				ReadinessAddress: address,
				QRCodeFiles:      []string{"qrcode.png"},
				Env:              env,
				Transport:        transport,
			}, nil
		},
	)

	runDone := make(chan error, 1)
	go func() {
		runDone <- runtime.Run(context.Background(), builtinProcessTestCore{})
	}()

	qrContext, cancelQR := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelQR()
	result, err := runtime.ExecuteAction(qrContext, adapterapi.ActionRequest{Kind: adapterapi.ActionKindRequestQRCode})
	if err != nil {
		t.Fatalf("request QR code: %v", err)
	}
	if result.Artifact == nil || string(result.Artifact.Plaintext) != "test-qr" {
		t.Fatalf("unexpected QR artifact: %#v", result.Artifact)
	}

	stopContext, cancelStop := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelStop()
	if err := runtime.Stop(stopContext); err != nil {
		t.Fatalf("stop runtime: %v", err)
	}
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("runtime Run: %v", err)
		}
	case <-stopContext.Done():
		t.Fatal("runtime Run did not stop")
	}
}

func TestBuiltinProcessStopDuringLaunchIsNotStartupFailure(t *testing.T) {
	for _, stopRuntime := range []bool{true, false} {
		t.Run(strconv.FormatBool(stopRuntime), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			started := make(chan struct{})
			runtime := newBuiltinProcessRuntime(adapterapi.RuntimeInit{EndpointID: "stop-during-launch", Generation: 1}, adapterapi.CapabilityLifecycle,
				func(ctx context.Context) (builtinProcessLaunch, error) {
					close(started)
					<-ctx.Done()
					return builtinProcessLaunch{}, ctx.Err()
				})
			done := make(chan error, 1)
			go func() { done <- runtime.Run(ctx, builtinProcessTestCore{}) }()
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("runtime did not enter launch")
			}
			if stopRuntime {
				if err := runtime.Stop(t.Context()); err != nil {
					t.Fatal(err)
				}
			} else {
				cancel()
			}
			select {
			case err := <-done:
				if stopRuntime && err != nil {
					t.Fatalf("requested stop became a startup failure: %v", err)
				}
				if !stopRuntime && !errors.Is(err, context.Canceled) {
					t.Fatalf("parent cancellation was lost: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("runtime did not stop")
			}
		})
	}
}

func TestBuiltinProcessChild(t *testing.T) {
	if os.Getenv("SCARDICE_BUILTIN_TEST_CHILD") != "1" {
		return
	}
	listener, err := net.Listen("tcp", os.Getenv("SCARDICE_BUILTIN_TEST_ADDRESS"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.WriteFile(os.Getenv("SCARDICE_BUILTIN_TEST_QR"), []byte("test-qr"), 0o600); err != nil {
		t.Fatal(err)
	}
	for {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		_ = connection.Close()
	}
}

type builtinProcessTestTransport struct {
	stopOnce sync.Once
}

func (t *builtinProcessTestTransport) Run(ctx context.Context, _ adapterapi.CorePort) error {
	<-ctx.Done()
	return nil
}

func (t *builtinProcessTestTransport) Stop(context.Context) error {
	t.stopOnce.Do(func() {})
	return nil
}

func (t *builtinProcessTestTransport) Capabilities() adapterapi.CapabilitySet {
	return adapterapi.CapabilityLifecycle | adapterapi.CapabilityInbound | adapterapi.CapabilityOutbound
}

func (*builtinProcessTestTransport) Execute(context.Context, adapterapi.OutboundEffect) adapterapi.EffectResult {
	return adapterapi.TerminalResult("test", "test")
}

func (*builtinProcessTestTransport) Diagnostics(context.Context) adapterapi.DiagnosticReport {
	return adapterapi.DiagnosticReport{}
}

type builtinProcessTestCore struct{}

func (builtinProcessTestCore) HandleInbound(context.Context, adapterapi.InboundMessage) (adapterapi.IngressReceipt, error) {
	return adapterapi.IngressReceipt{}, nil
}

func (builtinProcessTestCore) ReportObservation(context.Context, adapterapi.LifecycleObservation) error {
	return nil
}
