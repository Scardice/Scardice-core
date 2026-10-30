package dice

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"Scardice-core/utils/jsengine/services"
)

type nativeFilesystemTestSink struct {
	complete chan services.Response
}

func (s *nativeFilesystemTestSink) Event(services.RequestID, services.Response) error { return nil }
func (s *nativeFilesystemTestSink) Complete(_ services.RequestID, response services.Response) error {
	s.complete <- response
	return nil
}
func (s *nativeFilesystemTestSink) Close(_ services.RequestID, response services.Response) error {
	s.complete <- response
	return nil
}

func TestNativeFilesystemServiceReadFile(t *testing.T) {
	root := t.TempDir()
	filename := filepath.Join(root, "fixture.txt")
	if err := os.WriteFile(filename, []byte("native fs"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := &Dice{BaseConfig: BaseConfig{DataDir: root}}
	d.AdvancedConfig.AllowFilesystemUnrestrictedAccess = true
	service := &nativeFilesystemService{dice: d}
	sink := &nativeFilesystemTestSink{complete: make(chan services.Response, 1)}
	if err := service.Start(services.AsyncCall{
		ID: 1,
		Call: services.Call{Request: services.Request{
			Service:   services.Filesystem,
			Operation: services.OpFilesystemReadFile,
			String:    filename,
		}},
		Sink: sink,
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case response := <-sink.complete:
		if response.Status != services.StatusOK || string(response.Bytes) != "native fs" {
			t.Fatalf("filesystem response = %#v, want successful fixture read", response)
		}
	case <-time.After(time.Second):
		t.Fatal("filesystem service did not complete")
	}
}

func TestNativeFilesystemServiceSyncReadWrite(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "sync.txt")
	d := &Dice{BaseConfig: BaseConfig{DataDir: root}}
	d.AdvancedConfig.AllowFilesystemUnrestrictedAccess = true
	service := &nativeFilesystemService{dice: d}

	if response, err := service.Invoke(services.Call{Request: services.Request{
		Service:   services.Filesystem,
		Operation: services.OpFilesystemWriteFileSync,
		String:    target,
		Bytes:     []byte("sync fs"),
	}}); err != nil || response.Status != services.StatusOK {
		t.Fatalf("sync filesystem write = %#v, %v; want success", response, err)
	}
	response, err := service.Invoke(services.Call{Request: services.Request{
		Service:   services.Filesystem,
		Operation: services.OpFilesystemReadFileSync,
		String:    target,
	}})
	if err != nil || response.Status != services.StatusOK || string(response.Bytes) != "sync fs" {
		t.Fatalf("sync filesystem read = %#v, %v; want sync fs", response, err)
	}
}

func TestNativeFilesystemServiceSyncLargeUnlimitedAndExplicitLimit(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "large.bin")
	const size = 16*1024*1024 + 1
	payload := make([]byte, size)
	payload[0] = 0x5a
	payload[len(payload)-1] = 0xa5
	d := &Dice{BaseConfig: BaseConfig{DataDir: root}}
	d.AdvancedConfig.AllowFilesystemUnrestrictedAccess = true
	service := &nativeFilesystemService{dice: d}

	if response, err := service.Invoke(services.Call{Request: services.Request{
		Service:   services.Filesystem,
		Operation: services.OpFilesystemWriteFileSync,
		String:    target,
		Bytes:     payload,
	}}); err != nil || response.Status != services.StatusOK {
		t.Fatalf("unlimited sync filesystem write = %#v, %v; want success", response, err)
	}
	response, err := service.Invoke(services.Call{Request: services.Request{
		Service:   services.Filesystem,
		Operation: services.OpFilesystemReadFileSync,
		String:    target,
	}})
	if err != nil || response.Status != services.StatusOK ||
		len(response.Bytes) != size || response.Bytes[0] != 0x5a ||
		response.Bytes[len(response.Bytes)-1] != 0xa5 {
		t.Fatalf("unlimited sync filesystem read = status %v, bytes %d, err %v; want %d bytes", response.Status, len(response.Bytes), err, size)
	}

	d.Config.QuickJSMaxFilesystemReadMiB = 1
	response, err = service.Invoke(services.Call{Request: services.Request{
		Service:   services.Filesystem,
		Operation: services.OpFilesystemReadFileSync,
		String:    target,
	}})
	if err == nil || response.Status != services.StatusInvalid {
		t.Fatalf("explicit sync filesystem read = %#v, %v; want invalid over-limit response", response, err)
	}
	d.Config.QuickJSMaxFilesystemWriteMiB = 1
	response, err = service.Invoke(services.Call{Request: services.Request{
		Service:   services.Filesystem,
		Operation: services.OpFilesystemWriteFileSync,
		String:    filepath.Join(root, "limited.bin"),
		Bytes:     payload,
	}})
	if err == nil || response.Status != services.StatusInternal {
		t.Fatalf("explicit sync filesystem write = %#v, %v; want internal over-limit response", response, err)
	}
}
