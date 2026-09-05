package dice

import (
	"bytes"
	"encoding/hex"
	"testing"

	"Scardice-core/utils/jsengine/services"
)

func TestNativeCryptoServiceDigest(t *testing.T) {
	service := &nativeCryptoService{}
	response, err := service.Invoke(services.Call{Request: services.Request{
		Service:   services.Crypto,
		Operation: services.OpCryptoDigest,
		String:    "SHA-256",
		Bytes:     []byte("abc"),
	}})
	if err != nil {
		t.Fatalf("digest() error = %v", err)
	}
	if response.Status != services.StatusOK {
		t.Fatalf("digest() status = %v, want %v", response.Status, services.StatusOK)
	}
	want, _ := hex.DecodeString("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
	if !bytes.Equal(response.Bytes, want) {
		t.Fatalf("digest() = %x, want %x", response.Bytes, want)
	}
}

func TestNativeCryptoServiceRandomBytes(t *testing.T) {
	service := &nativeCryptoService{}
	response, err := service.Invoke(services.Call{Request: services.Request{
		Service:   services.Crypto,
		Operation: services.OpCryptoRandomBytes,
		Uint64:    32,
	}})
	if err != nil {
		t.Fatalf("random() error = %v", err)
	}
	if response.Status != services.StatusOK {
		t.Fatalf("random() status = %v, want %v", response.Status, services.StatusOK)
	}
	if len(response.Bytes) != 32 {
		t.Fatalf("random() length = %d, want 32", len(response.Bytes))
	}
}

func TestNativeCryptoServiceRejectsUnsupportedOperation(t *testing.T) {
	service := &nativeCryptoService{}
	response, err := service.Invoke(services.Call{Request: services.Request{
		Service:   services.Crypto,
		Operation: services.OpCryptoDigest,
		String:    "SHA-999",
	}})
	if err == nil {
		t.Fatal("unsupported digest error = nil")
	}
	if response.Status != services.StatusUnsupported {
		t.Fatalf("unsupported digest status = %v, want %v", response.Status, services.StatusUnsupported)
	}
}
