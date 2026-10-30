package eventstore

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestCryptoKnownVector(t *testing.T) {
	source := newTestKeySource()
	got, err := a6HMAC(context.Background(), source, "plugin-key-index/v1", "ext", "key")
	if err != nil {
		t.Fatal(err)
	}
	const want = "0c8ff04fa7aed3f959d1149243a62e586c79c8a4ccc5f8283abd5c00c0f71b88"
	if hex.EncodeToString(got) != want {
		t.Fatalf("HMAC vector=%x want=%s", got, want)
	}
}
func TestA6CryptoRoundTripAndAuthentication(t *testing.T) {
	source := newTestKeySource()
	ciphertext, nonce, keyID, err := a6Seal(context.Background(), source, "adapter-secret/v1", "secret-ref", "endpoint/adapter", 1, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if keyID != "root-v1" || string(ciphertext) == "secret" || len(nonce) != 12 {
		t.Fatalf("crypto output key=%q nonce=%d ciphertext=%q", keyID, len(nonce), ciphertext)
	}
	plain, err := a6Open(context.Background(), source, "adapter-secret/v1", "secret-ref", "endpoint/adapter", 1, keyID, ciphertext, nonce)
	if err != nil || string(plain) != "secret" {
		t.Fatalf("round trip plaintext=%q err=%v", plain, err)
	}
	if _, err := a6Open(context.Background(), source, "adapter-secret/v1", "other-ref", "endpoint/adapter", 1, keyID, ciphertext, nonce); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("wrong AAD err=%v", err)
	}
}
func TestKeyFileSecurity(t *testing.T) {
	if os.Getenv("GOOS") == "windows" {
		t.Skip("Unix key file contract")
	}
	path := filepath.Join(t.TempDir(), "root.key")
	material := []byte("01234567890123456789012345678901")
	if err := CreateLocalKeyFile(path, material); err != nil {
		t.Fatal(err)
	}
	got, err := readKeyFile(path)
	if err != nil || string(got) != string(material) {
		t.Fatalf("key read=%q err=%v", got, err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readKeyFile(path); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("insecure mode err=%v", err)
	}
}
func TestLocalFileKeySourceCachesIndexRootAfterFirstSuccessfulRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix key-file cache contract")
	}
	path := filepath.Join(t.TempDir(), "index.key")
	material := []byte("01234567890123456789012345678901")
	if err := CreateLocalKeyFile(path, material); err != nil {
		t.Fatal(err)
	}
	source := NewLocalFileKeySource(path, "")
	first, err := source.IndexRootMaterial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	first[0] ^= 0xff
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chmod(path, 0o600); err != nil {
			t.Errorf("restore key permissions: %v", err)
		}
	}()
	second, err := source.IndexRootMaterial(context.Background())
	if err != nil {
		t.Fatalf("cached index root became unavailable: %v", err)
	}
	if !bytes.Equal(second, material) {
		t.Fatalf("cached index root=%x want=%x", second, material)
	}
}
func TestLocalFileKeySourceRefreshesEncryptionRootAfterTTL(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix key-file cache contract")
	}
	rootsDir := t.TempDir()
	path := filepath.Join(rootsDir, "root-a.key")
	firstMaterial := []byte("01234567890123456789012345678901")
	secondMaterial := []byte("abcdefghijklmnopqrstuvwxyz123456")
	if err := CreateLocalKeyFile(path, firstMaterial); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0)
	source := NewLocalFileKeySource("", rootsDir)
	source.cacheTTL = time.Minute
	source.now = func() time.Time { return now }
	first, err := source.EncryptionRoot(context.Background(), "root-a")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, firstMaterial) {
		t.Fatalf("first root=%x want=%x", first, firstMaterial)
	}
	if err := os.WriteFile(path, secondMaterial, 0o600); err != nil {
		t.Fatal(err)
	}
	cached, err := source.EncryptionRoot(context.Background(), "root-a")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cached, firstMaterial) {
		t.Fatalf("root changed before TTL: got=%x want=%x", cached, firstMaterial)
	}
	now = now.Add(2 * time.Minute)
	refreshed, err := source.EncryptionRoot(context.Background(), "root-a")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(refreshed, secondMaterial) {
		t.Fatalf("root did not refresh after TTL: got=%x want=%x", refreshed, secondMaterial)
	}
}
func TestLocalFileKeySourceRefreshesCurrentRootIDAfterTTL(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix key-file cache contract")
	}
	rootsDir := t.TempDir()
	rootA := []byte("01234567890123456789012345678901")
	rootB := []byte("abcdefghijklmnopqrstuvwxyz123456")
	if err := CreateLocalKeyFile(filepath.Join(rootsDir, "root-a.key"), rootA); err != nil {
		t.Fatal(err)
	}
	if err := CreateLocalKeyFile(filepath.Join(rootsDir, "root-b.key"), rootB); err != nil {
		t.Fatal(err)
	}
	currentPath := filepath.Join(rootsDir, "current")
	if err := os.WriteFile(currentPath, []byte("root-a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0)
	source := NewLocalFileKeySource("", rootsDir)
	source.cacheTTL = time.Minute
	source.now = func() time.Time { return now }
	first, err := source.CurrentEncryptionRoot(context.Background())
	if err != nil || first.ID != "root-a" || !bytes.Equal(first.Material, rootA) {
		t.Fatalf("first current root=%#v err=%v", first, err)
	}
	if err := os.WriteFile(currentPath, []byte("root-b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cached, err := source.CurrentEncryptionRoot(context.Background())
	if err != nil || cached.ID != "root-a" || !bytes.Equal(cached.Material, rootA) {
		t.Fatalf("current root changed before TTL=%#v err=%v", cached, err)
	}
	now = now.Add(2 * time.Minute)
	refreshed, err := source.CurrentEncryptionRoot(context.Background())
	if err != nil || refreshed.ID != "root-b" || !bytes.Equal(refreshed.Material, rootB) {
		t.Fatalf("current root did not refresh=%#v err=%v", refreshed, err)
	}
}
func TestLocalFileKeySourceConcurrentCacheAccess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix key-file cache contract")
	}
	dir := t.TempDir()
	indexMaterial := []byte("01234567890123456789012345678901")
	rootMaterial := []byte("abcdefghijklmnopqrstuvwxyz123456")
	indexPath := filepath.Join(dir, "index.key")
	rootsDir := filepath.Join(dir, "roots")
	if err := os.Mkdir(rootsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := CreateLocalKeyFile(indexPath, indexMaterial); err != nil {
		t.Fatal(err)
	}
	if err := CreateLocalKeyFile(filepath.Join(rootsDir, "root-a.key"), rootMaterial); err != nil {
		t.Fatal(err)
	}
	source := NewLocalFileKeySource(indexPath, rootsDir)
	source.CurrentID = "root-a"

	const workers = 32
	errs := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for range 100 {
				index, err := source.IndexRootMaterial(context.Background())
				if err != nil || !bytes.Equal(index, indexMaterial) {
					errs <- fmt.Errorf("index root=%x err=%w", index, err)
					return
				}
				root, err := source.CurrentEncryptionRoot(context.Background())
				if err != nil || root.ID != "root-a" || !bytes.Equal(root.Material, rootMaterial) {
					errs <- fmt.Errorf("encryption root=%#v err=%w", root, err)
					return
				}
			}
		}()
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
func TestUnixKeySourceUsesExplicitCurrentRoot(t *testing.T) {
	if os.Getenv("GOOS") == "windows" {
		t.Skip("Unix key source contract")
	}
	dir := t.TempDir()
	indexPath := filepath.Join(dir, "index.key")
	if err := CreateLocalKeyFile(indexPath, []byte("01234567890123456789012345678901")); err != nil {
		t.Fatal(err)
	}
	roots := filepath.Join(dir, "roots")
	if err := os.Mkdir(roots, 0700); err != nil {
		t.Fatal(err)
	}
	if err := CreateLocalKeyFile(filepath.Join(roots, "root-a.key"), []byte("abcdefghijklmnopqrstuvwxyz123456")); err != nil {
		t.Fatal(err)
	}
	if err := CreateLocalKeyFile(filepath.Join(roots, "root-z.key"), []byte("12345678901234567890123456789012")); err != nil {
		t.Fatal(err)
	}
	current := filepath.Join(roots, "current")
	if err := os.WriteFile(current, []byte("root-a"), 0600); err != nil {
		t.Fatal(err)
	}
	source := NewLocalFileKeySource(indexPath, roots)
	root, err := source.CurrentEncryptionRoot(context.Background())
	if err != nil || root.ID != "root-a" {
		t.Fatalf("current root=%#v err=%v", root, err)
	}
}
