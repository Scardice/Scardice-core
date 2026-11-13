package dice

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"testing"

	"golang.org/x/crypto/ed25519"
)

type nilVerifyLogger struct{}

func (nilVerifyLogger) Warn(...any)          {}
func (nilVerifyLogger) Warnf(string, ...any) {}
func (nilVerifyLogger) Infof(string, ...any) {}

func makeECDSAPrivateKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func TestNormalizeTrustedPrivateKeyRepairsEscapedNewlines(t *testing.T) {
	pemKey := makeECDSAPrivateKeyPEM(t)
	escaped := strings.ReplaceAll(strings.TrimSpace(pemKey), "\n", `\n`)

	normalized, ok := normalizeTrustedPrivateKey(escaped, nilVerifyLogger{}, "test")
	if !ok {
		t.Fatal("expected escaped pem to be repaired")
	}
	if !isTrustedPrivateKeyValid(normalized) {
		t.Fatal("expected normalized pem to validate")
	}
}

func TestNormalizeTrustedPrivateKeyDecodesBase64Payload(t *testing.T) {
	pemKey := makeECDSAPrivateKeyPEM(t)
	encoded := trustedKeyBase64Prefix + base64.StdEncoding.EncodeToString([]byte(strings.TrimSpace(pemKey)))

	normalized, ok := normalizeTrustedPrivateKey(encoded, nilVerifyLogger{}, "test")
	if !ok {
		t.Fatal("expected base64 pem to decode")
	}
	if !isTrustedPrivateKeyValid(normalized) {
		t.Fatal("expected decoded pem to validate")
	}
}

func TestNormalizeSignPrivateKeyRepairsWhitespace(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate sign key: %v", err)
	}
	raw := hex.EncodeToString(key)
	withWhitespace := raw[:16] + "\n" + raw[16:32] + "  " + raw[32:]

	normalized, ok := normalizeSignPrivateKey(withWhitespace, nilVerifyLogger{}, "test")
	if !ok {
		t.Fatal("expected sign key whitespace repair to succeed")
	}
	if normalized != raw {
		t.Fatal("expected sign key whitespace to be stripped")
	}
}
