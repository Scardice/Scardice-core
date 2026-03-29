package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"strings"

	"golang.org/x/crypto/ssh"
)

func normalizePEMText(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	if !strings.Contains(key, "\n") {
		key = strings.ReplaceAll(key, `\r\n`, "\n")
		key = strings.ReplaceAll(key, `\n`, "\n")
	}
	return key
}

// ReadPublicKey 读取公钥
func ReadPublicKey[T any](publicKey string) *T {
	publicKey = normalizePEMText(publicKey)
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return nil
	}
	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil
	}
	key, ok := publicKeyInterface.(*T)
	if !ok {
		return nil
	}
	return key
}

// ReadSshPublicKey 读取 ssh 格式的公钥
func ReadSshPublicKey[T any](publicKey string) *T {
	parsed, _ := ssh.ParsePublicKey([]byte(publicKey))
	parsedCryptoKey := parsed.(ssh.CryptoPublicKey)
	cryptoKey := parsedCryptoKey.CryptoPublicKey()
	key := cryptoKey.(*T)
	return key
}

// ReadPrivateKey 读取私钥
func ReadPrivateKey[T any](privateKey string) *T {
	privateKey = normalizePEMText(privateKey)
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		return nil
	}
	privateKeyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil
	}
	key, ok := privateKeyInterface.(*T)
	if !ok {
		return nil
	}
	return key
}
