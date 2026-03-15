//nolint:gosec // WebCrypto compatibility keeps legacy hash options for existing scripts.
package sealcrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

type encodedNode struct {
	T string          `json:"t"`
	V json.RawMessage `json:"v"`
}

type KeyRef struct {
	ID string
}

type keyPublic struct {
	ID          string
	Type        string
	Extractable bool
	Algorithm   map[string]any
	Usages      []string
}

type cryptoKey struct {
	ID          string
	Type        string
	Extractable bool
	Algorithm   map[string]any
	Usages      []string

	SecretKey []byte
	HMACHash  string

	RSAPublic  *rsa.PublicKey
	RSAPrivate *rsa.PrivateKey

	ECDSAPublic  *ecdsa.PublicKey
	ECDSAPrivate *ecdsa.PrivateKey
	ECDHPublic   *ecdsa.PublicKey
	ECDHPrivate  *ecdsa.PrivateKey

	Ed25519Public  ed25519.PublicKey
	Ed25519Private ed25519.PrivateKey
	X25519Public   *ecdh.PublicKey
	X25519Private  *ecdh.PrivateKey
}

type KeyStore struct {
	mu   sync.RWMutex
	seq  atomic.Uint64
	keys map[string]*cryptoKey
}

func NewKeyStore() *KeyStore {
	return &KeyStore{
		keys: map[string]*cryptoKey{},
	}
}

func (s *KeyStore) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = map[string]*cryptoKey{}
	s.seq.Store(0)
}

func (s *KeyStore) CallJSON(op string, argsJSON string) (string, error) {
	rawArgs := []json.RawMessage{}
	if strings.TrimSpace(argsJSON) != "" {
		if err := json.Unmarshal([]byte(argsJSON), &rawArgs); err != nil {
			return "", fmt.Errorf("invalid subtle args: %w", err)
		}
	}
	args := make([]any, 0, len(rawArgs))
	for _, raw := range rawArgs {
		v, err := decodeNode(raw)
		if err != nil {
			return "", err
		}
		args = append(args, v)
	}

	out, err := s.call(strings.TrimSpace(op), args)
	if err != nil {
		return "", err
	}
	node, err := encodeNode(out)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(node)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func (s *KeyStore) call(op string, args []any) (any, error) {
	switch op {
	case "digest":
		return s.opDigest(args)
	case "generateKey":
		return s.opGenerateKey(args)
	case "importKey":
		return s.opImportKey(args)
	case "exportKey":
		return s.opExportKey(args)
	case "sign":
		return s.opSign(args)
	case "verify":
		return s.opVerify(args)
	case "encrypt":
		return s.opEncrypt(args)
	case "decrypt":
		return s.opDecrypt(args)
	case "deriveBits":
		return s.opDeriveBits(args)
	case "deriveKey":
		return s.opDeriveKey(args)
	case "wrapKey":
		return s.opWrapKey(args)
	case "unwrapKey":
		return s.opUnwrapKey(args)
	default:
		return nil, fmt.Errorf("unsupported subtle method: %s", op)
	}
}

func (s *KeyStore) opDigest(args []any) (any, error) {
	if len(args) < 2 {
		return nil, errors.New("crypto.subtle.digest: missing args")
	}
	alg, _, err := parseAlgorithmIdentifier(args[0])
	if err != nil {
		return nil, err
	}
	data, err := requireBytes(args[1], "data")
	if err != nil {
		return nil, err
	}
	return digestBytes(alg, data)
}

func (s *KeyStore) opGenerateKey(args []any) (any, error) {
	if len(args) < 3 {
		return nil, errors.New("crypto.subtle.generateKey: missing args")
	}
	algorithm, algObj, err := parseAlgorithmIdentifier(args[0])
	if err != nil {
		return nil, err
	}
	extractable, err := toBool(args[1], "extractable")
	if err != nil {
		return nil, err
	}
	usages, err := toStringSlice(args[2], "keyUsages")
	if err != nil {
		return nil, err
	}

	switch algorithm {
	case "AES-CBC", "AES-GCM", "AES-CTR", "AES-KW":
		length, err := intField(algObj, "length", true, 0)
		if err != nil {
			return nil, err
		}
		if length != 128 && length != 192 && length != 256 {
			return nil, errors.New("AES key length must be 128, 192, or 256")
		}
		key := make([]byte, length/8)
		if _, err = rand.Read(key); err != nil {
			return nil, err
		}
		stored := &cryptoKey{
			Type:        "secret",
			Extractable: extractable,
			Algorithm: map[string]any{
				"name":   algorithm,
				"length": length,
			},
			Usages:    append([]string{}, usages...),
			SecretKey: key,
		}
		return s.saveKey(stored), nil
	case "HMAC":
		hashName, err := hashFromAlgorithmObject(algObj, "SHA-256")
		if err != nil {
			return nil, err
		}
		length, err := intField(algObj, "length", false, 0)
		if err != nil {
			return nil, err
		}
		if length <= 0 {
			length = digestLengthBytes(hashName) * 8
		}
		key := make([]byte, length/8)
		if _, err = rand.Read(key); err != nil {
			return nil, err
		}
		stored := &cryptoKey{
			Type:        "secret",
			Extractable: extractable,
			Algorithm: map[string]any{
				"name":   "HMAC",
				"hash":   map[string]any{"name": hashName},
				"length": length,
			},
			Usages:    append([]string{}, usages...),
			SecretKey: key,
			HMACHash:  hashName,
		}
		return s.saveKey(stored), nil
	case "DES-CBC":
		length := 64
		if algObj != nil {
			if v, ok := algObj["length"]; ok {
				length, err = toInt(v, "algorithm.length")
				if err != nil {
					return nil, err
				}
			}
		}
		if length != 64 {
			return nil, errors.New("DES-CBC key length must be 64")
		}
		key := make([]byte, 8)
		if _, err = rand.Read(key); err != nil {
			return nil, err
		}
		stored := &cryptoKey{
			Type:        "secret",
			Extractable: extractable,
			Algorithm: map[string]any{
				"name":   "DES-CBC",
				"length": 64,
			},
			Usages:    append([]string{}, usages...),
			SecretKey: key,
		}
		return s.saveKey(stored), nil
	case "3DES-CBC":
		length := 192
		if algObj != nil {
			if v, ok := algObj["length"]; ok {
				length, err = toInt(v, "algorithm.length")
				if err != nil {
					return nil, err
				}
			}
		}
		if length != 128 && length != 192 {
			return nil, errors.New("3DES-CBC key length must be 128 or 192")
		}
		key := make([]byte, length/8)
		if _, err = rand.Read(key); err != nil {
			return nil, err
		}
		stored := &cryptoKey{
			Type:        "secret",
			Extractable: extractable,
			Algorithm: map[string]any{
				"name":   "3DES-CBC",
				"length": length,
			},
			Usages:    append([]string{}, usages...),
			SecretKey: key,
		}
		return s.saveKey(stored), nil
	case "Ed25519":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		commonAlg := map[string]any{"name": "Ed25519"}
		pubUsages, priUsages := splitOKPUsages("Ed25519", usages)
		pubKey := &cryptoKey{
			Type:          "public",
			Extractable:   true,
			Algorithm:     cloneMapAny(commonAlg),
			Usages:        pubUsages,
			Ed25519Public: pub,
		}
		priKey := &cryptoKey{
			Type:           "private",
			Extractable:    extractable,
			Algorithm:      cloneMapAny(commonAlg),
			Usages:         priUsages,
			Ed25519Private: priv,
		}
		return map[string]any{
			"publicKey":  s.saveKey(pubKey),
			"privateKey": s.saveKey(priKey),
		}, nil
	case "ECDSA":
		if algObj == nil {
			return nil, errors.New("algorithm.namedCurve is required")
		}
		curveRaw, ok := algObj["namedCurve"]
		if !ok || curveRaw == nil {
			return nil, errors.New("algorithm.namedCurve is required")
		}
		curveName, err := toString(curveRaw, "algorithm.namedCurve")
		if err != nil {
			return nil, err
		}
		curve, normCurveName, err := namedCurveByName(curveName)
		if err != nil {
			return nil, err
		}
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, err
		}
		commonAlg := map[string]any{
			"name":       "ECDSA",
			"namedCurve": normCurveName,
		}
		pubUsages, priUsages := splitECUsages("ECDSA", usages)
		pubKey := &cryptoKey{
			Type:        "public",
			Extractable: true,
			Algorithm:   cloneMapAny(commonAlg),
			Usages:      pubUsages,
			ECDSAPublic: &priv.PublicKey,
		}
		priKey := &cryptoKey{
			Type:         "private",
			Extractable:  extractable,
			Algorithm:    cloneMapAny(commonAlg),
			Usages:       priUsages,
			ECDSAPrivate: priv,
		}
		return map[string]any{
			"publicKey":  s.saveKey(pubKey),
			"privateKey": s.saveKey(priKey),
		}, nil
	case "ECDH":
		if algObj == nil {
			return nil, errors.New("algorithm.namedCurve is required")
		}
		curveRaw, ok := algObj["namedCurve"]
		if !ok || curveRaw == nil {
			return nil, errors.New("algorithm.namedCurve is required")
		}
		curveName, err := toString(curveRaw, "algorithm.namedCurve")
		if err != nil {
			return nil, err
		}
		curve, normCurveName, err := namedCurveByName(curveName)
		if err != nil {
			return nil, err
		}
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, err
		}
		commonAlg := map[string]any{
			"name":       "ECDH",
			"namedCurve": normCurveName,
		}
		pubUsages, priUsages := splitECUsages("ECDH", usages)
		pubKey := &cryptoKey{
			Type:        "public",
			Extractable: true,
			Algorithm:   cloneMapAny(commonAlg),
			Usages:      pubUsages,
			ECDHPublic:  &priv.PublicKey,
		}
		priKey := &cryptoKey{
			Type:        "private",
			Extractable: extractable,
			Algorithm:   cloneMapAny(commonAlg),
			Usages:      priUsages,
			ECDHPrivate: priv,
		}
		return map[string]any{
			"publicKey":  s.saveKey(pubKey),
			"privateKey": s.saveKey(priKey),
		}, nil
	case "X25519":
		priv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		commonAlg := map[string]any{"name": "X25519"}
		pubUsages, priUsages := splitOKPUsages("X25519", usages)
		pubKey := &cryptoKey{
			Type:         "public",
			Extractable:  true,
			Algorithm:    cloneMapAny(commonAlg),
			Usages:       pubUsages,
			X25519Public: priv.PublicKey(),
		}
		priKey := &cryptoKey{
			Type:          "private",
			Extractable:   extractable,
			Algorithm:     cloneMapAny(commonAlg),
			Usages:        priUsages,
			X25519Private: priv,
		}
		return map[string]any{
			"publicKey":  s.saveKey(pubKey),
			"privateKey": s.saveKey(priKey),
		}, nil
	case "RSASSA-PKCS1-V1_5", "RSA-PSS", "RSA-OAEP", "RSAES-PKCS1-V1_5":
		modulusLength, err := intField(algObj, "modulusLength", true, 0)
		if err != nil {
			return nil, err
		}
		if modulusLength < 512 {
			return nil, errors.New("modulusLength must be >= 512")
		}
		exp, err := publicExponentFromAlg(algObj)
		if err != nil {
			return nil, err
		}
		hashName, err := hashFromAlgorithmObject(algObj, "SHA-256")
		if err != nil {
			return nil, err
		}
		priv, err := generateRSAKeyWithExponent(modulusLength, exp)
		if err != nil {
			return nil, err
		}

		commonAlg := map[string]any{
			"name":           algorithm,
			"modulusLength":  modulusLength,
			"publicExponent": big.NewInt(int64(exp)).Bytes(),
			"hash":           map[string]any{"name": hashName},
		}
		pubUsages, priUsages := splitRSAUsages(algorithm, usages)
		pubKey := &cryptoKey{
			Type:        "public",
			Extractable: true,
			Algorithm:   cloneMapAny(commonAlg),
			Usages:      pubUsages,
			RSAPublic:   &priv.PublicKey,
		}
		priKey := &cryptoKey{
			Type:        "private",
			Extractable: extractable,
			Algorithm:   cloneMapAny(commonAlg),
			Usages:      priUsages,
			RSAPrivate:  priv,
		}
		return map[string]any{
			"publicKey":  s.saveKey(pubKey),
			"privateKey": s.saveKey(priKey),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported generateKey algorithm: %s", algorithm)
	}
}

func (s *KeyStore) opImportKey(args []any) (any, error) {
	if len(args) < 5 {
		return nil, errors.New("crypto.subtle.importKey: missing args")
	}
	format, err := toString(args[0], "format")
	if err != nil {
		return nil, err
	}
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		return nil, errors.New("format is required")
	}
	algorithm, algObj, err := parseAlgorithmIdentifier(args[2])
	if err != nil {
		return nil, err
	}
	extractable, err := toBool(args[3], "extractable")
	if err != nil {
		return nil, err
	}
	usages, err := toStringSlice(args[4], "keyUsages")
	if err != nil {
		return nil, err
	}

	var key *cryptoKey
	switch format {
	case "raw":
		raw, err := requireBytes(args[1], "keyData")
		if err != nil {
			return nil, err
		}
		key, err = importRawKey(algorithm, algObj, raw, extractable, usages)
		if err != nil {
			return nil, err
		}
	case "jwk":
		jwk, ok := args[1].(map[string]any)
		if !ok {
			return nil, errors.New("JWK must be an object")
		}
		key, err = importJWK(algorithm, algObj, jwk, extractable, usages)
		if err != nil {
			return nil, err
		}
	case "pkcs1":
		raw, err := requireBytes(args[1], "keyData")
		if err != nil {
			return nil, err
		}
		if priv, parseErr := x509.ParsePKCS1PrivateKey(raw); parseErr == nil {
			key, err = privateKeyToCryptoKey(priv, algorithm, algObj, extractable, usages)
			if err != nil {
				return nil, err
			}
			return s.saveKey(key), nil
		}
		pub, err := x509.ParsePKCS1PublicKey(raw)
		if err != nil {
			return nil, errors.New("failed to parse pkcs1 key")
		}
		key, err = publicKeyToCryptoKey(pub, algorithm, algObj, usages)
		if err != nil {
			return nil, err
		}
	case "pkcs8":
		raw, err := requireBytes(args[1], "keyData")
		if err != nil {
			return nil, err
		}
		privAny, err := parsePrivateKey(raw)
		if err != nil {
			return nil, err
		}
		key, err = privateKeyToCryptoKey(privAny, algorithm, algObj, extractable, usages)
		if err != nil {
			return nil, err
		}
	case "sec1":
		raw, err := requireBytes(args[1], "keyData")
		if err != nil {
			return nil, err
		}
		priv, err := x509.ParseECPrivateKey(raw)
		if err != nil {
			return nil, errors.New("failed to parse sec1 key")
		}
		key, err = privateKeyToCryptoKey(priv, algorithm, algObj, extractable, usages)
		if err != nil {
			return nil, err
		}
	case "spki":
		raw, err := requireBytes(args[1], "keyData")
		if err != nil {
			return nil, err
		}
		pubAny, err := x509.ParsePKIXPublicKey(raw)
		if err != nil {
			return nil, err
		}
		key, err = publicKeyToCryptoKey(pubAny, algorithm, algObj, usages)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported key format: %s", format)
	}

	return s.saveKey(key), nil
}

func (s *KeyStore) opExportKey(args []any) (any, error) {
	if len(args) < 2 {
		return nil, errors.New("crypto.subtle.exportKey: missing args")
	}
	format, err := toString(args[0], "format")
	if err != nil {
		return nil, err
	}
	format = strings.ToLower(strings.TrimSpace(format))
	key, err := s.requireKey(args[1], "key")
	if err != nil {
		return nil, err
	}
	if !key.Extractable {
		return nil, errors.New("key is not extractable")
	}

	switch format {
	case "raw":
		if len(key.SecretKey) > 0 {
			out := make([]byte, len(key.SecretKey))
			copy(out, key.SecretKey)
			return out, nil
		}
		pubX := key.X25519Public
		if pubX == nil && key.X25519Private != nil {
			pubX = key.X25519Private.PublicKey()
		}
		if pubX != nil {
			out := pubX.Bytes()
			cp := make([]byte, len(out))
			copy(cp, out)
			return cp, nil
		}
		pubECDH := key.ECDHPublic
		if pubECDH == nil && key.ECDHPrivate != nil {
			pubECDH = &key.ECDHPrivate.PublicKey
		}
		if pubECDH != nil {
			return marshalECRawPublicKey(pubECDH), nil
		}
		pubEC := key.ECDSAPublic
		if pubEC == nil && key.ECDSAPrivate != nil {
			pubEC = &key.ECDSAPrivate.PublicKey
		}
		if pubEC != nil {
			return marshalECRawPublicKey(pubEC), nil
		}
		pubEd := key.Ed25519Public
		if len(pubEd) == 0 && len(key.Ed25519Private) != 0 {
			pubEd = key.Ed25519Private.Public().(ed25519.PublicKey)
		}
		if len(pubEd) != 0 {
			out := make([]byte, len(pubEd))
			copy(out, pubEd)
			return out, nil
		}
		return nil, errors.New("raw export requires a secret key or supported public key")
	case "jwk":
		jwk, err := exportJWK(key)
		if err != nil {
			return nil, err
		}
		return jwk, nil
	case "pkcs8":
		if key.RSAPrivate == nil && key.ECDSAPrivate == nil && key.ECDHPrivate == nil && len(key.Ed25519Private) == 0 && key.X25519Private == nil {
			return nil, errors.New("pkcs8 export requires a private key")
		}
		var privAny any
		if key.RSAPrivate != nil {
			privAny = key.RSAPrivate
		} else if key.ECDSAPrivate != nil {
			privAny = key.ECDSAPrivate
		} else if key.ECDHPrivate != nil {
			privAny = key.ECDHPrivate
		} else {
			if len(key.Ed25519Private) != 0 {
				privAny = key.Ed25519Private
			} else {
				privAny = key.X25519Private
			}
		}
		der, err := x509.MarshalPKCS8PrivateKey(privAny)
		if err != nil {
			return nil, err
		}
		return der, nil
	case "pkcs1":
		if key.RSAPrivate != nil {
			return x509.MarshalPKCS1PrivateKey(key.RSAPrivate), nil
		}
		pub := key.RSAPublic
		if pub == nil {
			return nil, errors.New("pkcs1 export requires an RSA key")
		}
		return x509.MarshalPKCS1PublicKey(pub), nil
	case "sec1":
		var ecPriv *ecdsa.PrivateKey
		if key.ECDSAPrivate != nil {
			ecPriv = key.ECDSAPrivate
		} else if key.ECDHPrivate != nil {
			ecPriv = key.ECDHPrivate
		}
		if ecPriv == nil {
			return nil, errors.New("sec1 export requires an EC private key")
		}
		der, err := x509.MarshalECPrivateKey(ecPriv)
		if err != nil {
			return nil, err
		}
		return der, nil
	case "spki":
		var pubAny any
		if key.RSAPublic != nil {
			pubAny = key.RSAPublic
		} else if key.RSAPrivate != nil {
			pubAny = &key.RSAPrivate.PublicKey
		} else if key.ECDSAPublic != nil {
			pubAny = key.ECDSAPublic
		} else if key.ECDSAPrivate != nil {
			pubAny = &key.ECDSAPrivate.PublicKey
		} else if key.ECDHPublic != nil {
			pubAny = key.ECDHPublic
		} else if key.ECDHPrivate != nil {
			pubAny = &key.ECDHPrivate.PublicKey
		} else if len(key.Ed25519Public) != 0 {
			pubAny = key.Ed25519Public
		} else if len(key.Ed25519Private) != 0 {
			pubAny = key.Ed25519Private.Public().(ed25519.PublicKey)
		} else if key.X25519Public != nil {
			pubAny = key.X25519Public
		} else if key.X25519Private != nil {
			pubAny = key.X25519Private.PublicKey()
		} else {
			return nil, errors.New("spki export requires a public key")
		}
		der, err := x509.MarshalPKIXPublicKey(pubAny)
		if err != nil {
			return nil, err
		}
		return der, nil
	default:
		return nil, fmt.Errorf("unsupported export format: %s", format)
	}
}

func (s *KeyStore) opSign(args []any) (any, error) {
	if len(args) < 3 {
		return nil, errors.New("crypto.subtle.sign: missing args")
	}
	algorithm, algObj, err := parseAlgorithmIdentifier(args[0])
	if err != nil {
		return nil, err
	}
	key, err := s.requireKey(args[1], "key")
	if err != nil {
		return nil, err
	}
	data, err := requireBytes(args[2], "data")
	if err != nil {
		return nil, err
	}
	switch algorithm {
	case "HMAC":
		if len(key.SecretKey) == 0 {
			return nil, errors.New("HMAC requires a secret key")
		}
		hashName := key.HMACHash
		if hashName == "" {
			hashName = "SHA-256"
		}
		if algObj != nil {
			if hv, ok := algObj["hash"]; ok {
				hashName, err = hashFromAlgorithmValue(hv)
				if err != nil {
					return nil, err
				}
			}
		}
		hf, err := hashFactory(hashName)
		if err != nil {
			return nil, err
		}
		mac := hmac.New(hf, key.SecretKey)
		_, _ = mac.Write(data)
		return mac.Sum(nil), nil
	case "RSASSA-PKCS1-V1_5":
		if key.RSAPrivate == nil {
			return nil, errors.New("RSASSA-PKCS1-v1_5 requires a private RSA key")
		}
		hashName, err := hashNameForRSA(algObj, key, "SHA-256")
		if err != nil {
			return nil, err
		}
		hashID, digest, err := digestForCryptoHash(hashName, data)
		if err != nil {
			return nil, err
		}
		return rsa.SignPKCS1v15(rand.Reader, key.RSAPrivate, hashID, digest)
	case "RSA-PSS":
		if key.RSAPrivate == nil {
			return nil, errors.New("RSA-PSS requires a private RSA key")
		}
		hashName, err := hashNameForRSA(algObj, key, "SHA-256")
		if err != nil {
			return nil, err
		}
		hashID, digest, err := digestForCryptoHash(hashName, data)
		if err != nil {
			return nil, err
		}
		saltLen := digestLengthBytes(hashName)
		if algObj != nil {
			if v, ok := algObj["saltLength"]; ok {
				saltLen, err = toInt(v, "algorithm.saltLength")
				if err != nil {
					return nil, err
				}
			}
		}
		return rsa.SignPSS(rand.Reader, key.RSAPrivate, hashID, digest, &rsa.PSSOptions{SaltLength: saltLen, Hash: hashID})
	case "Ed25519":
		if len(key.Ed25519Private) == 0 {
			return nil, errors.New("Ed25519 requires a private key")
		}
		return ed25519.Sign(key.Ed25519Private, data), nil
	case "ECDSA":
		if key.ECDSAPrivate == nil {
			return nil, errors.New("ECDSA requires a private EC key")
		}
		hashName := "SHA-256"
		if key.Algorithm != nil {
			if hv, ok := key.Algorithm["hash"].(map[string]any); ok {
				if name, ok := hv["name"].(string); ok && name != "" {
					hashName = name
				}
			}
		}
		if algObj != nil {
			if hv, ok := algObj["hash"]; ok {
				hashName, err = hashFromAlgorithmValue(hv)
				if err != nil {
					return nil, err
				}
			}
		}
		_, digest, err := digestForCryptoHash(hashName, data)
		if err != nil {
			return nil, err
		}
		r, s, err := ecdsa.Sign(rand.Reader, key.ECDSAPrivate, digest)
		if err != nil {
			return nil, err
		}
		size := (key.ECDSAPrivate.Curve.Params().BitSize + 7) / 8
		sig := make([]byte, size*2)
		copy(sig[:size], leftPad(r.Bytes(), size))
		copy(sig[size:], leftPad(s.Bytes(), size))
		return sig, nil
	default:
		return nil, fmt.Errorf("unsupported sign algorithm: %s", algorithm)
	}
}

func (s *KeyStore) opVerify(args []any) (any, error) {
	if len(args) < 4 {
		return nil, errors.New("crypto.subtle.verify: missing args")
	}
	algorithm, algObj, err := parseAlgorithmIdentifier(args[0])
	if err != nil {
		return nil, err
	}
	key, err := s.requireKey(args[1], "key")
	if err != nil {
		return nil, err
	}
	signature, err := requireBytes(args[2], "signature")
	if err != nil {
		return nil, err
	}
	data, err := requireBytes(args[3], "data")
	if err != nil {
		return nil, err
	}
	switch algorithm {
	case "HMAC":
		expected, err := s.opSign([]any{args[0], keyRefFromKey(key), data})
		if err != nil {
			return nil, err
		}
		eb, ok := expected.([]byte)
		if !ok {
			return nil, errors.New("internal sign result error")
		}
		return hmac.Equal(signature, eb), nil
	case "RSASSA-PKCS1-V1_5":
		pub := key.RSAPublic
		if pub == nil && key.RSAPrivate != nil {
			pub = &key.RSAPrivate.PublicKey
		}
		if pub == nil {
			return nil, errors.New("RSASSA-PKCS1-v1_5 requires an RSA key")
		}
		hashName, err := hashNameForRSA(algObj, key, "SHA-256")
		if err != nil {
			return nil, err
		}
		hashID, digest, err := digestForCryptoHash(hashName, data)
		if err != nil {
			return nil, err
		}
		if err := rsa.VerifyPKCS1v15(pub, hashID, digest, signature); err != nil {
			return false, nil
		}
		return true, nil
	case "RSA-PSS":
		pub := key.RSAPublic
		if pub == nil && key.RSAPrivate != nil {
			pub = &key.RSAPrivate.PublicKey
		}
		if pub == nil {
			return nil, errors.New("RSA-PSS requires an RSA key")
		}
		hashName, err := hashNameForRSA(algObj, key, "SHA-256")
		if err != nil {
			return nil, err
		}
		hashID, digest, err := digestForCryptoHash(hashName, data)
		if err != nil {
			return nil, err
		}
		saltLen := digestLengthBytes(hashName)
		if algObj != nil {
			if v, ok := algObj["saltLength"]; ok {
				saltLen, err = toInt(v, "algorithm.saltLength")
				if err != nil {
					return nil, err
				}
			}
		}
		if err := rsa.VerifyPSS(pub, hashID, digest, signature, &rsa.PSSOptions{SaltLength: saltLen, Hash: hashID}); err != nil {
			return false, nil
		}
		return true, nil
	case "Ed25519":
		pub := key.Ed25519Public
		if len(pub) == 0 && len(key.Ed25519Private) != 0 {
			pub = key.Ed25519Private.Public().(ed25519.PublicKey)
		}
		if len(pub) == 0 {
			return nil, errors.New("Ed25519 requires a key")
		}
		return ed25519.Verify(pub, data, signature), nil
	case "ECDSA":
		pub := key.ECDSAPublic
		if pub == nil && key.ECDSAPrivate != nil {
			pub = &key.ECDSAPrivate.PublicKey
		}
		if pub == nil {
			return nil, errors.New("ECDSA requires an EC key")
		}
		hashName := "SHA-256"
		if key.Algorithm != nil {
			if hv, ok := key.Algorithm["hash"].(map[string]any); ok {
				if name, ok := hv["name"].(string); ok && name != "" {
					hashName = name
				}
			}
		}
		if algObj != nil {
			if hv, ok := algObj["hash"]; ok {
				hashName, err = hashFromAlgorithmValue(hv)
				if err != nil {
					return nil, err
				}
			}
		}
		_, digest, err := digestForCryptoHash(hashName, data)
		if err != nil {
			return nil, err
		}
		size := (pub.Curve.Params().BitSize + 7) / 8
		if len(signature) == size*2 {
			r := new(big.Int).SetBytes(signature[:size])
			s := new(big.Int).SetBytes(signature[size:])
			return ecdsa.Verify(pub, digest, r, s), nil
		}
		return ecdsa.VerifyASN1(pub, digest, signature), nil
	default:
		return nil, fmt.Errorf("unsupported verify algorithm: %s", algorithm)
	}
}

func (s *KeyStore) opEncrypt(args []any) (any, error) {
	if len(args) < 3 {
		return nil, errors.New("crypto.subtle.encrypt: missing args")
	}
	algorithm, algObj, err := parseAlgorithmIdentifier(args[0])
	if err != nil {
		return nil, err
	}
	key, err := s.requireKey(args[1], "key")
	if err != nil {
		return nil, err
	}
	data, err := requireBytes(args[2], "data")
	if err != nil {
		return nil, err
	}

	return encryptData(algorithm, algObj, key, data)
}

func (s *KeyStore) opDecrypt(args []any) (any, error) {
	if len(args) < 3 {
		return nil, errors.New("crypto.subtle.decrypt: missing args")
	}
	algorithm, algObj, err := parseAlgorithmIdentifier(args[0])
	if err != nil {
		return nil, err
	}
	key, err := s.requireKey(args[1], "key")
	if err != nil {
		return nil, err
	}
	data, err := requireBytes(args[2], "data")
	if err != nil {
		return nil, err
	}

	return decryptData(algorithm, algObj, key, data)
}

func (s *KeyStore) opDeriveBits(args []any) (any, error) {
	if len(args) < 3 {
		return nil, errors.New("crypto.subtle.deriveBits: missing args")
	}
	algorithm, algObj, err := parseAlgorithmIdentifier(args[0])
	if err != nil {
		return nil, err
	}
	baseKey, err := s.requireKey(args[1], "baseKey")
	if err != nil {
		return nil, err
	}
	lengthBits, err := toInt(args[2], "length")
	if err != nil {
		return nil, err
	}
	if lengthBits <= 0 || lengthBits%8 != 0 {
		return nil, errors.New("length must be a positive multiple of 8")
	}

	return s.deriveBits(algorithm, algObj, baseKey, lengthBits)
}

func (s *KeyStore) opDeriveKey(args []any) (any, error) {
	if len(args) < 5 {
		return nil, errors.New("crypto.subtle.deriveKey: missing args")
	}
	baseAlgorithm, baseAlgObj, err := parseAlgorithmIdentifier(args[0])
	if err != nil {
		return nil, err
	}
	baseKey, err := s.requireKey(args[1], "baseKey")
	if err != nil {
		return nil, err
	}
	derivedAlgorithm, derivedAlgObj, err := parseAlgorithmIdentifier(args[2])
	if err != nil {
		return nil, err
	}
	extractable, err := toBool(args[3], "extractable")
	if err != nil {
		return nil, err
	}
	usages, err := toStringSlice(args[4], "keyUsages")
	if err != nil {
		return nil, err
	}
	lengthBits, err := deriveKeyLengthBits(derivedAlgorithm, derivedAlgObj)
	if err != nil {
		return nil, err
	}
	bits, err := s.deriveBits(baseAlgorithm, baseAlgObj, baseKey, lengthBits)
	if err != nil {
		return nil, err
	}
	key, err := importRawKey(derivedAlgorithm, derivedAlgObj, bits, extractable, usages)
	if err != nil {
		return nil, err
	}
	return s.saveKey(key), nil
}

func (s *KeyStore) opWrapKey(args []any) (any, error) {
	if len(args) < 4 {
		return nil, errors.New("crypto.subtle.wrapKey: missing args")
	}
	format, err := toString(args[0], "format")
	if err != nil {
		return nil, err
	}
	format = strings.ToLower(strings.TrimSpace(format))
	keyToWrap, err := s.requireKey(args[1], "key")
	if err != nil {
		return nil, err
	}
	wrappingKey, err := s.requireKey(args[2], "wrappingKey")
	if err != nil {
		return nil, err
	}
	wrapAlgorithm, wrapAlgObj, err := parseAlgorithmIdentifier(args[3])
	if err != nil {
		return nil, err
	}

	if !keyToWrap.Extractable {
		return nil, errors.New("key is not extractable")
	}

	rawKey, err := s.exportKeyBytesForWrap(format, keyToWrap)
	if err != nil {
		return nil, err
	}
	return encryptData(wrapAlgorithm, wrapAlgObj, wrappingKey, rawKey)
}

func (s *KeyStore) opUnwrapKey(args []any) (any, error) {
	if len(args) < 7 {
		return nil, errors.New("crypto.subtle.unwrapKey: missing args")
	}
	format, err := toString(args[0], "format")
	if err != nil {
		return nil, err
	}
	format = strings.ToLower(strings.TrimSpace(format))
	wrappedData, err := requireBytes(args[1], "wrappedKey")
	if err != nil {
		return nil, err
	}
	unwrappingKey, err := s.requireKey(args[2], "unwrappingKey")
	if err != nil {
		return nil, err
	}
	unwrapAlgorithm, unwrapAlgObj, err := parseAlgorithmIdentifier(args[3])
	if err != nil {
		return nil, err
	}
	unwrappedKeyAlgorithm, unwrappedKeyAlgObj, err := parseAlgorithmIdentifier(args[4])
	if err != nil {
		return nil, err
	}
	extractable, err := toBool(args[5], "extractable")
	if err != nil {
		return nil, err
	}
	usages, err := toStringSlice(args[6], "keyUsages")
	if err != nil {
		return nil, err
	}

	rawKey, err := decryptData(unwrapAlgorithm, unwrapAlgObj, unwrappingKey, wrappedData)
	if err != nil {
		return nil, err
	}
	var key *cryptoKey
	switch format {
	case "raw":
		key, err = importRawKey(unwrappedKeyAlgorithm, unwrappedKeyAlgObj, rawKey, extractable, usages)
		if err != nil {
			return nil, err
		}
	case "jwk":
		var jwk map[string]any
		if err = json.Unmarshal(rawKey, &jwk); err != nil {
			return nil, err
		}
		key, err = importJWK(unwrappedKeyAlgorithm, unwrappedKeyAlgObj, jwk, extractable, usages)
		if err != nil {
			return nil, err
		}
	case "pkcs8":
		privAny, err := parsePrivateKey(rawKey)
		if err != nil {
			return nil, err
		}
		key, err = privateKeyToCryptoKey(privAny, unwrappedKeyAlgorithm, unwrappedKeyAlgObj, extractable, usages)
		if err != nil {
			return nil, err
		}
	case "pkcs1":
		if priv, parseErr := x509.ParsePKCS1PrivateKey(rawKey); parseErr == nil {
			key, err = privateKeyToCryptoKey(priv, unwrappedKeyAlgorithm, unwrappedKeyAlgObj, extractable, usages)
			if err != nil {
				return nil, err
			}
			break
		}
		pub, err := x509.ParsePKCS1PublicKey(rawKey)
		if err != nil {
			return nil, errors.New("failed to parse pkcs1 key")
		}
		key, err = publicKeyToCryptoKey(pub, unwrappedKeyAlgorithm, unwrappedKeyAlgObj, usages)
		if err != nil {
			return nil, err
		}
	case "sec1":
		priv, err := x509.ParseECPrivateKey(rawKey)
		if err != nil {
			return nil, errors.New("failed to parse sec1 key")
		}
		key, err = privateKeyToCryptoKey(priv, unwrappedKeyAlgorithm, unwrappedKeyAlgObj, extractable, usages)
		if err != nil {
			return nil, err
		}
	case "spki":
		pubAny, err := x509.ParsePKIXPublicKey(rawKey)
		if err != nil {
			return nil, err
		}
		key, err = publicKeyToCryptoKey(pubAny, unwrappedKeyAlgorithm, unwrappedKeyAlgObj, usages)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported wrapped key format: %s", format)
	}
	return s.saveKey(key), nil
}

func (s *KeyStore) deriveBits(algorithm string, algObj map[string]any, baseKey *cryptoKey, lengthBits int) ([]byte, error) {
	switch algorithm {
	case "PBKDF2":
		if len(baseKey.SecretKey) == 0 {
			return nil, errors.New("PBKDF2 requires a secret key")
		}
		salt, err := bytesField(algObj, "salt", true)
		if err != nil {
			return nil, err
		}
		iterations, err := intField(algObj, "iterations", true, 0)
		if err != nil {
			return nil, err
		}
		if iterations <= 0 {
			return nil, errors.New("iterations must be > 0")
		}
		hashName, err := hashFromAlgorithmObject(algObj, "SHA-256")
		if err != nil {
			return nil, err
		}
		hf, err := hashFactory(hashName)
		if err != nil {
			return nil, err
		}
		return pbkdf2.Key(baseKey.SecretKey, salt, iterations, lengthBits/8, hf), nil
	case "HKDF":
		if len(baseKey.SecretKey) == 0 {
			return nil, errors.New("HKDF requires a secret key")
		}
		hashName, err := hashFromAlgorithmObject(algObj, "SHA-256")
		if err != nil {
			return nil, err
		}
		hf, err := hashFactory(hashName)
		if err != nil {
			return nil, err
		}
		salt, err := bytesField(algObj, "salt", false)
		if err != nil {
			return nil, err
		}
		info, err := bytesField(algObj, "info", false)
		if err != nil {
			return nil, err
		}
		reader := hkdf.New(hf, baseKey.SecretKey, salt, info)
		out := make([]byte, lengthBits/8)
		if _, err = io.ReadFull(reader, out); err != nil {
			return nil, err
		}
		return out, nil
	case "ECDH":
		if algObj == nil {
			return nil, errors.New("ECDH algorithm parameters are required")
		}
		priv := baseKey.ECDHPrivate
		if priv == nil {
			return nil, errors.New("ECDH baseKey must be an ECDH private key")
		}
		pubValue, ok := algObj["public"]
		if !ok || pubValue == nil {
			return nil, errors.New("algorithm.public is required")
		}
		pubKey, err := s.requireKey(pubValue, "algorithm.public")
		if err != nil {
			return nil, err
		}
		pub := pubKey.ECDHPublic
		if pub == nil && pubKey.ECDHPrivate != nil {
			pub = &pubKey.ECDHPrivate.PublicKey
		}
		if pub == nil {
			return nil, errors.New("algorithm.public must be an ECDH key")
		}
		if pub.Curve != priv.Curve {
			return nil, errors.New("ECDH curve mismatch")
		}
		x, _ := pub.ScalarMult(pub.X, pub.Y, priv.D.Bytes())
		if x == nil {
			return nil, errors.New("ECDH derive failed")
		}
		size := (pub.Curve.Params().BitSize + 7) / 8
		shared := leftPad(x.Bytes(), size)
		if lengthBits > len(shared)*8 {
			return nil, errors.New("requested length exceeds shared secret size")
		}
		return shared[:lengthBits/8], nil
	case "X25519":
		if algObj == nil {
			return nil, errors.New("X25519 algorithm parameters are required")
		}
		priv := baseKey.X25519Private
		if priv == nil {
			return nil, errors.New("X25519 baseKey must be an X25519 private key")
		}
		pubValue, ok := algObj["public"]
		if !ok || pubValue == nil {
			return nil, errors.New("algorithm.public is required")
		}
		pubKey, err := s.requireKey(pubValue, "algorithm.public")
		if err != nil {
			return nil, err
		}
		pub := pubKey.X25519Public
		if pub == nil && pubKey.X25519Private != nil {
			pub = pubKey.X25519Private.PublicKey()
		}
		if pub == nil {
			return nil, errors.New("algorithm.public must be an X25519 key")
		}
		shared, err := priv.ECDH(pub)
		if err != nil {
			return nil, err
		}
		if lengthBits > len(shared)*8 {
			return nil, errors.New("requested length exceeds shared secret size")
		}
		return shared[:lengthBits/8], nil
	default:
		return nil, fmt.Errorf("unsupported deriveBits algorithm: %s", algorithm)
	}
}

func deriveKeyLengthBits(algorithm string, algObj map[string]any) (int, error) {
	switch algorithm {
	case "AES-CBC", "AES-GCM", "AES-CTR", "AES-KW":
		length, err := intField(algObj, "length", true, 0)
		if err != nil {
			return 0, err
		}
		if length != 128 && length != 192 && length != 256 {
			return 0, errors.New("AES key length must be 128, 192, or 256")
		}
		return length, nil
	case "HMAC":
		length, err := intField(algObj, "length", false, 0)
		if err != nil {
			return 0, err
		}
		if length > 0 {
			return length, nil
		}
		hashName, err := hashFromAlgorithmObject(algObj, "SHA-256")
		if err != nil {
			return 0, err
		}
		return digestLengthBytes(hashName) * 8, nil
	case "DES-CBC":
		return 64, nil
	case "3DES-CBC":
		if algObj == nil {
			return 192, nil
		}
		if v, ok := algObj["length"]; ok {
			length, err := toInt(v, "algorithm.length")
			if err != nil {
				return 0, err
			}
			if length != 128 && length != 192 {
				return 0, errors.New("3DES-CBC length must be 128 or 192")
			}
			return length, nil
		}
		return 192, nil
	default:
		return 0, fmt.Errorf("unsupported derived key algorithm: %s", algorithm)
	}
}

func encryptData(algorithm string, algObj map[string]any, key *cryptoKey, data []byte) ([]byte, error) {
	switch algorithm {
	case "AES-CBC":
		if len(key.SecretKey) == 0 {
			return nil, errors.New("AES-CBC requires a secret key")
		}
		iv, err := bytesField(algObj, "iv", true)
		if err != nil {
			return nil, err
		}
		if len(iv) != aes.BlockSize {
			return nil, errors.New("AES-CBC iv length must be 16")
		}
		block, err := aes.NewCipher(key.SecretKey)
		if err != nil {
			return nil, err
		}
		padded := pkcs7Pad(data, aes.BlockSize)
		out := make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
		return out, nil
	case "AES-GCM":
		if len(key.SecretKey) == 0 {
			return nil, errors.New("AES-GCM requires a secret key")
		}
		iv, err := bytesField(algObj, "iv", true)
		if err != nil {
			return nil, err
		}
		tagLength, err := intField(algObj, "tagLength", false, 128)
		if err != nil {
			return nil, err
		}
		if err = validateAESGCMTagLength(tagLength); err != nil {
			return nil, err
		}
		block, err := aes.NewCipher(key.SecretKey)
		if err != nil {
			return nil, err
		}
		gcm, err := newAESGCMForParams(block, len(iv), tagLength)
		if err != nil {
			return nil, err
		}
		aad, err := bytesField(algObj, "additionalData", false)
		if err != nil {
			return nil, err
		}
		return gcm.Seal(nil, iv, data, aad), nil
	case "AES-CTR":
		if len(key.SecretKey) == 0 {
			return nil, errors.New("AES-CTR requires a secret key")
		}
		counter, err := bytesField(algObj, "counter", true)
		if err != nil {
			return nil, err
		}
		if len(counter) != aes.BlockSize {
			return nil, errors.New("AES-CTR counter length must be 16")
		}
		length, err := intField(algObj, "length", true, 0)
		if err != nil {
			return nil, err
		}
		if length < 1 || length > 128 {
			return nil, errors.New("AES-CTR length must be between 1 and 128")
		}
		block, err := aes.NewCipher(key.SecretKey)
		if err != nil {
			return nil, err
		}
		iv := make([]byte, len(counter))
		copy(iv, counter)
		out := make([]byte, len(data))
		cipher.NewCTR(block, iv).XORKeyStream(out, data)
		return out, nil
	case "AES-KW":
		if len(key.SecretKey) == 0 {
			return nil, errors.New("AES-KW requires a secret key")
		}
		return aesKeyWrap(key.SecretKey, data)
	case "DES-CBC":
		if len(key.SecretKey) != 8 {
			return nil, errors.New("DES-CBC requires an 8-byte secret key")
		}
		iv, err := bytesField(algObj, "iv", true)
		if err != nil {
			return nil, err
		}
		if len(iv) != des.BlockSize {
			return nil, errors.New("DES-CBC iv length must be 8")
		}
		block, err := des.NewCipher(key.SecretKey)
		if err != nil {
			return nil, err
		}
		padded := pkcs7Pad(data, des.BlockSize)
		out := make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
		return out, nil
	case "3DES-CBC":
		desKey, err := tripleDESKey(key.SecretKey)
		if err != nil {
			return nil, err
		}
		iv, err := bytesField(algObj, "iv", true)
		if err != nil {
			return nil, err
		}
		if len(iv) != des.BlockSize {
			return nil, errors.New("3DES-CBC iv length must be 8")
		}
		block, err := des.NewTripleDESCipher(desKey)
		if err != nil {
			return nil, err
		}
		padded := pkcs7Pad(data, des.BlockSize)
		out := make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
		return out, nil
	case "RSA-OAEP":
		pub := key.RSAPublic
		if pub == nil && key.RSAPrivate != nil {
			pub = &key.RSAPrivate.PublicKey
		}
		if pub == nil {
			return nil, errors.New("RSA-OAEP requires an RSA key")
		}
		hashName, err := hashNameForRSA(algObj, key, "SHA-256")
		if err != nil {
			return nil, err
		}
		hf, err := hashFactory(hashName)
		if err != nil {
			return nil, err
		}
		label, err := bytesField(algObj, "label", false)
		if err != nil {
			return nil, err
		}
		return rsa.EncryptOAEP(hf(), rand.Reader, pub, data, label)
	case "RSAES-PKCS1-V1_5":
		pub := key.RSAPublic
		if pub == nil && key.RSAPrivate != nil {
			pub = &key.RSAPrivate.PublicKey
		}
		if pub == nil {
			return nil, errors.New("RSAES-PKCS1-v1_5 requires an RSA key")
		}
		return rsa.EncryptPKCS1v15(rand.Reader, pub, data)
	default:
		return nil, fmt.Errorf("unsupported encrypt algorithm: %s", algorithm)
	}
}

func decryptData(algorithm string, algObj map[string]any, key *cryptoKey, data []byte) ([]byte, error) {
	switch algorithm {
	case "AES-CBC":
		if len(key.SecretKey) == 0 {
			return nil, errors.New("AES-CBC requires a secret key")
		}
		iv, err := bytesField(algObj, "iv", true)
		if err != nil {
			return nil, err
		}
		if len(iv) != aes.BlockSize {
			return nil, errors.New("AES-CBC iv length must be 16")
		}
		if len(data)%aes.BlockSize != 0 {
			return nil, errors.New("AES-CBC ciphertext length must be multiple of block size")
		}
		block, err := aes.NewCipher(key.SecretKey)
		if err != nil {
			return nil, err
		}
		out := make([]byte, len(data))
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)
		return pkcs7Unpad(out, aes.BlockSize)
	case "AES-GCM":
		if len(key.SecretKey) == 0 {
			return nil, errors.New("AES-GCM requires a secret key")
		}
		iv, err := bytesField(algObj, "iv", true)
		if err != nil {
			return nil, err
		}
		tagLength, err := intField(algObj, "tagLength", false, 128)
		if err != nil {
			return nil, err
		}
		if err = validateAESGCMTagLength(tagLength); err != nil {
			return nil, err
		}
		block, err := aes.NewCipher(key.SecretKey)
		if err != nil {
			return nil, err
		}
		gcm, err := newAESGCMForParams(block, len(iv), tagLength)
		if err != nil {
			return nil, err
		}
		aad, err := bytesField(algObj, "additionalData", false)
		if err != nil {
			return nil, err
		}
		return gcm.Open(nil, iv, data, aad)
	case "AES-CTR":
		if len(key.SecretKey) == 0 {
			return nil, errors.New("AES-CTR requires a secret key")
		}
		counter, err := bytesField(algObj, "counter", true)
		if err != nil {
			return nil, err
		}
		if len(counter) != aes.BlockSize {
			return nil, errors.New("AES-CTR counter length must be 16")
		}
		length, err := intField(algObj, "length", true, 0)
		if err != nil {
			return nil, err
		}
		if length < 1 || length > 128 {
			return nil, errors.New("AES-CTR length must be between 1 and 128")
		}
		block, err := aes.NewCipher(key.SecretKey)
		if err != nil {
			return nil, err
		}
		iv := make([]byte, len(counter))
		copy(iv, counter)
		out := make([]byte, len(data))
		cipher.NewCTR(block, iv).XORKeyStream(out, data)
		return out, nil
	case "AES-KW":
		if len(key.SecretKey) == 0 {
			return nil, errors.New("AES-KW requires a secret key")
		}
		return aesKeyUnwrap(key.SecretKey, data)
	case "DES-CBC":
		if len(key.SecretKey) != 8 {
			return nil, errors.New("DES-CBC requires an 8-byte secret key")
		}
		iv, err := bytesField(algObj, "iv", true)
		if err != nil {
			return nil, err
		}
		if len(iv) != des.BlockSize {
			return nil, errors.New("DES-CBC iv length must be 8")
		}
		if len(data)%des.BlockSize != 0 {
			return nil, errors.New("DES-CBC ciphertext length must be multiple of block size")
		}
		block, err := des.NewCipher(key.SecretKey)
		if err != nil {
			return nil, err
		}
		out := make([]byte, len(data))
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)
		return pkcs7Unpad(out, des.BlockSize)
	case "3DES-CBC":
		desKey, err := tripleDESKey(key.SecretKey)
		if err != nil {
			return nil, err
		}
		iv, err := bytesField(algObj, "iv", true)
		if err != nil {
			return nil, err
		}
		if len(iv) != des.BlockSize {
			return nil, errors.New("3DES-CBC iv length must be 8")
		}
		if len(data)%des.BlockSize != 0 {
			return nil, errors.New("3DES-CBC ciphertext length must be multiple of block size")
		}
		block, err := des.NewTripleDESCipher(desKey)
		if err != nil {
			return nil, err
		}
		out := make([]byte, len(data))
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)
		return pkcs7Unpad(out, des.BlockSize)
	case "RSA-OAEP":
		if key.RSAPrivate == nil {
			return nil, errors.New("RSA-OAEP requires a private RSA key")
		}
		hashName, err := hashNameForRSA(algObj, key, "SHA-256")
		if err != nil {
			return nil, err
		}
		hf, err := hashFactory(hashName)
		if err != nil {
			return nil, err
		}
		label, err := bytesField(algObj, "label", false)
		if err != nil {
			return nil, err
		}
		return rsa.DecryptOAEP(hf(), rand.Reader, key.RSAPrivate, data, label)
	case "RSAES-PKCS1-V1_5":
		if key.RSAPrivate == nil {
			return nil, errors.New("RSAES-PKCS1-v1_5 requires a private RSA key")
		}
		return rsa.DecryptPKCS1v15(rand.Reader, key.RSAPrivate, data)
	default:
		return nil, fmt.Errorf("unsupported decrypt algorithm: %s", algorithm)
	}
}

func importRawKey(algorithm string, algObj map[string]any, raw []byte, extractable bool, usages []string) (*cryptoKey, error) {
	cpy := make([]byte, len(raw))
	copy(cpy, raw)
	switch algorithm {
	case "AES-CBC", "AES-GCM", "AES-CTR", "AES-KW":
		length := len(cpy) * 8
		if length != 128 && length != 192 && length != 256 {
			return nil, errors.New("AES raw key length must be 16, 24, or 32 bytes")
		}
		return &cryptoKey{
			Type:        "secret",
			Extractable: extractable,
			Algorithm: map[string]any{
				"name":   algorithm,
				"length": length,
			},
			Usages:    append([]string{}, usages...),
			SecretKey: cpy,
		}, nil
	case "DES-CBC":
		if len(cpy) != 8 {
			return nil, errors.New("DES-CBC raw key length must be 8 bytes")
		}
		return &cryptoKey{
			Type:        "secret",
			Extractable: extractable,
			Algorithm: map[string]any{
				"name":   "DES-CBC",
				"length": 64,
			},
			Usages:    append([]string{}, usages...),
			SecretKey: cpy,
		}, nil
	case "3DES-CBC":
		if len(cpy) != 16 && len(cpy) != 24 {
			return nil, errors.New("3DES-CBC raw key length must be 16 or 24 bytes")
		}
		return &cryptoKey{
			Type:        "secret",
			Extractable: extractable,
			Algorithm: map[string]any{
				"name":   "3DES-CBC",
				"length": len(cpy) * 8,
			},
			Usages:    append([]string{}, usages...),
			SecretKey: cpy,
		}, nil
	case "HMAC":
		hashName, err := hashFromAlgorithmObject(algObj, "SHA-256")
		if err != nil {
			return nil, err
		}
		length, err := intField(algObj, "length", false, len(cpy)*8)
		if err != nil {
			return nil, err
		}
		return &cryptoKey{
			Type:        "secret",
			Extractable: extractable,
			Algorithm: map[string]any{
				"name":   "HMAC",
				"hash":   map[string]any{"name": hashName},
				"length": length,
			},
			Usages:    append([]string{}, usages...),
			SecretKey: cpy,
			HMACHash:  hashName,
		}, nil
	case "PBKDF2":
		return &cryptoKey{
			Type:        "secret",
			Extractable: extractable,
			Algorithm:   map[string]any{"name": "PBKDF2"},
			Usages:      append([]string{}, usages...),
			SecretKey:   cpy,
		}, nil
	case "HKDF":
		return &cryptoKey{
			Type:        "secret",
			Extractable: extractable,
			Algorithm:   map[string]any{"name": "HKDF"},
			Usages:      append([]string{}, usages...),
			SecretKey:   cpy,
		}, nil
	case "Ed25519":
		keyType, err := rawKeyTypeHint(algObj)
		if err != nil {
			return nil, err
		}
		isPrivate := keyType == "private"
		if keyType == "" && len(cpy) == ed25519.PrivateKeySize {
			isPrivate = true
		}
		if keyType == "" && len(cpy) == ed25519.SeedSize && usageContains(usages, "sign") && !usageContains(usages, "verify") {
			isPrivate = true
		}
		if isPrivate {
			switch len(cpy) {
			case ed25519.SeedSize:
				priv := ed25519.NewKeyFromSeed(cpy)
				return &cryptoKey{
					Type:           "private",
					Extractable:    extractable,
					Algorithm:      map[string]any{"name": "Ed25519"},
					Usages:         usages,
					Ed25519Private: priv,
				}, nil
			case ed25519.PrivateKeySize:
				priv := make([]byte, ed25519.PrivateKeySize)
				copy(priv, cpy)
				return &cryptoKey{
					Type:           "private",
					Extractable:    extractable,
					Algorithm:      map[string]any{"name": "Ed25519"},
					Usages:         usages,
					Ed25519Private: ed25519.PrivateKey(priv),
				}, nil
			default:
				return nil, errors.New("Ed25519 raw private key must be 32-byte seed or 64-byte private key")
			}
		}
		if len(cpy) != ed25519.PublicKeySize {
			return nil, errors.New("Ed25519 raw public key length must be 32 bytes")
		}
		pub := make([]byte, ed25519.PublicKeySize)
		copy(pub, cpy)
		return &cryptoKey{
			Type:          "public",
			Extractable:   true,
			Algorithm:     map[string]any{"name": "Ed25519"},
			Usages:        usages,
			Ed25519Public: ed25519.PublicKey(pub),
		}, nil
	case "ECDSA":
		if algObj == nil {
			return nil, errors.New("algorithm.namedCurve is required")
		}
		curveRaw, ok := algObj["namedCurve"]
		if !ok || curveRaw == nil {
			return nil, errors.New("algorithm.namedCurve is required")
		}
		curveName, err := toString(curveRaw, "algorithm.namedCurve")
		if err != nil {
			return nil, err
		}
		curve, normCurveName, err := namedCurveByName(curveName)
		if err != nil {
			return nil, err
		}
		size := (curve.Params().BitSize + 7) / 8
		if len(cpy) != 1+2*size || cpy[0] != 0x04 {
			return nil, errors.New("EC raw key must be an uncompressed point")
		}
		x := new(big.Int).SetBytes(cpy[1 : 1+size])
		y := new(big.Int).SetBytes(cpy[1+size:])
		if !curve.IsOnCurve(x, y) {
			return nil, errors.New("invalid EC raw public key")
		}
		pub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
		return &cryptoKey{
			Type:        "public",
			Extractable: true,
			Algorithm: map[string]any{
				"name":       "ECDSA",
				"namedCurve": normCurveName,
			},
			Usages:      usages,
			ECDSAPublic: pub,
		}, nil
	case "ECDH":
		if algObj == nil {
			return nil, errors.New("algorithm.namedCurve is required")
		}
		curveRaw, ok := algObj["namedCurve"]
		if !ok || curveRaw == nil {
			return nil, errors.New("algorithm.namedCurve is required")
		}
		curveName, err := toString(curveRaw, "algorithm.namedCurve")
		if err != nil {
			return nil, err
		}
		curve, normCurveName, err := namedCurveByName(curveName)
		if err != nil {
			return nil, err
		}
		size := (curve.Params().BitSize + 7) / 8
		if len(cpy) != 1+2*size || cpy[0] != 0x04 {
			return nil, errors.New("EC raw key must be an uncompressed point")
		}
		x := new(big.Int).SetBytes(cpy[1 : 1+size])
		y := new(big.Int).SetBytes(cpy[1+size:])
		if !curve.IsOnCurve(x, y) {
			return nil, errors.New("invalid EC raw public key")
		}
		pub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
		return &cryptoKey{
			Type:        "public",
			Extractable: true,
			Algorithm: map[string]any{
				"name":       "ECDH",
				"namedCurve": normCurveName,
			},
			Usages:     usages,
			ECDHPublic: pub,
		}, nil
	case "X25519":
		keyType, keyTypeErr := rawKeyTypeHint(algObj)
		if keyTypeErr != nil {
			return nil, keyTypeErr
		}
		if len(cpy) != 32 {
			if keyType == "private" {
				return nil, errors.New("X25519 raw private key length must be 32 bytes")
			}
			return nil, errors.New("X25519 raw public key length must be 32 bytes")
		}
		if keyType == "private" {
			priv, err := ecdh.X25519().NewPrivateKey(cpy)
			if err != nil {
				return nil, err
			}
			return &cryptoKey{
				Type:          "private",
				Extractable:   extractable,
				Algorithm:     map[string]any{"name": "X25519"},
				Usages:        usages,
				X25519Private: priv,
			}, nil
		}
		pub, err := ecdh.X25519().NewPublicKey(cpy)
		if err != nil {
			return nil, err
		}
		return &cryptoKey{
			Type:         "public",
			Extractable:  true,
			Algorithm:    map[string]any{"name": "X25519"},
			Usages:       usages,
			X25519Public: pub,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported raw key algorithm: %s", algorithm)
	}
}

func importJWK(algorithm string, algObj map[string]any, jwk map[string]any, extractable bool, usages []string) (*cryptoKey, error) {
	kty, _ := jwk["kty"].(string)
	switch strings.ToUpper(strings.TrimSpace(kty)) {
	case "OCT":
		kStr, _ := jwk["k"].(string)
		if strings.TrimSpace(kStr) == "" {
			return nil, errors.New("invalid oct JWK: missing k")
		}
		raw, err := base64.RawURLEncoding.DecodeString(kStr)
		if err != nil {
			return nil, errors.New("invalid oct JWK key material")
		}
		return importRawKey(algorithm, algObj, raw, extractable, usages)
	case "RSA":
		return importRSAJWK(algorithm, algObj, jwk, extractable, usages)
	case "OKP":
		crv := strings.TrimSpace(stringFromMap(jwk, "crv"))
		xEnc := stringFromMap(jwk, "x")
		if xEnc == "" {
			return nil, errors.New("invalid OKP JWK: missing x")
		}
		x, err := base64.RawURLEncoding.DecodeString(xEnc)
		if err != nil {
			return nil, errors.New("invalid OKP JWK x")
		}
		dEnc := stringFromMap(jwk, "d")
		switch strings.ToUpper(crv) {
		case "ED25519":
			if algorithm != "Ed25519" {
				return nil, errors.New("OKP Ed25519 key requires Ed25519 algorithm")
			}
			if dEnc != "" {
				d, err := base64.RawURLEncoding.DecodeString(dEnc)
				if err != nil {
					return nil, errors.New("invalid OKP JWK d")
				}
				if len(d) != ed25519.SeedSize {
					return nil, errors.New("invalid Ed25519 private seed length")
				}
				priv := ed25519.NewKeyFromSeed(d)
				return &cryptoKey{
					Type:           "private",
					Extractable:    extractable,
					Algorithm:      map[string]any{"name": "Ed25519"},
					Usages:         usages,
					Ed25519Private: priv,
				}, nil
			}
			if len(x) != ed25519.PublicKeySize {
				return nil, errors.New("invalid Ed25519 public key length")
			}
			return &cryptoKey{
				Type:          "public",
				Extractable:   true,
				Algorithm:     map[string]any{"name": "Ed25519"},
				Usages:        usages,
				Ed25519Public: ed25519.PublicKey(x),
			}, nil
		case "X25519":
			if algorithm != "X25519" {
				return nil, errors.New("OKP X25519 key requires X25519 algorithm")
			}
			if len(x) != 32 {
				return nil, errors.New("invalid X25519 public key length")
			}
			if dEnc != "" {
				d, err := base64.RawURLEncoding.DecodeString(dEnc)
				if err != nil {
					return nil, errors.New("invalid OKP JWK d")
				}
				priv, err := ecdh.X25519().NewPrivateKey(d)
				if err != nil {
					return nil, err
				}
				return &cryptoKey{
					Type:          "private",
					Extractable:   extractable,
					Algorithm:     map[string]any{"name": "X25519"},
					Usages:        usages,
					X25519Private: priv,
				}, nil
			}
			pub, err := ecdh.X25519().NewPublicKey(x)
			if err != nil {
				return nil, err
			}
			return &cryptoKey{
				Type:         "public",
				Extractable:  true,
				Algorithm:    map[string]any{"name": "X25519"},
				Usages:       usages,
				X25519Public: pub,
			}, nil
		default:
			return nil, errors.New("unsupported OKP crv")
		}
	case "EC":
		if algorithm != "ECDSA" && algorithm != "ECDH" {
			return nil, errors.New("EC JWK currently supports only ECDSA/ECDH algorithm")
		}
		crv := strings.TrimSpace(stringFromMap(jwk, "crv"))
		curve, normCurveName, err := namedCurveByName(crv)
		if err != nil {
			return nil, err
		}
		xNum, err := parseJWKBigInt(jwk, "x")
		if err != nil {
			return nil, err
		}
		yNum, err := parseJWKBigInt(jwk, "y")
		if err != nil {
			return nil, err
		}
		pub := &ecdsa.PublicKey{Curve: curve, X: xNum, Y: yNum}
		if !curve.IsOnCurve(xNum, yNum) {
			return nil, errors.New("invalid EC JWK point")
		}
		if hasMapKey(jwk, "d") {
			dNum, err := parseJWKBigInt(jwk, "d")
			if err != nil {
				return nil, err
			}
			priv := &ecdsa.PrivateKey{PublicKey: *pub, D: dNum}
			return &cryptoKey{
				Type:        "private",
				Extractable: extractable,
				Algorithm: map[string]any{
					"name":       algorithm,
					"namedCurve": normCurveName,
				},
				Usages: usages,
				ECDSAPrivate: func() *ecdsa.PrivateKey {
					if algorithm == "ECDSA" {
						return priv
					}
					return nil
				}(),
				ECDHPrivate: func() *ecdsa.PrivateKey {
					if algorithm == "ECDH" {
						return priv
					}
					return nil
				}(),
			}, nil
		}
		return &cryptoKey{
			Type:        "public",
			Extractable: true,
			Algorithm: map[string]any{
				"name":       algorithm,
				"namedCurve": normCurveName,
			},
			Usages: usages,
			ECDSAPublic: func() *ecdsa.PublicKey {
				if algorithm == "ECDSA" {
					return pub
				}
				return nil
			}(),
			ECDHPublic: func() *ecdsa.PublicKey {
				if algorithm == "ECDH" {
					return pub
				}
				return nil
			}(),
		}, nil
	default:
		return nil, errors.New("unsupported JWK kty")
	}
}

func jwkAlgForSymmetricKey(key *cryptoKey) string {
	if key == nil || key.Algorithm == nil {
		return ""
	}
	name, _ := key.Algorithm["name"].(string)
	switch name {
	case "AES-GCM":
		switch len(key.SecretKey) * 8 {
		case 128:
			return "A128GCM"
		case 192:
			return "A192GCM"
		case 256:
			return "A256GCM"
		}
	case "AES-KW":
		switch len(key.SecretKey) * 8 {
		case 128:
			return "A128KW"
		case 192:
			return "A192KW"
		case 256:
			return "A256KW"
		}
	case "HMAC":
		hashName := key.HMACHash
		if hashName == "" {
			hashName = "SHA-256"
		}
		switch hashName {
		case "SHA-256":
			return "HS256"
		case "SHA-384":
			return "HS384"
		case "SHA-512":
			return "HS512"
		case "SHA-1":
			return "HS1"
		case "MD5":
			return "HMD5"
		}
	}
	return ""
}

func exportJWK(key *cryptoKey) (map[string]any, error) {
	if key == nil {
		return nil, errors.New("invalid key")
	}
	if len(key.SecretKey) > 0 {
		jwk := map[string]any{
			"kty":     "oct",
			"k":       base64.RawURLEncoding.EncodeToString(key.SecretKey),
			"key_ops": append([]string{}, key.Usages...),
			"ext":     key.Extractable,
		}
		if alg := jwkAlgForSymmetricKey(key); alg != "" {
			jwk["alg"] = alg
		}
		return jwk, nil
	}
	if key.RSAPublic != nil || key.RSAPrivate != nil {
		return exportRSAJWK(key)
	}
	if len(key.Ed25519Public) != 0 || len(key.Ed25519Private) != 0 {
		jwk := map[string]any{
			"kty":     "OKP",
			"crv":     "Ed25519",
			"key_ops": append([]string{}, key.Usages...),
			"ext":     key.Extractable,
		}
		if alg := jwkAlgForAsymmetricKey(key); alg != "" {
			jwk["alg"] = alg
		}
		pub := key.Ed25519Public
		if len(pub) == 0 {
			pub = key.Ed25519Private.Public().(ed25519.PublicKey)
		}
		jwk["x"] = base64.RawURLEncoding.EncodeToString(pub)
		if len(key.Ed25519Private) != 0 {
			jwk["d"] = base64.RawURLEncoding.EncodeToString(key.Ed25519Private.Seed())
		}
		return jwk, nil
	}
	if key.X25519Public != nil || key.X25519Private != nil {
		jwk := map[string]any{
			"kty":     "OKP",
			"crv":     "X25519",
			"key_ops": append([]string{}, key.Usages...),
			"ext":     key.Extractable,
		}
		if alg := jwkAlgForAsymmetricKey(key); alg != "" {
			jwk["alg"] = alg
		}
		pub := key.X25519Public
		if pub == nil && key.X25519Private != nil {
			pub = key.X25519Private.PublicKey()
		}
		if pub == nil {
			return nil, errors.New("X25519 JWK export requires a key")
		}
		jwk["x"] = base64.RawURLEncoding.EncodeToString(pub.Bytes())
		if key.X25519Private != nil {
			jwk["d"] = base64.RawURLEncoding.EncodeToString(key.X25519Private.Bytes())
		}
		return jwk, nil
	}
	if key.ECDHPublic != nil || key.ECDHPrivate != nil {
		jwk := map[string]any{
			"kty":     "EC",
			"key_ops": append([]string{}, key.Usages...),
			"ext":     key.Extractable,
		}
		if alg := jwkAlgForAsymmetricKey(key); alg != "" {
			jwk["alg"] = alg
		}
		pub := key.ECDHPublic
		if pub == nil && key.ECDHPrivate != nil {
			pub = &key.ECDHPrivate.PublicKey
		}
		if pub == nil {
			return nil, errors.New("EC JWK export requires an EC key")
		}
		size := (pub.Curve.Params().BitSize + 7) / 8
		jwk["crv"] = namedCurveFromElliptic(pub.Curve)
		jwk["x"] = base64.RawURLEncoding.EncodeToString(leftPad(pub.X.Bytes(), size))
		jwk["y"] = base64.RawURLEncoding.EncodeToString(leftPad(pub.Y.Bytes(), size))
		if key.ECDHPrivate != nil {
			jwk["d"] = base64.RawURLEncoding.EncodeToString(leftPad(key.ECDHPrivate.D.Bytes(), size))
		}
		return jwk, nil
	}
	if key.ECDSAPublic != nil || key.ECDSAPrivate != nil {
		jwk := map[string]any{
			"kty":     "EC",
			"key_ops": append([]string{}, key.Usages...),
			"ext":     key.Extractable,
		}
		if alg := jwkAlgForAsymmetricKey(key); alg != "" {
			jwk["alg"] = alg
		}
		pub := key.ECDSAPublic
		if pub == nil && key.ECDSAPrivate != nil {
			pub = &key.ECDSAPrivate.PublicKey
		}
		if pub == nil {
			return nil, errors.New("EC JWK export requires an EC key")
		}
		size := (pub.Curve.Params().BitSize + 7) / 8
		jwk["crv"] = namedCurveFromElliptic(pub.Curve)
		jwk["x"] = base64.RawURLEncoding.EncodeToString(leftPad(pub.X.Bytes(), size))
		jwk["y"] = base64.RawURLEncoding.EncodeToString(leftPad(pub.Y.Bytes(), size))
		if key.ECDSAPrivate != nil {
			jwk["d"] = base64.RawURLEncoding.EncodeToString(leftPad(key.ECDSAPrivate.D.Bytes(), size))
		}
		return jwk, nil
	}
	return nil, errors.New("unsupported key type for JWK export")
}

func (s *KeyStore) exportKeyBytesForWrap(format string, key *cryptoKey) ([]byte, error) {
	switch format {
	case "raw":
		if len(key.SecretKey) == 0 {
			return nil, errors.New("raw export requires a secret key")
		}
		out := make([]byte, len(key.SecretKey))
		copy(out, key.SecretKey)
		return out, nil
	case "jwk":
		jwk, err := exportJWK(key)
		if err != nil {
			return nil, err
		}
		raw, err := json.Marshal(jwk)
		if err != nil {
			return nil, err
		}
		return raw, nil
	case "pkcs8":
		var privAny any
		if key.RSAPrivate != nil {
			privAny = key.RSAPrivate
		} else if key.ECDSAPrivate != nil {
			privAny = key.ECDSAPrivate
		} else if key.ECDHPrivate != nil {
			privAny = key.ECDHPrivate
		} else if len(key.Ed25519Private) != 0 {
			privAny = key.Ed25519Private
		} else if key.X25519Private != nil {
			privAny = key.X25519Private
		} else {
			return nil, errors.New("pkcs8 export requires a private key")
		}
		return x509.MarshalPKCS8PrivateKey(privAny)
	case "pkcs1":
		if key.RSAPrivate != nil {
			return x509.MarshalPKCS1PrivateKey(key.RSAPrivate), nil
		}
		pub := key.RSAPublic
		if pub == nil && key.RSAPrivate != nil {
			pub = &key.RSAPrivate.PublicKey
		}
		if pub == nil {
			return nil, errors.New("pkcs1 export requires an RSA key")
		}
		return x509.MarshalPKCS1PublicKey(pub), nil
	case "sec1":
		var ecPriv *ecdsa.PrivateKey
		if key.ECDSAPrivate != nil {
			ecPriv = key.ECDSAPrivate
		} else if key.ECDHPrivate != nil {
			ecPriv = key.ECDHPrivate
		}
		if ecPriv == nil {
			return nil, errors.New("sec1 export requires an EC private key")
		}
		return x509.MarshalECPrivateKey(ecPriv)
	case "spki":
		var pubAny any
		if key.RSAPublic != nil {
			pubAny = key.RSAPublic
		} else if key.ECDSAPublic != nil {
			pubAny = key.ECDSAPublic
		} else if key.ECDHPublic != nil {
			pubAny = key.ECDHPublic
		} else if len(key.Ed25519Public) != 0 {
			pubAny = key.Ed25519Public
		} else if key.X25519Public != nil {
			pubAny = key.X25519Public
		} else if key.RSAPrivate != nil {
			pubAny = &key.RSAPrivate.PublicKey
		} else if key.ECDSAPrivate != nil {
			pubAny = &key.ECDSAPrivate.PublicKey
		} else if key.ECDHPrivate != nil {
			pubAny = &key.ECDHPrivate.PublicKey
		} else if len(key.Ed25519Private) != 0 {
			pubAny = key.Ed25519Private.Public().(ed25519.PublicKey)
		} else if key.X25519Private != nil {
			pubAny = key.X25519Private.PublicKey()
		} else {
			return nil, errors.New("spki export requires a public key")
		}
		return x509.MarshalPKIXPublicKey(pubAny)
	default:
		return nil, fmt.Errorf("unsupported wrap format: %s", format)
	}
}

func (s *KeyStore) saveKey(key *cryptoKey) keyPublic {
	seq := s.seq.Add(1)
	id := fmt.Sprintf("k%d", seq)
	stored := &cryptoKey{
		ID:          id,
		Type:        key.Type,
		Extractable: key.Extractable,
		Algorithm:   cloneMapAny(key.Algorithm),
		Usages:      append([]string{}, key.Usages...),
		HMACHash:    key.HMACHash,
	}
	if len(key.SecretKey) > 0 {
		stored.SecretKey = make([]byte, len(key.SecretKey))
		copy(stored.SecretKey, key.SecretKey)
	}
	if len(key.Ed25519Public) > 0 {
		stored.Ed25519Public = make([]byte, len(key.Ed25519Public))
		copy(stored.Ed25519Public, key.Ed25519Public)
	}
	if len(key.Ed25519Private) > 0 {
		stored.Ed25519Private = make([]byte, len(key.Ed25519Private))
		copy(stored.Ed25519Private, key.Ed25519Private)
	}
	stored.ECDSAPublic = key.ECDSAPublic
	stored.ECDSAPrivate = key.ECDSAPrivate
	stored.ECDHPublic = key.ECDHPublic
	stored.ECDHPrivate = key.ECDHPrivate
	stored.RSAPublic = key.RSAPublic
	stored.RSAPrivate = key.RSAPrivate
	stored.X25519Public = key.X25519Public
	stored.X25519Private = key.X25519Private
	s.mu.Lock()
	s.keys[id] = stored
	s.mu.Unlock()
	return toPublicKey(stored)
}

func toPublicKey(key *cryptoKey) keyPublic {
	return keyPublic{
		ID:          key.ID,
		Type:        key.Type,
		Extractable: key.Extractable,
		Algorithm:   cloneMapAny(key.Algorithm),
		Usages:      append([]string{}, key.Usages...),
	}
}

func keyRefFromKey(key *cryptoKey) KeyRef {
	if key == nil {
		return KeyRef{}
	}
	return KeyRef{ID: key.ID}
}

func (s *KeyStore) requireKey(v any, field string) (*cryptoKey, error) {
	id, err := extractKeyID(v)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	s.mu.RLock()
	key, ok := s.keys[id]
	s.mu.RUnlock()
	if !ok || key == nil {
		return nil, errors.New("invalid CryptoKey")
	}
	return key, nil
}

func extractKeyID(v any) (string, error) {
	switch x := v.(type) {
	case KeyRef:
		if strings.TrimSpace(x.ID) == "" {
			return "", errors.New("invalid CryptoKey")
		}
		return x.ID, nil
	case *KeyRef:
		if x == nil || strings.TrimSpace(x.ID) == "" {
			return "", errors.New("invalid CryptoKey")
		}
		return x.ID, nil
	case map[string]any:
		if id, ok := x["id"].(string); ok && strings.TrimSpace(id) != "" {
			return id, nil
		}
		if id, ok := x["__sdKeyID"].(string); ok && strings.TrimSpace(id) != "" {
			return id, nil
		}
		return "", errors.New("invalid CryptoKey")
	default:
		return "", errors.New("invalid CryptoKey")
	}
}

func decodeNode(raw json.RawMessage) (any, error) {
	var node encodedNode
	if err := json.Unmarshal(raw, &node); err != nil {
		return nil, err
	}
	switch node.T {
	case "prim":
		var out any
		if len(node.V) == 0 || string(node.V) == "null" {
			return nil, nil
		}
		if err := json.Unmarshal(node.V, &out); err != nil {
			return nil, err
		}
		return out, nil
	case "bin":
		return decodeByteArray(node.V)
	case "key":
		var payload struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(node.V, &payload); err != nil {
			return nil, err
		}
		return KeyRef{ID: strings.TrimSpace(payload.ID)}, nil
	case "arr":
		var arr []json.RawMessage
		if err := json.Unmarshal(node.V, &arr); err != nil {
			return nil, err
		}
		out := make([]any, 0, len(arr))
		for _, one := range arr {
			v, err := decodeNode(one)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case "obj":
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(node.V, &obj); err != nil {
			return nil, err
		}
		out := make(map[string]any, len(obj))
		for k, one := range obj {
			v, err := decodeNode(one)
			if err != nil {
				return nil, err
			}
			out[k] = v
		}
		return out, nil
	default:
		return nil, fmt.Errorf("invalid encoded node type: %s", node.T)
	}
}

func encodeNode(v any) (encodedNode, error) {
	switch x := v.(type) {
	case nil:
		return marshalNode("prim", nil)
	case bool, string, float64, float32, int, int64, int32, int16, int8, uint, uint64, uint32, uint16, uint8:
		return marshalNode("prim", x)
	case []byte:
		nums := make([]int, len(x))
		for i, b := range x {
			nums[i] = int(b)
		}
		return marshalNode("bin", nums)
	case KeyRef:
		return marshalNode("key", map[string]any{"id": x.ID})
	case *KeyRef:
		if x == nil {
			return marshalNode("prim", nil)
		}
		return marshalNode("key", map[string]any{"id": x.ID})
	case keyPublic:
		return marshalNode("key", map[string]any{
			"id":          x.ID,
			"type":        x.Type,
			"extractable": x.Extractable,
			"algorithm":   sanitizeForJSON(x.Algorithm),
			"usages":      x.Usages,
		})
	case *keyPublic:
		if x == nil {
			return marshalNode("prim", nil)
		}
		return marshalNode("key", map[string]any{
			"id":          x.ID,
			"type":        x.Type,
			"extractable": x.Extractable,
			"algorithm":   sanitizeForJSON(x.Algorithm),
			"usages":      x.Usages,
		})
	case map[string]any:
		enc := map[string]encodedNode{}
		for k, vv := range x {
			node, err := encodeNode(vv)
			if err != nil {
				return encodedNode{}, err
			}
			enc[k] = node
		}
		return marshalNode("obj", enc)
	case []any:
		enc := make([]encodedNode, 0, len(x))
		for _, vv := range x {
			node, err := encodeNode(vv)
			if err != nil {
				return encodedNode{}, err
			}
			enc = append(enc, node)
		}
		return marshalNode("arr", enc)
	case []string:
		arr := make([]any, len(x))
		for i, vv := range x {
			arr[i] = vv
		}
		return encodeNode(arr)
	default:
		return encodedNode{}, fmt.Errorf("unsupported encode value type: %T", v)
	}
}

func sanitizeForJSON(v any) any {
	switch x := v.(type) {
	case nil:
		return nil
	case []byte:
		out := make([]int, len(x))
		for i, b := range x {
			out[i] = int(b)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, one := range x {
			out[k] = sanitizeForJSON(one)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, one := range x {
			out[i] = sanitizeForJSON(one)
		}
		return out
	default:
		return x
	}
}

func marshalNode(t string, v any) (encodedNode, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return encodedNode{}, err
	}
	return encodedNode{T: t, V: raw}, nil
}

func decodeByteArray(raw json.RawMessage) ([]byte, error) {
	var ints []int
	if err := json.Unmarshal(raw, &ints); err == nil {
		out := make([]byte, len(ints))
		for i, v := range ints {
			if v < 0 || v > 255 {
				return nil, errors.New("invalid byte value")
			}
			out[i] = byte(v)
		}
		return out, nil
	}
	var floats []float64
	if err := json.Unmarshal(raw, &floats); err != nil {
		return nil, err
	}
	out := make([]byte, len(floats))
	for i, v := range floats {
		if v < 0 || v > 255 {
			return nil, errors.New("invalid byte value")
		}
		out[i] = byte(int(v))
	}
	return out, nil
}

func parseAlgorithmIdentifier(v any) (string, map[string]any, error) {
	switch x := v.(type) {
	case string:
		name, err := normalizeAlgorithmName(x)
		if err != nil {
			return "", nil, err
		}
		return name, nil, nil
	case map[string]any:
		nameRaw, ok := x["name"]
		if !ok {
			return "", nil, errors.New("algorithm.name is required")
		}
		name, err := toString(nameRaw, "algorithm.name")
		if err != nil {
			return "", nil, err
		}
		norm, err := normalizeAlgorithmName(name)
		if err != nil {
			return "", nil, err
		}
		return norm, x, nil
	default:
		return "", nil, errors.New("algorithm must be string or object")
	}
}

func normalizeAlgorithmName(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("algorithm name is required")
	}
	n := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(raw, "_", "-"), " ", ""))
	switch n {
	case "MD5":
		return "MD5", nil
	case "SHA-1", "SHA1":
		return "SHA-1", nil
	case "SHA-224", "SHA224":
		return "SHA-224", nil
	case "SHA-256", "SHA256":
		return "SHA-256", nil
	case "SHA-384", "SHA384":
		return "SHA-384", nil
	case "SHA-512", "SHA512":
		return "SHA-512", nil
	case "AES-CBC", "AESCBC":
		return "AES-CBC", nil
	case "AES-GCM", "AESGCM":
		return "AES-GCM", nil
	case "AES-CTR", "AESCTR":
		return "AES-CTR", nil
	case "AES-KW", "AESKW":
		return "AES-KW", nil
	case "DES-CBC", "DESCBC":
		return "DES-CBC", nil
	case "3DES-CBC", "3DESCBC", "TRIPLEDES-CBC", "TRIPLEDESCBC", "DES-EDE3-CBC", "DES3-CBC":
		return "3DES-CBC", nil
	case "HMAC":
		return "HMAC", nil
	case "PBKDF2":
		return "PBKDF2", nil
	case "HKDF":
		return "HKDF", nil
	case "ED25519":
		return "Ed25519", nil
	case "ECDSA":
		return "ECDSA", nil
	case "ECDH":
		return "ECDH", nil
	case "X25519":
		return "X25519", nil
	case "RSA-PSS", "RSAPSS":
		return "RSA-PSS", nil
	case "RSASSA-PKCS1-V1_5", "RSASSA-PKCS1-V1.5", "RSASSA-PKCS1-V1-5", "RSASSAPKCS1V15", "RSASSA-PKCS1V1_5":
		return "RSASSA-PKCS1-V1_5", nil
	case "RSA-OAEP", "RSAOAEP":
		return "RSA-OAEP", nil
	case "RSAES-PKCS1-V1_5", "RSAES-PKCS1-V1.5", "RSAES-PKCS1-V1-5", "RSAESPKCS1V15":
		return "RSAES-PKCS1-V1_5", nil
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", raw)
	}
}

func hashFromAlgorithmObject(obj map[string]any, defaultName string) (string, error) {
	if obj == nil {
		return normalizeAlgorithmName(defaultName)
	}
	hv, ok := obj["hash"]
	if !ok {
		return normalizeAlgorithmName(defaultName)
	}
	return hashFromAlgorithmValue(hv)
}

func hashFromAlgorithmValue(v any) (string, error) {
	switch x := v.(type) {
	case string:
		return normalizeHashName(x)
	case map[string]any:
		nameRaw, ok := x["name"]
		if !ok {
			return "", errors.New("hash.name is required")
		}
		name, err := toString(nameRaw, "hash.name")
		if err != nil {
			return "", err
		}
		return normalizeHashName(name)
	default:
		return "", errors.New("invalid hash algorithm")
	}
}

func normalizeHashName(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("hash name is required")
	}
	n := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(raw, "_", "-"), " ", ""))
	switch n {
	case "MD5":
		return "MD5", nil
	case "SHA-1", "SHA1":
		return "SHA-1", nil
	case "SHA-224", "SHA224":
		return "SHA-224", nil
	case "SHA-256", "SHA256":
		return "SHA-256", nil
	case "SHA-384", "SHA384":
		return "SHA-384", nil
	case "SHA-512", "SHA512":
		return "SHA-512", nil
	default:
		return "", fmt.Errorf("unsupported hash algorithm: %s", raw)
	}
}

func hashFactory(name string) (func() hash.Hash, error) {
	switch name {
	case "MD5":
		return md5.New, nil
	case "SHA-1":
		return sha1.New, nil
	case "SHA-224":
		return sha256.New224, nil
	case "SHA-256":
		return sha256.New, nil
	case "SHA-384":
		return sha512.New384, nil
	case "SHA-512":
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %s", name)
	}
}

func digestBytes(algorithm string, data []byte) ([]byte, error) {
	switch algorithm {
	case "MD5":
		sum := md5.Sum(data)
		return sum[:], nil
	case "SHA-1":
		sum := sha1.Sum(data)
		return sum[:], nil
	case "SHA-224":
		sum := sha256.Sum224(data)
		return sum[:], nil
	case "SHA-256":
		sum := sha256.Sum256(data)
		return sum[:], nil
	case "SHA-384":
		sum := sha512.Sum384(data)
		return sum[:], nil
	case "SHA-512":
		sum := sha512.Sum512(data)
		return sum[:], nil
	default:
		return nil, fmt.Errorf("unsupported digest algorithm: %s", algorithm)
	}
}

func digestLengthBytes(hashName string) int {
	switch hashName {
	case "MD5":
		return md5.Size
	case "SHA-1":
		return sha1.Size
	case "SHA-224":
		return sha256.Size224
	case "SHA-256":
		return sha256.Size
	case "SHA-384":
		return sha512.Size384
	case "SHA-512":
		return sha512.Size
	default:
		return 32
	}
}

func validateAESGCMTagLength(tagLength int) error {
	switch tagLength {
	case 32, 64, 96, 104, 112, 120, 128:
		return nil
	default:
		return errors.New("invalid AES-GCM tagLength")
	}
}

func newAESGCMForParams(block cipher.Block, ivLen int, tagLengthBits int) (cipher.AEAD, error) {
	tagBytes := tagLengthBits / 8
	if ivLen == 12 {
		return cipher.NewGCMWithTagSize(block, tagBytes)
	}
	if tagBytes != 16 {
		return nil, errors.New("AES-GCM non-12-byte iv requires tagLength 128")
	}
	return cipher.NewGCMWithNonceSize(block, ivLen)
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - len(data)%blockSize
	if padLen == 0 {
		padLen = blockSize
	}
	pad := bytes.Repeat([]byte{byte(padLen)}, padLen)
	out := make([]byte, 0, len(data)+padLen)
	out = append(out, data...)
	out = append(out, pad...)
	return out
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("invalid PKCS7 padding")
	}
	padLen := int(data[len(data)-1])
	if padLen <= 0 || padLen > blockSize || padLen > len(data) {
		return nil, errors.New("invalid PKCS7 padding")
	}
	for i := len(data) - padLen; i < len(data); i++ {
		if int(data[i]) != padLen {
			return nil, errors.New("invalid PKCS7 padding")
		}
	}
	return data[:len(data)-padLen], nil
}

func aesKeyWrap(kek []byte, plaintext []byte) ([]byte, error) {
	if len(plaintext) < 16 || len(plaintext)%8 != 0 {
		return nil, errors.New("AES-KW plaintext length must be multiple of 8 and at least 16")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := len(plaintext) / 8
	a := []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}
	r := make([][]byte, n)
	for i := 0; i < n; i++ {
		r[i] = make([]byte, 8)
		copy(r[i], plaintext[i*8:(i+1)*8])
	}

	buf := make([]byte, 16)
	for j := 0; j < 6; j++ {
		for i := 0; i < n; i++ {
			copy(buf[:8], a)
			copy(buf[8:], r[i])
			block.Encrypt(buf, buf)
			t := uint64(n*j + i + 1)
			xorT(buf[:8], t)
			copy(a, buf[:8])
			copy(r[i], buf[8:])
		}
	}

	out := make([]byte, 8+8*n)
	copy(out[:8], a)
	for i := 0; i < n; i++ {
		copy(out[8+i*8:8+(i+1)*8], r[i])
	}
	return out, nil
}

func aesKeyUnwrap(kek []byte, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 24 || len(ciphertext)%8 != 0 {
		return nil, errors.New("AES-KW ciphertext length must be multiple of 8 and at least 24")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := len(ciphertext)/8 - 1
	a := make([]byte, 8)
	copy(a, ciphertext[:8])
	r := make([][]byte, n)
	for i := 0; i < n; i++ {
		r[i] = make([]byte, 8)
		copy(r[i], ciphertext[8+i*8:8+(i+1)*8])
	}

	buf := make([]byte, 16)
	for j := 5; j >= 0; j-- {
		for i := n - 1; i >= 0; i-- {
			copy(buf[:8], a)
			t := uint64(n*j + i + 1)
			xorT(buf[:8], t)
			copy(buf[8:], r[i])
			block.Decrypt(buf, buf)
			copy(a, buf[:8])
			copy(r[i], buf[8:])
		}
	}
	iv := []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}
	if !bytes.Equal(a, iv) {
		return nil, errors.New("AES-KW integrity check failed")
	}

	out := make([]byte, 8*n)
	for i := 0; i < n; i++ {
		copy(out[i*8:(i+1)*8], r[i])
	}
	return out, nil
}

func tripleDESKey(raw []byte) ([]byte, error) {
	switch len(raw) {
	case 24:
		out := make([]byte, 24)
		copy(out, raw)
		return out, nil
	case 16:
		// 2-key 3DES: K1 || K2 || K1
		out := make([]byte, 24)
		copy(out[:16], raw)
		copy(out[16:], raw[:8])
		return out, nil
	default:
		return nil, errors.New("3DES-CBC requires a 16-byte or 24-byte secret key")
	}
}

func xorT(a []byte, t uint64) {
	for i := 7; i >= 0; i-- {
		a[i] ^= byte(t & 0xff)
		t >>= 8
	}
}

func toString(v any, field string) (string, error) {
	switch x := v.(type) {
	case string:
		return x, nil
	default:
		return "", fmt.Errorf("%s must be a string", field)
	}
}

func toBool(v any, field string) (bool, error) {
	switch x := v.(type) {
	case bool:
		return x, nil
	case float64:
		return x != 0, nil
	case int:
		return x != 0, nil
	default:
		return false, fmt.Errorf("%s must be a boolean", field)
	}
}

func toInt(v any, field string) (int, error) {
	switch x := v.(type) {
	case int:
		return x, nil
	case int64:
		return int(x), nil
	case float64:
		return int(x), nil
	default:
		return 0, fmt.Errorf("%s must be a number", field)
	}
}

func toStringSlice(v any, field string) ([]string, error) {
	switch x := v.(type) {
	case nil:
		return nil, nil
	case []string:
		return append([]string{}, x...), nil
	case []any:
		out := make([]string, 0, len(x))
		for _, one := range x {
			s, ok := one.(string)
			if !ok {
				return nil, fmt.Errorf("%s must contain strings", field)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%s must be an array", field)
	}
}

func usageContains(usages []string, target string) bool {
	for _, u := range usages {
		if u == target {
			return true
		}
	}
	return false
}

func rawKeyTypeHint(algObj map[string]any) (string, error) {
	if algObj == nil {
		return "", nil
	}
	for _, key := range []string{"keyType", "type"} {
		v, ok := algObj[key]
		if !ok || v == nil {
			continue
		}
		s, err := toString(v, "algorithm."+key)
		if err != nil {
			return "", err
		}
		raw := strings.TrimSpace(strings.ToLower(s))
		switch raw {
		case "public":
			return "public", nil
		case "private":
			return "private", nil
		default:
			return "", fmt.Errorf("algorithm.%s must be 'public' or 'private'", key)
		}
	}
	return "", nil
}

func requireBytes(v any, field string) ([]byte, error) {
	data, ok := v.([]byte)
	if !ok {
		return nil, fmt.Errorf("%s must be ArrayBuffer/TypedArray", field)
	}
	out := make([]byte, len(data))
	copy(out, data)
	return out, nil
}

func intField(obj map[string]any, key string, required bool, def int) (int, error) {
	if obj == nil {
		if required {
			return 0, fmt.Errorf("algorithm.%s is required", key)
		}
		return def, nil
	}
	v, ok := obj[key]
	if !ok || v == nil {
		if required {
			return 0, fmt.Errorf("algorithm.%s is required", key)
		}
		return def, nil
	}
	i, err := toInt(v, "algorithm."+key)
	if err != nil {
		return 0, err
	}
	if i <= 0 && required {
		return 0, fmt.Errorf("algorithm.%s must be > 0", key)
	}
	if i <= 0 && !required {
		return def, nil
	}
	return i, nil
}

func bytesField(obj map[string]any, key string, required bool) ([]byte, error) {
	if obj == nil {
		if required {
			return nil, fmt.Errorf("algorithm.%s is required", key)
		}
		return nil, nil
	}
	v, ok := obj[key]
	if !ok || v == nil {
		if required {
			return nil, fmt.Errorf("algorithm.%s is required", key)
		}
		return nil, nil
	}
	return requireBytes(v, "algorithm."+key)
}

func cloneMapAny(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	dst := make(map[string]any, len(src))
	for k, v := range src {
		switch vv := v.(type) {
		case map[string]any:
			dst[k] = cloneMapAny(vv)
		case []byte:
			cp := make([]byte, len(vv))
			copy(cp, vv)
			dst[k] = cp
		case []string:
			cp := make([]string, len(vv))
			copy(cp, vv)
			dst[k] = cp
		default:
			dst[k] = vv
		}
	}
	return dst
}
