package sealcrypto

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"strings"

	"github.com/dop251/goja"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

const (
	maxGetRandomValuesBytes = 65536
	keyHandleSlot           = "__sealcrypto_key_handle__"
)

var integerTypedArrayNames = map[string]struct{}{
	"Int8Array":         {},
	"Uint8Array":        {},
	"Uint8ClampedArray": {},
	"Int16Array":        {},
	"Uint16Array":       {},
	"Int32Array":        {},
	"Uint32Array":       {},
	"BigInt64Array":     {},
	"BigUint64Array":    {},
}

type cryptoKeyHandle struct {
	Type        string
	Extractable bool
	Algorithm   map[string]interface{}
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

func Enable(rt *goja.Runtime) {
	_ = rt.Set("crypto", ensureCryptoObject(rt))
}

func Require(rt *goja.Runtime, module *goja.Object) {
	_ = module.Set("exports", ensureCryptoObject(rt))
}

func ensureCryptoObject(rt *goja.Runtime) *goja.Object {
	ensureTextEncodingGlobals(rt)

	if current := rt.Get("crypto"); !goja.IsUndefined(current) && !goja.IsNull(current) {
		if obj, ok := current.(*goja.Object); ok {
			return obj
		}
	}

	cryptoObj := rt.NewObject()
	subtleObj := rt.NewObject()

	_ = subtleObj.Set("digest", func(call goja.FunctionCall) goja.Value {
		return subtleDigest(rt, call)
	})
	_ = subtleObj.Set("generateKey", func(call goja.FunctionCall) goja.Value {
		return subtleGenerateKey(rt, call)
	})
	_ = subtleObj.Set("importKey", func(call goja.FunctionCall) goja.Value {
		return subtleImportKey(rt, call)
	})
	_ = subtleObj.Set("exportKey", func(call goja.FunctionCall) goja.Value {
		return subtleExportKey(rt, call)
	})
	_ = subtleObj.Set("sign", func(call goja.FunctionCall) goja.Value {
		return subtleSign(rt, call)
	})
	_ = subtleObj.Set("verify", func(call goja.FunctionCall) goja.Value {
		return subtleVerify(rt, call)
	})
	_ = subtleObj.Set("encrypt", func(call goja.FunctionCall) goja.Value {
		return subtleEncrypt(rt, call)
	})
	_ = subtleObj.Set("decrypt", func(call goja.FunctionCall) goja.Value {
		return subtleDecrypt(rt, call)
	})
	_ = subtleObj.Set("deriveBits", func(call goja.FunctionCall) goja.Value {
		return subtleDeriveBits(rt, call)
	})
	_ = subtleObj.Set("deriveKey", func(call goja.FunctionCall) goja.Value {
		return subtleDeriveKey(rt, call)
	})
	_ = subtleObj.Set("wrapKey", func(call goja.FunctionCall) goja.Value {
		return subtleWrapKey(rt, call)
	})
	_ = subtleObj.Set("unwrapKey", func(call goja.FunctionCall) goja.Value {
		return subtleUnwrapKey(rt, call)
	})

	_ = cryptoObj.Set("subtle", subtleObj)
	_ = cryptoObj.Set("getRandomValues", func(call goja.FunctionCall) goja.Value {
		return getRandomValues(rt, call)
	})
	_ = cryptoObj.Set("randomUUID", func() string {
		return randomUUID()
	})

	_ = rt.Set("crypto", cryptoObj)
	return cryptoObj
}

func getRandomValues(rt *goja.Runtime, call goja.FunctionCall) goja.Value {
	target := call.Argument(0)
	bytesData, err := bufferSourceBytes(rt, target, false, true)
	if err != nil {
		panic(rt.NewTypeError("crypto.getRandomValues: " + err.Error()))
	}
	if len(bytesData) > maxGetRandomValuesBytes {
		panic(rt.NewTypeError("crypto.getRandomValues: byteLength exceeds 65536"))
	}
	if _, err = rand.Read(bytesData); err != nil {
		panic(rt.NewGoError(err))
	}
	return target
}

func subtleDigest(rt *goja.Runtime, call goja.FunctionCall) goja.Value {
	algorithm, _, err := parseAlgorithmIdentifier(rt, call.Argument(0))
	if err != nil {
		return rejectedPromise(rt, err)
	}
	data, err := bufferSourceBytes(rt, call.Argument(1), true, false)
	if err != nil {
		return rejectedPromise(rt, err)
	}

	digest, err := digestBytes(algorithm, data)
	if err != nil {
		return rejectedPromise(rt, err)
	}
	return resolvedPromise(rt, rt.NewArrayBuffer(digest))
}

func subtleGenerateKey(rt *goja.Runtime, call goja.FunctionCall) goja.Value {
	algorithm, algObj, err := parseAlgorithmIdentifier(rt, call.Argument(0))
	if err != nil {
		return rejectedPromise(rt, err)
	}
	extractable := call.Argument(1).ToBoolean()
	usages, err := valueToStringSlice(call.Argument(2))
	if err != nil {
		return rejectedPromise(rt, err)
	}

	switch algorithm {
	case "AES-CBC", "AES-GCM", "AES-CTR", "AES-KW":
		length, err := intProperty(algObj, "length")
		if err != nil {
			return rejectedPromise(rt, err)
		}
		if length != 128 && length != 192 && length != 256 {
			return rejectedPromise(rt, errors.New("AES key length must be 128, 192, or 256"))
		}
		key := make([]byte, length/8)
		if _, err := rand.Read(key); err != nil {
			return rejectedPromise(rt, err)
		}
		handle := &cryptoKeyHandle{
			Type:        "secret",
			Extractable: extractable,
			Algorithm: map[string]interface{}{
				"name":   algorithm,
				"length": length,
			},
			Usages:    usages,
			SecretKey: key,
		}
		return resolvedPromise(rt, newCryptoKeyObject(rt, handle))
	case "DES-CBC":
		length := 64
		if algObj != nil {
			if v := algObj.Get("length"); isValuePresent(v) {
				length = int(v.ToInteger())
			}
		}
		if length != 64 {
			return rejectedPromise(rt, errors.New("DES-CBC key length must be 64"))
		}
		key := make([]byte, 8)
		if _, err := rand.Read(key); err != nil {
			return rejectedPromise(rt, err)
		}
		handle := &cryptoKeyHandle{
			Type:        "secret",
			Extractable: extractable,
			Algorithm: map[string]interface{}{
				"name":   "DES-CBC",
				"length": 64,
			},
			Usages:    usages,
			SecretKey: key,
		}
		return resolvedPromise(rt, newCryptoKeyObject(rt, handle))
	case "3DES-CBC":
		length := 192
		if algObj != nil {
			if v := algObj.Get("length"); isValuePresent(v) {
				length = int(v.ToInteger())
			}
		}
		if length != 128 && length != 192 {
			return rejectedPromise(rt, errors.New("3DES-CBC key length must be 128 or 192"))
		}
		key := make([]byte, length/8)
		if _, err := rand.Read(key); err != nil {
			return rejectedPromise(rt, err)
		}
		handle := &cryptoKeyHandle{
			Type:        "secret",
			Extractable: extractable,
			Algorithm: map[string]interface{}{
				"name":   "3DES-CBC",
				"length": length,
			},
			Usages:    usages,
			SecretKey: key,
		}
		return resolvedPromise(rt, newCryptoKeyObject(rt, handle))
	case "HMAC":
		hashName, err := hashFromAlgorithmObject(rt, algObj, "SHA-256")
		if err != nil {
			return rejectedPromise(rt, err)
		}
		length := 0
		if algObj != nil {
			if v := algObj.Get("length"); isValuePresent(v) {
				length = int(v.ToInteger())
			}
		}
		if length <= 0 {
			length = digestLengthBytes(hashName) * 8
		}
		key := make([]byte, length/8)
		if _, err := rand.Read(key); err != nil {
			return rejectedPromise(rt, err)
		}
		handle := &cryptoKeyHandle{
			Type:        "secret",
			Extractable: extractable,
			Algorithm: map[string]interface{}{
				"name":   "HMAC",
				"hash":   map[string]interface{}{"name": hashName},
				"length": length,
			},
			Usages:    usages,
			SecretKey: key,
			HMACHash:  hashName,
		}
		return resolvedPromise(rt, newCryptoKeyObject(rt, handle))
	case "ECDSA":
		if algObj == nil {
			return rejectedPromise(rt, errors.New("algorithm.namedCurve is required"))
		}
		curveNameVal := algObj.Get("namedCurve")
		if goja.IsUndefined(curveNameVal) || goja.IsNull(curveNameVal) {
			return rejectedPromise(rt, errors.New("algorithm.namedCurve is required"))
		}
		curveName := strings.TrimSpace(curveNameVal.String())
		curve, normCurveName, err := namedCurveByName(curveName)
		if err != nil {
			return rejectedPromise(rt, err)
		}
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return rejectedPromise(rt, err)
		}

		commonAlg := map[string]interface{}{
			"name":       "ECDSA",
			"namedCurve": normCurveName,
		}
		pubUsages, priUsages := splitECUsages("ECDSA", usages)
		pubHandle := &cryptoKeyHandle{
			Type:        "public",
			Extractable: true,
			Algorithm:   cloneMap(commonAlg),
			Usages:      pubUsages,
			ECDSAPublic: &priv.PublicKey,
		}
		priHandle := &cryptoKeyHandle{
			Type:         "private",
			Extractable:  extractable,
			Algorithm:    cloneMap(commonAlg),
			Usages:       priUsages,
			ECDSAPrivate: priv,
		}

		pair := rt.NewObject()
		_ = pair.Set("publicKey", newCryptoKeyObject(rt, pubHandle))
		_ = pair.Set("privateKey", newCryptoKeyObject(rt, priHandle))
		return resolvedPromise(rt, pair)
	case "ECDH":
		if algObj == nil {
			return rejectedPromise(rt, errors.New("algorithm.namedCurve is required"))
		}
		curveNameVal := algObj.Get("namedCurve")
		if goja.IsUndefined(curveNameVal) || goja.IsNull(curveNameVal) {
			return rejectedPromise(rt, errors.New("algorithm.namedCurve is required"))
		}
		curveName := strings.TrimSpace(curveNameVal.String())
		curve, normCurveName, err := namedCurveByName(curveName)
		if err != nil {
			return rejectedPromise(rt, err)
		}
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return rejectedPromise(rt, err)
		}

		commonAlg := map[string]interface{}{
			"name":       "ECDH",
			"namedCurve": normCurveName,
		}
		pubUsages, priUsages := splitECUsages("ECDH", usages)
		pubHandle := &cryptoKeyHandle{
			Type:        "public",
			Extractable: true,
			Algorithm:   cloneMap(commonAlg),
			Usages:      pubUsages,
			ECDHPublic:  &priv.PublicKey,
		}
		priHandle := &cryptoKeyHandle{
			Type:        "private",
			Extractable: extractable,
			Algorithm:   cloneMap(commonAlg),
			Usages:      priUsages,
			ECDHPrivate: priv,
		}

		pair := rt.NewObject()
		_ = pair.Set("publicKey", newCryptoKeyObject(rt, pubHandle))
		_ = pair.Set("privateKey", newCryptoKeyObject(rt, priHandle))
		return resolvedPromise(rt, pair)
	case "Ed25519":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return rejectedPromise(rt, err)
		}
		commonAlg := map[string]interface{}{"name": "Ed25519"}
		pubUsages, priUsages := splitOKPUsages("Ed25519", usages)
		pubHandle := &cryptoKeyHandle{
			Type:          "public",
			Extractable:   true,
			Algorithm:     cloneMap(commonAlg),
			Usages:        pubUsages,
			Ed25519Public: pub,
		}
		priHandle := &cryptoKeyHandle{
			Type:           "private",
			Extractable:    extractable,
			Algorithm:      cloneMap(commonAlg),
			Usages:         priUsages,
			Ed25519Private: priv,
		}
		pair := rt.NewObject()
		_ = pair.Set("publicKey", newCryptoKeyObject(rt, pubHandle))
		_ = pair.Set("privateKey", newCryptoKeyObject(rt, priHandle))
		return resolvedPromise(rt, pair)
	case "X25519":
		priv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return rejectedPromise(rt, err)
		}
		commonAlg := map[string]interface{}{"name": "X25519"}
		pubUsages, priUsages := splitOKPUsages("X25519", usages)
		pubHandle := &cryptoKeyHandle{
			Type:         "public",
			Extractable:  true,
			Algorithm:    cloneMap(commonAlg),
			Usages:       pubUsages,
			X25519Public: priv.PublicKey(),
		}
		priHandle := &cryptoKeyHandle{
			Type:          "private",
			Extractable:   extractable,
			Algorithm:     cloneMap(commonAlg),
			Usages:        priUsages,
			X25519Private: priv,
		}
		pair := rt.NewObject()
		_ = pair.Set("publicKey", newCryptoKeyObject(rt, pubHandle))
		_ = pair.Set("privateKey", newCryptoKeyObject(rt, priHandle))
		return resolvedPromise(rt, pair)
	case "RSASSA-PKCS1-V1_5", "RSA-PSS", "RSA-OAEP", "RSAES-PKCS1-V1_5":
		modulusLength, err := intProperty(algObj, "modulusLength")
		if err != nil {
			return rejectedPromise(rt, err)
		}
		if modulusLength < 512 {
			return rejectedPromise(rt, errors.New("modulusLength must be >= 512"))
		}
		exp, err := publicExponentFromAlg(rt, algObj)
		if err != nil {
			return rejectedPromise(rt, err)
		}
		hashName, err := hashFromAlgorithmObject(rt, algObj, "SHA-256")
		if err != nil {
			return rejectedPromise(rt, err)
		}

		priv, err := generateRSAKeyWithExponent(modulusLength, exp)
		if err != nil {
			return rejectedPromise(rt, err)
		}

		commonAlg := map[string]interface{}{
			"name":          algorithm,
			"modulusLength": modulusLength,
			"publicExponent": []byte{
				byte((exp >> 16) & 0xff),
				byte((exp >> 8) & 0xff),
				byte(exp & 0xff),
			},
			"hash": map[string]interface{}{"name": hashName},
		}

		pubUsages, priUsages := splitRSAUsages(algorithm, usages)
		pubHandle := &cryptoKeyHandle{
			Type:        "public",
			Extractable: true,
			Algorithm:   cloneMap(commonAlg),
			Usages:      pubUsages,
			RSAPublic:   &priv.PublicKey,
		}
		priHandle := &cryptoKeyHandle{
			Type:        "private",
			Extractable: extractable,
			Algorithm:   cloneMap(commonAlg),
			Usages:      priUsages,
			RSAPrivate:  priv,
		}

		pair := rt.NewObject()
		_ = pair.Set("publicKey", newCryptoKeyObject(rt, pubHandle))
		_ = pair.Set("privateKey", newCryptoKeyObject(rt, priHandle))
		return resolvedPromise(rt, pair)
	default:
		return rejectedPromise(rt, fmt.Errorf("unsupported generateKey algorithm: %s", algorithm))
	}
}

func subtleImportKey(rt *goja.Runtime, call goja.FunctionCall) goja.Value {
	format := strings.ToLower(strings.TrimSpace(call.Argument(0).String()))
	if format == "" {
		return rejectedPromise(rt, errors.New("format is required"))
	}
	algorithm, algObj, err := parseAlgorithmIdentifier(rt, call.Argument(2))
	if err != nil {
		return rejectedPromise(rt, err)
	}
	extractable := call.Argument(3).ToBoolean()
	usages, err := valueToStringSlice(call.Argument(4))
	if err != nil {
		return rejectedPromise(rt, err)
	}

	switch format {
	case "raw":
		raw, err := bufferSourceBytes(rt, call.Argument(1), true, false)
		if err != nil {
			return rejectedPromise(rt, err)
		}
		handle, err := importRawKey(rt, algorithm, algObj, raw, extractable, usages)
		if err != nil {
			return rejectedPromise(rt, err)
		}
		return resolvedPromise(rt, newCryptoKeyObject(rt, handle))
	case "jwk":
		jwk, err := parseJWK(rt, call.Argument(1))
		if err != nil {
			return rejectedPromise(rt, err)
		}
		handle, err := importJWK(rt, jwk, algorithm, algObj, extractable, usages)
		if err != nil {
			return rejectedPromise(rt, err)
		}
		return resolvedPromise(rt, newCryptoKeyObject(rt, handle))
	case "pkcs1":
		raw, err := bufferSourceBytes(rt, call.Argument(1), true, false)
		if err != nil {
			return rejectedPromise(rt, err)
		}
		if priv, err := x509.ParsePKCS1PrivateKey(raw); err == nil {
			handle, err := privateKeyToHandle(rt, priv, algorithm, algObj, extractable, usages)
			if err != nil {
				return rejectedPromise(rt, err)
			}
			return resolvedPromise(rt, newCryptoKeyObject(rt, handle))
		}
		pub, err := x509.ParsePKCS1PublicKey(raw)
		if err != nil {
			return rejectedPromise(rt, errors.New("failed to parse pkcs1 key"))
		}
		handle, err := publicKeyToHandle(rt, pub, algorithm, algObj, usages)
		if err != nil {
			return rejectedPromise(rt, err)
		}
		return resolvedPromise(rt, newCryptoKeyObject(rt, handle))
	case "sec1":
		raw, err := bufferSourceBytes(rt, call.Argument(1), true, false)
		if err != nil {
			return rejectedPromise(rt, err)
		}
		priv, err := x509.ParseECPrivateKey(raw)
		if err != nil {
			return rejectedPromise(rt, errors.New("failed to parse sec1 key"))
		}
		handle, err := privateKeyToHandle(rt, priv, algorithm, algObj, extractable, usages)
		if err != nil {
			return rejectedPromise(rt, err)
		}
		return resolvedPromise(rt, newCryptoKeyObject(rt, handle))
	case "pkcs8":
		raw, err := bufferSourceBytes(rt, call.Argument(1), true, false)
		if err != nil {
			return rejectedPromise(rt, err)
		}
		privAny, err := parsePrivateKey(raw)
		if err != nil {
			return rejectedPromise(rt, err)
		}
		handle, err := privateKeyToHandle(rt, privAny, algorithm, algObj, extractable, usages)
		if err != nil {
			return rejectedPromise(rt, err)
		}
		return resolvedPromise(rt, newCryptoKeyObject(rt, handle))
	case "spki":
		raw, err := bufferSourceBytes(rt, call.Argument(1), true, false)
		if err != nil {
			return rejectedPromise(rt, err)
		}
		pubAny, err := x509.ParsePKIXPublicKey(raw)
		if err != nil {
			return rejectedPromise(rt, err)
		}
		handle, err := publicKeyToHandle(rt, pubAny, algorithm, algObj, usages)
		if err != nil {
			return rejectedPromise(rt, err)
		}
		return resolvedPromise(rt, newCryptoKeyObject(rt, handle))
	default:
		return rejectedPromise(rt, fmt.Errorf("unsupported key format: %s", format))
	}
}

func subtleExportKey(rt *goja.Runtime, call goja.FunctionCall) goja.Value {
	format := strings.ToLower(strings.TrimSpace(call.Argument(0).String()))
	handle, err := extractCryptoKeyHandle(rt, call.Argument(1))
	if err != nil {
		return rejectedPromise(rt, err)
	}
	if !handle.Extractable {
		return rejectedPromise(rt, errors.New("key is not extractable"))
	}

	switch format {
	case "raw":
		out, err := exportRawKeyMaterial(handle)
		if err != nil {
			return rejectedPromise(rt, err)
		}
		return resolvedPromise(rt, rt.NewArrayBuffer(out))
	case "jwk":
		jwk, err := exportJWK(handle)
		if err != nil {
			return rejectedPromise(rt, err)
		}
		return resolvedPromise(rt, jwk)
	case "pkcs8":
		var privAny interface{}
		if handle.RSAPrivate != nil {
			privAny = handle.RSAPrivate
		} else if handle.ECDSAPrivate != nil {
			privAny = handle.ECDSAPrivate
		} else if handle.ECDHPrivate != nil {
			privAny = handle.ECDHPrivate
		} else if len(handle.Ed25519Private) != 0 {
			privAny = handle.Ed25519Private
		} else if handle.X25519Private != nil {
			privAny = handle.X25519Private
		} else {
			return rejectedPromise(rt, errors.New("pkcs8 export requires a private key"))
		}
		der, err := x509.MarshalPKCS8PrivateKey(privAny)
		if err != nil {
			return rejectedPromise(rt, err)
		}
		return resolvedPromise(rt, rt.NewArrayBuffer(der))
	case "pkcs1":
		if handle.RSAPrivate != nil {
			return resolvedPromise(rt, rt.NewArrayBuffer(x509.MarshalPKCS1PrivateKey(handle.RSAPrivate)))
		}
		pub := handle.RSAPublic
		if pub == nil && handle.RSAPrivate != nil {
			pub = &handle.RSAPrivate.PublicKey
		}
		if pub == nil {
			return rejectedPromise(rt, errors.New("pkcs1 export requires an RSA key"))
		}
		return resolvedPromise(rt, rt.NewArrayBuffer(x509.MarshalPKCS1PublicKey(pub)))
	case "sec1":
		var priv *ecdsa.PrivateKey
		if handle.ECDSAPrivate != nil {
			priv = handle.ECDSAPrivate
		} else if handle.ECDHPrivate != nil {
			priv = handle.ECDHPrivate
		} else {
			return rejectedPromise(rt, errors.New("sec1 export requires an EC private key"))
		}
		der, err := x509.MarshalECPrivateKey(priv)
		if err != nil {
			return rejectedPromise(rt, err)
		}
		return resolvedPromise(rt, rt.NewArrayBuffer(der))
	case "spki":
		var pubAny interface{}
		if handle.RSAPublic != nil {
			pubAny = handle.RSAPublic
		} else if handle.ECDSAPublic != nil {
			pubAny = handle.ECDSAPublic
		} else if handle.ECDHPublic != nil {
			pubAny = handle.ECDHPublic
		} else if len(handle.Ed25519Public) != 0 {
			pubAny = handle.Ed25519Public
		} else if handle.X25519Public != nil {
			pubAny = handle.X25519Public
		} else if handle.RSAPrivate != nil {
			pubAny = &handle.RSAPrivate.PublicKey
		} else if handle.ECDSAPrivate != nil {
			pubAny = &handle.ECDSAPrivate.PublicKey
		} else if handle.ECDHPrivate != nil {
			pubAny = &handle.ECDHPrivate.PublicKey
		} else if len(handle.Ed25519Private) != 0 {
			pubAny = handle.Ed25519Private.Public().(ed25519.PublicKey)
		} else if handle.X25519Private != nil {
			pubAny = handle.X25519Private.PublicKey()
		} else {
			return rejectedPromise(rt, errors.New("spki export requires a public key"))
		}
		der, err := x509.MarshalPKIXPublicKey(pubAny)
		if err != nil {
			return rejectedPromise(rt, err)
		}
		return resolvedPromise(rt, rt.NewArrayBuffer(der))
	default:
		return rejectedPromise(rt, fmt.Errorf("unsupported export format: %s", format))
	}
}

func subtleSign(rt *goja.Runtime, call goja.FunctionCall) goja.Value {
	algorithm, algObj, err := parseAlgorithmIdentifier(rt, call.Argument(0))
	if err != nil {
		return rejectedPromise(rt, err)
	}
	handle, err := extractCryptoKeyHandle(rt, call.Argument(1))
	if err != nil {
		return rejectedPromise(rt, err)
	}
	data, err := bufferSourceBytes(rt, call.Argument(2), true, false)
	if err != nil {
		return rejectedPromise(rt, err)
	}

	sig, err := signData(rt, algorithm, algObj, handle, data)
	if err != nil {
		return rejectedPromise(rt, err)
	}
	return resolvedPromise(rt, rt.NewArrayBuffer(sig))
}

func subtleVerify(rt *goja.Runtime, call goja.FunctionCall) goja.Value {
	algorithm, algObj, err := parseAlgorithmIdentifier(rt, call.Argument(0))
	if err != nil {
		return rejectedPromise(rt, err)
	}
	handle, err := extractCryptoKeyHandle(rt, call.Argument(1))
	if err != nil {
		return rejectedPromise(rt, err)
	}
	signature, err := bufferSourceBytes(rt, call.Argument(2), true, false)
	if err != nil {
		return rejectedPromise(rt, err)
	}
	data, err := bufferSourceBytes(rt, call.Argument(3), true, false)
	if err != nil {
		return rejectedPromise(rt, err)
	}

	ok, err := verifyData(rt, algorithm, algObj, handle, signature, data)
	if err != nil {
		return rejectedPromise(rt, err)
	}
	return resolvedPromise(rt, ok)
}

func subtleEncrypt(rt *goja.Runtime, call goja.FunctionCall) goja.Value {
	algorithm, algObj, err := parseAlgorithmIdentifier(rt, call.Argument(0))
	if err != nil {
		return rejectedPromise(rt, err)
	}
	handle, err := extractCryptoKeyHandle(rt, call.Argument(1))
	if err != nil {
		return rejectedPromise(rt, err)
	}
	data, err := bufferSourceBytes(rt, call.Argument(2), true, false)
	if err != nil {
		return rejectedPromise(rt, err)
	}

	cipherText, err := encryptData(rt, algorithm, algObj, handle, data)
	if err != nil {
		return rejectedPromise(rt, err)
	}
	return resolvedPromise(rt, rt.NewArrayBuffer(cipherText))
}

func subtleDecrypt(rt *goja.Runtime, call goja.FunctionCall) goja.Value {
	algorithm, algObj, err := parseAlgorithmIdentifier(rt, call.Argument(0))
	if err != nil {
		return rejectedPromise(rt, err)
	}
	handle, err := extractCryptoKeyHandle(rt, call.Argument(1))
	if err != nil {
		return rejectedPromise(rt, err)
	}
	data, err := bufferSourceBytes(rt, call.Argument(2), true, false)
	if err != nil {
		return rejectedPromise(rt, err)
	}

	plainText, err := decryptData(rt, algorithm, algObj, handle, data)
	if err != nil {
		return rejectedPromise(rt, err)
	}
	return resolvedPromise(rt, rt.NewArrayBuffer(plainText))
}

func subtleDeriveBits(rt *goja.Runtime, call goja.FunctionCall) goja.Value {
	algorithm, algObj, err := parseAlgorithmIdentifier(rt, call.Argument(0))
	if err != nil {
		return rejectedPromise(rt, err)
	}
	baseKey, err := extractCryptoKeyHandle(rt, call.Argument(1))
	if err != nil {
		return rejectedPromise(rt, err)
	}
	lengthBits := int(call.Argument(2).ToInteger())
	if lengthBits <= 0 || lengthBits%8 != 0 {
		return rejectedPromise(rt, errors.New("length must be a positive multiple of 8"))
	}

	var bits []byte
	switch algorithm {
	case "PBKDF2":
		bits, err = deriveBitsPBKDF2(rt, algObj, baseKey, lengthBits)
	case "HKDF":
		bits, err = deriveBitsHKDF(rt, algObj, baseKey, lengthBits)
	case "ECDH":
		bits, err = deriveBitsECDH(rt, algObj, baseKey, lengthBits)
	case "X25519":
		bits, err = deriveBitsX25519(rt, algObj, baseKey, lengthBits)
	default:
		return rejectedPromise(rt, fmt.Errorf("unsupported deriveBits algorithm: %s", algorithm))
	}
	if err != nil {
		return rejectedPromise(rt, err)
	}
	return resolvedPromise(rt, rt.NewArrayBuffer(bits))
}

func subtleDeriveKey(rt *goja.Runtime, call goja.FunctionCall) goja.Value {
	baseAlgorithm, baseAlgObj, err := parseAlgorithmIdentifier(rt, call.Argument(0))
	if err != nil {
		return rejectedPromise(rt, err)
	}
	baseKey, err := extractCryptoKeyHandle(rt, call.Argument(1))
	if err != nil {
		return rejectedPromise(rt, err)
	}
	derivedAlgorithm, derivedAlgObj, err := parseAlgorithmIdentifier(rt, call.Argument(2))
	if err != nil {
		return rejectedPromise(rt, err)
	}
	extractable := call.Argument(3).ToBoolean()
	usages, err := valueToStringSlice(call.Argument(4))
	if err != nil {
		return rejectedPromise(rt, err)
	}

	lengthBits, err := deriveKeyLengthBits(rt, derivedAlgorithm, derivedAlgObj)
	if err != nil {
		return rejectedPromise(rt, err)
	}

	var bits []byte
	switch baseAlgorithm {
	case "PBKDF2":
		bits, err = deriveBitsPBKDF2(rt, baseAlgObj, baseKey, lengthBits)
	case "HKDF":
		bits, err = deriveBitsHKDF(rt, baseAlgObj, baseKey, lengthBits)
	case "ECDH":
		bits, err = deriveBitsECDH(rt, baseAlgObj, baseKey, lengthBits)
	case "X25519":
		bits, err = deriveBitsX25519(rt, baseAlgObj, baseKey, lengthBits)
	default:
		return rejectedPromise(rt, fmt.Errorf("unsupported deriveKey base algorithm: %s", baseAlgorithm))
	}
	if err != nil {
		return rejectedPromise(rt, err)
	}

	handle, err := importRawKey(rt, derivedAlgorithm, derivedAlgObj, bits, extractable, usages)
	if err != nil {
		return rejectedPromise(rt, err)
	}
	return resolvedPromise(rt, newCryptoKeyObject(rt, handle))
}

func subtleWrapKey(rt *goja.Runtime, call goja.FunctionCall) goja.Value {
	format := strings.ToLower(strings.TrimSpace(call.Argument(0).String()))
	keyToWrap, err := extractCryptoKeyHandle(rt, call.Argument(1))
	if err != nil {
		return rejectedPromise(rt, err)
	}
	if !keyToWrap.Extractable {
		return rejectedPromise(rt, errors.New("key is not extractable"))
	}
	wrappingKey, err := extractCryptoKeyHandle(rt, call.Argument(2))
	if err != nil {
		return rejectedPromise(rt, err)
	}
	wrapAlgorithm, wrapAlgObj, err := parseAlgorithmIdentifier(rt, call.Argument(3))
	if err != nil {
		return rejectedPromise(rt, err)
	}

	rawKey, err := exportKeyBytesForWrap(rt, format, keyToWrap)
	if err != nil {
		return rejectedPromise(rt, err)
	}
	wrapped, err := encryptData(rt, wrapAlgorithm, wrapAlgObj, wrappingKey, rawKey)
	if err != nil {
		return rejectedPromise(rt, err)
	}
	return resolvedPromise(rt, rt.NewArrayBuffer(wrapped))
}

func subtleUnwrapKey(rt *goja.Runtime, call goja.FunctionCall) goja.Value {
	format := strings.ToLower(strings.TrimSpace(call.Argument(0).String()))
	wrappedData, err := bufferSourceBytes(rt, call.Argument(1), true, false)
	if err != nil {
		return rejectedPromise(rt, err)
	}
	unwrappingKey, err := extractCryptoKeyHandle(rt, call.Argument(2))
	if err != nil {
		return rejectedPromise(rt, err)
	}
	unwrapAlgorithm, unwrapAlgObj, err := parseAlgorithmIdentifier(rt, call.Argument(3))
	if err != nil {
		return rejectedPromise(rt, err)
	}
	unwrappedKeyAlgorithm, unwrappedKeyAlgObj, err := parseAlgorithmIdentifier(rt, call.Argument(4))
	if err != nil {
		return rejectedPromise(rt, err)
	}
	extractable := call.Argument(5).ToBoolean()
	usages, err := valueToStringSlice(call.Argument(6))
	if err != nil {
		return rejectedPromise(rt, err)
	}

	rawKey, err := decryptData(rt, unwrapAlgorithm, unwrapAlgObj, unwrappingKey, wrappedData)
	if err != nil {
		return rejectedPromise(rt, err)
	}

	handle, err := importUnwrappedKey(rt, format, rawKey, unwrappedKeyAlgorithm, unwrappedKeyAlgObj, extractable, usages)
	if err != nil {
		return rejectedPromise(rt, err)
	}
	return resolvedPromise(rt, newCryptoKeyObject(rt, handle))
}

func signData(rt *goja.Runtime, algorithm string, algObj *goja.Object, key *cryptoKeyHandle, data []byte) ([]byte, error) {
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
			v := algObj.Get("hash")
			if isValuePresent(v) {
				var err error
				hashName, err = hashFromAlgorithmValue(rt, v)
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
		hashName, err := hashNameForRSA(rt, algObj, key, "SHA-256")
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
		hashName, err := hashNameForRSA(rt, algObj, key, "SHA-256")
		if err != nil {
			return nil, err
		}
		hashID, digest, err := digestForCryptoHash(hashName, data)
		if err != nil {
			return nil, err
		}
		saltLen := digestLengthBytes(hashName)
		if algObj != nil {
			if v := algObj.Get("saltLength"); isValuePresent(v) {
				saltLen = int(v.ToInteger())
			}
		}
		return rsa.SignPSS(rand.Reader, key.RSAPrivate, hashID, digest, &rsa.PSSOptions{SaltLength: saltLen, Hash: hashID})
	case "ECDSA":
		if key.ECDSAPrivate == nil {
			return nil, errors.New("ECDSA requires a private EC key")
		}
		hashName := "SHA-256"
		if key.Algorithm != nil {
			if hv, ok := key.Algorithm["hash"].(map[string]interface{}); ok {
				if name, ok := hv["name"].(string); ok && name != "" {
					hashName = name
				}
			}
		}
		if algObj != nil {
			if v := algObj.Get("hash"); isValuePresent(v) {
				var err error
				hashName, err = hashFromAlgorithmValue(rt, v)
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
	case "Ed25519":
		if len(key.Ed25519Private) == 0 {
			return nil, errors.New("Ed25519 requires a private key")
		}
		return ed25519.Sign(key.Ed25519Private, data), nil
	default:
		return nil, fmt.Errorf("unsupported sign algorithm: %s", algorithm)
	}
}

func verifyData(rt *goja.Runtime, algorithm string, algObj *goja.Object, key *cryptoKeyHandle, signature []byte, data []byte) (bool, error) {
	switch algorithm {
	case "HMAC":
		if len(key.SecretKey) == 0 {
			return false, errors.New("HMAC requires a secret key")
		}
		hashName := key.HMACHash
		if hashName == "" {
			hashName = "SHA-256"
		}
		if algObj != nil {
			v := algObj.Get("hash")
			if isValuePresent(v) {
				var err error
				hashName, err = hashFromAlgorithmValue(rt, v)
				if err != nil {
					return false, err
				}
			}
		}
		hf, err := hashFactory(hashName)
		if err != nil {
			return false, err
		}
		mac := hmac.New(hf, key.SecretKey)
		_, _ = mac.Write(data)
		return hmac.Equal(signature, mac.Sum(nil)), nil
	case "RSASSA-PKCS1-V1_5":
		pub := key.RSAPublic
		if pub == nil && key.RSAPrivate != nil {
			pub = &key.RSAPrivate.PublicKey
		}
		if pub == nil {
			return false, errors.New("RSASSA-PKCS1-v1_5 requires an RSA key")
		}
		hashName, err := hashNameForRSA(rt, algObj, key, "SHA-256")
		if err != nil {
			return false, err
		}
		hashID, digest, err := digestForCryptoHash(hashName, data)
		if err != nil {
			return false, err
		}
		err = rsa.VerifyPKCS1v15(pub, hashID, digest, signature)
		return err == nil, nil
	case "RSA-PSS":
		pub := key.RSAPublic
		if pub == nil && key.RSAPrivate != nil {
			pub = &key.RSAPrivate.PublicKey
		}
		if pub == nil {
			return false, errors.New("RSA-PSS requires an RSA key")
		}
		hashName, err := hashNameForRSA(rt, algObj, key, "SHA-256")
		if err != nil {
			return false, err
		}
		hashID, digest, err := digestForCryptoHash(hashName, data)
		if err != nil {
			return false, err
		}
		saltLen := digestLengthBytes(hashName)
		if algObj != nil {
			if v := algObj.Get("saltLength"); isValuePresent(v) {
				saltLen = int(v.ToInteger())
			}
		}
		err = rsa.VerifyPSS(pub, hashID, digest, signature, &rsa.PSSOptions{SaltLength: saltLen, Hash: hashID})
		return err == nil, nil
	case "ECDSA":
		pub := key.ECDSAPublic
		if pub == nil && key.ECDSAPrivate != nil {
			pub = &key.ECDSAPrivate.PublicKey
		}
		if pub == nil {
			return false, errors.New("ECDSA requires an EC key")
		}
		hashName := "SHA-256"
		if key.Algorithm != nil {
			if hv, ok := key.Algorithm["hash"].(map[string]interface{}); ok {
				if name, ok := hv["name"].(string); ok && name != "" {
					hashName = name
				}
			}
		}
		if algObj != nil {
			if v := algObj.Get("hash"); isValuePresent(v) {
				var err error
				hashName, err = hashFromAlgorithmValue(rt, v)
				if err != nil {
					return false, err
				}
			}
		}
		_, digest, err := digestForCryptoHash(hashName, data)
		if err != nil {
			return false, err
		}
		size := (pub.Curve.Params().BitSize + 7) / 8
		if len(signature) == size*2 {
			r := new(big.Int).SetBytes(signature[:size])
			s := new(big.Int).SetBytes(signature[size:])
			return ecdsa.Verify(pub, digest, r, s), nil
		}
		// 兼容 DER ASN.1 格式
		return ecdsa.VerifyASN1(pub, digest, signature), nil
	case "Ed25519":
		pub := key.Ed25519Public
		if len(pub) == 0 && len(key.Ed25519Private) != 0 {
			pub = key.Ed25519Private.Public().(ed25519.PublicKey)
		}
		if len(pub) == 0 {
			return false, errors.New("Ed25519 requires a key")
		}
		return ed25519.Verify(pub, data, signature), nil
	default:
		return false, fmt.Errorf("unsupported verify algorithm: %s", algorithm)
	}
}

func encryptData(rt *goja.Runtime, algorithm string, algObj *goja.Object, key *cryptoKeyHandle, data []byte) ([]byte, error) {
	switch algorithm {
	case "AES-CBC":
		if len(key.SecretKey) == 0 {
			return nil, errors.New("AES-CBC requires a secret key")
		}
		iv, err := requiredBufferProperty(rt, algObj, "iv")
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
	case "DES-CBC":
		if len(key.SecretKey) != 8 {
			return nil, errors.New("DES-CBC requires an 8-byte secret key")
		}
		iv, err := requiredBufferProperty(rt, algObj, "iv")
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
		iv, err := requiredBufferProperty(rt, algObj, "iv")
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
	case "AES-GCM":
		if len(key.SecretKey) == 0 {
			return nil, errors.New("AES-GCM requires a secret key")
		}
		iv, err := requiredBufferProperty(rt, algObj, "iv")
		if err != nil {
			return nil, err
		}
		tagLength := 128
		if algObj != nil {
			if v := algObj.Get("tagLength"); isValuePresent(v) {
				tagLength = int(v.ToInteger())
			}
		}
		if err := validateAESGCMTagLength(tagLength); err != nil {
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
		aad := []byte(nil)
		if algObj != nil {
			if v := algObj.Get("additionalData"); isValuePresent(v) {
				aad, err = bufferSourceBytes(rt, v, true, false)
				if err != nil {
					return nil, err
				}
			}
		}
		return gcm.Seal(nil, iv, data, aad), nil
	case "AES-CTR":
		if len(key.SecretKey) == 0 {
			return nil, errors.New("AES-CTR requires a secret key")
		}
		counter, err := requiredBufferProperty(rt, algObj, "counter")
		if err != nil {
			return nil, err
		}
		if len(counter) != aes.BlockSize {
			return nil, errors.New("AES-CTR counter length must be 16")
		}
		length, err := intProperty(algObj, "length")
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
	case "RSA-OAEP":
		pub := key.RSAPublic
		if pub == nil && key.RSAPrivate != nil {
			pub = &key.RSAPrivate.PublicKey
		}
		if pub == nil {
			return nil, errors.New("RSA-OAEP requires an RSA key")
		}
		hashName, err := hashNameForRSA(rt, algObj, key, "SHA-256")
		if err != nil {
			return nil, err
		}
		hf, err := hashFactory(hashName)
		if err != nil {
			return nil, err
		}
		label := []byte(nil)
		if algObj != nil {
			if v := algObj.Get("label"); isValuePresent(v) {
				label, err = bufferSourceBytes(rt, v, true, false)
				if err != nil {
					return nil, err
				}
			}
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

func decryptData(rt *goja.Runtime, algorithm string, algObj *goja.Object, key *cryptoKeyHandle, data []byte) ([]byte, error) {
	switch algorithm {
	case "AES-CBC":
		if len(key.SecretKey) == 0 {
			return nil, errors.New("AES-CBC requires a secret key")
		}
		iv, err := requiredBufferProperty(rt, algObj, "iv")
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
	case "DES-CBC":
		if len(key.SecretKey) != 8 {
			return nil, errors.New("DES-CBC requires an 8-byte secret key")
		}
		iv, err := requiredBufferProperty(rt, algObj, "iv")
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
		iv, err := requiredBufferProperty(rt, algObj, "iv")
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
	case "AES-GCM":
		if len(key.SecretKey) == 0 {
			return nil, errors.New("AES-GCM requires a secret key")
		}
		iv, err := requiredBufferProperty(rt, algObj, "iv")
		if err != nil {
			return nil, err
		}
		tagLength := 128
		if algObj != nil {
			if v := algObj.Get("tagLength"); isValuePresent(v) {
				tagLength = int(v.ToInteger())
			}
		}
		if err := validateAESGCMTagLength(tagLength); err != nil {
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
		aad := []byte(nil)
		if algObj != nil {
			if v := algObj.Get("additionalData"); isValuePresent(v) {
				aad, err = bufferSourceBytes(rt, v, true, false)
				if err != nil {
					return nil, err
				}
			}
		}
		return gcm.Open(nil, iv, data, aad)
	case "AES-CTR":
		if len(key.SecretKey) == 0 {
			return nil, errors.New("AES-CTR requires a secret key")
		}
		counter, err := requiredBufferProperty(rt, algObj, "counter")
		if err != nil {
			return nil, err
		}
		if len(counter) != aes.BlockSize {
			return nil, errors.New("AES-CTR counter length must be 16")
		}
		length, err := intProperty(algObj, "length")
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
	case "RSA-OAEP":
		if key.RSAPrivate == nil {
			return nil, errors.New("RSA-OAEP requires a private RSA key")
		}
		hashName, err := hashNameForRSA(rt, algObj, key, "SHA-256")
		if err != nil {
			return nil, err
		}
		hf, err := hashFactory(hashName)
		if err != nil {
			return nil, err
		}
		label := []byte(nil)
		if algObj != nil {
			if v := algObj.Get("label"); isValuePresent(v) {
				label, err = bufferSourceBytes(rt, v, true, false)
				if err != nil {
					return nil, err
				}
			}
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

func deriveBitsPBKDF2(rt *goja.Runtime, algObj *goja.Object, baseKey *cryptoKeyHandle, lengthBits int) ([]byte, error) {
	if len(baseKey.SecretKey) == 0 {
		return nil, errors.New("PBKDF2 requires a secret key")
	}
	if algObj == nil {
		return nil, errors.New("PBKDF2 algorithm parameters are required")
	}
	salt, err := requiredBufferProperty(rt, algObj, "salt")
	if err != nil {
		return nil, err
	}
	iterations, err := intProperty(algObj, "iterations")
	if err != nil {
		return nil, err
	}
	if iterations <= 0 {
		return nil, errors.New("iterations must be > 0")
	}
	hashName, err := hashFromAlgorithmObject(rt, algObj, "SHA-256")
	if err != nil {
		return nil, err
	}
	hf, err := hashFactory(hashName)
	if err != nil {
		return nil, err
	}
	return pbkdf2.Key(baseKey.SecretKey, salt, iterations, lengthBits/8, hf), nil
}

func deriveBitsHKDF(rt *goja.Runtime, algObj *goja.Object, baseKey *cryptoKeyHandle, lengthBits int) ([]byte, error) {
	if len(baseKey.SecretKey) == 0 {
		return nil, errors.New("HKDF requires a secret key")
	}
	if algObj == nil {
		return nil, errors.New("HKDF algorithm parameters are required")
	}
	hashName, err := hashFromAlgorithmObject(rt, algObj, "SHA-256")
	if err != nil {
		return nil, err
	}
	hf, err := hashFactory(hashName)
	if err != nil {
		return nil, err
	}
	salt := []byte(nil)
	if v := algObj.Get("salt"); isValuePresent(v) {
		salt, err = bufferSourceBytes(rt, v, true, false)
		if err != nil {
			return nil, err
		}
	}
	info := []byte(nil)
	if v := algObj.Get("info"); isValuePresent(v) {
		info, err = bufferSourceBytes(rt, v, true, false)
		if err != nil {
			return nil, err
		}
	}
	reader := hkdf.New(hf, baseKey.SecretKey, salt, info)
	out := make([]byte, lengthBits/8)
	if _, err := io.ReadFull(reader, out); err != nil {
		return nil, err
	}
	return out, nil
}

func deriveBitsECDH(rt *goja.Runtime, algObj *goja.Object, baseKey *cryptoKeyHandle, lengthBits int) ([]byte, error) {
	if algObj == nil {
		return nil, errors.New("ECDH algorithm parameters are required")
	}
	priv := baseKey.ECDHPrivate
	if priv == nil {
		return nil, errors.New("ECDH baseKey must be an ECDH private key")
	}
	pubVal := algObj.Get("public")
	if !isValuePresent(pubVal) {
		return nil, errors.New("algorithm.public is required")
	}
	pubHandle, err := extractCryptoKeyHandle(rt, pubVal)
	if err != nil {
		return nil, err
	}
	pub := pubHandle.ECDHPublic
	if pub == nil && pubHandle.ECDHPrivate != nil {
		pub = &pubHandle.ECDHPrivate.PublicKey
	}
	if pub == nil {
		return nil, errors.New("algorithm.public must be an ECDH key")
	}
	if pub.Curve != priv.Curve {
		return nil, errors.New("ECDH curve mismatch")
	}
	x, _ := pub.Curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())
	if x == nil {
		return nil, errors.New("ECDH derive failed")
	}
	size := (pub.Curve.Params().BitSize + 7) / 8
	shared := leftPad(x.Bytes(), size)
	if lengthBits > len(shared)*8 {
		return nil, errors.New("requested length exceeds shared secret size")
	}
	return shared[:lengthBits/8], nil
}

func deriveBitsX25519(rt *goja.Runtime, algObj *goja.Object, baseKey *cryptoKeyHandle, lengthBits int) ([]byte, error) {
	if algObj == nil {
		return nil, errors.New("X25519 algorithm parameters are required")
	}
	priv := baseKey.X25519Private
	if priv == nil {
		return nil, errors.New("X25519 baseKey must be an X25519 private key")
	}
	pubVal := algObj.Get("public")
	if !isValuePresent(pubVal) {
		return nil, errors.New("algorithm.public is required")
	}
	pubHandle, err := extractCryptoKeyHandle(rt, pubVal)
	if err != nil {
		return nil, err
	}
	pub := pubHandle.X25519Public
	if pub == nil && pubHandle.X25519Private != nil {
		pub = pubHandle.X25519Private.PublicKey()
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
}

func deriveKeyLengthBits(rt *goja.Runtime, algorithm string, algObj *goja.Object) (int, error) {
	switch algorithm {
	case "AES-CBC", "AES-GCM", "AES-CTR", "AES-KW":
		return intProperty(algObj, "length")
	case "DES-CBC":
		return 64, nil
	case "3DES-CBC":
		if algObj == nil {
			return 192, nil
		}
		if v := algObj.Get("length"); isValuePresent(v) {
			length := int(v.ToInteger())
			if length != 128 && length != 192 {
				return 0, errors.New("3DES-CBC length must be 128 or 192")
			}
			return length, nil
		}
		return 192, nil
	case "HMAC":
		if algObj == nil {
			return 0, errors.New("HMAC algorithm parameters are required")
		}
		if v := algObj.Get("length"); isValuePresent(v) {
			length := int(v.ToInteger())
			if length <= 0 {
				return 0, errors.New("HMAC length must be > 0")
			}
			return length, nil
		}
		hashName, err := hashFromAlgorithmObject(rt, algObj, "SHA-256")
		if err != nil {
			return 0, err
		}
		return digestLengthBytes(hashName) * 8, nil
	default:
		return 0, fmt.Errorf("unsupported derived key algorithm: %s", algorithm)
	}
}

func importRawKey(rt *goja.Runtime, algorithm string, algObj *goja.Object, raw []byte, extractable bool, usages []string) (*cryptoKeyHandle, error) {
	cpy := make([]byte, len(raw))
	copy(cpy, raw)

	switch algorithm {
	case "AES-CBC", "AES-GCM", "AES-CTR", "AES-KW":
		length := len(cpy) * 8
		if length != 128 && length != 192 && length != 256 {
			return nil, errors.New("AES raw key length must be 16, 24, or 32 bytes")
		}
		return &cryptoKeyHandle{
			Type:        "secret",
			Extractable: extractable,
			Algorithm: map[string]interface{}{
				"name":   algorithm,
				"length": length,
			},
			Usages:    usages,
			SecretKey: cpy,
		}, nil
	case "DES-CBC":
		if len(cpy) != 8 {
			return nil, errors.New("DES-CBC raw key length must be 8 bytes")
		}
		return &cryptoKeyHandle{
			Type:        "secret",
			Extractable: extractable,
			Algorithm: map[string]interface{}{
				"name":   "DES-CBC",
				"length": 64,
			},
			Usages:    usages,
			SecretKey: cpy,
		}, nil
	case "3DES-CBC":
		if len(cpy) != 16 && len(cpy) != 24 {
			return nil, errors.New("3DES-CBC raw key length must be 16 or 24 bytes")
		}
		return &cryptoKeyHandle{
			Type:        "secret",
			Extractable: extractable,
			Algorithm: map[string]interface{}{
				"name":   "3DES-CBC",
				"length": len(cpy) * 8,
			},
			Usages:    usages,
			SecretKey: cpy,
		}, nil
	case "HMAC":
		hashName, err := hashFromAlgorithmObject(rt, algObj, "SHA-256")
		if err != nil {
			return nil, err
		}
		length := len(cpy) * 8
		if algObj != nil {
			if v := algObj.Get("length"); isValuePresent(v) {
				length = int(v.ToInteger())
			}
		}
		return &cryptoKeyHandle{
			Type:        "secret",
			Extractable: extractable,
			Algorithm: map[string]interface{}{
				"name":   "HMAC",
				"hash":   map[string]interface{}{"name": hashName},
				"length": length,
			},
			Usages:    usages,
			SecretKey: cpy,
			HMACHash:  hashName,
		}, nil
	case "PBKDF2":
		return &cryptoKeyHandle{
			Type:        "secret",
			Extractable: extractable,
			Algorithm: map[string]interface{}{
				"name": "PBKDF2",
			},
			Usages:    usages,
			SecretKey: cpy,
		}, nil
	case "HKDF":
		return &cryptoKeyHandle{
			Type:        "secret",
			Extractable: extractable,
			Algorithm: map[string]interface{}{
				"name": "HKDF",
			},
			Usages:    usages,
			SecretKey: cpy,
		}, nil
	case "ECDSA", "ECDH":
		if algObj == nil {
			return nil, errors.New("algorithm.namedCurve is required")
		}
		curveNameVal := algObj.Get("namedCurve")
		if !isValuePresent(curveNameVal) {
			return nil, errors.New("algorithm.namedCurve is required")
		}
		curve, normCurveName, err := namedCurveByName(curveNameVal.String())
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
		handle := &cryptoKeyHandle{
			Type:        "public",
			Extractable: true,
			Algorithm: map[string]interface{}{
				"name":       algorithm,
				"namedCurve": normCurveName,
			},
			Usages: usages,
		}
		if algorithm == "ECDSA" {
			handle.ECDSAPublic = pub
		} else {
			handle.ECDHPublic = pub
		}
		return handle, nil
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
				return &cryptoKeyHandle{
					Type:           "private",
					Extractable:    extractable,
					Algorithm:      map[string]interface{}{"name": "Ed25519"},
					Usages:         usages,
					Ed25519Private: priv,
				}, nil
			case ed25519.PrivateKeySize:
				priv := make([]byte, ed25519.PrivateKeySize)
				copy(priv, cpy)
				return &cryptoKeyHandle{
					Type:           "private",
					Extractable:    extractable,
					Algorithm:      map[string]interface{}{"name": "Ed25519"},
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
		return &cryptoKeyHandle{
			Type:          "public",
			Extractable:   true,
			Algorithm:     map[string]interface{}{"name": "Ed25519"},
			Usages:        usages,
			Ed25519Public: ed25519.PublicKey(pub),
		}, nil
	case "X25519":
		keyType, err := rawKeyTypeHint(algObj)
		if err != nil {
			return nil, err
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
			return &cryptoKeyHandle{
				Type:          "private",
				Extractable:   extractable,
				Algorithm:     map[string]interface{}{"name": "X25519"},
				Usages:        usages,
				X25519Private: priv,
			}, nil
		}
		pub, err := ecdh.X25519().NewPublicKey(cpy)
		if err != nil {
			return nil, err
		}
		return &cryptoKeyHandle{
			Type:         "public",
			Extractable:  true,
			Algorithm:    map[string]interface{}{"name": "X25519"},
			Usages:       usages,
			X25519Public: pub,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported raw key algorithm: %s", algorithm)
	}
}

func importJWK(rt *goja.Runtime, jwk map[string]interface{}, algorithm string, algObj *goja.Object, extractable bool, usages []string) (*cryptoKeyHandle, error) {
	kty := strings.ToUpper(stringFromMap(jwk, "kty"))
	switch kty {
	case "OCT":
		k := stringFromMap(jwk, "k")
		if k == "" {
			return nil, errors.New("invalid oct JWK: missing k")
		}
		keyBytes, err := base64.RawURLEncoding.DecodeString(k)
		if err != nil {
			return nil, errors.New("invalid oct JWK key material")
		}
		return importRawKey(rt, algorithm, algObj, keyBytes, extractable, usages)
	case "RSA":
		n, err := parseJWKBigInt(jwk, "n")
		if err != nil {
			return nil, err
		}
		eInt, err := parseJWKBigInt(jwk, "e")
		if err != nil {
			return nil, err
		}
		e := int(eInt.Int64())
		if e <= 0 {
			return nil, errors.New("invalid RSA JWK exponent")
		}
		hashName, err := hashFromAlgorithmObject(rt, algObj, "SHA-256")
		if err != nil {
			return nil, err
		}

		if hasMapKey(jwk, "d") {
			d, err := parseJWKBigInt(jwk, "d")
			if err != nil {
				return nil, err
			}
			if hasMapKey(jwk, "oth") {
				return nil, errors.New("RSA JWK multi-prime oth is unsupported")
			}
			hasP := hasMapKey(jwk, "p")
			hasQ := hasMapKey(jwk, "q")
			if hasP != hasQ {
				return nil, errors.New("RSA JWK p/q must both be present")
			}
			var p, q *big.Int
			if hasP {
				p, err = parseJWKBigInt(jwk, "p")
				if err != nil {
					return nil, err
				}
				q, err = parseJWKBigInt(jwk, "q")
				if err != nil {
					return nil, err
				}
			} else {
				p, q, err = recoverRSAFactorsFromNED(n, e, d)
				if err != nil {
					return nil, err
				}
			}
			priv := &rsa.PrivateKey{
				PublicKey: rsa.PublicKey{N: n, E: e},
				D:         d,
				Primes:    []*big.Int{p, q},
			}
			if err := priv.Validate(); err != nil {
				return nil, err
			}
			priv.Precompute()
			return &cryptoKeyHandle{
				Type:        "private",
				Extractable: extractable,
				Algorithm: map[string]interface{}{
					"name": algorithm,
					"hash": map[string]interface{}{"name": hashName},
				},
				Usages:     usages,
				RSAPrivate: priv,
			}, nil
		}

		pub := &rsa.PublicKey{N: n, E: e}
		return &cryptoKeyHandle{
			Type:        "public",
			Extractable: true,
			Algorithm: map[string]interface{}{
				"name": algorithm,
				"hash": map[string]interface{}{"name": hashName},
			},
			Usages:    usages,
			RSAPublic: pub,
		}, nil
	case "EC":
		if algorithm != "ECDSA" && algorithm != "ECDH" {
			return nil, errors.New("EC JWK currently supports only ECDSA/ECDH algorithm")
		}
		crv := strings.TrimSpace(stringFromMap(jwk, "crv"))
		curve, normCurveName, err := namedCurveByName(crv)
		if err != nil {
			return nil, err
		}
		x, err := parseJWKBigInt(jwk, "x")
		if err != nil {
			return nil, err
		}
		y, err := parseJWKBigInt(jwk, "y")
		if err != nil {
			return nil, err
		}
		pub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
		if !curve.IsOnCurve(pub.X, pub.Y) {
			return nil, errors.New("invalid EC JWK point")
		}
		if hasMapKey(jwk, "d") {
			d, err := parseJWKBigInt(jwk, "d")
			if err != nil {
				return nil, err
			}
			priv := &ecdsa.PrivateKey{PublicKey: *pub, D: d}
			handle := &cryptoKeyHandle{
				Type:        "private",
				Extractable: extractable,
				Algorithm: map[string]interface{}{
					"name":       algorithm,
					"namedCurve": normCurveName,
				},
				Usages: usages,
			}
			if algorithm == "ECDSA" {
				handle.ECDSAPrivate = priv
			} else {
				handle.ECDHPrivate = priv
			}
			return handle, nil
		}
		handle := &cryptoKeyHandle{
			Type:        "public",
			Extractable: true,
			Algorithm: map[string]interface{}{
				"name":       algorithm,
				"namedCurve": normCurveName,
			},
			Usages: usages,
		}
		if algorithm == "ECDSA" {
			handle.ECDSAPublic = pub
		} else {
			handle.ECDHPublic = pub
		}
		return handle, nil
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
			if len(x) != ed25519.PublicKeySize {
				return nil, errors.New("invalid Ed25519 public key length")
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
				return &cryptoKeyHandle{
					Type:           "private",
					Extractable:    extractable,
					Algorithm:      map[string]interface{}{"name": "Ed25519"},
					Usages:         usages,
					Ed25519Private: priv,
				}, nil
			}
			return &cryptoKeyHandle{
				Type:          "public",
				Extractable:   true,
				Algorithm:     map[string]interface{}{"name": "Ed25519"},
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
				return &cryptoKeyHandle{
					Type:          "private",
					Extractable:   extractable,
					Algorithm:     map[string]interface{}{"name": "X25519"},
					Usages:        usages,
					X25519Private: priv,
				}, nil
			}
			pub, err := ecdh.X25519().NewPublicKey(x)
			if err != nil {
				return nil, err
			}
			return &cryptoKeyHandle{
				Type:         "public",
				Extractable:  true,
				Algorithm:    map[string]interface{}{"name": "X25519"},
				Usages:       usages,
				X25519Public: pub,
			}, nil
		default:
			return nil, errors.New("unsupported OKP crv")
		}
	default:
		return nil, errors.New("unsupported JWK kty")
	}
}

func exportJWK(handle *cryptoKeyHandle) (map[string]interface{}, error) {
	jwk := map[string]interface{}{
		"key_ops": handle.Usages,
		"ext":     handle.Extractable,
	}
	if alg := jwkAlgForHandle(handle); alg != "" {
		jwk["alg"] = alg
	}

	if len(handle.SecretKey) > 0 {
		jwk["kty"] = "oct"
		jwk["k"] = base64.RawURLEncoding.EncodeToString(handle.SecretKey)
		return jwk, nil
	}

	if handle.RSAPublic != nil || handle.RSAPrivate != nil {
		jwk["kty"] = "RSA"
		pub := handle.RSAPublic
		if pub == nil {
			pub = &handle.RSAPrivate.PublicKey
		}
		jwk["n"] = base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
		jwk["e"] = base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
		if handle.RSAPrivate != nil {
			priv := handle.RSAPrivate
			jwk["d"] = base64.RawURLEncoding.EncodeToString(priv.D.Bytes())
			if len(priv.Primes) >= 2 {
				jwk["p"] = base64.RawURLEncoding.EncodeToString(priv.Primes[0].Bytes())
				jwk["q"] = base64.RawURLEncoding.EncodeToString(priv.Primes[1].Bytes())
				dp := new(big.Int).Mod(priv.D, new(big.Int).Sub(priv.Primes[0], big.NewInt(1)))
				dq := new(big.Int).Mod(priv.D, new(big.Int).Sub(priv.Primes[1], big.NewInt(1)))
				qi := new(big.Int).ModInverse(priv.Primes[1], priv.Primes[0])
				if qi != nil {
					jwk["dp"] = base64.RawURLEncoding.EncodeToString(dp.Bytes())
					jwk["dq"] = base64.RawURLEncoding.EncodeToString(dq.Bytes())
					jwk["qi"] = base64.RawURLEncoding.EncodeToString(qi.Bytes())
				}
			}
		}
		return jwk, nil
	}

	if handle.ECDSAPublic != nil || handle.ECDSAPrivate != nil || handle.ECDHPublic != nil || handle.ECDHPrivate != nil {
		jwk["kty"] = "EC"
		pub := handle.ECDSAPublic
		if pub == nil && handle.ECDSAPrivate != nil {
			pub = &handle.ECDSAPrivate.PublicKey
		}
		if pub == nil {
			pub = handle.ECDHPublic
		}
		if pub == nil && handle.ECDHPrivate != nil {
			pub = &handle.ECDHPrivate.PublicKey
		}
		size := (pub.Curve.Params().BitSize + 7) / 8
		jwk["crv"] = namedCurveFromElliptic(pub.Curve)
		jwk["x"] = base64.RawURLEncoding.EncodeToString(leftPad(pub.X.Bytes(), size))
		jwk["y"] = base64.RawURLEncoding.EncodeToString(leftPad(pub.Y.Bytes(), size))
		if handle.ECDSAPrivate != nil {
			jwk["d"] = base64.RawURLEncoding.EncodeToString(leftPad(handle.ECDSAPrivate.D.Bytes(), size))
		} else if handle.ECDHPrivate != nil {
			jwk["d"] = base64.RawURLEncoding.EncodeToString(leftPad(handle.ECDHPrivate.D.Bytes(), size))
		}
		return jwk, nil
	}

	if len(handle.Ed25519Public) != 0 || len(handle.Ed25519Private) != 0 {
		jwk["kty"] = "OKP"
		jwk["crv"] = "Ed25519"
		pub := handle.Ed25519Public
		if len(pub) == 0 {
			pub = handle.Ed25519Private.Public().(ed25519.PublicKey)
		}
		jwk["x"] = base64.RawURLEncoding.EncodeToString(pub)
		if len(handle.Ed25519Private) != 0 {
			jwk["d"] = base64.RawURLEncoding.EncodeToString(handle.Ed25519Private.Seed())
		}
		return jwk, nil
	}

	if handle.X25519Public != nil || handle.X25519Private != nil {
		jwk["kty"] = "OKP"
		jwk["crv"] = "X25519"
		pub := handle.X25519Public
		if pub == nil && handle.X25519Private != nil {
			pub = handle.X25519Private.PublicKey()
		}
		jwk["x"] = base64.RawURLEncoding.EncodeToString(pub.Bytes())
		if handle.X25519Private != nil {
			jwk["d"] = base64.RawURLEncoding.EncodeToString(handle.X25519Private.Bytes())
		}
		return jwk, nil
	}

	return nil, errors.New("unsupported key type for JWK export")
}

func jwkAlgForHandle(handle *cryptoKeyHandle) string {
	algName := strings.TrimSpace(algorithmNameFromHandle(handle))
	if algName == "" {
		return ""
	}
	switch algName {
	case "AES-GCM":
		switch algorithmLengthFromHandle(handle) {
		case 128:
			return "A128GCM"
		case 192:
			return "A192GCM"
		case 256:
			return "A256GCM"
		}
	case "AES-KW":
		switch algorithmLengthFromHandle(handle) {
		case 128:
			return "A128KW"
		case 192:
			return "A192KW"
		case 256:
			return "A256KW"
		}
	case "HMAC":
		switch algorithmHashNameFromHandle(handle) {
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
	case "RSASSA-PKCS1-V1_5":
		switch algorithmHashNameFromHandle(handle) {
		case "SHA-256":
			return "RS256"
		case "SHA-384":
			return "RS384"
		case "SHA-512":
			return "RS512"
		case "SHA-1":
			return "RS1"
		}
	case "RSA-PSS":
		switch algorithmHashNameFromHandle(handle) {
		case "SHA-256":
			return "PS256"
		case "SHA-384":
			return "PS384"
		case "SHA-512":
			return "PS512"
		case "SHA-1":
			return "PS1"
		}
	case "RSA-OAEP":
		switch algorithmHashNameFromHandle(handle) {
		case "SHA-1":
			return "RSA-OAEP"
		case "SHA-256":
			return "RSA-OAEP-256"
		case "SHA-384":
			return "RSA-OAEP-384"
		case "SHA-512":
			return "RSA-OAEP-512"
		}
	case "RSAES-PKCS1-V1_5":
		return "RSA1_5"
	case "ECDSA":
		switch strings.ToUpper(strings.TrimSpace(algorithmNamedCurveFromHandle(handle))) {
		case "P-256":
			return "ES256"
		case "P-384":
			return "ES384"
		case "P-521":
			return "ES512"
		}
	case "Ed25519":
		return "EdDSA"
	case "ECDH", "X25519":
		return "ECDH-ES"
	}
	return algName
}

func algorithmNameFromHandle(handle *cryptoKeyHandle) string {
	if handle == nil || handle.Algorithm == nil {
		return ""
	}
	if v, ok := handle.Algorithm["name"].(string); ok {
		return v
	}
	return ""
}

func algorithmHashNameFromHandle(handle *cryptoKeyHandle) string {
	if handle == nil || handle.Algorithm == nil {
		return ""
	}
	hashValue, ok := handle.Algorithm["hash"]
	if !ok || hashValue == nil {
		if handle.HMACHash != "" {
			return handle.HMACHash
		}
		return ""
	}
	switch hv := hashValue.(type) {
	case string:
		return hv
	case map[string]interface{}:
		if name, ok := hv["name"].(string); ok {
			return name
		}
	}
	return ""
}

func algorithmLengthFromHandle(handle *cryptoKeyHandle) int {
	if handle == nil || handle.Algorithm == nil {
		return 0
	}
	if v, ok := handle.Algorithm["length"]; ok {
		switch vv := v.(type) {
		case int:
			return vv
		case int8:
			return int(vv)
		case int16:
			return int(vv)
		case int32:
			return int(vv)
		case int64:
			return int(vv)
		case float32:
			return int(vv)
		case float64:
			return int(vv)
		}
	}
	if len(handle.SecretKey) > 0 {
		return len(handle.SecretKey) * 8
	}
	return 0
}

func algorithmNamedCurveFromHandle(handle *cryptoKeyHandle) string {
	if handle == nil || handle.Algorithm == nil {
		return ""
	}
	if v, ok := handle.Algorithm["namedCurve"].(string); ok {
		return v
	}
	return ""
}

func parsePrivateKey(der []byte) (interface{}, error) {
	if v, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := v.(type) {
		case *rsa.PrivateKey:
			return key, nil
		case *ecdsa.PrivateKey:
			return key, nil
		case ed25519.PrivateKey:
			return key, nil
		case *ecdh.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("pkcs8 key is unsupported")
		}
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("failed to parse private key")
}

func privateKeyToHandle(rt *goja.Runtime, privAny interface{}, algorithm string, algObj *goja.Object, extractable bool, usages []string) (*cryptoKeyHandle, error) {
	switch key := privAny.(type) {
	case *rsa.PrivateKey:
		switch algorithm {
		case "RSASSA-PKCS1-V1_5", "RSA-PSS", "RSA-OAEP", "RSAES-PKCS1-V1_5":
		default:
			return nil, errors.New("algorithm is not compatible with RSA private key")
		}
		hashName, err := hashFromAlgorithmObject(rt, algObj, "SHA-256")
		if err != nil {
			return nil, err
		}
		return &cryptoKeyHandle{
			Type:        "private",
			Extractable: extractable,
			Algorithm: map[string]interface{}{
				"name": algorithm,
				"hash": map[string]interface{}{"name": hashName},
			},
			Usages:     usages,
			RSAPrivate: key,
		}, nil
	case *ecdsa.PrivateKey:
		if algorithm != "ECDSA" && algorithm != "ECDH" {
			return nil, errors.New("algorithm is not compatible with EC private key")
		}
		handle := &cryptoKeyHandle{
			Type:        "private",
			Extractable: extractable,
			Algorithm: map[string]interface{}{
				"name":       algorithm,
				"namedCurve": namedCurveFromElliptic(key.Curve),
			},
			Usages: usages,
		}
		if algorithm == "ECDSA" {
			handle.ECDSAPrivate = key
		} else {
			handle.ECDHPrivate = key
		}
		return handle, nil
	case ed25519.PrivateKey:
		if algorithm != "Ed25519" {
			return nil, errors.New("algorithm is not compatible with Ed25519 private key")
		}
		return &cryptoKeyHandle{
			Type:           "private",
			Extractable:    extractable,
			Algorithm:      map[string]interface{}{"name": "Ed25519"},
			Usages:         usages,
			Ed25519Private: key,
		}, nil
	case *ecdh.PrivateKey:
		if algorithm != "X25519" {
			return nil, errors.New("algorithm is not compatible with X25519 private key")
		}
		return &cryptoKeyHandle{
			Type:          "private",
			Extractable:   extractable,
			Algorithm:     map[string]interface{}{"name": "X25519"},
			Usages:        usages,
			X25519Private: key,
		}, nil
	default:
		return nil, errors.New("unsupported private key type")
	}
}

func publicKeyToHandle(rt *goja.Runtime, pubAny interface{}, algorithm string, algObj *goja.Object, usages []string) (*cryptoKeyHandle, error) {
	switch key := pubAny.(type) {
	case *rsa.PublicKey:
		switch algorithm {
		case "RSASSA-PKCS1-V1_5", "RSA-PSS", "RSA-OAEP", "RSAES-PKCS1-V1_5":
		default:
			return nil, errors.New("algorithm is not compatible with RSA public key")
		}
		hashName, err := hashFromAlgorithmObject(rt, algObj, "SHA-256")
		if err != nil {
			return nil, err
		}
		return &cryptoKeyHandle{
			Type:        "public",
			Extractable: true,
			Algorithm: map[string]interface{}{
				"name": algorithm,
				"hash": map[string]interface{}{"name": hashName},
			},
			Usages:    usages,
			RSAPublic: key,
		}, nil
	case *ecdsa.PublicKey:
		if algorithm != "ECDSA" && algorithm != "ECDH" {
			return nil, errors.New("algorithm is not compatible with EC public key")
		}
		handle := &cryptoKeyHandle{
			Type:        "public",
			Extractable: true,
			Algorithm: map[string]interface{}{
				"name":       algorithm,
				"namedCurve": namedCurveFromElliptic(key.Curve),
			},
			Usages: usages,
		}
		if algorithm == "ECDSA" {
			handle.ECDSAPublic = key
		} else {
			handle.ECDHPublic = key
		}
		return handle, nil
	case ed25519.PublicKey:
		if algorithm != "Ed25519" {
			return nil, errors.New("algorithm is not compatible with Ed25519 public key")
		}
		return &cryptoKeyHandle{
			Type:          "public",
			Extractable:   true,
			Algorithm:     map[string]interface{}{"name": "Ed25519"},
			Usages:        usages,
			Ed25519Public: key,
		}, nil
	case *ecdh.PublicKey:
		if algorithm != "X25519" {
			return nil, errors.New("algorithm is not compatible with X25519 public key")
		}
		return &cryptoKeyHandle{
			Type:         "public",
			Extractable:  true,
			Algorithm:    map[string]interface{}{"name": "X25519"},
			Usages:       usages,
			X25519Public: key,
		}, nil
	default:
		return nil, errors.New("unsupported public key type")
	}
}

func parseJWK(rt *goja.Runtime, value goja.Value) (map[string]interface{}, error) {
	if goja.IsUndefined(value) || goja.IsNull(value) {
		return nil, errors.New("JWK value is required")
	}
	exported := value.Export()
	if m, ok := exported.(map[string]interface{}); ok {
		return m, nil
	}
	obj := value.ToObject(rt)
	if obj == nil {
		return nil, errors.New("invalid JWK object")
	}
	exported = obj.Export()
	m, ok := exported.(map[string]interface{})
	if !ok {
		return nil, errors.New("invalid JWK object")
	}
	return m, nil
}

func parseJWKBigInt(jwk map[string]interface{}, key string) (*big.Int, error) {
	v := stringFromMap(jwk, key)
	if v == "" {
		return nil, fmt.Errorf("invalid RSA JWK: missing %s", key)
	}
	buf, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("invalid RSA JWK field %s", key)
	}
	n := new(big.Int).SetBytes(buf)
	if n.Sign() <= 0 {
		return nil, fmt.Errorf("invalid RSA JWK field %s", key)
	}
	return n, nil
}

func recoverRSAFactorsFromNED(n *big.Int, e int, d *big.Int) (*big.Int, *big.Int, error) {
	if n == nil || d == nil || e <= 1 {
		return nil, nil, errors.New("invalid RSA key parameters")
	}
	one := big.NewInt(1)
	two := big.NewInt(2)
	nMinus1 := new(big.Int).Sub(n, one)

	k := new(big.Int).Mul(d, big.NewInt(int64(e)))
	k.Sub(k, one)
	if k.Sign() <= 0 || k.Bit(0) != 0 {
		return nil, nil, errors.New("failed to recover RSA factors from n/e/d")
	}

	r := new(big.Int).Set(k)
	t := 0
	for r.Bit(0) == 0 {
		r.Rsh(r, 1)
		t++
	}

	max := new(big.Int).Sub(n, two)
	if max.Sign() <= 0 {
		return nil, nil, errors.New("failed to recover RSA factors from n/e/d")
	}

	tryBase := func(g *big.Int) (*big.Int, *big.Int, bool) {
		gcd := new(big.Int).GCD(nil, nil, g, n)
		if gcd.Cmp(one) > 0 && gcd.Cmp(n) < 0 {
			p := gcd
			q := new(big.Int).Div(new(big.Int).Set(n), p)
			if p.Cmp(q) > 0 {
				p, q = q, p
			}
			return p, q, true
		}

		y := new(big.Int).Exp(g, r, n)
		if y.Cmp(one) == 0 || y.Cmp(nMinus1) == 0 {
			return nil, nil, false
		}

		for j := 0; j < t; j++ {
			x := new(big.Int).Mul(y, y)
			x.Mod(x, n)

			if x.Cmp(one) == 0 {
				p := new(big.Int).Sub(y, one)
				p.GCD(nil, nil, p, n)
				if p.Cmp(one) <= 0 || p.Cmp(n) >= 0 {
					return nil, nil, false
				}
				q := new(big.Int).Div(new(big.Int).Set(n), p)
				if new(big.Int).Mul(new(big.Int).Set(p), new(big.Int).Set(q)).Cmp(n) != 0 {
					return nil, nil, false
				}
				if p.Cmp(q) > 0 {
					p, q = q, p
				}
				return p, q, true
			}

			if x.Cmp(nMinus1) == 0 {
				return nil, nil, false
			}
			y = x
		}
		return nil, nil, false
	}

	for base := int64(2); base < 8192; base++ {
		g := big.NewInt(base)
		if g.Cmp(nMinus1) >= 0 {
			break
		}
		if p, q, ok := tryBase(g); ok {
			return p, q, nil
		}
	}

	// 随机兜底，理论上不应该走到这里
	for attempt := 0; attempt < 8192; attempt++ {
		g, err := rand.Int(rand.Reader, max)
		if err != nil {
			return nil, nil, err
		}
		g.Add(g, two)
		if g.Cmp(nMinus1) >= 0 {
			g.Sub(g, one)
		}
		if p, q, ok := tryBase(g); ok {
			return p, q, nil
		}
	}
	return nil, nil, errors.New("failed to recover RSA factors from n/e/d")
}

func hasMapKey(m map[string]interface{}, k string) bool {
	_, ok := m[k]
	return ok
}

func stringFromMap(m map[string]interface{}, k string) string {
	v, ok := m[k]
	if !ok || v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}

func splitRSAUsages(algorithm string, usages []string) (pubUsages []string, priUsages []string) {
	pubAllowed := map[string]struct{}{}
	priAllowed := map[string]struct{}{}
	switch algorithm {
	case "RSASSA-PKCS1-V1_5", "RSA-PSS":
		pubAllowed["verify"] = struct{}{}
		priAllowed["sign"] = struct{}{}
	case "RSA-OAEP", "RSAES-PKCS1-V1_5":
		pubAllowed["encrypt"] = struct{}{}
		pubAllowed["wrapKey"] = struct{}{}
		priAllowed["decrypt"] = struct{}{}
		priAllowed["unwrapKey"] = struct{}{}
	default:
		return nil, usages
	}

	for _, u := range usages {
		if _, ok := pubAllowed[u]; ok {
			pubUsages = append(pubUsages, u)
		}
		if _, ok := priAllowed[u]; ok {
			priUsages = append(priUsages, u)
		}
	}

	if len(pubUsages) == 0 {
		for u := range pubAllowed {
			pubUsages = append(pubUsages, u)
		}
	}
	if len(priUsages) == 0 {
		for u := range priAllowed {
			priUsages = append(priUsages, u)
		}
	}
	return
}

func splitECUsages(algorithm string, usages []string) (pubUsages []string, priUsages []string) {
	pubAllowed := map[string]struct{}{}
	priAllowed := map[string]struct{}{}
	switch algorithm {
	case "ECDSA":
		pubAllowed["verify"] = struct{}{}
		priAllowed["sign"] = struct{}{}
	case "ECDH":
		pubAllowed["deriveBits"] = struct{}{}
		pubAllowed["deriveKey"] = struct{}{}
		priAllowed["deriveBits"] = struct{}{}
		priAllowed["deriveKey"] = struct{}{}
	default:
		return nil, usages
	}

	for _, u := range usages {
		if _, ok := pubAllowed[u]; ok {
			pubUsages = append(pubUsages, u)
		}
		if _, ok := priAllowed[u]; ok {
			priUsages = append(priUsages, u)
		}
	}
	if len(pubUsages) == 0 {
		for u := range pubAllowed {
			pubUsages = append(pubUsages, u)
		}
	}
	if len(priUsages) == 0 {
		for u := range priAllowed {
			priUsages = append(priUsages, u)
		}
	}
	return
}

func splitOKPUsages(algorithm string, usages []string) (pubUsages []string, priUsages []string) {
	pubAllowed := map[string]struct{}{}
	priAllowed := map[string]struct{}{}
	switch algorithm {
	case "Ed25519":
		pubAllowed["verify"] = struct{}{}
		priAllowed["sign"] = struct{}{}
	case "X25519":
		pubAllowed["deriveBits"] = struct{}{}
		pubAllowed["deriveKey"] = struct{}{}
		priAllowed["deriveBits"] = struct{}{}
		priAllowed["deriveKey"] = struct{}{}
	default:
		return nil, usages
	}
	for _, u := range usages {
		if _, ok := pubAllowed[u]; ok {
			pubUsages = append(pubUsages, u)
		}
		if _, ok := priAllowed[u]; ok {
			priUsages = append(priUsages, u)
		}
	}
	if len(pubUsages) == 0 {
		for u := range pubAllowed {
			pubUsages = append(pubUsages, u)
		}
	}
	if len(priUsages) == 0 {
		for u := range priAllowed {
			priUsages = append(priUsages, u)
		}
	}
	return
}

func namedCurveByName(name string) (elliptic.Curve, string, error) {
	n := strings.ToUpper(strings.TrimSpace(name))
	switch n {
	case "P-256", "SECP256R1":
		return elliptic.P256(), "P-256", nil
	case "P-384", "SECP384R1":
		return elliptic.P384(), "P-384", nil
	case "P-521", "SECP521R1":
		return elliptic.P521(), "P-521", nil
	default:
		return nil, "", fmt.Errorf("unsupported namedCurve: %s", name)
	}
}

func namedCurveFromElliptic(curve elliptic.Curve) string {
	switch curve {
	case elliptic.P256():
		return "P-256"
	case elliptic.P384():
		return "P-384"
	case elliptic.P521():
		return "P-521"
	default:
		return ""
	}
}

func exportKeyBytesForWrap(rt *goja.Runtime, format string, handle *cryptoKeyHandle) ([]byte, error) {
	switch format {
	case "raw":
		return exportRawKeyMaterial(handle)
	case "pkcs8":
		var privAny interface{}
		if handle.RSAPrivate != nil {
			privAny = handle.RSAPrivate
		} else if handle.ECDSAPrivate != nil {
			privAny = handle.ECDSAPrivate
		} else if handle.ECDHPrivate != nil {
			privAny = handle.ECDHPrivate
		} else if len(handle.Ed25519Private) != 0 {
			privAny = handle.Ed25519Private
		} else if handle.X25519Private != nil {
			privAny = handle.X25519Private
		} else {
			return nil, errors.New("pkcs8 export requires a private key")
		}
		return x509.MarshalPKCS8PrivateKey(privAny)
	case "pkcs1":
		if handle.RSAPrivate != nil {
			return x509.MarshalPKCS1PrivateKey(handle.RSAPrivate), nil
		}
		pub := handle.RSAPublic
		if pub == nil && handle.RSAPrivate != nil {
			pub = &handle.RSAPrivate.PublicKey
		}
		if pub == nil {
			return nil, errors.New("pkcs1 export requires an RSA key")
		}
		return x509.MarshalPKCS1PublicKey(pub), nil
	case "sec1":
		var priv *ecdsa.PrivateKey
		if handle.ECDSAPrivate != nil {
			priv = handle.ECDSAPrivate
		} else if handle.ECDHPrivate != nil {
			priv = handle.ECDHPrivate
		} else {
			return nil, errors.New("sec1 export requires an EC private key")
		}
		return x509.MarshalECPrivateKey(priv)
	case "spki":
		var pubAny interface{}
		if handle.RSAPublic != nil {
			pubAny = handle.RSAPublic
		} else if handle.ECDSAPublic != nil {
			pubAny = handle.ECDSAPublic
		} else if handle.ECDHPublic != nil {
			pubAny = handle.ECDHPublic
		} else if len(handle.Ed25519Public) != 0 {
			pubAny = handle.Ed25519Public
		} else if handle.X25519Public != nil {
			pubAny = handle.X25519Public
		} else if handle.RSAPrivate != nil {
			pubAny = &handle.RSAPrivate.PublicKey
		} else if handle.ECDSAPrivate != nil {
			pubAny = &handle.ECDSAPrivate.PublicKey
		} else if handle.ECDHPrivate != nil {
			pubAny = &handle.ECDHPrivate.PublicKey
		} else if len(handle.Ed25519Private) != 0 {
			pubAny = handle.Ed25519Private.Public().(ed25519.PublicKey)
		} else if handle.X25519Private != nil {
			pubAny = handle.X25519Private.PublicKey()
		} else {
			return nil, errors.New("spki export requires a public key")
		}
		return x509.MarshalPKIXPublicKey(pubAny)
	case "jwk":
		jwk, err := exportJWK(handle)
		if err != nil {
			return nil, err
		}
		return json.Marshal(jwk)
	default:
		return nil, fmt.Errorf("unsupported wrap key format: %s", format)
	}
}

func importUnwrappedKey(rt *goja.Runtime, format string, rawKey []byte, algorithm string, algObj *goja.Object, extractable bool, usages []string) (*cryptoKeyHandle, error) {
	switch format {
	case "raw":
		return importRawKey(rt, algorithm, algObj, rawKey, extractable, usages)
	case "jwk":
		var jwk map[string]interface{}
		if err := json.Unmarshal(rawKey, &jwk); err != nil {
			return nil, errors.New("invalid wrapped JWK data")
		}
		return importJWK(rt, jwk, algorithm, algObj, extractable, usages)
	case "pkcs8":
		privAny, err := parsePrivateKey(rawKey)
		if err != nil {
			return nil, err
		}
		return privateKeyToHandle(rt, privAny, algorithm, algObj, extractable, usages)
	case "pkcs1":
		if priv, err := x509.ParsePKCS1PrivateKey(rawKey); err == nil {
			return privateKeyToHandle(rt, priv, algorithm, algObj, extractable, usages)
		}
		pub, err := x509.ParsePKCS1PublicKey(rawKey)
		if err != nil {
			return nil, errors.New("failed to parse pkcs1 key")
		}
		return publicKeyToHandle(rt, pub, algorithm, algObj, usages)
	case "sec1":
		priv, err := x509.ParseECPrivateKey(rawKey)
		if err != nil {
			return nil, errors.New("failed to parse sec1 key")
		}
		return privateKeyToHandle(rt, priv, algorithm, algObj, extractable, usages)
	case "spki":
		pubAny, err := x509.ParsePKIXPublicKey(rawKey)
		if err != nil {
			return nil, err
		}
		return publicKeyToHandle(rt, pubAny, algorithm, algObj, usages)
	default:
		return nil, fmt.Errorf("unsupported unwrap key format: %s", format)
	}
}

func parseAlgorithmIdentifier(rt *goja.Runtime, value goja.Value) (string, *goja.Object, error) {
	if goja.IsUndefined(value) || goja.IsNull(value) {
		return "", nil, errors.New("algorithm is required")
	}

	if s, ok := value.Export().(string); ok {
		name, err := normalizeAlgorithmName(s)
		return name, nil, err
	}

	obj := value.ToObject(rt)
	if obj == nil {
		return "", nil, errors.New("algorithm must be string or object")
	}
	nameVal := obj.Get("name")
	if goja.IsUndefined(nameVal) || goja.IsNull(nameVal) {
		return "", nil, errors.New("algorithm.name is required")
	}
	name, err := normalizeAlgorithmName(nameVal.String())
	if err != nil {
		return "", nil, err
	}
	return name, obj, nil
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
	case "ECDSA":
		return "ECDSA", nil
	case "ECDH":
		return "ECDH", nil
	case "ED25519":
		return "Ed25519", nil
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

func hashFromAlgorithmObject(rt *goja.Runtime, obj *goja.Object, defaultName string) (string, error) {
	if obj == nil {
		return normalizeAlgorithmName(defaultName)
	}
	v := obj.Get("hash")
	if !isValuePresent(v) {
		return normalizeAlgorithmName(defaultName)
	}
	return hashFromAlgorithmValue(rt, v)
}

func hashFromAlgorithmValue(rt *goja.Runtime, value goja.Value) (string, error) {
	if !isValuePresent(value) {
		return "", errors.New("invalid hash algorithm")
	}
	if s, ok := value.Export().(string); ok {
		return normalizeAlgorithmName(s)
	}
	obj := value.ToObject(rt)
	if obj == nil {
		return "", errors.New("invalid hash algorithm")
	}
	name := obj.Get("name")
	if goja.IsUndefined(name) || goja.IsNull(name) {
		return "", errors.New("hash.name is required")
	}
	return normalizeAlgorithmName(name.String())
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
		out := make([]byte, len(sum))
		copy(out, sum[:])
		return out, nil
	case "SHA-1":
		sum := sha1.Sum(data)
		out := make([]byte, len(sum))
		copy(out, sum[:])
		return out, nil
	case "SHA-224":
		sum := sha256.Sum224(data)
		out := make([]byte, len(sum))
		copy(out, sum[:])
		return out, nil
	case "SHA-256":
		sum := sha256.Sum256(data)
		out := make([]byte, len(sum))
		copy(out, sum[:])
		return out, nil
	case "SHA-384":
		sum := sha512.Sum384(data)
		out := make([]byte, len(sum))
		copy(out, sum[:])
		return out, nil
	case "SHA-512":
		sum := sha512.Sum512(data)
		out := make([]byte, len(sum))
		copy(out, sum[:])
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported digest algorithm: %s", algorithm)
	}
}

func digestForCryptoHash(hashName string, data []byte) (crypto.Hash, []byte, error) {
	switch hashName {
	case "MD5":
		sum := md5.Sum(data)
		return crypto.MD5, sum[:], nil
	case "SHA-1":
		sum := sha1.Sum(data)
		return crypto.SHA1, sum[:], nil
	case "SHA-224":
		sum := sha256.Sum224(data)
		return crypto.SHA224, sum[:], nil
	case "SHA-256":
		sum := sha256.Sum256(data)
		return crypto.SHA256, sum[:], nil
	case "SHA-384":
		sum := sha512.Sum384(data)
		return crypto.SHA384, sum[:], nil
	case "SHA-512":
		sum := sha512.Sum512(data)
		return crypto.SHA512, sum[:], nil
	default:
		return 0, nil, fmt.Errorf("unsupported hash for RSA: %s", hashName)
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

func generateRSAKeyWithExponent(modulusLength int, exp int) (*rsa.PrivateKey, error) {
	if exp <= 1 || exp%2 == 0 {
		return nil, errors.New("publicExponent must be an odd integer > 1")
	}
	if exp == 65537 {
		return rsa.GenerateKey(rand.Reader, modulusLength)
	}
	return generateRSAKeyCustomExponent(modulusLength, exp)
}

func generateRSAKeyCustomExponent(modulusLength int, exp int) (*rsa.PrivateKey, error) {
	one := big.NewInt(1)
	eBig := big.NewInt(int64(exp))
	bitsP := modulusLength / 2
	bitsQ := modulusLength - bitsP

	for attempt := 0; attempt < 256; attempt++ {
		p, err := rand.Prime(rand.Reader, bitsP)
		if err != nil {
			return nil, err
		}
		q, err := rand.Prime(rand.Reader, bitsQ)
		if err != nil {
			return nil, err
		}
		if p.Cmp(q) == 0 {
			continue
		}

		n := new(big.Int).Mul(p, q)
		if n.BitLen() != modulusLength {
			continue
		}

		pm1 := new(big.Int).Sub(p, one)
		qm1 := new(big.Int).Sub(q, one)
		if new(big.Int).GCD(nil, nil, eBig, pm1).Cmp(one) != 0 {
			continue
		}
		if new(big.Int).GCD(nil, nil, eBig, qm1).Cmp(one) != 0 {
			continue
		}

		phi := new(big.Int).Mul(pm1, qm1)
		d := new(big.Int).ModInverse(eBig, phi)
		if d == nil {
			continue
		}

		priv := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{N: n, E: exp},
			D:         d,
			Primes:    []*big.Int{p, q},
		}
		if err := priv.Validate(); err != nil {
			continue
		}
		priv.Precompute()
		return priv, nil
	}
	return nil, errors.New("failed to generate RSA key with requested publicExponent")
}

func hashNameForRSA(rt *goja.Runtime, algObj *goja.Object, key *cryptoKeyHandle, defaultName string) (string, error) {
	hashName := defaultName
	if key != nil && key.Algorithm != nil {
		if hv, ok := key.Algorithm["hash"].(map[string]interface{}); ok {
			if name, ok := hv["name"].(string); ok && name != "" {
				hashName = name
			}
		}
	}
	if algObj != nil {
		if v := algObj.Get("hash"); isValuePresent(v) {
			var err error
			hashName, err = hashFromAlgorithmValue(rt, v)
			if err != nil {
				return "", err
			}
		}
	}
	return normalizeAlgorithmName(hashName)
}

func intProperty(obj *goja.Object, key string) (int, error) {
	if obj == nil {
		return 0, fmt.Errorf("algorithm.%s is required", key)
	}
	v := obj.Get(key)
	if goja.IsUndefined(v) || goja.IsNull(v) {
		return 0, fmt.Errorf("algorithm.%s is required", key)
	}
	i := int(v.ToInteger())
	if i <= 0 {
		return 0, fmt.Errorf("algorithm.%s must be > 0", key)
	}
	return i, nil
}

func publicExponentFromAlg(rt *goja.Runtime, obj *goja.Object) (int, error) {
	if obj == nil {
		return 65537, nil
	}
	v := obj.Get("publicExponent")
	if goja.IsUndefined(v) || goja.IsNull(v) {
		return 65537, nil
	}
	b, err := bufferSourceBytes(rt, v, true, false)
	if err != nil {
		return 0, err
	}
	if len(b) == 0 {
		return 0, errors.New("invalid publicExponent")
	}
	eBig := new(big.Int).SetBytes(b)
	if eBig.Sign() <= 0 || eBig.Bit(0) == 0 {
		return 0, errors.New("publicExponent must be an odd integer > 1")
	}
	maxInt := big.NewInt(int64(int(^uint(0) >> 1)))
	if eBig.Cmp(maxInt) > 0 {
		return 0, errors.New("publicExponent exceeds int range")
	}
	e := int(eBig.Int64())
	if e <= 1 || e%2 == 0 {
		return 0, errors.New("publicExponent must be an odd integer > 1")
	}
	return e, nil
}

func requiredBufferProperty(rt *goja.Runtime, obj *goja.Object, key string) ([]byte, error) {
	if obj == nil {
		return nil, fmt.Errorf("algorithm.%s is required", key)
	}
	v := obj.Get(key)
	if goja.IsUndefined(v) || goja.IsNull(v) {
		return nil, fmt.Errorf("algorithm.%s is required", key)
	}
	return bufferSourceBytes(rt, v, true, false)
}

func isValuePresent(v goja.Value) bool {
	return v != nil && !goja.IsUndefined(v) && !goja.IsNull(v)
}

func valueToStringSlice(value goja.Value) ([]string, error) {
	if goja.IsUndefined(value) || goja.IsNull(value) {
		return nil, nil
	}
	exported := value.Export()
	switch vv := exported.(type) {
	case []interface{}:
		out := make([]string, 0, len(vv))
		for _, item := range vv {
			s, ok := item.(string)
			if !ok {
				return nil, errors.New("usage list must contain strings")
			}
			out = append(out, s)
		}
		return out, nil
	case []string:
		out := make([]string, len(vv))
		copy(out, vv)
		return out, nil
	default:
		return nil, errors.New("usage list must be an array")
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

func rawKeyTypeHint(algObj *goja.Object) (string, error) {
	if algObj == nil {
		return "", nil
	}
	keys := []string{"keyType", "type"}
	for _, key := range keys {
		v := algObj.Get(key)
		if !isValuePresent(v) {
			continue
		}
		raw := strings.TrimSpace(strings.ToLower(v.String()))
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

func bufferSourceBytes(rt *goja.Runtime, value goja.Value, allowArrayBuffer bool, requireIntegerTypedArray bool) ([]byte, error) {
	if goja.IsUndefined(value) || goja.IsNull(value) {
		return nil, errors.New("input is required")
	}

	if allowArrayBuffer {
		if arrayBuffer, ok := value.Export().(goja.ArrayBuffer); ok {
			return arrayBuffer.Bytes(), nil
		}
	}

	obj := value.ToObject(rt)
	if obj == nil {
		return nil, errors.New("input must be an ArrayBuffer or an ArrayBufferView")
	}

	if requireIntegerTypedArray {
		ctorName := constructorName(rt, obj)
		if _, ok := integerTypedArrayNames[ctorName]; !ok {
			return nil, errors.New("input must be an integer TypedArray")
		}
	}

	bufferVal := obj.Get("buffer")
	if goja.IsUndefined(bufferVal) || goja.IsNull(bufferVal) {
		return nil, errors.New("input must be an ArrayBufferView")
	}

	arrayBuffer, ok := bufferVal.Export().(goja.ArrayBuffer)
	if !ok {
		return nil, errors.New("input buffer must be an ArrayBuffer")
	}

	offset := int(obj.Get("byteOffset").ToInteger())
	length := int(obj.Get("byteLength").ToInteger())
	bufferBytes := arrayBuffer.Bytes()
	if offset < 0 || length < 0 || offset+length > len(bufferBytes) {
		return nil, errors.New("invalid buffer range")
	}

	return bufferBytes[offset : offset+length], nil
}

func constructorName(rt *goja.Runtime, obj *goja.Object) string {
	ctor := obj.Get("constructor")
	if goja.IsUndefined(ctor) || goja.IsNull(ctor) {
		return ""
	}
	ctorObj := ctor.ToObject(rt)
	name := ctorObj.Get("name")
	if goja.IsUndefined(name) || goja.IsNull(name) {
		return ""
	}
	return name.String()
}

func newCryptoKeyObject(rt *goja.Runtime, handle *cryptoKeyHandle) *goja.Object {
	obj := rt.NewObject()
	_ = obj.Set("type", handle.Type)
	_ = obj.Set("extractable", handle.Extractable)
	_ = obj.Set("algorithm", cloneMap(handle.Algorithm))
	_ = obj.Set("usages", append([]string{}, handle.Usages...))
	_ = obj.Set(keyHandleSlot, handle)
	return obj
}

func extractCryptoKeyHandle(rt *goja.Runtime, value goja.Value) (*cryptoKeyHandle, error) {
	if goja.IsUndefined(value) || goja.IsNull(value) {
		return nil, errors.New("CryptoKey is required")
	}
	if h, ok := value.Export().(*cryptoKeyHandle); ok {
		return h, nil
	}
	obj := value.ToObject(rt)
	if obj == nil {
		return nil, errors.New("invalid CryptoKey")
	}
	hVal := obj.Get(keyHandleSlot)
	if goja.IsUndefined(hVal) || goja.IsNull(hVal) {
		return nil, errors.New("invalid CryptoKey handle")
	}
	h, ok := hVal.Export().(*cryptoKeyHandle)
	if !ok || h == nil {
		return nil, errors.New("invalid CryptoKey handle")
	}
	return h, nil
}

func cloneMap(src map[string]interface{}) map[string]interface{} {
	if src == nil {
		return nil
	}
	dst := make(map[string]interface{}, len(src))
	for k, v := range src {
		switch vv := v.(type) {
		case map[string]interface{}:
			dst[k] = cloneMap(vv)
		case []byte:
			cp := make([]byte, len(vv))
			copy(cp, vv)
			dst[k] = cp
		default:
			dst[k] = vv
		}
	}
	return dst
}

func exportRawKeyMaterial(handle *cryptoKeyHandle) ([]byte, error) {
	if len(handle.SecretKey) != 0 {
		out := make([]byte, len(handle.SecretKey))
		copy(out, handle.SecretKey)
		return out, nil
	}

	if pub := ecPublicFromHandle(handle); pub != nil {
		return marshalECRawPublicKey(pub), nil
	}

	pubEd := handle.Ed25519Public
	if len(pubEd) == 0 && len(handle.Ed25519Private) != 0 {
		pubEd = handle.Ed25519Private.Public().(ed25519.PublicKey)
	}
	if len(pubEd) != 0 {
		out := make([]byte, len(pubEd))
		copy(out, pubEd)
		return out, nil
	}

	pubX := handle.X25519Public
	if pubX == nil && handle.X25519Private != nil {
		pubX = handle.X25519Private.PublicKey()
	}
	if pubX != nil {
		out := pubX.Bytes()
		cp := make([]byte, len(out))
		copy(cp, out)
		return cp, nil
	}

	return nil, errors.New("raw export requires a secret key or supported public key")
}

func ecPublicFromHandle(handle *cryptoKeyHandle) *ecdsa.PublicKey {
	if handle.ECDSAPublic != nil {
		return handle.ECDSAPublic
	}
	if handle.ECDSAPrivate != nil {
		return &handle.ECDSAPrivate.PublicKey
	}
	if handle.ECDHPublic != nil {
		return handle.ECDHPublic
	}
	if handle.ECDHPrivate != nil {
		return &handle.ECDHPrivate.PublicKey
	}
	return nil
}

func marshalECRawPublicKey(pub *ecdsa.PublicKey) []byte {
	size := (pub.Curve.Params().BitSize + 7) / 8
	out := make([]byte, 1+2*size)
	out[0] = 0x04
	copy(out[1:1+size], leftPad(pub.X.Bytes(), size))
	copy(out[1+size:], leftPad(pub.Y.Bytes(), size))
	return out
}

func leftPad(in []byte, size int) []byte {
	if len(in) >= size {
		cp := make([]byte, len(in))
		copy(cp, in)
		return cp
	}
	out := make([]byte, size)
	copy(out[size-len(in):], in)
	return out
}

func resolvedPromise(rt *goja.Runtime, value interface{}) goja.Value {
	p, resolve, _ := rt.NewPromise()
	_ = resolve(value)
	return rt.ToValue(p)
}

func rejectedPromise(rt *goja.Runtime, err error) goja.Value {
	p, _, reject := rt.NewPromise()
	_ = reject(rt.NewTypeError(err.Error()))
	return rt.ToValue(p)
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

func xorT(a []byte, t uint64) {
	for i := 7; i >= 0; i-- {
		a[i] ^= byte(t & 0xff)
		t >>= 8
	}
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

func randomUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}

	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80

	var out [36]byte
	hex.Encode(out[0:8], b[0:4])
	out[8] = '-'
	hex.Encode(out[9:13], b[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], b[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], b[8:10])
	out[23] = '-'
	hex.Encode(out[24:36], b[10:16])
	return string(out[:])
}
