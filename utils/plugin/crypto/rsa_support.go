//nolint:gosec // WebCrypto compatibility includes legacy RSA modes for existing scripts.
package sealcrypto

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

func splitRSAUsages(algorithm string, usages []string) ([]string, []string) {
	var pubUsages []string
	var priUsages []string
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
	return pubUsages, priUsages
}

func splitOKPUsages(algorithm string, usages []string) ([]string, []string) {
	var pubUsages []string
	var priUsages []string
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
	return pubUsages, priUsages
}

func splitECUsages(algorithm string, usages []string) ([]string, []string) {
	var pubUsages []string
	var priUsages []string
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
	return pubUsages, priUsages
}

func publicExponentFromAlg(obj map[string]any) (int, error) {
	if obj == nil {
		return 65537, nil
	}
	v, ok := obj["publicExponent"]
	if !ok || v == nil {
		return 65537, nil
	}
	b, err := requireBytes(v, "algorithm.publicExponent")
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

	for i := 0; i < 256; i++ {
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

func hashNameForRSA(algObj map[string]any, key *cryptoKey, defaultName string) (string, error) {
	hashName := defaultName
	if key != nil && key.Algorithm != nil {
		if hv, ok := key.Algorithm["hash"].(map[string]any); ok {
			if name, ok := hv["name"].(string); ok && strings.TrimSpace(name) != "" {
				hashName = name
			}
		}
	}
	if algObj != nil {
		if v, ok := algObj["hash"]; ok {
			name, err := hashFromAlgorithmValue(v)
			if err != nil {
				return "", err
			}
			hashName = name
		}
	}
	return normalizeHashName(hashName)
}

func digestForCryptoHash(hashName string, data []byte) (crypto.Hash, []byte, error) {
	switch hashName {
	case "MD5":
		sum := md5Sum(data)
		return crypto.MD5, sum, nil
	case "SHA-1":
		sum := sha1Sum(data)
		return crypto.SHA1, sum, nil
	case "SHA-224":
		sum := sha224Sum(data)
		return crypto.SHA224, sum, nil
	case "SHA-256":
		sum := sha256Sum(data)
		return crypto.SHA256, sum, nil
	case "SHA-384":
		sum := sha384Sum(data)
		return crypto.SHA384, sum, nil
	case "SHA-512":
		sum := sha512Sum(data)
		return crypto.SHA512, sum, nil
	default:
		return 0, nil, fmt.Errorf("unsupported hash for RSA: %s", hashName)
	}
}

func parsePrivateKey(der []byte) (any, error) {
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

func privateKeyToCryptoKey(privAny any, algorithm string, algObj map[string]any, extractable bool, usages []string) (*cryptoKey, error) {
	switch key := privAny.(type) {
	case *rsa.PrivateKey:
		switch algorithm {
		case "RSASSA-PKCS1-V1_5", "RSA-PSS", "RSA-OAEP", "RSAES-PKCS1-V1_5":
		default:
			return nil, errors.New("algorithm is not compatible with RSA private key")
		}
		hashName, err := hashFromAlgorithmObject(algObj, "SHA-256")
		if err != nil {
			return nil, err
		}
		return &cryptoKey{
			Type:        "private",
			Extractable: extractable,
			Algorithm: map[string]any{
				"name": algorithm,
				"hash": map[string]any{"name": hashName},
			},
			Usages:     usages,
			RSAPrivate: key,
		}, nil
	case ed25519.PrivateKey:
		if algorithm != "Ed25519" {
			return nil, errors.New("algorithm is not compatible with Ed25519 private key")
		}
		return &cryptoKey{
			Type:           "private",
			Extractable:    extractable,
			Algorithm:      map[string]any{"name": "Ed25519"},
			Usages:         usages,
			Ed25519Private: key,
		}, nil
	case *ecdsa.PrivateKey:
		if algorithm != "ECDSA" && algorithm != "ECDH" {
			return nil, errors.New("algorithm is not compatible with EC private key")
		}
		return &cryptoKey{
			Type:        "private",
			Extractable: extractable,
			Algorithm: map[string]any{
				"name":       algorithm,
				"namedCurve": namedCurveFromElliptic(key.Curve),
			},
			Usages: usages,
			ECDSAPrivate: func() *ecdsa.PrivateKey {
				if algorithm == "ECDSA" {
					return key
				}
				return nil
			}(),
			ECDHPrivate: func() *ecdsa.PrivateKey {
				if algorithm == "ECDH" {
					return key
				}
				return nil
			}(),
		}, nil
	case *ecdh.PrivateKey:
		if algorithm != "X25519" {
			return nil, errors.New("algorithm is not compatible with X25519 private key")
		}
		return &cryptoKey{
			Type:          "private",
			Extractable:   extractable,
			Algorithm:     map[string]any{"name": "X25519"},
			Usages:        usages,
			X25519Private: key,
		}, nil
	default:
		return nil, errors.New("unsupported private key type")
	}
}

func publicKeyToCryptoKey(pubAny any, algorithm string, algObj map[string]any, usages []string) (*cryptoKey, error) {
	switch key := pubAny.(type) {
	case *rsa.PublicKey:
		switch algorithm {
		case "RSASSA-PKCS1-V1_5", "RSA-PSS", "RSA-OAEP", "RSAES-PKCS1-V1_5":
		default:
			return nil, errors.New("algorithm is not compatible with RSA public key")
		}
		hashName, err := hashFromAlgorithmObject(algObj, "SHA-256")
		if err != nil {
			return nil, err
		}
		return &cryptoKey{
			Type:        "public",
			Extractable: true,
			Algorithm: map[string]any{
				"name": algorithm,
				"hash": map[string]any{"name": hashName},
			},
			Usages:    usages,
			RSAPublic: key,
		}, nil
	case ed25519.PublicKey:
		if algorithm != "Ed25519" {
			return nil, errors.New("algorithm is not compatible with Ed25519 public key")
		}
		return &cryptoKey{
			Type:          "public",
			Extractable:   true,
			Algorithm:     map[string]any{"name": "Ed25519"},
			Usages:        usages,
			Ed25519Public: key,
		}, nil
	case *ecdsa.PublicKey:
		if algorithm != "ECDSA" && algorithm != "ECDH" {
			return nil, errors.New("algorithm is not compatible with EC public key")
		}
		return &cryptoKey{
			Type:        "public",
			Extractable: true,
			Algorithm: map[string]any{
				"name":       algorithm,
				"namedCurve": namedCurveFromElliptic(key.Curve),
			},
			Usages: usages,
			ECDSAPublic: func() *ecdsa.PublicKey {
				if algorithm == "ECDSA" {
					return key
				}
				return nil
			}(),
			ECDHPublic: func() *ecdsa.PublicKey {
				if algorithm == "ECDH" {
					return key
				}
				return nil
			}(),
		}, nil
	case *ecdh.PublicKey:
		if algorithm != "X25519" {
			return nil, errors.New("algorithm is not compatible with X25519 public key")
		}
		return &cryptoKey{
			Type:         "public",
			Extractable:  true,
			Algorithm:    map[string]any{"name": "X25519"},
			Usages:       usages,
			X25519Public: key,
		}, nil
	default:
		return nil, errors.New("unsupported public key type")
	}
}

func importRSAJWK(algorithm string, algObj map[string]any, jwk map[string]any, extractable bool, usages []string) (*cryptoKey, error) {
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
	hashName, err := hashFromAlgorithmObject(algObj, "SHA-256")
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
		return &cryptoKey{
			Type:        "private",
			Extractable: extractable,
			Algorithm: map[string]any{
				"name": algorithm,
				"hash": map[string]any{"name": hashName},
			},
			Usages:     usages,
			RSAPrivate: priv,
		}, nil
	}

	pub := &rsa.PublicKey{N: n, E: e}
	return &cryptoKey{
		Type:        "public",
		Extractable: true,
		Algorithm: map[string]any{
			"name": algorithm,
			"hash": map[string]any{"name": hashName},
		},
		Usages:    usages,
		RSAPublic: pub,
	}, nil
}

func exportRSAJWK(key *cryptoKey) (map[string]any, error) {
	jwk := map[string]any{
		"kty":     "RSA",
		"key_ops": append([]string{}, key.Usages...),
		"ext":     key.Extractable,
	}
	if alg := jwkAlgForAsymmetricKey(key); alg != "" {
		jwk["alg"] = alg
	}
	pub := key.RSAPublic
	if pub == nil && key.RSAPrivate != nil {
		pub = &key.RSAPrivate.PublicKey
	}
	if pub == nil {
		return nil, errors.New("RSA JWK export requires an RSA key")
	}
	jwk["n"] = base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	jwk["e"] = base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	if key.RSAPrivate != nil {
		priv := key.RSAPrivate
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

func parseJWKBigInt(jwk map[string]any, key string) (*big.Int, error) {
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

	maxCandidate := new(big.Int).Sub(n, two)
	if maxCandidate.Sign() <= 0 {
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

		for i := 0; i < t; i++ {
			x := new(big.Int).Exp(y, two, n)
			if x.Cmp(one) == 0 {
				diff := new(big.Int).Sub(y, one)
				factor := new(big.Int).GCD(nil, nil, diff, n)
				if factor.Cmp(one) > 0 && factor.Cmp(n) < 0 {
					p := factor
					q := new(big.Int).Div(new(big.Int).Set(n), p)
					if p.Cmp(q) > 0 {
						p, q = q, p
					}
					return p, q, true
				}
				return nil, nil, false
			}
			if x.Cmp(nMinus1) == 0 {
				return nil, nil, false
			}
			y = x
		}
		return nil, nil, false
	}

	candidates := []int64{2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37}
	for _, c := range candidates {
		if c <= 1 {
			continue
		}
		g := big.NewInt(c)
		if g.Cmp(maxCandidate) > 0 {
			break
		}
		if p, q, ok := tryBase(g); ok {
			return p, q, nil
		}
	}

	for i := 0; i < 64; i++ {
		g, err := rand.Int(rand.Reader, maxCandidate)
		if err != nil {
			return nil, nil, err
		}
		g.Add(g, two)
		if p, q, ok := tryBase(g); ok {
			return p, q, nil
		}
	}
	return nil, nil, errors.New("failed to recover RSA factors from n/e/d")
}

func hasMapKey(m map[string]any, key string) bool {
	_, ok := m[key]
	return ok
}

func namedCurveByName(name string) (elliptic.Curve, string, error) {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "P-256", "SECP256R1":
		return elliptic.P256(), "P-256", nil
	case "P-384", "SECP384R1":
		return elliptic.P384(), "P-384", nil
	case "P-521", "SECP521R1":
		return elliptic.P521(), "P-521", nil
	default:
		return nil, "", errors.New("unsupported namedCurve")
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
		if curve != nil && curve.Params() != nil {
			return curve.Params().Name
		}
		return ""
	}
}

func leftPad(in []byte, size int) []byte {
	if len(in) >= size {
		out := make([]byte, len(in))
		copy(out, in)
		return out
	}
	out := make([]byte, size)
	copy(out[size-len(in):], in)
	return out
}

func marshalECRawPublicKey(pub *ecdsa.PublicKey) []byte {
	size := (pub.Curve.Params().BitSize + 7) / 8
	out := make([]byte, 1+2*size)
	out[0] = 0x04
	copy(out[1:1+size], leftPad(pub.X.Bytes(), size))
	copy(out[1+size:], leftPad(pub.Y.Bytes(), size))
	return out
}

func stringFromMap(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

func algorithmHashNameFromKey(key *cryptoKey) string {
	if key == nil || key.Algorithm == nil {
		return ""
	}
	hashValue, ok := key.Algorithm["hash"]
	if !ok || hashValue == nil {
		if key.HMACHash != "" {
			return key.HMACHash
		}
		return ""
	}
	switch hv := hashValue.(type) {
	case string:
		return hv
	case map[string]any:
		if name, ok := hv["name"].(string); ok {
			return name
		}
	}
	return ""
}

func jwkAlgForAsymmetricKey(key *cryptoKey) string {
	if key == nil || key.Algorithm == nil {
		return ""
	}
	algName, _ := key.Algorithm["name"].(string)
	switch algName {
	case "RSASSA-PKCS1-V1_5":
		switch algorithmHashNameFromKey(key) {
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
		switch algorithmHashNameFromKey(key) {
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
		switch algorithmHashNameFromKey(key) {
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
		curveName, _ := key.Algorithm["namedCurve"].(string)
		switch strings.ToUpper(strings.TrimSpace(curveName)) {
		case "P-256":
			return "ES256"
		case "P-384":
			return "ES384"
		case "P-521":
			return "ES512"
		}
	case "ECDH", "X25519":
		return "ECDH-ES"
	case "Ed25519":
		return "EdDSA"
	}
	return ""
}

func md5Sum(data []byte) []byte {
	sum := md5.Sum(data)
	return sum[:]
}

func sha1Sum(data []byte) []byte {
	sum := sha1.Sum(data)
	return sum[:]
}

func sha224Sum(data []byte) []byte {
	sum := sha256.Sum224(data)
	return sum[:]
}

func sha256Sum(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func sha384Sum(data []byte) []byte {
	sum := sha512.Sum384(data)
	return sum[:]
}

func sha512Sum(data []byte) []byte {
	sum := sha512.Sum512(data)
	return sum[:]
}
