//go:build quickjs

package quickjs

import (
	"testing"

	"Scardice-core/dice/jsengine"
)

func newTestQuickJSBackend(t *testing.T) *nativeBackend {
	t.Helper()
	backend, err := newNativeBackend(jsengine.Config{}, Options{})
	if err != nil {
		t.Fatalf("创建 QuickJS backend 失败: %v", err)
	}
	t.Cleanup(func() {
		_ = backend.Dispose()
	})
	return backend
}

func evalBoolResult(t *testing.T, backend *nativeBackend, code string) bool {
	t.Helper()
	v, err := backend.EvalWithResult(code)
	if err != nil {
		t.Fatalf("执行脚本失败: %v", err)
	}
	b, ok := v.(bool)
	if !ok {
		t.Fatalf("返回值不是 bool: %T (%v)", v, v)
	}
	return b
}

func TestQuickJSCryptoHMACSignVerify(t *testing.T) {
	backend := newTestQuickJSBackend(t)
	ok := evalBoolResult(t, backend, `(async () => {
  const key = await crypto.subtle.generateKey(
    { name: "HMAC", hash: { name: "SHA-256" }, length: 256 },
    true,
    ["sign", "verify"]
  );
  const data = new TextEncoder().encode("quickjs-hmac");
  const sig = await crypto.subtle.sign("HMAC", key, data);
  const verified = await crypto.subtle.verify("HMAC", key, sig, data);
  return verified === true && sig.byteLength > 0;
})()`)
	if !ok {
		t.Fatal("HMAC sign/verify 结果不符合预期")
	}
}

func TestQuickJSCryptoAESGCMEncryptDecrypt(t *testing.T) {
	backend := newTestQuickJSBackend(t)
	ok := evalBoolResult(t, backend, `(async () => {
  const key = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 128 },
    true,
    ["encrypt", "decrypt"]
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = new TextEncoder().encode("quickjs-aes-gcm");
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plain);
  const back = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher);
  return new TextDecoder().decode(back) === "quickjs-aes-gcm";
})()`)
	if !ok {
		t.Fatal("AES-GCM encrypt/decrypt 结果不符合预期")
	}
}

func TestQuickJSCryptoImportExportJWK(t *testing.T) {
	backend := newTestQuickJSBackend(t)
	ok := evalBoolResult(t, backend, `(async () => {
  const key = await crypto.subtle.generateKey(
    { name: "HMAC", hash: "SHA-256", length: 256 },
    true,
    ["sign", "verify"]
  );
  const jwk = await crypto.subtle.exportKey("jwk", key);
  const imported = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "HMAC", hash: "SHA-256" },
    true,
    ["sign", "verify"]
  );
  const data = new TextEncoder().encode("quickjs-jwk");
  const sig = await crypto.subtle.sign("HMAC", imported, data);
  const ok = await crypto.subtle.verify("HMAC", imported, sig, data);
  return ok === true && typeof jwk.k === "string" && sig.byteLength > 0;
})()`)
	if !ok {
		t.Fatal("JWK import/export 结果不符合预期")
	}
}

func TestQuickJSCryptoDeriveAndWrapUnwrap(t *testing.T) {
	backend := newTestQuickJSBackend(t)
	ok := evalBoolResult(t, backend, `(async () => {
  const base = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode("quickjs-password"),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  const derived = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: new Uint8Array([1,2,3,4]), iterations: 1000, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 128 },
    true,
    ["encrypt", "decrypt"]
  );

  const wrappingKey = await crypto.subtle.generateKey(
    { name: "AES-KW", length: 128 },
    true,
    ["wrapKey", "unwrapKey"]
  );
  const wrapped = await crypto.subtle.wrapKey("raw", derived, wrappingKey, "AES-KW");
  const unwrapped = await crypto.subtle.unwrapKey(
    "raw",
    wrapped,
    wrappingKey,
    "AES-KW",
    { name: "AES-GCM", length: 128 },
    true,
    ["encrypt", "decrypt"]
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = new TextEncoder().encode("quickjs-derive-wrap");
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, unwrapped, plain);
  const back = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, unwrapped, cipher);
  return new TextDecoder().decode(back) === "quickjs-derive-wrap";
})()`)
	if !ok {
		t.Fatal("derive/wrap/unwrap 结果不符合预期")
	}
}

func TestQuickJSCryptoGetRandomValuesLimit(t *testing.T) {
	backend := newTestQuickJSBackend(t)
	ok := evalBoolResult(t, backend, `(async () => {
  try {
    crypto.getRandomValues(new Uint8Array(65537));
    return false;
  } catch (e) {
    return String(e).includes("65536");
  }
})()`)
	if !ok {
		t.Fatal("getRandomValues 上限校验不符合预期")
	}
}

func TestQuickJSCryptoGetRandomValuesRejectsFloatTypedArray(t *testing.T) {
	backend := newTestQuickJSBackend(t)
	ok := evalBoolResult(t, backend, `(async () => {
  try {
    crypto.getRandomValues(new Float32Array(8));
    return false;
  } catch (e) {
    return String(e).includes("integer TypedArray");
  }
})()`)
	if !ok {
		t.Fatal("getRandomValues 非整数 typed array 校验不符合预期")
	}
}

func TestQuickJSCryptoRSAPSSSignVerify(t *testing.T) {
	backend := newTestQuickJSBackend(t)
	ok := evalBoolResult(t, backend, `(async () => {
  const pair = await crypto.subtle.generateKey(
    {
      name: "RSA-PSS",
      modulusLength: 1024,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["sign", "verify"]
  );
  const data = new TextEncoder().encode("quickjs-rsa-pss");
  const sig = await crypto.subtle.sign({ name: "RSA-PSS", saltLength: 32 }, pair.privateKey, data);
  const ok = await crypto.subtle.verify({ name: "RSA-PSS", saltLength: 32 }, pair.publicKey, sig, data);
  return ok === true && sig.byteLength > 0;
})()`)
	if !ok {
		t.Fatal("RSA-PSS sign/verify 结果不符合预期")
	}
}

func TestQuickJSCryptoRSAOAEPEncryptDecrypt(t *testing.T) {
	backend := newTestQuickJSBackend(t)
	ok := evalBoolResult(t, backend, `(async () => {
  const pair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 1024,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["encrypt", "decrypt"]
  );
  const data = new TextEncoder().encode("quickjs-rsa-oaep");
  const cipher = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, pair.publicKey, data);
  const plain = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, pair.privateKey, cipher);
  return new TextDecoder().decode(plain) === "quickjs-rsa-oaep";
})()`)
	if !ok {
		t.Fatal("RSA-OAEP encrypt/decrypt 结果不符合预期")
	}
}

func TestQuickJSCryptoEd25519SignVerifyAndJWK(t *testing.T) {
	backend := newTestQuickJSBackend(t)
	ok := evalBoolResult(t, backend, `(async () => {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const data = new TextEncoder().encode("quickjs-ed25519");
  const sig = await crypto.subtle.sign("Ed25519", pair.privateKey, data);
  const ok1 = await crypto.subtle.verify("Ed25519", pair.publicKey, sig, data);

  const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  const imported = await crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" }, true, ["sign", "verify"]);
  const sig2 = await crypto.subtle.sign("Ed25519", imported, data);
  const ok2 = await crypto.subtle.verify("Ed25519", pair.publicKey, sig2, data);
  return ok1 === true && ok2 === true && typeof jwk.crv === "string";
})()`)
	if !ok {
		t.Fatal("Ed25519 sign/verify/jwk 结果不符合预期")
	}
}

func TestQuickJSCryptoECDSASignVerifyAndRaw(t *testing.T) {
	backend := newTestQuickJSBackend(t)
	ok := evalBoolResult(t, backend, `(async () => {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
  const data = new TextEncoder().encode("quickjs-ecdsa");
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, data);
  const ok1 = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pair.publicKey, sig, data);

  const rawPub = await crypto.subtle.exportKey("raw", pair.publicKey);
  const importedPub = await crypto.subtle.importKey(
    "raw",
    rawPub,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"]
  );
  const ok2 = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, importedPub, sig, data);
  return ok1 === true && ok2 === true && rawPub.byteLength > 0;
})()`)
	if !ok {
		t.Fatal("ECDSA sign/verify/raw 结果不符合预期")
	}
}

func TestQuickJSCryptoECDHDeriveBits(t *testing.T) {
	backend := newTestQuickJSBackend(t)
	ok := evalBoolResult(t, backend, `(async () => {
  const alice = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );
  const bob = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );
  const ab = await crypto.subtle.deriveBits({ name: "ECDH", public: bob.publicKey }, alice.privateKey, 256);
  const ba = await crypto.subtle.deriveBits({ name: "ECDH", public: alice.publicKey }, bob.privateKey, 256);
  const a1 = new Uint8Array(ab);
  const a2 = new Uint8Array(ba);
  if (a1.length !== a2.length) return false;
  for (let i = 0; i < a1.length; i++) {
    if (a1[i] !== a2[i]) return false;
  }
  return true;
})()`)
	if !ok {
		t.Fatal("ECDH deriveBits 结果不符合预期")
	}
}

func TestQuickJSCryptoX25519DeriveKey(t *testing.T) {
	backend := newTestQuickJSBackend(t)
	ok := evalBoolResult(t, backend, `(async () => {
  const alice = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveKey"]);
  const bob = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveKey"]);
  const ab = await crypto.subtle.deriveKey(
    { name: "X25519", public: bob.publicKey },
    alice.privateKey,
    { name: "AES-GCM", length: 128 },
    true,
    ["encrypt", "decrypt"]
  );
  const ba = await crypto.subtle.deriveKey(
    { name: "X25519", public: alice.publicKey },
    bob.privateKey,
    { name: "AES-GCM", length: 128 },
    true,
    ["encrypt", "decrypt"]
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = new TextEncoder().encode("quickjs-x25519");
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, ab, plain);
  const back = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, ba, cipher);
  return new TextDecoder().decode(back) === "quickjs-x25519";
})()`)
	if !ok {
		t.Fatal("X25519 deriveKey 结果不符合预期")
	}
}

func TestQuickJSCrypto3DESCBCEncryptDecrypt(t *testing.T) {
	backend := newTestQuickJSBackend(t)
	ok := evalBoolResult(t, backend, `(async () => {
  const key = await crypto.subtle.generateKey(
    { name: "3DES-CBC", length: 192 },
    true,
    ["encrypt", "decrypt"]
  );
  const iv = crypto.getRandomValues(new Uint8Array(8));
  const plain = new TextEncoder().encode("quickjs-3des");
  const cipher = await crypto.subtle.encrypt({ name: "DES-EDE3-CBC", iv }, key, plain);
  const back = await crypto.subtle.decrypt({ name: "3DES-CBC", iv }, key, cipher);
  return new TextDecoder().decode(back) === "quickjs-3des";
})()`)
	if !ok {
		t.Fatal("3DES-CBC encrypt/decrypt 结果不符合预期")
	}
}

func TestQuickJSCryptoRSAImportExportPKCS8SPKI(t *testing.T) {
	backend := newTestQuickJSBackend(t)
	ok := evalBoolResult(t, backend, `(async () => {
  const pair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 1024,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["encrypt", "decrypt"]
  );
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", pair.privateKey);
  const spki = await crypto.subtle.exportKey("spki", pair.publicKey);

  const importedPriv = await crypto.subtle.importKey(
    "pkcs8",
    pkcs8,
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["decrypt"]
  );
  const importedPub = await crypto.subtle.importKey(
    "spki",
    spki,
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["encrypt"]
  );

  const data = new TextEncoder().encode("quickjs-rsa-pkcs");
  const cipher = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, importedPub, data);
  const plain = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, importedPriv, cipher);
  const expIsArray = Array.isArray(pair.publicKey && pair.publicKey.algorithm && pair.publicKey.algorithm.publicExponent);
  return new TextDecoder().decode(plain) === "quickjs-rsa-pkcs" && expIsArray;
})()`)
	if !ok {
		t.Fatal("RSA import/export pkcs8+spki 结果不符合预期")
	}
}

func TestQuickJSCryptoECDSAImportExportSEC1SPKI(t *testing.T) {
	backend := newTestQuickJSBackend(t)
	ok := evalBoolResult(t, backend, `(async () => {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
  const sec1 = await crypto.subtle.exportKey("sec1", pair.privateKey);
  const spki = await crypto.subtle.exportKey("spki", pair.publicKey);
  const importedPriv = await crypto.subtle.importKey(
    "sec1",
    sec1,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign"]
  );
  const importedPub = await crypto.subtle.importKey(
    "spki",
    spki,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"]
  );
  const data = new TextEncoder().encode("quickjs-ecdsa-sec1");
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, importedPriv, data);
  const ok = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, importedPub, sig, data);
  return ok === true && sec1.byteLength > 0 && spki.byteLength > 0;
})()`)
	if !ok {
		t.Fatal("ECDSA import/export sec1+spki 结果不符合预期")
	}
}

func TestQuickJSCryptoWrapUnwrapPKCS8WithRSAOAEP(t *testing.T) {
	backend := newTestQuickJSBackend(t)
	ok := evalBoolResult(t, backend, `(async () => {
  const ed = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const wrapPair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 1024,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["wrapKey", "unwrapKey"]
  );
  const wrapped = await crypto.subtle.wrapKey("pkcs8", ed.privateKey, wrapPair.publicKey, { name: "RSA-OAEP" });
  const unwrapped = await crypto.subtle.unwrapKey(
    "pkcs8",
    wrapped,
    wrapPair.privateKey,
    { name: "RSA-OAEP" },
    { name: "Ed25519" },
    true,
    ["sign"]
  );
  const data = new TextEncoder().encode("quickjs-wrap-pkcs8");
  const sig = await crypto.subtle.sign("Ed25519", unwrapped, data);
  const ok = await crypto.subtle.verify("Ed25519", ed.publicKey, sig, data);
  return ok === true && wrapped.byteLength > 0;
})()`)
	if !ok {
		t.Fatal("wrap/unwrap pkcs8 + RSA-OAEP 结果不符合预期")
	}
}
