(async () => {
    const enc = new TextEncoder();
    const dec = new TextDecoder();

    const toHex = (b) =>
    Array.from(new Uint8Array(b))
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");

    const pass = (suite, name, detail, data) =>
    console.log(`[PASS] ${suite}/${name} | ${detail}${data ? " | " + data : ""}`);

    const legacy = (suite, name, detail, data) =>
    console.log(c
        `[LEGACY] ${suite}/${name} | ${detail}${data ? " | " + data : ""}`
    );

    const extra = (suite, name, detail, data) =>
    console.log(
        `[EXTRA] ${suite}/${name} | ${detail}${data ? " | " + data : ""}`
    );

    const fail = (suite, name, e) =>
    console.log(`[FAIL] ${suite}/${name} | ${e.name}: ${e.message}`);

    const test = async (suite, name, fn) => {
        try {
            await fn();
        } catch (e) {
            fail(suite, name, e);
        }
    };

    const abEq = (a, b) => {
        const ua = new Uint8Array(a);
        const ub = new Uint8Array(b);
        if (ua.byteLength !== ub.byteLength) return false;
        for (let i = 0; i < ua.byteLength; i++) if (ua[i] !== ub[i]) return false;
        return true;
    };

    const dataStrict = enc.encode("strict_test_vector_2026");
    const dataSeal = enc.encode("sealdice_crypto_test");
    const dataLegacy = enc.encode("legacy_compat_test");

    console.log("--- CRYPTO TEST SUITE START ---");

    await test("BASE", "randomUUID", async () => {
        pass("BASE", "randomUUID", "Value", crypto.randomUUID());
    });

    await test("BASE", "getRandomValues_8", async () => {
        const buf = new Uint8Array(8);
        crypto.getRandomValues(buf);
        pass("BASE", "getRandomValues", "8 bytes hex", toHex(buf));
    });

    await test("STRICT", "getRandomValues_Boundary", async () => {
        const limits = [1, 65536];
        for (const l of limits) {
            const b = new Uint8Array(l);
            crypto.getRandomValues(b);
        }
        pass("STRICT", "getRandomValues", "Boundaries checked", "1 to 65536 bytes");
    });

    await test("STRICT", "getRandomValues_OverLimit_ShouldThrow", async () => {
        let threw = false;
        try {
            crypto.getRandomValues(new Uint8Array(65537));
        } catch (e) {
            threw = true;
        }
        if (!threw) throw new Error("Expected getRandomValues(65537) to throw");
        pass("STRICT", "getRandomValues", "OverLimit", "65537 bytes -> threw");
    });

    await test("SEAL", "digest_sha256", async () => {
        const h = await crypto.subtle.digest("SHA-256", dataSeal);
        pass("SEAL", "SHA-256", "Hex", toHex(h));
    });

    await test("STRICT", "digest_sha512_long", async () => {
        const h = await crypto.subtle.digest("SHA-512", dataStrict);
        pass("STRICT", "SHA-512", "Hex", toHex(h));
    });

    await test("EXTRA", "digest_md5_extra", async () => {
        const h = await crypto.subtle.digest("MD5", dataSeal);
        extra("EXTRA", "MD5", "Hex", toHex(h));
    });

    await test("EXTRA", "MD5_Digest", async () => {
        const h = await crypto.subtle.digest("MD5", dataLegacy);
        extra("EXTRA", "MD5", "Hex", toHex(h));
    });

    await test("LEGACY", "SHA1_Digest", async () => {
        const h = await crypto.subtle.digest("SHA-1", dataLegacy);
        legacy("LEGACY", "SHA-1", "Hex", toHex(h));
    });

    let rsaPssKey;
    await test("STRICT", "RSA_PSS_Sign_Verify", async () => {
        rsaPssKey = await crypto.subtle.generateKey(
            {
                name: "RSA-PSS",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                    hash: "SHA-256",
            },
            true,
            ["sign", "verify"]
        );
        const sig = await crypto.subtle.sign(
            { name: "RSA-PSS", saltLength: 32 },
            rsaPssKey.privateKey,
            dataStrict
        );
        const ok = await crypto.subtle.verify(
            { name: "RSA-PSS", saltLength: 32 },
            rsaPssKey.publicKey,
            sig,
            dataStrict
        );
        pass("STRICT", "RSA-PSS", `SigLen: ${sig.byteLength}`, `Verified: ${ok}`);
    });

    await test("STRICT", "RSA_PKCS1_Sign_Verify", async () => {
        const k = await crypto.subtle.generateKey(
            {
                name: "RSASSA-PKCS1-v1_5",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                    hash: "SHA-256",
            },
            true,
            ["sign", "verify"]
        );
        const s = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", k.privateKey, dataStrict);
        const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", k.publicKey, s, dataStrict);
        pass("STRICT", "PKCS1-v1_5", "SigLen", `${s.byteLength} | Verified: ${ok}`);
    });

    await test("STRICT", "ECDSA_P256", async () => {
        const kp = await crypto.subtle.generateKey(
            { name: "ECDSA", namedCurve: "P-256" },
            true,
            ["sign", "verify"]
        );
        const sig = await crypto.subtle.sign(
            { name: "ECDSA", hash: "SHA-256" },
            kp.privateKey,
            dataStrict
        );
        const ok = await crypto.subtle.verify(
            { name: "ECDSA", hash: "SHA-256" },
            kp.publicKey,
            sig,
            dataStrict
        );
        pass("STRICT", "ECDSA_P256", "SigHex", toHex(sig));
        pass("STRICT", "ECDSA_P256", "Verified", String(ok));
    });

    await test("STRICT", "ECDSA_P256_Negatives", async () => {
        const kp = await crypto.subtle.generateKey(
            { name: "ECDSA", namedCurve: "P-256" },
            true,
            ["sign", "verify"]
        );

        const sig = await crypto.subtle.sign(
            { name: "ECDSA", hash: "SHA-256" },
            kp.privateKey,
            dataStrict
        );

        const ok = await crypto.subtle.verify(
            { name: "ECDSA", hash: "SHA-256" },
            kp.publicKey,
            sig,
            dataStrict
        );
        if (!ok) throw new Error("Expected verify(true) for original sig/data");

        const tamperedSig = new Uint8Array(sig);
        tamperedSig[0] ^= 0x01;

        const okSig = await crypto.subtle.verify(
            { name: "ECDSA", hash: "SHA-256" },
            kp.publicKey,
            tamperedSig,
            dataStrict
        );
        if (okSig) throw new Error("Expected verify(false) for tampered signature");

        const tamperedData = enc.encode("strict_test_vector_2026X");
        const okData = await crypto.subtle.verify(
            { name: "ECDSA", hash: "SHA-256" },
            kp.publicKey,
            sig,
            tamperedData
        );
        if (okData) throw new Error("Expected verify(false) for tampered data");

        pass("STRICT", "ECDSA_P256_Negatives", "verify(false) checks", "sig/data tamper -> false");
    });

    await test("SEAL", "Ed25519_Flow", async () => {
        const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
            "sign",
            "verify",
        ]);
        const sig = await crypto.subtle.sign("Ed25519", kp.privateKey, dataSeal);
        const ok = await crypto.subtle.verify("Ed25519", kp.publicKey, sig, dataSeal);
        pass("SEAL", "Ed25519", `SigLen: ${sig.byteLength}`, `Verified: ${ok}`);
    });

    await test("EXTRA", "Ed25519_Raw_Import_Seed", async () => {
        const seed = new Uint8Array(32).fill(0x55);
        const k = await crypto.subtle.importKey(
            "raw",
            seed,
            { name: "Ed25519", keyType: "private" },
            true,
            ["sign"]
        );
        const s = await crypto.subtle.sign("Ed25519", k, dataStrict);
        extra(
            "EXTRA",
            "Ed25519_Raw",
            "KeyType",
            `${k.type} | SigHex: ${toHex(s).slice(0, 16)}...`
        );
    });

    await test("SEAL", "PBKDF2_Derive", async () => {
        const password = enc.encode("password123");
        const base = await crypto.subtle.importKey("raw", password, "PBKDF2", false, [
            "deriveBits",
        ]);
        const bits = await crypto.subtle.deriveBits(
            {
                name: "PBKDF2",
                salt: new Uint8Array(8).fill(0),
                                                    iterations: 1000,
                                                    hash: "SHA-256",
            },
            base,
            128
        );
        pass("SEAL", "PBKDF2-1000-SHA256", "DerivedBitsHex", toHex(bits));
    });

    await test("STRICT", "HKDF_Derive", async () => {
        const ikm = await crypto.subtle.importKey(
            "raw",
            new Uint8Array(32).fill(0x01),
                                                  "HKDF",
                                                  false,
                                                  ["deriveKey", "deriveBits"]
        );
        const bits = await crypto.subtle.deriveBits(
            {
                name: "HKDF",
                hash: "SHA-256",
                salt: new Uint8Array(16),
                                                    info: enc.encode("info"),
            },
            ikm,
            256
        );
        pass("STRICT", "HKDF", "DerivedBits", toHex(bits));
    });

    await test("STRICT", "ECDH_Key_Agreement", async () => {
        const alice = await crypto.subtle.generateKey(
            { name: "ECDH", namedCurve: "P-256" },
            true,
            ["deriveKey", "deriveBits"]
        );
        const bob = await crypto.subtle.generateKey(
            { name: "ECDH", namedCurve: "P-256" },
            true,
            ["deriveKey", "deriveBits"]
        );
        const shared = await crypto.subtle.deriveBits(
            { name: "ECDH", public: bob.publicKey },
            alice.privateKey,
            256
        );
        pass("STRICT", "ECDH_P256", "SharedSecretHex", toHex(shared));
    });

    await test("STRICT", "ECDH_Bilateral_Match", async () => {
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

        const ab = await crypto.subtle.deriveBits(
            { name: "ECDH", public: bob.publicKey },
            alice.privateKey,
            256
        );
        const ba = await crypto.subtle.deriveBits(
            { name: "ECDH", public: alice.publicKey },
            bob.privateKey,
            256
        );

        if (!abEq(ab, ba)) {
            throw new Error(
                `ECDH secrets mismatch | ab=${toHex(ab).slice(0, 16)}... ba=${toHex(ba).slice(0, 16)}...`
            );
        }

        pass("STRICT", "ECDH_Bilateral_Match", "SharedSecret", toHex(ab));
    });

    await test("EXTRA", "X25519_Raw_Import", async () => {
        const rawPriv = new Uint8Array(32).fill(0x42);
        const k = await crypto.subtle.importKey(
            "raw",
            rawPriv,
            { name: "X25519", keyType: "private" },
            true,
            ["deriveBits"]
        );
        extra("EXTRA", "X25519_Raw", "KeyType", k.type);
    });

    let aesGcmKey;
    const gcmIv = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

    await test("SEAL", "AES_GCM_Encrypt_Decrypt", async () => {
        aesGcmKey = await crypto.subtle.generateKey(
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt", "wrapKey"]
        );
        const encBytes = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv: gcmIv },
            aesGcmKey,
            dataSeal
        );
        const decBytes = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: gcmIv },
            aesGcmKey,
            encBytes
        );
        pass("SEAL", "AES-GCM", "CipherHex", toHex(encBytes));
        pass("SEAL", "AES-GCM", "Decrypted", dec.decode(decBytes));
    });

    await test("STRICT", "AES_GCM_SameIV_DiffPlaintexts", async () => {
        if (!aesGcmKey) {
            aesGcmKey = await crypto.subtle.generateKey(
                { name: "AES-GCM", length: 256 },
                true,
                ["encrypt", "decrypt", "wrapKey"]
            );
        }

        const p1 = enc.encode("gcm_plaintext_A");
        const p2 = enc.encode("gcm_plaintext_B");

        const c1 = await crypto.subtle.encrypt({ name: "AES-GCM", iv: gcmIv }, aesGcmKey, p1);
        const c2 = await crypto.subtle.encrypt({ name: "AES-GCM", iv: gcmIv }, aesGcmKey, p2);

        if (abEq(c1, c2)) throw new Error("Expected different ciphertexts for different plaintexts");

        const d1 = await crypto.subtle.decrypt({ name: "AES-GCM", iv: gcmIv }, aesGcmKey, c1);
        const d2 = await crypto.subtle.decrypt({ name: "AES-GCM", iv: gcmIv }, aesGcmKey, c2);

        pass("STRICT", "AES-GCM", "SameIV_DiffPT", `c1!=c2 | d1=${dec.decode(d1)} d2=${dec.decode(d2)}`);
    });

    await test("STRICT", "AES_GCM_RandomIV_TwiceSamePT", async () => {
        if (!aesGcmKey) {
            aesGcmKey = await crypto.subtle.generateKey(
                { name: "AES-GCM", length: 256 },
                true,
                ["encrypt", "decrypt", "wrapKey"]
            );
        }

        const iv1 = crypto.getRandomValues(new Uint8Array(12));
        const iv2 = crypto.getRandomValues(new Uint8Array(12));

        const c1 = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv1 }, aesGcmKey, dataSeal);
        const c2 = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv2 }, aesGcmKey, dataSeal);

        if (abEq(c1, c2)) throw new Error("Expected different ciphertexts for different IVs");

        pass("STRICT", "AES-GCM", "RandomIV_Twice", `iv1=${toHex(iv1)} iv2=${toHex(iv2)}`);
    });

    await test("STRICT", "AES_CTR_Counter_Wrap", async () => {
        const k = await crypto.subtle.generateKey(
            { name: "AES-CTR", length: 128 },
            true,
            ["encrypt"]
        );
        const counter = new Uint8Array(16).fill(0xff);
        const encBytes = await crypto.subtle.encrypt(
            { name: "AES-CTR", counter, length: 64 },
            k,
            dataStrict
        );
        pass("STRICT", "AES-CTR", "CipherHex", toHex(encBytes));
    });

    await test("SEAL", "JWK_Export", async () => {
        if (!aesGcmKey) throw new Error("AES-GCM key not generated yet");
        const jwk = await crypto.subtle.exportKey("jwk", aesGcmKey);
        pass("SEAL", "JWK_Export", "Alg", `${jwk.alg} | K: ${jwk.k}`);
    });

    await test("SEAL", "WrapKey_AES_GCM", async () => {
        if (!aesGcmKey) throw new Error("AES-GCM key not generated yet");
        const wrapIv = new Uint8Array(12).fill(9);
        const wrapped = await crypto.subtle.wrapKey("jwk", aesGcmKey, aesGcmKey, {
            name: "AES-GCM",
            iv: wrapIv,
        });
        pass("SEAL", "WrapKey", "WrappedHex", toHex(wrapped));
    });

    await test("STRICT", "AES_Import_Raw", async () => {
        const rawKey = new Uint8Array(16).fill(0x11);
        const key = await crypto.subtle.importKey(
            "raw",
            rawKey,
            { name: "AES-GCM" },
            true,
            ["encrypt", "decrypt"]
        );
        pass("STRICT", "importKey_Raw", "Alg", key.algorithm.name);
    });

    await test("STRICT", "JWK_RoundTrip_AES", async () => {
        const originalKey = await crypto.subtle.generateKey(
            { name: "AES-GCM", length: 128 },
            true,
            ["encrypt"]
        );
        const jwk = await crypto.subtle.exportKey("jwk", originalKey);
        const importedKey = await crypto.subtle.importKey(
            "jwk",
            jwk,
            { name: "AES-GCM" },
            true,
            ["encrypt"]
        );
        pass("STRICT", "JWK_RoundTrip", "Status", importedKey.type === "secret" ? "SUCCESS" : "FAIL");
    });

    await test("STRICT", "ECDSA_Import_SPKI_Public", async () => {
        const kp = await crypto.subtle.generateKey(
            { name: "ECDSA", namedCurve: "P-256" },
            true,
            ["verify"]
        );
        const spki = await crypto.subtle.exportKey("spki", kp.publicKey);
        const importedPubKey = await crypto.subtle.importKey(
            "spki",
            spki,
            { name: "ECDSA", namedCurve: "P-256" },
            true,
            ["verify"]
        );
        pass("STRICT", "importKey_SPKI", "Status", importedPubKey.type === "public" ? "SUCCESS" : "FAIL");
    });

    await test("STRICT", "PKCS8_Import_RSA_Private", async () => {
        const kp = await crypto.subtle.generateKey(
            {
                name: "RSASSA-PKCS1-v1_5",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                    hash: "SHA-256",
            },
            true,
            ["sign"]
        );
        const pkcs8 = await crypto.subtle.exportKey("pkcs8", kp.privateKey);
        const importedPrivKey = await crypto.subtle.importKey(
            "pkcs8",
            pkcs8,
            { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
            true,
            ["sign"]
        );
        pass("STRICT", "importKey_PKCS8", "Status", importedPrivKey.type === "private" ? "SUCCESS" : "FAIL");
    });

    await test("EXTRA", "3DES_CBC_Generate", async () => {
        const k = await crypto.subtle.generateKey(
            { name: "3DES-CBC", length: 192 },
            true,
            ["encrypt"]
        );
        extra("EXTRA", "3DES-CBC", "AlgorithmName", k.algorithm.name);
    });

    await test("EXTRA", "DES_EDE3_CBC_Encrypt_Decrypt", async () => {
        const k = await crypto.subtle.generateKey(
            { name: "3DES-CBC", length: 192 },
            true,
            ["encrypt", "decrypt"]
        );
        const iv = crypto.getRandomValues(new Uint8Array(8));
        const encBytes = await crypto.subtle.encrypt({ name: "3DES-CBC", iv }, k, dataLegacy);
        const decBytes = await crypto.subtle.decrypt({ name: "3DES-CBC", iv }, k, encBytes);
        extra("EXTRA", "3DES-CBC", "Decrypted", dec.decode(decBytes));
    });

    await test("EXTRA", "RSAES_PKCS1_v1_5", async () => {
        const kp = await crypto.subtle.generateKey(
            {
                name: "RSAES-PKCS1-v1_5",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
            },
            true,
            ["encrypt", "decrypt"]
        );
        const encBytes = await crypto.subtle.encrypt(
            { name: "RSAES-PKCS1-v1_5" },
            kp.publicKey,
            dataLegacy
        );
        const decBytes = await crypto.subtle.decrypt(
            { name: "RSAES-PKCS1-v1_5" },
            kp.privateKey,
            encBytes
        );
        extra(
            "EXTRA",
            "RSAES-PKCS1",
            "Status",
            dec.decode(decBytes) === "legacy_compat_test" ? "SUCCESS" : "FAIL"
        );
    });

    await test("EXTRA", "HMAC_MD5", async () => {
        const k = await crypto.subtle.generateKey({ name: "HMAC", hash: "MD5" }, true, ["sign"]);
        const s = await crypto.subtle.sign("HMAC", k, dataLegacy);
        extra("EXTRA", "HMAC-MD5", "SigLen", String(s.byteLength));
    });

    await test("STRESS", "HMAC_SHA256_100", async () => {
        const iterations = 100;
        let ok = 0;

        for (let i = 0; i < iterations; i++) {
            try {
                const buf = crypto.getRandomValues(new Uint8Array(1024));
                const key = await crypto.subtle.generateKey(
                    { name: "HMAC", hash: "SHA-256" },
                    false,
                    ["sign"]
                );
                await crypto.subtle.sign("HMAC", key, buf);
                ok++;
            } catch {}
        }

        pass("STRESS", "HMAC-SHA256", "SUCCESS", `${ok}/${iterations}`);
        if (ok === iterations) console.log("RESULT: STABLE");
    });

        console.log("--- CRYPTO TEST SUITE COMPLETE ---");
})();
