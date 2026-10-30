package gojaservices_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/eventloop"
	"github.com/dop251/goja_nodejs/require"

	gojaservices "Scardice-core/utils/jsengine/services/goja"
)

type cryptoLogEntry struct {
	level   string
	message string
}

type cryptoLogPrinter struct {
	entries []cryptoLogEntry
}

func (p *cryptoLogPrinter) Log(message string) {
	p.entries = append(p.entries, cryptoLogEntry{level: "info", message: message})
}

func (p *cryptoLogPrinter) Warn(message string) {
	p.entries = append(p.entries, cryptoLogEntry{level: "warn", message: message})
}

func (p *cryptoLogPrinter) Error(message string) {
	p.entries = append(p.entries, cryptoLogEntry{level: "error", message: message})
}

type cryptoServiceRuntime struct {
	loop    *eventloop.EventLoop
	printer *cryptoLogPrinter
}

func newCryptoServiceRuntime(t *testing.T) *cryptoServiceRuntime {
	t.Helper()
	registry := require.NewRegistry()
	loop := eventloop.NewEventLoop(eventloop.EnableConsole(false), eventloop.WithRegistry(registry))
	printer := &cryptoLogPrinter{}
	installer := gojaservices.NewInstaller(gojaservices.Options{
		Registry: registry,
		Loop:     loop,
		Printer:  printer,
	})
	t.Cleanup(func() {
		if err := installer.Close(); err != nil {
			t.Error(err)
		}
		loop.Terminate()
	})
	if err := installer.Install(); err != nil {
		t.Fatal(err)
	}
	var enableErr error
	loop.Run(func(vm *goja.Runtime) {
		enableErr = installer.Enable(vm)
	})
	if enableErr != nil {
		t.Fatal(enableErr)
	}
	return &cryptoServiceRuntime{loop: loop, printer: printer}
}

func (r *cryptoServiceRuntime) run(t *testing.T, source, script string) any {
	t.Helper()
	var result any
	var runErr error
	r.loop.Run(func(vm *goja.Runtime) {
		value, err := vm.RunScript(source, script)
		if err != nil {
			runErr = err
			return
		}
		promise, ok := value.Export().(*goja.Promise)
		if !ok {
			runErr = fmt.Errorf("crypto script returned %T, want Promise", value.Export())
			return
		}
		if promise.State() != goja.PromiseStateFulfilled {
			runErr = fmt.Errorf("crypto script promise state = %v, result = %s", promise.State(), promise.Result())
			return
		}
		result = promise.Result().Export()
	})
	if runErr != nil {
		t.Fatal(runErr)
	}
	return result
}

func TestCryptoLegacyWarningsAreAttributedAndRuntimeLocal(t *testing.T) {
	first := newCryptoServiceRuntime(t)
	second := newCryptoServiceRuntime(t)
	for _, test := range []struct {
		name    string
		entry   string
		secret  string
		runtime *cryptoServiceRuntime
	}{
		{name: "plugin-a.js", entry: "crypto", secret: "PRIVATE_PAYLOAD_A", runtime: first},
		{name: "plugin-b.js", entry: `require("crypto")`, secret: "PRIVATE_PAYLOAD_B", runtime: second},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := test.runtime.run(t, test.name, fmt.Sprintf(`(async () => {
				const api = %s;
				console.warn = () => { throw new Error("deprecation must not call replaceable JS console.warn"); };
				const pair = await api.subtle.generateKey(
					{name: "RSAES-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1])},
					true, ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
				);
				const input = new TextEncoder().encode(%q);
				const encrypted = await api.subtle.encrypt("RSAES-PKCS1-v1.5", pair.publicKey, input);
				const decrypted = await api.subtle.decrypt("RSAES-PKCS1-v1_5", pair.privateKey, encrypted);
				const aesBytes = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
				const aes = await api.subtle.importKey("raw", aesBytes, "AES-GCM", true, ["encrypt", "decrypt"]);
				const wrapped = await api.subtle.wrapKey("raw", aes, pair.publicKey, "RSAESPKCS1V15");
				const unwrapped = await api.subtle.unwrapKey("raw", wrapped, pair.privateKey,
					"RSAES-PKCS1-v1_5", "AES-GCM", true, ["encrypt", "decrypt"]);
				const restored = new Uint8Array(await api.subtle.exportKey("raw", unwrapped));
				if (!restored.every((value, index) => value === aesBytes[index]) || restored.length !== aesBytes.length) {
					throw new Error("legacy wrapped key changed");
				}
				let rejected = false;
				try { await api.subtle.decrypt("RSAES-PKCS1-v1_5", pair.publicKey, encrypted); }
				catch (_) { rejected = true; }
				if (!rejected) throw new Error("public key accepted for decryption");
				globalThis.legacyPair = pair;
				return new TextDecoder().decode(decrypted);
			})()`, test.entry, test.secret))
			if result != test.secret {
				t.Fatalf("legacy plaintext = %v, want original payload", result)
			}
			operations := []string{"encrypt", "decrypt", "wrapKey", "unwrapKey", "decrypt"}
			if len(test.runtime.printer.entries) != len(operations) {
				t.Fatalf("deprecation log count = %d, want %d WARN entries", len(test.runtime.printer.entries), len(operations))
			}
			for index, operation := range operations {
				entry := test.runtime.printer.entries[index]
				if entry.level != "warn" {
					t.Errorf("log level = %s, want warn", entry.level)
				}
				for _, field := range []string{"crypto.subtle." + operation, "RSAES-PKCS1-v1_5", "RSA-OAEP", "SHA-256", test.name} {
					if !strings.Contains(entry.message, field) {
						t.Errorf("deprecation log missing %q: %s", field, entry.message)
					}
				}
				if strings.Contains(entry.message, test.secret) {
					t.Error("deprecation log disclosed plaintext")
				}
			}
		})
	}
	first.run(t, "another-plugin.js", `(async () => {
		const input = new TextEncoder().encode("second invocation");
		const encrypted = await crypto.subtle.encrypt("RSAES-PKCS1-v1_5", legacyPair.publicKey, input);
		return new TextDecoder().decode(await crypto.subtle.decrypt("RSAES-PKCS1-v1_5", legacyPair.privateKey, encrypted));
	})()`)
	if len(first.printer.entries) != 7 || len(second.printer.entries) != 5 {
		t.Fatalf("runtime-local warning counts = %d, %d; want 7, 5", len(first.printer.entries), len(second.printer.entries))
	}
	for _, entry := range first.printer.entries[5:] {
		if !strings.Contains(entry.message, "another-plugin.js") {
			t.Errorf("later plugin was attributed to the wrong source: %s", entry.message)
		}
	}
}

func TestCryptoOAEPInteroperatesWithSHA256WithoutDeprecation(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &privateKey.PublicKey, []byte("from Go\x00中文"), nil)
	if err != nil {
		t.Fatal(err)
	}
	runtime := newCryptoServiceRuntime(t)
	result := runtime.run(t, "modern-plugin.js", fmt.Sprintf(`(async () => {
		const algorithm = {name: "RSA-OAEP", hash: "SHA-256"};
		const publicKey = await crypto.subtle.importKey("spki", Buffer.from(%q, "hex"), algorithm, false, ["encrypt"]);
		const privateKey = await crypto.subtle.importKey("pkcs8", Buffer.from(%q, "hex"), algorithm, false, ["decrypt"]);
		const decrypted = await crypto.subtle.decrypt("RSA-OAEP", privateKey, Buffer.from(%q, "hex"));
		if (new TextDecoder().decode(decrypted) !== "from Go\u0000中文") throw new Error("Go OAEP ciphertext did not decrypt");
		const encrypted = await crypto.subtle.encrypt("RSA-OAEP", publicKey, new TextEncoder().encode("from JS\u0000中文"));
		return Buffer.from(encrypted).toString("hex");
	})()`, hex.EncodeToString(publicKey), hex.EncodeToString(pkcs8), hex.EncodeToString(ciphertext)))
	encoded, ok := result.(string)
	if !ok {
		t.Fatalf("OAEP result type = %T, want string", result)
	}
	fromJS, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, fromJS, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "from JS\x00中文" {
		t.Fatal("JS OAEP ciphertext did not preserve the expected plaintext")
	}
	if len(runtime.printer.entries) != 0 {
		t.Fatalf("modern OAEP API emitted unexpected logs: %v", runtime.printer.entries)
	}
}
