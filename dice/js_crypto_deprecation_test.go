package dice

import (
	"fmt"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"Scardice-core/utils/jsengine"
)

func TestJSRuntimeCryptoWarningsFollowCallingScript(t *testing.T) {
	logCore, logs := observer.New(zapcore.WarnLevel)
	d := &Dice{Logger: zap.New(logCore).Sugar()}
	provider := &diceGojaProvider{dice: d}
	loop, err := provider.Open(t.Context(), jsengine.RuntimeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer loop.Close()

	for _, test := range []struct {
		name  string
		entry string
	}{
		{name: "crypto-first", entry: "crypto"},
		{name: "crypto-second", entry: `require("crypto")`},
		{name: "crypto-first", entry: "crypto"},
	} {
		t.Run(test.name, func(t *testing.T) {
			script := &JsScriptInfo{Name: test.name, Filename: "/plugins/" + test.name + ".js"}
			execution := &jsExecutionContext{Script: script}
			source := fmt.Sprintf(`
				const api = %s;
				const keys = api.subtle.generateKey(
					{name: "RSAES-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1])},
					false, ["encrypt", "decrypt"]
				);
				globalThis[%q] = async () => {
					const pair = await keys;
					const message = new TextEncoder().encode("PRIVATE_PLUGIN_PAYLOAD");
					const encrypted = await api.subtle.encrypt("RSAES-PKCS1-v1_5", pair.publicKey, message);
					const decrypted = await api.subtle.decrypt("RSAES-PKCS1-v1_5", pair.privateKey, encrypted);
					return new TextDecoder().decode(decrypted);
				};
			`, test.entry, test.name)
			if err := jsengine.LoadEntryWithContext(loop, execution, jsengine.Entry{
				Filename: script.Filename, Source: source, Kind: jsengine.EntryExtension,
			}); err != nil {
				t.Fatal(err)
			}
			logs.TakeAll()
			var plaintext any
			if err := jsengine.RunWithContext(loop, execution, func(runtime jsengine.Runtime) error {
				_, runErr := runtime.RunString("invoke-plugin.js", fmt.Sprintf(`
					globalThis.cryptoDeprecationResult = undefined;
					globalThis[%q]().then(
						value => { globalThis.cryptoDeprecationResult = value; },
						error => { globalThis.cryptoDeprecationResult = "failure: " + error.message; }
					);
				`, test.name))
				if runErr != nil {
					return runErr
				}
				plaintext = runtime.Get("cryptoDeprecationResult").Export()
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if plaintext != "PRIVATE_PLUGIN_PAYLOAD" {
				t.Fatalf("plugin crypto result = %v, want unchanged plaintext", plaintext)
			}
			entries := logs.FilterMessageSnippet("RSAES-PKCS1-v1_5").All()
			if len(entries) != 2 {
				t.Fatalf("crypto warning count = %d, want 2", len(entries))
			}
			for _, entry := range entries {
				if entry.Level != zapcore.WarnLevel || !strings.Contains(entry.Message, script.Name) || !strings.Contains(entry.Message, script.Filename) {
					t.Errorf("warning lost current plugin identity: level=%v message=%s", entry.Level, entry.Message)
				}
				if strings.Contains(entry.Message, "PRIVATE_PLUGIN_PAYLOAD") {
					t.Error("warning disclosed plugin plaintext")
				}
			}
		})
	}
}
