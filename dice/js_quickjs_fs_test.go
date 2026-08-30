package dice

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"Scardice-core/utils/jsengine"
	quickjsadapter "Scardice-core/utils/jsengine/quickjs"
)

const quickJSFSTestExtension = "QuickJS FS Test"

func runQuickJSFSEntry(t *testing.T, dice *Dice, source string) error {
	t.Helper()
	dice.JsLoadingScript = &JsScriptInfo{Name: quickJSFSTestExtension}
	defer func() { dice.JsLoadingScript = nil }()
	return quickJSNodeTestLoop(t, dice).Run(func(runtime jsengine.Runtime) error {
		_, err := quickjsadapter.LoadModule(runtime, "quickjs-fs-test.mjs", source)
		return err
	})
}

func TestQuickJSFSRespectsDataIsolation(t *testing.T) {
	dice := newQuickJSNodeTestDice(t)
	dice.JsInit()
	dice.JsCurrentPlugin = &ExtInfo{Name: quickJSFSTestExtension}
	t.Cleanup(func() { dice.JsCurrentPlugin = nil })

	if err := runQuickJSFSEntry(t, dice, `
		import { readFile, writeFile } from "node:fs/promises";
		globalThis.quickJSFSAsyncValue = null;
		globalThis.quickJSFSError = null;
		(async () => {
			const path = "data://settings.json";
			const settings = { enabled: true };
			await writeFile(path, JSON.stringify(settings));
			const saved = JSON.parse(await readFile(path, "utf8"));
			globalThis.quickJSFSAsyncValue = String(saved.enabled);
		})().catch(error => { globalThis.quickJSFSError = String(error); });
		export {};
	`); err != nil {
		t.Fatal(err)
	}
	waitForQuickJSFSValue(t, dice, `globalThis.quickJSFSError === null && globalThis.quickJSFSAsyncValue === "true"`)
}

func waitForQuickJSFSValue(t *testing.T, dice *Dice, condition string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var matched bool
		err := quickJSNodeTestLoop(t, dice).Run(func(runtime jsengine.Runtime) error {
			value, err := runtime.RunString("quickjs-fs-check.js", condition)
			if err != nil {
				return err
			}
			matched = value.ToBoolean()
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if matched {
			return
		}
		if time.Now().After(deadline) {
			var diagnostic interface{}
			err := quickJSNodeTestLoop(t, dice).Run(func(runtime jsengine.Runtime) error {
				value, err := runtime.RunString("quickjs-fs-debug.js", `String(globalThis.quickJSFSError)`)
				if err != nil {
					return err
				}
				diagnostic = value.Export()
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Fatalf("QuickJS condition did not become true: %s (error: %v)", condition, diagnostic)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestQuickJSFSRejectsDataSymlinkEscape(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, unrestricted := range []bool{false, true} {
		dice := newQuickJSNodeTestDice(t)
		dice.AdvancedConfig.AllowFilesystemUnrestrictedAccess = unrestricted
		dice.JsInit()
		dataRoot := filepath.Join(dice.BaseConfig.DataDir, "extensions", quickJSFSTestExtension, "data")
		if err := os.MkdirAll(dataRoot, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(dataRoot, "escape")); err != nil {
			t.Fatal(err)
		}

		if err := runQuickJSFSEntry(t, dice, `
			import { readFile } from "fs/promises";
			globalThis.quickJSFSError = null;
			globalThis.quickJSFSSymlinkDenied = false;
			(async () => {
				let denied = false;
				try { await readFile("data://escape/secret.txt", "utf8"); } catch (_) { denied = true; }
				if (!denied) throw new Error("data symlink escape unexpectedly succeeded");
				globalThis.quickJSFSSymlinkDenied = true;
			})().catch(error => { globalThis.quickJSFSError = String(error); });
			export {};
		`); err != nil {
			t.Fatal(err)
		}
		waitForQuickJSFSValue(t, dice, `globalThis.quickJSFSError === null && globalThis.quickJSFSSymlinkDenied`)
	}
}

func TestQuickJSFSRequiresUnrestrictedAccess(t *testing.T) {
	target := filepath.Join(t.TempDir(), "host-path.txt")
	encoded, err := json.Marshal(target)
	if err != nil {
		t.Fatal(err)
	}

	restricted := newQuickJSNodeTestDice(t)
	restricted.JsInit()
	if err := runQuickJSFSEntry(t, restricted, `import { writeFile } from "node:fs/promises";
		globalThis.quickJSFSError = null;
		globalThis.quickJSFSHostPathResult = null;
		(async () => {
			try {
				await writeFile(`+string(encoded)+`, "blocked");
				globalThis.quickJSFSHostPathResult = "allowed";
			} catch (_) {
				globalThis.quickJSFSHostPathResult = "denied";
			}
		})().catch(error => { globalThis.quickJSFSError = String(error); });
		export {};`); err != nil {
		t.Fatal(err)
	}
	waitForQuickJSFSValue(t, restricted, `globalThis.quickJSFSError === null && globalThis.quickJSFSHostPathResult === "denied"`)

	unrestricted := newQuickJSNodeTestDice(t)
	unrestricted.AdvancedConfig.AllowFilesystemUnrestrictedAccess = true
	unrestricted.JsInit()
	if err := runQuickJSFSEntry(t, unrestricted, `import { readFile, writeFile } from "node:fs/promises";
		globalThis.quickJSFSError = null;
		globalThis.quickJSFSHostPathResult = null;
		(async () => {
			await writeFile(`+string(encoded)+`, "host");
			globalThis.quickJSFSHostPathResult = await readFile(`+string(encoded)+`, "utf8");
		})().catch(error => { globalThis.quickJSFSError = String(error); });
		export {};`); err != nil {
		t.Fatal(err)
	}
	waitForQuickJSFSValue(t, unrestricted, `globalThis.quickJSFSError === null && globalThis.quickJSFSHostPathResult === "host"`)
}

func TestQuickJSFSUnrestrictedAccessFollowsHostSymlinks(t *testing.T) {
	target := filepath.Join(t.TempDir(), "target.txt")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	encoded, err := json.Marshal(link)
	if err != nil {
		t.Fatal(err)
	}

	dice := newQuickJSNodeTestDice(t)
	dice.AdvancedConfig.AllowFilesystemUnrestrictedAccess = true
	dice.JsInit()
	if err := runQuickJSFSEntry(t, dice, `import { readFile } from "node:fs/promises";
		globalThis.quickJSFSError = null;
		globalThis.quickJSFSSymlinkValue = null;
		(async () => {
			globalThis.quickJSFSSymlinkValue = await readFile(`+string(encoded)+`, "utf8");
		})().catch(error => { globalThis.quickJSFSError = String(error); });
		export {};`); err != nil {
		t.Fatal(err)
	}
	waitForQuickJSFSValue(t, dice, `globalThis.quickJSFSError === null && globalThis.quickJSFSSymlinkValue === "secret"`)
}
