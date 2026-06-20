package dice

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/eventloop"
)

func newTestFsDice(t *testing.T) *Dice {
	t.Helper()
	return &Dice{
		BaseConfig: BaseConfig{DataDir: t.TempDir()},
		JsCurrentPlugin: &ExtInfo{
			Name: "fsTest",
		},
	}
}

func TestJsFsResolveDataPathRejectsTraversalAndPlatformAmbiguity(t *testing.T) {
	d := newTestFsDice(t)
	badPaths := []string{
		"data://..",
		"data://../example.json",
		"data://a/../../example.json",
		"data:///etc/passwd",
		"data://C:/Windows/win.ini",
		"data://c:/Windows/win.ini",
		"data://..\\example.json",
		"data://C:\\Windows\\win.ini",
	}
	for _, path := range badPaths {
		if _, err := jsFsResolveAbsolute(d, path); err == nil {
			t.Fatalf("expected %q to be rejected", path)
		}
	}
}

func TestJsFsResolveDataPathStaysInsideBase(t *testing.T) {
	d := newTestFsDice(t)
	resolved, err := jsFsResolveAbsolute(d, "data://nested/example.json")
	if err != nil {
		t.Fatalf("resolve data path: %v", err)
	}
	base := filepath.Join(d.BaseConfig.DataDir, "extensions", "fsTest", "data")
	if err := jsFsEnsureInsideBase(resolved.base, resolved.abs); err != nil {
		t.Fatalf("resolved path should stay inside base: %v", err)
	}
	if resolved.base != filepath.Clean(base) && resolved.base != mustAbs(t, base) {
		t.Fatalf("unexpected resolved base: %s", resolved.base)
	}
}

func TestJsFsDataPathRejectsSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated permissions on some Windows hosts")
	}
	d := newTestFsDice(t)
	base := filepath.Join(d.BaseConfig.DataDir, "extensions", "fsTest", "data")
	outside := t.TempDir()
	if err := os.MkdirAll(base, 0755); err != nil {
		t.Fatalf("create data base: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("secret"), 0644); err != nil {
		t.Fatalf("create outside file: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(base, "link")); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	readTarget, resolveErr := jsFsResolveAbsolute(d, "data://link/secret.txt")
	if resolveErr != nil {
		t.Fatalf("lexical resolve should pass before symlink validation: %v", resolveErr)
	}
	if err := jsFsEnsureExistingDataTargetInside(readTarget); err == nil {
		t.Fatal("expected symlinked read target outside data base to be rejected")
	}

	writeTarget, err := jsFsResolveAbsolute(d, "data://link/new.txt")
	if err != nil {
		t.Fatalf("lexical resolve should pass before parent symlink validation: %v", err)
	}
	if err := jsFsEnsureDataParentInside(writeTarget); err == nil {
		t.Fatal("expected symlinked write parent outside data base to be rejected")
	}
}

func TestJsFsAsyncDataPathOperations(t *testing.T) {
	d := newTestFsDice(t)
	loop := startFsTestLoop(t)
	runFsLoopSync(t, loop, func(vm *goja.Runtime) {
		jsFsEnable(vm, d, loop)
		_, err := vm.RunString(`
			globalThis.__fsDone = false;
			globalThis.__fsErr = "";
			(async () => {
				await fs.promises.mkdir("data://async/nested");
				await fs.promises.writeFile("data://async/nested/file.txt", "hello");
				const bytes = await fs.readFileAsync("data://async/nested/file.txt");
				const entries = await fs.promises.readDir("data://async/nested");
				const stat = await fs.statAsync("data://async/nested/file.txt");
				await fs.removeAsync("data://async/nested/file.txt");
				globalThis.__fsResult = [bytes.byteLength, new Uint8Array(bytes)[0], entries[0].name, stat.isDir, stat.size].join("|");
				globalThis.__fsDone = true;
			})().catch((err) => {
				globalThis.__fsErr = String(err);
				globalThis.__fsDone = true;
			});
		`)
		if err != nil {
			t.Fatalf("run async fs script: %v", err)
		}
	})
	waitFsLoopBool(t, loop, "__fsDone")
	result := fsLoopString(t, loop, "__fsResult")
	if errText := fsLoopString(t, loop, "__fsErr"); errText != "" {
		t.Fatalf("async fs script failed: %s", errText)
	}
	if result != "5|104|file.txt|false|5" {
		t.Fatalf("unexpected async fs result: %s", result)
	}
}

func TestJsFsAsyncRejectsUnsafePaths(t *testing.T) {
	d := newTestFsDice(t)
	loop := startFsTestLoop(t)
	runFsLoopSync(t, loop, func(vm *goja.Runtime) {
		jsFsEnable(vm, d, loop)
		_, err := vm.RunString(`
			globalThis.__fsDone = false;
			globalThis.__fsErr = "";
			globalThis.__fsRejected = 0;
			(async () => {
				for (const path of ["data://../secret.txt", "deck/example.json"]) {
					try {
						await fs.promises.readFile(path);
					} catch (_) {
						globalThis.__fsRejected++;
					}
				}
				globalThis.__fsDone = true;
			})().catch((err) => {
				globalThis.__fsErr = String(err);
				globalThis.__fsDone = true;
			});
		`)
		if err != nil {
			t.Fatalf("run async rejection script: %v", err)
		}
	})
	waitFsLoopBool(t, loop, "__fsDone")
	if errText := fsLoopString(t, loop, "__fsErr"); errText != "" {
		t.Fatalf("async rejection script failed: %s", errText)
	}
	if got := fsLoopInt(t, loop, "__fsRejected"); got != 2 {
		t.Fatalf("expected 2 rejected unsafe async paths, got %d", got)
	}
}

func TestJsFsAsyncDataPathRejectsSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated permissions on some Windows hosts")
	}
	d := newTestFsDice(t)
	base := filepath.Join(d.BaseConfig.DataDir, "extensions", "fsTest", "data")
	outside := t.TempDir()
	if err := os.MkdirAll(base, 0755); err != nil {
		t.Fatalf("create data base: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("secret"), 0644); err != nil {
		t.Fatalf("create outside file: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(base, "link")); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	loop := startFsTestLoop(t)
	runFsLoopSync(t, loop, func(vm *goja.Runtime) {
		jsFsEnable(vm, d, loop)
		_, err := vm.RunString(`
			globalThis.__fsDone = false;
			globalThis.__fsErr = "";
			globalThis.__fsRejected = false;
			(async () => {
				try {
					await fs.readFileAsync("data://link/secret.txt");
				} catch (_) {
					globalThis.__fsRejected = true;
				}
				globalThis.__fsDone = true;
			})().catch((err) => {
				globalThis.__fsErr = String(err);
				globalThis.__fsDone = true;
			});
		`)
		if err != nil {
			t.Fatalf("run async symlink script: %v", err)
		}
	})
	waitFsLoopBool(t, loop, "__fsDone")
	if errText := fsLoopString(t, loop, "__fsErr"); errText != "" {
		t.Fatalf("async symlink script failed: %s", errText)
	}
	if !fsLoopBool(t, loop, "__fsRejected") {
		t.Fatal("expected symlinked async read outside data base to be rejected")
	}
}

func TestJsFsAsyncUnrestrictedAbsolutePath(t *testing.T) {
	d := newTestFsDice(t)
	d.AdvancedConfig.AllowFilesystemUnrestrictedAccess = true
	target := filepath.Join(t.TempDir(), "async-unrestricted.txt")
	loop := startFsTestLoop(t)
	runFsLoopSync(t, loop, func(vm *goja.Runtime) {
		jsFsEnable(vm, d, loop)
		_ = vm.Set("__fsTarget", target)
		_, err := vm.RunString(`
			globalThis.__fsDone = false;
			globalThis.__fsErr = "";
			(async () => {
				await fs.promises.writeFile(globalThis.__fsTarget, "open-path");
				const bytes = await fs.promises.readFile(globalThis.__fsTarget);
				const stat = await fs.promises.stat(globalThis.__fsTarget);
				globalThis.__fsResult = [String.fromCharCode(...new Uint8Array(bytes)), stat.size, stat.isDir].join("|");
				globalThis.__fsDone = true;
			})().catch((err) => {
				globalThis.__fsErr = String(err);
				globalThis.__fsDone = true;
			});
		`)
		if err != nil {
			t.Fatalf("run unrestricted async fs script: %v", err)
		}
	})
	waitFsLoopBool(t, loop, "__fsDone")
	if errText := fsLoopString(t, loop, "__fsErr"); errText != "" {
		t.Fatalf("unrestricted async fs script failed: %s", errText)
	}
	if result := fsLoopString(t, loop, "__fsResult"); result != "open-path|9|false" {
		t.Fatalf("unexpected unrestricted async result: %s", result)
	}
}

func TestJsFsConcurrentAsyncOperations(t *testing.T) {
	d := newTestFsDice(t)
	loop := startFsTestLoop(t)
	runFsLoopSync(t, loop, func(vm *goja.Runtime) {
		jsFsEnable(vm, d, loop)
		_, err := vm.RunString(`
			globalThis.__fsDone = false;
			globalThis.__fsErr = "";
			(async () => {
				await fs.promises.mkdir("data://concurrent");
				const writes = [];
				for (let i = 0; i < 20; i++) {
					writes.push(fs.writeFileAsync("data://concurrent/" + i + ".txt", String(i)));
				}
				await Promise.all(writes);
				const reads = [];
				for (let i = 0; i < 20; i++) {
					reads.push(fs.readFileAsync("data://concurrent/" + i + ".txt").then((bytes) => String.fromCharCode(...new Uint8Array(bytes))));
				}
				globalThis.__fsResult = (await Promise.all(reads)).join(",");
				globalThis.__fsDone = true;
			})().catch((err) => {
				globalThis.__fsErr = String(err);
				globalThis.__fsDone = true;
			});
		`)
		if err != nil {
			t.Fatalf("run concurrent async fs script: %v", err)
		}
	})
	waitFsLoopBool(t, loop, "__fsDone")
	if errText := fsLoopString(t, loop, "__fsErr"); errText != "" {
		t.Fatalf("concurrent async fs script failed: %s", errText)
	}
	want := "0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19"
	if result := fsLoopString(t, loop, "__fsResult"); result != want {
		t.Fatalf("unexpected concurrent async result: %s", result)
	}
}

func startFsTestLoop(t *testing.T) *eventloop.EventLoop {
	t.Helper()
	loop := eventloop.NewEventLoop(eventloop.EnableConsole(false))
	go loop.StartInForeground()
	runFsLoopSync(t, loop, func(_ *goja.Runtime) {})
	t.Cleanup(func() {
		loop.Stop()
	})
	return loop
}

func runFsLoopSync(t *testing.T, loop *eventloop.EventLoop, f func(*goja.Runtime)) {
	t.Helper()
	done := make(chan struct{})
	var recovered interface{}
	loop.RunOnLoop(func(vm *goja.Runtime) {
		defer close(done)
		defer func() {
			recovered = recover()
		}()
		f(vm)
	})
	<-done
	if recovered != nil {
		t.Fatalf("panic in JS event loop test callback: %v", recovered)
	}
}

func waitFsLoopBool(t *testing.T, loop *eventloop.EventLoop, name string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if fsLoopBool(t, loop, name) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", name)
}

func fsLoopBool(t *testing.T, loop *eventloop.EventLoop, name string) bool {
	t.Helper()
	var result bool
	runFsLoopSync(t, loop, func(vm *goja.Runtime) {
		value := vm.Get(name)
		if value == nil || goja.IsUndefined(value) || goja.IsNull(value) {
			return
		}
		result = value.ToBoolean()
	})
	return result
}

func fsLoopString(t *testing.T, loop *eventloop.EventLoop, name string) string {
	t.Helper()
	var result string
	runFsLoopSync(t, loop, func(vm *goja.Runtime) {
		value := vm.Get(name)
		if value == nil || goja.IsUndefined(value) || goja.IsNull(value) {
			return
		}
		result = value.String()
	})
	return result
}

func fsLoopInt(t *testing.T, loop *eventloop.EventLoop, name string) int64 {
	t.Helper()
	var result int64
	runFsLoopSync(t, loop, func(vm *goja.Runtime) {
		value := vm.Get(name)
		if value == nil || goja.IsUndefined(value) || goja.IsNull(value) {
			return
		}
		result = value.ToInteger()
	})
	return result
}

func mustAbs(t *testing.T, path string) string {
	t.Helper()
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("abs %s: %v", path, err)
	}
	return abs
}
