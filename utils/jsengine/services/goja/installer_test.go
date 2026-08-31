package gojaservices_test

import (
	"net/http"
	"testing"

	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/eventloop"
	"github.com/dop251/goja_nodejs/require"

	"Scardice-core/utils/jsengine/services"
	gojaservices "Scardice-core/utils/jsengine/services/goja"
)

func TestInstallerPreservesCoreGojaServiceBehavior(t *testing.T) {
	loop := eventloop.NewEventLoop(eventloop.EnableConsole(false))
	defer loop.Terminate()
	moduleRegistry := require.NewRegistry()
	installer := gojaservices.NewInstaller(gojaservices.Options{
		Registry: moduleRegistry,
		Loop:     loop,
		Proxy:    http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		Filesystem: gojaservices.FilesystemHooks{
			Require: func(*goja.Runtime, *goja.Object) {},
			Enable:  func(*goja.Runtime) {},
		},
	})
	registry := services.NewRegistry()
	installation, err := registry.Install(installer)
	if err != nil {
		t.Fatalf("registry.Install() error = %v", err)
	}
	defer installation.Close()

	var runErr error
	loop.Run(func(vm *goja.Runtime) {
		runErr = installer.Enable(vm)
		if runErr != nil {
			return
		}
		_, runErr = vm.RunString(`
			const controller = new AbortController();
			let aborted = false;
			controller.signal.addEventListener("abort", () => { aborted = true; });
			controller.abort("stop");
			const cloned = structuredClone({ answer: 42, nested: [true] });
			const inspected = util.inspect({ answer: 42 });
			const required = require("@seal/structuredclone");
			globalThis.__serviceResult = [aborted, cloned.answer, cloned.nested[0], inspected, typeof required.structuredClone];
		`)
	})
	if runErr != nil {
		t.Fatalf("Goja service script error = %v", runErr)
	}
	loop.Run(func(vm *goja.Runtime) {
		value := vm.Get("__serviceResult").Export()
		result, ok := value.([]interface{})
		if !ok || len(result) != 5 {
			t.Fatalf("service result = %#v", value)
		}
		if result[0] != true || result[1] != int64(42) || result[2] != true || result[4] != "function" {
			t.Fatalf("service result = %#v", result)
		}
		if result[3] == "" {
			t.Fatal("util.inspect returned an empty string")
		}
	})

	for _, name := range []services.Name{
		services.Console, services.Crypto, services.Fetch, services.HTTP,
		services.WebSocket, services.Filesystem, services.Abort, services.StructuredClone, services.UtilInspect,
	} {
		if _, err := registry.Lookup(name); err != nil {
			t.Fatalf("Lookup(%q) error = %v", name, err)
		}
	}
}
