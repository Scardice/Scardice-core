//go:build cgo

package native

import (
	"errors"
	"fmt"
	"reflect"
	goruntime "runtime"
	"testing"
	"time"

	"Scardice-core/utils/jsengine"
)

type nativeAnonymousFunctionHost struct {
	Callback func() string `jsbind:"callback"`
}

func TestNativeDroppedAnonymousHostFunctionsReleaseTheirOwners(t *testing.T) {
	loop := openQuickJSJSONLoop(t).(*nativeLoop)
	var baselineFunctions, baselineObjects int
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		if err := runtime.Set("host", &nativeAnonymousFunctionHost{Callback: func() string { return "field" }}); err != nil {
			return err
		}
		if err := runtime.Set("factory", func() func() string {
			return func() string { return "returned" }
		}); err != nil {
			return err
		}
		baselineFunctions = loop.host.session.FunctionCount()
		baselineObjects = loop.host.session.ObjectCount()
		_, err := runtime.RunString("drop-anonymous-host-functions.js", `
			for (let index = 0; index < 32; index++) {
				void host.callback;
				void factory();
			}
		`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// A second owner entry is after the prior native value scope has released
	// its handles, so QuickJS's real function/owner finalizers have run.
	if err := loop.Run(func(jsengine.Runtime) error {
		if got := loop.host.session.FunctionCount(); got != baselineFunctions {
			return fmt.Errorf("dropped anonymous functions left %d HostFuncRefs, want baseline %d", got, baselineFunctions)
		}
		if got := loop.host.session.ObjectCount(); got != baselineObjects {
			return fmt.Errorf("dropped anonymous functions left %d HostRefs, want baseline %d", got, baselineObjects)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestNativeDroppedDangerousFunctionFieldsReleaseTheirOwners(t *testing.T) {
	loop := openQuickJSJSONLoop(t).(*nativeLoop)
	var baselineFunctions, baselineObjects int
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		value, err := runtime.(jsengine.DangerousExposer).ExposeDangerous(&nativeAnonymousFunctionHost{
			Callback: func() string { return "dangerous field" },
		})
		if err != nil {
			return err
		}
		if err := runtime.Set("dangerous", value); err != nil {
			return err
		}
		baselineFunctions = loop.host.session.FunctionCount()
		baselineObjects = loop.host.session.ObjectCount()
		_, err = runtime.RunString("drop-dangerous-function-fields.js", `
			for (let index = 0; index < 16; index++) void dangerous.Callback;
		`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if got := loop.host.session.FunctionCount(); got != baselineFunctions {
		t.Fatalf("dropped dangerous functions left %d HostFuncRefs, want baseline %d", got, baselineFunctions)
	}
	if got := loop.host.session.ObjectCount(); got != baselineObjects {
		t.Fatalf("dropped dangerous functions left %d HostRefs, want baseline %d", got, baselineObjects)
	}
}

func TestNativeReplacedGlobalHostFunctionsReleaseTheirOwners(t *testing.T) {
	loop := openQuickJSJSONLoop(t).(*nativeLoop)
	baselineFunctions := loop.host.session.FunctionCount()
	baselineObjects := loop.host.session.ObjectCount()
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		for range 32 {
			if err := runtime.Set("temporary", func() string { return "temporary" }); err != nil {
				return err
			}
			if err := runtime.Set("temporary", nil); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := loop.host.session.FunctionCount(); got != baselineFunctions {
		t.Fatalf("replaced globals retained %d HostFuncRefs, want baseline %d", got, baselineFunctions)
	}
	if got := loop.host.session.ObjectCount(); got != baselineObjects {
		t.Fatalf("replaced globals retained %d function owner HostRefs, want baseline %d", got, baselineObjects)
	}
}

func TestNativeDetachedFunctionKeepsSnapshotWithoutKeepingParentProxy(t *testing.T) {
	loop := openQuickJSJSONLoop(t).(*nativeLoop)
	baselineFunctions := loop.host.session.FunctionCount()
	baselineObjects := loop.host.session.ObjectCount()
	host := &nativeAnonymousFunctionHost{Callback: func() string { return "original" }}
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		if err := runtime.Set("host", host); err != nil {
			return err
		}
		result, err := runtime.RunString("detach-host-function.js", `
			globalThis.detached = host.callback;
			host.callback = null;
			globalThis.host = null;
			detached();
		`)
		if err != nil {
			return err
		}
		if got := result.Export(); got != "original" {
			return fmt.Errorf("detached function = %v, want original", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if host.Callback != nil {
		t.Fatal("clearing the function property did not update its Go field")
	}
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		result, err := runtime.RunString("call-detached-host-function.js", `detached()`)
		if err != nil {
			return err
		}
		if got := result.Export(); got != "original" {
			return fmt.Errorf("detached snapshot after dropping parent = %v, want original", got)
		}
		_, err = runtime.RunString("release-detached-host-function.js", `globalThis.detached = null`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if got := loop.host.session.FunctionCount(); got != baselineFunctions {
		t.Fatalf("dropped detached function retained %d HostFuncRefs, want baseline %d", got, baselineFunctions)
	}
	if got := loop.host.session.ObjectCount(); got != baselineObjects {
		t.Fatalf("dropped parent and detached function retained %d HostRefs, want baseline %d", got, baselineObjects)
	}
}

func TestNativeAnonymousFunctionConstructionFailureRollsBackRegistration(t *testing.T) {
	loop := openQuickJSJSONLoop(t).(*nativeLoop)
	if err := loop.Run(func(jsengine.Runtime) error {
		functions := loop.host.session.FunctionCount()
		objects := loop.host.session.ObjectCount()
		value, err := loop.host.reflectValue(reflect.ValueOf(func() string { return "unpublished" }), nil)
		if err != nil {
			return err
		}
		// Runtime 0 is rejected by the real QuickJS ABI constructor before it
		// can create an owner proxy; the Go registration must be rolled back.
		if _, err := loop.host.encodeValue(0, value); err == nil {
			return errors.New("native constructor accepted runtime 0")
		}
		if got := loop.host.session.FunctionCount(); got != functions {
			return fmt.Errorf("failed native constructor retained %d HostFuncRefs, want %d", got, functions)
		}
		if got := loop.host.session.ObjectCount(); got != objects {
			return fmt.Errorf("failed native constructor retained %d HostRefs, want %d", got, objects)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestNativeDroppedFunctionGetterReleasesOriginalCallbackLease(t *testing.T) {
	loop := openQuickJSJSONLoop(t).(*nativeLoop)
	host := &nativeCallbackLifetimeHost{}
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		if err := runtime.Set("host", host); err != nil {
			return err
		}
		_, err := runtime.RunString("release-callback-getter.js", `
			host.callback = () => "lease";
			for (let index = 0; index < 16; index++) void host.callback;
			host.callback = null;
			globalThis.host = null;
		`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if host.Callback != nil {
		t.Fatal("callback field retained its function after null assignment")
	}
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for nativeRetainedCallbackCount(loop) != 0 {
		goruntime.GC()
		if err := loop.Run(func(jsengine.Runtime) error { return nil }); err != nil {
			t.Fatal(err)
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatalf("dropped getter functions keep %d native callback leases reachable", nativeRetainedCallbackCount(loop))
		}
	}
}

func TestNativeStaleRuntimeSetDoesNotRegisterHostFunction(t *testing.T) {
	loop := openQuickJSJSONLoop(t).(*nativeLoop)
	var stale jsengine.Runtime
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		stale = runtime
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := loop.Run(func(jsengine.Runtime) error {
		functions := loop.host.session.FunctionCount()
		objects := loop.host.session.ObjectCount()
		if err := stale.Set("unpublished", func() string { return "stale" }); err == nil {
			return errors.New("stale Runtime.Set accepted a function binding")
		}
		if got := loop.host.session.FunctionCount(); got != functions {
			return fmt.Errorf("rejected stale Runtime.Set registered %d HostFuncRefs, want %d", got, functions)
		}
		if got := loop.host.session.ObjectCount(); got != objects {
			return fmt.Errorf("rejected stale Runtime.Set registered %d HostRefs, want %d", got, objects)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
