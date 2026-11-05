//go:build cgo

package native

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"Scardice-core/utils/jsengine"
	"Scardice-core/utils/jsengine/hostbridge"
)

type nativeCallbackLifetimeHost struct {
	Text     string                 `jsbind:"text"`
	Callback func() (string, error) `jsbind:"callback"`
	saved    func() (string, error)
	calls    int
}

type nativeCallbackCapturedHost struct {
	Text string `jsbind:"text"`
}

type nativeCallbackCancellationScope struct {
	*invocationTestContext
}

func (*nativeCallbackCancellationScope) HostWrap(any) (hostbridge.ControlledObject, bool, error) {
	return nil, false, nil
}

func (h *nativeCallbackLifetimeHost) Accept(callback func() (string, error), _ string) {
	h.calls++
	h.saved = callback
}

func (h *nativeCallbackLifetimeHost) Store(callback func() (string, error)) {
	h.saved = callback
}

func (h *nativeCallbackLifetimeHost) StoreAndFail(callback func() (string, error)) error {
	h.saved = callback
	return errors.New("host rejected after accepting callback")
}

func (h *nativeCallbackLifetimeHost) StoreAndPanic(callback func() (string, error)) {
	h.saved = callback
	panic("host panicked after accepting callback")
}

func (h *nativeCallbackLifetimeHost) StoreAndReturnUnsupported(callback func() (string, error)) chan int {
	h.saved = callback
	return make(chan int)
}

func nativeRetainedCallbackCount(loop *nativeLoop) int {
	loop.host.mu.Lock()
	defer loop.host.mu.Unlock()
	return len(loop.host.callbacks)
}

func TestNativeRejectedCallbackConversionReleasesIngressRetains(t *testing.T) {
	for _, test := range []struct {
		name   string
		source string
	}{
		{name: "string field", source: `host.text = callback`},
		{name: "missing field", source: `host.missing = callback`},
		{name: "nonfunction parameter", source: `acceptString(callback)`},
		{name: "too few arguments", source: `host.accept(callback)`},
		{name: "too many arguments", source: `host.accept(callback, "valid", "extra")`},
		{name: "later native conversion", source: `host.accept(callback, {toJSON() { throw new Error("snapshot rejected"); }})`},
		{name: "later typed conversion", source: `host.accept(callback, 7)`},
	} {
		t.Run(test.name, func(t *testing.T) {
			loop := openQuickJSJSONLoop(t).(*nativeLoop)
			host := &nativeCallbackLifetimeHost{Text: "unchanged"}
			if err := loop.Run(func(runtime jsengine.Runtime) error {
				if err := runtime.Set("host", host); err != nil {
					return err
				}
				if err := runtime.Set("acceptString", func(string) { host.calls++ }); err != nil {
					return err
				}
				if err := runtime.Set("makeCaptured", func() *nativeCallbackCapturedHost {
					return &nativeCallbackCapturedHost{Text: "captured"}
				}); err != nil {
					return err
				}
				baselineObjects := loop.host.session.ObjectCount()
				value, err := runtime.RunString("rejected-native-callback.js", `
					(() => {
						let rejected = 0;
						for (let index = 0; index < 16; index++) {
							const captured = makeCaptured();
							const callback = () => captured.text;
							try { `+test.source+`; } catch (_) { rejected++; }
						}
						return rejected;
					})()
				`)
				if err != nil {
					return err
				}
				if got := value.Export(); got != int64(16) {
					return fmt.Errorf("rejected callback operations = %v, want 16", got)
				}
				if got := nativeRetainedCallbackCount(loop); got != 0 {
					return fmt.Errorf("failed conversion retained %d native callbacks before GC, want 0", got)
				}
				if got := loop.host.session.ObjectCount(); got != baselineObjects {
					return fmt.Errorf("failed conversion kept %d host objects alive through native retains, want baseline %d", got, baselineObjects)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if host.Text != "unchanged" || host.calls != 0 || host.saved != nil {
				t.Fatalf("rejected conversion mutated host: text=%q calls=%d callback=%v", host.Text, host.calls, host.saved != nil)
			}
		})
	}
}

func TestNativePartialCallbackSlicePushKeepsOnlyAcceptedPrefix(t *testing.T) {
	loop := openQuickJSJSONLoop(t).(*nativeLoop)
	var callbacks []func() (string, error)
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		if err := runtime.Set("callbacks", &callbacks); err != nil {
			return err
		}
		result, err := runtime.RunString("partial-native-callback-push.js", `
			(() => {
				try {
					callbacks.push(() => "accepted", "not a callback", () => "unaccepted");
					return false;
				} catch (_) { return true; }
			})()
		`)
		if err != nil {
			return err
		}
		if got := result.Export(); got != true {
			return fmt.Errorf("invalid slice push was not rejected: %v", got)
		}
		if got := nativeRetainedCallbackCount(loop); got != 1 {
			return fmt.Errorf("partial slice push retained %d callbacks, want only its accepted prefix", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(callbacks) != 1 {
		t.Fatalf("partial callback slice length = %d, want 1", len(callbacks))
	}
	if got, err := callbacks[0](); err != nil || got != "accepted" {
		t.Fatalf("accepted prefix callback = %q, %v", got, err)
	}
}

func TestNativeAcceptedCallbackResultKeepsItsTransferredLease(t *testing.T) {
	loop := openQuickJSJSONLoop(t).(*nativeLoop)
	var factory func() (func() (string, error), error)
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		if err := runtime.Set("captureFactory", func(callback func() (func() (string, error), error)) {
			factory = callback
		}); err != nil {
			return err
		}
		_, err := runtime.RunString("native-callback-factory.js", `captureFactory(() => () => "transferred result")`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if factory == nil {
		t.Fatal("host did not receive the callback factory")
	}
	callback, err := factory()
	if err != nil {
		t.Fatal(err)
	}
	if callback == nil {
		t.Fatal("callback factory did not return its JavaScript function")
	}
	if got, err := callback(); err != nil || got != "transferred result" {
		t.Fatalf("transferred callback result = %q, %v", got, err)
	}
	if got := nativeRetainedCallbackCount(loop); got != 2 {
		t.Fatalf("factory and transferred result retain %d callbacks, want 2", got)
	}
}

func TestNativeCanceledCallbackReentryDoesNotAcquireAnotherRetain(t *testing.T) {
	loop := openQuickJSJSONLoop(t).(*nativeLoop)
	execution, cancel := context.WithCancel(context.Background())
	defer cancel()
	scope := &nativeCallbackCancellationScope{
		invocationTestContext: &invocationTestContext{Context: execution, id: 105},
	}
	host := &nativeCallbackLifetimeHost{}
	if err := loop.RunWithContext(scope, func(runtime jsengine.Runtime) error {
		if err := runtime.Set("host", host); err != nil {
			return err
		}
		_, err := runtime.RunString("cancel-native-callback.js", `host.store(() => "canceled callback")`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if host.saved == nil {
		t.Fatal("host did not receive the callback")
	}
	cancel()
	if _, err := host.saved(); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled callback error = %v, want context.Canceled", err)
	}
	if got := nativeRetainedCallbackCount(loop); got != 1 {
		t.Fatalf("rejected callback reentry retains %d callbacks, want its one original lease", got)
	}
	if err := loop.Close(); err != nil {
		t.Fatal(err)
	}
	if got := nativeRetainedCallbackCount(loop); got != 0 {
		t.Fatalf("Close retained %d canceled callback leases", got)
	}
}

func TestNativeAcceptedCallbackSurvivesHostFailureAndClosesWithRuntime(t *testing.T) {
	for _, test := range []struct {
		name     string
		source   string
		rejected bool
		field    bool
	}{
		{name: "field", source: `host.callback = () => "still live"`, field: true},
		{name: "call", source: `host.store(() => "still live")`},
		{name: "host error", source: `host.storeAndFail(() => "still live")`, rejected: true},
		{name: "host panic", source: `host.storeAndPanic(() => "still live")`, rejected: true},
		{name: "output conversion", source: `host.storeAndReturnUnsupported(() => "still live")`, rejected: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			loop := openQuickJSJSONLoop(t).(*nativeLoop)
			host := &nativeCallbackLifetimeHost{}
			if err := loop.Run(func(runtime jsengine.Runtime) error {
				if err := runtime.Set("host", host); err != nil {
					return err
				}
				value, err := runtime.RunString("accepted-native-callback.js", `
					(() => {
						try { `+test.source+`; return false; } catch (_) { return true; }
					})()
				`)
				if err != nil {
					return err
				}
				if got := value.Export(); got != test.rejected {
					return fmt.Errorf("host rejected=%v, want %v", got, test.rejected)
				}
				if got := nativeRetainedCallbackCount(loop); got != 1 {
					return fmt.Errorf("accepted callback retains = %d, want 1", got)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			callback := host.saved
			if test.field {
				callback = host.Callback
			}
			if callback == nil {
				t.Fatal("host did not retain its accepted callback")
			}
			if got, err := callback(); err != nil || got != "still live" {
				t.Fatalf("accepted callback = %q, %v; want still live", got, err)
			}
			if err := loop.Close(); err != nil {
				t.Fatal(err)
			}
			if got := nativeRetainedCallbackCount(loop); got != 0 {
				t.Fatalf("closed runtime retained %d callbacks", got)
			}
			if _, err := callback(); !errors.Is(err, ErrNativeClosed) && !errors.Is(err, hostbridge.ErrStaleRuntimeCallback) {
				t.Fatalf("closed callback error = %v, want closed or stale", err)
			}
		})
	}
}

func TestNativeRejectedCallbackResultReleasesIngressRetain(t *testing.T) {
	loop := openQuickJSJSONLoop(t).(*nativeLoop)
	host := &nativeCallbackLifetimeHost{}
	var baselineObjects int
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		if err := runtime.Set("host", host); err != nil {
			return err
		}
		if err := runtime.Set("makeCaptured", func() *nativeCallbackCapturedHost {
			return &nativeCallbackCapturedHost{Text: "captured result"}
		}); err != nil {
			return err
		}
		baselineObjects = loop.host.session.ObjectCount()
		_, err := runtime.RunString("rejected-native-callback-result.js", `
			host.store(() => {
				const captured = makeCaptured();
				return () => captured.text;
			})
		`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if host.saved == nil {
		t.Fatal("host did not receive its callback")
	}
	for range 16 {
		if _, err := host.saved(); err == nil {
			t.Fatal("callback returning a function was accepted as a string")
		}
		if got := nativeRetainedCallbackCount(loop); got != 1 {
			t.Fatalf("rejected callback result retained %d callbacks before GC, want only the accepted callback", got)
		}
		if got := loop.host.session.ObjectCount(); got != baselineObjects {
			t.Fatalf("rejected callback result kept %d host objects alive through native retains, want baseline %d", got, baselineObjects)
		}
	}
}
