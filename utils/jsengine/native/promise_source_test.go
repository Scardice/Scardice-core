//go:build cgo

package native

import (
	"strings"
	"testing"

	"github.com/dop251/goja"
)

// Exercise the provider-independent observer program with a real JavaScript VM.
// Native ABI/service-event scope coverage remains in the native loop tests.
func TestNativePromiseProgramUsesIntrinsicAndAlwaysReportsRejection(t *testing.T) {
	vm := goja.New()
	type completion struct {
		token    int64
		rejected bool
		result   string
	}
	var (
		completed   []completion
		getValue    goja.Callable
		callbackErr error
	)
	if err := vm.Set("__scardicePromiseSettled", func(token int64, rejected bool, reason string) {
		if !rejected {
			value, err := getValue(goja.Undefined())
			if err != nil {
				callbackErr = err
				return
			}
			reason = value.String()
		}
		completed = append(completed, completion{token, rejected, reason})
	}); err != nil {
		t.Fatal(err)
	}
	helperValue, err := vm.RunString(nativePromiseObserverSource)
	if err != nil {
		t.Fatal(err)
	}
	helpers := helperValue.ToObject(vm)
	observe, ok := goja.AssertFunction(helpers.Get("observe"))
	if !ok {
		t.Fatal("observer program did not return an observe function")
	}
	getValue, ok = goja.AssertFunction(helpers.Get("getValue"))
	if !ok {
		t.Fatal("observer program did not return a fulfillment getter")
	}
	for _, name := range []string{
		"__scardicePromiseSettled",
		"__scardicePromiseIs",
		"__scardicePromiseObserve",
		"__scardicePromiseValue",
	} {
		if value := vm.Get(name); value != nil && !goja.IsUndefined(value) {
			t.Fatalf("observer helper %q remained globally reachable", name)
		}
	}
	observePromise := func(value goja.Value, token int64) (bool, error) {
		result, err := observe(goja.Undefined(), value, vm.ToValue(token))
		if err != nil {
			return false, err
		}
		return result.ToBoolean(), nil
	}

	ordinaryValue, err := vm.RunString(`(() => {
		const state = { calls: 0 };
		state.value = { get then() { state.calls++; throw Error("unrelated getter"); } };
		return state;
	})()`)
	if err != nil {
		t.Fatal(err)
	}
	ordinary := ordinaryValue.ToObject(vm)
	observed, err := observePromise(ordinary.Get("value"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if observed {
		t.Fatal("ordinary object was recognized as a Promise")
	}
	if calls := ordinary.Get("calls").ToInteger(); calls != 0 {
		t.Fatalf("ordinary .then getter calls = %d, want 0", calls)
	}

	pendingValue, err := vm.RunString(`(() => {
		let resolve;
		const promise = new Promise(done => { resolve = done; });
		promise.then = () => { throw Error("poisoned instance then"); };
		return { promise, resolve };
	})()`)
	if err != nil {
		t.Fatal(err)
	}
	pending := pendingValue.ToObject(vm)
	observed, err = observePromise(pending.Get("promise"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !observed {
		t.Fatal("Promise with poisoned instance .then was not recognized")
	}
	resolve, ok := goja.AssertFunction(pending.Get("resolve"))
	if !ok {
		t.Fatal("pending Promise resolver is not callable")
	}
	if _, err := resolve(goja.Undefined(), vm.ToValue("actual")); err != nil {
		t.Fatal(err)
	}

	prototypeNull, err := vm.RunString(`(() => {
		const promise = Promise.resolve("prototype-null");
		Object.setPrototypeOf(promise, null);
		return promise;
	})()`)
	if err != nil {
		t.Fatal(err)
	}
	observed, err = observePromise(prototypeNull, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !observed {
		t.Fatal("Promise with a null prototype was not recognized")
	}

	speciesFailure, err := vm.RunString(`(() => {
		const promise = Promise.resolve("unused");
		Object.defineProperty(promise, "constructor", {
			get() { throw new TypeError("species exploded"); }
		});
		return promise;
	})()`)
	if err != nil {
		t.Fatal(err)
	}
	observed, err = observePromise(speciesFailure, 3)
	if err == nil || !strings.Contains(err.Error(), "species exploded") {
		t.Fatalf("constructor failure = (%v, %v), want propagated TypeError", observed, err)
	}

	unprintable, err := vm.RunString(`Promise.reject({
		toString() { throw Error("unprintable"); }
	})`)
	if err != nil {
		t.Fatal(err)
	}
	observed, err = observePromise(unprintable, 4)
	if err != nil {
		t.Fatal(err)
	}
	if !observed {
		t.Fatal("rejected Promise was not recognized")
	}
	if callbackErr != nil {
		t.Fatal(callbackErr)
	}
	if len(completed) != 3 {
		t.Fatalf("completed = %#v, want two fulfillments and one rejection", completed)
	}
	if completed[0] != (completion{token: 1, result: "actual"}) {
		t.Fatalf("fulfilled value = %#v, want intrinsic Promise result", completed[0])
	}
	if completed[1] != (completion{token: 2, result: "prototype-null"}) {
		t.Fatalf("prototype-null fulfillment = %#v", completed[1])
	}
	if completed[2].token != 4 || !completed[2].rejected || completed[2].result == "" {
		t.Fatalf("unprintable rejection was lost: %#v", completed[2])
	}
	value, err := getValue(goja.Undefined())
	if err != nil {
		t.Fatal(err)
	}
	if !goja.IsUndefined(value) {
		t.Fatal("observer retained the last fulfillment value after delivery")
	}
}
