package goja

import (
	goruntime "runtime"
	"testing"
	"time"
	"weak"

	"Scardice-core/utils/jsengine"
)

func TestPromiseObservationDoesNotEvaluateOrdinaryResultGetters(t *testing.T) {
	loop := New()
	defer loop.Close()
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		result, err := runtime.RunString("plain-hook-result.js", `
			var unrelatedGetterCalls = 0;
			({ matched: true, solved: true, get unrelated() { unrelatedGetterCalls++; return "unused"; } });
		`)
		if err != nil {
			return err
		}
		observed, err := jsengine.ObservePromise(runtime, result, func(jsengine.Value, error) {
			t.Error("ordinary result was treated as an asynchronously settled Promise")
		})
		if err != nil {
			return err
		}
		if observed {
			t.Error("ordinary result was treated as a Promise")
		}
		if got := runtime.Get("unrelatedGetterCalls").Export(); got != int64(0) {
			t.Errorf("Promise detection evaluated an unrelated getter %v times", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPromiseObservationUsesIntrinsicAndOriginContext(t *testing.T) {
	loop := New()
	defer loop.Close()
	origin := newAwaitOwnershipScope(t, "origin")
	resolver := newAwaitOwnershipScope(t, "resolver")
	var actual string
	constructorObserved := false
	if err := jsengine.RunWithContext(loop, origin, func(runtime jsengine.Runtime) error {
		if err := runtime.Bind("inspectConstructor", func() {
			constructorObserved = true
			if jsengine.CurrentContext(loop) != origin {
				t.Error("Promise constructor getter lost its originating context")
			}
		}); err != nil {
			return err
		}
		result, err := runtime.RunString("pending-observation.js", `
			var resolveObserved;
			var observedPromise = new Promise(resolve => { resolveObserved = resolve; });
			observedPromise.then = done => done("fake");
			Object.defineProperty(observedPromise, "constructor", {
				get() { inspectConstructor(); return Promise; }
			});
			observedPromise;
		`)
		if err != nil {
			return err
		}
		observed, err := jsengine.ObservePromise(runtime, result, func(value jsengine.Value, err error) {
			if err != nil {
				t.Error(err)
				return
			}
			if jsengine.CurrentContext(loop) != origin {
				t.Error("settlement consumed the result under its resolver's context")
			}
			actual, _ = value.Export().(string)
		})
		if !observed {
			t.Error("pending Promise was not observed")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if actual != "" {
		t.Fatalf("mutable then forged an early result: %q", actual)
	}
	if err := jsengine.RunWithContext(loop, resolver, func(runtime jsengine.Runtime) error {
		_, err := runtime.RunString("resolve-observation.js", `resolveObserved("actual");`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if actual != "actual" || !constructorObserved {
		t.Fatalf("result=%q constructorObserved=%v", actual, constructorObserved)
	}
}

func TestPromiseObservationReportsUnprintableRejection(t *testing.T) {
	for _, pending := range []bool{false, true} {
		name := "already-rejected"
		if pending {
			name = "pending"
		}
		t.Run(name, func(t *testing.T) {
			loop := New()
			defer loop.Close()
			settlements := 0
			if err := loop.Run(func(runtime jsengine.Runtime) error {
				source := `Promise.reject({toString() { throw Error("unprintable"); }});`
				if pending {
					source = `var rejectObserved; new Promise((_, reject) => { rejectObserved = reject; });`
				}
				result, err := runtime.RunString("rejected-observation.js", source)
				if err != nil {
					return err
				}
				observed, err := jsengine.ObservePromise(runtime, result, func(_ jsengine.Value, err error) {
					settlements++
					if err == nil {
						t.Error("unprintable reason was reported as a successful settlement")
					}
				})
				if err != nil {
					return err
				}
				if !observed {
					t.Error("rejected Promise was not observed")
				}
				if pending {
					_, err = runtime.RunString("reject-observation.js", `rejectObserved({toString() { throw Error("unprintable"); }});`)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if settlements != 1 {
				t.Fatalf("settlement calls = %d, want one rejection", settlements)
			}
		})
	}
}

type promiseObserverRetentionProbe struct{ data [256]byte }

func TestCanceledPromiseObservationReleasesHostCallback(t *testing.T) {
	checkPromiseObserverRelease(t, false)
}

func TestClosedPromiseObservationReleasesHostCallback(t *testing.T) {
	checkPromiseObserverRelease(t, true)
}

func checkPromiseObserverRelease(t *testing.T, closeLoop bool) {
	t.Helper()
	loop := New()
	defer loop.Close()
	origin := newAwaitOwnershipScope(t, "origin")
	var weakProbe weak.Pointer[promiseObserverRetentionProbe]
	if err := jsengine.RunWithContext(loop, origin, func(runtime jsengine.Runtime) error {
		result, err := runtime.RunString("retained-promise.js", `var retainedPromise = new Promise(() => {}); retainedPromise;`)
		if err != nil {
			return err
		}
		probe := &promiseObserverRetentionProbe{}
		weakProbe = weak.Make(probe)
		observed, err := jsengine.ObservePromise(runtime, result, func(jsengine.Value, error) {
			goruntime.KeepAlive(probe)
			t.Error("never-settled Promise invoked its callback")
		})
		if !observed {
			t.Error("pending Promise was not observed")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if closeLoop {
		if err := loop.Close(); err != nil {
			t.Fatal(err)
		}
	} else {
		origin.cancel()
	}
	deadline := time.Now().Add(3 * time.Second)
	for weakProbe.Value() != nil {
		if time.Now().After(deadline) {
			t.Fatal("script-rooted Promise retained an ended host callback")
		}
		goruntime.GC()
		time.Sleep(time.Millisecond)
	}
	goruntime.KeepAlive(loop)
}
