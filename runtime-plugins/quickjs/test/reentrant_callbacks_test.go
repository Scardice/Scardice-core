package quickjs_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"Scardice-core/utils/jsengine"
	"Scardice-core/utils/jsengine/native"
)

const reentrantCaseTimeout = 2 * time.Second

type reentrantEngine struct {
	name           string
	requiresNative bool
	open           func() (jsengine.Loop, error)
}

func reentrantEngines(t *testing.T) []reentrantEngine {
	t.Helper()
	engines := []reentrantEngine{}
	engines = append(engines, reentrantEngine{
		name:           "native-quickjs",
		requiresNative: true,
		open: func() (jsengine.Loop, error) {
			candidates, err := native.Discover(os.Getenv("SCARDICE_QUICKJS_PACKAGE"))
			if err != nil {
				return nil, err
			}
			if len(candidates) != 1 {
				return nil, fmt.Errorf("Discover returned %d candidates, want one", len(candidates))
			}
			provider, err := candidates[0].Load()
			if err != nil {
				return nil, err
			}
			return provider.Open(context.Background(), jsengine.RuntimeOptions{})
		},
	})
	return engines
}

func boundedReentrant(t *testing.T, fn func() error) (err error, timedOut bool) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err = <-done:
		return err, false
	case <-time.After(reentrantCaseTimeout):
		return fmt.Errorf("operation exceeded %s", reentrantCaseTimeout), true
	}
}

func withReentrantEngine(t *testing.T, engine reentrantEngine, fn func(jsengine.Loop, *reentrantHost) error) {
	t.Helper()
	var loop jsengine.Loop
	host := &reentrantHost{}
	err, timedOut := boundedReentrant(t, func() error {
		var err error
		loop, err = engine.open()
		if err != nil {
			return err
		}
		return fn(loop, host)
	})
	if err != nil {
		t.Fatal(err)
	}
	if timedOut {
		return
	}
	if loop == nil {
		t.Fatal("engine returned a nil loop")
	}
	closeErr, closeTimedOut := boundedReentrant(t, loop.Close)
	if closeErr != nil {
		t.Fatalf("Close() error = %v", closeErr)
	}
	if closeTimedOut {
		t.Fatal("Close() exceeded case timeout")
	}
}

func forEachReentrantEngine(t *testing.T, fn func(jsengine.Loop, *reentrantHost) error) {
	t.Helper()
	for _, engine := range reentrantEngines(t) {
		t.Run(engine.name, func(t *testing.T) {
			if engine.requiresNative && os.Getenv("SCARDICE_QUICKJS_PACKAGE") == "" {
				t.Skip("SCARDICE_QUICKJS_PACKAGE is not set")
			}
			withReentrantEngine(t, engine, fn)
		})
	}
}

type reentrantHost struct {
	Callback func(int) (int, error) `jsbind:"callback"`

	mu     sync.Mutex
	events []string
	calls  int
}

func (h *reentrantHost) mark(event string) {
	h.mu.Lock()
	h.events = append(h.events, event)
	h.mu.Unlock()
}

func (h *reentrantHost) snapshot() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.events...)
}

func (h *reentrantHost) Record(label string) int {
	h.mu.Lock()
	h.events = append(h.events, "go.record."+label)
	h.calls++
	count := h.calls
	h.mu.Unlock()
	return count
}

func (h *reentrantHost) Invoke(callback func(int) (int, error)) (int, error) {
	h.mark("go.invoke.enter")
	value, err := callback(5)
	if err != nil {
		h.mark("go.invoke.error")
		return 0, err
	}
	h.mark("go.invoke.exit")
	return value + 1, nil
}

func (h *reentrantHost) callCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.calls
}

func (h *reentrantHost) Panic() int {
	h.mark("go.panic")
	panic("reentrant host panic")
}

func (h *reentrantHost) Timeout() (int, error) {
	h.mark("go.timeout")
	return 0, context.DeadlineExceeded
}
func bindReentrantHost(runtime jsengine.Runtime, host *reentrantHost) error {
	return runtime.Bind("host", host)
}

func evalInt(runtime jsengine.Runtime, filename, source string) (int64, error) {
	value, err := runtime.RunString(filename, source)
	if err != nil {
		return 0, err
	}
	primitive, err := value.ExportPrimitive()
	if err != nil {
		return 0, err
	}
	switch number := primitive.(type) {
	case int:
		return int64(number), nil
	case int64:
		return number, nil
	case uint64:
		return int64(number), nil
	case float64:
		return int64(number), nil
	default:
		return 0, fmt.Errorf("result = %#v (%T), want number", primitive, primitive)
	}
}

func eventsError(host *reentrantHost, want ...string) error {
	if got := host.snapshot(); fmt.Sprint(got) != fmt.Sprint(want) {
		return fmt.Errorf("events = %v, want %v", got, want)
	}
	return nil
}

// A: a Go caller invokes a JavaScript callback retained by the host adapter.
func TestReentrantMatrixA_GoToJS(t *testing.T) {
	forEachReentrantEngine(t, func(loop jsengine.Loop, host *reentrantHost) error {
		if err := loop.Run(func(runtime jsengine.Runtime) error {
			if err := bindReentrantHost(runtime, host); err != nil {
				return err
			}
			_, err := runtime.RunString("a.js", `host.callback = value => value * 2`)
			return err
		}); err != nil {
			return err
		}
		if host.Callback == nil {
			return errors.New("JavaScript callback was not assigned")
		}
		host.mark("go.call.start")
		value, err := host.Callback(5)
		host.mark("go.call.end")
		if err != nil || value != 10 {
			return fmt.Errorf("Go→JS callback = %d, %v; want 10", value, err)
		}
		if err := eventsError(host, "go.call.start", "go.call.end"); err != nil {
			return err
		}
		return nil
	})
}

// B: JavaScript calls a Go host method and receives its exact result.
func TestReentrantMatrixB_JSToGo(t *testing.T) {
	forEachReentrantEngine(t, func(loop jsengine.Loop, host *reentrantHost) error {
		return loop.Run(func(runtime jsengine.Runtime) error {
			if err := bindReentrantHost(runtime, host); err != nil {
				return err
			}
			value, err := evalInt(runtime, "b.js", `host.record("js")`)
			if err != nil {
				return err
			}
			if host.callCount() != 1 {
				return fmt.Errorf("JS→Go call count = %d, want 1", host.callCount())
			}
			if value != 1 {
				return fmt.Errorf("JS→Go result = %d, want 1", value)
			}
			if err := eventsError(host, "go.record.js"); err != nil {
				return err
			}
			return nil
		})
	})
}

// C: a Go-invoked JavaScript callback calls back into a Go host method.
func TestReentrantMatrixC_GoToJSToGo(t *testing.T) {
	forEachReentrantEngine(t, func(loop jsengine.Loop, host *reentrantHost) error {
		if err := loop.Run(func(runtime jsengine.Runtime) error {
			if err := bindReentrantHost(runtime, host); err != nil {
				return err
			}
			_, err := runtime.RunString("c.js", `host.callback = value => host.record("nested") + value`)
			return err
		}); err != nil {
			return err
		}
		host.mark("go.call.start")
		value, err := host.Callback(5)
		host.mark("go.call.end")
		if err != nil || value != 6 {
			return fmt.Errorf("Go→JS→Go result = %d, %v; want 6", value, err)
		}
		if host.callCount() != 1 {
			return fmt.Errorf("Go→JS→Go call count = %d, want 1", host.callCount())
		}
		if err := eventsError(host, "go.call.start", "go.record.nested", "go.call.end"); err != nil {
			return err
		}
		return nil
	})
}

// D: JavaScript enters Go, which invokes a JavaScript callback before returning.
func TestReentrantMatrixD_JSToGoToJS(t *testing.T) {
	forEachReentrantEngine(t, func(loop jsengine.Loop, host *reentrantHost) error {
		return loop.Run(func(runtime jsengine.Runtime) error {
			if err := bindReentrantHost(runtime, host); err != nil {
				return err
			}
			value, err := evalInt(runtime, "d.js", `host.invoke(value => value * 3)`)
			if err != nil {
				return err
			}
			if value != 16 {
				return fmt.Errorf("JS→Go→JS result = %d, want 16", value)
			}
			if host.callCount() != 0 {
				return fmt.Errorf("JS→Go→JS call count = %d, want 0", host.callCount())
			}
			if err := eventsError(host, "go.invoke.enter", "go.invoke.exit"); err != nil {
				return err
			}
			return nil
		})
	})
}

// E: a Go-invoked JavaScript callback enters Go and that Go method invokes JS.
func TestReentrantMatrixE_GoToJSToGoToJS(t *testing.T) {
	forEachReentrantEngine(t, func(loop jsengine.Loop, host *reentrantHost) error {
		if err := loop.Run(func(runtime jsengine.Runtime) error {
			if err := bindReentrantHost(runtime, host); err != nil {
				return err
			}
			_, err := runtime.RunString("e.js", `host.callback = value => host.invoke(inner => host.record("inner") + inner + value)`)
			return err
		}); err != nil {
			return err
		}
		host.mark("go.call.start")
		value, err := host.Callback(5)
		host.mark("go.call.end")
		if err != nil || value != 12 {
			return fmt.Errorf("Go→JS→Go→JS result = %d, %v; want 12", value, err)
		}
		if host.callCount() != 1 {
			return fmt.Errorf("Go→JS→Go→JS call count = %d, want 1", host.callCount())
		}
		if err := eventsError(host, "go.call.start", "go.invoke.enter", "go.record.inner", "go.invoke.exit", "go.call.end"); err != nil {
			return err
		}
		return nil
	})
}

func TestReentrantMatrixF_ClosedCallbackIsDeterministic(t *testing.T) {
	for _, engine := range reentrantEngines(t) {
		t.Run(engine.name, func(t *testing.T) {
			if engine.requiresNative && os.Getenv("SCARDICE_QUICKJS_PACKAGE") == "" {
				t.Skip("SCARDICE_QUICKJS_PACKAGE is not set")
			}
			var loop jsengine.Loop
			host := &reentrantHost{}
			err, timedOut := boundedReentrant(t, func() error {
				var err error
				loop, err = engine.open()
				if err != nil {
					return err
				}
				return loop.Run(func(runtime jsengine.Runtime) error {
					if err := bindReentrantHost(runtime, host); err != nil {
						return err
					}
					_, err := runtime.RunString("f.js", `host.callback = value => value + 1`)
					return err
				})
			})
			if err != nil {
				t.Fatal(err)
			}
			if timedOut {
				t.Fatal("opening callback fixture exceeded case timeout")
			}
			old := host.Callback
			if old == nil {
				t.Fatal("old callback was not assigned")
			}
			if err, timedOut = boundedReentrant(t, loop.Close); err != nil || timedOut {
				t.Fatalf("closing old loop: error=%v timeout=%v", err, timedOut)
			}

			if err, timedOut = boundedReentrant(t, func() error {
				_, callbackErr := old(1)
				if callbackErr == nil || (!strings.Contains(strings.ToLower(callbackErr.Error()), "closed") && !strings.Contains(strings.ToLower(callbackErr.Error()), "stale")) {
					return fmt.Errorf("old callback error = %v, want deterministic closed/stale error", callbackErr)
				}
				return nil
			}); err != nil || timedOut {
				t.Fatalf("old callback after close: error=%v timeout=%v", err, timedOut)
			}

			var recreated jsengine.Loop
			err, timedOut = boundedReentrant(t, func() error {
				var err error
				recreated, err = engine.open()
				if err != nil {
					return err
				}
				return recreated.Run(func(runtime jsengine.Runtime) error {
					if err := bindReentrantHost(runtime, host); err != nil {
						return err
					}
					_, err := runtime.RunString("f-recreated.js", `host.callback = value => value + 2`)
					return err
				})
			})
			if err != nil || timedOut {
				t.Fatalf("recreating loop: error=%v timeout=%v", err, timedOut)
			}
			var value int
			err, timedOut = boundedReentrant(t, func() error {
				var callbackErr error
				value, callbackErr = host.Callback(1)
				if callbackErr != nil || value != 3 {
					return fmt.Errorf("new callback = %d, %v; want 3", value, callbackErr)
				}
				return nil
			})
			if err != nil || timedOut {
				t.Fatalf("new callback: error=%v timeout=%v", err, timedOut)
			}
			if err, timedOut = boundedReentrant(t, func() error {
				_, callbackErr := old(1)
				if callbackErr == nil || (!strings.Contains(strings.ToLower(callbackErr.Error()), "closed") && !strings.Contains(strings.ToLower(callbackErr.Error()), "stale")) {
					return fmt.Errorf("old callback after recreation error = %v, want deterministic closed/stale error", callbackErr)
				}
				return nil
			}); err != nil || timedOut {
				t.Fatalf("old callback after recreation: error=%v timeout=%v", err, timedOut)
			}
			if err, timedOut = boundedReentrant(t, recreated.Close); err != nil || timedOut {
				t.Fatalf("closing recreated loop: error=%v timeout=%v", err, timedOut)
			}
		})
	}
}

func TestReentrantMatrixG_ErrorsRestoreContext(t *testing.T) {
	forEachReentrantEngine(t, func(loop jsengine.Loop, host *reentrantHost) error {
		if err := loop.Run(func(runtime jsengine.Runtime) error {
			if err := bindReentrantHost(runtime, host); err != nil {
				return err
			}
			if _, err := runtime.RunString("g-panic.js", `host.panic()`); err == nil || !strings.Contains(strings.ToLower(err.Error()), "panic") {
				return fmt.Errorf("panic result = %v, want panic error", err)
			}
			if _, err := runtime.RunString("g-callback-timeout.js", `host.callback = () => { throw new Error("g callback deadline exceeded") }`); err != nil {
				return err
			}
			if _, err := host.Callback(1); err == nil || !strings.Contains(err.Error(), "deadline exceeded") {
				return fmt.Errorf("callback timeout result = %v, want deadline exceeded", err)
			}
			if _, err := runtime.RunString("g-exception.js", `throw new Error("g JS exception")`); err == nil || !strings.Contains(err.Error(), "g JS exception") {
				return fmt.Errorf("JS exception result = %v, want exception error", err)
			}
			value, err := runtime.RunString("g-timeout.js", `(() => { try { host.timeout() } catch (error) { return String(error).includes("deadline exceeded") } })()`)
			if err != nil {
				return err
			}
			if !value.ToBoolean() {
				return errors.New("timeout host error was not catchable")
			}
			if _, err := runtime.RunString("g-restored.js", `host.record("restored")`); err != nil {
				return err
			}
			if host.callCount() != 1 {
				return fmt.Errorf("restored host call count = %d, want 1", host.callCount())
			}
			if err := eventsError(host, "go.panic", "go.timeout", "go.record.restored"); err != nil {
				return err
			}
			return nil
		}); err != nil {
			return err
		}
		return nil
	})
}
