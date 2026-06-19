package sealabort

import (
	"sync"

	"github.com/dop251/goja"
)

type abortSignal struct {
	mu        sync.Mutex
	aborted   bool
	reason    goja.Value
	rt        *goja.Runtime
	listeners []func(goja.Value)
	obj       *goja.Object
}

func newSignal(rt *goja.Runtime) *abortSignal {
	return &abortSignal{rt: rt}
}

func (s *abortSignal) bind(obj *goja.Object) {
	s.obj = obj
}

func (s *abortSignal) doAbort(reason goja.Value) bool {
	s.mu.Lock()
	if s.aborted {
		s.mu.Unlock()
		return false
	}
	s.aborted = true
	if reason == nil || goja.IsUndefined(reason) || goja.IsNull(reason) {
		reason = s.rt.ToValue("Aborted")
	}
	s.reason = reason
	listeners := s.listeners
	s.listeners = nil
	obj := s.obj
	s.mu.Unlock()

	if obj != nil {
		_ = obj.Set("aborted", true)
		_ = obj.Set("reason", reason)
	}
	for _, fn := range listeners {
		fn(reason)
	}
	return true
}

func Enable(rt *goja.Runtime) {
	_ = rt.Set("AbortController", newAbortControllerCtor(rt))
	_ = rt.Set("AbortSignal", newAbortSignalStatic(rt))
}

func Require(rt *goja.Runtime, module *goja.Object) {
	exports := module.Get("exports").(*goja.Object)
	_ = exports.Set("AbortController", newAbortControllerCtor(rt))
	_ = exports.Set("AbortSignal", newAbortSignalStatic(rt))
}

func newAbortControllerCtor(rt *goja.Runtime) func(call goja.ConstructorCall) *goja.Object {
	return func(call goja.ConstructorCall) *goja.Object {
		sig := newSignal(rt)
		obj := call.This

		signalObj := buildSignalObj(rt, sig)
		_ = obj.Set("signal", signalObj)
		_ = obj.Set("abort", func(call goja.FunctionCall) goja.Value {
			sig.doAbort(call.Argument(0))
			return goja.Undefined()
		})
		return obj
	}
}

func newAbortSignalStatic(rt *goja.Runtime) *goja.Object {
	static := rt.NewObject()
	_ = static.Set("abort", func(call goja.FunctionCall) goja.Value {
		sig := newSignal(rt)
		sig.doAbort(call.Argument(0))
		return buildSignalObj(rt, sig)
	})
	_ = static.Set("timeout", func(call goja.FunctionCall) goja.Value {
		ms := call.Argument(0).ToInteger()
		sig := newSignal(rt)
		signalObj := buildSignalObj(rt, sig)
		if timer := rt.Get("setTimeout"); timer != nil {
			if fn, ok := goja.AssertFunction(timer); ok {
				cb := func(call goja.FunctionCall) goja.Value {
					sig.doAbort(rt.ToValue("TimeoutError"))
					return goja.Undefined()
				}
				_, _ = fn(goja.Undefined(), rt.ToValue(cb), rt.ToValue(ms))
			}
		}
		return signalObj
	})
	return static
}

func buildSignalObj(rt *goja.Runtime, sig *abortSignal) *goja.Object {
	obj := rt.NewObject()
	sig.bind(obj)

	_ = obj.Set("aborted", false)
	_ = obj.Set("reason", goja.Undefined())

	_ = obj.Set("addEventListener", func(call goja.FunctionCall) goja.Value {
		evType := call.Argument(0).String()
		if evType != "abort" {
			return goja.Undefined()
		}
		handler, ok := goja.AssertFunction(call.Argument(1))
		if !ok {
			return goja.Undefined()
		}
		fn := func(reason goja.Value) {
			_, _ = handler(goja.Undefined(), rt.ToValue(map[string]interface{}{
				"type":   "abort",
				"target": obj,
				"reason": reason,
			}))
		}
		sig.mu.Lock()
		if sig.aborted {
			reason := sig.reason
			sig.mu.Unlock()
			fn(reason)
		} else {
			sig.listeners = append(sig.listeners, fn)
			sig.mu.Unlock()
		}
		return goja.Undefined()
	})

	_ = obj.Set("removeEventListener", func(call goja.FunctionCall) goja.Value {
		return goja.Undefined()
	})

	_ = obj.Set("throwIfAborted", func(call goja.FunctionCall) goja.Value {
		sig.mu.Lock()
		aborted := sig.aborted
		reason := sig.reason
		sig.mu.Unlock()
		if aborted {
			panic(rt.NewTypeError("Aborted: " + reason.String()))
		}
		return goja.Undefined()
	})

	return obj
}
