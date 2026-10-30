package goja

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"

	"github.com/dop251/goja"

	"Scardice-core/utils/jsengine"
)

type promiseObservationPayload struct {
	context any
	realm   *realm
	settled func(jsengine.Value, error)
}

// The Promise callbacks retain this revocable cell, not the invocation. A
// script-rooted unresolved Promise must not keep canceled host waiters alive.
type promiseObservation struct {
	mu      sync.Mutex
	payload promiseObservationPayload
	stop    func() bool
}

func (o *promiseObservation) take() promiseObservationPayload {
	o.mu.Lock()
	payload, stop := o.payload, o.stop
	o.payload = promiseObservationPayload{}
	o.stop = nil
	o.mu.Unlock()
	if payload.realm != nil {
		payload.realm.promiseMu.Lock()
		delete(payload.realm.promises, o)
		payload.realm.promiseMu.Unlock()
	}
	if stop != nil {
		stop()
	}
	return payload
}

func (o *promiseObservation) finish(result goja.Value, rejected bool) {
	payload := o.take()
	if payload.settled != nil {
		settleObservedPromise(payload, result, rejected)
	}
}

func (r *realm) addPromiseObservation(observation *promiseObservation) error {
	r.promiseMu.Lock()
	defer r.promiseMu.Unlock()
	if r.promiseClosed {
		return errors.New("goja runtime is closed")
	}
	if r.promises == nil {
		r.promises = make(map[*promiseObservation]struct{})
	}
	r.promises[observation] = struct{}{}
	return nil
}

func (r *realm) closePromiseObservations() {
	r.promiseMu.Lock()
	pending := r.promises
	r.promises = nil
	r.promiseClosed = true
	r.promiseMu.Unlock()
	for observation := range pending {
		observation.take()
	}
}

func settleObservedPromise(payload promiseObservationPayload, result goja.Value, rejected bool) {
	execution := jsengine.ContextForExecution(payload.context)
	if err := execution.Err(); err != nil {
		payload.settled(nil, err)
		return
	}
	alreadyEntered := jsengine.ContextForExecution(payload.realm.state.currentContext()) == execution
	delivered := false
	consume := func() error {
		var rejection error
		if rejected {
			rejection = promiseRejectionError(result)
		}
		if err := execution.Err(); err != nil {
			rejection = err
		}
		delivered = true
		if rejection != nil {
			payload.settled(nil, rejection)
		} else {
			payload.settled(value{value: result, realm: payload.realm}, nil)
		}
		return nil
	}
	err := payload.realm.state.with(payload.context, func() error {
		if alreadyEntered {
			return consume()
		}
		return runWithExecutionContext(execution, payload.realm.vm, consume)
	})
	if err != nil && !delivered {
		payload.settled(nil, err)
	}
}

func promiseRejectionError(reason goja.Value) (err error) {
	err = errors.New("promise rejected: reason could not be converted to text")
	defer func() {
		if recovered := recover(); recovered != nil {
			// A throwing toString must still reject the host callback. Hard VM
			// interrupts keep their normal unwind and cancellation semantics.
			if _, exception := recovered.(*goja.Exception); !exception {
				panic(recovered)
			}
		}
	}()
	if reason == nil {
		reason = goja.Undefined()
	}
	return fmt.Errorf("promise rejected: %s", reason.String())
}

func (r *runtime) ObservePromise(input jsengine.Value, settled func(jsengine.Value, error)) (bool, error) {
	if r == nil || r.vm == nil || r.realm == nil {
		return false, errors.New("goja runtime is required")
	}
	if settled == nil {
		return false, errors.New("Promise settlement callback is nil")
	}
	adapted, ok := input.(value)
	if !ok {
		return false, nil
	}
	if adapted.realm != r.realm {
		return false, errors.New("goja Promise belongs to another realm")
	}
	_, scope := r.valueScope()
	if err := validateValueScope(adapted.owner, adapted.scope, r, scope); err != nil {
		return false, err
	}
	if adapted.value == nil || adapted.value.ExportType() != reflect.TypeFor[*goja.Promise]() {
		return false, nil
	}
	promise, ok := adapted.value.Export().(*goja.Promise)
	if !ok {
		return false, nil
	}

	payload := promiseObservationPayload{context: r.realm.state.currentContext(), realm: r.realm, settled: settled}
	switch promise.State() {
	case goja.PromiseStateFulfilled:
		settleObservedPromise(payload, promise.Result(), false)
		return true, nil
	case goja.PromiseStateRejected:
		settleObservedPromise(payload, promise.Result(), true)
		return true, nil
	case goja.PromiseStatePending:
		if r.realm.promiseThen == nil {
			return false, errors.New("goja Promise intrinsic is unavailable")
		}
		execution := jsengine.ContextForExecution(payload.context)
		if err := execution.Err(); err != nil {
			return false, err
		}
		observation := &promiseObservation{payload: payload}
		observation.mu.Lock()
		if err := r.realm.addPromiseObservation(observation); err != nil {
			observation.mu.Unlock()
			observation.take()
			return false, err
		}
		if execution.Done() != nil {
			observation.stop = context.AfterFunc(execution, func() { observation.take() })
		}
		observation.mu.Unlock()
		onFulfilled := r.vm.ToValue(func(call goja.FunctionCall) goja.Value {
			observation.finish(call.Argument(0), false)
			return goja.Undefined()
		})
		onRejected := r.vm.ToValue(func(call goja.FunctionCall) goja.Value {
			observation.finish(call.Argument(0), true)
			return goja.Undefined()
		})
		if _, err := r.realm.promiseThen(adapted.value, onFulfilled, onRejected); err != nil {
			observation.take()
			return false, err
		}
		return true, nil
	default:
		return false, errors.New("unknown Promise state")
	}
}

var _ jsengine.PromiseObserver = (*runtime)(nil)
