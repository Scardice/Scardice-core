//go:build cgo

package native

/*
#include <stdint.h>
#include "bridge.h"
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"unsafe"

	"Scardice-core/utils/jsengine"
)

// Installed before plugin code. The returned functions are retained privately
// by the native loop; the temporary bootstrap callback is removed immediately.
const nativePromiseObserverSource = `(function () {
  const then = Promise.prototype.then;
  const apply = Reflect.apply;
  const getPrototypeOf = Object.getPrototypeOf;
  const getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
  const stringify = String;
  const settled = globalThis.__scardicePromiseSettled;
  delete globalThis.__scardicePromiseSettled;

  let incompatibleReady = false;
  let incompatiblePrototype;
  let incompatibleHasMessage = false;
  let incompatibleMessage;
  try {
    apply(then, {}, []);
  } catch (error) {
    const descriptor = getOwnPropertyDescriptor(error, "message");
    incompatibleReady = true;
    incompatiblePrototype = getPrototypeOf(error);
    incompatibleHasMessage = descriptor !== undefined && "value" in descriptor;
    if (incompatibleHasMessage) incompatibleMessage = descriptor.value;
  }
  if (!incompatibleReady) throw new Error("Promise intrinsic accepted an incompatible receiver");

  const isIncompatibleReceiver = error => {
    try {
      const descriptor = getOwnPropertyDescriptor(error, "message");
      const hasMessage = descriptor !== undefined && "value" in descriptor;
      return getPrototypeOf(error) === incompatiblePrototype &&
        hasMessage === incompatibleHasMessage &&
        (!hasMessage || descriptor.value === incompatibleMessage);
    } catch (_) {
      return false;
    }
  };

  let currentValue;
  const getValue = () => currentValue;
  const observe = function (promise, token) {
    try {
      apply(then, promise, [function (value) {
        const previous = currentValue;
        currentValue = value;
        try { settled(token, false, ""); } finally { currentValue = previous; }
      }, function (reason) {
        let text;
        try { text = stringify(reason); }
        catch (_) { text = "Promise rejection reason could not be converted to text"; }
        settled(token, true, text);
      }]);
      return true;
    } catch (error) {
      if (isIncompatibleReceiver(error)) return false;
      throw error;
    }
  };
  return Object.freeze({ observe, getValue });
})();`

type nativePromiseObservation struct {
	context any
	token   uint64
	settled func(jsengine.Value, error)
	stop    func() bool
}

func (r *nativeRuntime) installPromiseObserver() error {
	if !r.loop.provider.descriptor.Capabilities.Has(jsengine.CapabilityPromise) {
		return nil
	}
	if err := r.Set("__scardicePromiseSettled", r.loop.finishPromiseObservation); err != nil {
		return err
	}
	helperValue, err := r.RunString("promise-observer-init.js", nativePromiseObserverSource)
	if err != nil {
		return err
	}
	helpers, ok := helperValue.Object().(*nativeObject)
	if !ok {
		return errors.New("native Promise observer did not return helper functions")
	}
	observe, err := retainNativePromiseHelper(helpers, "observe")
	if err != nil {
		return err
	}
	getValue, err := retainNativePromiseHelper(helpers, "getValue")
	if err != nil {
		_ = observe.releasePersistent()
		return err
	}
	r.loop.promiseObserve = observe
	r.loop.promiseGetValue = getValue
	return nil
}

func retainNativePromiseHelper(helpers *nativeObject, name string) (*nativeValue, error) {
	raw, err := helpers.GetWithError(name)
	if err != nil {
		return nil, err
	}
	helper, ok := raw.(*nativeValue)
	if !ok {
		return nil, fmt.Errorf("native Promise helper %q is unavailable", name)
	}
	typ, err := helper.typeOf()
	if err != nil {
		return nil, err
	}
	if typ != uint32(nativeTypeFunction) {
		return nil, fmt.Errorf("native Promise helper %q is not callable", name)
	}
	if err := helper.retain(); err != nil {
		return nil, err
	}
	return helper, nil
}

func (r *nativeRuntime) callPromiseFunction(function *nativeValue, args ...*nativeValue) (*nativeValue, error) {
	if r == nil || r.loop == nil || r.scope == nil || r.scope.released.Load() ||
		function == nil || function.loop != r.loop || !function.usable() || len(args) > 2 {
		return nil, errors.New("native Promise helper is unavailable")
	}
	var arguments [2]uint64
	for index, argument := range args {
		if argument == nil || argument.loop != r.loop || !argument.usable() {
			return nil, ErrNativeStaleValue
		}
		arguments[index] = argument.handle
	}
	var output C.uint64_t
	var errorBuffer [512]byte
	status := C.sc_native_function_call(
		C.uint64_t(r.loop.provider.library), C.uint64_t(r.loop.runtime), C.uint64_t(function.handle), 0,
		pointerToUint64(arguments[:len(args)]), C.uint64_t(len(args)), &output,
		(*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer)),
	)
	if err := r.loop.operation(status, cError(errorBuffer[:])); err != nil {
		return nil, err
	}
	return r.scope.value(uint64(output)), nil
}

func (r *nativeRuntime) ObservePromise(input jsengine.Value, settled func(jsengine.Value, error)) (bool, error) {
	if r == nil || r.loop == nil || r.scope == nil || r.scope.released.Load() {
		return false, ErrNativeStaleValue
	}
	if settled == nil {
		return false, errors.New("Promise settlement callback is nil")
	}
	promise, ok := input.(*nativeValue)
	if !ok || r.loop.promiseObserve == nil || r.loop.promiseGetValue == nil {
		return false, nil
	}
	if promise.loop != r.loop || !promise.usable() {
		return false, ErrNativeStaleValue
	}
	typ, err := promise.typeOf()
	if err != nil {
		return false, err
	}
	if typ != uint32(nativeTypeObject) {
		return false, nil
	}
	originalContext := r.loop.CurrentContext()
	execution := jsengine.ContextForExecution(originalContext)
	if err := execution.Err(); err != nil {
		return false, err
	}
	contextToken := r.loop.currentNativeToken()

	l := r.loop
	l.promiseMu.Lock()
	l.nextPromiseObservation++
	id := l.nextPromiseObservation
	observation := &nativePromiseObservation{context: originalContext, token: contextToken, settled: settled}
	if l.promiseObservations == nil {
		l.promiseObservations = make(map[uint64]*nativePromiseObservation)
	}
	l.promiseObservations[id] = observation
	l.promiseObservers.Add(1)
	if execution.Done() != nil {
		observation.stop = context.AfterFunc(execution, func() { l.takePromiseObservation(id) })
	}
	l.promiseMu.Unlock()

	token, err := r.newUint(id)
	var observed *nativeValue
	if err == nil {
		observed, err = r.callPromiseFunction(l.promiseObserve, promise, token)
	}
	if err != nil {
		l.takePromiseObservation(id)
		return false, err
	}
	if observed == nil || !observed.ToBoolean() {
		l.takePromiseObservation(id)
		return false, nil
	}
	return true, nil
}

func (l *nativeLoop) takePromiseObservation(id uint64) *nativePromiseObservation {
	l.promiseMu.Lock()
	observation := l.promiseObservations[id]
	if observation != nil {
		delete(l.promiseObservations, id)
		l.promiseObservers.Add(-1)
	}
	l.promiseMu.Unlock()
	if observation != nil && observation.stop != nil {
		observation.stop()
	}
	return observation
}

func (l *nativeLoop) finishPromiseObservation(id uint64, rejected bool, reason string) {
	observation := l.takePromiseObservation(id)
	if observation == nil {
		return
	}
	if err := jsengine.ContextForExecution(observation.context).Err(); err != nil {
		observation.settled(nil, err)
		return
	}
	leave, err := jsengine.EnterExecution(observation.context, l.CurrentContext())
	if err != nil {
		observation.settled(nil, err)
		return
	}
	defer leave()
	previousToken, previousContext, err := l.enterContext(observation.token, observation.context)
	if err != nil {
		observation.settled(nil, err)
		return
	}
	defer func() {
		if err := l.leaveContext(previousToken, previousContext); err != nil && l.host != nil {
			l.host.setError(err)
		}
	}()
	if rejected {
		observation.settled(nil, fmt.Errorf("promise rejected: %s", reason))
		return
	}
	if l.activeScope == nil || l.activeScope.released.Load() {
		observation.settled(nil, ErrNativeStaleValue)
		return
	}
	current := &nativeRuntime{loop: l, scope: l.activeScope}
	value, err := current.callPromiseFunction(l.promiseGetValue)
	observation.settled(value, err)
}

func (l *nativeLoop) discardPromiseObservations() {
	l.promiseMu.Lock()
	observations := l.promiseObservations
	l.promiseObservations = nil
	l.promiseObservers.Store(0)
	l.promiseMu.Unlock()
	for _, observation := range observations {
		if observation.stop != nil {
			observation.stop()
		}
	}
}

var _ jsengine.PromiseObserver = (*nativeRuntime)(nil)
