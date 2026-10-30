//go:build cgo

package native

/*
#include <stdint.h>
#include "bridge.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"

	"Scardice-core/utils/jsengine"
	"Scardice-core/utils/jsengine/hostbridge"
)

var (
	errNativeJSONParseUnavailable     = errors.New("native JSON.parse helper is unavailable")
	errNativeJSONStringifyUnavailable = errors.New("native JSON.stringify helper is unavailable")
)

// JSON intrinsics are captured during runtime startup through the owner scope
// and never published by the host. Retaining each once isolates host behavior
// from plugin mutations without retaining one helper per operation.

func (s *nativeHostState) decodeJSONSnapshot(runtimeHandle, handle uint64) (hostbridge.Value, error) {
	if err := s.checkRuntime(C.sc_runtime_t(runtimeHandle)); err != nil {
		return hostbridge.UndefinedValue(), err
	}
	loop := s.loop
	if !loop.onOwnerThread() || loop.activeScope == nil || loop.activeScope.released.Load() {
		return hostbridge.UndefinedValue(), ErrNativeStaleValue
	}
	runtime := &nativeRuntime{loop: loop, scope: loop.activeScope}
	helper, err := runtime.jsonStringifyHelper()
	if err != nil {
		return hostbridge.UndefinedValue(), err
	}
	serialized, err := runtime.callJSONIntrinsic(helper, handle, "JSON.stringify")
	if err != nil {
		return hostbridge.UndefinedValue(), err
	}
	typ, err := serialized.typeOf()
	if err != nil {
		return hostbridge.UndefinedValue(), err
	}
	if typ != uint32(nativeTypeString) {
		return hostbridge.UndefinedValue(), fmt.Errorf("JSON.stringify returned unsupported native value type %d", typ)
	}
	text, err := serialized.stringValue()
	if err != nil {
		return hostbridge.UndefinedValue(), err
	}
	return hostbridge.Value{Kind: hostbridge.KindJSON, String: text}, nil
}

func (r *nativeRuntime) jsonParseHelper() (*nativeValue, error) {
	if r == nil || r.loop == nil {
		return nil, ErrNativeStaleValue
	}
	return r.jsonIntrinsicHelper(r.loop.jsonParse, errNativeJSONParseUnavailable, "JSON.parse")
}

func (r *nativeRuntime) jsonStringifyHelper() (*nativeValue, error) {
	if r == nil || r.loop == nil {
		return nil, ErrNativeStaleValue
	}
	return r.jsonIntrinsicHelper(r.loop.jsonStringify, errNativeJSONStringifyUnavailable, "JSON.stringify")
}

func (r *nativeRuntime) jsonIntrinsicHelper(helper *nativeValue, unavailable error, name string) (*nativeValue, error) {
	if r == nil || r.loop == nil || r.scope == nil || r.scope.released.Load() {
		return nil, ErrNativeStaleValue
	}
	if helper == nil {
		return nil, unavailable
	}
	if !helper.usable() || helper.loop != r.loop || helper.runtime != r.loop.runtime {
		return nil, fmt.Errorf("native %s helper is stale", name)
	}
	return helper, nil
}

func (r *nativeRuntime) captureJSONParse() error {
	if r == nil || r.loop == nil || r.scope == nil || r.scope.released.Load() {
		return ErrNativeStaleValue
	}
	if r.loop.jsonParse != nil {
		_, err := r.jsonParseHelper()
		return err
	}
	helper, err := r.captureJSONIntrinsic("parse", errNativeJSONParseUnavailable)
	if err != nil {
		return err
	}
	r.loop.jsonParse = helper
	return nil
}

func (r *nativeRuntime) captureJSONStringify() error {
	if r == nil || r.loop == nil || r.scope == nil || r.scope.released.Load() {
		return ErrNativeStaleValue
	}
	if r.loop.jsonStringify != nil {
		_, err := r.jsonStringifyHelper()
		return err
	}
	if _, err := r.lookupJSONIntrinsic("stringify", errNativeJSONStringifyUnavailable); err != nil {
		return err
	}
	// Reject values JSON.stringify would silently omit or replace with null:
	// dropping a filter predicate must never widen an event subscription.
	value, err := r.RunString("<host-json-snapshot>", `(function () {
		const stringify = JSON.stringify;
		const finite = Number.isFinite;
		const boxedNumber = Function.prototype.call.bind(Number.prototype.valueOf);
		const symbols = Object.getOwnPropertySymbols;
		const enumerable = Function.prototype.call.bind(Object.prototype.propertyIsEnumerable);
		const ErrorType = TypeError;
		function validate(_key, item) {
			const kind = typeof item;
			let numeric = item;
			if (kind === "object" && item !== null) {
				const keys = symbols(item);
				for (let index = 0; index < keys.length; index++) {
					if (enumerable(item, keys[index])) {
						throw new ErrorType("host JSON values must have string keys");
					}
				}
				try { numeric = boxedNumber(item); } catch (_) {}
			}
			if (kind === "undefined" || kind === "function" || kind === "symbol" ||
			    kind === "bigint" || (typeof numeric === "number" && !finite(numeric))) {
				throw new ErrorType("host JSON values must be JSON-compatible");
			}
			return item;
		}
		return function (item) { return stringify(item, validate); };
	})()`)
	if err != nil {
		return err
	}
	helper, ok := value.(*nativeValue)
	if !ok || helper == nil {
		return errNativeJSONStringifyUnavailable
	}
	if err := helper.retain(); err != nil {
		return err
	}
	r.loop.jsonStringify = helper
	return nil
}

func (r *nativeRuntime) captureJSONIntrinsic(property string, unavailable error) (*nativeValue, error) {
	helper, err := r.lookupJSONIntrinsic(property, unavailable)
	if err != nil {
		return nil, err
	}
	if err := helper.retain(); err != nil {
		return nil, err
	}
	return helper, nil
}

func (r *nativeRuntime) lookupJSONIntrinsic(property string, unavailable error) (*nativeValue, error) {
	jsonValue, err := r.getGlobal("JSON")
	if err != nil {
		return nil, err
	}
	if jsonValue == nil {
		return nil, unavailable
	}
	jsonObject, ok := jsonValue.Object().(*nativeObject)
	if !ok || jsonObject == nil {
		return nil, unavailable
	}
	raw, err := jsonObject.GetWithError(property)
	if err != nil {
		return nil, err
	}
	helper, ok := raw.(*nativeValue)
	if !ok || helper == nil {
		return nil, unavailable
	}
	typ, err := helper.typeOf()
	if err != nil {
		return nil, err
	}
	if typ != uint32(nativeTypeFunction) {
		return nil, unavailable
	}
	return helper, nil
}

func (r *nativeRuntime) ParseJSON(raw string) (jsengine.Value, error) {
	if r == nil || r.loop == nil || !r.loop.onOwnerThread() || r.scope == nil ||
		r.scope.released.Load() || r.loop.activeScope != r.scope {
		return nil, ErrNativeStaleValue
	}
	helper, err := r.jsonParseHelper()
	if err != nil {
		return nil, err
	}
	input, err := r.newString(raw)
	if err != nil {
		return nil, err
	}
	return r.callJSONIntrinsic(helper, input.handle, "JSON.parse")
}

func (r *nativeRuntime) callJSONIntrinsic(function *nativeValue, input uint64, name string) (*nativeValue, error) {
	if r == nil || r.loop == nil || !r.loop.onOwnerThread() || r.scope == nil ||
		r.scope.released.Load() || r.loop.activeScope != r.scope ||
		function == nil || function.loop != r.loop || function.runtime != r.loop.runtime ||
		!function.usable() || input == 0 {
		return nil, fmt.Errorf("native %s helper is unavailable", name)
	}
	arguments := [1]uint64{input}
	var output C.uint64_t
	var errorBuffer [512]byte
	status := C.sc_native_function_call(
		C.uint64_t(r.loop.provider.library), C.uint64_t(r.loop.runtime), C.uint64_t(function.handle), 0,
		pointerToUint64(arguments[:]), 1, &output,
		(*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer)),
	)
	if err := r.loop.operation(status, cError(errorBuffer[:])); err != nil {
		return nil, err
	}
	if output == 0 {
		return nil, fmt.Errorf("%s returned an empty native value", name)
	}
	value := r.scope.value(uint64(output))
	if value == nil {
		C.sc_native_value_release(C.uint64_t(r.loop.provider.library), C.uint64_t(r.loop.runtime), output)
		return nil, ErrNativeStaleValue
	}
	return value, nil
}
