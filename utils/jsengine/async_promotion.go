package jsengine

import (
	"errors"
)

// PersistentAsyncPromoter upgrades an engine-owned asynchronous callback from
// a generation-lifetime scheduler context into a fresh host execution. The
// callback and its result are valid only while PromotePersistentAsync owns the
// engine value scope.
type PersistentAsyncPromoter interface {
	PromotePersistentAsync(run func() (Value, error)) error
}

// HostCompletionDeliverer lets an execution scope decide where the completion
// of host I/O it started resumes script. The provider calls deliver on its
// owner thread; the scope runs it under the original invocation while that
// invocation is live, or in a fresh independent root when the invocation has
// finished normally in the meantime.
type HostCompletionDeliverer interface {
	DeliverHostCompletion(deliver func() error) error
}

const persistentAsyncPromotionSource = `(function (global) {
	var bridgeName = "__scardicePromotePersistentAsyncInternal";
	var markerName = "__scardicePersistentAsyncPromotionInstalled";
	var promote = global[bridgeName];
	try {
		global[bridgeName] = undefined;
		delete global[bridgeName];
	} catch (_) {}
	if (global[bridgeName] === promote) {
		throw new Error("failed to hide persistent async promotion bridge");
	}
	if (global[markerName] === true) return;
	if (typeof promote !== "function") {
		throw new Error("persistent async promotion bridge is unavailable");
	}
	Object.defineProperty(global, markerName, {
		value: true,
		configurable: false,
		enumerable: false,
		writable: false
	});

	function wrap(callback) {
		if (typeof callback !== "function") return callback;
		return function () {
			var receiver = this;
			var args = arguments;
			promote(function () {
				return callback.apply(receiver, args);
			});
		};
	}

	var timerNames = ["setTimeout", "setInterval", "setImmediate"];
	for (var index = 0; index < timerNames.length; index++) {
		(function (name) {
			var original = global[name];
			if (typeof original !== "function") return;
			global[name] = function (callback) {
				var args = Array.prototype.slice.call(arguments, 1);
				args.unshift(wrap(callback));
				return original.apply(this, args);
			};
		})(timerNames[index]);
	}
})(globalThis);`

// InstallPersistentAsyncPromotion wraps timer callbacks with a trusted,
// closure-held host bridge. Contexts that implement PersistentAsyncPromoter
// may create a fresh invocation root before user code runs. Other contexts
// retain the provider's ordinary callback behavior.
//
// Installation is idempotent and must run after provider context propagation
// is installed, but before untrusted entry code.
func InstallPersistentAsyncPromotion(loop Loop) error {
	if loop == nil {
		return errors.New("JavaScript loop is required")
	}
	return loop.Run(func(runtime Runtime) error {
		if runtime == nil {
			return errors.New("JavaScript runtime is required")
		}
		promote := func(run func() (Value, error)) error {
			if run == nil {
				return errors.New("persistent async callback is required")
			}
			if owner, ok := CurrentContext(loop).(PersistentAsyncPromoter); ok {
				return owner.PromotePersistentAsync(run)
			}
			_, err := run()
			return err
		}
		if err := runtime.Bind("__scardicePromotePersistentAsyncInternal", promote); err != nil {
			return err
		}
		_, err := runtime.RunString("<internal:persistent-async-promotion>", persistentAsyncPromotionSource)
		return err
	})
}
