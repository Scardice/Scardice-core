package jsengine

// PromiseObserver is an optional runtime capability for consuming a returned
// JavaScript Promise without allowing its values to escape the owning callback.
// ObservePromise is called on the runtime owner. A true result means settlement
// was registered; false means value is not a Promise and remains valid for
// immediate consumption by the caller. settled runs at most once on the owner.
type PromiseObserver interface {
	ObservePromise(value Value, settled func(Value, error)) (bool, error)
}

// ObservePromise asks runtime to observe value when the provider supports it.
// Plain values are consumed before the current owner callback returns; Promise
// settlement values are consumed synchronously inside settled on that owner.
func ObservePromise(runtime Runtime, value Value, settled func(Value, error)) (bool, error) {
	observer, ok := runtime.(PromiseObserver)
	if !ok {
		return false, nil
	}
	return observer.ObservePromise(value, settled)
}
