package hostbridge

import "reflect"

// ControlledObject is the only bridge contract used for invocation-scoped
// domain handles. Implementations own property policy and typed unwrapping;
// adapters must not reflect over a ControlledObject as a fallback.
type ControlledObject interface {
	HostGet(name string) (value any, exists bool, err error)
	HostSet(name string, value any) error
	HostKeys() []string
	HostUnwrap(target reflect.Type) (any, error)
}

// ControlledObjectScope optionally belongs to the opaque execution context
// passed to a JavaScript loop. It turns selected raw host arguments and return
// values into invocation-scoped handles without making an engine import the
// application packages that define those values.
type ControlledObjectScope interface {
	HostWrap(value any) (object ControlledObject, wrapped bool, err error)
}

// ScopeIdentifier lets a scope declare the identity under which runtimes cache
// the JavaScript proxies it produces. Scopes that resolve wrapping through the
// same underlying owner (for example a persistent binding delegating to the
// invocation currently entering the realm) must report the same identity so a
// host object keeps one JavaScript identity per owner.
type ScopeIdentifier interface {
	HostScopeIdentity() any
}

// Scope returns the controlled-object wrapper carried by an opaque execution
// context, if any.
func Scope(context any) ControlledObjectScope {
	scope, _ := context.(ControlledObjectScope)
	return scope
}

// Wrap asks scope to wrap value. Values that already implement
// ControlledObject do not require an ambient scope.
func Wrap(scope ControlledObjectScope, value any) (ControlledObject, bool, error) {
	if object, ok := value.(ControlledObject); ok {
		return object, true, nil
	}
	if scope == nil {
		return nil, false, nil
	}
	return scope.HostWrap(value)
}
