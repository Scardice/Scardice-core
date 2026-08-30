package jsengine

// Value is a JavaScript value scoped to a Runtime callback.
type Value interface {
	Export() interface{}
	ToBoolean() bool
	Object() Object
}

// Object is a mutable JavaScript object scoped to a Runtime callback.
type Object interface {
	Set(name string, value interface{}) error
	Get(name string) Value
	Has(name string) bool
}

// Loop serializes all access to one JavaScript realm.
type Loop interface {
	Engine() EngineID
	Run(func(Runtime) error) error
	Close()
}

// Runtime accesses a JavaScript realm while its owning Loop is executing the
// callback passed to Loop.Run. Values obtained from it MUST NOT escape that
// callback.
type Runtime interface {
	Engine() EngineID
	RunString(filename, source string) (Value, error)
	// LoadCommonJS evaluates source once and returns its cached module exports.
	LoadCommonJS(filename, source string) (Value, error)
	NewObject() Object
	Get(name string) Value
	Set(name string, value interface{}) error
	// Bind exposes a Go value under a JavaScript global name.
	Bind(name string, value interface{}) error
}
