package quickjs_test

import (
	"testing"

	"Scardice-core/utils/jsengine"
	"Scardice-core/utils/jsengine/quickjs"
)

func TestHostFunctionPanicBecomesJavaScriptException(t *testing.T) {
	loop, err := quickjs.New()
	if err != nil {
		t.Fatal(err)
	}
	defer loop.Close()

	if err := loop.Run(func(runtime jsengine.Runtime) error {
		if err := runtime.Set("panicHost", func() { panic("host panic") }); err != nil {
			return err
		}
		value, err := runtime.RunString("host-panic.js", `
			let caught = false;
			try { panicHost(); } catch (error) { caught = String(error).includes("host panic"); }
			caught && 1 + 1 === 2
		`)
		if err != nil {
			return err
		}
		if !value.ToBoolean() {
			t.Fatal("host panic did not become a catchable JavaScript exception")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
