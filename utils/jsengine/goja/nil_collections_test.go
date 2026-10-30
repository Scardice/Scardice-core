package goja_test

import (
	"testing"

	"Scardice-core/utils/jsengine"
	gojaengine "Scardice-core/utils/jsengine/goja"
)

// Host functions return nil slices and maps when there is nothing to report.
// Existing plugins read `.length`, iterate or `forEach` over those results, so a
// Go nil has to arrive as an empty collection and not as null.
func TestHostFunctionsReturningNilCollectionsYieldEmptyOnes(t *testing.T) {
	t.Parallel()

	loop := gojaengine.New()
	defer loop.Close()

	var got string
	err := loop.Run(func(runtime jsengine.Runtime) error {
		if err := runtime.Set("nilList", func() []string { return nil }); err != nil {
			return err
		}
		if err := runtime.Set("nilListWithError", func() ([]string, error) { return nil, nil }); err != nil {
			return err
		}
		if err := runtime.Set("nilMap", func() map[string]int { return nil }); err != nil {
			return err
		}
		if err := runtime.Set("someList", func() []string { return []string{"a"} }); err != nil {
			return err
		}
		value, err := runtime.RunString("plugin.js", `
			var seen = 0;
			nilList().forEach(function () { seen++; });
			JSON.stringify({
				listLength: nilList().length,
				withError: nilListWithError().length,
				spread: [...nilList()].length,
				list: nilList(),
				map: nilMap(),
				mapKeys: Object.keys(nilMap()).length,
				seen: seen,
				some: someList(),
			})
		`)
		if err != nil {
			return err
		}
		got, _ = value.Export().(string)
		return nil
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	const want = `{"listLength":0,"withError":0,"spread":0,"list":[],"map":{},"mapKeys":0,"seen":0,"some":["a"]}`
	if got != want {
		t.Fatalf("nil collections from host functions = %s, want %s", got, want)
	}
}
