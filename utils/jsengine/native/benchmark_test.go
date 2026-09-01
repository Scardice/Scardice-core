//go:build cgo

package native

import (
	"context"
	"fmt"
	"os"
	"testing"

	"Scardice-core/utils/jsengine"
	builtinGoja "Scardice-core/utils/jsengine/builtin/goja"
)

type benchmarkHost struct {
	Value int `jsbind:"value"`
}

func (h *benchmarkHost) Add(delta int) int {
	return h.Value + delta
}

type benchmarkCallbackHost struct{}

func (benchmarkCallbackHost) Apply(callback func(int) int) int {
	return callback(5) + 1
}

func openNativeBenchmarkLoop(b *testing.B) jsengine.Loop {
	b.Helper()
	root := os.Getenv("SCARDICE_QUICKJS_PACKAGE")
	if root == "" {
		b.Skip("SCARDICE_QUICKJS_PACKAGE is not set")
	}
	candidates, err := Discover(root)
	if err != nil {
		b.Fatal(err)
	}
	if len(candidates) != 1 {
		b.Fatalf("Discover returned %d candidates, want one", len(candidates))
	}
	provider, err := candidates[0].Load()
	if err != nil {
		b.Fatal(err)
	}
	loop, err := provider.Open(context.Background(), jsengine.RuntimeOptions{})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = loop.Close() })
	return loop
}

func runBenchmarkSetup(b *testing.B, loop jsengine.Loop, setup func(jsengine.Runtime) error) {
	b.Helper()
	if err := loop.Run(setup); err != nil {
		b.Fatal(err)
	}
}

func BenchmarkNativePrimitiveGet(b *testing.B) {
	loop := openNativeBenchmarkLoop(b)
	runBenchmarkSetup(b, loop, func(runtime jsengine.Runtime) error {
		return runtime.Set("primitive", int64(42))
	})
	var sink any
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := loop.Run(func(runtime jsengine.Runtime) error {
			value, err := runtime.Get("primitive").ExportPrimitive()
			if err != nil {
				return err
			}
			sink = value
			return nil
		}); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	if sink != int64(42) {
		b.Fatalf("primitive sink = %#v", sink)
	}
}

func BenchmarkNativePrimitiveSet(b *testing.B) {
	loop := openNativeBenchmarkLoop(b)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := loop.Run(func(runtime jsengine.Runtime) error {
			return runtime.Set("primitive", int64(42))
		}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNativeHostPropertyGet(b *testing.B) {
	loop := openNativeBenchmarkLoop(b)
	host := &benchmarkHost{Value: 42}
	runBenchmarkSetup(b, loop, func(runtime jsengine.Runtime) error {
		return runtime.Bind("host", host)
	})
	var sink any
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := loop.Run(func(runtime jsengine.Runtime) error {
			object := runtime.Get("host").Object()
			if object == nil {
				return fmt.Errorf("host object is nil")
			}
			value, err := object.Get("value").ExportPrimitive()
			if err != nil {
				return err
			}
			sink = value
			return nil
		}); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	if sink != int64(42) {
		b.Fatalf("host property sink = %#v", sink)
	}
}

func BenchmarkNativeHostMethod(b *testing.B) {
	loop := openNativeBenchmarkLoop(b)
	host := &benchmarkHost{Value: 42}
	runBenchmarkSetup(b, loop, func(runtime jsengine.Runtime) error {
		return runtime.Bind("host", host)
	})
	var sink any
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := loop.Run(func(runtime jsengine.Runtime) error {
			value, err := runtime.RunString("host-method.js", "host.add(1)")
			if err != nil {
				return err
			}
			primitive, err := value.ExportPrimitive()
			if err != nil {
				return err
			}
			sink = primitive
			return nil
		}); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	if sink != int64(43) {
		b.Fatalf("host method sink = %#v", sink)
	}
}

func BenchmarkNativeCallback(b *testing.B) {
	loop := openNativeBenchmarkLoop(b)
	runBenchmarkSetup(b, loop, func(runtime jsengine.Runtime) error {
		return runtime.Bind("callback", func(value int) int { return value + 1 })
	})
	var sink any
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := loop.Run(func(runtime jsengine.Runtime) error {
			value, err := runtime.RunString("callback.js", "callback(1)")
			if err != nil {
				return err
			}
			primitive, err := value.ExportPrimitive()
			if err != nil {
				return err
			}
			sink = primitive
			return nil
		}); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	if sink != int64(2) {
		b.Fatalf("callback sink = %#v", sink)
	}
}

func BenchmarkNativeNestedCallback(b *testing.B) {
	loop := openNativeBenchmarkLoop(b)
	runBenchmarkSetup(b, loop, func(runtime jsengine.Runtime) error {
		return runtime.Bind("host", benchmarkCallbackHost{})
	})
	var sink any
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := loop.Run(func(runtime jsengine.Runtime) error {
			value, err := runtime.RunString("nested-callback.js", "host.apply(value => value + 1)")
			if err != nil {
				return err
			}
			primitive, err := value.ExportPrimitive()
			if err != nil {
				return err
			}
			sink = primitive
			return nil
		}); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	if sink != int64(7) {
		b.Fatalf("nested callback sink = %#v", sink)
	}
}

func BenchmarkGojaEquivalent(b *testing.B) {
	provider := builtinGoja.Provider()
	loop, err := provider.Open(context.Background(), jsengine.RuntimeOptions{})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = loop.Close() })
	runBenchmarkSetup(b, loop, func(runtime jsengine.Runtime) error {
		return runtime.Bind("host", benchmarkCallbackHost{})
	})
	var sink any
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := loop.Run(func(runtime jsengine.Runtime) error {
			value, err := runtime.RunString("goja-equivalent.js", "host.apply(value => value + 1)")
			if err != nil {
				return err
			}
			primitive, err := value.ExportPrimitive()
			if err != nil {
				return err
			}
			sink = primitive
			return nil
		}); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	if sink != int64(7) {
		b.Fatalf("Goja sink = %#v", sink)
	}
}
