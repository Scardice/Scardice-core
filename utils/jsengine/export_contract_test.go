package jsengine_test

import (
	"errors"
	"fmt"
	"testing"

	"Scardice-core/utils/jsengine"
	gojaengine "Scardice-core/utils/jsengine/goja"
)

func TestExportPrimitiveSupportsPrimitiveValues(t *testing.T) {

	loop := gojaengine.New()
	defer loop.Close()
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		for _, test := range []struct {
			source string
			want   any
		}{
			{source: "true", want: true},
			{source: "'text'", want: "text"},
			{source: "42", want: float64(42)},
			{source: "undefined", want: nil},
			{source: "null", want: nil},
		} {
			value, err := runtime.RunString("export.js", test.source)
			if err != nil {
				return err
			}
			got, err := value.ExportPrimitive()
			if test.want == nil {
				if !errors.Is(err, jsengine.ErrNoPrimitiveValue) {
					return fmt.Errorf("source %s export error = %w, want ErrNoPrimitiveValue", test.source, err)
				}
				continue
			}
			if err != nil {
				return err
			}
			if test.source == "42" {
				switch numeric := got.(type) {
				case int64:
					if numeric != 42 {
						return fmt.Errorf("source %s exported %#v", test.source, got)
					}
				case float64:
					if numeric != 42 {
						return fmt.Errorf("source %s exported %#v", test.source, got)
					}
				default:
					return fmt.Errorf("source %s exported %#v (%T)", test.source, got, got)
				}
				continue
			}
			if got != test.want {
				return fmt.Errorf("source %s exported %#v (%T), want %#v (%T)", test.source, got, got, test.want, test.want)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestExportPrimitiveRejectsObjectsAndFunctions(t *testing.T) {

	loop := gojaengine.New()
	defer loop.Close()
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		for _, source := range []string{"({ answer: 42 })", "(function () {})"} {
			value, err := runtime.RunString("export.js", source)
			if err != nil {
				return err
			}
			if _, err := value.ExportPrimitive(); !errors.Is(err, jsengine.ErrPrimitiveExportUnsupported) {
				return errors.New("object export did not return the unsupported primitive error")
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
