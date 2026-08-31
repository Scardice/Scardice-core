package dice

import (
	"errors"
	"testing"

	"Scardice-core/utils/jsengine"
	gojaengine "Scardice-core/utils/jsengine/goja"
	quickjs "Scardice-core/utils/jsengine/quickjs"
)

func TestParseJSSolveEngineResult(t *testing.T) {
	engines := []struct {
		name string
		new  func(t *testing.T) jsengine.Loop
	}{
		{name: "goja", new: func(t *testing.T) jsengine.Loop { return gojaengine.New() }},
		{
			name: "quickjs",
			new: func(t *testing.T) jsengine.Loop {
				loop, err := quickjs.New()
				if err != nil {
					t.Fatal(err)
				}
				return loop
			},
		},
	}

	for _, engine := range engines {
		t.Run(engine.name, func(t *testing.T) {
			loop := engine.new(t)
			defer loop.Close()

			if err := loop.Run(func(runtime jsengine.Runtime) error {
				value, err := runtime.RunString("solve.js", "({ matched: 'yes', solved: 0, showHelp: null })")
				if err != nil {
					return err
				}
				result, err := parseJSSolveEngineResult(nil, "test", value)
				if err != nil {
					return err
				}
				if result != (CmdExecuteResult{Matched: true}) {
					return errors.New("unexpected solve result")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestParseMessagePreprocessEngineValue(t *testing.T) {
	engines := []struct {
		name string
		new  func(t *testing.T) jsengine.Loop
	}{
		{name: "goja", new: func(t *testing.T) jsengine.Loop { return gojaengine.New() }},
		{
			name: "quickjs",
			new: func(t *testing.T) jsengine.Loop {
				loop, err := quickjs.New()
				if err != nil {
					t.Fatal(err)
				}
				return loop
			},
		},
	}

	for _, engine := range engines {
		t.Run(engine.name, func(t *testing.T) {
			loop := engine.new(t)
			defer loop.Close()

			if err := loop.Run(func(runtime jsengine.Runtime) error {
				value, err := runtime.RunString("preprocess.js", "({ message: 'rewritten', reason: 'filter' })")
				if err != nil {
					return err
				}
				decision := parseMessagePreprocessEngineValue(value)
				if decision != (messagePreprocessDecision{
					action:  messagePreprocessRewrite,
					message: "rewritten",
					reason:  "filter",
				}) {
					return errors.New("unexpected preprocess decision")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCallOnMessagePreprocess_UsesEngineNeutralCallback(t *testing.T) {
	loop, err := quickjs.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = loop.Close() })

	d := &Dice{ExtLoopManager: NewJsLoopManager()}
	version := d.ExtLoopManager.SetLoop(loop)
	ext := &ExtInfo{
		Name:          "engine-preprocess",
		IsJsExt:       true,
		JSLoopVersion: version,
		OnMessagePreprocessEngine: func(runtime jsengine.Runtime, _ *MsgContext, _ *Message) (jsengine.Value, error) {
			return runtime.RunString("preprocess.js", "({ message: 'rewritten', reason: 'engine' })")
		},
	}

	decision := ext.CallOnMessagePreprocess(d, &MsgContext{}, &Message{Message: "original"})
	if decision != (messagePreprocessDecision{
		action:  messagePreprocessRewrite,
		message: "rewritten",
		reason:  "engine",
	}) {
		t.Fatalf("decision = %#v", decision)
	}
}

type fakeEngineObject struct {
	values map[string]jsengine.Value
}

func (o fakeEngineObject) Set(string, interface{}) error { return nil }

func (o fakeEngineObject) Get(name string) jsengine.Value {
	return o.values[name]
}

func (o fakeEngineObject) Has(name string) bool {
	_, ok := o.values[name]
	return ok
}

type fakeEngineValue struct {
	object jsengine.Object
	prim   any
}

func (v fakeEngineValue) Export() interface{} { return nil }
func (v fakeEngineValue) ExportPrimitive() (any, error) {
	return v.prim, nil
}
func (v fakeEngineValue) ToBoolean() bool         { return v.prim != nil && v.prim != false }
func (v fakeEngineValue) Object() jsengine.Object { return v.object }

func TestParseEngineValuesReadsObjectWithoutLegacyExport(t *testing.T) {
	object := fakeEngineObject{values: map[string]jsengine.Value{
		"message": fakeEngineValue{prim: "rewritten"},
		"reason":  fakeEngineValue{prim: "from-native-object"},
	}}
	decision := parseMessagePreprocessEngineValue(fakeEngineValue{object: object})
	if decision != (messagePreprocessDecision{
		action:  messagePreprocessRewrite,
		message: "rewritten",
		reason:  "from-native-object",
	}) {
		t.Fatalf("decision = %#v", decision)
	}
}

func TestParseSolveEngineValueReadsObjectWithoutLegacyExport(t *testing.T) {
	object := fakeEngineObject{values: map[string]jsengine.Value{
		"matched":  fakeEngineValue{prim: true},
		"solved":   fakeEngineValue{prim: true},
		"showHelp": fakeEngineValue{prim: false},
	}}
	result, err := parseJSSolveEngineResult(nil, "native-object", fakeEngineValue{object: object})
	if err != nil {
		t.Fatal(err)
	}
	if result != (CmdExecuteResult{Matched: true, Solved: true}) {
		t.Fatalf("result = %#v", result)
	}
}
