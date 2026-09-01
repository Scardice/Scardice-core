package dice

import (
	"errors"
	"testing"

	"go.uber.org/zap"

	"Scardice-core/utils/jsengine"
	gojaengine "Scardice-core/utils/jsengine/goja"
)

func TestParseJSSolveEngineResult(t *testing.T) {
	engines := []struct {
		name string
		new  func(t *testing.T) jsengine.Loop
	}{
		{name: "goja", new: func(t *testing.T) jsengine.Loop { return gojaengine.New() }},
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
	loop := gojaengine.New()
	t.Cleanup(func() { _ = loop.Close() })

	d := &Dice{
		Config:         Config{JsConfig: JsConfig{JsEnable: true}},
		ExtLoopManager: NewJsLoopManager(),
	}
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
func TestCallOnMessagePreprocessEngineSupportsNonJSProviderAndRestoresContext(t *testing.T) {
	loop := gojaengine.New()
	d := &Dice{
		Config:         Config{JsConfig: JsConfig{JsEnable: true}},
		ExtLoopManager: NewJsLoopManager(),
		Logger:         zap.NewNop().Sugar(),
	}
	version := d.ExtLoopManager.SetLoop(loop)
	previous := &ExtInfo{Name: "previous"}
	d.JsCurrentPlugin = previous
	ext := &ExtInfo{
		Name:          "neutral-provider",
		JSLoopVersion: version,
		OnMessagePreprocessEngine: func(runtime jsengine.Runtime, _ *MsgContext, _ *Message) (jsengine.Value, error) {
			if d.JsCurrentPlugin == nil || d.JsCurrentPlugin.Name != "neutral-provider" {
				return nil, errors.New("callback context was not installed")
			}
			return runtime.RunString("preprocess.js", "({ message: 'rewritten' })")
		},
	}

	decision := ext.CallOnMessagePreprocess(d, &MsgContext{}, &Message{Message: "original"})
	if decision.action != messagePreprocessRewrite || decision.message != "rewritten" {
		t.Fatalf("decision = %#v", decision)
	}
	if d.JsCurrentPlugin != previous {
		t.Fatalf("JsCurrentPlugin = %p, want previous %p", d.JsCurrentPlugin, previous)
	}
}

func TestCallOnMessagePreprocessEngineReportsCallbackErrorAndPanicAsNoop(t *testing.T) {
	for _, test := range []struct {
		name string
		fn   func(jsengine.Runtime, *MsgContext, *Message) (jsengine.Value, error)
	}{
		{
			name: "error",
			fn: func(jsengine.Runtime, *MsgContext, *Message) (jsengine.Value, error) {
				return nil, errors.New("callback failed")
			},
		},
		{
			name: "panic",
			fn: func(jsengine.Runtime, *MsgContext, *Message) (jsengine.Value, error) {
				panic("callback panicked")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			loop := gojaengine.New()
			t.Cleanup(func() { _ = loop.Close() })

			d := &Dice{
				ExtLoopManager: NewJsLoopManager(),
				Logger:         zap.NewNop().Sugar(),
			}
			version := d.ExtLoopManager.SetLoop(loop)
			ext := &ExtInfo{
				Name:                      "callback-failure",
				JSLoopVersion:             version,
				OnMessagePreprocessEngine: test.fn,
			}
			if decision := ext.CallOnMessagePreprocess(d, &MsgContext{}, &Message{}); decision.action != messagePreprocessNoop {
				t.Fatalf("decision = %#v, want noop", decision)
			}
		})
	}
}

func TestCallOnMessagePreprocessEngineHonorsJsEnableForJSProvider(t *testing.T) {
	loop := gojaengine.New()
	t.Cleanup(func() { _ = loop.Close() })

	called := false
	d := &Dice{
		Config:         Config{JsConfig: JsConfig{JsEnable: false}},
		ExtLoopManager: NewJsLoopManager(),
		Logger:         zap.NewNop().Sugar(),
	}
	version := d.ExtLoopManager.SetLoop(loop)
	ext := &ExtInfo{
		Name:          "disabled-js-provider",
		IsJsExt:       true,
		JSLoopVersion: version,
		OnMessagePreprocessEngine: func(jsengine.Runtime, *MsgContext, *Message) (jsengine.Value, error) {
			called = true
			return nil, nil
		},
	}

	if decision := ext.CallOnMessagePreprocess(d, &MsgContext{}, &Message{}); decision.action != messagePreprocessNoop {
		t.Fatalf("decision = %#v, want noop", decision)
	}
	if called {
		t.Fatal("disabled JS provider callback was invoked")
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
