package dice

import (
	"context"
	"errors"
	"testing"

	"github.com/dop251/goja"
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

func newEngineValueMessageContext(t *testing.T, d *Dice, label string) (*MsgContext, *Message) {
	t.Helper()
	message := newPrivateMsg("QQ:engine-value-user", "")
	return newCanonicalTestMessageContext(
		t, d, newCanonicalTestEndpoint(d, "QQ:engine-value-bot"), message, label,
	), message
}

func TestCallOnMessagePreprocess_UsesEngineNeutralCallback(t *testing.T) {
	loop := gojaengine.New()
	t.Cleanup(func() { _ = loop.Close() })

	d, _ := newCanonicalTestDice(t)
	d.ExtLoopManager = NewJsLoopManager()
	updateCanonicalTestConfig(t, d, func(config *Config) { config.JsEnable = true })
	version := d.ExtLoopManager.SetLoop(loop)
	ext := &ExtInfo{
		Name:          "engine-preprocess",
		IsJsExt:       true,
		JSLoopVersion: version,
		OnMessagePreprocessEngine: func(runtime jsengine.Runtime, _ *MsgContext, _ *Message) (jsengine.Value, error) {
			return runtime.RunString("preprocess.js", "({ message: 'rewritten', reason: 'engine' })")
		},
	}

	ctx, message := newEngineValueMessageContext(t, d, "engine-neutral-callback")
	decision := ext.CallOnMessagePreprocess(d, ctx, message)
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
	d, _ := newCanonicalTestDice(t)
	d.ExtLoopManager = NewJsLoopManager()
	d.Logger = zap.NewNop().Sugar()
	updateCanonicalTestConfig(t, d, func(config *Config) { config.JsEnable = true })
	version := d.ExtLoopManager.SetLoop(loop)
	var ext *ExtInfo
	ext = &ExtInfo{
		Name:          "neutral-provider",
		JSLoopVersion: version,
		OnMessagePreprocessEngine: func(runtime jsengine.Runtime, _ *MsgContext, _ *Message) (jsengine.Value, error) {
			if jsContextPlugin(jsExecutionContextFor(loop)) != ext {
				return nil, errors.New("callback context was not installed")
			}
			return runtime.RunString("preprocess.js", "({ message: 'rewritten' })")
		},
	}

	ctx, message := newEngineValueMessageContext(t, d, "non-js-provider")
	message.Message = "original"
	decision := ext.CallOnMessagePreprocess(d, ctx, message)
	if decision.action != messagePreprocessRewrite || decision.message != "rewritten" {
		t.Fatalf("decision = %#v", decision)
	}
	if jsengine.CurrentContext(loop) != nil {
		t.Fatalf("loop context was not restored: %v", jsengine.CurrentContext(loop))
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

			d, _ := newCanonicalTestDice(t)
			d.ExtLoopManager = NewJsLoopManager()
			d.Logger = zap.NewNop().Sugar()
			version := d.ExtLoopManager.SetLoop(loop)
			ext := &ExtInfo{
				Name:                      "callback-failure",
				JSLoopVersion:             version,
				OnMessagePreprocessEngine: test.fn,
			}
			ctx, message := newEngineValueMessageContext(t, d, "callback-failure:"+test.name)
			if decision := ext.CallOnMessagePreprocess(d, ctx, message); decision.action != messagePreprocessNoop {
				t.Fatalf("decision = %#v, want noop", decision)
			}
		})
	}
}

func TestCallOnMessagePreprocessEngineHonorsJsEnableForJSProvider(t *testing.T) {
	loop := gojaengine.New()
	t.Cleanup(func() { _ = loop.Close() })

	called := false
	d, _ := newCanonicalTestDice(t)
	d.ExtLoopManager = NewJsLoopManager()
	d.Logger = zap.NewNop().Sugar()
	updateCanonicalTestConfig(t, d, func(config *Config) { config.JsEnable = false })
	version := d.ExtLoopManager.SetLoop(loop)
	ext := &ExtInfo{
		Name:          "disabled-js-provider",
		IsJsExt:       true,
		JSLoopVersion: version,
		OnMessagePreprocessEngine: func(jsengine.Runtime, *MsgContext, *Message) (jsengine.Value, error) {
			called = true
			return nil, jsengine.ErrNoPrimitiveValue
		},
	}

	ctx, message := newEngineValueMessageContext(t, d, "disabled-js-provider")
	if decision := ext.CallOnMessagePreprocess(d, ctx, message); decision.action != messagePreprocessNoop {
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

func TestLegacyPreprocessRunsOnce(t *testing.T) {
	d, _ := newCanonicalTestDice(t)
	d.Logger = zap.NewNop().Sugar()
	d.ExtLoopManager = NewJsLoopManager()
	updateCanonicalTestConfig(t, d, func(config *Config) { config.JsEnable = true })
	manager := NewJSRuntimeManagerForDice(d)
	loop, err := manager.Resolve(context.Background(), jsengine.EngineGoja, jsengine.RuntimeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	version := d.ExtLoopManager.SetLoop(loop)
	t.Cleanup(func() {
		d.ExtLoopManager.SetLoop(nil)
	})
	calls := 0
	ext := &ExtInfo{IsJsExt: true, JSLoopVersion: version,
		OnMessagePreprocess: func(*MsgContext, *Message) goja.Value {
			calls++
			return goja.Undefined()
		},
	}
	ctx, message := newEngineValueMessageContext(t, d, "legacy-preprocess")
	ext.CallOnMessagePreprocess(d, ctx, message)
	if calls != 1 {
		t.Fatalf("one message invoked the legacy callback %d times", calls)
	}
}
