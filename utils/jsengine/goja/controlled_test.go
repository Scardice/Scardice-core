package goja_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	goruntime "runtime"
	"strings"
	"testing"
	"time"
	"weak"

	"Scardice-core/utils/jsengine"
	gojaengine "Scardice-core/utils/jsengine/goja"
	"Scardice-core/utils/jsengine/hostbridge"
)

var errControlledScopeRevoked = errors.New("controlled scope is revoked")

type controlledFacade struct {
	Name  string
	Child *controlledFacade
}

type controlledScope struct {
	context.Context
	alive    bool
	wrappers map[*controlledFacade]*controlledView
}

func newControlledScope() *controlledScope {
	return &controlledScope{
		Context:  context.Background(),
		alive:    true,
		wrappers: make(map[*controlledFacade]*controlledView),
	}
}

func (s *controlledScope) ExecutionContext() context.Context { return s.Context }

func (s *controlledScope) HostWrap(value any) (hostbridge.ControlledObject, bool, error) {
	if !s.alive {
		return nil, false, errControlledScopeRevoked
	}
	facade, ok := value.(*controlledFacade)
	if !ok || facade == nil {
		return nil, false, nil
	}
	if existing := s.wrappers[facade]; existing != nil {
		return existing, true, nil
	}
	wrapped := &controlledView{scope: s, facade: facade}
	s.wrappers[facade] = wrapped
	return wrapped, true, nil
}

type controlledView struct {
	scope  *controlledScope
	facade *controlledFacade
}

func (v *controlledView) valid() error {
	if v == nil || v.scope == nil || !v.scope.alive {
		return errControlledScopeRevoked
	}
	return nil
}

func (v *controlledView) HostGet(name string) (any, bool, error) {
	if err := v.valid(); err != nil {
		return nil, false, err
	}
	switch name {
	case "name":
		return v.facade.Name, true, nil
	case "child":
		return v.facade.Child, v.facade.Child != nil, nil
	case "rename":
		return func(name string) *controlledFacade {
			v.facade.Name = name
			return v.facade
		}, true, nil
	default:
		return nil, false, nil
	}
}

func (v *controlledView) HostSet(name string, value any) error {
	if err := v.valid(); err != nil {
		return err
	}
	if name != "name" {
		return fmt.Errorf("unknown controlled property %q", name)
	}
	text, ok := value.(string)
	if !ok {
		return fmt.Errorf("name expects string, got %T", value)
	}
	v.facade.Name = text
	return nil
}

func (v *controlledView) HostKeys() []string {
	if v.valid() != nil {
		return nil
	}
	return []string{"name", "child", "rename"}
}

func (v *controlledView) HostUnwrap(target reflect.Type) (any, error) {
	if err := v.valid(); err != nil {
		return nil, err
	}
	if target != reflect.TypeFor[*controlledFacade]() {
		return nil, fmt.Errorf("controlled facade cannot unwrap into %s", target)
	}
	return v.facade, nil
}

type mutableDTO struct {
	Label string `jsbind:"label"`
}

func TestGojaControlledObjectsRoundTripWithoutExposingCanonicalPointers(t *testing.T) {
	loop := gojaengine.New()
	defer loop.Close()

	child := &controlledFacade{Name: "child"}
	root := &controlledFacade{Name: "before", Child: child}
	scope := newControlledScope()
	boundDTO := &mutableDTO{Label: "bound"}
	var callback func(*controlledFacade) string
	var result any

	err := jsengine.RunWithContext(loop, scope, func(runtime jsengine.Runtime) error {
		if err := runtime.Bind("root", root); err != nil {
			return err
		}
		if err := runtime.Bind("identity", func(value *controlledFacade) *controlledFacade { return value }); err != nil {
			return err
		}
		if err := runtime.Bind("install", func(value func(*controlledFacade) string) { callback = value }); err != nil {
			return err
		}
		if err := runtime.Bind("mutateDTO", func(value *mutableDTO) *mutableDTO {
			value.Label += "!"
			return value
		}); err != nil {
			return err
		}
		if err := runtime.Bind("boundDTO", boundDTO); err != nil {
			return err
		}
		value, err := runtime.RunString("controlled.js", `
			const sameChild = root.child === root.child;
			const detachedRename = root.rename;
			const returnedRoot = detachedRename("renamed");
			const removed = delete root.name;
			root.name = "written";
			install(value => value === root ? value.name : "wrong-object");
			const plain = {label: "plain"};
			const returnedDTO = mutateDTO(plain);
			mutateDTO(boundDTO);
			[
				root.name,
				returnedRoot === root,
				identity(root) === root,
				sameChild,
				"name" in root,
				removed,
				Object.keys(root).sort().join(","),
				returnedDTO.label,
				boundDTO.label
			].join("|")
		`)
		if err != nil {
			return err
		}
		result = value.Export()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "written|true|true|true|true|false|child,name,rename|plain!|bound!"
	if result != want {
		t.Fatalf("controlled result = %#v, want %q", result, want)
	}
	if root.Name != "written" || boundDTO.Label != "bound!" {
		t.Fatalf("read-your-writes did not reach host: root=%q dto=%q", root.Name, boundDTO.Label)
	}
	if callback == nil {
		t.Fatal("typed JavaScript callback was not installed")
	}
	if got := callback(root); got != "written" {
		t.Fatalf("Go-to-JS controlled callback argument = %q, want written", got)
	}
}

func TestGojaControlledObjectsRejectStaleAndCrossRealmUse(t *testing.T) {
	first := gojaengine.New()
	defer first.Close()
	second := gojaengine.New()
	defer second.Close()

	scope := newControlledScope()
	root := &controlledFacade{Name: "live"}
	var exported any
	if err := jsengine.RunWithContext(first, scope, func(runtime jsengine.Runtime) error {
		if err := runtime.Bind("root", root); err != nil {
			return err
		}
		exported = runtime.Get("root").Export()
		_, err := runtime.RunString("retain.js", "globalThis.savedControlled = root")
		return err
	}); err != nil {
		t.Fatal(err)
	}

	if err := second.Run(func(runtime jsengine.Runtime) error {
		if err := runtime.Bind("foreignControlled", exported); err == nil {
			return errors.New("cross-realm controlled handler was accepted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	scope.alive = false
	if err := first.Run(func(runtime jsengine.Runtime) error {
		value, err := runtime.RunString("stale.js", `
			try {
				savedControlled.name
				"missing-error"
			} catch (error) {
				String(error && error.message || error)
			}
		`)
		if err != nil {
			return err
		}
		message, _ := value.ExportPrimitive()
		if !strings.Contains(fmt.Sprint(message), errControlledScopeRevoked.Error()) {
			return fmt.Errorf("stale controlled error = %q", message)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestGojaControlledObjectHostUnwrapRejectsWrongTypedParameter(t *testing.T) {
	loop := gojaengine.New()
	defer loop.Close()

	type wrongTarget struct{}
	scope := newControlledScope()
	root := &controlledFacade{Name: "root"}
	if err := jsengine.RunWithContext(loop, scope, func(runtime jsengine.Runtime) error {
		if err := runtime.Bind("root", root); err != nil {
			return err
		}
		if err := runtime.Bind("wrong", func(*wrongTarget) {}); err != nil {
			return err
		}
		value, err := runtime.RunString("wrong-target.js", `
			try {
				wrong(root)
				"missing-error"
			} catch (error) {
				String(error && error.message || error)
			}
		`)
		if err != nil {
			return err
		}
		message, _ := value.ExportPrimitive()
		if !strings.Contains(fmt.Sprint(message), "cannot unwrap") {
			return fmt.Errorf("wrong target error = %q", message)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

type callbackContainer struct {
	Hook  func(*controlledFacade) string `jsbind:"hook"`
	Items []*controlledFacade            `jsbind:"items"`
}

func TestGojaOrdinaryHostObjectsRecursivelyWrapControlledValues(t *testing.T) {
	loop := gojaengine.New()
	defer loop.Close()

	scope := newControlledScope()
	root := &controlledFacade{Name: "root"}
	host := &callbackContainer{Items: []*controlledFacade{root}}
	var nestedIdentity any
	if err := jsengine.RunWithContext(loop, scope, func(runtime jsengine.Runtime) error {
		if err := runtime.Bind("root", root); err != nil {
			return err
		}
		if err := runtime.Bind("host", host); err != nil {
			return err
		}
		value, err := runtime.RunString("nested-controlled.js", `
			host.hook = value => value === root ? value.name : "wrong-object";
			Array.isArray(host.items) && host.items[0] === root;
		`)
		if err != nil {
			return err
		}
		nestedIdentity = value.Export()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if nestedIdentity != true {
		t.Fatalf("nested controlled value identity = %#v, want true", nestedIdentity)
	}
	if host.Hook == nil {
		t.Fatal("ordinary host callback field was not decoded")
	}
	if got := host.Hook(root); got != "root" {
		t.Fatalf("ordinary host callback returned %q, want root", got)
	}
}

func TestGojaCallbackEngineValueUsesInvocationScope(t *testing.T) {
	loop := gojaengine.New()
	defer loop.Close()

	scope := newControlledScope()
	var callback func() jsengine.Value
	if err := jsengine.RunWithContext(loop, scope, func(runtime jsengine.Runtime) error {
		if err := runtime.Bind("installValueCallback", func(value func() jsengine.Value) {
			callback = value
		}); err != nil {
			return err
		}
		_, err := runtime.RunString("install-value-callback.js", `
			installValueCallback(() => ({answer: 42}));
		`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if callback == nil {
		t.Fatal("engine-value callback was not installed")
	}

	if err := jsengine.RunWithContext(loop, scope, func(jsengine.Runtime) error {
		exported := callback().Export()
		object, ok := exported.(map[string]any)
		if !ok || object["answer"] != int64(42) {
			return fmt.Errorf("callback value = %#v, want answer 42", exported)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestGojaDroppedControlledProxyReleasesInvocationScope(t *testing.T) {
	loop := gojaengine.New()
	defer loop.Close()

	scope := newControlledScope()
	weakScope := weak.Make(scope)
	root := &controlledFacade{Name: "temporary"}
	if err := jsengine.RunWithContext(loop, scope, func(runtime jsengine.Runtime) error {
		if err := runtime.Bind("temporaryControlled", root); err != nil {
			return err
		}
		_, err := runtime.RunString("drop-controlled.js", `temporaryControlled = null`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	root = nil

	deadline := time.Now().Add(3 * time.Second)
	for weakScope.Value() != nil {
		if time.Now().After(deadline) {
			t.Fatal("dropped controlled proxy retained its invocation scope")
		}
		goruntime.GC()
		time.Sleep(time.Millisecond)
	}
	goruntime.KeepAlive(loop)
}
