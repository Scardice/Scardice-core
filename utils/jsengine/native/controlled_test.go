//go:build cgo

package native

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"Scardice-core/utils/jsengine"
	"Scardice-core/utils/jsengine/hostbridge"
)

var errNativeControlledRevoked = errors.New("native controlled scope is revoked")

type nativeControlledFacade struct {
	Name  string
	Child *nativeControlledFacade
}

type nativeControlledScope struct {
	context.Context
	alive    bool
	wrappers map[*nativeControlledFacade]*nativeControlledView
}

func newNativeControlledScope() *nativeControlledScope {
	return &nativeControlledScope{
		Context:  context.Background(),
		alive:    true,
		wrappers: make(map[*nativeControlledFacade]*nativeControlledView),
	}
}

func (s *nativeControlledScope) ExecutionContext() context.Context { return s.Context }

func (s *nativeControlledScope) HostWrap(value any) (hostbridge.ControlledObject, bool, error) {
	if !s.alive {
		return nil, false, errNativeControlledRevoked
	}
	facade, ok := value.(*nativeControlledFacade)
	if !ok || facade == nil {
		return nil, false, nil
	}
	if existing := s.wrappers[facade]; existing != nil {
		return existing, true, nil
	}
	wrapped := &nativeControlledView{scope: s, facade: facade}
	s.wrappers[facade] = wrapped
	return wrapped, true, nil
}

type nativeControlledView struct {
	scope  *nativeControlledScope
	facade *nativeControlledFacade
}

func (v *nativeControlledView) valid() error {
	if v == nil || v.scope == nil || !v.scope.alive {
		return errNativeControlledRevoked
	}
	return nil
}

func (v *nativeControlledView) HostGet(name string) (any, bool, error) {
	if err := v.valid(); err != nil {
		return nil, false, err
	}
	switch name {
	case "name":
		return v.facade.Name, true, nil
	case "child":
		return v.facade.Child, v.facade.Child != nil, nil
	case "rename":
		return func(name string) *nativeControlledFacade {
			v.facade.Name = name
			return v.facade
		}, true, nil
	default:
		return nil, false, nil
	}
}

func (v *nativeControlledView) HostSet(name string, value any) error {
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

func (v *nativeControlledView) HostKeys() []string {
	if v.valid() != nil {
		return nil
	}
	return []string{"name", "child", "rename"}
}

func (v *nativeControlledView) HostUnwrap(target reflect.Type) (any, error) {
	if err := v.valid(); err != nil {
		return nil, err
	}
	if target != reflect.TypeFor[*nativeControlledFacade]() {
		return nil, fmt.Errorf("native controlled facade cannot unwrap into %s", target)
	}
	return v.facade, nil
}

type nativeMutableDTO struct {
	Label string `jsbind:"label"`
}

type nativeCallbackContainer struct {
	Hook  func(*nativeControlledFacade) string `jsbind:"hook"`
	Items []*nativeControlledFacade            `jsbind:"items"`
}

func TestNativeControlledObjectsBilateralRoundTrip(t *testing.T) {
	loop := openEcho(t)
	defer loop.Close()

	child := &nativeControlledFacade{Name: "child"}
	root := &nativeControlledFacade{Name: "before", Child: child}
	scope := newNativeControlledScope()
	boundDTO := &nativeMutableDTO{Label: "bound"}
	host := &nativeCallbackContainer{Items: []*nativeControlledFacade{root}}
	var callback func(*nativeControlledFacade) string
	var result any

	err := jsengine.RunWithContext(loop, scope, func(runtime jsengine.Runtime) error {
		if err := runtime.Bind("root", root); err != nil {
			return err
		}
		if err := runtime.Bind("identity", func(value *nativeControlledFacade) *nativeControlledFacade { return value }); err != nil {
			return err
		}
		if err := runtime.Bind("install", func(value func(*nativeControlledFacade) string) { callback = value }); err != nil {
			return err
		}
		if err := runtime.Bind("mutateDTO", func(value *nativeMutableDTO) *nativeMutableDTO {
			value.Label += "!"
			return value
		}); err != nil {
			return err
		}
		if err := runtime.Bind("boundDTO", boundDTO); err != nil {
			return err
		}
		if err := runtime.Bind("host", host); err != nil {
			return err
		}
		value, err := runtime.RunString("native-controlled.js", `
			const sameChild = root.child === root.child;
			const detachedRename = root.rename;
			const returnedRoot = detachedRename("renamed");
			const removed = delete root.name;
			root.name = "written";
			install(value => value === root ? value.name : "wrong-object");
			host.hook = value => value === root ? value.name : "wrong-object";
			const plain = {label: "plain"};
			const returnedDTO = mutateDTO(plain);
			mutateDTO(boundDTO);
			[
				root.name,
				returnedRoot === root,
				identity(root) === root,
				host.items[0] === root,
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
	want := "written|true|true|true|true|true|false|child,name,rename|plain!|bound!"
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
	if host.Hook == nil {
		t.Fatal("ordinary native host callback field was not decoded")
	}
	if got := host.Hook(root); got != "written" {
		t.Fatalf("ordinary native host callback returned %q, want written", got)
	}
}

func TestNativeControlledObjectsRejectStaleAndCrossRuntimeUse(t *testing.T) {
	first := openEcho(t)
	defer first.Close()
	second := openEcho(t)
	defer second.Close()

	scope := newNativeControlledScope()
	root := &nativeControlledFacade{Name: "live"}
	var controlled jsengine.Value
	if err := jsengine.RunWithContext(first, scope, func(runtime jsengine.Runtime) error {
		if err := runtime.Bind("root", root); err != nil {
			return err
		}
		controlled = runtime.Get("root")
		_, err := runtime.RunString("retain-native-controlled.js", "globalThis.savedControlled = root")
		return err
	}); err != nil {
		t.Fatal(err)
	}

	if err := second.Run(func(runtime jsengine.Runtime) error {
		if err := runtime.Bind("foreignControlled", controlled); err == nil {
			return errors.New("cross-runtime controlled value was accepted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	scope.alive = false
	if err := first.Run(func(runtime jsengine.Runtime) error {
		value, err := runtime.RunString("stale-native-controlled.js", `
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
		if !strings.Contains(fmt.Sprint(message), errNativeControlledRevoked.Error()) {
			return fmt.Errorf("stale controlled error = %q", message)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
