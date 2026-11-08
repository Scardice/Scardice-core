package dice

import (
	"sync"
	"testing"

	"github.com/dop251/goja"
)

func newJSGroupActiveTestVM(t *testing.T) (*goja.Runtime, *GroupInfo) {
	t.Helper()
	vm := goja.New()
	vm.SetFieldNameMapper(goja.TagFieldNameMapper("jsbind", true))
	if err := installJSGroupActiveAccessor(vm); err != nil {
		t.Fatal(err)
	}
	group := &GroupInfo{GroupID: "js-active-test"}
	group.SetActiveRaw(true)
	if err := vm.Set("g", vm.ToValue(group)); err != nil {
		t.Fatal(err)
	}
	return vm, group
}

func TestJSGroupActiveUsesLockedAccessor(t *testing.T) {
	vm, group := newJSGroupActiveTestVM(t)

	value, err := vm.RunString("g.active")
	if err != nil {
		t.Fatal(err)
	}
	if !value.ToBoolean() {
		t.Fatal("g.active should be true")
	}

	value, err = vm.RunString("Object.prototype.hasOwnProperty.call(g, 'active')")
	if err != nil {
		t.Fatal(err)
	}
	if value.ToBoolean() {
		t.Fatal("GroupInfo.Active must be hidden from goja's struct field mapping")
	}

	if _, err = vm.RunString("g.active = false"); err != nil {
		t.Fatal(err)
	}
	if group.IsActiveRaw() {
		t.Fatal("JS assignment bypassed SetActiveRaw")
	}

	if _, err = vm.RunString("g.active = 1"); err != nil {
		t.Fatal(err)
	}
	if !group.IsActiveRaw() {
		t.Fatal("truthy JS assignment did not enable the group")
	}

	// 普通 JS 对象仍保持自己的 active 数据属性，JSON.stringify 不受影响。
	value, err = vm.RunString("var o = {}; o.active = 7; JSON.stringify(o)")
	if err != nil {
		t.Fatal(err)
	}
	if got := value.String(); got != `{"active":7}` {
		t.Fatalf("plain object JSON = %s, want {\"active\":7}", got)
	}
}

func TestJSGroupActiveConcurrentWithSetActiveRaw(t *testing.T) {
	vm, group := newJSGroupActiveTestVM(t)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range 2000 {
			group.SetActiveRaw(i%2 == 0)
		}
	}()
	for range 2000 {
		if _, err := vm.RunString("g.active"); err != nil {
			t.Errorf("read g.active: %v", err)
			break
		}
	}
	wg.Wait()
}
