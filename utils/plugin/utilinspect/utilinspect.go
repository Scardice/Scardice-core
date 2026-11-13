package utilinspect

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/dop251/goja"
)

const defaultDepth = 2

func Enable(rt *goja.Runtime) {
	exports := rt.NewObject()
	_ = exports.Set("inspect", Inspect(rt))
	_ = rt.Set("utilinspect", exports)
}

func Require(rt *goja.Runtime, module *goja.Object) {
	exports := module.Get("exports").(*goja.Object)
	_ = exports.Set("inspect", Inspect(rt))
}

func Inspect(rt *goja.Runtime) func(call goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 1 {
			return rt.ToValue("undefined")
		}
		val := call.Argument(0)
		depth := defaultDepth
		if len(call.Arguments) >= 2 {
			if opts := call.Argument(1).ToObject(rt); !goja.IsUndefined(opts) {
				if d := opts.Get("depth"); d != nil && !goja.IsUndefined(d) {
					if di := d.ToInteger(); di >= 0 {
						depth = int(di)
					} else if di == -1 {
						depth = 1 << 30
					}
				}
			}
		}
		seen := newSeenSet()
		s := inspectValue(rt, val, depth, seen)
		return rt.ToValue(s)
	}
}

type seenSet struct {
	ids map[string]bool
}

func newSeenSet() *seenSet {
	return &seenSet{ids: make(map[string]bool)}
}

func (s *seenSet) has(id string) bool { return s.ids[id] }
func (s *seenSet) mark(id string)     { s.ids[id] = true }
func (s *seenSet) unmark(id string)   { delete(s.ids, id) }

func inspectValue(rt *goja.Runtime, v goja.Value, depth int, seen *seenSet) string {
	if v == nil || goja.IsUndefined(v) {
		return "undefined"
	}
	if goja.IsNull(v) {
		return "null"
	}

	if obj, ok := v.(*goja.Object); ok {
		return inspectObject(rt, obj, depth, seen)
	}

	switch v.ExportType().String() {
	case "string":
		return fmt.Sprintf("'%s'", v.String())
	case "bool":
		if v.ToBoolean() {
			return "true"
		}
		return "false"
	}
	s := v.String()
	if s == "[object Undefined]" {
		return "undefined"
	}
	if s == "[object Null]" {
		return "null"
	}
	return s
}

func inspectObject(rt *goja.Runtime, obj *goja.Object, depth int, seen *seenSet) string {
	id := fmt.Sprintf("%p", obj)
	if seen.has(id) {
		return "[Circular]"
	}
	seen.mark(id)
	defer seen.unmark(id)

	if depth < 0 {
		return "[Object]"
	}

	if isArray(obj) {
		return inspectArray(rt, obj, depth, seen)
	}

	if isFunction(obj) {
		name := obj.Get("name")
		nm := ""
		if name != nil {
			nm = name.String()
		}
		if nm != "" {
			return fmt.Sprintf("[Function: %s]", nm)
		}
		return "[Function (anonymous)]"
	}

	keys := obj.Keys()
	if len(keys) == 0 {
		return "{}"
	}

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		v := obj.Get(k)
		parts = append(parts, fmt.Sprintf("'%s': %s", k, inspectValue(rt, v, depth-1, seen)))
	}
	return "{ " + strings.Join(parts, ", ") + " }"
}

func inspectArray(rt *goja.Runtime, obj *goja.Object, depth int, seen *seenSet) string {
	if depth < 0 {
		return "[Array]"
	}
	lenVal := obj.Get("length")
	if lenVal == nil || goja.IsUndefined(lenVal) {
		return "[]"
	}
	n := int(lenVal.ToInteger())
	if n == 0 {
		return "[]"
	}
	parts := make([]string, n)
	for i := range n {
		v := obj.Get(strconv.Itoa(i))
		parts[i] = inspectValue(rt, v, depth-1, seen)
	}
	return "[ " + strings.Join(parts, ", ") + " ]"
}

func isArray(obj *goja.Object) bool {
	return obj.ClassName() == "Array"
}

func isFunction(obj *goja.Object) bool {
	cn := obj.ClassName()
	return cn == "Function" || cn == "ArrowFunction" || cn == "GeneratorFunction"
}
