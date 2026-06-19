package sealhttp

import (
	"strconv"
	"strings"

	"github.com/dop251/goja"
)

func Enable(rt *goja.Runtime) {
	_ = rt.Set("Headers", newHeadersCtor(rt))
	_ = rt.Set("Request", newRequestCtor(rt))
	_ = rt.Set("Response", newResponseCtor(rt))
	_ = rt.Set("FormData", newFormDataCtor(rt))
}

func Require(rt *goja.Runtime, module *goja.Object) {
	exports := module.Get("exports").(*goja.Object)
	_ = exports.Set("Headers", newHeadersCtor(rt))
	_ = exports.Set("Request", newRequestCtor(rt))
	_ = exports.Set("Response", newResponseCtor(rt))
	_ = exports.Set("FormData", newFormDataCtor(rt))
}

type headersData struct {
	store map[string][]string
}

func newHeadersData() *headersData {
	return &headersData{store: make(map[string][]string)}
}

func (h *headersData) normalize(key string) string {
	return strings.ToLower(strings.TrimSpace(key))
}

func (h *headersData) get(key string) string {
	k := h.normalize(key)
	if vals, ok := h.store[k]; ok && len(vals) > 0 {
		return strings.Join(vals, ", ")
	}
	return ""
}

func (h *headersData) set(key, val string) {
	h.store[h.normalize(key)] = []string{val}
}

func (h *headersData) append(key, val string) {
	k := h.normalize(key)
	h.store[k] = append(h.store[k], val)
}

func (h *headersData) has(key string) bool {
	_, ok := h.store[h.normalize(key)]
	return ok
}

func (h *headersData) delete(key string) {
	delete(h.store, h.normalize(key))
}

func (h *headersData) forEach(fn goja.Value, rt *goja.Runtime) {
	cb, ok := goja.AssertFunction(fn)
	if !ok {
		return
	}
	for k, vals := range h.store {
		v := strings.Join(vals, ", ")
		_, _ = cb(goja.Undefined(), rt.ToValue(v), rt.ToValue(k), goja.Undefined())
	}
}

func (h *headersData) keys() []string {
	keys := make([]string, 0, len(h.store))
	for k := range h.store {
		keys = append(keys, k)
	}
	return keys
}

func (h *headersData) values() []string {
	vals := make([]string, 0, len(h.store))
	for _, v := range h.store {
		vals = append(vals, strings.Join(v, ", "))
	}
	return vals
}

func (h *headersData) entries() [][2]string {
	entries := make([][2]string, 0, len(h.store))
	for k, v := range h.store {
		entries = append(entries, [2]string{k, strings.Join(v, ", ")})
	}
	return entries
}

func newHeadersCtor(rt *goja.Runtime) func(call goja.ConstructorCall) *goja.Object {
	return func(call goja.ConstructorCall) *goja.Object {
		data := newHeadersData()
		obj := call.This
		bindHeaders(rt, obj, data)

		if init := call.Argument(0); !goja.IsUndefined(init) && !goja.IsNull(init) {
			fillHeaders(rt, data, init)
		}
		return obj
	}
}

func bindHeaders(rt *goja.Runtime, obj *goja.Object, data *headersData) {
	_ = obj.Set("get", func(call goja.FunctionCall) goja.Value {
		return rt.ToValue(data.get(call.Argument(0).String()))
	})
	_ = obj.Set("set", func(call goja.FunctionCall) goja.Value {
		data.set(call.Argument(0).String(), call.Argument(1).String())
		return goja.Undefined()
	})
	_ = obj.Set("append", func(call goja.FunctionCall) goja.Value {
		data.append(call.Argument(0).String(), call.Argument(1).String())
		return goja.Undefined()
	})
	_ = obj.Set("has", func(call goja.FunctionCall) goja.Value {
		return rt.ToValue(data.has(call.Argument(0).String()))
	})
	_ = obj.Set("delete", func(call goja.FunctionCall) goja.Value {
		data.delete(call.Argument(0).String())
		return goja.Undefined()
	})
	_ = obj.Set("forEach", func(call goja.FunctionCall) goja.Value {
		data.forEach(call.Argument(0), rt)
		return goja.Undefined()
	})
	_ = obj.Set("keys", func(call goja.FunctionCall) goja.Value {
		return rt.ToValue(data.keys())
	})
	_ = obj.Set("values", func(call goja.FunctionCall) goja.Value {
		return rt.ToValue(data.values())
	})
	_ = obj.Set("entries", func(call goja.FunctionCall) goja.Value {
		entries := data.entries()
		arr := make([][]string, len(entries))
		for i, e := range entries {
			arr[i] = []string{e[0], e[1]}
		}
		return rt.ToValue(arr)
	})
}

func fillHeaders(rt *goja.Runtime, data *headersData, init goja.Value) {
	if obj, ok := init.(*goja.Object); ok {
		if obj.ClassName() == "Array" {
			n := int(obj.Get("length").ToInteger())
			for i := range n {
				entry := obj.Get(strconv.Itoa(i)).ToObject(rt)
				k := entry.Get("0").String()
				v := entry.Get("1").String()
				data.append(k, v)
			}
		} else {
			for _, k := range obj.Keys() {
				data.set(k, obj.Get(k).String())
			}
		}
	}
}

type formDataEntry struct {
	name     string
	value    string
	filename string
	isFile   bool
}

type formDataData struct {
	entries []formDataEntry
}

func newFormDataCtor(rt *goja.Runtime) func(call goja.ConstructorCall) *goja.Object {
	return func(call goja.ConstructorCall) *goja.Object {
		data := &formDataData{}
		obj := call.This
		bindFormData(rt, obj, data)
		return obj
	}
}

func bindFormData(rt *goja.Runtime, obj *goja.Object, data *formDataData) {
	_ = obj.Set("append", func(call goja.FunctionCall) goja.Value {
		name := call.Argument(0).String()
		value := call.Argument(1).String()
		filename := ""
		isFile := false
		if arg2 := call.Argument(2); !goja.IsUndefined(arg2) && !goja.IsNull(arg2) {
			filename = arg2.String()
			isFile = true
		}
		data.entries = append(data.entries, formDataEntry{name: name, value: value, filename: filename, isFile: isFile})
		return goja.Undefined()
	})
	_ = obj.Set("set", func(call goja.FunctionCall) goja.Value {
		name := call.Argument(0).String()
		value := call.Argument(1).String()
		filename := ""
		isFile := false
		if arg2 := call.Argument(2); !goja.IsUndefined(arg2) && !goja.IsNull(arg2) {
			filename = arg2.String()
			isFile = true
		}
		filtered := data.entries[:0]
		for _, e := range data.entries {
			if e.name != name {
				filtered = append(filtered, e)
			}
		}
		filtered = append(filtered, formDataEntry{name: name, value: value, filename: filename, isFile: isFile})
		data.entries = filtered
		return goja.Undefined()
	})
	_ = obj.Set("get", func(call goja.FunctionCall) goja.Value {
		name := call.Argument(0).String()
		for _, e := range data.entries {
			if e.name == name {
				return rt.ToValue(e.value)
			}
		}
		return goja.Undefined()
	})
	_ = obj.Set("getAll", func(call goja.FunctionCall) goja.Value {
		name := call.Argument(0).String()
		var vals []string
		for _, e := range data.entries {
			if e.name == name {
				vals = append(vals, e.value)
			}
		}
		return rt.ToValue(vals)
	})
	_ = obj.Set("has", func(call goja.FunctionCall) goja.Value {
		name := call.Argument(0).String()
		for _, e := range data.entries {
			if e.name == name {
				return rt.ToValue(true)
			}
		}
		return rt.ToValue(false)
	})
	_ = obj.Set("delete", func(call goja.FunctionCall) goja.Value {
		name := call.Argument(0).String()
		filtered := data.entries[:0]
		for _, e := range data.entries {
			if e.name != name {
				filtered = append(filtered, e)
			}
		}
		data.entries = filtered
		return goja.Undefined()
	})
	_ = obj.Set("forEach", func(call goja.FunctionCall) goja.Value {
		cb, ok := goja.AssertFunction(call.Argument(0))
		if !ok {
			return goja.Undefined()
		}
		for _, e := range data.entries {
			_, _ = cb(goja.Undefined(), rt.ToValue(e.value), rt.ToValue(e.name), goja.Undefined())
		}
		return goja.Undefined()
	})
	_ = obj.Set("keys", func(call goja.FunctionCall) goja.Value {
		var keys []string
		for _, e := range data.entries {
			keys = append(keys, e.name)
		}
		return rt.ToValue(keys)
	})
	_ = obj.Set("values", func(call goja.FunctionCall) goja.Value {
		var vals []string
		for _, e := range data.entries {
			vals = append(vals, e.value)
		}
		return rt.ToValue(vals)
	})
	_ = obj.Set("entries", func(call goja.FunctionCall) goja.Value {
		var entries [][]string
		for _, e := range data.entries {
			entries = append(entries, []string{e.name, e.value})
		}
		return rt.ToValue(entries)
	})
}

type requestData struct {
	url      string
	method   string
	headers  *headersData
	body     goja.Value
	mode     string
	cred     string
	cache    string
	redirect string
}

func newRequestCtor(rt *goja.Runtime) func(call goja.ConstructorCall) *goja.Object {
	return func(call goja.ConstructorCall) *goja.Object {
		data := &requestData{
			method:   "GET",
			headers:  newHeadersData(),
			mode:     "cors",
			cred:     "same-origin",
			cache:    "default",
			redirect: "follow",
		}
		obj := call.This

		if url := call.Argument(0); !goja.IsUndefined(url) {
			data.url = url.String()
		}
		if init := call.Argument(1); !goja.IsUndefined(init) && !goja.IsNull(init) {
			if initObj, ok := init.(*goja.Object); ok {
				if m := initObj.Get("method"); m != nil && !goja.IsUndefined(m) {
					data.method = strings.ToUpper(m.String())
				}
				if h := initObj.Get("headers"); h != nil && !goja.IsUndefined(h) {
					fillHeaders(rt, data.headers, h)
				}
				if b := initObj.Get("body"); b != nil && !goja.IsUndefined(b) {
					data.body = b
				}
				if m := initObj.Get("mode"); m != nil && !goja.IsUndefined(m) {
					data.mode = m.String()
				}
				if c := initObj.Get("credentials"); c != nil && !goja.IsUndefined(c) {
					data.cred = c.String()
				}
				if c := initObj.Get("cache"); c != nil && !goja.IsUndefined(c) {
					data.cache = c.String()
				}
				if r := initObj.Get("redirect"); r != nil && !goja.IsUndefined(r) {
					data.redirect = r.String()
				}
			}
		}

		_ = obj.Set("url", data.url)
		_ = obj.Set("method", data.method)
		_ = obj.Set("mode", data.mode)
		_ = obj.Set("credentials", data.cred)
		_ = obj.Set("cache", data.cache)
		_ = obj.Set("redirect", data.redirect)
		headersObj := rt.NewObject()
		bindHeaders(rt, headersObj, data.headers)
		_ = obj.Set("headers", headersObj)
		_ = obj.Set("body", data.body)

		return obj
	}
}

type responseData struct {
	status     int
	statusText string
	headers    *headersData
	body       goja.Value
}

func newResponseCtor(rt *goja.Runtime) func(call goja.ConstructorCall) *goja.Object {
	return func(call goja.ConstructorCall) *goja.Object {
		data := &responseData{
			status:     200,
			statusText: "OK",
			headers:    newHeadersData(),
		}
		obj := call.This

		if body := call.Argument(0); !goja.IsUndefined(body) && !goja.IsNull(body) {
			data.body = body
		}
		if init := call.Argument(1); !goja.IsUndefined(init) && !goja.IsNull(init) {
			if initObj, ok := init.(*goja.Object); ok {
				if s := initObj.Get("status"); s != nil && !goja.IsUndefined(s) {
					data.status = int(s.ToInteger())
				}
				if st := initObj.Get("statusText"); st != nil && !goja.IsUndefined(st) {
					data.statusText = st.String()
				}
				if h := initObj.Get("headers"); h != nil && !goja.IsUndefined(h) {
					fillHeaders(rt, data.headers, h)
				}
			}
		}

		_ = obj.Set("status", data.status)
		_ = obj.Set("statusText", data.statusText)
		_ = obj.Set("ok", data.status >= 200 && data.status < 300)
		headersObj := rt.NewObject()
		bindHeaders(rt, headersObj, data.headers)
		_ = obj.Set("headers", headersObj)

		_ = obj.Set("text", func(call goja.FunctionCall) goja.Value {
			p, resolve, _ := rt.NewPromise()
			body := ""
			if data.body != nil {
				body = data.body.String()
			}
			_ = resolve(rt.ToValue(body))
			return rt.ToValue(p)
		})

		_ = obj.Set("json", func(call goja.FunctionCall) goja.Value {
			p, resolve, reject := rt.NewPromise()
			if data.body == nil {
				_ = reject(rt.NewTypeError("no body"))
				return rt.ToValue(p)
			}
			raw := data.body.String()
			jsonObj := rt.Get("JSON").ToObject(rt)
			parse, _ := goja.AssertFunction(jsonObj.Get("parse"))
			if parsed, err := parse(goja.Undefined(), rt.ToValue(raw)); err == nil {
				_ = resolve(parsed)
			} else {
				_ = reject(err)
			}
			return rt.ToValue(p)
		})

		_ = obj.Set("arrayBuffer", func(call goja.FunctionCall) goja.Value {
			p, resolve, _ := rt.NewPromise()
			var bytes []byte
			if data.body != nil {
				bytes = []byte(data.body.String())
			}
			_ = resolve(rt.ToValue(rt.NewArrayBuffer(bytes)))
			return rt.ToValue(p)
		})

		return obj
	}
}
