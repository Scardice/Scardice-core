package sealhttp

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/buffer"
	"github.com/dop251/goja_nodejs/eventloop"
	"github.com/dop251/goja_nodejs/url"

	sealabort "Scardice-core/utils/plugin/abort"
)

func startHTTPExtraTestLoop(t *testing.T) *eventloop.EventLoop {
	t.Helper()
	loop := eventloop.NewEventLoop(eventloop.EnableConsole(false))
	go loop.StartInForeground()
	runHTTPExtraLoopSync(t, loop, func(_ *goja.Runtime) {})
	t.Cleanup(func() {
		loop.Stop()
	})
	return loop
}

func runHTTPExtraLoopSync(t *testing.T, loop *eventloop.EventLoop, f func(*goja.Runtime)) {
	t.Helper()
	done := make(chan struct{})
	var recovered any
	loop.RunOnLoop(func(vm *goja.Runtime) {
		defer close(done)
		defer func() {
			recovered = recover()
		}()
		f(vm)
	})
	<-done
	if recovered != nil {
		t.Fatalf("panic in JS event loop test callback: %v", recovered)
	}
}

func waitHTTPExtraLoopBool(t *testing.T, loop *eventloop.EventLoop, name string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if httpExtraLoopBool(t, loop, name) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", name)
}

func httpExtraLoopBool(t *testing.T, loop *eventloop.EventLoop, name string) bool {
	t.Helper()
	var result bool
	runHTTPExtraLoopSync(t, loop, func(vm *goja.Runtime) {
		value := vm.Get(name)
		if value == nil || goja.IsUndefined(value) || goja.IsNull(value) {
			return
		}
		result = value.ToBoolean()
	})
	return result
}

func httpExtraLoopString(t *testing.T, loop *eventloop.EventLoop, name string) string {
	t.Helper()
	var result string
	runHTTPExtraLoopSync(t, loop, func(vm *goja.Runtime) {
		value := vm.Get(name)
		if value == nil || goja.IsUndefined(value) || goja.IsNull(value) {
			return
		}
		result = value.String()
	})
	return result
}

func TestFetchTextJSONAndArrayBuffer(t *testing.T) {
	loop := startHTTPExtraTestLoop(t)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte{'{', '"', 'o', 'k', '"', ':', 't', 'r', 'u', 'e', ',', '"', 'b', 'i', 'n', '"', ':', '[', '0', ',', '1', '2', '8', ',', '2', '5', '5', ']', '}'})
	})

	runHTTPExtraLoopSync(t, loop, func(vm *goja.Runtime) {
		Enable(vm)
		if err := EnableFetch(vm, loop, handler); err != nil {
			t.Fatalf("EnableFetch failed: %v", err)
		}
		_, err := vm.RunString(`
			globalThis.__done = false;
			globalThis.__err = "";
			(async () => {
				try {
					const response = await fetch("https://example.test/data?b=2&a=1");
					const text = await response.text();
					const json = await response.json();
					const arrayBuffer = await response.arrayBuffer();
					const bytes = new Uint8Array(arrayBuffer);
					let byteText = "";
					for (let i = 0; i < bytes.length; i++) {
						if (i > 0) byteText += ",";
						byteText += String(bytes[i]);
					}
					globalThis.__status = String(response.status);
					globalThis.__ok = String(response.ok);
					globalThis.__contentType = response.headers.get("content-type");
					globalThis.__jsonOK = String(json.ok);
					globalThis.__text = text;
					globalThis.__bytes = byteText;
				} catch (e) {
					globalThis.__err = String(e && e.stack || e);
				} finally {
					globalThis.__done = true;
				}
			})();
		`)
		if err != nil {
			t.Fatalf("run fetch script failed: %v", err)
		}
	})

	waitHTTPExtraLoopBool(t, loop, "__done")
	if errText := httpExtraLoopString(t, loop, "__err"); errText != "" {
		t.Fatalf("fetch script failed: %s", errText)
	}
	if got := httpExtraLoopString(t, loop, "__status"); got != "200" {
		t.Fatalf("unexpected status: %s", got)
	}
	if got := httpExtraLoopString(t, loop, "__ok"); got != "true" {
		t.Fatalf("unexpected ok: %s", got)
	}
	if got := httpExtraLoopString(t, loop, "__contentType"); got != "application/json" {
		t.Fatalf("unexpected content-type: %s", got)
	}
	if got := httpExtraLoopString(t, loop, "__jsonOK"); got != "true" {
		t.Fatalf("unexpected json ok: %s", got)
	}
	if got := httpExtraLoopString(t, loop, "__bytes"); got != "123,34,111,107,34,58,116,114,117,101,44,34,98,105,110,34,58,91,48,44,49,50,56,44,50,53,53,93,125" {
		t.Fatalf("unexpected arrayBuffer bytes: %s", got)
	}
	if !strings.Contains(httpExtraLoopString(t, loop, "__text"), `"bin":[0,128,255]`) {
		t.Fatalf("unexpected text: %s", httpExtraLoopString(t, loop, "__text"))
	}
}

func TestFetchPostBodyAndHeaders(t *testing.T) {
	loop := startHTTPExtraTestLoop(t)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		w.Header().Set("X-Seal-Method", r.Method)
		_, _ = fmt.Fprintf(w, "%s|%s", r.Header.Get("X-Test"), string(body))
	})

	runHTTPExtraLoopSync(t, loop, func(vm *goja.Runtime) {
		Enable(vm)
		if err := EnableFetch(vm, loop, handler); err != nil {
			t.Fatalf("EnableFetch failed: %v", err)
		}
		_, err := vm.RunString(`
			globalThis.__done = false;
			globalThis.__err = "";
			fetch("https://example.test/post", {
				method: "POST",
				headers: { "X-Test": "header-ok" },
				body: "payload-ok"
			}).then(response => response.text()).then(text => {
				globalThis.__result = text;
			}).catch(e => {
				globalThis.__err = String(e && e.stack || e);
			}).finally(() => {
				globalThis.__done = true;
			});
		`)
		if err != nil {
			t.Fatalf("run fetch script failed: %v", err)
		}
	})

	waitHTTPExtraLoopBool(t, loop, "__done")
	if errText := httpExtraLoopString(t, loop, "__err"); errText != "" {
		t.Fatalf("fetch script failed: %s", errText)
	}
	if got := httpExtraLoopString(t, loop, "__result"); got != "header-ok|payload-ok" {
		t.Fatalf("unexpected post result: %s", got)
	}
}

func TestFetchPreservesExplicitConnectionHeader(t *testing.T) {
	loop := startHTTPExtraTestLoop(t)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Header.Get("Connection"))
	})

	runHTTPExtraLoopSync(t, loop, func(vm *goja.Runtime) {
		Enable(vm)
		if err := EnableFetch(vm, loop, handler); err != nil {
			t.Fatalf("EnableFetch failed: %v", err)
		}
		_, err := vm.RunString(`
			globalThis.__done = false;
			globalThis.__err = "";
			fetch("https://example.test/connection", {
				headers: { "Connection": "keep-alive" }
			}).then(response => response.text()).then(text => {
				globalThis.__result = text;
			}).catch(e => {
				globalThis.__err = String(e && e.stack || e);
			}).finally(() => {
				globalThis.__done = true;
			});
		`)
		if err != nil {
			t.Fatalf("run connection header fetch script failed: %v", err)
		}
	})

	waitHTTPExtraLoopBool(t, loop, "__done")
	if errText := httpExtraLoopString(t, loop, "__err"); errText != "" {
		t.Fatalf("fetch script failed: %s", errText)
	}
	if got := httpExtraLoopString(t, loop, "__result"); got != "keep-alive" {
		t.Fatalf("unexpected connection header: %s", got)
	}
}

func TestFetchRejectsRequestConstructionError(t *testing.T) {
	loop := startHTTPExtraTestLoop(t)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("handler should not be called for invalid request method")
	})

	runHTTPExtraLoopSync(t, loop, func(vm *goja.Runtime) {
		Enable(vm)
		if err := EnableFetch(vm, loop, handler); err != nil {
			t.Fatalf("EnableFetch failed: %v", err)
		}
		_, err := vm.RunString(`
			globalThis.__done = false;
			globalThis.__err = "";
			fetch("https://example.test/bad-method", {
				method: "BAD METHOD"
			}).then(response => {
				globalThis.__result = "resolved:" + String(response.status);
			}).catch(e => {
				globalThis.__result = "rejected:" + String(e);
			}).finally(() => {
				globalThis.__done = true;
			});
		`)
		if err != nil {
			t.Fatalf("run request construction error fetch script failed: %v", err)
		}
	})

	waitHTTPExtraLoopBool(t, loop, "__done")
	if errText := httpExtraLoopString(t, loop, "__err"); errText != "" {
		t.Fatalf("fetch script failed: %s", errText)
	}
	got := httpExtraLoopString(t, loop, "__result")
	if !strings.HasPrefix(got, "rejected:") {
		t.Fatalf("expected rejection, got: %s", got)
	}
}

func TestResponseArrayBufferFromTypedArray(t *testing.T) {
	vm := goja.New()
	Enable(vm)

	value, err := vm.RunString(`new Response(new Uint8Array([0, 128, 255])).arrayBuffer()`)
	if err != nil {
		t.Fatalf("run Response.arrayBuffer script failed: %v", err)
	}
	promise, ok := value.Export().(*goja.Promise)
	if !ok {
		t.Fatalf("expected Promise, got %T", value.Export())
	}
	if promise.State() != goja.PromiseStateFulfilled {
		t.Fatalf("promise not fulfilled, state=%v result=%v", promise.State(), promise.Result())
	}
	arrayBuffer, ok := promise.Result().Export().(goja.ArrayBuffer)
	if !ok {
		t.Fatalf("expected ArrayBuffer, got %T", promise.Result().Export())
	}
	got := arrayBuffer.Bytes()
	want := []byte{0, 128, 255}
	if len(got) != len(want) {
		t.Fatalf("unexpected arrayBuffer length: %d", len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected arrayBuffer byte %d: got %d want %d", i, got[i], want[i])
		}
	}
}

func TestResponseTextFromPlainArrayUsesStringCoercion(t *testing.T) {
	vm := goja.New()
	Enable(vm)

	value, err := vm.RunString(`new Response([1, 2, 3]).text()`)
	if err != nil {
		t.Fatalf("run Response.text script failed: %v", err)
	}
	promise, ok := value.Export().(*goja.Promise)
	if !ok {
		t.Fatalf("expected Promise, got %T", value.Export())
	}
	if promise.State() != goja.PromiseStateFulfilled {
		t.Fatalf("promise not fulfilled, state=%v result=%v", promise.State(), promise.Result())
	}
	if got := promise.Result().String(); got != "1,2,3" {
		t.Fatalf("unexpected plain array text: %q", got)
	}
}

func TestFetchURLSearchParamsBody(t *testing.T) {
	loop := startHTTPExtraTestLoop(t)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		_, _ = fmt.Fprintf(w, "%s|%s", r.Header.Get("Content-Type"), string(body))
	})

	runHTTPExtraLoopSync(t, loop, func(vm *goja.Runtime) {
		url.Enable(vm)
		Enable(vm)
		if err := EnableFetch(vm, loop, handler); err != nil {
			t.Fatalf("EnableFetch failed: %v", err)
		}
		_, err := vm.RunString(`
			globalThis.__done = false;
			globalThis.__err = "";
			(async () => {
				try {
					const params = new URLSearchParams();
					params.append("a", "1");
					params.append("b", "hello world");
					globalThis.__result = await (await fetch("https://example.test/form", {
						method: "POST",
						body: params
					})).text();
				} catch (e) {
					globalThis.__err = String(e && e.stack || e);
				} finally {
					globalThis.__done = true;
				}
			})();
		`)
		if err != nil {
			t.Fatalf("run URLSearchParams fetch script failed: %v", err)
		}
	})

	waitHTTPExtraLoopBool(t, loop, "__done")
	if errText := httpExtraLoopString(t, loop, "__err"); errText != "" {
		t.Fatalf("fetch script failed: %s", errText)
	}
	got := httpExtraLoopString(t, loop, "__result")
	if !strings.HasPrefix(got, "application/x-www-form-urlencoded;charset=UTF-8|") {
		t.Fatalf("unexpected content-type/body: %s", got)
	}
	if !strings.Contains(got, "a=1&b=hello+world") {
		t.Fatalf("unexpected URLSearchParams body: %s", got)
	}
}

func TestFetchFormDataBody(t *testing.T) {
	loop := startHTTPExtraTestLoop(t)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		_, _ = fmt.Fprintf(w, "%s|%s", r.Header.Get("Content-Type"), string(body))
	})

	runHTTPExtraLoopSync(t, loop, func(vm *goja.Runtime) {
		Enable(vm)
		if err := EnableFetch(vm, loop, handler); err != nil {
			t.Fatalf("EnableFetch failed: %v", err)
		}
		_, err := vm.RunString(`
			globalThis.__done = false;
			globalThis.__err = "";
			(async () => {
				try {
					const form = new FormData();
					form.append("name", "seal");
					form.append("file", "file-body", "note.txt");
					globalThis.__result = await (await fetch("https://example.test/upload", {
						method: "POST",
						body: form
					})).text();
				} catch (e) {
					globalThis.__err = String(e && e.stack || e);
				} finally {
					globalThis.__done = true;
				}
			})();
		`)
		if err != nil {
			t.Fatalf("run FormData fetch script failed: %v", err)
		}
	})

	waitHTTPExtraLoopBool(t, loop, "__done")
	if errText := httpExtraLoopString(t, loop, "__err"); errText != "" {
		t.Fatalf("fetch script failed: %s", errText)
	}
	got := httpExtraLoopString(t, loop, "__result")
	for _, want := range []string{
		"multipart/form-data; boundary=",
		`name="name"`,
		"seal",
		`name="file"; filename="note.txt"`,
		"file-body",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("FormData result missing %q: %s", want, got)
		}
	}
}

func TestFetchBinaryRequestBodies(t *testing.T) {
	loop := startHTTPExtraTestLoop(t)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		parts := make([]string, len(body))
		for i, b := range body {
			parts[i] = strconv.Itoa(int(b))
		}
		_, _ = io.WriteString(w, strings.Join(parts, ","))
	})

	runHTTPExtraLoopSync(t, loop, func(vm *goja.Runtime) {
		buffer.Enable(vm)
		Enable(vm)
		if err := EnableFetch(vm, loop, handler); err != nil {
			t.Fatalf("EnableFetch failed: %v", err)
		}
		_, err := vm.RunString(`
			globalThis.__done = false;
			globalThis.__err = "";
			(async () => {
				try {
					const typed = await (await fetch("https://example.test/typed", {
						method: "POST",
						body: new Uint8Array([0, 128, 255])
					})).text();
					const buffer = await (await fetch("https://example.test/buffer", {
						method: "POST",
						body: Buffer.from([1, 2, 250])
					})).text();
					globalThis.__result = typed + "|" + buffer;
				} catch (e) {
					globalThis.__err = String(e && e.stack || e);
				} finally {
					globalThis.__done = true;
				}
			})();
		`)
		if err != nil {
			t.Fatalf("run binary fetch script failed: %v", err)
		}
	})

	waitHTTPExtraLoopBool(t, loop, "__done")
	if errText := httpExtraLoopString(t, loop, "__err"); errText != "" {
		t.Fatalf("fetch script failed: %s", errText)
	}
	if got := httpExtraLoopString(t, loop, "__result"); got != "0,128,255|1,2,250" {
		t.Fatalf("unexpected binary body result: %s", got)
	}
}

func TestFetchAbortSignalCancelsRequest(t *testing.T) {
	loop := startHTTPExtraTestLoop(t)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})

	runHTTPExtraLoopSync(t, loop, func(vm *goja.Runtime) {
		sealabort.Enable(vm)
		Enable(vm)
		if err := EnableFetch(vm, loop, handler); err != nil {
			t.Fatalf("EnableFetch failed: %v", err)
		}
		_, err := vm.RunString(`
			globalThis.__done = false;
			globalThis.__err = "";
			(async () => {
				const controller = new AbortController();
				const request = fetch("https://example.test/slow", { signal: controller.signal })
					.then(() => { globalThis.__result = "resolved"; })
					.catch((e) => { globalThis.__result = String(e); });
				setTimeout(() => controller.abort("abort-ok"), 10);
				try {
					await request;
				} catch (e) {
					globalThis.__err = String(e && e.stack || e);
				} finally {
					globalThis.__done = true;
				}
			})();
		`)
		if err != nil {
			t.Fatalf("run abort fetch script failed: %v", err)
		}
	})

	waitHTTPExtraLoopBool(t, loop, "__done")
	if errText := httpExtraLoopString(t, loop, "__err"); errText != "" {
		t.Fatalf("fetch script failed: %s", errText)
	}
	if got := httpExtraLoopString(t, loop, "__result"); got != "abort-ok" {
		t.Fatalf("unexpected abort result: %s", got)
	}
}
