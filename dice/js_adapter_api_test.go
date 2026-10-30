package dice

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"Scardice-core/adapterapi"
	"Scardice-core/utils/jsengine"
)

func TestJSAdapterAPIKeepsCallerAcrossAwaitAndPreservesRawFrames(t *testing.T) {
	for _, engine := range []string{"goja", "quickjs"} {
		t.Run(engine, func(t *testing.T) {
			if engine == "quickjs" && os.Getenv("SCARDICE_RUNTIME_ROOT") == "" && os.Getenv("SCARDICE_QUICKJS_PACKAGE") == "" {
				t.Skip("native QuickJS package is not configured")
			}
			const name = "Adapter API caller ownership"
			script := `var adapterExt = seal.ext.new("Adapter API caller ownership", "test", "1.0.0");
adapterExt.onAdapterEvent = async function (ctx, event) {
  const first = await seal.adapter.callApi(event.endPoint, "vendor.first", { tag: event.body.tag });
  const raw = await seal.adapter.callApiRaw(event.endPoint.id,
    '{"action":"vendor.raw","echo":"caller-owned","params":{"id":9007199254740993},"vendor":{"decimal":1.2300e+04}}');
  recordAdapterAPI(first.status, first.vendor.tag, raw, ctx.group.groupId);
};
seal.ext.register(adapterExt);`
			runtime, peer := startOnebotPassthroughPeer(t)
			d, endpoint, _, _, loop := preparePublicPreprocessRuntime(t, engine, "test/adapter-api-ownership", name, script)
			if err := peer.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			d.ProviderCall = runtime
			if engine == "goja" {
				d.ProviderCall = &builtinProcessRuntime{transport: runtime}
			}
			scope, _ := adapterEventGroupScope(t, d, endpoint, name)
			type outcome struct {
				status, tag, raw, group string
				owned                   bool
			}
			outcomes := make(chan outcome, 1)
			if err := loop.Run(func(vm jsengine.Runtime) error {
				return vm.Bind("recordAdapterAPI", func(status, tag, raw, group string) {
					owner := jsExecutionContextFor(loop)
					owned := owner != nil && owner.Message == scope && owner.Plugin != nil && owner.Plugin.Name == name
					outcomes <- outcome{status: status, tag: tag, raw: raw, group: group, owned: owned}
				})
			}); err != nil {
				t.Fatal(err)
			}
			dispatched := make(chan error, 1)
			go func() {
				dispatched <- d.dispatchAdapterEvent(scope, scope, adapterapi.AdapterEvent{
					Protocol: "onebot11", Type: "notice", RawJSON: `{"post_type":"notice","tag":"caller-a"}`,
				}, endpoint)
			}()

			var first struct {
				Action string `json:"action"`
				Echo   string `json:"echo"`
				Params struct {
					Tag string `json:"tag"`
				} `json:"params"`
			}
			if err := peer.ReadJSON(&first); err != nil {
				t.Fatal(err)
			}
			if first.Action != "vendor.first" || first.Params.Tag != "caller-a" {
				t.Fatalf("unexpected first provider request: %#v", first)
			}
			// The provider has not answered. An unrelated owner entry must still
			// execute, and cannot become the resumed hook's message authority.
			ownerFree := make(chan error, 1)
			go func() { ownerFree <- loop.Run(func(jsengine.Runtime) error { return nil }) }()
			select {
			case err := <-ownerFree:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("adapter call blocked the JavaScript owner while waiting for the provider")
			}
			if err := peer.WriteJSON(map[string]any{
				"echo": first.Echo, "status": "failed", "retcode": 1404,
				"vendor": map[string]string{"tag": "complete-provider-response"},
			}); err != nil {
				t.Fatal(err)
			}
			var second struct {
				Action string                     `json:"action"`
				Echo   string                     `json:"echo"`
				Params map[string]json.RawMessage `json:"params"`
				Vendor map[string]json.RawMessage `json:"vendor"`
			}
			if err := peer.ReadJSON(&second); err != nil {
				t.Fatal(err)
			}
			if second.Action != "vendor.raw" || second.Echo == "" || second.Echo == "caller-owned" ||
				string(second.Params["id"]) != "9007199254740993" || string(second.Vendor["decimal"]) != "1.2300e+04" {
				t.Fatalf("raw provider envelope was corrupted: %#v", second)
			}
			wantRaw := fmt.Sprintf("{\n \"echo\":%q,\"status\":\"ok\",\"retcode\":0,\"vendor\":{\"id\":9007199254740993}\n}", second.Echo)
			if err := peer.WriteMessage(websocket.TextMessage, []byte(wantRaw)); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-dispatched:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("adapter hook did not join its returned Promise")
			}
			select {
			case got := <-outcomes:
				if got.status != "failed" || got.tag != "complete-provider-response" || got.raw != wantRaw ||
					got.group != scope.Group.GroupID || !got.owned {
					t.Fatalf("resumed adapter callback = %#v", got)
				}
			default:
				t.Fatal("hook Promise completed before its awaited work")
			}
		})
	}
}

func TestJSAdapterAPICanceledInvocationCannotResumeAfterLateResponse(t *testing.T) {
	const name = "Adapter API cancellation"
	script := `globalThis.__testAdapterResumed = false;
var adapterExt = seal.ext.new("Adapter API cancellation", "test", "1.0.0");
adapterExt.onAdapterEvent = async function (_ctx, event) {
  await seal.adapter.callApi(event.endPoint, "vendor.slow", {});
  globalThis.__testAdapterResumed = true;
};
seal.ext.register(adapterExt);`
	runtime, peer := startOnebotPassthroughPeer(t)
	d, endpoint, _, _, loop := preparePublicPreprocessRuntime(t, "goja", "test/adapter-api-cancellation", name, script)
	d.ProviderCall = runtime
	scope, _ := adapterEventGroupScope(t, d, endpoint, name)
	dispatched := make(chan error, 1)
	go func() {
		dispatched <- d.dispatchAdapterEvent(scope, scope, adapterapi.AdapterEvent{
			Protocol: "onebot11", Type: "notice", RawJSON: `{"post_type":"notice"}`,
		}, endpoint)
	}()
	var request struct {
		Echo string `json:"echo"`
	}
	if err := peer.ReadJSON(&request); err != nil {
		t.Fatal(err)
	}
	scope.releaseExecutionState()
	select {
	case err := <-dispatched:
		if err == nil {
			t.Fatal("canceled callback unexpectedly succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("canceled callback remained blocked on the provider")
	}
	if err := peer.WriteJSON(map[string]any{"echo": request.Echo, "status": "ok", "retcode": 0}); err != nil {
		t.Fatal(err)
	}
	if err := jsengine.RunWithContext(loop, nil, func(vm jsengine.Runtime) error {
		value, err := vm.RunString("adapter-cancel-result.js", "globalThis.__testAdapterResumed")
		if err != nil {
			return err
		}
		if value.ToBoolean() {
			return fmt.Errorf("late API response resumed a revoked invocation")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestOnebotDirectCallFailsWhenItsConnectionCloses(t *testing.T) {
	runtime, peer := startOnebotPassthroughPeer(t)
	finished := make(chan error, 1)
	go func() {
		_, err := runtime.CallAPI(context.Background(), adapterapi.AdapterCallRequest{
			EndpointID: "disconnect-test", RawJSON: `{"action":"vendor.no_reply"}`,
		})
		finished <- err
	}()
	var request map[string]json.RawMessage
	if err := peer.ReadJSON(&request); err != nil {
		t.Fatal(err)
	}
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("disconnected API call reported success")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("disconnected API call waited for the full echo timeout")
	}
}

func TestJSAdapterAPIDisabledAwaitStaysRevokedUntilCallerDeadline(t *testing.T) {
	for _, engine := range []string{"goja", "quickjs"} {
		t.Run(engine, func(t *testing.T) {
			if engine == "quickjs" && os.Getenv("SCARDICE_RUNTIME_ROOT") == "" && os.Getenv("SCARDICE_QUICKJS_PACKAGE") == "" {
				t.Skip("native QuickJS package is not configured")
			}
			const name = "Adapter API disabled await"
			script := `var ext = seal.ext.new("Adapter API disabled await", "test", "1.0.0");
globalThis.__testDisabledAdapterResumed = false;
ext.onAdapterEvent = async function (_ctx, event) {
  try { await seal.adapter.callApi(event.endPoint, "vendor.pending", {}); }
  finally { globalThis.__testDisabledAdapterResumed = true; }
};
seal.ext.register(ext);`
			runtime, peer := startOnebotPassthroughPeer(t)
			d, endpoint, _, _, loop := preparePublicPreprocessRuntime(t, engine, "test/adapter-disabled-await", name, script)
			d.ProviderCall = runtime
			scope, _ := adapterEventGroupScope(t, d, endpoint, name)
			deadline, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
			defer cancel()
			scope.executionContext = deadline
			dispatched := make(chan error, 1)
			go func() {
				dispatched <- d.dispatchAdapterEvent(scope, scope, adapterapi.AdapterEvent{
					Protocol: "onebot11", Type: "notice", RawJSON: `{"post_type":"notice"}`,
				}, endpoint)
			}()
			var request struct {
				Echo string `json:"echo"`
			}
			if err := peer.ReadJSON(&request); err != nil {
				t.Fatal(err)
			}
			extension, ok := d.JsExtRegistry.Load(name)
			if !ok || extension == nil || extension.Source == nil {
				t.Fatal("loaded extension has no script owner")
			}
			d.JsScriptList = append(d.JsScriptList, extension.Source)
			JsDisable(d, extension.Source.Name)
			if err := peer.WriteJSON(map[string]any{"echo": request.Echo, "status": "ok", "retcode": 0}); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-dispatched:
				if err == nil {
					t.Fatal("disabled invocation unexpectedly completed successfully")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("disabled invocation outlived its caller deadline")
			}
			if err := loop.Run(func(vm jsengine.Runtime) error {
				value, err := vm.RunString("disabled-adapter-state.js", "globalThis.__testDisabledAdapterResumed")
				if err != nil {
					return err
				}
				if value.ToBoolean() {
					return fmt.Errorf("disabled plugin continuation or finally resumed")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
