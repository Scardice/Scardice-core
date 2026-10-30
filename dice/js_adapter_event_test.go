package dice

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/utils/jsengine"
)

type adapterEventTestHit struct {
	label       string
	contextKind string
	eventType   string
	protocol    string
	rawJSON     string
	endpointID  string
	bodyValue   string
}

func bindAdapterEventTestRecorder(t *testing.T, loop jsengine.Loop) <-chan adapterEventTestHit {
	t.Helper()
	hits := make(chan adapterEventTestHit, 16)
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		return runtime.Bind("recordAdapterEvent", func(label, contextKind, eventType, protocol, rawJSON, endpointID, bodyValue string) {
			hits <- adapterEventTestHit{
				label: label, contextKind: contextKind, eventType: eventType, protocol: protocol,
				rawJSON: rawJSON, endpointID: endpointID, bodyValue: bodyValue,
			}
		})
	}); err != nil {
		t.Fatal(err)
	}
	return hits
}

func requireAdapterEventHit(t *testing.T, hits <-chan adapterEventTestHit) adapterEventTestHit {
	t.Helper()
	select {
	case hit := <-hits:
		return hit
	default:
		t.Fatal("adapter event callback did not run")
		return adapterEventTestHit{}
	}
}

func requireNoAdapterEventHit(t *testing.T, hits <-chan adapterEventTestHit) {
	t.Helper()
	select {
	case hit := <-hits:
		t.Fatalf("unexpected adapter event callback: %#v", hit)
	default:
	}
}

func adapterEventGroupScope(t *testing.T, d *Dice, endpoint *EndPointInfo, extensionNames ...string) (*MsgContext, *GroupInfo) {
	t.Helper()
	setup := &MsgContext{Dice: d, Session: d.ImSession, EndPoint: endpoint}
	group := SetBotOnAtGroup(setup, "QQ-Group:adapter-event-test")
	wrappers := make([]*ExtInfo, 0, len(extensionNames))
	for _, name := range extensionNames {
		wrapper := d.ExtFind(name, false)
		if wrapper == nil {
			t.Fatalf("registered extension %q is unavailable", name)
		}
		wrappers = append(wrappers, wrapper)
	}
	group.SetActivatedExtList(wrappers, d)
	scope := &MsgContext{
		Dice: d, Session: d.ImSession, EndPoint: endpoint, Group: group,
		MessageType: "group", IsCurGroupBotOn: true,
	}
	t.Cleanup(scope.releaseExecutionState)
	return scope, group
}

func TestJSAdapterEventFilterDefaultNullEmptyAndExplicitAll(t *testing.T) {
	const (
		packageID     = "test/adapter-event-defaults"
		extensionName = "Adapter event defaults"
	)
	script := `var adapterEventExt = seal.ext.new("Adapter event defaults", "test", "1.0.0");
adapterEventExt.onAdapterEvent = function (ctx, event) {
  recordAdapterEvent("default", ctx === null ? "null" : "ctx", event.type, event.protocol,
    event.rawJson, event.endPoint.id, typeof event.body.code + ":" + String(event.body.code));
};
seal.ext.register(adapterEventExt);`
	d, endpoint, _, _, loop := preparePublicPreprocessRuntime(t, string(jsengine.EngineGoja), packageID, extensionName, script)
	hits := bindAdapterEventTestRecorder(t, loop)
	scope, _ := adapterEventGroupScope(t, d, endpoint, extensionName)

	message := adapterapi.AdapterEvent{Protocol: "onebot11", Type: "message", RawJSON: `{"post_type":"message","code":1}`}
	if err := d.dispatchAdapterEvent(scope, scope, message, endpoint); err != nil {
		t.Fatal(err)
	}
	requireNoAdapterEventHit(t, hits)

	rawNotice := " {\n  \"post_type\": \"notice\", \"code\": 9007199254740993\n} "
	notice := adapterapi.AdapterEvent{Protocol: "onebot11", Type: "notice", RawJSON: rawNotice}
	if err := d.dispatchAdapterEvent(scope, scope, notice, endpoint); err != nil {
		t.Fatal(err)
	}
	hit := requireAdapterEventHit(t, hits)
	if hit.contextKind != "ctx" || hit.eventType != "notice" || hit.protocol != "onebot11" || hit.rawJSON != rawNotice || hit.endpointID != endpoint.ID || !strings.HasPrefix(hit.bodyValue, "number:") {
		t.Fatalf("default notice view = %#v", hit)
	}

	if err := loop.Run(func(runtime jsengine.Runtime) error {
		_, err := runtime.RunString("adapter-filter-null.js", `seal.ext.find("Adapter event defaults").adapterEventFilter = null`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := d.dispatchAdapterEvent(scope, scope, notice, endpoint); err != nil {
		t.Fatal(err)
	}
	requireAdapterEventHit(t, hits)

	if err := loop.Run(func(runtime jsengine.Runtime) error {
		_, err := runtime.RunString("adapter-filter-empty.js", `seal.ext.find("Adapter event defaults").adapterEventFilter = {}`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := d.dispatchAdapterEvent(scope, scope, notice, endpoint); err != nil {
		t.Fatal(err)
	}
	requireAdapterEventHit(t, hits)

	if err := loop.Run(func(runtime jsengine.Runtime) error {
		_, err := runtime.RunString("adapter-filter-events.js", `seal.ext.find("Adapter event defaults").adapterEventFilter = { events: ["message"] }`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := d.dispatchAdapterEvent(scope, scope, notice, endpoint); err != nil {
		t.Fatal(err)
	}
	requireNoAdapterEventHit(t, hits)
	if err := d.dispatchAdapterEvent(scope, scope, message, endpoint); err != nil {
		t.Fatal(err)
	}
	requireAdapterEventHit(t, hits)

	if err := loop.Run(func(runtime jsengine.Runtime) error {
		_, err := runtime.RunString("adapter-filter-none.js", `seal.ext.find("Adapter event defaults").adapterEventFilter = { events: [] }`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := d.dispatchAdapterEvent(scope, scope, notice, endpoint); err != nil {
		t.Fatal(err)
	}
	requireNoAdapterEventHit(t, hits)

	if err := loop.Run(func(runtime jsengine.Runtime) error {
		_, err := runtime.RunString("adapter-filter-all.js", `seal.ext.find("Adapter event defaults").adapterEventFilter = { events: "all" }`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	request := adapterapi.AdapterEvent{Protocol: "onebot11", Type: "request", RawJSON: `{"post_type":"request","request_type":"friend","code":2}`}
	if err := d.dispatchAdapterEvent(scope, scope, request, endpoint); err != nil {
		t.Fatal(err)
	}
	if hit = requireAdapterEventHit(t, hits); hit.eventType != "request" || hit.bodyValue != "number:2" {
		t.Fatalf("explicit all request view = %#v", hit)
	}
}

func TestJSAdapterEventFilterStrictWhereAndLiveNestedMutation(t *testing.T) {
	const (
		packageID     = "test/adapter-event-where"
		extensionName = "Adapter event where"
	)
	script := `var adapterEventExt = seal.ext.new("Adapter event where", "test", "1.0.0");
adapterEventExt.adapterEventFilter = { events: ["notice"], where: { code: 1, active: true } };
adapterEventExt.onAdapterEvent = function (ctx, event) {
  recordAdapterEvent("where", ctx === null ? "null" : "ctx", event.type, event.protocol,
    event.rawJson, event.endPoint.id, typeof event.body.code + ":" + String(event.body.code));
};
seal.ext.register(adapterEventExt);`
	d, endpoint, _, _, loop := preparePublicPreprocessRuntime(t, string(jsengine.EngineGoja), packageID, extensionName, script)
	hits := bindAdapterEventTestRecorder(t, loop)
	scope, _ := adapterEventGroupScope(t, d, endpoint, extensionName)

	for _, raw := range []string{
		`{"post_type":"notice","code":"1","active":true}`,
		`{"post_type":"notice","code":1,"active":"true"}`,
		`{"post_type":"notice","code":1}`,
	} {
		if err := d.dispatchAdapterEvent(scope, scope, adapterapi.AdapterEvent{Protocol: "onebot11", Type: "notice", RawJSON: raw}, endpoint); err != nil {
			t.Fatal(err)
		}
		requireNoAdapterEventHit(t, hits)
	}
	if err := d.dispatchAdapterEvent(scope, scope, adapterapi.AdapterEvent{Protocol: "onebot11", Type: "notice", RawJSON: `{"post_type":"notice","code":1,"active":true}`}, endpoint); err != nil {
		t.Fatal(err)
	}
	if hit := requireAdapterEventHit(t, hits); hit.bodyValue != "number:1" {
		t.Fatalf("strict numeric match = %#v", hit)
	}

	if err := loop.Run(func(runtime jsengine.Runtime) error {
		_, err := runtime.RunString("adapter-filter-nested.js", `seal.ext.find("Adapter event where").adapterEventFilter.where.code = ["1", 2]`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := d.dispatchAdapterEvent(scope, scope, adapterapi.AdapterEvent{Protocol: "onebot11", Type: "notice", RawJSON: `{"post_type":"notice","code":1,"active":true}`}, endpoint); err != nil {
		t.Fatal(err)
	}
	requireNoAdapterEventHit(t, hits)
	for _, raw := range []string{
		`{"post_type":"notice","code":"1","active":true}`,
		`{"post_type":"notice","code":2,"active":true}`,
	} {
		if err := d.dispatchAdapterEvent(scope, scope, adapterapi.AdapterEvent{Protocol: "onebot11", Type: "notice", RawJSON: raw}, endpoint); err != nil {
			t.Fatal(err)
		}
		requireAdapterEventHit(t, hits)
	}

	if err := loop.Run(func(runtime jsengine.Runtime) error {
		_, err := runtime.RunString("adapter-filter-invalid.js", `seal.ext.find("Adapter event where").adapterEventFilter = { events: "notice" }`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	err := d.dispatchAdapterEvent(scope, scope, adapterapi.AdapterEvent{Protocol: "onebot11", Type: "notice", RawJSON: `{"post_type":"notice","code":2,"active":true}`}, endpoint)
	if err == nil || !strings.Contains(err.Error(), "events") {
		t.Fatalf("invalid filter error = %v", err)
	}
	requireNoAdapterEventHit(t, hits)
}

func TestJSAdapterEventBodyIsDetachedPerExtension(t *testing.T) {
	const (
		packageID  = "test/adapter-event-detached-body"
		firstName  = "Adapter event body first"
		secondName = "Adapter event body second"
	)
	script := `var firstAdapterExt = seal.ext.new("Adapter event body first", "test", "1.0.0");
firstAdapterExt.onAdapterEvent = function (_ctx, event) {
  event.body.nested.value = "changed";
  event.body.added = true;
};
seal.ext.register(firstAdapterExt);
var secondAdapterExt = seal.ext.new("Adapter event body second", "test", "1.0.0");
secondAdapterExt.onAdapterEvent = function (ctx, event) {
  recordAdapterEvent("second", ctx === null ? "null" : "ctx", event.type, event.protocol,
    event.rawJson, event.endPoint.id, event.body.nested.value + ":" + String("added" in event.body));
};
seal.ext.register(secondAdapterExt);`
	d, endpoint, _, _, loop := preparePublicPreprocessRuntime(t, string(jsengine.EngineGoja), packageID, firstName, script)
	hits := bindAdapterEventTestRecorder(t, loop)
	scope, _ := adapterEventGroupScope(t, d, endpoint, firstName, secondName)
	event := adapterapi.AdapterEvent{Protocol: "onebot11", Type: "notice", RawJSON: `{"post_type":"notice","nested":{"value":"original"}}`}
	if err := d.dispatchAdapterEvent(scope, scope, event, endpoint); err != nil {
		t.Fatal(err)
	}
	if hit := requireAdapterEventHit(t, hits); hit.label != "second" || hit.bodyValue != "original:false" {
		t.Fatalf("second extension observed shared body mutation: %#v", hit)
	}
}

func TestJSAdapterEventBodyUsesEngineNativeParsedJSON(t *testing.T) {
	for _, engine := range []string{"goja", "quickjs"} {
		t.Run(engine, func(t *testing.T) {
			if engine == "quickjs" && os.Getenv("SCARDICE_RUNTIME_ROOT") == "" && os.Getenv("SCARDICE_QUICKJS_PACKAGE") == "" {
				t.Skip("native QuickJS package is not configured")
			}
			const firstName = "Adapter event native JSON first"
			script := `var nativeJSONFirstExt = seal.ext.new("Adapter event native JSON first", "test", "1.0.0");
nativeJSONFirstExt.adapterEventFilter = { events: ["notice"], where: { code: 1, active: true } };
nativeJSONFirstExt.onAdapterEvent = function (ctx, event) {
  var items = event.body.items;
  var iterated = [];
  for (var item of items) iterated.push(item);
  var result = [
    Array.isArray(items),
    items.map(function (item) { return item * 2; }).join(","),
    [...items].join(","),
    iterated.join(","),
    JSON.stringify(items),
    String(event.body.large),
    JSON.stringify(event.body)
  ];
  items.push(4);
  items[0] = 99;
  result.push(items.length, items[0]);
  recordAdapterEvent("first", ctx === null ? "null" : "ctx", event.type, event.protocol,
    event.rawJson, event.endPoint.id, result.join("|"));
};
seal.ext.register(nativeJSONFirstExt);
var nativeJSONSecondExt = seal.ext.new("Adapter event native JSON second", "test", "1.0.0");
nativeJSONSecondExt.adapterEventFilter = { events: ["notice"], where: { code: 1, active: true } };
nativeJSONSecondExt.onAdapterEvent = function (ctx, event) {
  var items = event.body.items;
  var iterated = [];
  for (var item of items) iterated.push(item);
  recordAdapterEvent("second", ctx === null ? "null" : "ctx", event.type, event.protocol,
    event.rawJson, event.endPoint.id, [
      Array.isArray(items),
      items.map(function (item) { return item; }).join(","),
      [...items].join(","),
      iterated.join(","),
      JSON.stringify(items),
      String(event.body.large),
      JSON.stringify(event.body),
      items.length,
      items[0]
    ].join("|"));
};
seal.ext.register(nativeJSONSecondExt);`
			d, endpoint, _, _, loop := preparePublicPreprocessRuntime(
				t, engine, "test/adapter-event-native-json-"+engine, firstName, script,
			)
			hits := bindAdapterEventTestRecorder(t, loop)
			scope := &MsgContext{Dice: d, Session: d.ImSession, EndPoint: endpoint}
			t.Cleanup(scope.releaseExecutionState)

			strictMismatch := adapterapi.AdapterEvent{
				Protocol: "onebot11",
				Type:     "notice",
				RawJSON:  `{"post_type":"notice","code":"1","active":true,"items":[1,2,3]}`,
			}
			if err := d.dispatchAdapterEvent(scope, nil, strictMismatch, endpoint); err != nil {
				t.Fatal(err)
			}
			requireNoAdapterEventHit(t, hits)

			raw := " {\n  \"post_type\": \"notice\", \"code\": 1, \"active\": true,\n  \"items\": [1, 2, 3], \"large\": 9007199254740993\n} "
			event := adapterapi.AdapterEvent{Protocol: "onebot11", Type: "notice", RawJSON: raw}
			if err := d.dispatchAdapterEvent(scope, nil, event, endpoint); err != nil {
				t.Fatal(err)
			}
			first := requireAdapterEventHit(t, hits)
			if first.label != "first" || first.contextKind != "null" || first.rawJSON != raw ||
				first.bodyValue != `true|2,4,6|1,2,3|1,2,3|[1,2,3]|9007199254740992|{"post_type":"notice","code":1,"active":true,"items":[1,2,3],"large":9007199254740992}|4|99` {
				t.Fatalf("first engine-native event view = %#v", first)
			}
			second := requireAdapterEventHit(t, hits)
			if second.label != "second" || second.contextKind != "null" || second.rawJSON != raw ||
				second.bodyValue != `true|1,2,3|1,2,3|1,2,3|[1,2,3]|9007199254740992|{"post_type":"notice","code":1,"active":true,"items":[1,2,3],"large":9007199254740992}|3|1` {
				t.Fatalf("second extension observed a non-array or shared mutation: %#v", second)
			}
		})
	}
}

func TestJSAdapterEventGroupPrivateGlobalAndPluginLifecycle(t *testing.T) {
	const (
		packageID     = "test/adapter-event-lifecycle"
		extensionName = "Adapter event lifecycle"
	)
	script := `var lifecycleAdapterExt = seal.ext.new("Adapter event lifecycle", "test", "1.0.0");
lifecycleAdapterExt.adapterEventFilter = { events: "all" };
lifecycleAdapterExt.onAdapterEvent = function (ctx, event) {
  recordAdapterEvent("original", ctx === null ? "null" : "ctx", event.type, event.protocol,
    event.rawJson, event.endPoint.id, "");
};
seal.ext.register(lifecycleAdapterExt);`
	d, endpoint, _, _, loop := preparePublicPreprocessRuntime(t, string(jsengine.EngineGoja), packageID, extensionName, script)
	hits := bindAdapterEventTestRecorder(t, loop)
	scope, group := adapterEventGroupScope(t, d, endpoint, extensionName)
	event := adapterapi.AdapterEvent{Protocol: "onebot11", Type: "request", RawJSON: `{"post_type":"request","request_type":"friend"}`}

	if err := d.dispatchAdapterEvent(scope, scope, event, endpoint); err != nil {
		t.Fatal(err)
	}
	if hit := requireAdapterEventHit(t, hits); hit.contextKind != "ctx" {
		t.Fatalf("group callback context = %#v", hit)
	}

	group.Active = false
	if err := d.dispatchAdapterEvent(scope, scope, event, endpoint); err != nil {
		t.Fatal(err)
	}
	requireNoAdapterEventHit(t, hits)

	scope.MessageType, scope.IsPrivate = "private", true
	if err := d.dispatchAdapterEvent(scope, scope, event, endpoint); err != nil {
		t.Fatal(err)
	}
	requireAdapterEventHit(t, hits)

	group.SetActivatedExtList(nil, d)
	if err := d.dispatchAdapterEvent(scope, scope, event, endpoint); err != nil {
		t.Fatal(err)
	}
	requireNoAdapterEventHit(t, hits)

	globalScope := &MsgContext{Dice: d, Session: d.ImSession, EndPoint: endpoint}
	t.Cleanup(globalScope.releaseExecutionState)
	if err := d.dispatchAdapterEvent(globalScope, nil, event, endpoint); err != nil {
		t.Fatal(err)
	}
	if hit := requireAdapterEventHit(t, hits); hit.contextKind != "null" {
		t.Fatalf("global callback fabricated a context: %#v", hit)
	}

	original, ok := d.JsExtRegistry.Load(extensionName)
	if !ok || original == nil || original.Source == nil {
		t.Fatal("original extension has no live script identity")
	}
	d.JsScriptList = append(d.JsScriptList, original.Source)
	if err := jsengine.RunWithContext(loop, jsContextForPlugin(original), func(runtime jsengine.Runtime) error {
		_, err := runtime.RunString("adapter-replacement.js", `
var replacementAdapterExt = seal.ext.new("Adapter event lifecycle", "test", "2.0.0");
replacementAdapterExt.adapterEventFilter = { events: "all" };
replacementAdapterExt.onAdapterEvent = function (ctx, event) {
  recordAdapterEvent("replacement", ctx === null ? "null" : "ctx", event.type, event.protocol,
    event.rawJson, event.endPoint.id, "");
};
seal.ext.register(replacementAdapterExt);`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := d.dispatchAdapterEvent(globalScope, nil, event, endpoint); err != nil {
		t.Fatal(err)
	}
	if hit := requireAdapterEventHit(t, hits); hit.label != "replacement" {
		t.Fatalf("replaced plugin callback remained live: %#v", hit)
	}

	replacement, ok := d.JsExtRegistry.Load(extensionName)
	if !ok || replacement == nil || replacement.Source == nil {
		t.Fatal("replacement extension has no live script identity")
	}
	JsDisable(d, replacement.Source.Name)
	if err := d.dispatchAdapterEvent(globalScope, nil, event, endpoint); err != nil {
		t.Fatal(err)
	}
	requireNoAdapterEventHit(t, hits)

	JsEnable(d, replacement.Source.Name)
	if err := d.dispatchAdapterEvent(globalScope, nil, event, endpoint); err != nil {
		t.Fatal(err)
	}
	if hit := requireAdapterEventHit(t, hits); hit.label != "replacement" {
		t.Fatalf("re-enabled plugin callback = %#v", hit)
	}

	JsDelete(d, replacement.Source)
	if err := d.dispatchAdapterEvent(globalScope, nil, event, endpoint); err != nil {
		t.Fatal(err)
	}
	requireNoAdapterEventHit(t, hits)
}

func TestJSAdapterEventConcurrentDisableFencesQueuedHook(t *testing.T) {
	const (
		packageID     = "test/adapter-event-concurrent-disable"
		extensionName = "Adapter event concurrent disable"
	)
	script := `var concurrentAdapterExt = seal.ext.new("Adapter event concurrent disable", "test", "1.0.0");
concurrentAdapterExt.onAdapterEvent = function (ctx, event) {
  recordAdapterEvent("concurrent", ctx === null ? "null" : "ctx", event.type, event.protocol,
    event.rawJson, event.endPoint.id, "");
};
seal.ext.register(concurrentAdapterExt);`
	d, endpoint, _, _, loop := preparePublicPreprocessRuntime(t, string(jsengine.EngineGoja), packageID, extensionName, script)
	hits := bindAdapterEventTestRecorder(t, loop)
	scope, _ := adapterEventGroupScope(t, d, endpoint, extensionName)
	event := adapterapi.AdapterEvent{Protocol: "onebot11", Type: "notice", RawJSON: `{"post_type":"notice"}`}
	extension, ok := d.JsExtRegistry.Load(extensionName)
	if !ok || extension == nil || extension.Source == nil {
		t.Fatal("registered extension has no script lifecycle owner")
	}

	extension.Source.runtimeStateMu.Lock()
	started := make(chan struct{})
	returned := make(chan error, 1)
	go func() {
		close(started)
		returned <- d.dispatchAdapterEvent(scope, scope, event, endpoint)
	}()
	<-started
	extension.Source.Enable = false
	extension.Source.runtimeStateMu.Unlock()
	select {
	case err := <-returned:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("queued adapter hook did not finish after concurrent disable")
	}
	requireNoAdapterEventHit(t, hits)

	extension.Source.runtimeStateMu.Lock()
	extension.Source.Enable = true
	extension.Source.runtimeStateMu.Unlock()
	if err := d.dispatchAdapterEvent(scope, scope, event, endpoint); err != nil {
		t.Fatal(err)
	}
	requireAdapterEventHit(t, hits)
}

func TestJSAdapterEventReturnedPromiseKeepsThenRevokesContext(t *testing.T) {
	const (
		packageID     = "test/adapter-event-promise"
		extensionName = "Adapter event promise"
	)
	script := `var retainedAdapterCtx;
var promiseAdapterExt = seal.ext.new("Adapter event promise", "test", "1.0.0");
promiseAdapterExt.adapterEventFilter = { events: "all" };
promiseAdapterExt.onAdapterEvent = async function (ctx) {
  retainedAdapterCtx = ctx;
  adapterPromiseStarted();
  await new Promise(function (resolve) { globalThis.__testResolveAdapterEvent = resolve; });
  seal.vars.strSet(ctx, "$tAdapterPromise", "settled");
  adapterPromiseSettled();
};
globalThis.__testAttemptLateAdapterContext = function () {
  try {
    seal.vars.strSet(retainedAdapterCtx, "$tAdapterLate", "escaped");
    adapterLateResult("escaped");
  } catch (_) {
    adapterLateResult("revoked");
  }
};
seal.ext.register(promiseAdapterExt);`
	d, endpoint, _, _, loop := preparePublicPreprocessRuntime(t, string(jsengine.EngineGoja), packageID, extensionName, script)
	started := make(chan struct{}, 1)
	settled := make(chan struct{}, 1)
	lateResult := make(chan string, 1)
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		if err := runtime.Bind("adapterPromiseStarted", func() { started <- struct{}{} }); err != nil {
			return err
		}
		if err := runtime.Bind("adapterPromiseSettled", func() { settled <- struct{}{} }); err != nil {
			return err
		}
		return runtime.Bind("adapterLateResult", func(result string) { lateResult <- result })
	}); err != nil {
		t.Fatal(err)
	}
	scope, _ := adapterEventGroupScope(t, d, endpoint, extensionName)
	event := adapterapi.AdapterEvent{Protocol: "onebot11", Type: "notice", RawJSON: `{"post_type":"notice"}`}
	returned := make(chan error, 1)
	go func() { returned <- d.dispatchAdapterEvent(scope, scope, event, endpoint) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("adapter event Promise did not start")
	}
	select {
	case err := <-returned:
		t.Fatalf("dispatch returned before adapter event Promise settled: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		_, err := runtime.RunString("resolve-adapter-event.js", `globalThis.__testResolveAdapterEvent()`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-settled:
	case <-time.After(2 * time.Second):
		t.Fatal("adapter event Promise did not resume")
	}
	select {
	case err := <-returned:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("dispatch did not join the returned Promise")
	}
	if value, ok := VarGetValueStr(scope, "$tAdapterPromise"); !ok || value != "settled" {
		t.Fatalf("Promise continuation did not retain its context: value=%q ok=%v", value, ok)
	}

	scope.releaseExecutionState()
	if err := loop.Run(func(runtime jsengine.Runtime) (err error) {
		// A revoked Go host binding may panic with context.Canceled instead
		// of producing a catchable JS exception. Observe its original cause.
		defer func() {
			if recovered := recover(); recovered != nil {
				if cause, ok := recovered.(error); ok {
					err = cause
					return
				}
				panic(recovered)
			}
		}()
		_, err = runtime.RunString("late-adapter-context.js", `globalThis.__testAttemptLateAdapterContext()`)
		return err
	}); err != nil {
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		return
	}
	select {
	case result := <-lateResult:
		if result != "revoked" {
			t.Fatalf("late adapter context result = %q", result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("late adapter context check did not run")
	}
}

func TestJSAdapterEventPromiseRejectionAndGlobalCancellationFailDispatch(t *testing.T) {
	t.Run("rejection", func(t *testing.T) {
		const (
			packageID     = "test/adapter-event-rejection"
			extensionName = "Adapter event rejection"
		)
		script := `var rejectionAdapterExt = seal.ext.new("Adapter event rejection", "test", "1.0.0");
rejectionAdapterExt.onAdapterEvent = async function () { throw new Error("ADAPTER_EVENT_REJECTED"); };
seal.ext.register(rejectionAdapterExt);`
		d, endpoint, _, _, _ := preparePublicPreprocessRuntime(t, string(jsengine.EngineGoja), packageID, extensionName, script)
		scope, _ := adapterEventGroupScope(t, d, endpoint, extensionName)
		err := d.dispatchAdapterEvent(scope, scope, adapterapi.AdapterEvent{Protocol: "onebot11", Type: "notice", RawJSON: `{"post_type":"notice"}`}, endpoint)
		if err == nil || !strings.Contains(err.Error(), "ADAPTER_EVENT_REJECTED") {
			t.Fatalf("Promise rejection error = %v", err)
		}
	})

	t.Run("global cancellation", func(t *testing.T) {
		const (
			packageID     = "test/adapter-event-global-cancel"
			extensionName = "Adapter event global cancel"
		)
		script := `var cancelAdapterExt = seal.ext.new("Adapter event global cancel", "test", "1.0.0");
cancelAdapterExt.onAdapterEvent = async function (ctx) {
  if (ctx !== null) throw new Error("global event fabricated a context");
  adapterCancelStarted();
  await new Promise(function () {});
};
seal.ext.register(cancelAdapterExt);`
		d, endpoint, _, _, loop := preparePublicPreprocessRuntime(t, string(jsengine.EngineGoja), packageID, extensionName, script)
		started := make(chan struct{}, 1)
		if err := loop.Run(func(runtime jsengine.Runtime) error {
			return runtime.Bind("adapterCancelStarted", func() { started <- struct{}{} })
		}); err != nil {
			t.Fatal(err)
		}
		parent, cancel := context.WithCancel(context.Background())
		scope := &MsgContext{Dice: d, Session: d.ImSession, EndPoint: endpoint, executionContext: parent}
		t.Cleanup(scope.releaseExecutionState)
		returned := make(chan error, 1)
		go func() {
			returned <- d.dispatchAdapterEvent(scope, nil, adapterapi.AdapterEvent{Protocol: "onebot11", Type: "notice", RawJSON: `{"post_type":"notice"}`}, endpoint)
		}()
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("global adapter event Promise did not start")
		}
		cancel()
		select {
		case err := <-returned:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("global cancellation error = %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("global adapter event ignored host cancellation")
		}
	})
}

func TestJSAdapterEventFilterRejectsLossyConversions(t *testing.T) {
	for _, engine := range []string{"goja", "quickjs"} {
		t.Run(engine, func(t *testing.T) {
			if engine == "quickjs" && os.Getenv("SCARDICE_RUNTIME_ROOT") == "" && os.Getenv("SCARDICE_QUICKJS_PACKAGE") == "" {
				t.Skip("native QuickJS package is not configured")
			}
			const name = "Adapter event filter types"
			script := `var ext = seal.ext.new("Adapter event filter types", "test", "1.0.0");
ext.adapterEventFilter = {events: []};
ext.onAdapterEvent = function (ctx, event) {
  recordAdapterEvent("filter-types", "ctx", event.type, event.protocol,
    event.rawJson, event.endPoint.id, String(event.body.code));
};
seal.ext.register(ext);`
			d, endpoint, _, _, loop := preparePublicPreprocessRuntime(t, engine, "test/adapter-event-filter-types", name, script)
			hits := bindAdapterEventTestRecorder(t, loop)
			for _, tc := range []struct {
				name   string
				filter string
				body   string
			}{
				{"undefined predicate", `{where: {code: undefined}}`, `{"post_type":"notice","code":null}`},
				{"symbol predicate", `{where: {code: Symbol("x")}}`, `{"post_type":"notice","code":"Symbol(x)"}`},
				{"undefined array item", `{where: {code: [undefined]}}`, `{"post_type":"notice","code":null}`},
				{"array instead of filter object", `[]`, `{"post_type":"notice","code":null}`},
				{"symbol predicate key", `{where: {[Symbol("code")]: 1}}`, `{"post_type":"notice","code":1}`},
			} {
				t.Run(tc.name, func(t *testing.T) {
					scope, _ := adapterEventGroupScope(t, d, endpoint, name)
					assignErr := loop.Run(func(runtime jsengine.Runtime) error {
						_, err := runtime.RunString("adapter-filter-invalid-types.js",
							`seal.ext.find("Adapter event filter types").adapterEventFilter = {events: []};
seal.ext.find("Adapter event filter types").adapterEventFilter = `+tc.filter)
						return err
					})
					dispatchErr := d.dispatchAdapterEvent(scope, scope, adapterapi.AdapterEvent{
						Protocol: "onebot11", Type: "notice", RawJSON: tc.body,
					}, endpoint)
					requireNoAdapterEventHit(t, hits)
					if assignErr == nil && dispatchErr == nil {
						t.Fatal("invalid filter was accepted without an error")
					}
				})
			}

			scope, _ := adapterEventGroupScope(t, d, endpoint, name)
			if err := loop.Run(func(runtime jsengine.Runtime) error {
				_, err := runtime.RunString("adapter-filter-explicit-null.js",
					`seal.ext.find("Adapter event filter types").adapterEventFilter = {where: {code: null}}`)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if err := d.dispatchAdapterEvent(scope, scope, adapterapi.AdapterEvent{
				Protocol: "onebot11", Type: "notice", RawJSON: `{"post_type":"notice","code":null}`,
			}, endpoint); err != nil {
				t.Fatal(err)
			}
			if hit := requireAdapterEventHit(t, hits); hit.bodyValue != "null" {
				t.Fatalf("explicit JSON null did not match: %#v", hit)
			}
		})
	}
}
