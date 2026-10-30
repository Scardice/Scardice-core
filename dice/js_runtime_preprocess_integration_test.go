package dice

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"Scardice-core/utils/jsengine"
)

func TestJSRuntimeMessagePreprocessPublicPropertyExecutesCommand(t *testing.T) {
	packageID := "test/public-message-preprocess"
	extensionName := "Public message preprocess test"
	scriptSource := `var ext = seal.ext.new("Public message preprocess test", "test", "1.0.0");
ext.onMessagePreprocess = function (_ctx, msg) {
  if (msg.message === "rewrite-probe") return { message: ".rollshape set soft" };
  if (msg.message === ".rollshape set safe-tail") throw new Error("intentional preprocess callback failure");
  return null;
};
seal.ext.register(ext);
`

	for _, runtimeID := range []string{string(jsengine.EngineGoja), "quickjs"} {
		t.Run(runtimeID, func(t *testing.T) {
			if runtimeID == "quickjs" && os.Getenv("SCARDICE_RUNTIME_ROOT") == "" && os.Getenv("SCARDICE_QUICKJS_PACKAGE") == "" {
				t.Skip("native QuickJS package is not configured")
			}

			d, ep, adapter, cleanup := newExecuteNewTestDice(t)
			defer func() {
				if d.ExtLoopManager != nil {
					d.ExtLoopManager.SetLoop(nil)
				}
				cleanup()
			}()

			logCore, observedLogs := observer.New(zapcore.ErrorLevel)
			d.jsRuntimeManager = newJSRuntimeManagerForDice(d, false)
			d.Logger = zap.New(logCore).Sugar()
			d.Config.JsEngine = string(jsengine.EngineGoja)
			d.Config.JsRuntimeRoutes = map[string]string{packageID: runtimeID}
			d.JsInit()
			if !d.Config.JsEnable {
				t.Fatalf("JS initialization for global Goja failed: runtime status=%+v", d.jsRuntimeManagerInstance().Statuses())
			}

			scriptPath := filepath.Join(d.BaseConfig.DataDir, "scripts", "public-message-preprocess.js")
			if err := os.WriteFile(scriptPath, []byte(scriptSource), 0o600); err != nil {
				t.Fatal(err)
			}
			script := &JsScriptInfo{
				Name:      extensionName,
				Enable:    true,
				Filename:  scriptPath,
				PackageID: packageID,
			}
			d.JsLoadScriptRaw(script)
			if script.ErrText != "" {
				t.Fatalf("loading public SDK script failed: %s", script.ErrText)
			}
			if script.RuntimeID != runtimeID {
				t.Fatalf("script runtime = %q, want package route %q; provider statuses=%+v; discovery=%s", script.RuntimeID, runtimeID, d.jsRuntimeManagerInstance().Statuses(), d.jsRuntimeManagerInstance().DiscoveryError())
			}
			registered, ok := d.JsExtRegistry.Load(extensionName)
			if !ok || registered == nil {
				t.Fatal("public seal.ext.register did not register the extension")
			}
			d.ApplyExtDefaultSettings()

			groupID := "QQ-Group:preprocess-public-property"
			rewriteMessage := newGroupMsg(groupID, "QQ:999", "rewrite-probe")
			rewriteMessage.Sender.GroupRole = "admin"
			d.ImSession.ExecuteNew(ep, rewriteMessage)
			if _, ok := adapter.waitForMsg(2 * time.Second); !ok {
				t.Error("rewritten command did not produce a consumer reply")
			}
			if rewriteMessage.Message != ".rollshape set soft" {
				t.Errorf("public callback left message %q, want rewritten command", rewriteMessage.Message)
			}
			group, ok := d.ImSession.ServiceAtNew.Load(groupID)
			if !ok || group.RollShaperMode != string(DiceRollShaperModeSoft) {
				t.Errorf("rewritten command produced group state %#v, want roll-shaper mode %q", group, DiceRollShaperModeSoft)
			}

			exceptionMessage := newGroupMsg(groupID, "QQ:999", ".rollshape set safe-tail")
			exceptionMessage.Sender.GroupRole = "admin"
			d.ImSession.ExecuteNew(ep, exceptionMessage)
			if _, ok := adapter.waitForMsg(2 * time.Second); !ok {
				t.Error("command continuation after callback exception did not produce a reply")
			}
			if exceptionMessage.Message != ".rollshape set safe-tail" {
				t.Errorf("throwing callback changed message to %q, want original command", exceptionMessage.Message)
			}
			group, ok = d.ImSession.ServiceAtNew.Load(groupID)
			if !ok || group.RollShaperMode != string(DiceRollShaperModeSafeTail) {
				t.Errorf("command continuation produced group state %#v, want roll-shaper mode %q", group, DiceRollShaperModeSafeTail)
			}

			loggedIntentionalError := false
			for _, entry := range observedLogs.All() {
				if strings.Contains(entry.Message+" "+fmt.Sprint(entry.Context), "intentional preprocess callback failure") {
					loggedIntentionalError = true
					break
				}
			}
			if !loggedIntentionalError {
				t.Errorf("throwing public callback error was not observable in the error log; observed=%v", observedLogs.All())
			}
		})
	}
}

func TestJSRuntimeMessagePreprocessLifetimeAndParserContract(t *testing.T) {
	if os.Getenv("SCARDICE_RUNTIME_ROOT") == "" && os.Getenv("SCARDICE_QUICKJS_PACKAGE") == "" {
		t.Skip("native QuickJS package is not configured")
	}

	const (
		packageID     = "test/public-message-preprocess-lifetime"
		extensionName = "Public preprocess lifetime test"
		repeatedCalls = 24
	)
	scriptSource := `globalThis.__preprocessMode = "none";
globalThis.__preprocessRetained = [];
var ext = seal.ext.new("Public preprocess lifetime test", "test", "1.0.0");
ext.onMessagePreprocess = function (ctx, msg) {
  if (globalThis.__preprocessMode === "retain") {
    globalThis.__preprocessRetained.push([ctx, msg]);
    return null;
  }
  if (globalThis.__preprocessMode === "retention-check" && msg.message === "retention-check") {
    return globalThis.__preprocessRetained.length === 4 &&
      globalThis.__preprocessRetained[0][1].message === ".rollshape set safe-tail" &&
      !!globalThis.__preprocessRetained[0][0].group
      ? { message: ".rollshape set soft" }
      : { message: "" };
  }
  if (globalThis.__preprocessMode === "clear" && msg.message === ".rollshape set safe-tail") {
    globalThis.__preprocessRetained = [];
    return null;
  }
  if (globalThis.__preprocessMode === "own" && msg.message === "own-probe") {
    return { message: ".rollshape set soft" };
  }
  if (globalThis.__preprocessMode === "string" && msg.message === "string-probe") {
    return ".rollshape set soft";
  }
  if (globalThis.__preprocessMode === "getter" && msg.message === ".rollshape set soft") {
    return { get message() { throw new Error("PREPROCESS_GETTER_THROW"); } };
  }
  if (globalThis.__preprocessMode === "inherited" && msg.message === "prototype-probe") {
    return Object.create({ message: ".rollshape set soft" });
  }
  if (globalThis.__preprocessMode === "direct-throw" && msg.message === ".rollshape set safe-tail") {
    throw new Error("PREPROCESS_DIRECT_THROW");
  }
  if (globalThis.__preprocessMode === "method-read") {
    void ctx.roll;
    return null;
  }
  if (globalThis.__preprocessMode === "method-stash" && msg.message === "method-stash") {
    globalThis.__preprocessSavedRoll = ctx.roll;
    globalThis.__preprocessSavedRollAlias = ctx.roll;
    return null;
  }
  if (globalThis.__preprocessMode === "method-invoke" && msg.message === "method-invoke") {
    return globalThis.__preprocessSavedRoll(1) === 1
      ? { message: ".rollshape set soft" }
      : { message: "" };
  }
  if (globalThis.__preprocessMode === "method-drop" && msg.message === "method-drop") {
    globalThis.__preprocessSavedRoll = null;
    globalThis.__preprocessSavedRollAlias = null;
    return null;
  }
  return null;
};
seal.ext.register(ext);
`

	for _, runtimeID := range []string{string(jsengine.EngineGoja), "quickjs"} {
		t.Run(runtimeID, func(t *testing.T) {
			d, ep, adapter, logs, loop := preparePublicPreprocessRuntime(t, runtimeID, packageID, extensionName, scriptSource)
			groupID := "QQ-Group:preprocess-lifetime-" + runtimeID
			if runtimeID == "quickjs" {
				status, ok := d.jsRuntimeManagerInstance().Status("quickjs")
				if !ok || !status.Loaded || status.Path == "" || status.Version != "0.8.0" || status.ABI != "v1" {
					t.Fatalf("QuickJS provider is not the requested 0.8.0 runtime ABI v1: status=%+v ok=%t", status, ok)
				}
				objectsBefore, identitiesBefore, ok := preprocessNativeRegistryCounts(loop)
				if !ok {
					t.Fatalf("selected loop %T does not expose its native HostBridge session", loop)
				}
				var warmupObjects, warmupIdentities int
				deltas := make([]int, 0, repeatedCalls)
				for n := range repeatedCalls {
					preprocessExecuteMessage(t, d, ep, adapter, groupID, ".rollshape set safe-tail", true)
					objects, identities, ok := preprocessNativeRegistryCounts(loop)
					if !ok {
						t.Fatal("native HostBridge session disappeared while runtime remained open")
					}
					deltas = append(deltas, objects-objectsBefore)
					if n == 0 {
						warmupObjects, warmupIdentities = objects, identities
					}
				}
				objectsAfter, identitiesAfter, ok := preprocessNativeRegistryCounts(loop)
				if !ok {
					t.Fatal("native HostBridge session disappeared after repeated consumer calls")
				}
				if objectsAfter != warmupObjects || identitiesAfter != warmupIdentities {
					t.Fatalf("actual public callback HostRef registry did not reach a steady bound after warmup: first=(%d,%d) final=(%d,%d) base=(%d,%d) per-call-object-deltas=%v",
						warmupObjects, warmupIdentities, objectsAfter, identitiesAfter, objectsBefore, identitiesBefore, deltas)
				}

				// JS reachability must keep the proxies alive beyond callback return.
				if err := preprocessSetMode(loop, "retain"); err != nil {
					t.Fatal(err)
				}
				retainGroup := groupID + "-retained"
				for range 4 {
					preprocessExecuteMessage(t, d, ep, adapter, retainGroup, ".rollshape set safe-tail", true)
				}
				if err := preprocessSetMode(loop, "retention-check"); err != nil {
					t.Fatal(err)
				}
				retained := preprocessExecuteMessage(t, d, ep, adapter, retainGroup, "retention-check", true)
				if retained.Message != ".rollshape set soft" || preprocessGroupMode(d, retainGroup) != string(DiceRollShaperModeSoft) {
					t.Fatalf("JS-retained same-generation ctx/msg were not usable by a later real command: message=%q mode=%q", retained.Message, preprocessGroupMode(d, retainGroup))
				}
				if err := preprocessSetMode(loop, "clear"); err != nil {
					t.Fatal(err)
				}
				preprocessExecuteMessage(t, d, ep, adapter, retainGroup, ".rollshape set safe-tail", true)
				objectsReleased, identitiesReleased, ok := preprocessNativeRegistryCounts(loop)
				if !ok || objectsReleased != warmupObjects || identitiesReleased != warmupIdentities {
					t.Fatalf("clearing JS references did not release their actual HostRefs: got=(%d,%d) ok=%t want=(%d,%d)",
						objectsReleased, identitiesReleased, ok, warmupObjects, warmupIdentities)
				}

				methodBaseline, ok := preprocessNativeRegistrySnapshot(loop)
				if !ok {
					t.Fatal("native HostBridge method registry is unavailable")
				}
				if err := preprocessSetMode(loop, "method-read"); err != nil {
					t.Fatal(err)
				}
				for range repeatedCalls {
					preprocessExecuteMessage(t, d, ep, adapter, groupID, ".rollshape set safe-tail", true)
				}
				methodRead, ok := preprocessNativeRegistrySnapshot(loop)
				if !ok || methodRead.functions != methodBaseline.functions ||
					methodRead.methodOperations != methodBaseline.methodOperations {
					t.Fatalf("unretained method reads must return function entries to baseline: before=%+v after=%+v ok=%t",
						methodBaseline, methodRead, ok)
				}

				if err := preprocessSetMode(loop, "method-stash"); err != nil {
					t.Fatal(err)
				}
				preprocessExecuteMessage(t, d, ep, adapter, groupID, "method-stash", false)
				methodStashed, ok := preprocessNativeRegistrySnapshot(loop)
				if !ok || methodStashed.functions != methodBaseline.functions+1 ||
					methodStashed.methodOperations != methodBaseline.methodOperations+1 ||
					methodStashed.objects != methodBaseline.objects+1 ||
					methodStashed.identities != methodBaseline.identities+1 ||
					methodStashed.proxyRefs != methodBaseline.proxyRefs+2 {
					t.Fatalf("two retained wrappers for one owner method must share one live operation and keep both owner proxies: baseline=%+v stashed=%+v ok=%t",
						methodBaseline, methodStashed, ok)
				}

				if err := preprocessSetMode(loop, "method-invoke"); err != nil {
					t.Fatal(err)
				}
				invoked := preprocessExecuteMessage(t, d, ep, adapter, groupID, "method-invoke", true)
				methodInvoked, ok := preprocessNativeRegistrySnapshot(loop)
				if invoked.Message != ".rollshape set soft" ||
					preprocessGroupMode(d, groupID) != string(DiceRollShaperModeSoft) {
					t.Fatalf("detached method was not callable from the later real message: message=%q mode=%q",
						invoked.Message, preprocessGroupMode(d, groupID))
				}
				if !ok || methodInvoked != methodStashed {
					t.Fatalf("invoking a retained method changed its owner registrations: stashed=%+v invoked=%+v ok=%t",
						methodStashed, methodInvoked, ok)
				}

				if err := preprocessSetMode(loop, "method-drop"); err != nil {
					t.Fatal(err)
				}
				preprocessExecuteMessage(t, d, ep, adapter, groupID, "method-drop", false)
				methodDropped, ok := preprocessNativeRegistrySnapshot(loop)
				if !ok || methodDropped != methodBaseline {
					t.Fatalf("dropping the last method wrappers did not release their HostRefs and owner operations: baseline=%+v dropped=%+v ok=%t",
						methodBaseline, methodDropped, ok)
				}
			} else {
				for range repeatedCalls {
					preprocessExecuteMessage(t, d, ep, adapter, groupID, ".rollshape set safe-tail", true)
				}
				if _, _, native := preprocessNativeRegistryCounts(loop); native {
					t.Fatal("Goja control unexpectedly exposes a native HostBridge session")
				}
			}

			preprocessRunParserCases(t, runtimeID, d, ep, adapter, logs, loop, groupID)
			if runtimeID == "quickjs" {
				if err := preprocessSetMode(loop, "method-stash"); err != nil {
					t.Fatal(err)
				}
				preprocessExecuteMessage(t, d, ep, adapter, groupID, "method-stash", false)
				beforeClose, ok := preprocessNativeRegistrySnapshot(loop)
				if !ok || beforeClose.methodOperations == 0 || beforeClose.proxyRefs == 0 {
					t.Fatalf("actual QuickJS destroy test did not retain a HostRef-backed method: state=%+v ok=%t",
						beforeClose, ok)
				}
				lastErrBefore, ok := preprocessNativeLastError(loop)
				if !ok {
					t.Fatal("native host callback error state is unavailable")
				}
				closer, ok := loop.(interface{ Close() error })
				if !ok {
					t.Fatalf("loaded QuickJS loop %T cannot be closed", loop)
				}
				if err := closer.Close(); err != nil {
					t.Fatalf("closing the loaded QuickJS provider failed: %v", err)
				}
				lastErrAfter, ok := preprocessNativeLastError(loop)
				if !ok || lastErrAfter != lastErrBefore {
					t.Fatalf("actual QuickJS destroy added a host release error: before=%q after=%q ok=%t",
						lastErrBefore, lastErrAfter, ok)
				}
				afterClose, ok := preprocessNativeRegistrySnapshot(loop)
				if !ok || afterClose != (preprocessNativeRegistryState{}) {
					t.Fatalf("QuickJS destroy did not leave HostBridge registries empty: state=%+v ok=%t",
						afterClose, ok)
				}
			}
		})
	}

	t.Run("quickjs-no-preprocess-control", func(t *testing.T) {
		const noHookName = "Public preprocess no-hook control"
		noHookScript := `var ext = seal.ext.new("Public preprocess no-hook control", "test", "1.0.0"); seal.ext.register(ext);`
		d, ep, adapter, _, loop := preparePublicPreprocessRuntime(t, "quickjs", "test/public-preprocess-no-hook", noHookName, noHookScript)
		objectsBefore, identitiesBefore, ok := preprocessNativeRegistryCounts(loop)
		if !ok {
			t.Fatalf("selected loop %T does not expose its native HostBridge session", loop)
		}
		for range repeatedCalls {
			preprocessExecuteMessage(t, d, ep, adapter, "QQ-Group:preprocess-no-hook-control", ".rollshape set safe-tail", true)
		}
		objectsAfter, identitiesAfter, ok := preprocessNativeRegistryCounts(loop)
		if !ok || objectsAfter != objectsBefore || identitiesAfter != identitiesBefore {
			t.Fatalf("no-callback control registry changed: before=(%d,%d), after=(%d,%d), ok=%t",
				objectsBefore, identitiesBefore, objectsAfter, identitiesAfter, ok)
		}
	})
}

func preparePublicPreprocessRuntime(t *testing.T, runtimeID, packageID, extensionName, scriptSource string) (*Dice, *EndPointInfo, *mockPlatformAdapter, *observer.ObservedLogs, jsengine.Loop) {
	t.Helper()
	d, ep, adapter, cleanup := newExecuteNewTestDice(t)
	t.Cleanup(func() {
		if d.ExtLoopManager != nil {
			d.ExtLoopManager.SetLoop(nil)
		}
		cleanup()
	})
	logCore, observedLogs := observer.New(zapcore.ErrorLevel)
	d.jsRuntimeManager = newJSRuntimeManagerForDice(d, false)
	d.Logger = zap.New(logCore).Sugar()
	d.Config.JsEngine = string(jsengine.EngineGoja)
	d.Config.JsRuntimeRoutes = map[string]string{packageID: runtimeID}
	d.JsInit()
	if !d.Config.JsEnable {
		t.Fatalf("JS initialization for global Goja failed: runtime status=%+v", d.jsRuntimeManagerInstance().Statuses())
	}
	scriptPath := filepath.Join(d.BaseConfig.DataDir, "scripts", "public-preprocess-lifetime.js")
	if err := os.WriteFile(scriptPath, []byte(scriptSource), 0o600); err != nil {
		t.Fatal(err)
	}
	script := &JsScriptInfo{Name: extensionName, Enable: true, Filename: scriptPath, PackageID: packageID}
	d.JsLoadScriptRaw(script)
	if script.ErrText != "" || script.RuntimeID != runtimeID {
		t.Fatalf("public SDK script resolution failed: runtime=%q err=%q wanted=%q statuses=%+v discovery=%s",
			script.RuntimeID, script.ErrText, runtimeID, d.jsRuntimeManagerInstance().Statuses(), d.jsRuntimeManagerInstance().DiscoveryError())
	}
	registered, ok := d.JsExtRegistry.Load(extensionName)
	if !ok || registered == nil || registered.GetRealExt() == nil {
		t.Fatal("public seal.ext.register did not register the extension")
	}
	d.ApplyExtDefaultSettings()
	loop, err := d.ExtLoopManager.GetLoop(registered.GetRealExt().JSLoopVersion)
	if err != nil || loop == nil {
		t.Fatalf("selected runtime loop unavailable: loop=%v err=%v", loop, err)
	}
	return d, ep, adapter, observedLogs, loop
}

func preprocessNativeRegistryCounts(loop jsengine.Loop) (objects, identities int, ok bool) {
	loopValue := reflect.ValueOf(loop)
	if loopValue.Kind() != reflect.Pointer || loopValue.IsNil() {
		return 0, 0, false
	}
	nativeLoop := loopValue.Elem()
	host := nativeLoop.FieldByName("host")
	if !host.IsValid() || host.Kind() != reflect.Pointer || host.IsNil() {
		return 0, 0, false
	}
	session := host.Elem().FieldByName("session")
	if !session.IsValid() || session.Kind() != reflect.Pointer || session.IsNil() {
		return 0, 0, false
	}
	objectsMap := session.Elem().FieldByName("objects")
	identitiesMap := session.Elem().FieldByName("identities")
	if !objectsMap.IsValid() || objectsMap.Kind() != reflect.Map || !identitiesMap.IsValid() || identitiesMap.Kind() != reflect.Map {
		return 0, 0, false
	}
	return objectsMap.Len(), identitiesMap.Len(), true
}

type preprocessNativeRegistryState struct {
	objects          int
	identities       int
	functions        int
	methodOperations int
	proxyRefs        uint64
}

func preprocessNativeRegistrySnapshot(loop jsengine.Loop) (preprocessNativeRegistryState, bool) {
	loopValue := reflect.ValueOf(loop)
	if loopValue.Kind() != reflect.Pointer || loopValue.IsNil() {
		return preprocessNativeRegistryState{}, false
	}
	nativeLoop := loopValue.Elem()
	host := nativeLoop.FieldByName("host")
	if !host.IsValid() || host.Kind() != reflect.Pointer || host.IsNil() {
		return preprocessNativeRegistryState{}, false
	}
	session := host.Elem().FieldByName("session")
	if !session.IsValid() || session.Kind() != reflect.Pointer || session.IsNil() {
		return preprocessNativeRegistryState{}, false
	}
	sessionValue := session.Elem()
	objects := sessionValue.FieldByName("objects")
	identities := sessionValue.FieldByName("identities")
	functions := sessionValue.FieldByName("functions")
	if !objects.IsValid() || objects.Kind() != reflect.Map ||
		!identities.IsValid() || identities.Kind() != reflect.Map ||
		!functions.IsValid() || functions.Kind() != reflect.Map {
		return preprocessNativeRegistryState{}, false
	}
	snapshot := preprocessNativeRegistryState{
		objects:    objects.Len(),
		identities: identities.Len(),
		functions:  functions.Len(),
	}
	objectEntries := objects.MapRange()
	for objectEntries.Next() {
		proxyRefs := objectEntries.Value().FieldByName("proxyRefs")
		if !proxyRefs.IsValid() || proxyRefs.Kind() != reflect.Uint64 {
			return preprocessNativeRegistryState{}, false
		}
		snapshot.proxyRefs += proxyRefs.Uint()
	}
	functionEntries := functions.MapRange()
	for functionEntries.Next() {
		entry := functionEntries.Value()
		owner := entry.FieldByName("owner")
		operation := entry.FieldByName("operation")
		if !owner.IsValid() || owner.Kind() != reflect.Uint64 ||
			!operation.IsValid() || operation.Kind() != reflect.String {
			return preprocessNativeRegistryState{}, false
		}
		if owner.Uint() != 0 && operation.String() != "" {
			snapshot.methodOperations++
		}
	}
	return snapshot, true
}

func preprocessNativeLastError(loop jsengine.Loop) (string, bool) {
	loopValue := reflect.ValueOf(loop)
	if loopValue.Kind() != reflect.Pointer || loopValue.IsNil() {
		return "", false
	}
	host := loopValue.Elem().FieldByName("host")
	if !host.IsValid() || host.Kind() != reflect.Pointer || host.IsNil() {
		return "", false
	}
	lastErr := host.Elem().FieldByName("lastErr")
	if !lastErr.IsValid() || lastErr.Kind() != reflect.String {
		return "", false
	}
	return lastErr.String(), true
}

func preprocessSetMode(loop jsengine.Loop, mode string) error {
	return jsengine.RunWithContext(loop, nil, func(runtime jsengine.Runtime) error {
		_, err := runtime.RunString("preprocess-test-mode", fmt.Sprintf("globalThis.__preprocessMode = %q", mode))
		return err
	})
}

func preprocessExecuteMessage(t *testing.T, d *Dice, ep *EndPointInfo, adapter *mockPlatformAdapter, groupID, text string, wantReply bool) *Message {
	t.Helper()
	msg := newGroupMsg(groupID, "QQ:999", text)
	msg.Sender.GroupRole = "admin"
	d.ImSession.ExecuteNew(ep, msg)
	_, replied := adapter.waitForMsg(2 * time.Second)
	if replied != wantReply {
		t.Fatalf("message %q reply=%t, want %t", text, replied, wantReply)
	}
	return msg
}

func preprocessGroupMode(d *Dice, groupID string) string {
	group, ok := d.ImSession.ServiceAtNew.Load(groupID)
	if !ok || group == nil {
		return ""
	}
	return group.RollShaperMode
}

func preprocessRunParserCases(t *testing.T, runtimeID string, d *Dice, ep *EndPointInfo, adapter *mockPlatformAdapter, logs *observer.ObservedLogs, loop jsengine.Loop, baseGroup string) {
	t.Helper()
	groupID := baseGroup + "-parser"
	preprocessExecuteMessage(t, d, ep, adapter, groupID, ".rollshape set safe-tail", true)

	if err := preprocessSetMode(loop, "own"); err != nil {
		t.Fatal(err)
	}
	own := preprocessExecuteMessage(t, d, ep, adapter, groupID, "own-probe", true)
	if own.Message != ".rollshape set soft" || preprocessGroupMode(d, groupID) != string(DiceRollShaperModeSoft) {
		t.Fatalf("own-message result not rewritten for %s: message=%q mode=%q", runtimeID, own.Message, preprocessGroupMode(d, groupID))
	}

	if err := preprocessSetMode(loop, "string"); err != nil {
		t.Fatal(err)
	}
	stringResult := preprocessExecuteMessage(t, d, ep, adapter, groupID, "string-probe", true)
	if stringResult.Message != ".rollshape set soft" {
		t.Fatalf("string result not rewritten for %s: message=%q", runtimeID, stringResult.Message)
	}

	if err := preprocessSetMode(loop, "getter"); err != nil {
		t.Fatal(err)
	}
	getter := preprocessExecuteMessage(t, d, ep, adapter, groupID, ".rollshape set soft", true)
	if getter.Message != ".rollshape set soft" || preprocessGroupMode(d, groupID) != string(DiceRollShaperModeSoft) || !strings.Contains(fmt.Sprint(logs.All()), "PREPROCESS_GETTER_THROW") {
		t.Fatalf("throwing getter must log and continue command for %s: msg=%q mode=%q logs=%v", runtimeID, getter.Message, preprocessGroupMode(d, groupID), logs.All())
	}

	if err := preprocessSetMode(loop, "inherited"); err != nil {
		t.Fatal(err)
	}
	inherited := preprocessExecuteMessage(t, d, ep, adapter, groupID, "prototype-probe", false)
	if inherited.Message != "prototype-probe" || preprocessGroupMode(d, groupID) != string(DiceRollShaperModeSoft) {
		t.Fatalf("inherited-only message must not rewrite for %s: msg=%q mode=%q", runtimeID, inherited.Message, preprocessGroupMode(d, groupID))
	}

	if err := preprocessSetMode(loop, "direct-throw"); err != nil {
		t.Fatal(err)
	}
	thrown := preprocessExecuteMessage(t, d, ep, adapter, groupID, ".rollshape set safe-tail", true)
	if thrown.Message != ".rollshape set safe-tail" || preprocessGroupMode(d, groupID) != string(DiceRollShaperModeSafeTail) || !strings.Contains(fmt.Sprint(logs.All()), "PREPROCESS_DIRECT_THROW") {
		t.Fatalf("direct callback throw must remain logged no-op for %s: msg=%q mode=%q logs=%v", runtimeID, thrown.Message, preprocessGroupMode(d, groupID), logs.All())
	}
}
