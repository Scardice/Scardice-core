package dice

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"

	"Scardice-core/utils/jsengine"
	quickjsadapter "Scardice-core/utils/jsengine/quickjs"
)

func newQuickJSNodeTestDice(t *testing.T) *Dice {
	t.Helper()
	dice := &Dice{
		Logger: zap.NewNop().Sugar(),
		BaseConfig: BaseConfig{
			DataDir: t.TempDir(),
		},
		ImSession: &IMSession{
			ServiceAtNew: new(SyncMap[string, *GroupInfo]),
			EndPoints:    []*EndPointInfo{},
		},
		DirtyGroups:  new(SyncMap[string, int64]),
		AttrsManager: &AttrsManager{},
		ExtRegistry:  new(SyncMap[string, *ExtInfo]),
	}
	dice.Config.JsEngine = string(jsengine.EngineQuickJS)
	t.Cleanup(func() {
		if dice.ExtLoopManager != nil {
			dice.ExtLoopManager.SetEngineLoop(nil)
		}
	})
	return dice
}

func TestQuickJSNodeEnforcesConfiguredMemoryLimit(t *testing.T) {
	dice := newQuickJSNodeTestDice(t)
	dice.Config.QuickJSMemoryLimitMiB = 8
	dice.Config.QuickJSGCThresholdMiB = 2
	dice.JsInit()

	if err := quickJSNodeTestLoop(t, dice).Run(func(runtime jsengine.Runtime) error {
		_, err := runtime.RunString("memory-limit.js", `new ArrayBuffer(16 * 1024 * 1024)`)
		if err == nil {
			return errors.New("QuickJS allocation unexpectedly exceeded its configured memory limit")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func quickJSNodeTestLoop(t *testing.T, dice *Dice) jsengine.Loop {
	t.Helper()
	loop, err := dice.ExtLoopManager.GetEngineLoop(dice.ExtLoopManager.version)
	if err != nil || loop == nil {
		t.Fatalf("active QuickJS loop = %v, %v", loop, err)
	}
	return loop
}

func TestQuickJSNodeBuiltinsUseEnvironmentSnapshot(t *testing.T) {
	t.Setenv("LANG", "zh_CN.UTF-8")
	t.Setenv("SCARDICE_QJS_SECRET", "before")
	dice := newQuickJSNodeTestDice(t)
	dice.JsInit()
	t.Setenv("LANG", "en_US.UTF-8")
	t.Setenv("SCARDICE_QJS_SECRET", "after")

	if err := quickJSNodeTestLoop(t, dice).Run(func(runtime jsengine.Runtime) error {
		_, err := quickjsadapter.LoadModule(runtime, "builtins.mjs", `
			import { Buffer } from "buffer";
			import { subtle } from "crypto";
			const util = await import("util");
			if (Buffer.from("ok").toString() !== "ok") throw new Error("buffer");
			if (typeof subtle.digest !== "function") throw new Error("crypto");
			if (util.format("%s:%d", "ok", 7) !== "ok:7") throw new Error("util");
			if (process.env.LANG !== "zh_CN.UTF-8") throw new Error("language");
			if ("SCARDICE_QJS_SECRET" in process.env) throw new Error("secret");
		`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestQuickJSNodeLocksHostGlobalsWithoutFreezingPluginGlobals(t *testing.T) {
	dice := newQuickJSNodeTestDice(t)
	dice.JsInit()

	if err := quickJSNodeTestLoop(t, dice).Run(func(runtime jsengine.Runtime) error {
		value, err := runtime.RunString("global-lock.js", `
			const originalSeal = globalThis.seal;
			try { globalThis.seal = { replaced: true }; } catch (_) {}
			globalThis.http = { pluginOwned: true };
			globalThis.seal === originalSeal && globalThis.http.pluginOwned === true
		`)
		if err != nil {
			return err
		}
		if !value.ToBoolean() {
			return errors.New("host global rebinding or plugin global assignment did not match policy")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestQuickJSNodeCoreCompatibilityModules(t *testing.T) {
	dice := newQuickJSNodeTestDice(t)
	dice.JsInit()

	if err := quickJSNodeTestLoop(t, dice).Run(func(runtime jsengine.Runtime) error {
		_, err := quickjsadapter.LoadModule(runtime, "core-modules.mjs", `
			import { AbortController } from "abort";
			import { Blob } from "blob";
			import { MessageChannel } from "messagechannel";
			import { structuredClone } from "structuredclone";
			import { inspect } from "util";

			const controller = new AbortController();
			controller.abort("stopped");
			if (!controller.signal.aborted || controller.signal.reason !== "stopped") throw new Error("abort");

			const source = { nested: ["value"] };
			const clone = structuredClone(source);
			clone.nested[0] = "changed";
			if (source.nested[0] !== "value") throw new Error("structuredClone");

			if (new Blob(["ok"]).size !== 2) throw new Error("blob");
			const channel = new MessageChannel();
			if (typeof channel.port1.postMessage !== "function") throw new Error("messagechannel");
			if (typeof inspect(source) !== "string") throw new Error("utilinspect");
		`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestQuickJSNodeRejectsPathBackedRequire(t *testing.T) {
	dice := newQuickJSNodeTestDice(t)
	dice.JsInit()

	if err := quickJSNodeTestLoop(t, dice).Run(func(runtime jsengine.Runtime) error {
		_, err := quickjsadapter.LoadModule(runtime, "require.mjs", `
			let denied = false;
			try { require("./helper"); } catch (_) { denied = true; }
			if (!denied) throw new Error("path require unexpectedly resolved");
			export {};
		`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestProxyRoundTripperUsesHandler(t *testing.T) {
	transport := proxyRoundTripper{handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Proxy-Test", "yes")
		writer.WriteHeader(http.StatusCreated)
		_, _ = writer.Write([]byte("proxied"))
	})}
	request := httptest.NewRequest(http.MethodGet, "https://example.invalid/test", nil)
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusCreated || response.Header.Get("X-Proxy-Test") != "yes" ||
		string(body) != "proxied" || response.Request != request {
		t.Fatalf("proxy response = %#v, body = %q", response, body)
	}
}

func TestQuickJSReinitializationClosesPreviousRealm(t *testing.T) {
	dice := newQuickJSNodeTestDice(t)
	dice.JsInit()
	oldLoop := quickJSNodeTestLoop(t, dice)

	dice.ExtLoopManager.SetEngineLoop(nil)
	if err := oldLoop.Run(func(jsengine.Runtime) error { return nil }); err == nil {
		t.Fatal("closed QuickJS loop accepted a new task")
	}

	dice.JsInit()
	newLoop := quickJSNodeTestLoop(t, dice)
	if newLoop == oldLoop {
		t.Fatal("QuickJS reinitialization reused the closed loop")
	}
	if err := newLoop.Run(func(runtime jsengine.Runtime) error {
		_, err := quickjsadapter.LoadModule(runtime, "reload.mjs", `
			const ext = seal.ext.new("QuickJS Reload Test", "test", "1.0.0");
			seal.ext.register(ext);
			export {};
		`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok := dice.JsExtRegistry.Load("QuickJS Reload Test"); !ok {
		t.Fatal("reinitialized QuickJS realm did not register its extension")
	}
}
