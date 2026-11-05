package dice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"Scardice-core/eventstore"
	"Scardice-core/utils/jsengine"
)

func TestJSInvocationRegistryRoundTripAndStaleWriteDenial(t *testing.T) {
	const scriptSource = `
globalThis.__registryResult = {};
globalThis.__savedContext = null;
var sealInstAbsent = !Object.prototype.hasOwnProperty.call(seal, "inst") && typeof seal.inst === "undefined";
var ext = seal.ext.new("Invocation registry integration", "test", "1.0.0");
ext.onMessagePreprocess = function (ctx, msg) {
  if (msg.message === "registry-live") {
    var result = {};
    result.sealInstAbsent = sealInstAbsent;
    result.groupIdentity = ctx.group === ctx.group;
    result.playerIdentity = ctx.player === ctx.player;
    result.enumeration = Object.keys(ctx).indexOf("group") !== -1 &&
      Object.keys(ctx.group).indexOf("groupName") !== -1 &&
      Object.keys(ctx.player).indexOf("name") !== -1 &&
      Object.keys(ctx.endPoint).indexOf("userId") !== -1;
    result.endpointIdentity = ctx.endPoint === ctx.endPoint;

    ctx.group.groupName = "Registry Group";
    ctx.group.cocRuleIndex = 6;
    ctx.player.name = "Registry Player";
    ctx.player.autoSetNameTemplate = "Registry Card";
    ctx.isPrivate = true;
    ctx.isCurGroupBotOn = true;
    ctx.commandHideFlag = "registry-hide";
    ctx.privilegeLevel = 77;
    ctx.delegateText = "registry-delegate";

    result.groupName = ctx.group.groupName;
    result.cocRuleIndex = ctx.group.cocRuleIndex;
    result.playerName = ctx.player.name;
    result.playerTemplate = ctx.player.autoSetNameTemplate;
    result.localFlags = ctx.isPrivate && ctx.isCurGroupBotOn &&
      ctx.commandHideFlag === "registry-hide" && ctx.privilegeLevel === 77 &&
      ctx.delegateText === "registry-delegate";

    var detachedRoll = ctx.roll;
    result.detachedRoll = detachedRoll(1);
    var detachedFormat = seal.format;
    result.detachedTypedHost = detachedFormat(ctx, "registry-format") === "registry-format";
    seal.replyToSender(ctx, msg, "registry-typed-reply");
    result.typedReply = true;

    var temporaryMessage = seal.newMessage();
    temporaryMessage.messageType = msg.messageType;
    temporaryMessage.groupId = msg.groupId;
    temporaryMessage.sender.userId = msg.sender.userId;
    temporaryMessage.sender.nickname = msg.sender.nickname;
    var temporaryContext = seal.createTempCtx(ctx.endPoint, temporaryMessage);
    result.tempRoll = temporaryContext.roll(1);
    result.tempEndpointIdentity = temporaryContext.endPoint === ctx.endPoint;
    result.tempGroupIdentity = temporaryContext.group === ctx.group;
    result.tempPlayerIdentity = temporaryContext.player === ctx.player;

    var endpoints = seal.getEndPoints();
    result.nestedEndpointIdentity = endpoints[0] === ctx.endPoint;

    var proxyContext = seal.getCtxProxyAtPos(ctx, { at: [] }, 0);
    result.proxyIdentity = proxyContext === ctx;

    globalThis.__savedContext = ctx;
    msg.message = ".rollshape set soft";
    result.messageMutation = msg.message;
    globalThis.__registryResult = result;
    return null;
  }
  if (msg.message === "registry-stale") {
    var stale = {};
    stale.groupName = globalThis.__savedContext.group.groupName;
    stale.playerName = globalThis.__savedContext.player.name;
    stale.roll = globalThis.__savedContext.roll(1);
    try {
      globalThis.__savedContext.group.groupName = "escaped stale write";
      stale.groupWriteDenied = false;
    } catch (_) {
      stale.groupWriteDenied = true;
    }
    try {
      globalThis.__savedContext.player.name = "escaped stale player write";
      stale.playerWriteDenied = false;
    } catch (_) {
      stale.playerWriteDenied = true;
    }
    try {
      globalThis.__savedContext.isPrivate = false;
      stale.localWriteDenied = false;
    } catch (_) {
      stale.localWriteDenied = true;
    }
    try {
      seal.format(globalThis.__savedContext, "escaped unwrap");
      stale.typedUnwrapDenied = false;
    } catch (_) {
      stale.typedUnwrapDenied = true;
    }
    // Ingestion adopts the platform group name on every message, so the live
    // value is the message's name; the denied stale write must not replace it.
    stale.currentGroupUnchanged = ctx.group.groupName === "TestGroup";
    stale.currentPlayerUnchanged = ctx.player.name === "Registry Player";
    globalThis.__registryResult = stale;
    msg.message = ".rollshape set safe-tail";
    return undefined;
  }
  return null;
};
var command = seal.ext.newCmdItemInfo();
command.name = "registrysolve";
command.raw = true;
command.solve = function (ctx, msg) {
  msg.message = "solve-local-message";
  globalThis.__registrySolveResult = {
    groupIdentity: ctx.group === ctx.group,
    playerIdentity: ctx.player === ctx.player,
    detachedRoll: ctx.roll(1),
    typedHost: seal.format(ctx, "registry-solve") === "registry-solve",
    messageMutation: msg.message === "solve-local-message"
  };
  return seal.ext.newCmdExecuteResult(true);
};
ext.cmdMap["registrysolve"] = command;
seal.ext.register(ext);
`

	for _, runtimeID := range []string{string(jsengine.EngineGoja), "quickjs"} {
		t.Run(runtimeID, func(t *testing.T) {
			if runtimeID == "quickjs" && os.Getenv("SCARDICE_RUNTIME_ROOT") == "" && os.Getenv("SCARDICE_QUICKJS_PACKAGE") == "" {
				t.Skip("native QuickJS package is not configured")
			}
			packageID := "test/invocation-registry/" + runtimeID
			d, ep, adapter, _, loop := preparePublicPreprocessRuntime(t, runtimeID, packageID, "Invocation registry integration", scriptSource)
			groupID := "QQ-Group:invocation-registry-" + runtimeID

			preprocessExecuteMessage(t, d, ep, adapter, groupID, "registry-live", true)
			live := readJSRegistryResult(t, loop)
			for _, key := range []string{"sealInstAbsent", "groupIdentity", "playerIdentity", "endpointIdentity", "enumeration", "localFlags", "detachedTypedHost", "typedReply", "proxyIdentity", "tempEndpointIdentity", "tempGroupIdentity", "tempPlayerIdentity", "nestedEndpointIdentity"} {
				if value, _ := live[key].(bool); !value {
					t.Fatalf("live %s = %#v, want true; result=%#v", key, live[key], live)
				}
			}
			if live["groupName"] != "Registry Group" || live["playerName"] != "Registry Player" || live["playerTemplate"] != "Registry Card" || live["messageMutation"] != ".rollshape set soft" {
				t.Fatalf("live roundtrip mismatch: %#v", live)
			}
			if live["cocRuleIndex"] != float64(6) || live["detachedRoll"] != float64(1) || live["tempRoll"] != float64(1) {
				t.Fatalf("live numeric roundtrip mismatch: %#v", live)
			}

			preprocessExecuteMessage(t, d, ep, adapter, groupID, "registry-stale", true)
			stale := readJSRegistryResult(t, loop)
			if stale["groupName"] != "Registry Group" || stale["playerName"] != "Registry Player" || stale["roll"] != float64(1) {
				t.Fatalf("stale pure reads failed: %#v", stale)
			}
			for _, key := range []string{"groupWriteDenied", "playerWriteDenied", "localWriteDenied", "typedUnwrapDenied", "currentGroupUnchanged", "currentPlayerUnchanged"} {
				if value, _ := stale[key].(bool); !value {
					t.Fatalf("stale %s = %#v, want true; result=%#v", key, stale[key], stale)
				}
			}

			preprocessExecuteMessage(t, d, ep, adapter, groupID, ".registrysolve", true)
			solve := readJSJSONResult(t, loop, "globalThis.__registrySolveResult")
			for _, key := range []string{"groupIdentity", "playerIdentity", "typedHost", "messageMutation"} {
				if value, _ := solve[key].(bool); !value {
					t.Fatalf("solve %s = %#v, want true; result=%#v", key, solve[key], solve)
				}
			}
			if solve["detachedRoll"] != float64(1) {
				t.Fatalf("solve detached roll = %#v, want 1; result=%#v", solve["detachedRoll"], solve)
			}
		})
	}
}

func TestJSPersistentTopLevelTimersUseIndependentRoots(t *testing.T) {
	const (
		extensionName = "Persistent timer roots"
		scriptSource  = `
globalThis.__timerAwaiting = false;
globalThis.__timerDone = false;
globalThis.__intervalDone = false;
globalThis.__releasePersistentTimer = null;
var ext = seal.ext.new("Persistent timer roots", "test", "1.0.0");
seal.ext.register(ext);
globalThis.__timerTempContext = false;
setTimeout(async function () {
  var timerMessage = seal.newMessage();
  timerMessage.messageType = "private";
  timerMessage.sender.userId = "QQ:timer-user";
  timerMessage.sender.nickname = "Timer User";
  var timerContext = seal.createTempCtx(seal.getEndPoints()[0], timerMessage);
  globalThis.__timerTempContext = timerContext.roll(1) === 1;
  ext.storageSet("timer-before", "before");
  globalThis.__timerAwaiting = true;
  await new Promise(function (resolve) {
    globalThis.__releasePersistentTimer = resolve;
  });
  ext.storageSet("timer-after", "after");
  globalThis.__timerDone = true;
}, 20);
var interval = setInterval(function () {
  clearInterval(interval);
  ext.storageSet("interval", "fired");
  globalThis.__intervalDone = true;
}, 25);
`
	)

	for _, runtimeID := range []string{string(jsengine.EngineGoja), "quickjs"} {
		t.Run(runtimeID, func(t *testing.T) {
			if runtimeID == "quickjs" && os.Getenv("SCARDICE_RUNTIME_ROOT") == "" && os.Getenv("SCARDICE_QUICKJS_PACKAGE") == "" {
				t.Skip("native QuickJS package is not configured")
			}
			d, _, _, _, loop := preparePublicPreprocessRuntime(
				t,
				runtimeID,
				"test/persistent-timer-roots/"+runtimeID,
				extensionName,
				scriptSource,
			)

			waitJSGlobalBoolean(t, loop, "__timerAwaiting")
			waitJSGlobalBoolean(t, loop, "__intervalDone")
			waitPluginKV(t, d, extensionName, "interval", "fired")
			for _, key := range []string{"timer-before", "timer-after"} {
				repository, err := d.durablePluginKV()
				if err != nil {
					t.Fatal(err)
				}
				if item, err := repository.GetPluginKV(context.Background(), extensionName, key); !errors.Is(err, eventstore.ErrPluginKVNotFound) {
					t.Fatalf("%s committed while returned timer Promise was pending: value=%q err=%v", key, item.Value, err)
				}
			}

			resolverIdentity := d.DomainExecutionIdentity("js-test-persistent-timer-resolver", runtimeID)
			if err := d.WithDomainExecution(context.Background(), resolverIdentity, []byte("resolve-persistent-timer"), func(transaction *DurableCallbackTransaction) error {
				parent := context.Background()
				if transaction != nil && transaction.executionContext != nil {
					parent = transaction.executionContext
				}
				realm := jsContextForRoot(parent, d, nil, nil, transaction, false)
				return runJSExecutionRoot(realm, func() error {
					return jsengine.RunWithContext(loop, realm, func(runtime jsengine.Runtime) error {
						_, err := runtime.RunString("release-persistent-timer.js", "globalThis.__releasePersistentTimer()")
						return err
					})
				})
			}); err != nil {
				t.Fatal(err)
			}
			waitJSGlobalBoolean(t, loop, "__timerDone")
			waitJSGlobalBoolean(t, loop, "__timerTempContext")
			waitPluginKV(t, d, extensionName, "timer-before", "before")
			waitPluginKV(t, d, extensionName, "timer-after", "after")
		})
	}
}

func TestJSPersistentFetchContinuationUsesIndependentRoot(t *testing.T) {
	for _, runtimeID := range []string{string(jsengine.EngineGoja), "quickjs"} {
		t.Run(runtimeID, func(t *testing.T) {
			if runtimeID == "quickjs" && os.Getenv("SCARDICE_RUNTIME_ROOT") == "" && os.Getenv("SCARDICE_QUICKJS_PACKAGE") == "" {
				t.Skip("native QuickJS package is not configured")
			}
			releaseFetch := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				<-releaseFetch
				_, _ = writer.Write([]byte("fetch-root-value"))
			}))
			t.Cleanup(func() {
				select {
				case <-releaseFetch:
				default:
					close(releaseFetch)
				}
				server.Close()
			})
			extensionName := "Persistent fetch root " + runtimeID
			scriptSource := fmt.Sprintf(`// ==UserScript==
// @runtime %s:Scardice
// ==/UserScript==
globalThis.__fetchDone = false;
globalThis.__fetchError = "";
var ext = seal.ext.new(%q, "test", "1.0.0");
seal.ext.register(ext);
fetch(%q).then(function (response) {
  return response.text();
}).then(function (text) {
  ext.storageSet("fetch", text);
  globalThis.__fetchDone = true;
}, function (error) {
  globalThis.__fetchError = String(error);
  globalThis.__fetchDone = true;
});
`, runtimeID, extensionName, server.URL)
			d, _, _, _, loop := preparePublicPreprocessRuntime(
				t,
				runtimeID,
				"",
				extensionName,
				scriptSource,
			)
			close(releaseFetch)
			waitJSGlobalBoolean(t, loop, "__fetchDone")
			waitPluginKV(t, d, extensionName, "fetch", "fetch-root-value")
		})
	}
}

func TestExecuteJSUsesFreshRootAndAwaitsReturnedPromise(t *testing.T) {
	const (
		extensionName = "Execute JS root integration"
		scriptSource  = `var executeRootExt = seal.ext.new("Execute JS root integration", "test", "1.0.0"); seal.ext.register(executeRootExt);`
	)
	for _, runtimeID := range []string{string(jsengine.EngineGoja), "quickjs"} {
		t.Run(runtimeID, func(t *testing.T) {
			if runtimeID == "quickjs" && os.Getenv("SCARDICE_RUNTIME_ROOT") == "" && os.Getenv("SCARDICE_QUICKJS_PACKAGE") == "" {
				t.Skip("native QuickJS package is not configured")
			}
			d, _, _, _, _ := preparePublicPreprocessRuntime(
				t,
				runtimeID,
				"test/execute-js-root/"+runtimeID,
				extensionName,
				scriptSource,
			)
			initial, err := d.ExecuteJS(
				context.Background(),
				"api-js-exec.js",
				fmt.Sprintf(`seal.ext.find(%q).storageSet("count", "0"); undefined`, extensionName),
			)
			if err != nil {
				t.Fatal(err)
			}
			if initial != nil {
				t.Fatalf("undefined export = %#v, want nil", initial)
			}
			increment := fmt.Sprintf(`
new Promise(function (resolve) {
  setTimeout(function () {
    var target = seal.ext.find(%q);
    var next = Number(target.storageGet("count")) + 1;
    target.storageSet("count", String(next));
    resolve(next);
  }, 1);
})`, extensionName)
			for want := 1; want <= 2; want++ {
				got, executeErr := d.ExecuteJS(context.Background(), "api-js-exec.js", increment)
				if executeErr != nil {
					t.Fatal(executeErr)
				}
				if fmt.Sprint(got) != strconv.Itoa(want) {
					t.Fatalf("execution %d result = %#v", want, got)
				}
			}
			value, err := d.durableStorageGet(extensionName, "count")
			if err != nil {
				t.Fatal(err)
			}
			if value != "2" {
				t.Fatalf("committed count = %q, want 2", value)
			}
			if _, err = d.ExecuteJS(context.Background(), "api-js-exec.js", `({notPrimitive: true})`); !errors.Is(err, jsengine.ErrPrimitiveExportUnsupported) {
				t.Fatalf("object export error = %v", err)
			}
		})
	}
}

func TestJSHostLookupMissesPreserveNullAndUndefined(t *testing.T) {
	const (
		extensionName = "Host lookup absence contract"
		scriptSource  = `var lookupExt = seal.ext.new("Host lookup absence contract", "test", "1.0.0");
seal.ext.register(lookupExt);
var unregisteredLookupExt = seal.ext.new("Unregistered lookup absence", "test", "1.0.0");
if (seal.ban.getUser("QQ:missing-lookup-subject") !== null) {
  throw Error("missing ban lookup must return null");
}
if (seal.ext.find("Missing lookup extension") !== null) {
  throw Error("missing extension lookup must return null");
}
if (seal.ext.getConfig(lookupExt, "missing") !== null ||
    seal.ext.getConfig(unregisteredLookupExt, "missing") !== null ||
    seal.ext.getConfig(null, "missing") !== null) {
  throw Error("missing configuration lookup must return null");
}
if (lookupExt.missingProperty !== undefined) {
  throw Error("missing host property must remain undefined");
}
var missingTypedConfigRejected = false;
try {
  seal.ext.getStringConfig(lookupExt, "missing");
} catch (error) {
  missingTypedConfigRejected = String(error).indexOf("配置值类型不匹配") !== -1;
}
if (!missingTypedConfigRejected) {
  throw Error("typed configuration lookup must reject missing configuration");
}
if (seal.ext.removeTask(lookupExt, "*", "") !== 0) {
  throw Error("missing task configuration must not fabricate a task");
}
globalThis.__lookupAbsenceChecked = true;`
	)
	for _, runtimeID := range []string{string(jsengine.EngineGoja), "quickjs"} {
		t.Run(runtimeID, func(t *testing.T) {
			if runtimeID == "quickjs" && os.Getenv("SCARDICE_RUNTIME_ROOT") == "" && os.Getenv("SCARDICE_QUICKJS_PACKAGE") == "" {
				t.Skip("native QuickJS package is not configured")
			}
			_, _, _, _, loop := preparePublicPreprocessRuntime(
				t, runtimeID, "test/host-lookup-absence/"+runtimeID, extensionName, scriptSource,
			)
			if err := loop.Run(func(runtime jsengine.Runtime) error {
				if !runtime.Get("__lookupAbsenceChecked").ToBoolean() {
					return errors.New("host lookup absence assertions did not complete")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestJSBanLookupFailureIsNotMissingUser(t *testing.T) {
	const (
		extensionName = "Host lookup error contract"
		scriptSource  = `var lookupErrorExt = seal.ext.new("Host lookup error contract", "test", "1.0.0");
seal.ext.register(lookupErrorExt);`
	)
	for _, runtimeID := range []string{string(jsengine.EngineGoja), "quickjs"} {
		t.Run(runtimeID, func(t *testing.T) {
			if runtimeID == "quickjs" && os.Getenv("SCARDICE_RUNTIME_ROOT") == "" && os.Getenv("SCARDICE_QUICKJS_PACKAGE") == "" {
				t.Skip("native QuickJS package is not configured")
			}
			d, _, _, _, loop := preparePublicPreprocessRuntime(
				t, runtimeID, "test/host-lookup-error/"+runtimeID, extensionName, scriptSource,
			)
			store := d.DurableStore
			d.DurableStore = nil
			defer func() { d.DurableStore = store }()
			if err := loop.Run(func(runtime jsengine.Runtime) error {
				value, err := runtime.RunString("ban-lookup-failure.js", `
(function () {
  try {
    seal.ban.getUser("QQ:unavailable-lookup-subject");
    return false;
  } catch (error) {
    return true;
  }
})()`)
				if err != nil {
					return err
				}
				if !value.ToBoolean() {
					return errors.New("ban lookup storage failure became a missing-user result")
				}
				unconfigured := &Dice{}
				view := newDefaultConfigReadView(unconfigured)
				view.config.BanList = nil
				unconfigured.configView.Store(view)
				if installErr := unconfigured.installJSHostAPI(runtime, loop); installErr != nil {
					return installErr
				}
				value, err = runtime.RunString("ban-lookup-unconfigured.js", `seal.ban.getUser("QQ:missing-service") === null`)
				if err != nil {
					return err
				}
				if !value.ToBoolean() {
					return errors.New("missing ban service no longer returns null")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestJSTaskRemovalWithoutConfigRetiresRegisteredTask(t *testing.T) {
	const (
		extensionName = "Task removal without configuration"
		scriptSource  = `var noConfigTaskExt = seal.ext.new("Task removal without configuration", "test", "1.0.0");
seal.ext.register(noConfigTaskExt);
globalThis.noConfigTaskExt = noConfigTaskExt;
seal.ext.registerTask(noConfigTaskExt, "once", "3600000", function () {}, "", "", "");`
	)
	for _, runtimeID := range []string{string(jsengine.EngineGoja), "quickjs"} {
		t.Run(runtimeID, func(t *testing.T) {
			if runtimeID == "quickjs" && os.Getenv("SCARDICE_RUNTIME_ROOT") == "" && os.Getenv("SCARDICE_QUICKJS_PACKAGE") == "" {
				t.Skip("native QuickJS package is not configured")
			}
			d, _, _, _, loop := preparePublicPreprocessRuntime(
				t, runtimeID, "test/task-removal-no-config/"+runtimeID, extensionName, scriptSource,
			)
			extension := d.ExtFind(extensionName, true)
			if extension == nil || len(extension.taskList) != 1 {
				t.Fatal("once task was not registered after the script-load commit")
			}
			task := extension.taskList[0]
			t.Cleanup(func() { task.Off() })
			identity := d.DomainExecutionIdentity("js-test-remove-task-no-config", runtimeID)
			err := d.WithDomainExecution(context.Background(), identity, []byte(extensionName), func(transaction *DurableCallbackTransaction) error {
				realm := jsContextForRoot(transaction.executionContext, d, extension, extension.Source, transaction, false)
				return runJSExecutionRoot(realm, func() error {
					return jsengine.RunWithContext(loop, realm, func(runtime jsengine.Runtime) error {
						value, runErr := runtime.RunString("remove-task-no-config.js", `seal.ext.removeTask(globalThis.noConfigTaskExt, "once", "") === 1`)
						if runErr != nil {
							return runErr
						}
						if !value.ToBoolean() {
							return errors.New("missing configuration hid the registered once task")
						}
						return nil
					})
				})
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(extension.taskList) != 0 {
				t.Fatal("removed once task remained in the extension task list after commit")
			}
		})
	}
}

func waitJSGlobalBoolean(t *testing.T, loop jsengine.Loop, name string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var ready bool
		if err := jsengine.RunWithContext(loop, nil, func(runtime jsengine.Runtime) error {
			ready = runtime.Get(name).ToBoolean()
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if ready {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not become true", name)
		}
		time.Sleep(time.Millisecond)
	}
}

func waitPluginKV(t *testing.T, d *Dice, extensionID, key, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		value, err := d.durableStorageGet(extensionID, key)
		if err == nil && value == want {
			return
		}
		if err != nil && !errors.Is(err, eventstore.ErrPluginKVNotFound) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("plugin KV %s/%s = %q, %v; want %q", extensionID, key, value, err, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func readJSRegistryResult(t *testing.T, loop jsengine.Loop) map[string]any {
	t.Helper()
	return readJSJSONResult(t, loop, "globalThis.__registryResult")
}

func readJSJSONResult(t *testing.T, loop jsengine.Loop, expression string) map[string]any {
	t.Helper()
	var raw string
	if err := jsengine.RunWithContext(loop, nil, func(runtime jsengine.Runtime) error {
		value, err := runtime.RunString("invocation-registry-result.js", "JSON.stringify("+expression+")")
		if err != nil {
			return err
		}
		primitive, err := value.ExportPrimitive()
		if err != nil {
			return err
		}
		var ok bool
		raw, ok = primitive.(string)
		if !ok {
			return fmt.Errorf("registry result has type %T", primitive)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	result := map[string]any{}
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		t.Fatal(err)
	}
	return result
}
