package dice

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"Scardice-core/core/messageflow"
	"Scardice-core/eventstore"
	"Scardice-core/utils/jsengine"
	gojaengine "Scardice-core/utils/jsengine/goja"
)

func TestExpiredMessageTimerCannotSendOrPersist(t *testing.T) {
	testExpiredMessageTimerCannotSendOrPersist(t, gojaengine.WrapEventLoop(startFsTestLoop(t)))
}

func testExpiredMessageTimerCannotSendOrPersist(t *testing.T, loop jsengine.Loop) {
	store, _ := repairTestStore(t)
	ctx, msg, _ := bridgeTestContext(&bridgeTestSubmitter{})
	ctx.Dice.DurableStore = store
	manager := NewJsLoopManager()
	generation := manager.SetLoop(loop)
	ctx.Dice.ExtLoopManager = manager
	ext := &ExtInfo{Name: "late-plugin", IsJsExt: true, dice: ctx.Dice, JSLoopVersion: generation}
	collector := messageflow.NewMutationCollector(eventstore.EventFactory{})
	tx, err := NewDurableCallbackTransaction(store, collector)
	if err != nil {
		t.Fatal(err)
	}
	ctx.callbackTransaction = tx
	if loop.Engine() == jsengine.EngineGoja {
		if err := gojaengine.InstallContextPropagation(loop); err != nil {
			t.Fatal(err)
		}
	}
	if err := loop.Run(func(rt jsengine.Runtime) error {
		if vm, ok := gojaengine.Raw(rt); ok {
			vm.SetFieldNameMapper(gojaengine.FieldNameMapper())
		}
		if err := rt.Bind("extension", ext); err != nil {
			return err
		}
		return rt.Bind("reply", func() { _ = ctx.Dice.OutboundBridge.SubmitText(ctx, msg, "late", "", false) })
	}); err != nil {
		t.Fatal(err)
	}
	if err := jsengine.RunWithContext(loop, jsContextForMessage(ext, ctx), func(rt jsengine.Runtime) error {
		_, err := rt.RunString("late.js", `setTimeout(function(){try { extension.storageSet("late", "escaped"); } catch (_) {} reply();}, 10)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	ctx.releaseExecutionState()
	finished := make(chan struct{})
	if err := loop.Run(func(rt jsengine.Runtime) error {
		if err := rt.Bind("finished", func() { close(finished) }); err != nil {
			return err
		}
		_, err := rt.RunString("unbound-timer.js", `setTimeout(function(){extension.storageSet("ordinary", "allowed"); finished();}, 40)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("ordinary scheduled task stopped")
	}
	if _, err := store.GetPluginKV(context.Background(), ext.Name, "late"); !errors.Is(err, eventstore.ErrPluginKVNotFound) {
		t.Errorf("late callback persisted: %v", err)
	}
	if value, err := store.GetPluginKV(context.Background(), ext.Name, "ordinary"); err != nil || string(value.Value) != "allowed" {
		t.Errorf("ordinary task value=%s err=%v", value.Value, err)
	}
	submitter := ctx.Dice.OutboundBridge.(*DurableOutboundBridge).submitter.(*bridgeTestSubmitter)
	submitter.mu.Lock()
	sent := submitter.request.Effect.ID
	submitter.mu.Unlock()
	if sent != "" {
		t.Errorf("late callback escaped to standalone outbound: %s", sent)
	}
}

func TestCopiedMessageCannotWriteAfterSourceRelease(t *testing.T) {
	store, _ := repairTestStore(t)
	source := &MsgContext{Dice: &Dice{DurableStore: store}}
	copied := source.ShallowCopy()
	jsContextForMessage(nil, copied)
	source.releaseExecutionState()
	if err := copied.ExtensionStorageSet("late-copy", "key", "escaped"); !errors.Is(err, context.Canceled) {
		t.Fatalf("copied message outlived source: %v", err)
	}
	if _, err := store.GetPluginKV(context.Background(), "late-copy", "key"); !errors.Is(err, eventstore.ErrPluginKVNotFound) {
		t.Fatalf("copied message persisted after release: %v", err)
	}
}

func TestSolveGraceReplyDoesNotAbortMessage(t *testing.T) {
	ctx, msg, _ := bridgeTestContext(&bridgeTestSubmitter{})
	loop := gojaengine.WrapEventLoop(startFsTestLoop(t))
	ctx.Dice.ExtLoopManager = NewJsLoopManager()
	generation := ctx.Dice.ExtLoopManager.SetLoop(loop)
	if err := gojaengine.InstallContextPropagation(loop); err != nil {
		t.Fatal(err)
	}
	if err := loop.Run(func(rt jsengine.Runtime) error {
		return rt.Bind("reply", func() { ReplyToSender(ctx, msg, "accepted reply") })
	}); err != nil {
		t.Fatal(err)
	}
	session := &IMSession{Parent: ctx.Dice}
	item := &CmdItemInfo{Name: "grace", JSLoopVersion: generation, SolveEngine: func(rt jsengine.Runtime, _ *MsgContext, _ *Message, _ *CmdArgs) (jsengine.Value, error) {
		return rt.RunString("grace.js", `setTimeout(reply, 10); undefined`)
	}}
	if result, err := session.executeSolveEngine(ctx, msg, &CmdArgs{}, item, nil); err != nil || !result.Solved {
		t.Fatalf("grace reply result=%#v err=%v", result, err)
	}
	if err := ctx.stopJSExecution(); err != nil {
		t.Fatalf("successful grace reply aborted message: %v", err)
	}
}

func TestJSOnMessageReceivedPromiseOwnsDispatchUntilFulfilled(t *testing.T) {
	const (
		packageID     = "test/on-message-received-promise"
		extensionName = "Async message hook"
	)
	script := `var ext = seal.ext.new("Async message hook", "test", "1.0.0");
ext.onMessageReceived = async function () {
  hookStarted();
  await new Promise(function (resolve) { globalThis.resolveMessageHook = resolve; });
  hookSettled();
};
seal.ext.register(ext);`
	d, ep, _, _, loop := preparePublicPreprocessRuntime(t, string(jsengine.EngineGoja), packageID, extensionName, script)
	started := make(chan struct{})
	settled := make(chan struct{})
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		if err := runtime.Bind("hookStarted", func() { close(started) }); err != nil {
			return err
		}
		return runtime.Bind("hookSettled", func() { close(settled) })
	}); err != nil {
		t.Fatal(err)
	}

	returned := make(chan messageExecutionResult, 1)
	go func() {
		returned <- d.ImSession.executeMessage(ep, newGroupMsg("QQ-Group:async-hook", "QQ:1001", "ordinary text"), messageExecutionOptions{
			parser: messageParserSegments, runInSync: true,
		})
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("onMessageReceived did not start")
	}
	select {
	case <-returned:
		t.Fatal("message dispatch returned while the onMessageReceived Promise was pending")
	case <-time.After(100 * time.Millisecond):
	}

	if err := loop.Run(func(runtime jsengine.Runtime) error {
		_, err := runtime.RunString("resolve-message-hook.js", "resolveMessageHook()")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-settled:
	case <-time.After(2 * time.Second):
		t.Fatal("onMessageReceived did not resume after fulfillment")
	}
	select {
	case <-returned:
		// Returning after hookSettled proves the continuation completed before
		// executeMessage released its message-owned execution scope.
	case <-time.After(2 * time.Second):
		t.Fatal("message dispatch did not return after the hook Promise fulfilled")
	}
}

func TestJSOnMessageReceivedPromiseRejectionReachesMessageExecution(t *testing.T) {
	const (
		packageID     = "test/on-message-received-rejection"
		extensionName = "Rejecting message hook"
		rejection     = "MESSAGE_HOOK_REJECTED"
	)
	script := `var ext = seal.ext.new("Rejecting message hook", "test", "1.0.0");
ext.onMessageReceived = async function () {
  hookStarted();
  await new Promise(function (_, reject) { globalThis.rejectMessageHook = reject; });
};
seal.ext.register(ext);`
	d, ep, _, _, loop := preparePublicPreprocessRuntime(t, string(jsengine.EngineGoja), packageID, extensionName, script)
	started := make(chan struct{})
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		return runtime.Bind("hookStarted", func() { close(started) })
	}); err != nil {
		t.Fatal(err)
	}

	returned := make(chan messageExecutionResult, 1)
	go func() {
		returned <- d.ImSession.executeMessage(ep, newGroupMsg("QQ-Group:rejecting-hook", "QQ:1001", "ordinary text"), messageExecutionOptions{
			parser: messageParserSegments, runInSync: true,
		})
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("onMessageReceived did not start")
	}
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		_, err := runtime.RunString("reject-message-hook.js", `rejectMessageHook(new Error("`+rejection+`"))`)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	select {
	case execution := <-returned:
		err := execution.context.stopJSExecution()
		if err == nil || !strings.Contains(err.Error(), rejection) {
			t.Fatalf("message execution error = %v, want Promise rejection containing %q", err, rejection)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("message dispatch did not return after the hook Promise rejected")
	}
}

func TestExecuteSolveEngineAwaitsEngineNeutralPromise(t *testing.T) {
	ctx, msg, _ := bridgeTestContext(&bridgeTestSubmitter{})
	loop := gojaengine.WrapEventLoop(startFsTestLoop(t))
	ctx.Dice.ExtLoopManager = NewJsLoopManager()
	generation := ctx.Dice.ExtLoopManager.SetLoop(loop)
	if err := gojaengine.InstallContextPropagation(loop); err != nil {
		t.Fatal(err)
	}

	promiseCreated := make(chan struct{})
	resolveErr := make(chan error, 1)
	go func() {
		<-promiseCreated
		resolveErr <- loop.Run(func(runtime jsengine.Runtime) error {
			_, err := runtime.RunString("resolve-engine-solve.js", "resolveEngineSolve({ matched: true, solved: true })")
			return err
		})
	}()

	item := &CmdItemInfo{
		Name:          "async-engine",
		JSLoopVersion: generation,
		SolveEngine: func(runtime jsengine.Runtime, _ *MsgContext, _ *Message, _ *CmdArgs) (jsengine.Value, error) {
			value, err := runtime.RunString("async-engine-solve.js", "new Promise(function (resolve) { globalThis.resolveEngineSolve = resolve; })")
			close(promiseCreated)
			return value, err
		},
	}
	result, err := (&IMSession{Parent: ctx.Dice}).executeSolveEngine(ctx, msg, &CmdArgs{}, item, nil)
	if resolverErr := <-resolveErr; resolverErr != nil {
		t.Fatal(resolverErr)
	}
	if err != nil {
		t.Fatalf("engine-neutral async solve failed: %v", err)
	}
	if !result.Matched || !result.Solved || result.ShowHelp {
		t.Fatalf("engine-neutral async solve result = %#v", result)
	}
}

func TestPendingMessageHookReturnsWhenMessageContextIsCanceled(t *testing.T) {
	const (
		packageID     = "test/pending-hook-cancellation"
		extensionName = "Pending canceled hook"
	)
	script := `var ext = seal.ext.new("Pending canceled hook", "test", "1.0.0");
ext.onMessageReceived = async function () {
  hookStarted();
  await new Promise(function () {});
};
seal.ext.register(ext);`
	d, ep, _, _, loop := preparePublicPreprocessRuntime(t, string(jsengine.EngineGoja), packageID, extensionName, script)
	started := make(chan struct{})
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		return runtime.Bind("hookStarted", func() { close(started) })
	}); err != nil {
		t.Fatal(err)
	}
	parent, cancel := context.WithCancel(context.Background())
	transaction := &DurableCallbackTransaction{executionContext: parent}
	returned := make(chan messageExecutionResult, 1)
	go func() {
		returned <- d.ImSession.executeMessage(ep, newGroupMsg("QQ-Group:cancel-hook", "QQ:1001", "ordinary text"), messageExecutionOptions{
			parser: messageParserSegments, runInSync: true, callbackTransaction: transaction,
		})
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("pending hook did not start")
	}
	cancel()
	select {
	case execution := <-returned:
		if err := execution.context.stopJSExecution(); !errors.Is(err, context.Canceled) {
			t.Fatalf("message cancellation error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("message dispatch did not stop after its context was canceled")
	}
}

func TestPendingMessageHookReleasedByLoopManagerLifecycle(t *testing.T) {
	for _, lifecycle := range []string{"replace", "stop"} {
		t.Run(lifecycle, func(t *testing.T) {
			packageID := "test/pending-hook-" + lifecycle
			extensionName := "Pending " + lifecycle + " hook"
			script := `var ext = seal.ext.new("` + extensionName + `", "test", "1.0.0");
ext.onMessageReceived = async function () {
  hookStarted();
  await new Promise(function () {});
};
seal.ext.register(ext);`
			d, ep, _, _, loop := preparePublicPreprocessRuntime(t, string(jsengine.EngineGoja), packageID, extensionName, script)
			started := make(chan struct{})
			if err := loop.Run(func(runtime jsengine.Runtime) error {
				return runtime.Bind("hookStarted", func() { close(started) })
			}); err != nil {
				t.Fatal(err)
			}
			transaction := &DurableCallbackTransaction{executionContext: context.Background()}
			returned := make(chan messageExecutionResult, 1)
			go func() {
				returned <- d.ImSession.executeMessage(ep, newGroupMsg("QQ-Group:manager-hook", "QQ:1001", "ordinary text"), messageExecutionOptions{
					parser: messageParserSegments, runInSync: true, callbackTransaction: transaction,
				})
			}()
			select {
			case <-started:
			case <-time.After(2 * time.Second):
				t.Fatal("pending hook did not start")
			}
			var replacement jsengine.Loop
			if lifecycle == "replace" {
				replacement = gojaengine.New()
			}
			lifecycleDone := make(chan struct{})
			go func() {
				defer close(lifecycleDone)
				if lifecycle == "replace" {
					d.ExtLoopManager.SetLoop(replacement)
				} else {
					_ = d.ExtLoopManager.stop()
				}
			}()
			select {
			case <-lifecycleDone:
			case <-time.After(2 * time.Second):
				t.Fatalf("manager %s waited for the message timeout", lifecycle)
			}
			select {
			case execution := <-returned:
				if err := execution.context.stopJSExecution(); err == nil {
					t.Fatalf("manager %s did not reach the pending hook", lifecycle)
				}
			case <-time.After(2 * time.Second):
				t.Fatalf("pending hook was not released by manager %s", lifecycle)
			}
		})
	}
}

func TestReentrantOnMessageSendPromiseJoinsMessageCompletion(t *testing.T) {
	const (
		packageID     = "test/reentrant-send-promise"
		extensionName = "Reentrant send promise"
	)
	script := `var ext = seal.ext.new("Reentrant send promise", "test", "1.0.0");
ext.onMessageSend = async function () {
  hookStarted();
  await new Promise(function (resolve) { globalThis.resolveSendHook = resolve; });
  hookSettled();
};
seal.ext.register(ext);`
	d, ep, _, _, loop := preparePublicPreprocessRuntime(t, string(jsengine.EngineGoja), packageID, extensionName, script)
	started := make(chan struct{})
	settled := make(chan struct{})
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		if err := runtime.Bind("hookStarted", func() { close(started) }); err != nil {
			return err
		}
		return runtime.Bind("hookSettled", func() { close(settled) })
	}); err != nil {
		t.Fatal(err)
	}
	ext, ok := d.JsExtRegistry.Load(extensionName)
	if !ok || ext == nil {
		t.Fatal("send hook extension was not registered")
	}
	ctx := &MsgContext{Dice: d, Session: d.ImSession, EndPoint: ep}
	msg := newGroupMsg("QQ-Group:send-hook", "QQ:1001", "outbound")
	ownerReturned := make(chan error, 1)
	go func() {
		ownerReturned <- jsengine.RunWithContext(loop, jsContextForMessage(ext, ctx), func(jsengine.Runtime) error {
			ext.CallOnMessageSend(d, ctx, msg, "")
			return nil
		})
	}()
	select {
	case err := <-ownerReturned:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("onMessageSend owner reentry deadlocked")
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("scheduled onMessageSend did not start")
	}
	stopped := make(chan error, 1)
	go func() { stopped <- ctx.stopJSExecution() }()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for {
		execution := ctx.messageJSExecution()
		execution.pendingMu.Lock()
		stopping, pending := execution.stopping, execution.pending
		execution.pendingMu.Unlock()
		if stopping {
			if pending != 1 {
				t.Fatalf("pending send hook count = %d", pending)
			}
			break
		}
		select {
		case err := <-stopped:
			t.Fatalf("message completed before send Promise settled: %v", err)
		case <-deadline.C:
			t.Fatal("message finalization did not join the send hook")
		default:
			runtime.Gosched()
		}
	}
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		_, err := runtime.RunString("resolve-send-hook.js", "resolveSendHook()")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-settled:
	case <-time.After(2 * time.Second):
		t.Fatal("onMessageSend did not settle")
	}
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatalf("message completion failed after send hook: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("message completion did not release after send Promise")
	}
}

func TestPublicAsyncSolveReleasedByLoopManagerStop(t *testing.T) {
	const (
		packageID     = "test/public-async-solve-stop"
		extensionName = "Public async solve stop"
	)
	script := `var ext = seal.ext.new("Public async solve stop", "test", "1.0.0");
var cmd = seal.ext.newCmdItemInfo();
cmd.name = "pending";
cmd.raw = true;
cmd.solve = async function () {
  solveStarted();
  await new Promise(function () {});
  return { matched: true, solved: true };
};
ext.cmdMap["pending"] = cmd;
seal.ext.register(ext);`
	d, ep, _, _, loop := preparePublicPreprocessRuntime(t, string(jsengine.EngineGoja), packageID, extensionName, script)
	started := make(chan struct{})
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		return runtime.Bind("solveStarted", func() { close(started) })
	}); err != nil {
		t.Fatal(err)
	}

	returned := make(chan messageExecutionResult, 1)
	go func() {
		returned <- d.ImSession.executeMessage(ep, newGroupMsg("QQ-Group:async-solve-stop", "QQ:1001", ".pending"), messageExecutionOptions{
			parser: messageParserSegments, runInSync: true,
		})
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("public async solve did not start")
	}

	stopped := make(chan error, 1)
	go func() { stopped <- d.ExtLoopManager.stop() }()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatalf("loop manager stop failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("loop manager stop waited for the pending public solve")
	}
	select {
	case execution := <-returned:
		if err := execution.context.stopJSExecution(); err == nil {
			t.Fatal("pending public solve did not report manager shutdown")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("public async solve was not released by manager stop")
	}
}
