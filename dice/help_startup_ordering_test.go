package dice

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"Scardice-core/eventstore"
	"Scardice-core/projectionset"
	"Scardice-core/utils/jsengine"

	ds "github.com/sealdice/dicescript"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type helpStartupLoadSyncer struct {
	loaded chan struct{}
	once   sync.Once
}

func (s *helpStartupLoadSyncer) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("帮助文档异步加载结束")) {
		s.once.Do(func() { close(s.loaded) })
	}
	return len(p), nil
}

func (*helpStartupLoadSyncer) Sync() error { return nil }

func TestInitialHelpLoadPendingWaitsForStartupJSBeforeManagerRead(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)

	loadSyncer := &helpStartupLoadSyncer{loaded: make(chan struct{})}
	core := zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), loadSyncer, zapcore.DebugLevel)
	restoreLogger := zap.ReplaceGlobals(zap.New(core))
	t.Cleanup(restoreLogger)

	testDice := &Dice{
		BaseConfig: BaseConfig{Name: "startup-help", DataDir: "data/startup-help"},
		CmdMap:     CmdMapCls{},
		ExtList:    []*ExtInfo{},
	}
	testDice.Config = NewConfig(testDice)
	testDice.Config.BaseConfig = testDice.BaseConfig
	manager := &DiceManager{Dice: []*Dice{testDice}, HelpDocEngineType: int(BlugeSearch)}
	testDice.Parent = manager

	testDice.beginStartupJsLoad()
	var releaseOnce sync.Once
	releaseStartupJS := func() { releaseOnce.Do(testDice.finishStartupJsLoad) }
	manager.startHelpDocLoadAsync()

	t.Cleanup(func() {
		releaseStartupJS()
		testDice.WaitStartupJsLoaded()
		select {
		case <-loadSyncer.loaded:
		case <-time.After(5 * time.Second):
			t.Error("initial HelpDoc load did not finish during cleanup")
		}
		manager.helpReloadLock.Lock()
		help := manager.Help
		manager.helpReloadLock.Unlock()
		if help != nil {
			help.Close()
		}
	})

	if !manager.IsHelpDocLoading() {
		t.Error("HelpDoc loading state is false while initial publication waits for startup JS")
	}

	type readResult struct {
		help *HelpManager
		err  error
	}
	readResults := make(chan readResult, 1)
	readStarted := make(chan struct{})
	go func() {
		close(readStarted)
		err := manager.WithHelpDocManagerRead(func(help *HelpManager) error {
			readResults <- readResult{help: help}
			return nil
		})
		if err != nil {
			readResults <- readResult{err: err}
		}
	}()
	<-readStarted

	var earlyRead *readResult
	select {
	case result := <-readResults:
		earlyRead = &result
	case <-time.After(100 * time.Millisecond):
		// The startup-JS barrier is channel-controlled; this deadline only
		// distinguishes a premature manager read from a correctly blocked one.
	}
	if earlyRead != nil && earlyRead.help == nil {
		t.Errorf("HelpDoc manager read returned nil before startup JS and initial publication completed")
	}

	releaseStartupJS()
	select {
	case <-loadSyncer.loaded:
	case <-time.After(5 * time.Second):
		t.Fatal("initial HelpDoc load did not finish after startup JS was released")
	}

	var published *HelpManager
	if err := manager.WithHelpDocManagerRead(func(help *HelpManager) error {
		published = help
		return nil
	}); err != nil {
		t.Fatalf("read published HelpDoc manager: %v", err)
	}
	if published == nil || !published.IsAvailable() {
		t.Fatal("initial HelpDoc load did not publish an available manager")
	}
	if earlyRead == nil {
		select {
		case result := <-readResults:
			if result.err != nil || result.help == nil {
				t.Fatalf("manager read after startup completion = %#v, want published HelpDoc manager", result)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("manager read did not complete after initial HelpDoc publication")
		}
	}
}

type helpStartupFailureSyncer struct {
	failed chan struct{}
	once   sync.Once
}

func (s *helpStartupFailureSyncer) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("Dice实例不存在")) {
		s.once.Do(func() { close(s.failed) })
	}
	return len(p), nil
}

func (*helpStartupFailureSyncer) Sync() error { return nil }

func TestInitialHelpLoadFailureReturnsErrorAndEndsPendingState(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)

	failureSyncer := &helpStartupFailureSyncer{failed: make(chan struct{})}
	core := zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), failureSyncer, zapcore.DebugLevel)
	restoreLogger := zap.ReplaceGlobals(zap.New(core))
	t.Cleanup(restoreLogger)

	manager := &DiceManager{}
	manager.startHelpDocLoadAsync()
	select {
	case <-failureSyncer.failed:
	case <-time.After(5 * time.Second):
		t.Fatal("initial HelpDoc load did not report the missing Dice instance")
	}

	callbackCalled := false
	err := manager.WithHelpDocManagerRead(func(*HelpManager) error {
		callbackCalled = true
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "Dice实例不存在") {
		t.Errorf("manager read after failed initial load error = %v, want explicit Dice instance error", err)
	}
	if callbackCalled {
		t.Error("manager read callback ran after initial HelpDoc load failed")
	}
	if manager.IsHelpReloading.Load() {
		t.Error("active HelpDoc reload remained set after initial load failure")
	}
	if manager.IsHelpDocLoading() {
		t.Error("HelpDoc loading remained true after initial load failure completed")
	}
}

const (
	nativeHelpStartupFixtureEnv    = "SCARDICE_NATIVE_HELP_STARTUP_FIXTURE"
	nativeHelpStartupPartialMarker = "native-help-partial-index-ready"
	nativeHelpStartupDoneMarker    = "native-help-startup-script-done"
	nativeHelpStartupUniqueTitle   = "native-help-startup-unique-extension"
)

type nativeHelpStartupGate struct {
	partialReached chan struct{}
	releasePartial chan struct{}
	scriptDone     chan struct{}
	partialOnce    sync.Once
	releaseOnce    sync.Once
	doneOnce       sync.Once
}

func newNativeHelpStartupGate() *nativeHelpStartupGate {
	return &nativeHelpStartupGate{
		partialReached: make(chan struct{}),
		releasePartial: make(chan struct{}),
		scriptDone:     make(chan struct{}),
	}
}

func (s *nativeHelpStartupGate) Write(p []byte) (int, error) {
	switch {
	case bytes.Contains(p, []byte(nativeHelpStartupPartialMarker)):
		s.partialOnce.Do(func() {
			close(s.partialReached)
			<-s.releasePartial
		})
	case bytes.Contains(p, []byte(nativeHelpStartupDoneMarker)):
		s.doneOnce.Do(func() { close(s.scriptDone) })
	}
	return len(p), nil
}

func (*nativeHelpStartupGate) Sync() error { return nil }

func (s *nativeHelpStartupGate) release() {
	s.releaseOnce.Do(func() { close(s.releasePartial) })
}

func TestNativeHelpCommandsUseOnlyPublishedStartupHelp(t *testing.T) {
	if root := os.Getenv(nativeHelpStartupFixtureEnv); root != "" {
		runNativeHelpStartupScenario(t, root)
		return
	}

	root := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNativeHelpCommandsUseOnlyPublishedStartupHelp$", "-test.count=1")
	command.Env = append(os.Environ(), nativeHelpStartupFixtureEnv+"="+root)
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("isolated native HelpDoc fixture exceeded 20s and was terminated:\n%s", output)
	}
	if err != nil {
		t.Fatalf("isolated native HelpDoc fixture failed: %v\n%s", err, output)
	}
}

func runNativeHelpStartupScenario(t *testing.T, root string) {
	t.Chdir(root)
	const startupScript = `// ==UserScript==
// @name Native Help startup publication fixture
// ==/UserScript==
seal.inst.config.jsEnable = false;
seal.inst.parent.reloadHelp();
console.log("native-help-partial-index-ready");
const ext = seal.ext.new("native-help-startup-unique-extension", "test", "1.0.0");
seal.ext.register(ext);
console.log("native-help-startup-script-done");
`
	scriptsDir := filepath.Join(root, "data", "default", "scripts")
	if err := os.MkdirAll(scriptsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scriptsDir, "eventstore-startup.js"), []byte(startupScript), 0o600); err != nil {
		t.Fatal(err)
	}

	gate := newNativeHelpStartupGate()
	core := zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), gate, zapcore.DebugLevel)
	restoreLogger := zap.ReplaceGlobals(zap.New(core))
	ctx := context.Background()
	database, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{
		Type: "sqlite",
		DSN:  filepath.Join(root, "events.db"),
	})
	if err != nil {
		restoreLogger()
		t.Fatal(err)
	}
	store := eventstore.NewStore(database, projectionset.StoreOptions()...)
	runtime := &Dice{
		BaseConfig:    BaseConfig{Name: "default", DataDir: filepath.Join("data", "default")},
		DurableStore:  store,
		ContainerMode: true,
	}
	runtime.Config = NewConfig(runtime)
	runtime.Config.BaseConfig = runtime.BaseConfig
	runtime.Config.JsEnable = false
	manager := &DiceManager{Dice: []*Dice{runtime}, HelpDocEngineType: int(BlugeSearch)}
	if err := manager.InitializeRuntime(); err != nil {
		restoreLogger()
		t.Fatal(err)
	}
	if err := manager.PrepareEventSourcedState(ctx); err != nil {
		restoreLogger()
		t.Fatal(err)
	}
	runtime.AdvancedConfig.ExposeDangerousSealInst = true
	runtime.Config.JsEnable = true
	t.Cleanup(func() {
		gate.release()
		startupDone := make(chan struct{})
		go func() {
			runtime.WaitStartupJsLoaded()
			close(startupDone)
		}()
		select {
		case <-startupDone:
		case <-time.After(5 * time.Second):
			t.Error("startup JavaScript did not finish during cleanup")
		}
		if runtime.ExtLoopManager != nil {
			if loop, _ := runtime.ExtLoopManager.CurrentLoop(); loop != nil {
				if err := loop.Run(func(jsengine.Runtime) error { return nil }); err != nil {
					t.Errorf("startup JavaScript event loop did not stop: %v", err)
				}
			}
			runtime.ExtLoopManager.SetLoop(nil)
		}
		manager.WaitNamesLoaded()
		if runtime.AttrsManager != nil {
			runtime.AttrsManager.Stop()
		}
		if runtime.Cron != nil {
			runtime.Cron.Stop()
		}
		if manager.Cron != nil {
			manager.Cron.Stop()
		}
		manager.helpReloadLock.Lock()
		help := manager.Help
		manager.helpReloadLock.Unlock()
		if help != nil {
			help.Close()
		}
		_ = store.Close()
		_ = database.Close()
		restoreLogger()
	})

	manager.InitDice(nil)
	select {
	case <-gate.partialReached:
	case <-time.After(5 * time.Second):
		t.Fatal("startup script did not reach the post-ReloadHelp partial-index gate")
	}
	if manager.IsHelpReloading.Load() {
		t.Fatal("explicit ReloadHelp is still active at the partial-index gate")
	}
	if !manager.IsHelpDocLoading() {
		t.Fatal("initial HelpDoc publication is not pending at the partial-index gate")
	}

	replies := &nameCommandReplyCapture{texts: make(chan string, 4)}
	runtime.OutboundBridge = replies
	endpoint := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{Platform: "test"}}
	newMsgContext := func() (*MsgContext, *Message) {
		player := &GroupPlayerInfo{Name: "Tester", UserID: "test:private", ValueMapTemp: &ds.ValueMap{}}
		msg := &Message{
			Platform:    "test",
			MessageType: "private",
			Sender:      SenderBase{UserID: player.UserID, Nickname: player.Name},
		}
		msgCtx := &MsgContext{
			Dice:                runtime,
			Session:             runtime.ImSession,
			EndPoint:            endpoint,
			Group:               &GroupInfo{GroupID: "test:private-group"},
			Player:              player,
			MessageType:         "private",
			IsPrivate:           true,
			IsCompatibilityTest: true,
		}
		return msgCtx, msg
	}
	solveAndReadReply := func(command string, args *CmdArgs) string {
		t.Helper()
		item := runtime.CmdMap[command]
		if item == nil {
			t.Fatalf("native command %q is not registered", command)
		}
		msgCtx, msg := newMsgContext()
		result := item.Solve(msgCtx, msg, args)
		if !result.Matched || !result.Solved {
			t.Fatalf(".%s result = %#v, want matched and solved", command, result)
		}
		select {
		case reply := <-replies.texts:
			return reply
		case <-time.After(5 * time.Second):
			t.Fatalf(".%s did not submit a reply", command)
			return ""
		}
	}

	manager.helpReloadLock.RLock()
	partialHelp := manager.Help
	if partialHelp == nil || !partialHelp.IsAvailable() {
		manager.helpReloadLock.RUnlock()
		t.Fatal("explicit ReloadHelp did not publish a partial HelpDoc manager")
	}
	partialCtx, _ := newMsgContext()
	partialResult, partialTotal, _, _, err := partialHelp.Search(partialCtx, nativeHelpStartupUniqueTitle, true, 10, 1, "")
	manager.helpReloadLock.RUnlock()
	if err != nil {
		t.Fatalf("search partial HelpDoc index: %v", err)
	}
	if partialTotal != 0 || partialResult == nil || len(partialResult.Hits) != 0 {
		t.Fatalf("partial HelpDoc search total=%d result=%#v, want no unique extension yet", partialTotal, partialResult)
	}

	findPendingReply := solveAndReadReply("find", &CmdArgs{Args: []string{nativeHelpStartupUniqueTitle}, CleanArgs: nativeHelpStartupUniqueTitle})
	if !strings.Contains(findPendingReply, "帮助文档") || !strings.Contains(findPendingReply, "正在") {
		t.Fatalf(".find during initial pending/partial index = %q, want a user-visible HelpDoc loading response", findPendingReply)
	}
	helpPendingReply := solveAndReadReply("help", &CmdArgs{Args: []string{nativeHelpStartupUniqueTitle}, CleanArgs: nativeHelpStartupUniqueTitle})
	if !strings.Contains(helpPendingReply, "帮助文档") || !strings.Contains(helpPendingReply, "正在") {
		t.Fatalf(".help during initial pending/partial index = %q, want a user-visible HelpDoc loading response", helpPendingReply)
	}

	gate.release()
	select {
	case <-gate.scriptDone:
	case <-time.After(5 * time.Second):
		t.Fatal("startup script did not register the unique extension")
	}
	startupDone := make(chan struct{})
	go func() {
		runtime.WaitStartupJsLoaded()
		close(startupDone)
	}()
	select {
	case <-startupDone:
	case <-time.After(5 * time.Second):
		t.Fatal("startup JavaScript did not finish after releasing the partial-index gate")
	}
	waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := manager.WaitForHelpDocStartup(waitCtx); err != nil {
		t.Fatalf("wait for final HelpDoc publication: %v", err)
	}

	findFinalReply := solveAndReadReply("find", &CmdArgs{Args: []string{nativeHelpStartupUniqueTitle}, CleanArgs: nativeHelpStartupUniqueTitle})
	if !strings.Contains(findFinalReply, nativeHelpStartupUniqueTitle) {
		t.Fatalf(".find after final startup publication = %q, want extension %q", findFinalReply, nativeHelpStartupUniqueTitle)
	}
	helpFinalReply := solveAndReadReply("help", &CmdArgs{Args: []string{nativeHelpStartupUniqueTitle}, CleanArgs: nativeHelpStartupUniqueTitle})
	if !strings.Contains(helpFinalReply, nativeHelpStartupUniqueTitle) {
		t.Fatalf(".help after final startup publication = %q, want extension %q", helpFinalReply, nativeHelpStartupUniqueTitle)
	}
}
