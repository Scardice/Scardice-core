package dice

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"Scardice-core/core/configstate"
	"Scardice-core/dice/censor"
	"Scardice-core/dice/sealpack"
	"Scardice-core/eventstore"
	"Scardice-core/projectionset"
	"Scardice-core/utils/jsengine"

	"github.com/robfig/cron/v3"
	ds "github.com/sealdice/dicescript"
	"github.com/xuri/excelize/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type lightweightReadinessStore struct {
	eventstore.Store
	metadataCalls int
	fullCalls     int
}

func (s *lightweightReadinessStore) GetReadiness(context.Context) (eventstore.Readiness, error) {
	s.fullCalls++
	return eventstore.Readiness{}, context.Canceled
}

func (s *lightweightReadinessStore) GetReadinessMetadata(context.Context) (eventstore.Readiness, error) {
	s.metadataCalls++
	return eventstore.Readiness{Mode: "import"}, nil
}

func (*lightweightReadinessStore) SetReadiness(context.Context, eventstore.Readiness) error {
	return nil
}

func TestDefaultDiceMasterSeedUsesLightweightReadinessMetadata(t *testing.T) {
	store := &lightweightReadinessStore{}
	seed, err := shouldSeedDefaultDiceMasters(context.Background(), store, "default")
	if err != nil || seed {
		t.Fatalf("seed=%t err=%v", seed, err)
	}
	if store.metadataCalls != 1 || store.fullCalls != 0 {
		t.Fatalf("readiness calls: metadata=%d full=%d", store.metadataCalls, store.fullCalls)
	}
}

func TestRestoreEventSourcedDiceUsesConfigProjectionWithoutLegacyFiles(t *testing.T) {
	ctx := context.Background()
	database, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "events.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store := eventstore.NewStore(database, projectionset.StoreOptions()...)
	defer store.Close()
	for _, diceID := range []string{"beta", "alpha"} {
		baseline := configstate.Baseline{DiceID: diceID, CommandPrefix: []string{"."}}
		if _, err = configstate.NewRepository(store).DecideAndAppend(ctx, configstate.State{}, 0, eventstore.Metadata{}, configstate.Command{
			Kind: configstate.CommandImportBaseline, Baseline: &baseline,
		}); err != nil {
			t.Fatal(err)
		}
	}
	manager := &DiceManager{}
	if err = manager.InitializeRuntime(); err != nil {
		t.Fatal(err)
	}
	defer manager.Cron.Stop()
	if err = manager.RestoreEventSourcedDice(ctx, store); err != nil {
		t.Fatal(err)
	}
	if len(manager.Dice) != 2 || manager.Dice[0].BaseConfig.Name != "alpha" || manager.Dice[1].BaseConfig.Name != "beta" {
		t.Fatalf("restored Dice = %#v", manager.Dice)
	}
	for _, instance := range manager.Dice {
		if instance.DurableStore != store || instance.BaseConfig.DataDir != filepath.Join("data", instance.BaseConfig.Name) {
			t.Fatalf("restored instance = %#v", instance.BaseConfig)
		}
	}
}

type nameCommandReplyCapture struct {
	texts chan string
}

func (c *nameCommandReplyCapture) SubmitText(_ *MsgContext, _ *Message, text, _ string, _ bool) error {
	c.texts <- text
	return nil
}

type deckLoadCompletionSyncer struct {
	completed            chan struct{}
	jsStartupComplete    chan struct{}
	helpCompleted        chan struct{}
	helpCompletedAfterJS chan struct{}
	completedOnce        sync.Once
	jsCompleteOnce       sync.Once
	orderMu              sync.Mutex
	order                int
	jsCompleteOrder      int
	helpCompleteOrders   []int
	manager              *DiceManager
}

func (s *deckLoadCompletionSyncer) Write(p []byte) (int, error) {
	message := string(p)
	if strings.Contains(message, "JS 扩展脚本异步加载完成") {
		s.orderMu.Lock()
		if s.jsCompleteOrder == 0 {
			s.order++
			s.jsCompleteOrder = s.order
			s.jsCompleteOnce.Do(func() { close(s.jsStartupComplete) })
		}
		s.orderMu.Unlock()
	}
	if strings.Contains(message, "帮助文档异步加载结束") {
		s.orderMu.Lock()
		s.order++
		s.helpCompleteOrders = append(s.helpCompleteOrders, s.order)
		afterStartup := s.jsCompleteOrder != 0
		s.orderMu.Unlock()
		if s.helpCompleted != nil {
			select {
			case s.helpCompleted <- struct{}{}:
			default:
			}
		}
		if afterStartup && s.helpCompletedAfterJS != nil {
			select {
			case s.helpCompletedAfterJS <- struct{}{}:
			default:
			}
		}
	}
	if strings.Contains(message, "牌堆异步加载完成") {
		s.completedOnce.Do(func() { close(s.completed) })
	}
	return len(p), nil
}

func (s *deckLoadCompletionSyncer) Sync() error { return nil }

func TestWaitStartupJsLoadedWaitsAfterJsEnableCleared(t *testing.T) {
	previousMaxProcs := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previousMaxProcs)

	d := &Dice{Config: Config{JsConfig: JsConfig{JsEnable: false}}}
	d.beginStartupJsLoad()
	waitStarted := make(chan struct{})
	waitFinished := make(chan struct{})
	go func() {
		close(waitStarted)
		d.WaitStartupJsLoaded()
		close(waitFinished)
	}()

	<-waitStarted
	select {
	case <-waitFinished:
		d.finishStartupJsLoad()
		t.Fatal("WaitStartupJsLoaded returned while the startup load was active")
	default:
	}
	d.beginStartupJsLoad()
	d.finishStartupJsLoad()
	select {
	case <-waitFinished:
		d.finishStartupJsLoad()
		t.Fatal("WaitStartupJsLoaded returned before all startup loads completed")
	default:
	}
	d.finishStartupJsLoad()
	<-waitFinished
}
func writeNamesWorkbook(t *testing.T, path, sheetName string, rows [][]any) {
	t.Helper()
	file := excelize.NewFile()
	defaultSheet := file.GetSheetName(0)
	if err := file.SetSheetName(defaultSheet, sheetName); err != nil {
		t.Fatalf("rename names sheet: %v", err)
	}
	for i, row := range rows {
		cell := "A" + strconv.Itoa(i+1)
		if err := file.SetSheetRow(sheetName, cell, &row); err != nil {
			t.Fatalf("set names row %d: %v", i+1, err)
		}
	}
	if err := file.SaveAs(path); err != nil {
		t.Fatalf("save names workbook: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close names workbook: %v", err)
	}
}

func TestEventSourcedInitDiceLoadsNamesForPrivateNameCommand(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	namesDir := filepath.Join(root, "data", "names")
	if err := os.MkdirAll(namesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeNamesWorkbook(t, filepath.Join(namesDir, "names.xlsx"), "中文", [][]any{
		{"姓氏", "姓氏权重", "男性名", "女性名"},
		{"张", "1", "伟", "芳"},
		{"李", "1", "华", "婷"},
	})
	writeNamesWorkbook(t, filepath.Join(namesDir, "names-dnd.xlsx"), "DND", [][]any{
		{"未使用数据"},
	})

	ctx := context.Background()
	database, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{
		Type: "sqlite",
		DSN:  filepath.Join(root, "events.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	store := eventstore.NewStore(database, projectionset.StoreOptions()...)
	t.Cleanup(func() { _ = store.Close() })

	runtime := &Dice{
		BaseConfig:    BaseConfig{Name: "default", DataDir: filepath.Join(root, "dice")},
		DurableStore:  store,
		ContainerMode: true,
	}
	runtime.Config = NewConfig(runtime)
	runtime.Config.BaseConfig = runtime.BaseConfig
	runtime.Config.JsEnable = false
	manager := &DiceManager{Dice: []*Dice{runtime}}
	if err := manager.InitializeRuntime(); err != nil {
		t.Fatal(err)
	}
	if err := manager.PrepareEventSourcedState(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		manager.WaitNamesLoaded()
		runtime.WaitStartupJsLoaded()
		if runtime.ExtLoopManager != nil {
			if loop, _ := runtime.ExtLoopManager.CurrentLoop(); loop != nil {
				if err := loop.Run(func(jsengine.Runtime) error { return nil }); err != nil {
					t.Errorf("JS event loop did not start: %v", err)
				}
			}
			runtime.ExtLoopManager.SetLoop(nil)
		}
		manager.helpReloadLock.Lock()
		help := manager.Help
		manager.helpReloadLock.Unlock()
		if help != nil {
			help.Close()
		}
		if runtime.AttrsManager != nil {
			runtime.AttrsManager.Stop()
		}
		if runtime.Cron != nil {
			runtime.Cron.Stop()
		}
		if manager.Cron != nil {
			manager.Cron.Stop()
		}
	})

	manager.InitDice(nil)

	ext := runtime.ExtFind("story", false)
	if ext == nil || ext.CmdMap["name"] == nil {
		t.Fatal("EventStore runtime did not register the name command")
	}
	replies := &nameCommandReplyCapture{texts: make(chan string, 1)}
	runtime.OutboundBridge = replies
	endpoint := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{Platform: "test"}}
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
	result := ext.CmdMap["name"].Solve(msgCtx, msg, &CmdArgs{Args: []string{"cn", "2"}, RawArgs: "cn 2"})
	if !result.Matched || !result.Solved {
		t.Fatalf(".name cn 2 result = %#v, want solved", result)
	}
	if manager.NamesGenerator == nil {
		t.Fatal("private .name cn 2 returned before the EventStore names loader completed")
	}
	var replyText string
	select {
	case replyText = <-replies.texts:
	case <-time.After(5 * time.Second):
		t.Fatal("private .name cn 2 did not submit a reply")
	}
	lines := strings.Split(strings.TrimSpace(replyText), "\n")
	names := strings.Split(strings.TrimSpace(lines[len(lines)-1]), "、")
	if len(names) != 2 {
		t.Fatalf(".name cn 2 generated names = %q, want two names", replyText)
	}
	localNames := map[string]bool{
		"张伟": true, "张华": true, "张芳": true, "张婷": true,
		"李伟": true, "李华": true, "李芳": true, "李婷": true,
	}
	for _, name := range names {
		if name == "" || !localNames[name] {
			t.Fatalf(".name cn 2 generated %q, want a non-empty name from the local workbook; reply = %q", name, replyText)
		}
	}
}

const (
	startupHelpReloadChildEnv = "SCARDICE_STARTUP_HELP_RELOAD_FIXTURE"
	startupHelpReloadTestName = "TestEventSourcedStartupScriptReloadHelpCompletes"
)

func TestEventSourcedStartupScriptReloadHelpCompletes(t *testing.T) {
	if root := os.Getenv(startupHelpReloadChildEnv); root != "" {
		script := `// ==UserScript==
// @name EventStore startup ReloadHelp
// ==/UserScript==
seal.inst.config.jsEnable = false;
seal.inst.parent.reloadHelp();
const ext = seal.ext.new("startup-help-fixture", "test", "1.0.0");
seal.ext.register(ext);
`
		loadComplete := runEventSourcedInitDiceLoadsDecksWithScript(t, root, true, script, true)
		for i := range 2 {
			select {
			case <-loadComplete.helpCompleted:
			case <-time.After(5 * time.Second):
				t.Fatalf("help reload %d did not complete", i+1)
			}
		}
		loadComplete.orderMu.Lock()
		jsCompleteOrder := loadComplete.jsCompleteOrder
		helpCompleteOrders := append([]int(nil), loadComplete.helpCompleteOrders...)
		loadComplete.orderMu.Unlock()
		if len(helpCompleteOrders) < 2 || helpCompleteOrders[0] >= jsCompleteOrder || helpCompleteOrders[1] <= jsCompleteOrder {
			t.Fatalf("explicit and initial help completion order = %v, startup JS completion = %d", helpCompleteOrders, jsCompleteOrder)
		}
		manager := loadComplete.manager
		manager.helpReloadLock.Lock()
		help := manager.Help
		manager.helpReloadLock.Unlock()
		if help == nil || !help.IsAvailable() {
			t.Fatal("initial help startup did not leave an available help manager")
		}
		_, items := help.GetHelpItemPage(1, 1000, "", "", "", "")
		for _, item := range items {
			if item.Title == "startup-help-fixture" {
				return
			}
		}
		t.Fatalf("final help index did not include extension registered after explicit ReloadHelp: %#v", items)
		return
	}

	root := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+startupHelpReloadTestName+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), startupHelpReloadChildEnv+"="+root)
	output, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("isolated startup fixture exceeded its %s deadline; child terminated to contain blocked goroutines:\\n%s", 8*time.Second, output)
	}
	if err != nil {
		t.Fatalf("isolated startup fixture failed: %v\\n%s", err, output)
	}
}

func TestEventSourcedInitDiceLoadsDecksFromOnLoad(t *testing.T) {
	for _, jsEnabled := range []bool{false, true} {
		name := "js-disabled"
		if jsEnabled {
			name = "js-enabled"
		}
		t.Run(name, func(t *testing.T) {
			runEventSourcedInitDiceLoadsDecksFromOnLoad(t, jsEnabled, false)
		})
	}
}

func TestEventSourcedInitDiceLoadsDecksAfterJSDisablesJsEnable(t *testing.T) {
	runEventSourcedInitDiceLoadsDecksFromOnLoad(t, true, true)
}

func runEventSourcedInitDiceLoadsDecksFromOnLoad(t *testing.T, jsEnabled, disableJsOnStartup bool) *deckLoadCompletionSyncer {
	root := t.TempDir()
	startupScript := ""
	if disableJsOnStartup {
		startupScript = "// ==UserScript==\n// @name EventStore disables JS during startup\n// ==/UserScript==\n" +
			"seal.inst.config.jsEnable = false;\n"
	}
	return runEventSourcedInitDiceLoadsDecksWithScript(t, root, jsEnabled, startupScript, disableJsOnStartup)
}

func runEventSourcedInitDiceLoadsDecksWithScript(t *testing.T, root string, jsEnabled bool, startupScript string, expectJsDisabled bool) *deckLoadCompletionSyncer {
	t.Chdir(root)
	decksDir := filepath.Join(root, "data", "decks")
	if err := os.MkdirAll(decksDir, 0o700); err != nil {
		t.Fatal(err)
	}
	deckFixture := `{
		"_title": ["EventStore OnLoad Fixture"],
		"_author": ["local test"],
		"_version": ["1.0"],
		"Test OnLoad Deck": ["This deck was loaded during startup."]
	}`
	if err := os.WriteFile(filepath.Join(decksDir, "eventstore-onload.json"), []byte(deckFixture), 0o600); err != nil {
		t.Fatal(err)
	}

	loadComplete := &deckLoadCompletionSyncer{
		completed:            make(chan struct{}),
		jsStartupComplete:    make(chan struct{}),
		helpCompleted:        make(chan struct{}, 4),
		helpCompletedAfterJS: make(chan struct{}, 1),
	}
	core := zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), loadComplete, zapcore.DebugLevel)
	restoreLogger := zap.ReplaceGlobals(zap.New(core))
	t.Cleanup(restoreLogger)

	ctx := context.Background()
	database, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{
		Type: "sqlite",
		DSN:  filepath.Join(root, "events.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	store := eventstore.NewStore(database, projectionset.StoreOptions()...)
	t.Cleanup(func() { _ = store.Close() })

	dataDir := filepath.Join("data", "default")
	if startupScript != "" {
		scriptsDir := filepath.Join(dataDir, "scripts")
		if err := os.MkdirAll(scriptsDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(scriptsDir, "eventstore-startup.js"), []byte(startupScript), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runtime := &Dice{
		BaseConfig:    BaseConfig{Name: "default", DataDir: dataDir},
		DurableStore:  store,
		ContainerMode: true,
	}
	runtime.Config = NewConfig(runtime)
	runtime.Config.BaseConfig = runtime.BaseConfig
	runtime.Config.JsEnable = false
	manager := &DiceManager{Dice: []*Dice{runtime}}
	loadComplete.manager = manager
	if err := manager.InitializeRuntime(); err != nil {
		t.Fatal(err)
	}
	if err := manager.PrepareEventSourcedState(ctx); err != nil {
		t.Fatal(err)
	}
	runtime.AdvancedConfig.ExposeDangerousSealInst = startupScript != ""
	runtime.Config.JsEnable = jsEnabled
	t.Cleanup(func() {
		runtime.WaitStartupJsLoaded()
		if runtime.ExtLoopManager != nil {
			if loop, _ := runtime.ExtLoopManager.CurrentLoop(); loop != nil {
				if err := loop.Run(func(jsengine.Runtime) error { return nil }); err != nil {
					t.Errorf("JS event loop did not start: %v", err)
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
	})

	manager.InitDice(nil)
	if jsEnabled {
		runtime.WaitStartupJsLoaded()
		select {
		case <-loadComplete.jsStartupComplete:
		case <-time.After(5 * time.Second):
			t.Fatal("startup JS completion was not observed")
		}
		if expectJsDisabled && runtime.Config.JsEnable {
			var scriptStatus string
			if len(runtime.JsScriptList) > 0 {
				script := runtime.JsScriptList[0]
				scriptStatus = script.Name + " enable=" + strconv.FormatBool(script.Enable) + " err=" + script.ErrText
			}
			t.Fatalf("local startup script did not disable JsEnable: exposed=%v script=%q", runtime.JsSealInstExposed, scriptStatus)
		}
		for _, script := range runtime.JsScriptList {
			if script != nil && script.ErrText != "" {
				t.Fatalf("startup script %q failed: %s", script.Name, script.ErrText)
			}
		}
	}
	select {
	case <-loadComplete.completed:
	case <-time.After(5 * time.Second):
		t.Fatal("EventStore InitDice did not complete the deck loader from extension OnLoad")
	}

	ext := runtime.ExtFind("deck", false)
	if ext == nil || ext.CmdMap["draw"] == nil {
		t.Fatal("EventStore runtime did not register the deck draw command")
	}
	replies := &nameCommandReplyCapture{texts: make(chan string, 1)}
	runtime.OutboundBridge = replies
	endpoint := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{Platform: "test"}}
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
	result := ext.CmdMap["draw"].Solve(msgCtx, msg, &CmdArgs{Args: []string{"list"}, RawArgs: "list"})
	if !result.Matched || !result.Solved {
		t.Fatalf(".draw list result = %#v, want solved", result)
	}
	var replyText string
	select {
	case replyText = <-replies.texts:
	case <-time.After(5 * time.Second):
		t.Fatal(".draw list did not submit a reply")
	}
	if !strings.Contains(replyText, "EventStore OnLoad Fixture") {
		t.Fatalf(".draw list reply = %q, want startup-loaded local fixture", replyText)
	}
	helpCompletion := loadComplete.helpCompleted
	if jsEnabled {
		helpCompletion = loadComplete.helpCompletedAfterJS
	}
	select {
	case <-helpCompletion:
	case <-time.After(5 * time.Second):
		t.Fatal("initial help load did not complete")
	}
	return loadComplete
}

func TestInitEventSourcedRuntimeUsesUserTextTemplatesWithoutBuiltinBackfill(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	dataDir := filepath.Join(root, "dice")
	configDir := filepath.Join(dataDir, "configs")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	textTemplate := `核心:
  骰子名字:
    - ["自定义骰名", 1]
测试分类:
  欢迎:
    - ["自定义欢迎文案", 1]
`
	if err := os.WriteFile(filepath.Join(configDir, "text-template.yaml"), []byte(textTemplate), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	database, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{
		Type: "sqlite",
		DSN:  filepath.Join(root, "events.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store := eventstore.NewStore(database, projectionset.StoreOptions()...)
	defer store.Close()

	parent := &DiceManager{Cron: cron.New()}
	parent.Cron.Start()
	defer parent.Cron.Stop()
	runtime := &Dice{
		Parent:       parent,
		BaseConfig:   BaseConfig{Name: "default", DataDir: dataDir},
		DurableStore: store,
	}
	runtime.Config = NewConfig(runtime)
	runtime.Config.BaseConfig = runtime.BaseConfig
	// Keep the test focused on text initialization, not the JS event loop.
	runtime.Config.JsEnable = false
	defer func() {
		if runtime.AttrsManager != nil {
			runtime.AttrsManager.Stop()
		}
		if runtime.Cron != nil {
			runtime.Cron.Stop()
		}
	}()

	runtime.initEventSourcedRuntime(nil)

	msgCtx := &MsgContext{Dice: runtime, Session: runtime.ImSession}
	if got := DiceFormatTmpl(msgCtx, "核心:骰子名字"); got != "自定义骰名" {
		t.Fatalf("custom core text = %q, want %q", got, "自定义骰名")
	}
	if _, exists := runtime.TextMapRaw["核心"]["骰子帮助文本_骰点"]; exists {
		t.Fatal("builtin text missing from the user template was merged")
	}
	if got := DiceFormatTmpl(msgCtx, "测试分类:欢迎"); got != "自定义欢迎文案" {
		t.Fatalf("persisted custom category text = %q, want %q", got, "自定义欢迎文案")
	}
	if help := runtime.TextMapHelpInfo["测试分类"]["欢迎"]; help == nil || !help.NotBuiltin {
		t.Fatalf("custom text help metadata = %#v, want a custom entry", help)
	}
}
func TestPrepareEventSourcedConfigSeedsDefaultDiceMasters(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	database, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{
		Type: "sqlite",
		DSN:  filepath.Join(root, "events.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store := eventstore.NewStore(database, projectionset.StoreOptions()...)
	defer store.Close()

	runtime := &Dice{
		BaseConfig:   BaseConfig{Name: "default", DataDir: filepath.Join(root, "default")},
		DurableStore: store,
	}
	if err := runtime.prepareEventSourcedConfig(ctx, nil); err != nil {
		t.Fatalf("prepare event-sourced config: %v", err)
	}
	if want := []string{"UI:1001"}; !slices.Equal(runtime.DiceMasters, want) {
		t.Fatalf("fresh DiceMasters = %#v, want %#v", runtime.DiceMasters, want)
	}
}

func TestInitEventSourcedRuntimeLoadsPackageAndStoreManagers(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/info") {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"formatVersion":"2.0","name":"Local Store","protocolVersions":["2.0"]}`))
	}))
	defer server.Close()
	withOfficialStoreBackendBaseURL(t, server.URL)

	packageTemplate := loadTemplateFixture(t, "runtime-startup-template")
	jsOverride := strings.Replace(loadTemplateFixture(t, "runtime-startup-template"), "fullName: package fixture", "fullName: JS override", 1)
	jsOnly := strings.Replace(loadTemplateFixture(t, "runtime-js-only-template"), "fullName: package fixture", "fullName: JS only", 1)
	jsSource := "// ==UserScript==\n// @name EventStore startup template test\n// ==/UserScript==\n" +
		"seal.gameSystem.newTemplateByYaml(" + strconv.Quote(jsOverride) + ");\n" +
		"seal.gameSystem.newTemplateByYaml(" + strconv.Quote(jsOnly) + ");\n"
	archive := createTestSealPack(t, "", "alice/runtime-ui", "1.0.0", map[string][]string{
		"scripts":   {"scripts/*.js"},
		"templates": {"templates/*.yaml"},
	}, map[string]string{
		"scripts/startup-template.js": jsSource,
		"templates/runtime.yaml":      packageTemplate,
	})
	packageDir := filepath.Join("data", "packages", "alice")
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		t.Fatal(err)
	}
	copyTestFile(t, archive, filepath.Join(packageDir, "runtime-ui@1.0.0.sealpack"))
	dataDir := filepath.Join("data", "default")
	packageBootstrap := &Dice{
		BaseConfig: BaseConfig{DataDir: dataDir},
		Logger:     zap.NewNop().Sugar(),
	}
	packageBootstrap.PackageManager = NewPackageManager(packageBootstrap)
	if err := packageBootstrap.PackageManager.Init(); err != nil {
		t.Fatalf("initialize package state: %v", err)
	}
	if _, err := packageBootstrap.PackageManager.Enable("alice/runtime-ui"); err != nil {
		t.Fatalf("enable package template fixture: %v", err)
	}

	ctx := context.Background()
	database, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{
		Type: "sqlite",
		DSN:  filepath.Join(root, "events.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store := eventstore.NewStore(database, projectionset.StoreOptions()...)
	defer store.Close()

	parent := &DiceManager{Cron: cron.New()}
	parent.Cron.Start()
	defer parent.Cron.Stop()
	runtime := &Dice{
		Parent:       parent,
		BaseConfig:   BaseConfig{Name: "default", DataDir: dataDir},
		DurableStore: store,
	}
	runtime.Config = NewConfig(runtime)
	runtime.Config.BaseConfig = runtime.BaseConfig
	runtime.Config.JsEnable = true
	runtime.Config.EnableCensor = true
	runtime.Config.BackendUrls = []string{server.URL + "/custom"}
	defer func() {
		runtime.WaitStartupJsLoaded()
		if runtime.ExtLoopManager != nil {
			if loop, _ := runtime.ExtLoopManager.CurrentLoop(); loop != nil {
				if err := loop.Run(func(jsengine.Runtime) error { return nil }); err != nil {
					t.Errorf("JS 事件循环未在预期时间内启动: %v", err)
				}
			}
			runtime.ExtLoopManager.SetLoop(nil)
		}
		if runtime.AttrsManager != nil {
			runtime.AttrsManager.Stop()
		}
		if runtime.Cron != nil {
			runtime.Cron.Stop()
		}
	}()

	runtime.initEventSourcedRuntime(nil)
	runtime.WaitStartupJsLoaded()
	if !runtime.Config.JsEnable {
		t.Fatal("JS support was disabled during event-sourced initialization")
	}
	if runtime.CensorManager == nil || runtime.CensorManager.DB != nil {
		t.Fatalf("event-sourced censor manager = %#v, want initialized without legacy database", runtime.CensorManager)
	}

	pkg, ok := runtime.PackageManager.Get("alice/runtime-ui")
	if !ok || pkg == nil || pkg.Manifest == nil || pkg.Manifest.Package.Version != "1.0.0" {
		t.Fatalf("installed package was not available after initialization: %#v", pkg)
	}
	if pkg.State != sealpack.PackageStateEnabled {
		t.Fatalf("package state = %q, want enabled", pkg.State)
	}
	loadedPackageTemplate, ok := runtime.GameSystemMap.Load("runtime-startup-template")
	if !ok || loadedPackageTemplate.FullName != "package fixture" {
		t.Fatalf("package template after JS startup = %#v, want package fixture", loadedPackageTemplate)
	}
	var scriptStatus []string
	for _, script := range runtime.JsScriptList {
		if script != nil {
			scriptStatus = append(scriptStatus, script.Name+" enabled="+strconv.FormatBool(script.Enable)+" err="+script.ErrText)
		}
	}
	if _, ok := runtime.GameSystemMap.Load("runtime-js-only-template"); !ok {
		t.Fatalf("JS-only template was lost while restoring package templates; scripts = %v", scriptStatus)
	}

	reload := runtime.PackageManager.reloadPackageContent(packageReloadContentFlags{scripts: true, templates: true})
	if !reload.result.Success {
		t.Fatalf("reload scripts and templates together: %s", reload.result.Message)
	}
	if got, exists := runtime.GameSystemMap.Load("runtime-startup-template"); !exists || got.FullName != "package fixture" {
		t.Fatalf("package template after combined reload = %#v, want package fixture", got)
	}
	if _, exists := runtime.GameSystemMap.Load("runtime-js-only-template"); !exists {
		t.Fatal("JS-only template was lost after combined script and template reload")
	}

	var customBackend *StoreBackend
	for _, backend := range runtime.StoreManager.StoreBackendList() {
		if backend.Url == server.URL+"/custom" {
			customBackend = backend
			break
		}
	}
	if customBackend == nil || !customBackend.Health || customBackend.Name != "Local Store" {
		t.Fatalf("custom store backend was not available after initialization: %#v", customBackend)
	}
}

func TestPrepareEventSourcedConfigBackfillsDefaultMastersForUntouchedFreshStore(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	database, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{
		Type: "sqlite",
		DSN:  filepath.Join(root, "events.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store := eventstore.NewStore(database, projectionset.StoreOptions()...)
	defer store.Close()
	repository := configstate.NewRepository(store)
	if _, err := repository.DecideAndAppend(ctx, configstate.State{}, 0, eventstore.Metadata{}, configstate.Command{
		Kind: configstate.CommandImportBaseline,
		Baseline: &configstate.Baseline{
			DiceID:        "default",
			CommandPrefix: []string{"."},
		},
	}); err != nil {
		t.Fatalf("write old fresh baseline: %v", err)
	}

	runtime := &Dice{
		BaseConfig:   BaseConfig{Name: "default", DataDir: filepath.Join(root, "default")},
		DurableStore: store,
	}
	if err := runtime.prepareEventSourcedConfig(ctx, nil); err != nil {
		t.Fatalf("prepare old fresh configuration: %v", err)
	}
	if want := []string{"UI:1001"}; !slices.Equal(runtime.DiceMasters, want) {
		t.Fatalf("migrated DiceMasters = %#v, want %#v", runtime.DiceMasters, want)
	}
}

func TestPrepareEventSourcedConfigPreservesExplicitlyClearedMasters(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	database, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{
		Type: "sqlite",
		DSN:  filepath.Join(root, "events.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store := eventstore.NewStore(database, projectionset.StoreOptions()...)
	defer store.Close()
	repository := configstate.NewRepository(store)
	if _, err := repository.DecideAndAppend(ctx, configstate.State{}, 0, eventstore.Metadata{}, configstate.Command{
		Kind: configstate.CommandImportBaseline,
		Baseline: &configstate.Baseline{
			DiceID:        "default",
			CommandPrefix: []string{"."},
			DiceMasters:   []string{"UI:1001"},
		},
	}); err != nil {
		t.Fatalf("write baseline: %v", err)
	}
	state, err := repository.Load(ctx, "default")
	if err != nil {
		t.Fatalf("load baseline: %v", err)
	}
	if _, err := repository.DecideAndAppend(ctx, state, state.Version, eventstore.Metadata{}, configstate.Command{
		Kind: configstate.CommandPatch,
		Patch: &configstate.ConfigPatch{
			SetDiceMasters: true,
			DiceMasters:    []string{},
		},
	}); err != nil {
		t.Fatalf("clear DiceMasters: %v", err)
	}

	runtime := &Dice{
		BaseConfig:   BaseConfig{Name: "default", DataDir: filepath.Join(root, "default")},
		DurableStore: store,
	}
	if err := runtime.prepareEventSourcedConfig(ctx, nil); err != nil {
		t.Fatalf("prepare explicitly cleared configuration: %v", err)
	}
	if len(runtime.DiceMasters) != 0 {
		t.Fatalf("explicitly cleared DiceMasters restored unexpectedly: %#v", runtime.DiceMasters)
	}
}
func TestCensorCheckTracksThresholdWithoutLegacyLogStorage(t *testing.T) {
	engine := &censor.Censor{
		SensitiveKeys: map[string]censor.WordInfo{
			"badword": {Level: censor.Danger, Origin: "badword"},
		},
	}
	if err := engine.Load(); err != nil {
		t.Fatalf("load censor rules: %v", err)
	}
	manager := &CensorManager{Censor: engine}
	message := &Message{
		Sender:  SenderBase{UserID: "user-1"},
		Message: "badword",
	}
	result, err := manager.Check(&MsgContext{MessageType: "group"}, message, message.Message)
	if err != nil {
		t.Fatalf("check content without legacy log storage: %v", err)
	}
	if result.Level != censor.Danger || !slices.Contains(result.CurSensitiveWords, "badword") {
		t.Fatalf("censor result = %#v, want Danger hit for badword", result)
	}
	if result.HitCounts[censor.Danger] != 1 {
		t.Fatalf("in-memory hit counts without database = %#v, want Danger: 1", result.HitCounts)
	}
	otherMessage := &Message{
		Sender:  SenderBase{UserID: "user-2"},
		Message: "badword",
	}
	otherResult, err := manager.Check(&MsgContext{MessageType: "group"}, otherMessage, otherMessage.Message)
	if err != nil {
		t.Fatalf("check another user without legacy log storage: %v", err)
	}
	if otherResult.HitCounts[censor.Danger] != 1 {
		t.Fatalf("other user in-memory hit counts = %#v, want Danger: 1", otherResult.HitCounts)
	}

	result, err = manager.Check(&MsgContext{MessageType: "group"}, message, message.Message)
	if err != nil {
		t.Fatalf("repeat check without legacy log storage: %v", err)
	}
	if result.HitCounts[censor.Danger] != 2 {
		t.Fatalf("repeat in-memory hit counts = %#v, want Danger: 2", result.HitCounts)
	}
}
func TestCensorThresholdWithoutLegacyLogStorageTriggersAndClears(t *testing.T) {
	engine := &censor.Censor{
		SensitiveKeys: map[string]censor.WordInfo{
			"badword": {Level: censor.Danger, Origin: "badword"},
		},
	}
	if err := engine.Load(); err != nil {
		t.Fatalf("load censor rules: %v", err)
	}
	d := &Dice{
		Logger: zap.NewNop().Sugar(),
		Config: Config{
			CensorConfig: CensorConfig{
				CensorThresholds: map[censor.Level]int{
					censor.Ignore:  0,
					censor.Notice:  0,
					censor.Caution: 0,
					censor.Warning: 0,
					censor.Danger:  1,
				},
				CensorHandlers: make(map[censor.Level]uint8),
			},
		},
		CensorManager: &CensorManager{Censor: engine},
	}
	session := &IMSession{ServiceAtNew: new(SyncMap[string, *GroupInfo])}
	message := &Message{
		MessageType: "private",
		Sender:      SenderBase{UserID: "user-1"},
		Message:     "badword",
	}

	for index, wantTerminate := range []bool{false, true, false} {
		mctx := &MsgContext{Dice: d, Session: session, MessageType: "private"}
		_, _, gotTerminate, _ := d.CensorMsg(mctx, message, message.Message, "")
		if gotTerminate != wantTerminate {
			t.Fatalf("CensorMsg() hit %d termination = %v, want %v", index+1, gotTerminate, wantTerminate)
		}
	}
}
func TestCensorConcurrentMemoryThresholdsDoNotLoseHits(t *testing.T) {
	const (
		workerCount   = 16
		hitsPerWorker = 64
		threshold     = 1
	)
	previousProcs := runtime.GOMAXPROCS(4)
	t.Cleanup(func() {
		runtime.GOMAXPROCS(previousProcs)
	})

	engine := &censor.Censor{
		SensitiveKeys: map[string]censor.WordInfo{
			"badword": {Level: censor.Danger, Origin: "badword"},
		},
	}
	if err := engine.Load(); err != nil {
		t.Fatalf("load censor rules: %v", err)
	}
	manager := &CensorManager{Censor: engine}
	d := &Dice{
		Logger: zap.NewNop().Sugar(),
		Config: Config{
			CensorConfig: CensorConfig{
				CensorThresholds: map[censor.Level]int{
					censor.Ignore:  0,
					censor.Notice:  0,
					censor.Caution: 0,
					censor.Warning: 0,
					censor.Danger:  threshold,
				},
				CensorHandlers: make(map[censor.Level]uint8),
			},
		},
		CensorManager: manager,
	}
	session := &IMSession{ServiceAtNew: new(SyncMap[string, *GroupInfo])}
	message := &Message{
		MessageType: "private",
		Sender:      SenderBase{UserID: "concurrent-user"},
		Message:     "badword",
	}

	start := make(chan struct{})
	var workers sync.WaitGroup
	var terminated atomic.Int64
	for range workerCount {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			for range hitsPerWorker {
				mctx := &MsgContext{Dice: d, Session: session, MessageType: "private"}
				_, _, shouldTerminate, _ := d.CensorMsg(mctx, message, message.Message, "")
				if shouldTerminate {
					terminated.Add(1)
				}
			}
		}()
	}
	close(start)
	workers.Wait()

	totalHits := workerCount * hitsPerWorker
	wantTriggered := totalHits / (threshold + 1)
	if got := int(terminated.Load()); got != wantTriggered {
		t.Fatalf("concurrent threshold triggers = %d, want %d", got, wantTriggered)
	}
	counts := manager.snapshotMemoryHitCounts("concurrent-user", censor.Danger, false)
	if got, want := counts[censor.Danger], totalHits%(threshold+1); got != want {
		t.Fatalf("remaining concurrent hit count = %d, want %d", got, want)
	}
}
