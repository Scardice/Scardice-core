package dice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"Scardice-core/core/groupstate"
	"Scardice-core/core/messageflow"
	"Scardice-core/core/playerstate"
	"Scardice-core/eventstore"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"Scardice-core/utils/jsengine"
	gojaengine "Scardice-core/utils/jsengine/goja"
)

func TestPluginCompatibilityManifestIsExplicit(t *testing.T) {
	data, err := os.ReadFile("testdata/plugin_compat/manifest.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		ManifestVersion string `json:"manifestVersion"`
		FixtureVersion  string `json:"fixtureVersion"`
		Fixture struct {
			Covers []string `json:"covers"`
		} `json:"fixture"`
		RealmRules []string `json:"realmRules"`
		Callbacks struct {
			Order  []string `json:"order"`
			Fields []string `json:"fields"`
		} `json:"callbacks"`
		Categories map[string][]struct {
			Name    string   `json:"name"`
			Members []string `json:"members"`
			Reason  string   `json:"reason"`
		} `json:"categories"`
		MutationWhitelistCandidates map[string]json.RawMessage `json:"mutationWhitelistCandidates"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("manifest JSON: %v", err)
	}
	if manifest.ManifestVersion == "" {
		t.Fatal("manifestVersion is required")
	}
	requiredCoverage := []string{"$t", "$m", "$g", "player-attrs", "ban", "extension-config", "opaque-storage", "callbacks", "lifecycle", "external-effects"}
	coverage := make(map[string]bool, len(manifest.Fixture.Covers))
	for _, item := range manifest.Fixture.Covers {
		coverage[item] = true
	}
	for _, item := range requiredCoverage {
		if !coverage[item] {
			t.Fatalf("fixture coverage %q is required", item)
		}
	}
	if manifest.FixtureVersion == "" {
		t.Fatal("fixtureVersion is required")
	}
	for _, category := range []string{"supported", "unsupported_compatibility", "unsupported_private", "external_effect_ambiguous"} {
		entries, ok := manifest.Categories[category]
		if !ok || len(entries) == 0 {
			t.Fatalf("category %q must be explicit and non-empty", category)
		}
		for _, entry := range entries {
			if entry.Name == "" {
				t.Fatalf("category %q has unnamed entry", category)
			}
			if category == "supported" && len(entry.Members) == 0 {
				t.Fatalf("supported entry %q has no members", entry.Name)
			}
			if category != "supported" && entry.Reason == "" {
				t.Fatalf("category %q entry %q has no reason", category, entry.Name)
			}
		}
	}
	if len(manifest.RealmRules) == 0 || len(manifest.Callbacks.Order) == 0 || len(manifest.Callbacks.Fields) == 0 {
		t.Fatal("realm rules and callback order/fields are required")
	}
	candidates, ok := manifest.MutationWhitelistCandidates["context"]
	var contextCandidates []json.RawMessage
	if !ok || json.Unmarshal(candidates, &contextCandidates) != nil || len(contextCandidates) == 0 {
		t.Fatal("context mutation whitelist candidates are required")
	}
}

func TestPluginCompatibilityFixtureHostAndContext(t *testing.T) {
	fixture, err := os.ReadFile("testdata/plugin_compat/fixture.js")
	if err != nil {
		t.Fatal(err)
	}
	loop := gojaengine.New()
	defer loop.Close()

	var context *MsgContext
	var message *Message
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		d := &Dice{Logger: zap.NewNop().Sugar()}
		d.Config.BanList = &BanListInfo{Parent: d}
		d.Config.BanList.Init()
		if err := d.installJSHostAPI(runtime); err != nil {
			return err
		}
		if err := d.installJSExtHostAPI(runtime, loop, runtime.Get("seal").Object(), 1, nil); err != nil {
			return err
		}
		context = &MsgContext{
			MessageType:     "group",
			IsPrivate:       false,
			IsCurGroupBotOn: true,
			PrivilegeLevel:  50,
			DelegateText:    "delegate",
			CommandHideFlag: "",
			Group:           &GroupInfo{GroupID: "QQ-Group:100", GroupName: "Fixture"},
		}
		message = &Message{MessageType: "group", GroupID: "QQ-Group:100", Message: "hello", Sender: SenderBase{UserID: "QQ:200", Nickname: "Alice"}}
		if err := runtime.Bind("fixtureContext", context); err != nil {
			return err
		}
		if err := runtime.Bind("fixtureMessage", message); err != nil {
			return err
		}
		if _, err := runtime.RunString("plugin-compat-fixture.js", string(fixture)); err != nil {
			return err
		}
		value, err := runtime.RunString("plugin-compat-host.js", `JSON.stringify(pluginCompatFixture.host())`)
		if err != nil {
			return err
		}
		if got := value.Export(); got != `{"functionTypes":["function","function","function","function","function","function","function","function"],"extensionMethods":["function","function","function"],"roundTrip":"Scardice","forward":"1001","message":"hello","versionType":"string"}` {
			t.Fatalf("host fixture = %v", got)
		}
		value, err = runtime.RunString("plugin-compat-context.js", `JSON.stringify(pluginCompatFixture.context(fixtureContext, fixtureMessage))`)
		if err != nil {
			return err
		}
		if got := value.Export(); got != `{"groupId":"QQ-Group:100","message":"hello","sender":"QQ:200","private":false,"privilege":50,"delegate":"delegate"}` {
			t.Fatalf("context fixture = %v", got)
		}
		if _, err := runtime.RunString("plugin-compat-mutate.js", `pluginCompatFixture.mutateContext(fixtureContext)`); err != nil {
			return err
		}
		value, err = runtime.RunString("plugin-compat-errors.js", `pluginCompatFixture.errors()`)
		if err != nil {
			return err
		}
		if !strings.Contains(value.Export().(string), "请先完成此扩展的注册") {
			t.Fatalf("documented error = %q", value.Export())
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !context.IsPrivate || context.CommandHideFlag != "hidden" || context.DelegateText != "changed" {
		t.Fatalf("writable context fields = private=%v hide=%q delegate=%q", context.IsPrivate, context.CommandHideFlag, context.DelegateText)
	}
	if message.Message != "hello" {
		t.Fatalf("fixture unexpectedly changed message: %q", message.Message)
	}
}

func TestPluginCompatibilityCallbackOrderFixture(t *testing.T) {
	fixture, err := os.ReadFile("testdata/plugin_compat/fixture.js")
	if err != nil {
		t.Fatal(err)
	}
	loop := gojaengine.New()
	defer loop.Close()

	if err := loop.Run(func(runtime jsengine.Runtime) error {
		d := &Dice{Logger: zap.NewNop().Sugar()}
		d.Config.BanList = &BanListInfo{Parent: d}
		d.Config.BanList.Init()
		if err := d.installJSHostAPI(runtime); err != nil {
			return err
		}
		if err := d.installJSExtHostAPI(runtime, loop, runtime.Get("seal").Object(), 1, nil); err != nil {
			return err
		}
		ext := &ExtInfo{}
		if err := runtime.Bind("fixtureExtension", ext); err != nil {
			return err
		}
		if _, err := runtime.RunString("plugin-compat-callback-fixture.js", string(fixture)+`
			globalThis.pluginCompatOrder = [];
			pluginCompatFixture.callbacks(fixtureExtension);
		`); err != nil {
			return err
		}
		ctx, msg := &MsgContext{}, &Message{}
		if ext.OnMessagePreprocess == nil || ext.OnMessageReceived == nil || ext.OnCommandReceived == nil || ext.OnMessageSend == nil {
			return fmt.Errorf("fixture did not install callback fields")
		}
		ext.OnMessagePreprocess(ctx, msg)
		ext.OnMessageReceived(ctx, msg)
		ext.OnCommandReceived(ctx, msg, &CmdArgs{})
		ext.OnMessageSend(ctx, msg, "fixture")
		value, err := runtime.RunString("plugin-compat-callback-order.js", `JSON.stringify(pluginCompatOrder)`)
		if err != nil {
			return err
		}
		if got := value.Export(); got != `["preprocess","received","command","send"]` {
			return fmt.Errorf("callback order = %v", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
func TestPluginCompatibilityFixtureDurableSmokePlan(t *testing.T) {
	fixture, err := os.ReadFile("testdata/plugin_compat/fixture.js")
	if err != nil {
		t.Fatal(err)
	}
	loop := gojaengine.New()
	defer loop.Close()
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		if _, err := runtime.RunString("plugin-compat-durable-smoke.js", string(fixture)); err != nil {
			return err
		}
		value, err := runtime.RunString("plugin-compat-durable-smoke-plan.js", `JSON.stringify(pluginCompatFixture.durableSmoke())`)
		if err != nil {
			return err
		}

		if got := value.Export(); got != `{"transient":"$t","owners":["$m","$g"],"attrs":"player","ban":["add","remove"],"config":"extension","storage":"opaque","callbacks":["preprocess","command","reply","send"],"lifecycle":["group","member"]}` {
			return fmt.Errorf("durable smoke plan = %v", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
func TestPluginCompatibilityFixtureExercisesDurableSurface(t *testing.T) {
	fixture, err := os.ReadFile("testdata/plugin_compat/fixture.js")
	if err != nil {
		t.Fatal(err)
	}
	transient, storage := "before", "opaque-before"
	probe := map[string]any{
		"transientGet": func() string { return transient },
		"transientSet": func(value string) { transient = value },
		"ownerM":       func() string { return "$m-unsupported" },
		"ownerG":       func() string { return "$g-unsupported" },
		"banAdd":       func() string { return "added" },
		"banRemove":    func() string { return "removed" },
		"config":       func() string { return "enabled" },
		"storageGet":   func() string { return storage },
		"storageSet":   func(value string) { storage = value },
		"reply":        func() string { return "reply" },
		"send":         func() string { return "send" },
	}
	loop := gojaengine.New()
	defer loop.Close()
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		if err := runtime.Bind("pluginCompatProbe", probe); err != nil {
			return err
		}
		if _, err := runtime.RunString("plugin-compat-durable-surface.js", string(fixture)); err != nil {
			return err
		}
		value, err := runtime.RunString("plugin-compat-durable-surface-run.js", `JSON.stringify(pluginCompatFixture.durableSmoke(pluginCompatProbe))`)
		if err != nil {
			return err
		}
		if got := value.Export(); got != `{"transient":["before","changed"],"owners":["$m-unsupported","$g-unsupported"],"ban":["added","removed"],"config":"enabled","storage":["opaque-before","opaque-after"],"callbacks":["preprocess","command","reply","send"]}` {
			return fmt.Errorf("durable smoke surface = %v", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if transient != "changed" || storage != "opaque-after" {
		t.Fatalf("probe state transient=%q storage=%q", transient, storage)
	}
}

func TestPluginCompatibilityDurableSmokeRestartRebuildAndCrash(t *testing.T) {
	ctx := context.Background()
	clock := &compatFixedClock{now: time.Unix(1_700_000_000, 123).UTC()}
	ids := &compatFixedIDs{}
	dsn := filepath.Join(t.TempDir(), "plugin-compat.db")
	store, _ := openCompatSmokeStore(t, dsn, clock, ids, true)

	scope := JSMutationScope{DiceID: "dice-compat", GroupID: "group-compat", UserID: "user-compat"}
	metadata := eventstore.Metadata{
		CommandID: "compat-command", CorrelationID: "compat-correlation",
		OccurredAt: clock.Now(), Producer: "plugin-compat-fixture",
	}
	transient := playerstate.NewLocalOverlay()
	transient.Set("$tfixture", "before")
	if value, ok := transient.Get("$tfixture"); !ok || value != "before" {
		t.Fatalf("$t read-after-write = %q, present=%v", value, ok)
	}
	if _, ok := transient.Get("$mfixture"); ok {
		t.Fatal("request-local $t overlay exposed an owner value")
	}
	core := messageflow.NewMutationCollector(eventstore.EventFactory{Clock: clock, IDs: ids})
	collector := NewJSMutationCollector(core, scope, metadata)
	if err := collector.CaptureGroup(
		groupstate.NewGroupCreatedV1(scope.DiceID, scope.GroupID, "Compatibility", clock.Now().Unix()),
		groupstate.NewGroupExtensionChangedV1("fixture-extension", true),
	); err != nil {
		t.Fatalf("group lifecycle capture: %v", err)
	}
	if err := collector.CapturePlayer(
		playerstate.NewPlayerCreatedV1(scope.DiceID, scope.GroupID, scope.UserID, "Alice"),
		playerstate.NewPlayerPrivilegeChangedV1(20),
	); err != nil {
		t.Fatalf("player lifecycle capture: %v", err)
	}
	if err := collector.CaptureGroupUserAttrs([]playerstate.GroupUserAttrsEvent{
		playerstate.NewGroupUserAttrsCreatedV1(scope.DiceID, scope.GroupID, scope.UserID),
		playerstate.NewGroupUserAttrsSetV1("score", []byte("opaque-value"), "root-v1"),
	}, nil); err != nil {
		t.Fatalf("player attrs capture: %v", err)
	}
	if err := collector.CaptureM(JSGroupUserAttrsMutation{Operation: "set", Key: "unsupported-m"}); !errors.Is(err, ErrJSUnsupportedOwner) {
		t.Fatalf("unsupported $m error = %v", err)
	}
	if err := collector.CaptureG(JSGroupUserAttrsMutation{Operation: "set", Key: "unsupported-g"}); !errors.Is(err, ErrJSUnsupportedOwner) {
		t.Fatalf("unsupported $g error = %v", err)
	}
	collector.RegisterConfig("fixture-extension", "enabled", func(value any) error {
		if enabled, ok := value.(bool); !ok || !enabled {
			return errors.New("enabled must be true")
		}
		return nil
	})
	if err := collector.CaptureConfig(JSConfigMutation{ExtensionID: "fixture-extension", Key: "enabled", Value: true}); err != nil {
		t.Fatalf("extension config capture: %v", err)
	}

	overlay, err := NewJSPluginKVOverlayForCollectorWithBackend("fixture-extension", store, core, store)
	if err != nil {
		t.Fatalf("opaque storage overlay: %v", err)
	}
	if err := overlay.Put(ctx, "opaque", []byte("read-your-writes"), 0); err != nil {
		t.Fatalf("opaque storage write: %v", err)
	}
	pending, err := overlay.Get(ctx, "opaque")
	if err != nil || string(pending.Value) != "read-your-writes" || pending.Version != 1 {
		t.Fatalf("opaque storage read-your-writes = %#v, err=%v", pending, err)
	}
	listed, err := overlay.List(ctx, "", 10)
	if err != nil || len(listed) != 1 || listed[0].Key != "opaque" {
		t.Fatalf("opaque storage list = %#v, err=%v", listed, err)
	}
	if err := overlay.Commit(ctx); err != nil {
		t.Fatalf("opaque storage commit: %v", err)
	}
	standalone, err := NewJSPluginKVOverlay("fixture-extension", store, store)
	if err != nil {
		t.Fatalf("standalone opaque storage overlay: %v", err)
	}
	if err := standalone.Put(ctx, "standalone", []byte("standalone-write"), 0); err != nil {
		t.Fatalf("standalone opaque storage write: %v", err)
	}
	standalonePending, err := standalone.Get(ctx, "standalone")
	if err != nil || string(standalonePending.Value) != "standalone-write" {
		t.Fatalf("standalone read-your-writes = %#v, err=%v", standalonePending, err)
	}
	if err := standalone.Commit(ctx); err != nil {
		t.Fatalf("standalone opaque storage commit: %v", err)
	}

	replyCipher, replyNonce, replyKey, err := store.EncryptBound(ctx, "outbox/v1", "compat-reply", "endpoint-compat", 1, []byte("reply"))
	if err != nil {
		t.Fatalf("reply effect encryption: %v", err)
	}
	if err := collector.CaptureReply(JSEffectRequest{
		EffectID: "compat-reply", EndpointID: "endpoint-compat", LaneHMAC: []byte("compat-reply-lane"),
		RiskClass: eventstore.RiskPreDispatchRetryable, Status: eventstore.OutboxStatusPending,
		PayloadCiphertext: replyCipher, PayloadNonce: replyNonce, PayloadVersion: 1, PayloadEncryptionKeyID: replyKey,
	}); err != nil {
		t.Fatalf("reply effect capture: %v", err)
	}
	sendCipher, sendNonce, sendKey, err := store.EncryptBound(ctx, "outbox/v1", "compat-send", "endpoint-compat", 1, []byte("send"))
	if err != nil {
		t.Fatalf("send effect encryption: %v", err)
	}
	if err := collector.CaptureEffect(JSEffectRequest{
		EffectID: "compat-send", EndpointID: "endpoint-compat", LaneHMAC: []byte("compat-send-lane"),
		EffectType: "send", RiskClass: eventstore.RiskNonIdempotentAfterDispatch, Status: eventstore.OutboxStatusPending,
		PayloadCiphertext: sendCipher, PayloadNonce: sendNonce, PayloadVersion: 1, PayloadEncryptionKeyID: sendKey,
	}); err != nil {
		t.Fatalf("best-effort send effect capture: %v", err)
	}

	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatalf("compatibility unit of work: %v", err)
	}
	if len(work.Streams) != 3 || len(work.PluginKVUpdates) != 1 || len(work.Effects) != 2 {
		t.Fatalf("compatibility work participants = %#v", work)
	}
	if _, err := store.Commit(ctx, work); err != nil {
		t.Fatalf("compatibility commit: %v", err)
	}
	if _, err := store.Commit(ctx, work); !errors.Is(err, eventstore.ErrConflict) {
		t.Fatalf("pre-callback conflict = %v", err)
	}

	group, err := groupstate.NewRepository(store).Load(ctx, scope.DiceID, scope.GroupID)
	if err != nil || group.GroupName != "Compatibility" || len(group.ActivatedExtensions) != 1 {
		t.Fatalf("group read = %#v, err=%v", group, err)
	}
	player, err := playerstate.NewRepository(store).LoadPlayer(ctx, scope.DiceID, scope.GroupID, scope.UserID)
	if err != nil || player.Name != "Alice" || player.Privilege != 20 {
		t.Fatalf("player read = %#v, err=%v", player, err)
	}
	attrs, err := playerstate.NewRepository(store).LoadGroupUserAttrs(ctx, scope.DiceID, scope.GroupID, scope.UserID)
	if err != nil || len(attrs.Operations) != 1 || attrs.Operations[0].Key != "score" {
		t.Fatalf("player attrs read = %#v, err=%v", attrs, err)
	}
	configs := collector.ConfigMutations()
	if len(configs) != 1 || configs[0].ExtensionID != "fixture-extension" || configs[0].Value != true {
		t.Fatalf("extension config read = %#v", configs)
	}

	groupEvents, err := store.Load(ctx, groupstate.GroupStream(scope.DiceID, scope.GroupID), 1)
	if err != nil || len(groupEvents) == 0 {
		t.Fatalf("group events = %#v, err=%v", groupEvents, err)
	}
	liveProjection, err := store.ReadProjectionRow(ctx, "compat", groupEvents[0].EventID)
	if err != nil || len(liveProjection.Payload) == 0 {
		t.Fatalf("live projection = %#v, err=%v", liveProjection, err)
	}
	effects := make(map[string]string, 2)
	for range 2 {
		lease, claimErr := store.ClaimOutbox(ctx, eventstore.OutboxClaimRequest{WorkerID: "compat-worker", LeaseDuration: time.Minute})
		if claimErr != nil {
			t.Fatalf("claim effect: %v", claimErr)
		}
		effects[lease.Effect.EffectID] = lease.Effect.EffectType
		dispatched, err := store.MarkOutboxDispatched(ctx, eventstore.OutboxDispatchRequest{EffectID: lease.Effect.EffectID, WorkerID: lease.Effect.LeaseOwner, LeaseEpoch: lease.Effect.LeaseEpoch, AttemptID: lease.Effect.AttemptID})
		if err != nil {
			t.Fatalf("dispatch effect %s: %v", lease.Effect.EffectID, err)
		}
		if _, err := store.CompleteOutbox(ctx, eventstore.OutboxCompletionRequest{EffectID: lease.Effect.EffectID, WorkerID: dispatched.Effect.LeaseOwner, LeaseEpoch: dispatched.Effect.LeaseEpoch, AttemptID: dispatched.Effect.AttemptID, Status: eventstore.OutboxStatusSucceeded}); err != nil {
			t.Fatalf("complete effect %s: %v", lease.Effect.EffectID, err)
		}
	}
	if effects["compat-reply"] != "reply" || effects["compat-send"] != "send" {
		t.Fatalf("observable effects = %#v", effects)
	}

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, restartedDB := openCompatSmokeStore(t, dsn, clock, &compatFixedIDs{}, false)
	defer restartedDB.Close()
	restartedGroup, err := groupstate.NewRepository(restarted).Load(ctx, scope.DiceID, scope.GroupID)
	if err != nil || restartedGroup.GroupName != group.GroupName {
		t.Fatalf("restarted group = %#v, err=%v", restartedGroup, err)
	}
	restartedGroupEvents, err := restarted.Load(ctx, groupstate.GroupStream(scope.DiceID, scope.GroupID), 1)
	if err != nil || len(restartedGroupEvents) != len(groupEvents) {
		t.Fatalf("restarted group events = %#v, want %d, err=%v", restartedGroupEvents, len(groupEvents), err)
	}
	for i := range groupEvents {
		if restartedGroupEvents[i].EventID != groupEvents[i].EventID || restartedGroupEvents[i].EventType != groupEvents[i].EventType {
			t.Fatalf("restarted event[%d] = %#v, want %#v", i, restartedGroupEvents[i], groupEvents[i])
		}
	}
	restartedKV, err := restarted.GetPluginKV(ctx, "fixture-extension", "opaque")
	if err != nil || string(restartedKV.Value) != "read-your-writes" {
		t.Fatalf("restarted opaque storage = %#v, err=%v", restartedKV, err)
	}
	restartedStandalone, err := restarted.GetPluginKV(ctx, "fixture-extension", "standalone")
	if err != nil || string(restartedStandalone.Value) != "standalone-write" {
		t.Fatalf("restarted standalone storage = %#v, err=%v", restartedStandalone, err)
	}
	if _, err := restarted.ClaimOutbox(ctx, eventstore.OutboxClaimRequest{WorkerID: "replay-worker", LeaseDuration: time.Minute}); !errors.Is(err, eventstore.ErrNotFound) {
		t.Fatalf("restarted effect replay = %v", err)
	}
	rebuilt, err := restarted.Rebuild(ctx, eventstore.RebuildRequest{ProjectorVersion: "compat-v1"})
	if err != nil {
		t.Fatalf("projection rebuild: %v", err)
	}
	rebuiltProjection, err := restarted.ReadProjectionRow(ctx, "compat", groupEvents[0].EventID)
	if err != nil || string(rebuiltProjection.Payload) != string(liveProjection.Payload) || rebuilt.TerminalPosition == 0 {
		t.Fatalf("rebuilt projection = %#v, live=%#v, result=%#v, err=%v", rebuiltProjection, liveProjection, rebuilt, err)
	}

	tracker := NewJSExternalEffectTracker()
	called := false
	if err := NewJSCompatibilityBoundary(JSCompatibilityLive).InvokeLegacyCallbackWithTracker(tracker, func() error {
		called = true
		tracker.MarkPossible()
		return errors.New("fixture crash after callback-started")
	}); !errors.Is(err, ErrJSExternalEffectAmbiguous) || !called || !tracker.PossiblyStarted() {
		t.Fatalf("post-callback-started crash err=%v called=%v started=%v", err, called, tracker.PossiblyStarted())
	}
	replayed := false
	if err := NewJSCompatibilityBoundary(JSCompatibilityReplay).InvokeLegacyCallback(func() error {
		replayed = true
		return nil
	}); !errors.Is(err, ErrJSCompatibilityReplaySuppressed) || replayed {
		t.Fatalf("replay callback err=%v called=%v", err, replayed)
	}
}

type compatFixedClock struct{ now time.Time }
func (c *compatFixedClock) Now() time.Time { return c.now }

type compatFixedIDs struct{ next int }
func (g *compatFixedIDs) NewID() (string, error) {
	g.next++
	return fmt.Sprintf("compat-generated-%02d", g.next), nil
}

type compatKeySource struct{}
func (compatKeySource) IndexRootID(context.Context) (string, error) { return "index-v1", nil }
func (compatKeySource) IndexRootMaterial(context.Context) ([]byte, error) {
	return []byte("01234567890123456789012345678901"), nil
}
func (compatKeySource) CurrentEncryptionRoot(context.Context) (eventstore.EncryptionRoot, error) {
	return eventstore.EncryptionRoot{ID: "root-v1", Material: []byte("abcdefghijklmnopqrstuvwxyz123456")}, nil
}
func (compatKeySource) EncryptionRoot(context.Context, string) ([]byte, error) {
	return []byte("abcdefghijklmnopqrstuvwxyz123456"), nil
}

func openCompatSmokeStore(t *testing.T, dsn string, clock eventstore.Clock, ids eventstore.IDGenerator, initialize bool) (*eventstore.GORMStore, *eventstore.Database) {
	t.Helper()
	db, err := eventstore.OpenDatabase(context.Background(), eventstore.DatabaseConfig{Type: "sqlite", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	store := eventstore.NewStore(db,
		eventstore.WithKeySource(compatKeySource{}),
		eventstore.WithClock(clock),
		eventstore.WithIDGenerator(ids),
		eventstore.WithProjection(eventstore.ProjectionDescriptor{
			Name: "compat", Version: "compat-v1",
			Apply: func(_ context.Context, tx *gorm.DB, events []eventstore.Envelope) error {
				for _, event := range events {
					if err := eventstore.UpsertProjectionRow(tx, "compat", event.EventID, event.Payload); err != nil {
						return err
					}
				}
				return nil
			},
		}),
	)
	if initialize {
		if err := store.SetReadiness(context.Background(), eventstore.Readiness{
			Mode: "import", SchemaVersion: 1, DatabaseIdentity: "plugin-compat-db", IndexRootID: "index-v1",
			EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32),
			TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC(),
		}); err != nil {
			db.Close()
			t.Fatal(err)
		}
	}
	return store, db
}
