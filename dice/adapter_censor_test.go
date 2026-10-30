package dice

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/messageflow"
	"Scardice-core/dice/censor"
	"Scardice-core/eventstore"
	"Scardice-core/utils/jsengine"
)

func installAdapterTestCensor(t *testing.T, d *Dice, mode CensorMode) {
	t.Helper()
	engine := &censor.Censor{SensitiveKeys: map[string]censor.WordInfo{
		"gateword": {Level: censor.Danger, Origin: "gateword"},
	}}
	if err := engine.Load(); err != nil {
		t.Fatal(err)
	}
	d.Config.EnableCensor = true
	d.Config.CensorMode = mode
	d.CensorManager = &CensorManager{Censor: engine}
}

func TestAdapterCensorDurableAdmission(t *testing.T) {
	for _, raw := range []string{
		`{"action":"vendor.test","params":{"text":"gateword"}}`,
		`{"action":"vendor.test","params":{"nested":[{"value":"\u0067ateword"}]}}`,
		`{"action":"send_msg","params":{"message":[{"type":"text","data":{"text":"gate"}},{"type":"text","data":{"text":"word"}}]}}`,
		`{"action":"send_msg","params":{"message":[{"type":"json","data":{"data":"{\"title\":\"\\u0067ateword\"}"}}]}}`,
		`{"action":"send_group_forward_msg","params":{"messages":[{"type":"node","data":{"content":[{"type":"text","data":{"text":"gate"}},{"type":"text","data":{"text":"word"}}]}}]}}`,
	} {
		for _, staged := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/staged=%t", raw, staged), func(t *testing.T) {
				ctx, bridge, submitter, _ := newAdapterAPIBridgeTest(t)
				installAdapterTestCensor(t, ctx.Dice, OnlyOutputReply)
				if staged {
					ctx.callbackTransaction = &DurableCallbackTransaction{collector: messageflow.NewMutationCollector(eventstore.EventFactory{})}
				}
				operation, err := bridge.EnqueueAdapterAPI(context.Background(), ctx, "target-endpoint", raw)
				if err == nil || operation.ID != "" {
					t.Errorf("sensitive request admitted: operation=%+v error=%v", operation, err)
				}
				if len(submitter.prepared) != 0 || len(submitter.submitted) != 0 {
					t.Error("sensitive request reached durable preparation or submission")
				}
			})
		}
	}
}

func TestAdapterCensorOutputModeAndUnavailablePolicy(t *testing.T) {
	for _, test := range []struct {
		name        string
		mode        CensorMode
		enabled     bool
		unavailable string
		blocked     bool
	}{
		{"output", OnlyOutputReply, true, "", true},
		{"disabled", OnlyOutputReply, false, "", false},
		{"command-input", OnlyInputCommand, true, "", false},
		{"all-input", AllInput, true, "", false},
		{"loading", OnlyOutputReply, true, "loading", true},
		{"missing", OnlyOutputReply, true, "missing", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, bridge, submitter, _ := newAdapterAPIBridgeTest(t)
			installAdapterTestCensor(t, ctx.Dice, test.mode)
			ctx.Dice.Config.EnableCensor = test.enabled
			if test.unavailable == "loading" {
				ctx.Dice.CensorManager.IsLoading = true
			}
			if test.unavailable == "missing" {
				ctx.Dice.CensorManager = nil
			}
			raw := "{\n \"action\":\"vendor.test\",\"params\":{\"text\":\"gateword\",\"id\":900719925474099312345}\n}"
			operation, err := bridge.EnqueueAdapterAPI(context.Background(), ctx, "target-endpoint", raw)
			if test.blocked {
				if err == nil || operation.ID != "" || len(submitter.submitted) != 0 {
					t.Fatalf("request admitted: %+v, %v", operation, err)
				}
				return
			}
			if err != nil || len(submitter.submitted) != 1 {
				t.Fatalf("allowed request failed: %+v, %v", operation, err)
			}
			if submitter.submitted[0].Effect.Payload.RequestJSON != raw {
				t.Fatal("raw request changed during admission")
			}
		})
	}
}

type adapterCensorCaller struct{ calls atomic.Int32 }

func (c *adapterCensorCaller) CallAPI(context.Context, adapterapi.AdapterCallRequest) (adapterapi.AdapterCallResult, error) {
	c.calls.Add(1)
	return adapterapi.AdapterCallResult{RawJSON: `{"status":"ok","retcode":0}`}, nil
}

func TestAdapterCensorPublicGlobalCalls(t *testing.T) {
	for _, engine := range []string{"goja", "quickjs"} {
		t.Run(engine, func(t *testing.T) {
			if engine == "quickjs" && os.Getenv("SCARDICE_RUNTIME_ROOT") == "" && os.Getenv("SCARDICE_QUICKJS_PACKAGE") == "" {
				t.Skip("native QuickJS package is not configured")
			}
			const name = "Adapter censor public API"
			d, _, _, _, loop := preparePublicPreprocessRuntime(t, engine, "test/adapter-censor", name,
				`seal.ext.register(seal.ext.new("Adapter censor public API", "test", "1.0.0"));`)
			installAdapterTestCensor(t, d, OnlyOutputReply)
			_, bridge, submitter, _ := newAdapterAPIBridgeTest(t)
			d.OutboundBridge = bridge
			caller := &adapterCensorCaller{}
			d.ProviderCall = caller
			results := make(chan bool, 1)
			if err := loop.Run(func(runtime jsengine.Runtime) error {
				return runtime.Bind("recordCensorAdmission", func(rejected bool) { results <- rejected })
			}); err != nil {
				t.Fatal(err)
			}
			for _, call := range []string{
				`seal.adapter.callApi("target-endpoint", "vendor.test", {text:"gateword"})`,
				`seal.adapter.callApiRaw("target-endpoint", '{"action":"vendor.test","params":{"text":"gateword"}}')`,
				`seal.adapter.enqueueApi("target-endpoint", "vendor.test", {text:"gateword"})`,
				`seal.adapter.enqueueApiRaw("target-endpoint", '{"action":"vendor.test","params":{"text":"gateword"}}')`,
			} {
				if err := loop.Run(func(runtime jsengine.Runtime) error {
					_, err := runtime.RunString("adapter-censor-global.js", `(() => { try { Promise.resolve(`+call+`).then(() => recordCensorAdmission(false), () => recordCensorAdmission(true)); } catch (_) { recordCensorAdmission(true); } })()`)
					return err
				}); err != nil {
					t.Fatal(err)
				}
				select {
				case rejected := <-results:
					if !rejected {
						t.Errorf("global call accepted sensitive content: %s", call)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("public API did not settle")
				}
			}
			if caller.calls.Load() != 0 || len(submitter.submitted) != 0 || len(submitter.prepared) != 0 {
				t.Fatal("rejected content crossed provider or durable boundary")
			}
		})
	}
}

func TestAdapterCensorInboundModes(t *testing.T) {
	const name = "Adapter censor events"
	script := `var ext = seal.ext.new("Adapter censor events", "test", "1.0.0");
ext.adapterEventFilter = {events:"all"};
ext.onAdapterEvent = function(ctx,event) { recordAdapterEvent("hit",ctx===null?"null":"ctx",event.type,event.protocol,event.rawJson,event.endPoint.id,""); };
seal.ext.register(ext);`
	d, endpoint, _, _, loop := preparePublicPreprocessRuntime(t, "goja", "test/adapter-censor-events", name, script)
	hits := bindAdapterEventTestRecorder(t, loop)
	scope, _ := adapterEventGroupScope(t, d, endpoint, name)
	installAdapterTestCensor(t, d, AllInput)
	for _, test := range []struct {
		name      string
		mode      CensorMode
		eventType string
		command   bool
		censored  bool
		global    bool
		loading   bool
		wantHit   bool
	}{
		{"all-input-notice", AllInput, "notice", false, false, false, false, false},
		{"all-input-global", AllInput, "notice", false, false, true, false, false},
		{"output-notice", OnlyOutputReply, "notice", false, false, false, false, true},
		{"command-mode-notice", OnlyInputCommand, "notice", false, false, false, false, true},
		{"command-mode-chat", OnlyInputCommand, "message", false, false, false, false, true},
		{"command-mode-command", OnlyInputCommand, "message", true, false, false, false, false},
		{"already-censored", OnlyInputCommand, "message", true, true, false, false, false},
		{"unknown-mode", CensorMode(99), "notice", false, false, false, false, true},
		{"loading", AllInput, "notice", false, false, false, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			installAdapterTestCensor(t, d, test.mode)
			d.Config.CensorThresholds = map[censor.Level]int{censor.Danger: 10}
			d.CensorManager.IsLoading = test.loading
			scope.CommandID = 0
			if test.command {
				scope.CommandID = 1
			}
			scope.Censored = test.censored
			carrier, callback := scope, scope
			if test.global {
				carrier, callback = &MsgContext{Dice: d, Session: d.ImSession, EndPoint: endpoint}, nil
				defer carrier.releaseExecutionState()
			}
			raw := fmt.Sprintf(`{"post_type":%q,"text":"gateword"}`, test.eventType)
			if test.censored {
				raw = `{"post_type":"message","text":"clean"}`
			}
			err := d.dispatchAdapterEvent(carrier, callback, adapterapi.AdapterEvent{Protocol: "onebot11", Type: test.eventType, RawJSON: raw}, endpoint)
			if test.loading {
				if err == nil {
					t.Error("unavailable input censor admitted the event")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if test.wantHit {
				requireAdapterEventHit(t, hits)
			} else {
				requireNoAdapterEventHit(t, hits)
			}
			if test.eventType != "message" && scope.Player != nil {
				if counts := d.CensorManager.snapshotMemoryHitCounts(scope.Player.UserID, censor.Ignore, false); len(counts) != 0 {
					t.Fatalf("opaque event attributed to its scoped member: %v", counts)
				}
			}
		})
	}
}

func TestAdapterCensorCleanRawPreservesIndependentFields(t *testing.T) {
	ctx, bridge, submitter, _ := newAdapterAPIBridgeTest(t)
	installAdapterTestCensor(t, ctx.Dice, OnlyOutputReply)
	raw := "{\n \"action\":\"vendor.test\",\"params\":{\"left\":\"gate\",\"right\":\"word\",\"id\":900719925474099312345}\n}"
	operation, err := bridge.EnqueueAdapterAPI(context.Background(), ctx, "target-endpoint", raw)
	if err != nil || operation.ID == "" || len(submitter.submitted) != 1 {
		t.Fatalf("clean request admission: %+v, %v", operation, err)
	}
	if submitter.submitted[0].Effect.Payload.RequestJSON != raw {
		t.Fatal("clean raw JSON changed during censorship")
	}
}

func TestAdapterCensorCountsActualActorOncePerScope(t *testing.T) {
	ctx, bridge, _, _ := newAdapterAPIBridgeTest(t)
	installAdapterTestCensor(t, ctx.Dice, OnlyOutputReply)
	ctx.Dice.Config.CensorThresholds = map[censor.Level]int{censor.Danger: 10}
	ctx.MessageType, ctx.IsPrivate = "private", true
	ctx.Player = &GroupPlayerInfo{UserID: "source-actor", Name: "source"}
	ctx.Session.ServiceAtNew = new(SyncMap[string, *GroupInfo])
	raw := `{"action":"vendor.test","params":{"user_id":"target-user","text":"gateword","other":"gateword"}}`
	for range 2 {
		if _, err := bridge.EnqueueAdapterAPI(context.Background(), ctx, "target-endpoint", raw); err == nil {
			t.Fatal("sensitive request accepted")
		}
	}
	manager := ctx.Dice.CensorManager
	if counts := manager.snapshotMemoryHitCounts("source-actor", censor.Ignore, false); counts[censor.Danger] != 1 {
		t.Fatalf("actor hit counts after repeated calls: %v", counts)
	}
	if counts := manager.snapshotMemoryHitCounts("target-user", censor.Ignore, false); len(counts) != 0 {
		t.Fatalf("protocol target received actor penalties: %v", counts)
	}
	fresh := &MsgContext{Dice: ctx.Dice, Session: ctx.Session, EndPoint: ctx.EndPoint, Player: ctx.Player, MessageType: "private", IsPrivate: true}
	if _, err := bridge.EnqueueAdapterAPI(context.Background(), fresh, "target-endpoint", raw); err == nil {
		t.Fatal("fresh scope accepted sensitive content")
	}
	if counts := manager.snapshotMemoryHitCounts("source-actor", censor.Ignore, false); counts[censor.Danger] != 2 {
		t.Fatalf("fresh scope hit counts: %v", counts)
	}
}

func TestAdapterCensorProtocolTextRepresentations(t *testing.T) {
	for _, test := range []struct {
		name    string
		word    string
		raw     string
		blocked bool
	}{
		{"duplicate fields", "gateword", `{"action":"vendor.test","params":{"text":"gateword","text":"clean"}}`, true},
		{"literal entity matched", "amp", `{"action":"send_msg","params":{"message":[{"type":"text","data":{"text":"&amp;"}}]}}`, true},
		{"literal entity preserved", "R&D", `{"action":"send_msg","params":{"message":[{"type":"text","data":{"text":"R&amp;D"}}]}}`, false},
		{"CQ parameter decoded", "R&D", `{"action":"send_msg","params":{"message":"[CQ:tts,text=R&amp;D]"}}`, true},
		{"CQ visible text", "gateword", `{"action":"send_msg","params":{"message":"gate[CQ:face,id=1]word"}}`, true},
		{"literal JSON sample", "gateword", `{"action":"send_msg","params":{"message":[{"type":"text","data":{"text":"[{\"type\":\"text\",\"data\":{\"text\":\"gate\"}},{\"type\":\"text\",\"data\":{\"text\":\"word\"}}]"}}]}}`, false},
		{"independent objects", "gateword", `{"action":"vendor.test","params":{"records":[{"type":"text","data":{"text":"gate"}},{"type":"text","data":{"text":"word"}}]}}`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, bridge, submitter, _ := newAdapterAPIBridgeTest(t)
			installAdapterTestCensor(t, ctx.Dice, OnlyOutputReply)
			engine := ctx.Dice.CensorManager.Censor
			engine.SensitiveKeys = map[string]censor.WordInfo{test.word: {Level: censor.Danger, Origin: test.word}}
			if err := engine.Load(); err != nil {
				t.Fatal(err)
			}
			operation, err := bridge.EnqueueAdapterAPI(context.Background(), ctx, "target-endpoint", test.raw)
			if test.blocked {
				if err == nil || operation.ID != "" || len(submitter.prepared) != 0 || len(submitter.submitted) != 0 {
					t.Fatalf("blocked content admitted: operation=%+v, error=%v", operation, err)
				}
			} else if err != nil || operation.ID == "" || len(submitter.submitted) != 1 || submitter.submitted[0].Effect.Payload.RequestJSON != test.raw {
				t.Fatalf("literal content changed or rejected: operation=%+v, error=%v", operation, err)
			}
		})
	}
}

func TestAdapterCensorModerationSurvivesRejectedCallback(t *testing.T) {
	submitter := &bridgeTestSubmitter{}
	ctx, source, _ := bridgeTestContext(submitter)
	installAdapterTestCensor(t, ctx.Dice, OnlyOutputReply)
	ctx.MessageType, ctx.IsPrivate = "private", true
	ctx.Player = &GroupPlayerInfo{UserID: source.Sender.UserID, Name: "source"}
	ctx.Session.ServiceAtNew = new(SyncMap[string, *GroupInfo])
	ctx.Dice.Config.CensorHandlers = map[censor.Level]uint8{censor.Danger: 1 << SendEncodedDetails}
	collector := messageflow.NewMutationCollector(eventstore.EventFactory{})
	ctx.callbackTransaction = &DurableCallbackTransaction{collector: collector}
	err := ctx.Dice.checkAdapterOutboundCensor(ctx, `{"action":"send_msg","params":{"message":"gateword"}}`)
	if err == nil {
		t.Fatal("sensitive request accepted")
	}
	payload := submitter.request.Effect.Payload
	if payload.Kind != adapterapi.EffectPayloadPersonText || payload.Target.Conversation != adapterapi.ConversationID(source.Sender.UserID) || payload.Text != formatCensorHitDetails(censor.LevelText[censor.Danger], []string{"gateword"}, "gateword") {
		t.Fatalf("moderation warning was not independently submitted: %+v", payload)
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(work.Effects) != 0 {
		t.Fatal("moderation warning depends on rejected callback commit")
	}
	if !ctx.Censored || ctx.checkExecution() != nil {
		t.Fatal("censor accounting or original callback lifetime changed")
	}
}

func TestAdapterCensorOpaqueScopeOutputHasNoUserPenalty(t *testing.T) {
	ctx, bridge, _, _ := newAdapterAPIBridgeTest(t)
	installAdapterTestCensor(t, ctx.Dice, OnlyOutputReply)
	ctx.Dice.Config.CensorThresholds = map[censor.Level]int{censor.Danger: 10}
	ctx.MessageType, ctx.IsPrivate = "private", true
	ctx.Player = &GroupPlayerInfo{UserID: "affected-member", Name: "target"}
	ctx.Session.ServiceAtNew = new(SyncMap[string, *GroupInfo])
	ctx.adapterEventUnattributed = true
	_, err := bridge.EnqueueAdapterAPI(context.Background(), ctx.ShallowCopy(), "target-endpoint", `{"action":"vendor.test","params":{"text":"gateword"}}`)
	if err == nil {
		t.Fatal("sensitive request accepted")
	}
	if counts := ctx.Dice.CensorManager.snapshotMemoryHitCounts("affected-member", censor.Ignore, false); len(counts) != 0 {
		t.Fatalf("opaque scope target received a user penalty: %v", counts)
	}
}
