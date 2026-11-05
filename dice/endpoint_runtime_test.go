//nolint:testpackage
package dice

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"Scardice-core/adapterapi"
	"Scardice-core/core/messageflow"
	"Scardice-core/endpoint"
	"Scardice-core/eventstore"
)

func TestBindRuntimeSetsSessionOnPureOnebotEndpoint(t *testing.T) {
	d, _, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()

	ep := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{ID: "pure-1", Platform: "QQ", ProtocolType: "pureonebot"}}
	if ep.Session != nil {
		t.Fatalf("expected new endpoint session to be nil before binding, got %#v", ep.Session)
	}

	ep.bindCompatibilityRuntime(d.ImSession)

	if ep.Session != d.ImSession {
		t.Fatalf("expected endpoint session to be bound to imSession, got %#v", ep.Session)
	}
	if ep.Adapter != nil {
		t.Fatalf("a pure OneBot endpoint must not acquire a legacy adapter, got %T", ep.Adapter)
	}
}

func TestCreateTempCtxAllowsBoundInternalUIEndpoint(t *testing.T) {
	d, _, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()

	uiEp := &EndPointInfo{
		EndPointInfoBase: EndPointInfoBase{
			ID:       "1",
			UserID:   "UI:1000",
			Nickname: "UI",
			Platform: "UI",
			Enable:   true,
			State:    StateConnected,
		},
		Adapter: &PlatformAdapterHTTP{},
	}
	uiEp.bindCompatibilityRuntime(d.ImSession)

	msg := newGroupMsg("UI-Group:2101", "UI:1101", ".r 1")
	ctx := CreateTempCtx(uiEp, msg)
	defer ctx.releaseExecutionState()

	if ctx.EndPoint != uiEp {
		t.Fatalf("expected internal UI endpoint to be used directly")
	}
	if ctx.Session != d.ImSession {
		t.Fatalf("expected ctx session to be current imSession, got %#v", ctx.Session)
	}
	if ctx.callbackTransaction != nil {
		t.Fatal("detached temporary context unexpectedly acquired a durable root")
	}
	if ctx.Player == nil || ctx.Player.UserID() != "UI:1101" {
		t.Fatalf("detached player identity = %#v", ctx.Player)
	}
	VarSetValueStr(ctx, "$t局部", "value")
	if got, ok := VarGetValueStr(ctx, "$t局部"); !ok || got != "value" {
		t.Fatalf("temporary value = %q, %t", got, ok)
	}
	VarDelValue(ctx, "$t局部")
	if _, ok := VarGetValue(ctx, "$t局部"); ok {
		t.Fatal("temporary delete fell through to persistent attributes")
	}
	ctx.IsCompatibilityTest = true
	for _, key := range []string{"$mPreview", "$gPreview", "skill"} {
		VarSetValueStr(ctx, key, "preview")
		if got, ok := VarGetValueStr(ctx, key); !ok || got != "preview" {
			t.Fatalf("compatibility value %q = %q, %t", key, got, ok)
		}
		VarDelValue(ctx, key)
		if _, ok := VarGetValue(ctx, key); ok {
			t.Fatalf("compatibility delete %q reached persistent attributes", key)
		}
	}
	ctx.IsCompatibilityTest = false
	if err := ctx.Player.SetName("must-not-persist"); !errors.Is(err, ErrPlayerHandleUnavailable) {
		t.Fatalf("detached durable setter error = %v", err)
	}
	if err := ctx.getExecutionError(); err != nil {
		t.Fatalf("local temporary operations poisoned context: %v", err)
	}
}

type endpointIdentityProjectionStore struct {
	*eventstore.GORMStore
	rows []eventstore.ProjectionRow
}

func (s endpointIdentityProjectionStore) ListProjectionRows(context.Context, string) ([]eventstore.ProjectionRow, error) {
	return s.rows, nil
}

func TestObservedEndpointIdentityRecognizesBotMentionOverStaleAccountHint(t *testing.T) {
	payload, err := json.Marshal(endpoint.EndpointView{
		EndpointID: "telegram-endpoint", AdapterKey: TelegramAdapterKey, ProviderID: "TG:123",
		Config: adapterapi.ValidatedConfig{Version: 1, Canonical: json.RawMessage(`{"accountHint":"TG:outdated"}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	session := &IMSession{Parent: &Dice{DurableStore: endpointIdentityProjectionStore{
		rows: []eventstore.ProjectionRow{{Payload: payload}},
	}}}
	request := messageflow.CallbackRequest{
		EndpointID: "telegram-endpoint",
		Message:    adapterapi.InboundMessage{Platform: "TG", Text: "<@123> .r 1d1"},
	}
	bot := compatibilityCallbackEndpoint(session, request)
	if !isBotMentionedInSegments(compatibilityCallbackMessage(request), bot.UserID) {
		t.Fatalf("mention of observed bot identity was lost; resolved identity=%q", bot.UserID)
	}
}
