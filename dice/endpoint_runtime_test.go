//nolint:testpackage
package dice

import (
	"context"
	"encoding/json"
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

	if ctx.EndPoint != uiEp {
		t.Fatalf("expected internal UI endpoint to be used directly")
	}
	if ctx.Session != d.ImSession {
		t.Fatalf("expected ctx session to be current imSession, got %#v", ctx.Session)
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
