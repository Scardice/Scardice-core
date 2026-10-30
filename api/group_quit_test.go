package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"

	"Scardice-core/adapterapi"
	"Scardice-core/core/messageflow"
	"Scardice-core/dice"
	"Scardice-core/endpoint"
	"Scardice-core/eventstore"
)

const (
	groupQuitAPIToken      = "group-quit-api-token"
	groupQuitAPIEndpointID = adapterapi.EndpointID("group-quit-api-endpoint")
	groupQuitAPIDiceID     = "discord:group-quit-bot"
	groupQuitAPIGroupID    = "discord:group-quit-target"
)

type groupQuitAPIKeySource struct{}

func (groupQuitAPIKeySource) IndexRootID(context.Context) (string, error) {
	return "group-quit-index-v1", nil
}

func (groupQuitAPIKeySource) IndexRootMaterial(context.Context) ([]byte, error) {
	return []byte("01234567890123456789012345678901"), nil
}

func (groupQuitAPIKeySource) CurrentEncryptionRoot(context.Context) (eventstore.EncryptionRoot, error) {
	return eventstore.EncryptionRoot{ID: "group-quit-root-v1", Material: []byte("abcdefghijklmnopqrstuvwxyz123456")}, nil
}

func (groupQuitAPIKeySource) EncryptionRoot(_ context.Context, id string) ([]byte, error) {
	if id != "group-quit-root-v1" {
		return nil, eventstore.ErrKeyUnavailable
	}
	return []byte("abcdefghijklmnopqrstuvwxyz123456"), nil
}

type groupQuitAPIDescriptor struct {
	supportsQuit bool
}

func (groupQuitAPIDescriptor) Key() adapterapi.AdapterKey { return dice.DiscordAdapterKey }
func (groupQuitAPIDescriptor) ConfigVersion() uint16      { return 1 }
func (groupQuitAPIDescriptor) ValidateConfig(_ context.Context, raw json.RawMessage) (adapterapi.ValidatedConfig, error) {
	canonical, err := adapterapi.CanonicalizeJSON(raw)
	if err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	return adapterapi.ValidatedConfig{Version: 1, Canonical: canonical}, nil
}
func (groupQuitAPIDescriptor) Capabilities(adapterapi.ValidatedConfig) adapterapi.CapabilitySet {
	return adapterapi.CapabilityOutbound | adapterapi.CapabilityActions
}
func (d groupQuitAPIDescriptor) SupportedActions(adapterapi.ValidatedConfig) adapterapi.ActionSet {
	actions := adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage)
	if d.supportsQuit {
		actions = actions.With(adapterapi.ActionKindQuit)
	}
	return actions
}
func (groupQuitAPIDescriptor) NewRuntime(adapterapi.RuntimeInit) (adapterapi.AdapterRuntime, error) {
	return nil, errors.New("group quit API tests do not construct adapter runtimes")
}

type groupQuitAPIResolver struct {
	service    *endpoint.Service
	store      *eventstore.GORMStore
	descriptor groupQuitAPIDescriptor
}

func (r groupQuitAPIResolver) Resolve(ctx context.Context, endpointID adapterapi.EndpointID) (messageflow.EndpointSnapshot, error) {
	view, err := r.service.Get(ctx, endpointID)
	if err != nil {
		return messageflow.EndpointSnapshot{}, err
	}
	_, rootID, err := r.store.KeyedDigest(ctx, "group-quit-endpoint-snapshot/v1", string(endpointID))
	if err != nil {
		return messageflow.EndpointSnapshot{}, err
	}
	return messageflow.EndpointSnapshot{
		EndpointID:    view.EndpointID,
		AdapterKey:    view.AdapterKey,
		DesiredState:  string(view.DesiredState),
		ObservedState: view.ObservedState,
		Capabilities:  r.descriptor.Capabilities(view.Config),
		Actions:       r.descriptor.SupportedActions(view.Config),
		IndexRootID:   rootID,
		IndexSigner:   r.store,
	}, nil
}

type groupQuitAPIFailingSubmitter struct {
	delegate     *messageflow.OutboundService
	err          error
	failAt       int
	submitCalls  int
	prepareCalls int
}

func (s *groupQuitAPIFailingSubmitter) Submit(ctx context.Context, request messageflow.SubmitRequest) (messageflow.SubmitResult, error) {
	s.submitCalls++
	if s.submitCalls == s.failAt {
		return messageflow.SubmitResult{}, s.err
	}
	return s.delegate.Submit(ctx, request)
}

func (s *groupQuitAPIFailingSubmitter) Prepare(ctx context.Context, request messageflow.SubmitRequest) (messageflow.PreparedOutbound, error) {
	s.prepareCalls++
	if s.prepareCalls == s.failAt {
		return messageflow.PreparedOutbound{}, s.err
	}
	return s.delegate.Prepare(ctx, request)
}

type groupQuitAPINoticeCaptureBridge struct {
	texts chan string
}

func (b *groupQuitAPINoticeCaptureBridge) SubmitText(_ *dice.MsgContext, _ *dice.Message, text, _ string, _ bool) error {
	b.texts <- text
	return nil
}

type groupQuitAPIFixture struct {
	t        *testing.T
	database *eventstore.Database
	store    *eventstore.GORMStore
	runtime  *dice.Dice
	manager  *dice.DiceManager
	group    *dice.GroupInfo
}

func newGroupQuitAPIFixture(t *testing.T, supportsQuit bool, bridgeErr, secondSubmitErr error) *groupQuitAPIFixture {
	t.Helper()
	ctx := context.Background()
	keys := groupQuitAPIKeySource{}
	database, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{
		Type:             "sqlite",
		DSN:              filepath.Join(t.TempDir(), "group-quit-api.db"),
		KeySource:        keys,
		DatabaseIdentity: "group-quit-api-test",
	})
	if err != nil {
		t.Fatalf("open group quit EventStore: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	store := eventstore.NewStore(database, eventstore.WithKeySource(keys))
	if err = store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "group-quit-api-test",
		IndexRootID: "group-quit-index-v1", EncryptionRootIDs: []string{"group-quit-root-v1"},
		SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32),
		CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatalf("initialize group quit EventStore readiness: %v", err)
	}

	descriptor := groupQuitAPIDescriptor{supportsQuit: supportsQuit}
	registry := endpoint.NewRegistry()
	if err = registry.Register(descriptor); err != nil {
		t.Fatalf("register group quit descriptor: %v", err)
	}
	endpointService := endpoint.NewService(store, registry)
	if endpointService.InitError != nil {
		t.Fatalf("initialize endpoint service: %v", endpointService.InitError)
	}
	config, err := descriptor.ValidateConfig(ctx, json.RawMessage(`{"mode":"test"}`))
	if err != nil {
		t.Fatalf("validate endpoint config: %v", err)
	}
	created, err := endpointService.Create(ctx, endpoint.Command{
		CommandID: "group-quit-create", CorrelationID: "group-quit-create",
		EndpointID: groupQuitAPIEndpointID, AdapterKey: descriptor.Key(), Config: config,
		DisplayName: "Group Quit API Bot", ProviderID: adapterapi.PrincipalID(groupQuitAPIDiceID),
	})
	if err != nil {
		t.Fatalf("create group quit endpoint: %v", err)
	}
	enabled, err := endpointService.Enable(ctx, endpoint.Command{
		CommandID: "group-quit-enable", CorrelationID: "group-quit-enable", EndpointID: groupQuitAPIEndpointID,
		ExpectedVersion: created.State.Version, ExpectedVersionSet: true,
	})
	if err != nil {
		t.Fatalf("enable group quit endpoint: %v", err)
	}
	if _, err = endpointService.Complete(ctx, endpoint.Command{
		CommandID: "group-quit-connect", CorrelationID: "group-quit-connect",
		OperationID: enabled.State.OperationID, EndpointID: groupQuitAPIEndpointID,
		Generation: enabled.State.Generation, DesiredVersion: enabled.State.DesiredVersion,
		ObservedState: adapterapi.ObservedStateConnected, CompletionState: endpoint.OperationStateSucceeded,
	}); err != nil {
		t.Fatalf("connect group quit endpoint: %v", err)
	}

	runtime := &dice.Dice{
		BaseConfig:   dice.BaseConfig{Name: "group-quit-api-dice", DataDir: t.TempDir()},
		DurableStore: store,
		Logger:       zap.NewNop().Sugar(),
	}
	runtime.Config = dice.NewConfig(runtime)
	manager := &dice.DiceManager{Dice: []*dice.Dice{runtime}}
	manager.AccessTokens.Store(groupQuitAPIToken, true)
	runtime.Parent = manager
	session := &dice.IMSession{
		Parent:       runtime,
		ServiceAtNew: new(dice.SyncMap[string, *dice.GroupInfo]),
		PendingQuits: new(dice.SyncMap[string, *dice.PendingQuitInfo]),
	}
	runtime.ImSession = session
	group := &dice.GroupInfo{
		GroupID:         groupQuitAPIGroupID,
		GroupName:       "Group Quit Target",
		DiceIDActiveMap: new(dice.SyncMap[string, bool]),
		DiceIDExistsMap: new(dice.SyncMap[string, bool]),
	}
	group.DiceIDActiveMap.Store(groupQuitAPIDiceID, true)
	group.DiceIDExistsMap.Store(groupQuitAPIDiceID, true)
	session.ServiceAtNew.Store(groupQuitAPIGroupID, group)

	resolver := groupQuitAPIResolver{service: endpointService, store: store, descriptor: descriptor}
	outbound, err := messageflow.NewOutboundService(store, resolver, store, eventstore.UUIDGenerator{})
	if err != nil {
		t.Fatalf("construct group quit outbound service: %v", err)
	}
	failErr, failAt := bridgeErr, 1
	if secondSubmitErr != nil {
		failErr, failAt = secondSubmitErr, 2
	}
	if failErr != nil {
		runtime.OutboundBridge = dice.NewDurableOutboundBridge(&groupQuitAPIFailingSubmitter{
			delegate: outbound,
			err:      failErr,
			failAt:   failAt,
		}, resolver, eventstore.UUIDGenerator{})
	} else {
		runtime.OutboundBridge = dice.NewDurableOutboundBridge(outbound, resolver, eventstore.UUIDGenerator{})
	}

	endpoints := session.EndPointsReadOnly()
	if len(endpoints) != 1 || endpoints[0].ID != string(groupQuitAPIEndpointID) || endpoints[0].UserID != groupQuitAPIDiceID {
		t.Fatalf("projected endpoints = %#v, want group quit endpoint", endpoints)
	}
	if endpoints[0].Adapter != nil {
		t.Fatalf("projected endpoint Adapter = %T, want nil durable DTO", endpoints[0].Adapter)
	}

	previousDice, previousManager := myDice, dm
	myDice, dm = runtime, manager
	t.Cleanup(func() { myDice, dm = previousDice, previousManager })
	return &groupQuitAPIFixture{t: t, database: database, store: store, runtime: runtime, manager: manager, group: group}
}

func (f *groupQuitAPIFixture) request(diceID string, silence bool, extraText string) *httptest.ResponseRecorder {
	return f.requestContext(context.Background(), diceID, silence, extraText)
}

func (f *groupQuitAPIFixture) requestContext(requestCtx context.Context, diceID string, silence bool, extraText string) *httptest.ResponseRecorder {
	f.t.Helper()
	payload, err := json.Marshal(map[string]any{
		"groupId":   groupQuitAPIGroupID,
		"diceId":    diceID,
		"silence":   silence,
		"extraText": extraText,
	})
	if err != nil {
		f.t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/sd-api/group/quit_one", bytes.NewReader(payload)).WithContext(requestCtx)
	request.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	request.Header.Set("Token", groupQuitAPIToken)
	recorder := httptest.NewRecorder()
	ctx := echo.New().NewContext(request, recorder)
	if err = groupQuit(ctx); err != nil {
		f.t.Fatalf("groupQuit returned error: %v", err)
	}
	return recorder
}

type groupQuitStoredEffect struct {
	effect           adapterapi.OutboundEffect
	orderingSequence uint64
	laneHMAC         []byte
}

func (f *groupQuitAPIFixture) storedEffects() []groupQuitStoredEffect {
	f.t.Helper()
	var rows []struct {
		EffectID          string `gorm:"column:effect_id"`
		EndpointID        string `gorm:"column:endpoint_id"`
		OrderingSequence  uint64 `gorm:"column:ordering_sequence"`
		LaneHMAC          []byte `gorm:"column:lane_hmac"`
		PayloadVersion    uint64 `gorm:"column:payload_version"`
		PayloadCiphertext []byte `gorm:"column:payload_ciphertext"`
		PayloadNonce      []byte `gorm:"column:payload_nonce"`
		EncryptionKeyID   string `gorm:"column:encryption_key_id"`
	}
	if err := f.database.GORM().Table("outbox_effects").Order("ordering_sequence ASC").Find(&rows).Error; err != nil {
		f.t.Fatalf("list group quit outbox effects: %v", err)
	}
	result := make([]groupQuitStoredEffect, 0, len(rows))
	for _, row := range rows {
		if bytes.Contains(row.PayloadCiphertext, []byte(groupQuitAPIGroupID)) {
			f.t.Fatalf("outbox ciphertext leaked group target: %q", row.PayloadCiphertext)
		}
		version := row.PayloadVersion
		if version == 0 {
			version = 1
		}
		plain, err := f.store.DecryptBound(context.Background(), "outbox/v1", row.EffectID, row.EndpointID, version, row.PayloadCiphertext, row.PayloadNonce, row.EncryptionKeyID)
		if err != nil {
			f.t.Fatalf("decrypt group quit effect %q: %v", row.EffectID, err)
		}
		var wire struct {
			Effect adapterapi.OutboundEffect `json:"effect"`
		}
		if err = json.Unmarshal(plain, &wire); err != nil {
			f.t.Fatalf("decode group quit effect %q: %v", row.EffectID, err)
		}
		result = append(result, groupQuitStoredEffect{effect: wire.Effect, orderingSequence: row.OrderingSequence, laneHMAC: row.LaneHMAC})
	}
	return result
}

func requireGroupQuitAPIError(t *testing.T, recorder *httptest.ResponseRecorder, contains string) {
	t.Helper()
	if recorder.Code != http.StatusOK {
		t.Fatalf("group quit error status=%d body=%q, want HTTP 200 error envelope", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Result bool   `json:"result"`
		Err    string `json:"err"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode group quit error body %q: %v", recorder.Body.String(), err)
	}
	if body.Result || body.Err == "" {
		t.Fatalf("group quit error body=%s, want result=false with err", recorder.Body.String())
	}
	if contains != "" && !strings.Contains(body.Err, contains) {
		t.Fatalf("group quit error=%q, want substring %q", body.Err, contains)
	}
}

func TestGroupQuitAPIQueuesEncryptedDurableQuitWithNilAdapter(t *testing.T) {
	fixture := newGroupQuitAPIFixture(t, true, nil, nil)
	started := time.Now()
	recorder := fixture.request(groupQuitAPIDiceID, false, "api durable goodbye")
	if elapsed := time.Since(started); elapsed >= 3*time.Second {
		t.Fatalf("durable group quit blocked for %s; farewell and quit share a FIFO lane and must not sleep", elapsed)
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("group quit status=%d body=%q, want 200", recorder.Code, recorder.Body.String())
	}
	if fixture.group.DiceIDExistsMap.Exists(groupQuitAPIDiceID) {
		t.Fatal("accepted durable quit retained the local group-existence marker")
	}

	effects := fixture.storedEffects()
	if len(effects) != 2 {
		t.Fatalf("group quit outbox effects=%d, want farewell then quit", len(effects))
	}
	farewell, quit := effects[0], effects[1]
	if farewell.effect.Payload.Kind != adapterapi.EffectPayloadGroupText || !strings.Contains(farewell.effect.Payload.Text, "api durable goodbye") {
		t.Fatalf("first group quit effect=%#v, want farewell group text", farewell.effect.Payload)
	}
	if quit.effect.Payload.Kind != adapterapi.EffectPayloadQuit || quit.effect.Kind != adapterapi.EffectKindAction {
		t.Fatalf("second group quit effect=%#v, want quit action", quit.effect)
	}
	if quit.effect.EndpointID != groupQuitAPIEndpointID || quit.effect.Payload.Target.Kind != adapterapi.TargetGroup || quit.effect.Payload.Target.Conversation != adapterapi.ConversationID(groupQuitAPIGroupID) {
		t.Fatalf("quit effect target=%#v endpoint=%q, want group %q on %q", quit.effect.Payload.Target, quit.effect.EndpointID, groupQuitAPIGroupID, groupQuitAPIEndpointID)
	}
	if farewell.orderingSequence+1 != quit.orderingSequence || !bytes.Equal(farewell.laneHMAC, quit.laneHMAC) {
		t.Fatalf("farewell lane=(%d,%x) quit lane=(%d,%x), want consecutive effects on one FIFO lane", farewell.orderingSequence, farewell.laneHMAC, quit.orderingSequence, quit.laneHMAC)
	}
}

func TestSubmitDurableGroupQuitAcceptsIdenticalFarewellSegments(t *testing.T) {
	fixture := newGroupQuitAPIFixture(t, true, nil, nil)
	endpointView := fixture.runtime.ImSession.EndPointsReadOnly()[0]
	messageContext := &dice.MsgContext{
		Dice: fixture.runtime, Session: fixture.runtime.ImSession, EndPoint: endpointView,
		CommandID: 7002, CurrentCommand: "api/group-quit:identical-segments",
	}
	messageContext.SetSplitKey("#{SPLIT}")
	if err := dice.SubmitDurableGroupQuit(context.Background(), messageContext, groupQuitAPIGroupID, "A#{SPLIT}A"); err != nil {
		t.Fatalf("submit identical farewell segments: %v", err)
	}
	effects := fixture.storedEffects()
	if len(effects) != 3 {
		t.Fatalf("identical farewell effects=%d, want two messages then quit", len(effects))
	}
	if effects[0].effect.Payload.Text != "A" || effects[1].effect.Payload.Text != "A" ||
		effects[0].effect.CorrelationID == effects[1].effect.CorrelationID {
		t.Fatalf("identical farewell segments were deduplicated: %#v", effects)
	}
	if effects[2].effect.Payload.Kind != adapterapi.EffectPayloadQuit {
		t.Fatalf("final effect=%#v, want quit", effects[2].effect.Payload)
	}
}

func TestGroupQuitAPIUsesDistinctCommandIdentityPerRequest(t *testing.T) {
	fixture := newGroupQuitAPIFixture(t, true, nil, nil)
	for range 2 {
		recorder := fixture.request(groupQuitAPIDiceID, true, "")
		if recorder.Code != http.StatusOK {
			t.Fatalf("group quit status=%d body=%q, want 200", recorder.Code, recorder.Body.String())
		}
	}
	effects := fixture.storedEffects()
	if len(effects) != 2 {
		t.Fatalf("repeated group quit effects=%d, want two independently accepted requests", len(effects))
	}
	if effects[0].effect.ID == effects[1].effect.ID || effects[0].effect.CorrelationID == effects[1].effect.CorrelationID {
		t.Fatalf("repeated group quit reused durable identity: first=%#v second=%#v", effects[0].effect, effects[1].effect)
	}
}

func TestGroupQuitAPIFailureDoesNotSendAcceptedNotice(t *testing.T) {
	fixture := newGroupQuitAPIFixture(t, true, nil, nil)
	capture := &groupQuitAPINoticeCaptureBridge{texts: make(chan string, 1)}
	fixture.runtime.OutboundBridge = capture
	fixture.runtime.Config.NoticeIDs = []string{"discord:notice-owner:only=group"}

	recorder := fixture.request(groupQuitAPIDiceID, true, "")
	requireGroupQuitAPIError(t, recorder, "")
	if !fixture.group.DiceIDExistsMap.Exists(groupQuitAPIDiceID) {
		t.Fatal("rejected quit deleted the local group-existence marker")
	}
	if effects := fixture.storedEffects(); len(effects) != 0 {
		t.Fatalf("rejected quit persisted effects: %#v", effects)
	}
	select {
	case text := <-capture.texts:
		t.Fatalf("rejected quit sent accepted notice %q", text)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestGroupQuitAPIRejectsUnacceptedQuitWithoutDeletingMembership(t *testing.T) {
	t.Run("endpoint not matched", func(t *testing.T) {
		fixture := newGroupQuitAPIFixture(t, true, nil, nil)
		recorder := fixture.request("discord:other-bot", true, "")
		requireGroupQuitAPIError(t, recorder, "")
		if !fixture.group.DiceIDExistsMap.Exists(groupQuitAPIDiceID) {
			t.Fatal("unmatched endpoint deleted the local group-existence marker")
		}
		if effects := fixture.storedEffects(); len(effects) != 0 {
			t.Fatalf("unmatched endpoint queued effects: %#v", effects)
		}
	})

	t.Run("quit unsupported", func(t *testing.T) {
		fixture := newGroupQuitAPIFixture(t, false, nil, nil)
		recorder := fixture.request(groupQuitAPIDiceID, false, "unsupported quit farewell")
		requireGroupQuitAPIError(t, recorder, "capability")
		if !fixture.group.DiceIDExistsMap.Exists(groupQuitAPIDiceID) {
			t.Fatal("unsupported quit deleted the local group-existence marker")
		}
		if effects := fixture.storedEffects(); len(effects) != 0 {
			t.Fatalf("unsupported quit queued effects: %#v", effects)
		}
	})

	t.Run("submit error", func(t *testing.T) {
		forced := errors.New("forced durable quit submission failure")
		fixture := newGroupQuitAPIFixture(t, true, forced, nil)
		recorder := fixture.request(groupQuitAPIDiceID, true, "")
		requireGroupQuitAPIError(t, recorder, forced.Error())
		if !fixture.group.DiceIDExistsMap.Exists(groupQuitAPIDiceID) {
			t.Fatal("failed quit submission deleted the local group-existence marker")
		}
		if effects := fixture.storedEffects(); len(effects) != 0 {
			t.Fatalf("failed quit submission queued effects: %#v", effects)
		}
	})

	t.Run("farewell and quit submit atomically", func(t *testing.T) {
		forced := errors.New("forced second durable submission failure")
		fixture := newGroupQuitAPIFixture(t, true, nil, forced)
		recorder := fixture.request(groupQuitAPIDiceID, false, "atomic farewell")
		requireGroupQuitAPIError(t, recorder, forced.Error())
		if !fixture.group.DiceIDExistsMap.Exists(groupQuitAPIDiceID) {
			t.Fatal("partially submitted quit deleted the local group-existence marker")
		}
		if effects := fixture.storedEffects(); len(effects) != 0 {
			t.Fatalf("failed farewell-and-quit transaction persisted partial effects: %#v", effects)
		}
	})

	t.Run("request canceled before acceptance", func(t *testing.T) {
		fixture := newGroupQuitAPIFixture(t, true, nil, nil)
		requestCtx, cancel := context.WithCancel(context.Background())
		cancel()
		recorder := fixture.requestContext(requestCtx, groupQuitAPIDiceID, false, "canceled farewell")
		requireGroupQuitAPIError(t, recorder, context.Canceled.Error())
		if !fixture.group.DiceIDExistsMap.Exists(groupQuitAPIDiceID) {
			t.Fatal("canceled quit deleted the local group-existence marker")
		}
		if effects := fixture.storedEffects(); len(effects) != 0 {
			t.Fatalf("canceled quit queued effects: %#v", effects)
		}
	})
}
