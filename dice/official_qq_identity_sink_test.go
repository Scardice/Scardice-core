package dice

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/sealdice/botgo/dto"
	"gorm.io/gorm"

	"Scardice-core/adapterapi"
	"Scardice-core/core/groupstate"
	"Scardice-core/core/playerstate"
	"Scardice-core/endpoint"
	"Scardice-core/eventstore"
)

const officialQQIdentityGroupID = "OpenQQ-Group-T:123456789-group-open-id"
const officialQQIdentityMemberID = "OpenQQ-Member-T:123456789-group-open-id-member-open-id"

type officialQQIdentityFixture struct {
	dice    *Dice
	store   *eventstore.GORMStore
	service *endpoint.Service
	state   endpoint.State
}

func newOfficialQQIdentityFixture(t *testing.T) officialQQIdentityFixture {
	t.Helper()
	d, store := newCanonicalTestDice(t)
	if d.DBOperator != nil {
		t.Fatal("canonical runtime unexpectedly has a legacy database operator")
	}
	registry := endpoint.NewRegistry()
	for _, descriptor := range []adapterapi.Descriptor{NewOfficialQQDescriptor(), NewHTTPDescriptor()} {
		if err := registry.Register(descriptor); err != nil {
			t.Fatal(err)
		}
	}
	service := endpoint.NewService(store, registry)
	config, err := service.ValidateConfig(t.Context(), OfficialQQAdapterKey, json.RawMessage(`{"appId":123456789,"appSecret":{"secretRef":"identity-app-secret","version":1},"token":{"secretRef":"identity-token","version":1}}`))
	if err != nil {
		t.Fatal(err)
	}
	id := adapterapi.EndpointID("official-identity")
	if _, err = service.Create(t.Context(), endpoint.Command{
		CommandID: "official-identity-create", CorrelationID: "official-identity-create", EndpointID: id,
		AdapterKey: OfficialQQAdapterKey, Config: config,
	}); err != nil {
		t.Fatal(err)
	}
	enabled, err := service.Enable(t.Context(), endpoint.Command{
		CommandID: "official-identity-enable", CorrelationID: "official-identity-enable", EndpointID: id,
	})
	if err != nil {
		t.Fatal(err)
	}
	withCanonicalTestRoot(t, d, "official-identity-state", func(transaction *DurableCallbackTransaction) error {
		group, loadErr := transaction.Domain().Group(t.Context(), d.BaseConfig.Name, officialQQIdentityGroupID)
		if loadErr != nil {
			return loadErr
		}
		if decideErr := group.Decide(groupstate.Command{
			Kind: groupstate.CommandCreate, DiceID: d.BaseConfig.Name, GroupID: officialQQIdentityGroupID, GroupName: "AppID-scoped group",
		}); decideErr != nil {
			return decideErr
		}
		player, loadErr := transaction.Domain().Player(t.Context(), d.BaseConfig.Name, officialQQIdentityGroupID, officialQQIdentityMemberID)
		if loadErr != nil {
			return loadErr
		}
		return player.Decide(playerstate.PlayerCommand{
			Kind: playerstate.CommandPlayerCreate, DiceID: d.BaseConfig.Name, GroupID: officialQQIdentityGroupID,
			UserID: officialQQIdentityMemberID, Name: "AppID-scoped player",
		})
	})
	return officialQQIdentityFixture{dice: d, store: store, service: service, state: enabled.State}
}

type officialQQIdentitySinkCore struct {
	officialQQIngressCore
	sink  endpoint.IdentityObservationSink
	state endpoint.State
}

func (core *officialQQIdentitySinkCore) ReportObservation(ctx context.Context, observation adapterapi.LifecycleObservation) error {
	return core.sink.HandleIdentityObservation(ctx, endpoint.FencedIdentityObservation{
		EndpointID: core.state.EndpointID, Generation: core.state.Generation, DesiredVersion: core.state.DesiredVersion,
		Observation: observation,
	})
}

func (fixture officialQQIdentityFixture) core() *officialQQIdentitySinkCore {
	return &officialQQIdentitySinkCore{sink: endpoint.NewIdentityObservationSink(fixture.service), state: fixture.state}
}

func TestOfficialQQIdentityObservationAcceptsMeWithoutLegacyDatabase(t *testing.T) {
	fixture := newOfficialQQIdentityFixture(t)
	groupBefore, err := groupstate.ReadProjected(t.Context(), fixture.store, fixture.dice.BaseConfig.Name, officialQQIdentityGroupID)
	if err != nil {
		t.Fatal(err)
	}
	playerBefore, err := playerstate.ReadProjectedPlayer(t.Context(), fixture.store, fixture.dice.BaseConfig.Name, officialQQIdentityGroupID, officialQQIdentityMemberID)
	if err != nil {
		t.Fatal(err)
	}
	core := fixture.core()
	if err = reportOfficialQQVerifiedIdentity(t.Context(), core, &dto.User{ID: "99887766"}); err != nil {
		t.Fatalf("normal Me identity rejected without legacy storage: %v", err)
	}
	view, err := fixture.service.Get(t.Context(), fixture.state.EndpointID)
	if err != nil || view.ProviderID != "99887766" || view.Version != fixture.state.Version+1 {
		t.Fatalf("durable endpoint identity = %#v, err=%v", view, err)
	}
	replayed, err := endpoint.NewRepository(fixture.store).Load(t.Context(), fixture.state.EndpointID)
	if err != nil || replayed.ProviderID != "99887766" {
		t.Fatalf("replayed endpoint identity = %#v, err=%v", replayed, err)
	}
	groupAfter, err := groupstate.ReadProjected(t.Context(), fixture.store, fixture.dice.BaseConfig.Name, officialQQIdentityGroupID)
	if err != nil || !reflect.DeepEqual(groupAfter, groupBefore) {
		t.Fatalf("Me changed AppID-scoped group: before=%#v after=%#v err=%v", groupBefore, groupAfter, err)
	}
	playerAfter, err := playerstate.ReadProjectedPlayer(t.Context(), fixture.store, fixture.dice.BaseConfig.Name, officialQQIdentityGroupID, officialQQIdentityMemberID)
	if err != nil || !reflect.DeepEqual(playerAfter, playerBefore) {
		t.Fatalf("Me changed AppID-scoped player: before=%#v after=%#v err=%v", playerBefore, playerAfter, err)
	}
	if _, err = groupstate.ReadProjected(t.Context(), fixture.store, fixture.dice.BaseConfig.Name, "OpenQQ-Group:99887766-group-open-id"); !errors.Is(err, eventstore.ErrNotFound) {
		t.Fatalf("Me synthesized a different group identity: %v", err)
	}
	if err = reportOfficialQQVerifiedIdentity(t.Context(), core, &dto.User{ID: "99887766"}); err != nil {
		t.Fatal(err)
	}
	repeated, err := fixture.service.Get(t.Context(), fixture.state.EndpointID)
	if err != nil || repeated.Version != view.Version {
		t.Fatalf("repeated identity appended new events: %#v, err=%v", repeated, err)
	}
}

func TestOfficialQQIdentityObservationRollsBackFailedPersistence(t *testing.T) {
	fixture := newOfficialQQIdentityFixture(t)
	fixture.store.RegisterParticipant(func(_ context.Context, _ *gorm.DB, work eventstore.UnitOfWork) error {
		for _, stream := range work.Streams {
			for _, event := range stream.Events {
				if event.EventType == string(endpoint.EventEndpointIdentityObserved) {
					return errors.New("identity participant rejected commit")
				}
			}
		}
		return nil
	})
	before, err := fixture.service.Get(t.Context(), fixture.state.EndpointID)
	if err != nil {
		t.Fatal(err)
	}
	if err = reportOfficialQQVerifiedIdentity(t.Context(), fixture.core(), &dto.User{ID: "99887766"}); !errors.Is(err, eventstore.ErrParticipantFailure) {
		t.Fatalf("failed identity persistence error = %v", err)
	}
	after, err := fixture.service.Get(t.Context(), fixture.state.EndpointID)
	if err != nil || !reflect.DeepEqual(after, before) {
		t.Fatalf("failed identity partially published: before=%#v after=%#v err=%v", before, after, err)
	}
	replayed, err := endpoint.NewRepository(fixture.store).Load(t.Context(), fixture.state.EndpointID)
	if err != nil || replayed.ProviderID != "" || replayed.Version != fixture.state.Version {
		t.Fatalf("failed identity escaped event rollback: %#v, err=%v", replayed, err)
	}
}

type officialQQIdentityInterleavingStore struct {
	eventstore.Store
	beforeCommit func()
}

func (store *officialQQIdentityInterleavingStore) Commit(ctx context.Context, work eventstore.UnitOfWork) (eventstore.CommitResult, error) {
	if beforeCommit := store.beforeCommit; beforeCommit != nil {
		store.beforeCommit = nil
		beforeCommit()
	}
	return store.Store.Commit(ctx, work)
}

func TestOfficialQQIdentityObservationPreservesWinningIdentityOnConflict(t *testing.T) {
	fixture := newOfficialQQIdentityFixture(t)
	fixture.service.Repository.Store = &officialQQIdentityInterleavingStore{
		Store: fixture.store,
		beforeCommit: func() {
			if _, err := fixture.service.RecordIdentity(t.Context(), endpoint.Command{
				CommandID: "winning-identity", CorrelationID: "winning-identity", EndpointID: fixture.state.EndpointID,
				Generation: fixture.state.Generation, DesiredVersion: fixture.state.DesiredVersion, ProviderID: "11223344",
			}); err != nil {
				t.Fatalf("commit winning identity: %v", err)
			}
		},
	}
	if err := reportOfficialQQVerifiedIdentity(t.Context(), fixture.core(), &dto.User{ID: "99887766"}); !errors.Is(err, endpoint.ErrConflict) {
		t.Fatalf("concurrent identity error = %v", err)
	}
	view, err := fixture.service.Get(t.Context(), fixture.state.EndpointID)
	if err != nil || view.ProviderID != "11223344" || view.Version != fixture.state.Version+1 {
		t.Fatalf("losing identity partially published: %#v, err=%v", view, err)
	}
	replayed, err := endpoint.NewRepository(fixture.store).Load(t.Context(), fixture.state.EndpointID)
	if err != nil || replayed.ProviderID != "11223344" || replayed.Version != view.Version {
		t.Fatalf("losing identity escaped event rollback: %#v, err=%v", replayed, err)
	}
}

func TestOfficialQQIdentityObservationIgnoresStaleRuntimeFence(t *testing.T) {
	fixture := newOfficialQQIdentityFixture(t)
	for _, stale := range []endpoint.State{
		{EndpointID: fixture.state.EndpointID, Generation: fixture.state.Generation - 1, DesiredVersion: fixture.state.DesiredVersion},
		{EndpointID: fixture.state.EndpointID, Generation: fixture.state.Generation, DesiredVersion: fixture.state.DesiredVersion - 1},
	} {
		core := fixture.core()
		core.state = stale
		if err := reportOfficialQQVerifiedIdentity(t.Context(), core, &dto.User{ID: "99887766"}); err != nil {
			t.Fatal(err)
		}
	}
	view, err := fixture.service.Get(t.Context(), fixture.state.EndpointID)
	if err != nil || view.ProviderID != "" || view.Version != fixture.state.Version {
		t.Fatalf("stale identity changed endpoint: %#v, err=%v", view, err)
	}
}

func TestIdentityObservationKeepsNonOfficialAdapterBehavior(t *testing.T) {
	fixture := newOfficialQQIdentityFixture(t)
	config, err := fixture.service.ValidateConfig(t.Context(), HTTPAdapterKey, json.RawMessage(`{"version":"1","url":"http://127.0.0.1:1","method":"POST","timeoutSeconds":2}`))
	if err != nil {
		t.Fatal(err)
	}
	created, err := fixture.service.Create(t.Context(), endpoint.Command{
		CommandID: "http-identity-create", CorrelationID: "http-identity-create", EndpointID: "http-identity",
		AdapterKey: HTTPAdapterKey, Config: config,
	})
	if err != nil {
		t.Fatal(err)
	}
	sink := endpoint.NewIdentityObservationSink(fixture.service)
	if err = sink.HandleIdentityObservation(t.Context(), endpoint.FencedIdentityObservation{
		EndpointID: created.State.EndpointID, Generation: created.State.Generation, DesiredVersion: created.State.DesiredVersion,
		Observation: adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationIdentity, ProviderID: "HTTP:bot", Code: "identity", Detail: "HTTP Bot"},
	}); err != nil {
		t.Fatal(err)
	}
	view, err := fixture.service.Get(t.Context(), created.State.EndpointID)
	if err != nil || view.ProviderID != "HTTP:bot" || view.DisplayName != "HTTP Bot" {
		t.Fatalf("non-official identity = %#v, err=%v", view, err)
	}
}
