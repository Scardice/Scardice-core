package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"Scardice-core/core/groupstate"
	"Scardice-core/core/playerstate"
	"Scardice-core/dice"
	"Scardice-core/eventstore"
	"Scardice-core/projectionset"
)

const groupListEventStoreToken = "group-list-eventstore-token"
const groupListEventStoreDiceID = "group-list-eventstore-dice"
const groupListEventStoreDBIdentity = "group-list-eventstore-test"

type groupListEventStoreFixture struct {
	t        *testing.T
	root     string
	database *eventstore.Database
	store    *eventstore.GORMStore
	manager  *dice.DiceManager
	runtime  *dice.Dice
	server   *httptest.Server
}

func newGroupListEventStoreFixture(t *testing.T) *groupListEventStoreFixture {
	t.Helper()
	fixture := &groupListEventStoreFixture{t: t, root: t.TempDir()}
	fixture.openStore(true)
	fixture.startRuntime()
	t.Cleanup(fixture.close)
	return fixture
}

func (f *groupListEventStoreFixture) openStore(initializeReadiness bool) {
	f.t.Helper()
	database, err := eventstore.OpenDatabase(context.Background(), eventstore.DatabaseConfig{
		Type: "sqlite", DSN: filepath.Join(f.root, "events.db"),
		KeySource: endpointAPITestKeySource{}, DatabaseIdentity: groupListEventStoreDBIdentity,
	})
	if err != nil {
		f.t.Fatalf("open EventStore database: %v", err)
	}
	f.database = database
	storeOptions := append(projectionset.StoreOptions(), eventstore.WithKeySource(endpointAPITestKeySource{}))
	f.store = eventstore.NewStore(database, storeOptions...)
	if initializeReadiness {
		if err := f.store.SetReadiness(context.Background(), eventstore.Readiness{
			Mode: "import", SchemaVersion: 1, DatabaseIdentity: groupListEventStoreDBIdentity,
			IndexRootID: "api-test-index-v1", EncryptionRootIDs: []string{"api-test-root-v1"},
			SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC(),
		}); err != nil {
			f.t.Fatalf("set EventStore readiness: %v", err)
		}
	}
}

func (f *groupListEventStoreFixture) reopenStore() {
	f.t.Helper()
	if f.server != nil {
		f.server.Close()
		f.server = nil
	}
	if err := f.database.Close(); err != nil {
		f.t.Fatalf("close EventStore database before restart: %v", err)
	}
	f.database = nil
	f.openStore(false)
	f.runtime.DurableStore = f.store
	if err := f.manager.PrepareEventSourcedState(context.Background()); err != nil {
		f.t.Fatalf("rehydrate EventStore runtime after restart: %v", err)
	}
	f.hydrateGroups()
	e := echo.New()
	Bind(e, f.manager)
	f.server = httptest.NewServer(e)
}

func (f *groupListEventStoreFixture) startRuntime() {
	f.t.Helper()
	ctx := context.Background()
	runtime := &dice.Dice{
		BaseConfig:   dice.BaseConfig{Name: groupListEventStoreDiceID, DataDir: filepath.Join(f.root, "dice")},
		DurableStore: f.store,
	}
	manager := &dice.DiceManager{Dice: []*dice.Dice{runtime}}
	runtime.Parent = manager
	if err := manager.InitializeRuntime(); err != nil {
		f.t.Fatalf("initialize EventStore runtime: %v", err)
	}
	if err := manager.PrepareEventSourcedState(ctx); err != nil {
		f.t.Fatalf("prepare EventStore runtime: %v", err)
	}
	runtime.Config.JsEnable = false
	manager.InitDice(nil)
	manager.JustForTest = true
	if runtime.DBOperator != nil {
		f.t.Fatalf("EventStore runtime DBOperator = %T, want nil", runtime.DBOperator)
	}
	manager.AccessTokens.Store(groupListEventStoreToken, true)

	previousDice, previousManager := myDice, dm
	myDice, dm = runtime, manager
	f.t.Cleanup(func() { myDice, dm = previousDice, previousManager })

	e := echo.New()
	Bind(e, manager)
	f.server = httptest.NewServer(e)
	f.manager, f.runtime = manager, runtime
}

func (f *groupListEventStoreFixture) close() {
	if f.server != nil {
		f.server.Close()
		f.server = nil
	}
	if f.manager != nil && len(f.manager.Dice) != 0 && f.manager.Dice[0] != nil {
		runtime := f.manager.Dice[0]
		f.manager.WaitNamesLoaded()
		runtime.WaitStartupJsLoaded()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := f.manager.WaitForHelpDocStartup(ctx); err != nil {
			f.t.Errorf("wait for help-doc startup: %v", err)
		}
		cancel()
		if err := f.manager.WithHelpDocManagerWriteContext(context.Background(), func(help *dice.HelpManager) error {
			if help != nil {
				help.Close()
			}
			return nil
		}); err != nil {
			f.t.Errorf("close help-doc manager: %v", err)
		}
		if runtime.AttrsManager != nil {
			runtime.AttrsManager.Stop()
		}
		if runtime.Cron != nil {
			runtime.Cron.Stop()
		}
		if f.manager.Cron != nil {
			f.manager.Cron.Stop()
		}
	}
	if f.database != nil {
		if err := f.database.Close(); err != nil {
			f.t.Errorf("close EventStore database: %v", err)
		}
		f.database = nil
	}
}

func (f *groupListEventStoreFixture) request() (int, []byte) {
	f.t.Helper()
	request, err := http.NewRequest(http.MethodGet, f.server.URL+"/sd-api/group/list", nil)
	if err != nil {
		f.t.Fatalf("create authenticated group-list request: %v", err)
	}
	request.Header.Set("Token", groupListEventStoreToken)
	response, err := f.server.Client().Do(request)
	if err != nil {
		f.t.Fatalf("send authenticated group-list request: %v", err)
	}
	defer response.Body.Close()
	var body json.RawMessage
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		f.t.Fatalf("decode group-list response (status %d): %v", response.StatusCode, err)
	}
	return response.StatusCode, body
}

func (f *groupListEventStoreFixture) createGroup(groupID string) {
	f.createGroupForDice(groupListEventStoreDiceID, groupID)
}

func (f *groupListEventStoreFixture) createGroupForDice(diceID, groupID string) {
	f.t.Helper()
	ctx := context.Background()
	repository := groupstate.NewRepository(f.store)
	if _, err := repository.DecideAndAppend(ctx, groupstate.State{}, 0, eventstore.Metadata{}, groupstate.Command{
		Kind: groupstate.CommandCreate, DiceID: diceID, GroupID: groupID, GroupName: "persisted " + groupID,
	}); err != nil {
		f.t.Fatalf("persist group %q for Dice %q: %v", groupID, diceID, err)
	}
	state, err := repository.Load(ctx, diceID, groupID)
	if err != nil {
		f.t.Fatalf("load persisted group %q for Dice %q: %v", groupID, diceID, err)
	}
	if _, err := repository.DecideAndAppend(ctx, state, state.Version, eventstore.Metadata{}, groupstate.Command{
		Kind: groupstate.CommandActivation, DiceIDForActivation: diceID, Active: true, Exists: true,
	}); err != nil {
		f.t.Fatalf("persist group activation %q for Dice %q: %v", groupID, diceID, err)
	}
}

func (f *groupListEventStoreFixture) createPlayer(diceID, groupID, userID string) {
	f.t.Helper()
	_, err := playerstate.NewRepository(f.store).DecideAndAppendPlayer(context.Background(), playerstate.PlayerState{}, 0,
		eventstore.Metadata{}, playerstate.PlayerCommand{
			Kind: playerstate.CommandPlayerCreate, DiceID: diceID, GroupID: groupID, UserID: userID, Name: "persisted " + userID,
		})
	if err != nil {
		f.t.Fatalf("persist player %q in %q/%q: %v", userID, diceID, groupID, err)
	}
}

func (f *groupListEventStoreFixture) deletePlayer(diceID, groupID, userID string) {
	f.t.Helper()
	repository := playerstate.NewRepository(f.store)
	state, err := repository.LoadPlayer(context.Background(), diceID, groupID, userID)
	if err != nil {
		f.t.Fatalf("load persisted player %q in %q/%q before deletion: %v", userID, diceID, groupID, err)
	}
	if _, err = repository.DecideAndAppendPlayer(context.Background(), state, state.Version,
		eventstore.Metadata{}, playerstate.PlayerCommand{Kind: playerstate.CommandPlayerDelete}); err != nil {
		f.t.Fatalf("persist deletion of player %q in %q/%q: %v", userID, diceID, groupID, err)
	}
}

func (f *groupListEventStoreFixture) hydrateGroups() {
	f.t.Helper()
	rows, err := f.store.ListProjectionRows(context.Background(), groupstate.GroupProjectionName)
	if err != nil {
		f.t.Fatalf("list persisted group projections: %v", err)
	}
	f.runtime.ImSession.ServiceAtNew = new(dice.SyncMap[string, *dice.GroupInfo])
	for _, row := range rows {
		var state groupstate.State
		if err := json.Unmarshal(row.Payload, &state); err != nil {
			f.t.Fatalf("decode persisted group projection %q: %v", row.RowKey, err)
		}
		if state.DiceID != groupListEventStoreDiceID || state.Deleted {
			continue
		}
		group := &dice.GroupInfo{
			GroupID: state.GroupID, GroupName: state.GroupName,
			DiceIDExistsMap: new(dice.SyncMap[string, bool]),
		}
		for id, exists := range state.DiceIDExists {
			group.DiceIDExistsMap.Store(id, exists)
		}
		f.runtime.ImSession.ServiceAtNew.Store(state.GroupID, group)
	}
}

func TestEventSourcedGroupListCountsDistinctPersistedProfilesAcrossDice(t *testing.T) {
	fixture := newGroupListEventStoreFixture(t)
	const (
		groupA = "QQ-Group:group%_\\/path"
		groupB = "QQ-Group:groupAB\\/path"
		groupC = "QQ-Group:group-list-c"
	)
	fixture.createGroup(groupA)
	fixture.createGroup(groupB)
	fixture.createGroup(groupC)
	fixture.createPlayer(groupListEventStoreDiceID, groupA, "QQ:user-a1")
	fixture.createPlayer(groupListEventStoreDiceID, groupA, "QQ:user-a2")
	fixture.createPlayer(groupListEventStoreDiceID, groupA, "QQ:user-deleted")
	fixture.deletePlayer(groupListEventStoreDiceID, groupA, "QQ:user-deleted")
	fixture.createPlayer(groupListEventStoreDiceID, groupB, "QQ:user-b1")
	fixture.createGroupForDice("other-eventstore-dice", groupA)
	fixture.createPlayer("other-eventstore-dice", groupA, "QQ:user-a2")
	fixture.createPlayer("other-eventstore-dice", groupA, "QQ:other-dice-user")
	rows, err := fixture.store.ListProjectionRowsByRowKeyFragments(
		context.Background(), playerstate.PlayerProjectionName,
		[]string{fmt.Sprintf("%d:%s", len(groupA), groupA)},
	)
	if err != nil {
		t.Fatalf("list persisted profiles for literal group key fragment: %v", err)
	}
	if len(rows) != 5 {
		t.Fatalf("matching projection rows = %d, want 5 rows for %q across Dice", len(rows), groupA)
	}
	for _, row := range rows {
		var state playerstate.PlayerState
		if err := json.Unmarshal(row.Payload, &state); err != nil {
			t.Fatalf("decode matched player projection %q: %v", row.RowKey, err)
		}
		if state.GroupID != groupA {
			t.Fatalf("literal group fragment selected unrelated group %q from row %q", state.GroupID, row.RowKey)
		}
	}

	fixture.hydrateGroups()

	authRequest, err := http.NewRequest(http.MethodGet, fixture.server.URL+"/sd-api/hello", nil)
	if err != nil {
		t.Fatalf("create authentication check request: %v", err)
	}
	authRequest.Header.Set("Token", groupListEventStoreToken)
	authResponse, err := fixture.server.Client().Do(authRequest)
	if err != nil {
		t.Fatalf("send authentication check request: %v", err)
	}
	_ = authResponse.Body.Close()
	if authResponse.StatusCode != http.StatusOK {
		t.Fatalf("registered WebUI session status=%d, want 200", authResponse.StatusCode)
	}

	status, body := fixture.request()
	if status != http.StatusOK {
		t.Fatalf("authenticated GET /sd-api/group/list status=%d body=%s, want 200", status, body)
	}
	var response struct {
		Items []struct {
			GroupID      string `json:"groupId"`
			TmpPlayerNum int64  `json:"tmpPlayerNum"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("decode group-list items: %v", err)
	}
	counts := make(map[string]int64, len(response.Items))
	for _, item := range response.Items {
		counts[item.GroupID] = item.TmpPlayerNum
	}
	if len(counts) != 3 || counts[groupA] != 3 || counts[groupB] != 1 || counts[groupC] != 0 {
		t.Fatalf("group-list player counts = %#v, want global distinct profiles %q=3, %q=1, %q=0", counts, groupA, groupB, groupC)
	}

	store := fixture.runtime.DurableStore
	fixture.runtime.DurableStore = nil
	status, body = fixture.request()
	fixture.runtime.DurableStore = store
	if status != http.StatusServiceUnavailable {
		t.Fatalf("group-list without EventStore player read model status=%d body=%s, want 503 rather than fabricated zero counts", status, body)
	}

	// Reopen the durable database and reconstruct both the event-sourced
	// runtime configuration and group compatibility view from projections.
	fixture.reopenStore()
	status, body = fixture.request()
	if status != http.StatusOK {
		t.Fatalf("authenticated GET /sd-api/group/list after EventStore reopen status=%d body=%s, want 200", status, body)
	}
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("decode group-list after EventStore reopen: %v", err)
	}
	counts = make(map[string]int64, len(response.Items))
	for _, item := range response.Items {
		counts[item.GroupID] = item.TmpPlayerNum
	}
	if len(counts) != 3 || counts[groupA] != 3 || counts[groupB] != 1 || counts[groupC] != 0 {
		t.Fatalf("rehydrated group-list player counts = %#v, want %q=3, %q=1, %q=0", counts, groupA, groupB, groupC)
	}

	// A group with no persisted members must remain listed with count zero;
	// an empty runtime group map must produce an empty result.
	fixture.runtime.ImSession.ServiceAtNew = new(dice.SyncMap[string, *dice.GroupInfo])
	status, body = fixture.request()
	if status != http.StatusOK {
		t.Fatalf("empty authenticated GET /sd-api/group/list status=%d body=%s, want 200", status, body)
	}
	var empty struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(body, &empty); err != nil || len(empty.Items) != 0 {
		t.Fatalf("empty group-list response items=%s err=%v, want no groups", body, err)
	}
}
