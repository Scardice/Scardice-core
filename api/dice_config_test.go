package api //nolint:testpackage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"

	"Scardice-core/core/configstate"
	"Scardice-core/core/extensionstate"
	"Scardice-core/core/managerstate"
	"Scardice-core/dice"
	"Scardice-core/eventstore"
	"Scardice-core/projectionset"
)

func snapshotDiceConfigMemory(t *testing.T, runtime *dice.Dice) []byte {
	t.Helper()
	data, err := json.Marshal(&runtime.Config)
	if err != nil {
		t.Fatalf("snapshot in-memory Dice config: %v", err)
	}
	return data
}

func TestDiceConfigSetAcceptsCRNGRandomMode(t *testing.T) {
	t.Chdir(t.TempDir())

	previousDice := myDice
	previousDM := dm
	t.Cleanup(func() {
		myDice = previousDice
		dm = previousDM
	})

	testDice := &dice.Dice{
		BaseConfig: dice.BaseConfig{DataDir: "."},
		Config:     dice.NewConfig(nil),
		Logger:     zap.NewNop().Sugar(),
	}
	manager := &dice.DiceManager{
		Dice:           []*dice.Dice{testDice},
		DiceRandomMode: string(dice.DiceRandomModePCG),
		JustForTest:    true,
	}
	token := "test-token"
	manager.AccessTokens.Store(token, true)
	testDice.Parent = manager
	myDice = testDice
	dm = manager

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/sd-api/configs/dice", strings.NewReader(`{"diceRandomMode":"crng"}`))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set("Token", token)
	rec := httptest.NewRecorder()

	if err := DiceConfigSet(e.NewContext(req, rec)); err != nil {
		t.Fatalf("DiceConfigSet() error = %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if got := manager.DiceRandomMode; got != string(dice.DiceRandomModeCRNG) {
		t.Fatalf("manager DiceRandomMode = %q, want %q", got, dice.DiceRandomModeCRNG)
	}
	if got := testDice.Config.DiceRandomMode; got != string(dice.DiceRandomModeCRNG) {
		t.Fatalf("Dice mirror DiceRandomMode = %q, want %q", got, dice.DiceRandomModeCRNG)
	}
}
func TestDiceConfigUsesRuntimeExtensionDefaultsAndDurableOverrides(t *testing.T) {
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

	runtime := &dice.Dice{
		BaseConfig:   dice.BaseConfig{Name: "api-test", DataDir: filepath.Join(root, "api-test")},
		DurableStore: store,
	}
	manager := &dice.DiceManager{
		EventSourcedMode: true,
		Dice:             []*dice.Dice{runtime},
		DiceRandomMode:   string(dice.DiceRandomModePCG),
	}
	if err := manager.PrepareEventSourcedState(ctx); err != nil {
		t.Fatalf("prepare event-sourced state: %v", err)
	}
	runtime.Parent = manager
	manager.AccessTokens.Store("dice-config-token", true)
	extension := &dice.ExtInfo{Name: "test-extension", Version: "1.0.0"}
	runtime.ExtList = []*dice.ExtInfo{extension}
	runtime.Config.ExtDefaultSettings = []*dice.ExtDefaultSettingItem{{
		Name:            extension.Name,
		AutoActive:      true,
		DisabledCommand: map[string]bool{"runtime-disabled": true},
		ExtItem:         extension,
		Loaded:          true,
	}}

	previousDice, previousManager := myDice, dm
	t.Cleanup(func() {
		myDice = previousDice
		dm = previousManager
	})
	myDice = runtime
	dm = manager

	getConfig := func() DiceConfigInfo {
		t.Helper()
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/sd-api/configs/dice", nil)
		req.Header.Set("Token", "dice-config-token")
		rec := httptest.NewRecorder()
		if err := DiceConfig(e.NewContext(req, rec)); err != nil {
			t.Fatalf("get dice config: %v", err)
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusOK, rec.Body.String())
		}
		var response DiceConfigInfo
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatalf("decode dice config: %v", err)
		}
		return response
	}

	response := getConfig()
	if len(response.ExtDefaultSettings) != 1 {
		t.Fatalf("runtime extension defaults = %#v, want one setting", response.ExtDefaultSettings)
	}
	if setting := response.ExtDefaultSettings[0]; setting.Name != extension.Name || !setting.AutoActive || !setting.Loaded || !setting.DisabledCommand["runtime-disabled"] {
		t.Fatalf("runtime default setting = %#v", setting)
	}

	if err := runtime.DurableDiscoverExtension(ctx, extension); err != nil {
		t.Fatalf("discover durable extension: %v", err)
	}
	if err := runtime.DurableSetExtensionDefaults(ctx, extension.Name, false, []string{"durable-disabled"}); err != nil {
		t.Fatalf("set durable extension defaults: %v", err)
	}
	response = getConfig()
	if len(response.ExtDefaultSettings) != 1 {
		t.Fatalf("durable extension defaults = %#v, want one setting", response.ExtDefaultSettings)
	}
	setting := response.ExtDefaultSettings[0]
	if setting.AutoActive || setting.DisabledCommand["runtime-disabled"] || !setting.DisabledCommand["durable-disabled"] {
		t.Fatalf("durable extension setting did not override runtime defaults: %#v", setting)
	}
}

func TestDiceConfigSetDurablePersistsManagerConfigAndExtensionOwnersAtomically(t *testing.T) {
	t.Run("success persists and restores each owner", func(t *testing.T) {
		echoServer, manager, runtime, store := newDiceConfigDurableHandlerTest(t)
		store.commitCalls = 0
		recorder := postDiceConfigDurableRequest(echoServer, `{"serveAddress":"new-address:1234","trayTooltip":"new tray","uiPassword":"new-password-hash","friendAddComment":"durable config","extDefaultSettings":[{"name":"test-extension","autoActive":false,"disabledCommand":{"blocked":true}}]}`, "dice-config-owner-token")
		if recorder.Code != http.StatusOK {
			t.Fatalf("config update status = %d, body = %s", recorder.Code, recorder.Body.String())
		}
		if store.commitCalls != 1 {
			t.Fatalf("owner transaction commits = %d, want one UnitOfWork", store.commitCalls)
		}

		restored := &dice.DiceManager{EventSourcedMode: true}
		if err := restored.RestoreEventSourcedManager(context.Background(), store); err != nil {
			t.Fatalf("restore event-sourced manager: %v", err)
		}
		if restored.ServeAddress != "new-address:1234" || restored.GetTrayTooltip() != "new tray" ||
			restored.GetTrayTooltip() != manager.GetTrayTooltip() || restored.UIPasswordHash != "new-password-hash" {
			t.Fatalf("restored manager address=%q tooltip=%q password=%q", restored.ServeAddress, restored.GetTrayTooltip(), restored.UIPasswordHash)
		}
		if restored.AccessTokens.Exists("dice-config-owner-token") {
			t.Fatal("password update did not clear the persisted access token")
		}

		config, err := configstate.NewRepository(store).Load(context.Background(), runtime.BaseConfig.Name)
		if err != nil {
			t.Fatalf("load durable Dice config: %v", err)
		}
		if config.Base.FriendAddComment != "durable config" {
			t.Fatalf("persisted Dice config comment = %q", config.Base.FriendAddComment)
		}
		extensions, err := extensionstate.NewRepository(store).Load(context.Background(), runtime.BaseConfig.Name)
		if err != nil {
			t.Fatalf("load durable extension state: %v", err)
		}
		defaults := extensions.DefaultCommands["test-extension"]
		if defaults.AutoActive || !defaults.DisabledCommands["blocked"] {
			t.Fatalf("persisted extension defaults = %#v", defaults)
		}
	})

	t.Run("Dice-only update does not rewrite manager auth", func(t *testing.T) {
		echoServer, _, runtime, store := newDiceConfigDurableHandlerTest(t)
		beforeManager, beforeAuth := loadDiceConfigManagerState(t, store)

		store.commitCalls = 0
		recorder := postDiceConfigDurableRequest(echoServer, `{"friendAddComment":"config-only update"}`, "dice-config-owner-token")
		if recorder.Code != http.StatusOK {
			t.Fatalf("config-only update status = %d, body = %s", recorder.Code, recorder.Body.String())
		}
		if store.commitCalls != 1 {
			t.Fatalf("config-only commits = %d, want one UnitOfWork", store.commitCalls)
		}
		afterManager, afterAuth := loadDiceConfigManagerState(t, store)
		if afterManager.Version != beforeManager.Version || !reflect.DeepEqual(afterManager.Public, beforeManager.Public) ||
			!reflect.DeepEqual(afterAuth, beforeAuth) {
			t.Fatalf("Dice-only update rewrote manager state: before=%#v/%#v after=%#v/%#v", beforeManager, beforeAuth, afterManager, afterAuth)
		}
		config, err := configstate.NewRepository(store).Load(context.Background(), runtime.BaseConfig.Name)
		if err != nil || config.Base.FriendAddComment != "config-only update" {
			t.Fatalf("config-only update was not persisted: config=%#v err=%v", config, err)
		}
	})

	t.Run("failed commit publishes no owner", func(t *testing.T) {
		echoServer, manager, runtime, store := newDiceConfigDurableHandlerTest(t)
		beforeManager, beforeAuth := loadDiceConfigManagerState(t, store)
		beforeConfig, err := configstate.NewRepository(store).Load(context.Background(), runtime.BaseConfig.Name)
		if err != nil {
			t.Fatal(err)
		}
		beforeExtensions, err := extensionstate.NewRepository(store).Load(context.Background(), runtime.BaseConfig.Name)
		if err != nil {
			t.Fatal(err)
		}
		oldConfig := snapshotDiceConfigMemory(t, runtime)
		store.commitCalls = 0
		store.failCommit = true

		recorder := postDiceConfigDurableRequest(echoServer, `{"serveAddress":"failed-address:1234","trayTooltip":"fail tray","uiPassword":"failed-password-hash","friendAddComment":"must not persist","extDefaultSettings":[{"name":"test-extension","autoActive":false,"disabledCommand":{"blocked":true}}]}`, "dice-config-owner-token")
		if recorder.Code != http.StatusConflict {
			t.Fatalf("failed commit status = %d, body = %s", recorder.Code, recorder.Body.String())
		}
		if store.commitCalls != 1 {
			t.Fatalf("failed owner transaction commits = %d, want one UnitOfWork", store.commitCalls)
		}
		if manager.ServeAddress != beforeManager.Public.ServeAddress || manager.GetTrayTooltip() != beforeManager.Public.TrayTooltip ||
			manager.UIPasswordHash != beforeAuth.UIPasswordHash || !manager.AccessTokens.Exists("dice-config-owner-token") ||
			!bytes.Equal(snapshotDiceConfigMemory(t, runtime), oldConfig) {
			t.Fatalf("failed commit changed memory: address=%q tooltip=%q password=%q token=%v comment=%q",
				manager.ServeAddress, manager.GetTrayTooltip(), manager.UIPasswordHash,
				manager.AccessTokens.Exists("dice-config-owner-token"), runtime.Config.FriendAddComment)
		}

		store.failCommit = false
		afterManager, afterAuth := loadDiceConfigManagerState(t, store)
		afterConfig, err := configstate.NewRepository(store).Load(context.Background(), runtime.BaseConfig.Name)
		if err != nil {
			t.Fatal(err)
		}
		afterExtensions, err := extensionstate.NewRepository(store).Load(context.Background(), runtime.BaseConfig.Name)
		if err != nil {
			t.Fatal(err)
		}
		if afterManager.Version != beforeManager.Version || !reflect.DeepEqual(afterManager.Public, beforeManager.Public) ||
			!reflect.DeepEqual(afterAuth, beforeAuth) ||
			!reflect.DeepEqual(afterConfig, beforeConfig) ||
			!reflect.DeepEqual(afterExtensions, beforeExtensions) {
			t.Fatalf("failed commit changed persisted owners: manager=%#v config=%#v extensions=%#v", afterManager, afterConfig, afterExtensions)
		}
	})

	t.Run("invalid extension defaults publish no owner", func(t *testing.T) {
		echoServer, manager, runtime, store := newDiceConfigDurableHandlerTest(t)
		beforeManager, beforeAuth := loadDiceConfigManagerState(t, store)
		beforeConfig, err := configstate.NewRepository(store).Load(context.Background(), runtime.BaseConfig.Name)
		if err != nil {
			t.Fatal(err)
		}
		beforeExtensions, err := extensionstate.NewRepository(store).Load(context.Background(), runtime.BaseConfig.Name)
		if err != nil {
			t.Fatal(err)
		}
		oldConfig := snapshotDiceConfigMemory(t, runtime)

		store.commitCalls = 0
		recorder := postDiceConfigDurableRequest(echoServer, `{"serveAddress":"invalid-address:1234","trayTooltip":"bad tray","uiPassword":"invalid-password-hash","friendAddComment":"must not persist","extDefaultSettings":[{"name":"missing-extension","autoActive":false,"disabledCommand":{"blocked":true}}]}`, "dice-config-owner-token")
		if recorder.Code != http.StatusConflict {
			t.Fatalf("invalid defaults status = %d, body = %s", recorder.Code, recorder.Body.String())
		}
		if store.commitCalls != 0 {
			t.Fatalf("invalid extension defaults reached Commit %d times, want validation before commit", store.commitCalls)
		}
		afterManager, afterAuth := loadDiceConfigManagerState(t, store)
		afterConfig, err := configstate.NewRepository(store).Load(context.Background(), runtime.BaseConfig.Name)
		if err != nil {
			t.Fatal(err)
		}
		afterExtensions, err := extensionstate.NewRepository(store).Load(context.Background(), runtime.BaseConfig.Name)
		if err != nil {
			t.Fatal(err)
		}
		if manager.ServeAddress != beforeManager.Public.ServeAddress || manager.GetTrayTooltip() != beforeManager.Public.TrayTooltip ||
			manager.UIPasswordHash != beforeAuth.UIPasswordHash || !manager.AccessTokens.Exists("dice-config-owner-token") ||
			!bytes.Equal(snapshotDiceConfigMemory(t, runtime), oldConfig) ||
			afterManager.Version != beforeManager.Version || !reflect.DeepEqual(afterAuth, beforeAuth) ||
			!reflect.DeepEqual(afterConfig, beforeConfig) ||
			!reflect.DeepEqual(afterExtensions, beforeExtensions) {
			t.Fatalf("invalid extension defaults partially published: memory manager=%#v config=%#v; persisted manager=%#v config=%#v extensions=%#v",
				manager, runtime.Config, afterManager, afterConfig, afterExtensions)
		}
	})

	t.Run("auth check and test mode restrictions remain", func(t *testing.T) {
		echoServer, manager, _, _ := newDiceConfigDurableHandlerTest(t)
		unauthorized := postDiceConfigDurableRequest(echoServer, `{"serveAddress":"unauthorized:1234"}`, "")
		if unauthorized.Code != http.StatusForbidden {
			t.Fatalf("unauthenticated status = %d, want %d", unauthorized.Code, http.StatusForbidden)
		}
		manager.JustForTest = true
		recorder := postDiceConfigDurableRequest(echoServer, `{"serveAddress":"test-mode:1234","uiPassword":"test-mode-password"}`, "dice-config-owner-token")
		if recorder.Code != http.StatusOK {
			t.Fatalf("test-mode config status = %d, body = %s", recorder.Code, recorder.Body.String())
		}
		if manager.ServeAddress == "test-mode:1234" || manager.UIPasswordHash != "old-password-hash" ||
			!manager.AccessTokens.Exists("dice-config-owner-token") {
			t.Fatalf("test-mode request changed protected manager state: address=%q password=%q token=%v",
				manager.ServeAddress, manager.UIPasswordHash, manager.AccessTokens.Exists("dice-config-owner-token"))
		}
	})
}

func TestDiceConfigManagerCommitPreservesConcurrentDiceConfigAndSignIn(t *testing.T) {
	echoServer, manager, runtime, store := newDiceConfigDurableHandlerTest(t)
	commitEntered := make(chan struct{})
	releaseCommit := make(chan struct{})
	var releaseOnce sync.Once
	releaseManagerCommit := func() {
		releaseOnce.Do(func() { close(releaseCommit) })
	}
	defer releaseManagerCommit()

	var blockOnce sync.Once
	store.mu.Lock()
	store.beforeCommit = func(work eventstore.UnitOfWork) {
		for _, stream := range work.Streams {
			if stream.Stream.AggregateType == managerstate.AggregateType {
				blockOnce.Do(func() {
					close(commitEntered)
					<-releaseCommit
				})
				return
			}
		}
	}
	store.mu.Unlock()

	managerResult := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		managerResult <- postDiceConfigDurableRequest(echoServer, `{"serveAddress":"concurrent-address:1234"}`, "dice-config-owner-token")
	}()
	select {
	case <-commitEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("manager update did not reach its commit")
	}

	signInResult := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		request := httptest.NewRequest(http.MethodPost, "/sd-api/signin", strings.NewReader(`{"password":"old-password-hash"}`))
		request.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		recorder := httptest.NewRecorder()
		echoServer.ServeHTTP(recorder, request)
		signInResult <- recorder
	}()

	configResponse := postDiceConfigDurableRequest(echoServer, `{"friendAddComment":"concurrent config"}`, "dice-config-owner-token")
	if configResponse.Code != http.StatusOK {
		t.Fatalf("concurrent Dice update status = %d, body = %s", configResponse.Code, configResponse.Body.String())
	}
	if runtime.Config.FriendAddComment != "concurrent config" {
		t.Fatalf("concurrent Dice update missing in memory: %q", runtime.Config.FriendAddComment)
	}

	releaseManagerCommit()
	managerResponse := <-managerResult
	if managerResponse.Code != http.StatusOK {
		t.Fatalf("manager update status = %d, body = %s", managerResponse.Code, managerResponse.Body.String())
	}
	loginResponse := <-signInResult
	if loginResponse.Code != http.StatusOK {
		t.Fatalf("concurrent sign-in status = %d, body = %s", loginResponse.Code, loginResponse.Body.String())
	}
	store.mu.Lock()
	store.beforeCommit = nil
	store.mu.Unlock()

	if manager.ServeAddress != "concurrent-address:1234" || runtime.Config.FriendAddComment != "concurrent config" {
		t.Fatalf("concurrent publication lost owner state: address=%q comment=%q", manager.ServeAddress, runtime.Config.FriendAddComment)
	}
	var loginBody struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(loginResponse.Body.Bytes(), &loginBody); err != nil {
		t.Fatalf("decode sign-in response: %v", err)
	}
	if loginBody.Token == "" || !manager.AccessTokens.Exists(loginBody.Token) {
		t.Fatalf("successful sign-in token %q was not retained in manager memory", loginBody.Token)
	}
	_, auth := loadDiceConfigManagerState(t, store)
	tokenPersisted := false
	for _, token := range auth.AccessTokens {
		if token == loginBody.Token {
			tokenPersisted = true
			break
		}
	}
	if !tokenPersisted {
		t.Fatalf("successful sign-in token %q was not persisted", loginBody.Token)
	}
	config, err := configstate.NewRepository(store).Load(context.Background(), runtime.BaseConfig.Name)
	if err != nil || config.Base.FriendAddComment != "concurrent config" {
		t.Fatalf("concurrent Dice owner not persisted: comment=%q err=%v", config.Base.FriendAddComment, err)
	}
	state, _ := loadDiceConfigManagerState(t, store)
	if state.Public.ServeAddress != "concurrent-address:1234" {
		t.Fatalf("manager owner not persisted: serveAddress=%q", state.Public.ServeAddress)
	}
}

func loadDiceConfigManagerState(t *testing.T, store eventstore.Store) (managerstate.State, managerstate.Auth) {
	t.Helper()
	repository, err := managerstate.NewRepository(store)
	if err != nil {
		t.Fatal(err)
	}
	state, auth, err := repository.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return state, auth
}

type diceConfigDurableTestStore struct {
	*eventstore.GORMStore
	mu           sync.Mutex
	failCommit   bool
	commitCalls  int
	beforeCommit func(eventstore.UnitOfWork)
}

func (store *diceConfigDurableTestStore) Commit(ctx context.Context, work eventstore.UnitOfWork) (eventstore.CommitResult, error) {
	store.mu.Lock()
	store.commitCalls++
	beforeCommit := store.beforeCommit
	failCommit := store.failCommit
	store.mu.Unlock()
	if beforeCommit != nil {
		beforeCommit(work)
	}
	if failCommit {
		return eventstore.CommitResult{}, errors.New("injected commit failure")
	}
	return store.GORMStore.Commit(ctx, work)
}

func newDiceConfigDurableHandlerTest(t *testing.T) (*echo.Echo, *dice.DiceManager, *dice.Dice, *diceConfigDurableTestStore) {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	rootsDir := filepath.Join(root, "roots")
	if err := os.MkdirAll(rootsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	indexPath := filepath.Join(root, "index.key")
	if err := os.WriteFile(indexPath, bytes.Repeat([]byte{1}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootsDir, "root-v1.key"), bytes.Repeat([]byte{2}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	keys := eventstore.NewLocalFileKeySource(indexPath, rootsDir)
	keys.CurrentID = "root-v1"
	database, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(root, "events.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	options := projectionset.StoreOptions()
	store := &diceConfigDurableTestStore{GORMStore: eventstore.NewStore(database, append([]eventstore.StoreOption{eventstore.WithKeySource(keys)}, options...)...)}
	t.Cleanup(func() { _ = store.Close() })
	if err = store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "fresh", SchemaVersion: 1, DatabaseIdentity: "api-dice-config-atomic",
		IndexRootID: filepath.Base(indexPath), EncryptionRootIDs: []string{"root-v1"},
	}); err != nil {
		t.Fatal(err)
	}

	runtime := &dice.Dice{
		BaseConfig:   dice.BaseConfig{Name: "api-test", DataDir: filepath.Join(root, "api-test")},
		DurableStore: store,
	}
	manager := &dice.DiceManager{
		EventSourcedMode: true,
		Dice:             []*dice.Dice{runtime},
		ServeAddress:     "old-address:1234",
		UIPasswordSalt:   "old-salt",
		UIPasswordHash:   "old-password-hash",
		DiceRandomMode:   string(dice.DiceRandomModePCG),
	}
	manager.SetTrayTooltip("old tray text")
	runtime.Parent = manager
	if err = manager.RestoreEventSourcedManager(ctx, store); err != nil {
		t.Fatalf("initialize event-sourced manager: %v", err)
	}
	if err = manager.PrepareEventSourcedState(ctx); err != nil {
		t.Fatalf("initialize event-sourced Dice config: %v", err)
	}
	manager.AccessTokens.Store("dice-config-owner-token", true)
	manager.Save()

	extension := &dice.ExtInfo{Name: "test-extension", Version: "1.0.0"}
	runtime.ExtList = []*dice.ExtInfo{extension}
	if err = runtime.DurableDiscoverExtension(ctx, extension); err != nil {
		t.Fatalf("discover event-sourced extension: %v", err)
	}

	previousDice, previousManager := myDice, dm
	t.Cleanup(func() {
		myDice = previousDice
		dm = previousManager
	})
	echoServer := echo.New()
	Bind(echoServer, manager)
	return echoServer, manager, runtime, store
}

func reopenDiceConfigDurableTestStore(t *testing.T, runtime *dice.Dice) *diceConfigDurableTestStore {
	t.Helper()
	root, err := filepath.Abs(runtime.BaseConfig.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	root = filepath.Dir(root)
	keys := eventstore.NewLocalFileKeySource(filepath.Join(root, "index.key"), filepath.Join(root, "roots"))
	keys.CurrentID = "root-v1"
	database, err := eventstore.OpenDatabase(context.Background(), eventstore.DatabaseConfig{
		Type: "sqlite",
		DSN:  filepath.Join(root, "events.db"),
	})
	if err != nil {
		t.Fatalf("reopen durable event database: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	options := projectionset.StoreOptions()
	store := &diceConfigDurableTestStore{
		GORMStore: eventstore.NewStore(database, append([]eventstore.StoreOption{eventstore.WithKeySource(keys)}, options...)...),
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func postDiceConfigDurableRequest(server *echo.Echo, body, token string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/sd-api/dice/config/set", strings.NewReader(body))
	request.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	if token != "" {
		request.Header.Set("Token", token)
	}
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	return recorder
}
