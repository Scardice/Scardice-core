package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"Scardice-core/core/configstate"
	"Scardice-core/core/extensionstate"
	"Scardice-core/eventstore"
)

type postCommitHookStore struct {
	*diceConfigDurableTestStore
	afterCommit func(eventstore.UnitOfWork)
}

func (store *postCommitHookStore) Commit(ctx context.Context, work eventstore.UnitOfWork) (eventstore.CommitResult, error) {
	result, err := store.diceConfigDurableTestStore.Commit(ctx, work)
	if err == nil && store.afterCommit != nil {
		store.afterCommit(work)
	}
	return result, err
}

func TestDiceConfigSetSerializesConcurrentSnapshots(t *testing.T) {
	server, _, runtime, store := newDiceConfigDurableHandlerTest(t)
	firstCommitEntered := make(chan struct{})
	secondCommitEntered := make(chan struct{})
	releaseFirstCommit := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(releaseFirstCommit) })

	var hookMu sync.Mutex
	hookCalls := 0
	store.mu.Lock()
	store.commitCalls = 0
	store.beforeCommit = func(_ eventstore.UnitOfWork) {
		hookMu.Lock()
		hookCalls++
		call := hookCalls
		hookMu.Unlock()
		switch call {
		case 1:
			close(firstCommitEntered)
			<-releaseFirstCommit
		case 2:
			close(secondCommitEntered)
		}
	}
	store.mu.Unlock()

	firstResult := make(chan int, 1)
	go func() {
		firstResult <- postDiceConfigDurableRequest(server, `{"friendAddComment":"first update"}`, "dice-config-owner-token").Code
	}()
	select {
	case <-firstCommitEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("first config update did not reach Commit")
	}

	secondStarted := make(chan struct{})
	secondResult := make(chan int, 1)
	go func() {
		close(secondStarted)
		secondResult <- postDiceConfigDurableRequest(server, `{"refuseGroupInvite":true}`, "dice-config-owner-token").Code
	}()
	<-secondStarted
	overlapped := false
	select {
	case <-secondCommitEntered:
		overlapped = true
	case <-time.After(150 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(releaseFirstCommit) })
	firstStatus := <-firstResult
	secondStatus := <-secondResult
	store.mu.Lock()
	store.beforeCommit = nil
	commitCalls := store.commitCalls
	store.mu.Unlock()

	if overlapped {
		t.Fatal("second config snapshot reached durable commit before the first update published")
	}
	if firstStatus != http.StatusOK || secondStatus != http.StatusOK {
		t.Fatalf("concurrent config statuses = %d/%d, want both %d", firstStatus, secondStatus, http.StatusOK)
	}
	if commitCalls != 2 {
		t.Fatalf("config update commits = %d, want 2", commitCalls)
	}
	config, err := configstate.NewRepository(store).Load(context.Background(), runtime.BaseConfig.Name)
	if err != nil {
		t.Fatalf("load durable config: %v", err)
	}
	if config.Base.FriendAddComment != "first update" || !config.Base.RefuseGroupInvite {
		t.Fatalf("disjoint config updates were lost: comment=%q refuseInvite=%v", config.Base.FriendAddComment, config.Base.RefuseGroupInvite)
	}
	if runtime.Config.FriendAddComment != "first update" || !runtime.Config.RefuseGroupInvite {
		t.Fatalf("runtime config updates were lost: comment=%q refuseInvite=%v", runtime.Config.FriendAddComment, runtime.Config.RefuseGroupInvite)
	}
}

func TestDiceConfigSetClearsOmittedDurableExtensionDefaults(t *testing.T) {
	ctx := context.Background()
	server, _, runtime, store := newDiceConfigDurableHandlerTest(t)
	if err := runtime.DurableSetExtensionDefaults(ctx, "test-extension", true, []string{"blocked"}); err != nil {
		t.Fatalf("set initial extension defaults: %v", err)
	}
	store.mu.Lock()
	store.commitCalls = 0
	store.mu.Unlock()

	recorder := postDiceConfigDurableRequest(server, `{"extDefaultSettings":[]}`, "dice-config-owner-token")
	if recorder.Code != http.StatusOK {
		t.Fatalf("clear defaults status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	store.mu.Lock()
	commitCalls := store.commitCalls
	store.mu.Unlock()
	if commitCalls != 1 {
		t.Fatalf("clear defaults commits = %d, want one UnitOfWork", commitCalls)
	}
	state, err := extensionstate.NewRepository(store).Load(ctx, runtime.BaseConfig.Name)
	if err != nil {
		t.Fatalf("load extension state: %v", err)
	}
	if _, exists := state.DefaultCommands["test-extension"]; exists {
		t.Fatalf("removed extension defaults remain durable: %#v", state.DefaultCommands["test-extension"])
	}
	projected, err := extensionstate.ReadProjected(ctx, store, runtime.BaseConfig.Name)
	if err != nil {
		t.Fatalf("load projected extension state: %v", err)
	}
	if _, exists := projected.DefaultCommands["test-extension"]; exists {
		t.Fatalf("removed extension defaults remain projected: %#v", projected.DefaultCommands["test-extension"])
	}
}

func TestDiceAdvancedConfigSetSerializesWithSave(t *testing.T) {
	server, _, runtime, store := newDiceConfigDurableHandlerTest(t)
	runtime.AdvancedConfig.CustomReplyCooldown = 11
	gatedStore := &postCommitHookStore{diceConfigDurableTestStore: store}
	runtime.DurableStore = gatedStore

	advancedCommitPublished := make(chan struct{})
	saveCommitPublished := make(chan struct{})
	releaseAdvancedHandler := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(releaseAdvancedHandler) })
	var hookMu sync.Mutex
	hookCalls := 0
	gatedStore.afterCommit = func(eventstore.UnitOfWork) {
		hookMu.Lock()
		hookCalls++
		call := hookCalls
		hookMu.Unlock()
		switch call {
		case 1:
			close(advancedCommitPublished)
			<-releaseAdvancedHandler
		case 2:
			close(saveCommitPublished)
		}
	}

	advancedResult := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		request := httptest.NewRequest(http.MethodPost, "/sd-api/dice/config/advanced/set", strings.NewReader(`{"customReplyCooldown":17}`))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Token", "dice-config-owner-token")
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, request)
		advancedResult <- recorder
	}()
	select {
	case <-advancedCommitPublished:
	case <-time.After(5 * time.Second):
		select {
		case response := <-advancedResult:
			t.Fatalf("advanced request completed without committing: status=%d body=%s", response.Code, response.Body.String())
		default:
			t.Fatal("advanced config update did not reach post-commit publication")
		}
	}

	saveStarted := make(chan struct{})
	saveDone := make(chan struct{})
	go func() {
		close(saveStarted)
		runtime.Save(false)
		close(saveDone)
	}()
	<-saveStarted
	overlapped := false
	select {
	case <-saveCommitPublished:
		overlapped = true
	case <-time.After(150 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(releaseAdvancedHandler) })
	advancedResponse := <-advancedResult
	<-saveDone

	if overlapped {
		t.Fatal("Dice.Save committed an advanced snapshot before the API published its update")
	}
	if advancedResponse.Code != http.StatusOK {
		t.Fatalf("advanced config status = %d, body = %s", advancedResponse.Code, advancedResponse.Body.String())
	}
	state, err := configstate.NewRepository(gatedStore).Load(context.Background(), runtime.BaseConfig.Name)
	if err != nil {
		t.Fatalf("load durable config: %v", err)
	}
	if state.Advanced.CustomReplyCooldown != 17 || runtime.AdvancedConfig.CustomReplyCooldown != 17 {
		t.Fatalf("advanced update was overwritten: durable=%v runtime=%v", state.Advanced.CustomReplyCooldown, runtime.AdvancedConfig.CustomReplyCooldown)
	}
}
