package api

import (
	"context"
	"net/http"
	"testing"

	"Scardice-core/core/extensionstate"
)

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
