package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"

	"Scardice-core/core/configstate"
	"Scardice-core/dice"
)

func TestShouldReloadDangerousAPIState(t *testing.T) {
	tests := []struct {
		name       string
		jsEnabled  bool
		runtimeOn  bool
		desiredOn  bool
		wantReload bool
	}{
		{
			name:       "no js no reload",
			jsEnabled:  false,
			runtimeOn:  true,
			desiredOn:  false,
			wantReload: false,
		},
		{
			name:       "turn on reloads",
			jsEnabled:  true,
			runtimeOn:  false,
			desiredOn:  true,
			wantReload: true,
		},
		{
			name:       "turn off reloads even if config already mutated in memory",
			jsEnabled:  true,
			runtimeOn:  true,
			desiredOn:  false,
			wantReload: true,
		},
		{
			name:       "state already matches no reload",
			jsEnabled:  true,
			runtimeOn:  false,
			desiredOn:  false,
			wantReload: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldReloadDangerousAPIState(tt.jsEnabled, tt.runtimeOn, tt.desiredOn)
			if got != tt.wantReload {
				t.Fatalf("shouldReloadDangerousAPIState(%v, %v, %v) = %v, want %v", tt.jsEnabled, tt.runtimeOn, tt.desiredOn, got, tt.wantReload)
			}
		})
	}
}

func TestDiceAdvancedConfigRoundTripPreservesVersionAndTokenReference(t *testing.T) {
	firstServer, _, runtime, store := newDiceConfigDurableHandlerTest(t)
	const authToken = "dice-config-owner-token"
	const secretRef = "vault:scardice-test-story-log-token"
	request := func(client *http.Client, baseURL, method, body string) (int, []byte) {
		t.Helper()
		endpoint := "get"
		if method == http.MethodPost {
			endpoint = "set"
		}
		req, err := http.NewRequest(method, baseURL+"/sd-api/dice/config/advanced/"+endpoint, bytes.NewBufferString(body))
		if err != nil {
			t.Fatalf("create %s advanced-config request: %v", method, err)
		}
		req.Header.Set("Token", authToken)
		if method == http.MethodPost {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s advanced-config request: %v", method, err)
		}
		defer resp.Body.Close()
		payload, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read %s advanced-config response: %v", method, err)
		}
		return resp.StatusCode, payload
	}

	firstHTTP := httptest.NewServer(firstServer)
	status, payload := request(firstHTTP.Client(), firstHTTP.URL, http.MethodPost,
		`{"show":true,"enable":true,"storyLogBackendUrl":"http://127.0.0.1:18080/storylog","storyLogApiVersion":"V1","storyLogBackendToken":"`+secretRef+`","customReplyCooldown":11}`)
	firstHTTP.Close()
	if status != http.StatusOK {
		t.Fatalf("configure durable advanced settings: status=%d body=%s", status, payload)
	}

	restartedRuntime := &dice.Dice{BaseConfig: runtime.BaseConfig, DurableStore: store}
	restartedManager := &dice.DiceManager{EventSourcedMode: true, Dice: []*dice.Dice{restartedRuntime}}
	restartedRuntime.Parent = restartedManager
	if err := restartedManager.PrepareEventSourcedState(context.Background()); err != nil {
		t.Fatalf("hydrate restarted runtime: %v", err)
	}
	restartedManager.AccessTokens.Store(authToken, true)
	restartedServer := echo.New()
	Bind(restartedServer, restartedManager)
	restartedHTTP := httptest.NewServer(restartedServer)
	defer restartedHTTP.Close()

	status, payload = request(restartedHTTP.Client(), restartedHTTP.URL, http.MethodGet, "")
	if status != http.StatusOK {
		t.Fatalf("read durable advanced settings after restart: status=%d body=%s", status, payload)
	}
	if bytes.Contains(payload, []byte(secretRef)) {
		t.Fatal("advanced-config GET exposed the durable story-log token reference")
	}
	var advanced dice.AdvancedConfig
	if err := json.Unmarshal(payload, &advanced); err != nil {
		t.Fatalf("decode durable advanced settings: %v", err)
	}
	if advanced.StoryLogApiVersion != "V1" {
		t.Fatalf("GET after restart returned storyLogApiVersion=%q, want V1", advanced.StoryLogApiVersion)
	}
	if advanced.StoryLogBackendToken != "" {
		t.Fatal("advanced-config GET exposed the write-only secret reference")
	}

	advanced.CustomReplyCooldown = 19
	updateBody, err := json.Marshal(advanced)
	if err != nil {
		t.Fatalf("encode full advanced-config update: %v", err)
	}
	status, payload = request(restartedHTTP.Client(), restartedHTTP.URL, http.MethodPost, string(updateBody))
	if status != http.StatusOK {
		t.Fatalf("update unrelated advanced setting: status=%d body=%s", status, payload)
	}

	status, payload = request(restartedHTTP.Client(), restartedHTTP.URL, http.MethodGet, "")
	if status != http.StatusOK {
		t.Fatalf("read advanced settings after update: status=%d body=%s", status, payload)
	}
	advanced = dice.AdvancedConfig{}
	if err := json.Unmarshal(payload, &advanced); err != nil {
		t.Fatalf("decode advanced settings after update: %v", err)
	}
	if advanced.StoryLogApiVersion != "V1" || advanced.CustomReplyCooldown != 19 {
		t.Fatalf("advanced settings after unrelated update = version %q cooldown %v, want V1 and 19", advanced.StoryLogApiVersion, advanced.CustomReplyCooldown)
	}

	state, err := configstate.NewRepository(store).Load(context.Background(), runtime.BaseConfig.Name)
	if err != nil {
		t.Fatalf("load durable advanced state: %v", err)
	}
	if state.Advanced.StoryLogBackendTokenRef != secretRef {
		t.Fatalf("durable story-log token reference = %q, want configured reference preserved", state.Advanced.StoryLogBackendTokenRef)
	}
	if state.Advanced.StoryLogAPIVersion != "V1" {
		t.Fatalf("durable story-log API version = %q, want V1", state.Advanced.StoryLogAPIVersion)
	}
}
