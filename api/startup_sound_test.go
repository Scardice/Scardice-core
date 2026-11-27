package api //nolint:testpackage

import (
	"encoding/json"
	"net/http"
	"testing"

	"go.uber.org/zap"

	"Scardice-core/dice"
)

func TestStartupSoundStatus(t *testing.T) {
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
	testDice.Config.StartupSoundEnable = true
	manager := &dice.DiceManager{
		Dice:        []*dice.Dice{testDice},
		JustForTest: true,
	}
	token := "test-token"
	manager.AccessTokens.Store(token, true)
	testDice.Parent = manager
	myDice = testDice
	dm = manager

	unauthorized := performReplyAPIRequest(t, http.MethodGet, "/sd-api/dice/startup-sound/status", "", "bad-token", StartupSoundStatus)
	if unauthorized.Code != http.StatusForbidden {
		t.Fatalf("unauthorized status = %d, want 403", unauthorized.Code)
	}

	rec := performReplyAPIRequest(t, http.MethodGet, "/sd-api/dice/startup-sound/status", "", token, StartupSoundStatus)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp StartupSoundStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Enabled {
		t.Fatal("enabled 应为 true")
	}
	if resp.Status.Message == "" {
		t.Fatal("status.message 不应为空")
	}
}
