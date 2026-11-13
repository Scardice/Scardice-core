package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"Scardice-core/dice"
)

func Test_DiceConfig_notice_targets_round_trip_without_changing_masters(t *testing.T) {
	// Given
	previousDice := myDice
	t.Cleanup(func() { myDice = previousDice })
	t.Chdir(t.TempDir())
	if err := os.Mkdir("data", 0o755); err != nil {
		t.Fatalf("create config data directory: %v", err)
	}
	manager := &dice.DiceManager{}
	manager.AccessTokens.Store("task10-token", true)
	myDice = &dice.Dice{
		Parent:      manager,
		DiceMasters: []string{"QQ:permission-only"},
	}
	manager.Dice = []*dice.Dice{myDice}
	e := echo.New()
	requestBody := `{"noticeIds":[" QQ:1001:only=ban,group,ban ","QQ:1002:disable:only=send",""]}`
	setRequest := httptest.NewRequest(http.MethodPost, "/sd-api/dice/config", strings.NewReader(requestBody))
	setRequest.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	setRequest.Header.Set("Token", "task10-token")
	setRecorder := httptest.NewRecorder()

	// When
	if err := DiceConfigSet(e.NewContext(setRequest, setRecorder)); err != nil {
		t.Fatalf("set notice targets: %v", err)
	}
	getRequest := httptest.NewRequest(http.MethodGet, "/sd-api/dice/config", nil)
	getRequest.Header.Set("Token", "task10-token")
	getRecorder := httptest.NewRecorder()
	if err := DiceConfig(e.NewContext(getRequest, getRecorder)); err != nil {
		t.Fatalf("get notice targets: %v", err)
	}

	// Then
	if setRecorder.Code != http.StatusOK || getRecorder.Code != http.StatusOK {
		t.Fatalf("config statuses = set %d, get %d", setRecorder.Code, getRecorder.Code)
	}
	var response struct {
		NoticeIDs   []string `json:"noticeIds"`
		DiceMasters []string `json:"diceMasters"`
	}
	if err := json.Unmarshal(getRecorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode config response: %v", err)
	}
	wantTargets := []string{"QQ:1001:only=group,ban", "QQ:1002:disable:only=send"}
	if !reflect.DeepEqual(response.NoticeIDs, wantTargets) {
		t.Fatalf("notice targets = %v, want %v", response.NoticeIDs, wantTargets)
	}
	if !reflect.DeepEqual(response.DiceMasters, []string{"QQ:permission-only"}) {
		t.Fatalf("dice masters changed with notice targets: %v", response.DiceMasters)
	}
}
