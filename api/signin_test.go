package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"Scardice-core/dice"
)

func TestSignInLegacyModeReturnsToken(t *testing.T) {
	previousDice := myDice
	t.Cleanup(func() { myDice = previousDice })

	for _, test := range []struct {
		name     string
		password string
		hash     string
	}{
		{name: "empty password hash", password: "ignored"},
		{name: "matching password", password: "legacy-password-hash", hash: "legacy-password-hash"},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := &dice.DiceManager{UIPasswordHash: test.hash}
			myDice = &dice.Dice{Parent: manager}
			request := httptest.NewRequest(http.MethodPost, "/sd-api/signin", strings.NewReader(`{"password":"`+test.password+`"}`))
			request.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			recorder := httptest.NewRecorder()
			if err := doSignIn(echo.New().NewContext(request, recorder)); err != nil {
				t.Fatalf("doSignIn() error = %v", err)
			}
			if recorder.Code != http.StatusOK {
				t.Fatalf("sign-in status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
			}
			var response struct {
				Token string `json:"token"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatalf("decode sign-in response: %v", err)
			}
			if response.Token == "" || !manager.AccessTokens.Exists(response.Token) {
				t.Fatalf("sign-in token %q was not stored", response.Token)
			}
		})
	}
}
