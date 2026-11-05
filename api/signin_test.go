package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"Scardice-core/dice"
)

func TestSignInReturnsPersistedToken(t *testing.T) {
	for _, test := range []struct {
		name          string
		password      string
		clearPassword bool
	}{
		{name: "empty password hash", password: "ignored", clearPassword: true},
		{name: "matching password", password: "old-password-hash"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, manager, runtime, store := newDiceConfigDurableHandlerTest(t)
			if test.clearPassword {
				empty := ""
				if err := runtime.DurableCommitConfigRequest(context.Background(), dice.DurableConfigRequest{
					Manager: &dice.DurableManagerConfigPatch{UIPasswordHash: &empty},
				}); err != nil {
					t.Fatalf("clear manager password hash: %v", err)
				}
			}
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
			if _, auth := loadDiceConfigManagerState(t, store); !slices.Contains(auth.AccessTokens, response.Token) {
				t.Fatalf("sign-in token %q was not persisted", response.Token)
			}
		})
	}
}
