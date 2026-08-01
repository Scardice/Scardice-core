package dice

import (
	"testing"

	"github.com/sealdice/botgo/dto"
)

func TestOfficialQQBotAccountDetect_matchesOnlyTrustedEndpointID(t *testing.T) {
	tests := []struct {
		name   string
		author *dto.User
		want   bool
	}{
		{name: "same trusted bot ID", author: &dto.User{ID: "bot-account-id"}, want: true},
		{name: "different ID", author: &dto.User{ID: "other-account-id"}, want: false},
		{name: "empty ID", author: &dto.User{}, want: false},
		{name: "display name only", author: &dto.User{Username: "trusted bot"}, want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			endpoint := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{
				UserID:   "OpenQQ:bot-account-id",
				Nickname: "trusted bot",
			}}
			adapter := &PlatformAdapterOfficialQQ{EndPoint: endpoint}
			originalEndpointID := endpoint.UserID
			originalEndpointName := endpoint.Nickname
			originalAuthorID := test.author.ID
			originalAuthorName := test.author.Username

			// When
			got := adapter.detectBotAccount(test.author)

			// Then
			if got != test.want {
				t.Fatalf("detectBotAccount() = %t, want %t", got, test.want)
			}
			if endpoint.UserID != originalEndpointID || endpoint.Nickname != originalEndpointName ||
				test.author.ID != originalAuthorID || test.author.Username != originalAuthorName {
				t.Fatalf("identity changed: endpoint=%q author=%q", endpoint.UserID, test.author.ID)
			}
		})
	}
}
