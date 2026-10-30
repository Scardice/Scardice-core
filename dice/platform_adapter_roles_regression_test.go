package dice

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNonQQSenderRoleRestoration(t *testing.T) {
	cases := []struct {
		name string
		got  func(t *testing.T, base string) string
		want string
	}{
		{name: "discord admin role permissions", got: func(t *testing.T, base string) string {
			return (&discordRuntime{config: discordCanonicalConfig{ReverseProxyURL: base}, httpClient: http.DefaultClient}).senderRole(t.Context(), "token", "guild-1", "channel-1", "user-1")
		}, want: "admin"},
		{name: "kook guild master", got: func(t *testing.T, base string) string {
			return (&kookRuntime{config: kookCanonicalConfig{APIBaseURL: base}, httpClient: http.DefaultClient}).senderRole(t.Context(), "token", "guild-1", "master-1")
		}, want: "admin"},
		{name: "dodo island owner", got: func(t *testing.T, base string) string {
			return (&dodoRuntime{config: dodoCanonicalConfig{APIBaseURL: base}, httpClient: http.DefaultClient}).senderRole(t.Context(), "token", "island-1", "owner-1")
		}, want: "owner"},
		{name: "slack owner", got: func(t *testing.T, base string) string {
			return (&slackRuntime{config: slackCanonicalConfig{APIBaseURL: base}, httpClient: http.DefaultClient}).senderRole(t.Context(), "token", "U1")
		}, want: "owner"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(roleFixtureHandler(tc.name))
			defer server.Close()
			if role := tc.got(t, server.URL); role != tc.want {
				t.Fatalf("role = %q, want %q", role, tc.want)
			}
		})
	}
}

func TestNonQQSenderRoleLookupFailureIsNotAdmin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Error(writer, "provider unavailable", http.StatusInternalServerError)
	}))
	defer server.Close()
	if role := (&discordRuntime{config: discordCanonicalConfig{ReverseProxyURL: server.URL}, httpClient: http.DefaultClient}).senderRole(t.Context(), "token", "guild-1", "channel-1", "user-1"); role != "" {
		t.Fatalf("discord role = %q", role)
	}
	if role := (&kookRuntime{config: kookCanonicalConfig{APIBaseURL: server.URL}, httpClient: http.DefaultClient}).senderRole(t.Context(), "token", "guild-1", "user-1"); role != "" {
		t.Fatalf("kook role = %q", role)
	}
	if role := (&dodoRuntime{config: dodoCanonicalConfig{APIBaseURL: server.URL}, httpClient: http.DefaultClient}).senderRole(t.Context(), "token", "island-1", "user-1"); role != "" {
		t.Fatalf("dodo role = %q", role)
	}
	if role := (&slackRuntime{config: slackCanonicalConfig{APIBaseURL: server.URL}, httpClient: http.DefaultClient}).senderRole(t.Context(), "token", "U1"); role != "" {
		t.Fatalf("slack role = %q", role)
	}
}

func TestNonQQSenderRoleMissingIdentitySkipsLookup(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		_ = json.NewEncoder(writer).Encode(map[string]any{"data": map[string]any{}})
	}))
	defer server.Close()
	if role := (&discordRuntime{config: discordCanonicalConfig{ReverseProxyURL: server.URL}, httpClient: http.DefaultClient}).senderRole(t.Context(), "", "guild-1", "channel-1", "user-1"); role != "" {
		t.Fatalf("discord role = %q", role)
	}
	if role := (&kookRuntime{config: kookCanonicalConfig{APIBaseURL: server.URL}, httpClient: http.DefaultClient}).senderRole(t.Context(), "token", "", "user-1"); role != "" {
		t.Fatalf("kook role = %q", role)
	}
	if requests != 0 {
		t.Fatalf("unexpected provider requests = %d", requests)
	}
}

func roleFixtureHandler(caseName string) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch caseName {
		case "discord admin role permissions":
			switch request.URL.Path {
			case "/api/v10/guilds/guild-1/members/user-1":
				_ = json.NewEncoder(writer).Encode(map[string]any{"roles": []string{"role-admin"}})
			case "/api/v10/guilds/guild-1":
				_ = json.NewEncoder(writer).Encode(map[string]any{"owner_id": "owner-1", "roles": []any{map[string]any{"id": "role-admin", "permissions": "8"}}})
			case "/api/v10/channels/channel-1":
				_ = json.NewEncoder(writer).Encode(map[string]any{"permission_overwrites": []any{}})
			default:
				http.NotFound(writer, request)
			}
		case "kook guild master":
			switch request.URL.Path {
			case "/api/v3/user/view":
				_ = json.NewEncoder(writer).Encode(map[string]any{"code": 0, "data": map[string]any{"roles": []int{1}}})
			case "/api/v3/guild/view":
				_ = json.NewEncoder(writer).Encode(map[string]any{"code": 0, "data": map[string]any{"master_id": "master-1", "roles": []any{}}})
			default:
				http.NotFound(writer, request)
			}
		case "dodo island owner":
			if request.URL.Path != "/api/v1/island/info" {
				http.NotFound(writer, request)
				return
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{"status": 0, "data": map[string]any{"ownerDodoSourceId": "owner-1"}})
		case "slack owner":
			_ = json.NewEncoder(writer).Encode(map[string]any{"ok": true, "user": map[string]any{"is_owner": true, "is_admin": false}})
		default:
			http.NotFound(writer, request)
		}
	}
}

func TestDiscordSenderRolePreservesEffectivePermissionPrecedence(t *testing.T) {
	for _, test := range []struct {
		name        string
		owner       string
		roleID      string
		permissions string
		memberRoles []string
		overwrites  string
		want        string
	}{
		{name: "guild owner without roles", owner: "user-1", permissions: "0", want: "admin"},
		{name: "everyone role", roleID: "guild-1", permissions: "2", want: "admin"},
		{name: "unassigned role", roleID: "unassigned", permissions: "8"},
		{name: "member deny overrides role allow", roleID: "assigned", permissions: "2", memberRoles: []string{"assigned"}, overwrites: `[{"id":"user-1","type":1,"allow":"0","deny":"2"}]`},
		{name: "member allow overrides role deny", roleID: "assigned", permissions: "2", memberRoles: []string{"assigned"}, overwrites: `[{"id":"assigned","type":0,"allow":"0","deny":"2"},{"id":"user-1","type":1,"allow":"2","deny":"0"}]`, want: "admin"},
	} {
		t.Run(test.name, func(t *testing.T) {
			overwrites := test.overwrites
			if overwrites == "" {
				overwrites = "[]"
			}
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				switch request.URL.Path {
				case "/api/v10/guilds/guild-1":
					_ = json.NewEncoder(writer).Encode(map[string]any{"owner_id": test.owner, "roles": []any{map[string]any{"id": test.roleID, "permissions": test.permissions}}})
				case "/api/v10/guilds/guild-1/members/user-1":
					_ = json.NewEncoder(writer).Encode(map[string]any{"roles": test.memberRoles})
				case "/api/v10/channels/channel-1":
					_ = json.NewEncoder(writer).Encode(map[string]any{"permission_overwrites": json.RawMessage(overwrites)})
				default:
					http.NotFound(writer, request)
				}
			}))
			defer server.Close()
			runtime := &discordRuntime{config: discordCanonicalConfig{ReverseProxyURL: server.URL}, httpClient: server.Client()}
			if role := runtime.senderRole(t.Context(), "token", "guild-1", "channel-1", "user-1"); role != test.want {
				t.Fatalf("role = %q, want %q", role, test.want)
			}
		})
	}
}
