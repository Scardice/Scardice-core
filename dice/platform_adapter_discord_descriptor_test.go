package dice

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/bwmarrin/discordgo"

	"Scardice-core/adapterapi"
	"Scardice-core/adapterapi/contracttest"
)

func TestDiscordDescriptorCanonicalizesWithoutMutatingDiscordgoEndpoints(t *testing.T) {
	originalDiscord := discordgo.EndpointDiscord
	originalAPI := discordgo.EndpointAPI

	validated, err := (DiscordDescriptor{}).ValidateConfig(context.Background(), json.RawMessage(`{
		"version":"1",
		"guild":"guild-1",
		"channel":"channel-1",
		"token":{"secretRef":"discord-token","version":2},
		"proxyURL":"",
		"reverseProxyUrl":"https://discord.example/",
		"reverseProxyCDNUrl":"https://cdn.example/"
	}`))
	if err != nil {
		t.Fatalf("validate Discord config: %v", err)
	}
	if discordgo.EndpointDiscord != originalDiscord || discordgo.EndpointAPI != originalAPI {
		t.Fatalf("discordgo process globals changed: Discord=%q API=%q", discordgo.EndpointDiscord, discordgo.EndpointAPI)
	}
	want := `{"channel":"channel-1","guild":"guild-1","proxyURL":"","reverseProxyCDNUrl":"https://cdn.example","reverseProxyUrl":"https://discord.example","token":{"secretRef":"discord-token","version":2},"version":"1"}`
	if string(validated.Canonical) != want {
		t.Fatalf("canonical config = %s, want %s", validated.Canonical, want)
	}
	if len(validated.SecretRefs) != 1 || validated.SecretRefs[0].Ref != "discord-token" || validated.SecretRefs[0].Version != 2 {
		t.Fatalf("secret refs = %#v", validated.SecretRefs)
	}
}

func TestDiscordMessageInboundClassifiesDirectAndGroup(t *testing.T) {
	direct, err := discordMessageInbound("MESSAGE_CREATE", discordGatewayMessage{
		ID: "message-direct", ChannelID: "channel-direct", Author: discordGatewayUser{ID: "user-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if direct.ConversationKind != adapterapi.ConversationKindDirect {
		t.Fatalf("direct conversation kind = %v", direct.ConversationKind)
	}
	group, err := discordMessageInbound("MESSAGE_CREATE", discordGatewayMessage{
		ID: "message-group", ChannelID: "channel-group", GuildID: "guild-1", Author: discordGatewayUser{ID: "user-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if group.ConversationKind != adapterapi.ConversationKindGroup {
		t.Fatalf("group conversation kind = %v", group.ConversationKind)
	}
}

func TestDiscordDescriptorSatisfiesRuntimeContract(t *testing.T) {
	contracttest.Verify(t, contracttest.Case{
		NewDescriptor:                NewDiscordDescriptor,
		Config:                       json.RawMessage(`{"version":"1","guild":"","channel":"","token":{"secretRef":"discord-token","version":1},"proxyURL":"","reverseProxyUrl":"","reverseProxyCDNUrl":""}`),
		Init:                         adapterapi.RuntimeInit{EndpointID: "discord-contract", Generation: 1, DesiredVersion: 1},
		SecretValues:                 []string{"runtime-token"},
		RequireOwnedResourceManifest: true,
	})
}
