package dice

import (
	"testing"
	"time"

	"Scardice-core/adapterapi"
)

func TestDiscordMessageInboundNormalizesGuildMessage(t *testing.T) {
	message := discordGatewayMessage{
		ID:        "message-1",
		ChannelID: "channel-1",
		GuildID:   "guild-1",
		Content:   "hello",
		Timestamp: "2023-11-14T22:13:20Z",
		Author:    discordGatewayUser{ID: "user-1", Username: "alice"},
	}
	inbound, err := discordMessageInbound("MESSAGE_CREATE", message)
	if err != nil {
		t.Fatalf("normalize Discord message: %v", err)
	}
	if inbound.ProviderEventID != "discord-message-created:message-1" || inbound.MessageID != "message-1" || inbound.Sender != "DISCORD:user-1" || inbound.Conversation != "DISCORD-CH-Group:channel-1" || inbound.Target != "DISCORD-CH-Group:channel-1" || inbound.Kind != adapterapi.InboundKindMessage || inbound.Text != "hello" {
		t.Fatalf("inbound = %#v", inbound)
	}
	if !inbound.OccurredAt.Equal(time.Unix(1_700_000_000, 0).UTC()) {
		t.Fatalf("occurred at = %s", inbound.OccurredAt)
	}
}

func TestDiscordMessageInboundNormalizesUpdateAndDelete(t *testing.T) {
	updated, err := discordMessageInbound("MESSAGE_UPDATE", discordGatewayMessage{ID: "message-1", ChannelID: "channel-1", GuildID: "guild-1", Content: "edited", Author: discordGatewayUser{ID: "user-1"}})
	if err != nil {
		t.Fatalf("normalize Discord update: %v", err)
	}
	if updated.Kind != adapterapi.InboundKindMessageUpdated || updated.ProviderEventID != "discord-message-updated:message-1" {
		t.Fatalf("updated = %#v", updated)
	}
	deleted, err := discordMessageInbound("MESSAGE_DELETE", discordGatewayMessage{ID: "message-1", ChannelID: "channel-1", GuildID: "guild-1"})
	if err != nil {
		t.Fatalf("normalize Discord delete: %v", err)
	}
	if deleted.Kind != adapterapi.InboundKindMessageDeleted || deleted.ProviderEventID != "discord-message-deleted:message-1" || deleted.Conversation != "DISCORD-CH-Group:channel-1" {
		t.Fatalf("deleted = %#v", deleted)
	}
}
