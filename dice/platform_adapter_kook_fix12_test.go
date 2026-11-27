package dice

import (
	"testing"

	"github.com/lonelyevil/kook"
)

func TestKookPlainMessageMapsGroupAndPrivate(t *testing.T) {
	pa := &PlatformAdapterKook{}
	common := &kook.EventHandlerCommonContext{Common: &kook.EventDataGeneral{
		ChannelType:  "GROUP",
		TargetID:     "channel-1",
		AuthorID:     "user-1",
		Content:      "1d20",
		MsgID:        "msg-1",
		MsgTimestamp: 1700000000000,
	}}
	msg := pa.kookPlainMessage(common, kook.User{ID: "user-1", Nickname: "tester"}, "guild-1", "1d20")
	if msg == nil {
		t.Fatal("group message is nil")
	}
	if msg.MessageType != "group" || msg.GroupID != FormatDiceIDKookChannel("channel-1") {
		t.Fatalf("group mapping = %q/%q", msg.MessageType, msg.GroupID)
	}
	if msg.GuildID != FormatDiceIDKookGuild("guild-1") || msg.Message != "1d20" {
		t.Fatalf("group metadata = %q/%q", msg.GuildID, msg.Message)
	}

	common.Common.ChannelType = "PERSON"
	privateMsg := pa.kookPlainMessage(common, kook.User{ID: "user-1"}, "", "1d20")
	if privateMsg == nil || privateMsg.MessageType != "private" || privateMsg.GroupID != "" {
		t.Fatalf("private mapping = %#v", privateMsg)
	}
}

func TestKookMediaCQCode(t *testing.T) {
	if got := kookMediaCQCode("file", " https://example.com/a.zip "); got != "[CQ:file,file=somefile,url=https://example.com/a.zip]" {
		t.Fatalf("file code = %q", got)
	}
	if got := kookMediaCQCode("record", ""); got != "" {
		t.Fatalf("empty media code = %q", got)
	}
}
