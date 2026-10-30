package dice

import (
	"testing"

	milky "github.com/Szzrain/Milky-go-sdk"

	"Scardice-core/adapterapi"
)

func TestMilkyMessageInboundNormalizesGroupMessage(t *testing.T) {
	inbound, err := milkyMessageInbound(&milky.ReceiveMessage{
		PeerId:       200,
		MessageSeq:   42,
		SenderId:     100,
		Time:         1_700_000_000,
		MessageScene: "group",
		Segments: []milky.IMessageElement{
			&milky.TextElement{Text: "hello"},
			&milky.AtElement{UserID: 101},
		},
	})
	if err != nil {
		t.Fatalf("normalize Milky inbound: %v", err)
	}
	if inbound.ProviderEventID != "milky-message:group:200:42" || inbound.MessageID != "42" || inbound.Sender != "QQ:100" || inbound.Conversation != "QQ-Group:200" || inbound.Text != "hello" || inbound.Kind != adapterapi.InboundKindMessage {
		t.Fatalf("inbound = %#v", inbound)
	}
	if len(inbound.Segments) != 2 || inbound.Segments[1].Kind != "mention" || inbound.Segments[1].ProviderID != "QQ:101" {
		t.Fatalf("segments = %#v", inbound.Segments)
	}
}

func TestMilkyMessageInboundCarriesGroupMemberRole(t *testing.T) {
	cases := []struct {
		role string
		want string
	}{
		{role: "owner", want: "owner"},
		{role: "admin", want: "admin"},
		{role: "member", want: "member"},
		{role: "custom-title", want: ""},
		{role: "", want: ""},
	}
	for _, test := range cases {
		t.Run(test.role, func(t *testing.T) {
			inbound, err := milkyMessageInbound(&milky.ReceiveMessage{
				PeerId:       200,
				MessageSeq:   42,
				SenderId:     100,
				MessageScene: "group",
				GroupMember:  &milky.GroupMemberInfo{GroupId: 200, UserId: 100, Role: test.role},
			})
			if err != nil {
				t.Fatalf("normalize Milky inbound: %v", err)
			}
			if inbound.SenderRole != test.want {
				t.Fatalf("sender role = %q, want %q", inbound.SenderRole, test.want)
			}
		})
	}
}

func TestMilkyPrivateMessageInboundOmitsGroupRole(t *testing.T) {
	inbound, err := milkyMessageInbound(&milky.ReceiveMessage{
		PeerId:       100,
		MessageSeq:   42,
		SenderId:     100,
		MessageScene: "friend",
		GroupMember:  &milky.GroupMemberInfo{GroupId: 200, UserId: 100, Role: "owner"},
	})
	if err != nil {
		t.Fatalf("normalize Milky inbound: %v", err)
	}
	if inbound.SenderRole != "" {
		t.Fatalf("private message carried group role %q", inbound.SenderRole)
	}
}

func TestMilkyGroupMessageWithoutGroupMemberOmitsRole(t *testing.T) {
	inbound, err := milkyMessageInbound(&milky.ReceiveMessage{
		PeerId:       200,
		MessageSeq:   42,
		SenderId:     100,
		MessageScene: "group",
	})
	if err != nil {
		t.Fatalf("normalize Milky inbound: %v", err)
	}
	if inbound.SenderRole != "" {
		t.Fatalf("sender role = %q, want empty", inbound.SenderRole)
	}
}

func TestMilkyMessageInboundRejectsUnsupportedScene(t *testing.T) {
	_, err := milkyMessageInbound(&milky.ReceiveMessage{PeerId: 200, MessageSeq: 42, SenderId: 100, MessageScene: "temp"})
	if err == nil {
		t.Fatal("unsupported Milky message scene was accepted")
	}
}

func TestMilkyRecallInboundNormalizesDeletedMessage(t *testing.T) {
	inbound, err := milkyRecallInbound(&milky.MessageRecall{MessageScene: "group", PeerID: 200, MessageSeq: 42, SenderID: 100})
	if err != nil {
		t.Fatalf("normalize Milky recall: %v", err)
	}
	if inbound.ProviderEventID != "milky-recall:group:200:42" || inbound.MessageID != "42" || inbound.Sender != "QQ:100" || inbound.Conversation != "QQ-Group:200" || inbound.Kind != adapterapi.InboundKindMessageDeleted {
		t.Fatalf("inbound = %#v", inbound)
	}
}
