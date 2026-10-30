package dice

import (
	"errors"
	"strconv"
	"testing"

	"Scardice-core/message"
)

type failingReplyBridge struct {
	calls int
}

func (b *failingReplyBridge) SubmitText(_ *MsgContext, _ *Message, _, _ string, _ bool) error {
	b.calls++
	return errors.New("unexpected durable submission")
}

func TestReplyPlanUsesTransientUIAdapterWithDurableBridge(t *testing.T) {
	dice := &Dice{}
	session := &IMSession{Parent: dice}
	endpoint := newUIEndpoint(session)
	dice.UIEndpoint = endpoint
	bridge := &failingReplyBridge{}
	dice.OutboundBridge = bridge
	ctx := &MsgContext{Dice: dice, Session: session, EndPoint: endpoint}
	msg := &Message{MessageType: "private", Sender: SenderBase{UserID: "UI:1001"}}

	adapter := endpoint.Adapter.(*PlatformAdapterHTTP)
	cursor := adapter.RecentMessagesSince("").Cursor
	accepted := deliverReplyPlan(ctx, msg, "骰点结果：1d100=42", "", false)
	batch := adapter.RecentMessagesSince(cursor)
	got := batch.Messages
	want := HTTPSimpleMessage{UID: "UI:1001", Message: "骰点结果：1d100=42", MessageType: "private"}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("UI recent messages = %#v, want []HTTPSimpleMessage{%#v}", got, want)
	}
	if remaining := adapter.RecentMessagesSince(batch.Cursor).Messages; len(remaining) != 0 {
		t.Fatalf("acknowledged replies = %#v, want empty", remaining)
	}
	if bridge.calls != 0 {
		t.Fatalf("durable bridge submissions = %d, want 0 for transient UI endpoint", bridge.calls)
	}
	if !accepted {
		t.Fatal("transient UI reply was not accepted")
	}
}

func TestPlatformAdapterHTTPReplyHistoryBoundsAndReaderIsolation(t *testing.T) {
	adapter := &PlatformAdapterHTTP{}
	start := adapter.RecentMessagesSince("").Cursor
	for i := range uiReplyHistoryLimit + 2 {
		adapter.appendRecentMessages(nil, "UI-Group:2002", strconv.Itoa(i), "group")
	}
	batch := adapter.RecentMessagesSince(start)
	if !batch.Truncated || len(batch.Messages) != uiReplyHistoryLimit ||
		batch.Messages[0].Message != "2" || batch.Messages[uiReplyHistoryLimit-1].Message != strconv.Itoa(uiReplyHistoryLimit+1) {
		t.Fatalf("retained reply window = %#v, want bounded, ordered history and explicit gap", batch)
	}
	batch.Messages[0].Message = "mutated"
	if again := adapter.RecentMessagesSince(start); again.Messages[0].Message != "2" {
		t.Fatal("one reader mutated another reader's retained reply")
	}
	adapter.appendRecentMessages(nil, "UI:1001", "after overflow", "private")
	next := adapter.RecentMessagesSince(batch.Cursor)
	if next.Truncated || len(next.Messages) != 1 || next.Messages[0].Message != "after overflow" {
		t.Fatalf("cursor did not advance after overflow: %#v", next)
	}
}

func TestPlatformAdapterHTTPReplyCursorRecoversAfterRestart(t *testing.T) {
	old := (&PlatformAdapterHTTP{}).RecentMessagesSince("").Cursor
	adapter := &PlatformAdapterHTTP{}
	adapter.appendRecentMessages(nil, "UI:1001", "reply after restart", "private")
	batch := adapter.RecentMessagesSince(old)
	if !batch.Truncated || len(batch.Messages) != 1 || batch.Messages[0].Message != "reply after restart" {
		t.Fatalf("old stream cursor did not recover: %#v", batch)
	}
	for _, cursor := range []string{"invalid", adapter.replyStream + ":invalid", adapter.replyStream + ":999999"} {
		batch := adapter.RecentMessagesSince(cursor)
		if !batch.Truncated || len(batch.Messages) != 1 || batch.Messages[0].Message != "reply after restart" {
			t.Fatalf("invalid cursor %q did not recover: %#v", cursor, batch)
		}
	}
}
func TestReplyPersonRawNoCheckMarksForwardOnlyUIFallbackAccepted(t *testing.T) {
	dice := &Dice{}
	session := &IMSession{Parent: dice}
	endpoint := newUIEndpoint(session)
	ctx := &MsgContext{Dice: dice, Session: session, EndPoint: endpoint}
	msg := &Message{MessageType: "private", Sender: SenderBase{UserID: "UI:1001"}}
	body := "first fallback line\nsecond fallback line"
	adapter := endpoint.Adapter.(*PlatformAdapterHTTP)
	cursor := adapter.RecentMessagesSince("").Cursor

	replyPersonRawNoCheck(ctx, msg, ctx.wrapForward(body), "")

	got := adapter.RecentMessagesSince(cursor).Messages
	want := HTTPSimpleMessage{UID: "UI:1001", Message: body, MessageType: "private"}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("UI recent messages = %#v, want []HTTPSimpleMessage{%#v}", got, want)
	}
	if !ctx.IsCommandReplied() {
		t.Fatal("forward-only UI fallback was sent but command was not marked replied")
	}
}

type replyPlanForwardAdapter struct {
	*mockPlatformAdapter
	sendAccepted bool
}

func (a *replyPlanForwardAdapter) SendGroupForwardMsg(_ *MsgContext, _ string, _ []message.ForwardNode) bool {
	return a.sendAccepted
}

func (a *replyPlanForwardAdapter) SendPrivateForwardMsg(_ *MsgContext, _ string, _ []message.ForwardNode) bool {
	return a.sendAccepted
}

func TestReplyPersonRawNoCheckUsesForwardSenderAcceptance(t *testing.T) {
	for _, test := range []struct {
		name         string
		sendAccepted bool
	}{
		{name: "accepted", sendAccepted: true},
		{name: "rejected", sendAccepted: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			adapter := &replyPlanForwardAdapter{
				mockPlatformAdapter: newMockPlatformAdapter(),
				sendAccepted:        test.sendAccepted,
			}
			endpoint := &EndPointInfo{
				EndPointInfoBase: EndPointInfoBase{UserID: "TEST:1000", Nickname: "Bot", Platform: "TEST"},
				Adapter:          adapter,
			}
			ctx := &MsgContext{EndPoint: endpoint}
			msg := &Message{MessageType: "private", Sender: SenderBase{UserID: "TEST:1001"}}

			replyPersonRawNoCheck(ctx, msg, ctx.wrapForward("forward body"), "")

			if got := ctx.IsCommandReplied(); got != test.sendAccepted {
				t.Fatalf("CommandReplied = %t, want %t", got, test.sendAccepted)
			}
		})
	}
}
