package dice

import (
	"context"
	"testing"

	"Scardice-core/eventstore"
)

const channelRecallFixture = `{"message_type":"guild","sub_type":"channel","guild_id":"guild-1","channel_id":"channel-2","message_id":"raw-recall-id","post_type":"notice","notice_type":"guild_channel_recall"}`

func TestQQChannelRecallSkipsLogDeletionWithoutDatabaseOperator(t *testing.T) {
	d, store := newCanonicalTestDice(t)
	d.DBOperator = nil
	endpoint := newCanonicalTestEndpoint(d, "QQ-CH:fixture-bot")
	endpoint.Platform = "QQ-CH"
	endpoint.Session = d.ImSession
	adapter := &PlatformAdapterGocq{EndPoint: endpoint}
	const groupID = "QQ-CH-Group:guild-1-channel-2"
	message := newGroupMsg(groupID, "QQ-CH:fixture-user", "")
	message.Platform = "QQ-CH"

	withCanonicalTestMessageContext(t, d, endpoint, message, "seed-channel-recall-group", func(*MsgContext) error {
		return nil
	})
	session, err := store.CreateStoryLog(context.Background(), d.BaseConfig.Name, groupID, "recall-fixture")
	if err != nil {
		t.Fatalf("create recall fixture log: %v", err)
	}
	if err = store.SetStoryLogState(context.Background(), eventstore.StoryLogState{
		DiceID: d.BaseConfig.Name, GroupID: groupID,
		SessionID: session.ID, Name: session.Name, On: true,
	}); err != nil {
		t.Fatalf("enable recall fixture log: %v", err)
	}

	adapter.QQChannelTrySolve(channelRecallFixture)

	ctx := newCanonicalTestMessageContext(t, d, endpoint, message, "read-channel-recall")
	state, err := ctx.Group.GetLogState()
	if err != nil {
		t.Fatalf("read recall log state: %v", err)
	}
	if !state.On || state.Name != "recall-fixture" || state.ID != session.ID {
		t.Fatalf("recall changed enabled runtime log state: %#v", state)
	}
}

func TestQQChannelRecallReturnsSafelyWithoutDiceOwner(t *testing.T) {
	session := &IMSession{}
	endpoint := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{Platform: "QQ-CH"}}
	endpoint.Session = session
	adapter := &PlatformAdapterGocq{EndPoint: endpoint}
	adapter.QQChannelTrySolve(channelRecallFixture)
	if endpoint.Session != session {
		t.Fatal("ownerless recall unexpectedly replaced the endpoint session")
	}
}
