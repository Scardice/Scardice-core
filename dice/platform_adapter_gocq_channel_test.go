package dice

import "testing"

func TestQQChannelRecallSkipsLogDeletionWithoutDatabaseOperator(t *testing.T) {
	for _, test := range []struct {
		name string
		dice *Dice
	}{
		{name: "nil database operator", dice: &Dice{}},
		{name: "nil dice owner"},
	} {
		t.Run(test.name, func(t *testing.T) {
			const groupID = "QQ-CH-Group:guild-1-channel-2"
			group := &GroupInfo{GroupID: groupID}
			group.SetLogState(1, "recall-fixture", true)

			session := &IMSession{Parent: test.dice, ServiceAtNew: new(SyncMap[string, *GroupInfo])}
			session.ServiceAtNew.Store(groupID, group)
			endpoint := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{Platform: "QQ-CH"}}
			endpoint.Session = session
			adapter := &PlatformAdapterGocq{EndPoint: endpoint}

			if test.dice != nil && test.dice.DBOperator != nil {
				t.Fatal("test requires a nil database operator")
			}
			adapter.QQChannelTrySolve(`{"message_type":"guild","sub_type":"channel","guild_id":"guild-1","channel_id":"channel-2","message_id":"raw-recall-id","post_type":"notice","notice_type":"guild_channel_recall"}`)

			if state := group.GetLogState(); !state.On || state.Name != "recall-fixture" || state.ID != 1 {
				t.Fatalf("recall changed enabled log state: %#v", state)
			}
		})
	}
}
