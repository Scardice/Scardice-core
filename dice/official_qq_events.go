package dice

import (
	"errors"
	"strconv"

	"github.com/sealdice/botgo/dto"
	qqevent "github.com/sealdice/botgo/event"
	qqws "github.com/sealdice/botgo/websocket"
)

const officialQQGroupMembersIntent dto.Intent = 1 << 24

var ErrOfficialQQEventQueueClosed = errors.New("official QQ event queue is closed")

type officialQQGroupMemberEvent struct {
	Type           string
	GroupOpenID    string
	MemberOpenID   string
	OperatorOpenID string
	Timestamp      int64
}

func (pa *PlatformAdapterOfficialQQ) registerOfficialQQHandlers() dto.Intent {
	var channelAtMessage qqevent.ATMessageEventHandler = pa.ChannelAtMessageReceive
	var guildDirectMessage qqevent.DirectMessageEventHandler = pa.GuildDirectMessageReceive
	var groupAtMessage qqevent.GroupATMessageEventHandler = pa.GroupAtMessageReceive
	if pa.OnlyQQGuild {
		return qqws.RegisterHandlers(channelAtMessage, guildDirectMessage)
	}
	var groupMemberAdd qqevent.GroupMemberAddEventHandler = pa.officialQQGroupMemberAddReceive
	var groupMemberRemove qqevent.GroupMemberRemoveEventHandler = pa.officialQQGroupMemberRemoveReceive
	return qqws.RegisterHandlers(channelAtMessage, guildDirectMessage, groupAtMessage, groupMemberAdd, groupMemberRemove)
}

func (pa *PlatformAdapterOfficialQQ) officialQQGroupMemberAddReceive(_ *dto.WSPayload, data *dto.WSGroupMemberAddData) error {
	return pa.enqueueOfficialQQGroupMemberEvent("GROUP_MEMBER_ADD", data.GroupOpenID, data.MemberOpenID, data.OpMemberOpenID, data.Timestamp)
}

func (pa *PlatformAdapterOfficialQQ) officialQQGroupMemberRemoveReceive(_ *dto.WSPayload, data *dto.WSGroupMemberRemoveData) error {
	return pa.enqueueOfficialQQGroupMemberEvent("GROUP_MEMBER_REMOVE", data.GroupOpenID, data.MemberOpenID, data.OpMemberOpenID, data.Timestamp)
}

func (pa *PlatformAdapterOfficialQQ) enqueueOfficialQQGroupMemberEvent(eventType, groupOpenID, memberOpenID, operatorOpenID string, timestamp int64) error {
	memberEvent := officialQQGroupMemberEvent{
		Type:           eventType,
		GroupOpenID:    groupOpenID,
		MemberOpenID:   memberOpenID,
		OperatorOpenID: operatorOpenID,
		Timestamp:      timestamp,
	}
	if !pa.enqueueOfficialQQEvent(func() { pa.dispatchOfficialQQGroupMemberEvent(memberEvent) }) {
		return ErrOfficialQQEventQueueClosed
	}
	return nil
}

func (pa *PlatformAdapterOfficialQQ) dispatchOfficialQQGroupMemberEvent(memberEvent officialQQGroupMemberEvent) {
	if pa.memberEventSink != nil {
		pa.memberEventSink(memberEvent)
		return
	}
	if memberEvent.Type != "GROUP_MEMBER_ADD" || pa.EndPoint == nil || pa.EndPoint.Session == nil {
		return
	}
	account := strconv.FormatUint(pa.AppID, 10)
	message := &Message{
		Time:        memberEvent.Timestamp,
		MessageType: "group",
		Platform:    "OpenQQ",
		GroupID:     formatDiceIDOfficialQQGroupOpenID(account, memberEvent.GroupOpenID),
		Sender: SenderBase{
			UserID: formatDiceIDOfficialQQMemberOpenID(account, memberEvent.GroupOpenID, memberEvent.MemberOpenID),
		},
	}
	ctx := &MsgContext{MessageType: "group", EndPoint: pa.EndPoint, Session: pa.EndPoint.Session, Dice: pa.EndPoint.Session.Parent}
	pa.EndPoint.Session.OnGroupMemberJoined(ctx, message)
}
