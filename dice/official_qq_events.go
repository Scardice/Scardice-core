package dice

import (
	"encoding/json"
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
	var plain qqevent.PlainEventHandler = pa.officialQQPlainEventReceive
	if pa.OnlyQQGuild {
		return qqws.RegisterHandlers(channelAtMessage, guildDirectMessage, plain)
	}
	return qqws.RegisterHandlers(channelAtMessage, guildDirectMessage, groupAtMessage, plain) |
		officialQQGroupMembersIntent
}

func (pa *PlatformAdapterOfficialQQ) officialQQPlainEventReceive(payload *dto.WSPayload, raw []byte) error {
	if payload == nil || (payload.Type != "GROUP_MEMBER_ADD" && payload.Type != "GROUP_MEMBER_REMOVE") {
		return nil
	}
	var envelope struct {
		Data struct {
			GroupOpenID    string `json:"group_openid"`
			MemberOpenID   string `json:"member_openid"`
			OperatorOpenID string `json:"op_member_openid"`
			Timestamp      int64  `json:"timestamp"`
		} `json:"d"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return err
	}
	memberEvent := officialQQGroupMemberEvent{
		Type:           string(payload.Type),
		GroupOpenID:    envelope.Data.GroupOpenID,
		MemberOpenID:   envelope.Data.MemberOpenID,
		OperatorOpenID: envelope.Data.OperatorOpenID,
		Timestamp:      envelope.Data.Timestamp,
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
