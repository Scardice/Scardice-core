package dice

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/sealdice/botgo/dto"
	qqevent "github.com/sealdice/botgo/event"
	qqws "github.com/sealdice/botgo/websocket"
)

const officialQQGroupMembersIntent dto.Intent = 1 << 24

var ErrOfficialQQEventQueueClosed = errors.New("official QQ event queue is closed")

type officialQQGroupMemberEvent struct {
	Type           string `json:"type"`
	GroupOpenID    string `json:"groupOpenId"`
	MemberOpenID   string `json:"memberOpenId"`
	OperatorOpenID string `json:"operatorOpenId"`
	Timestamp      int64  `json:"timestamp"`
	EventID        string `json:"eventId,omitempty"`
	Sequence       uint32 `json:"sequence,omitempty"`
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

func (pa *PlatformAdapterOfficialQQ) officialQQGroupMemberAddReceive(event *dto.WSPayload, data *dto.WSGroupMemberAddData) error {
	if data == nil {
		return errors.New("official QQ group member add event is nil")
	}
	eventID, sequence := officialQQMemberEventIdentity(event)
	return pa.enqueueOfficialQQGroupMemberEvent("GROUP_MEMBER_ADD", data.GroupOpenID, data.MemberOpenID, data.OpMemberOpenID, data.Timestamp, eventID, sequence)
}

func (pa *PlatformAdapterOfficialQQ) officialQQGroupMemberRemoveReceive(event *dto.WSPayload, data *dto.WSGroupMemberRemoveData) error {
	if data == nil {
		return errors.New("official QQ group member remove event is nil")
	}
	eventID, sequence := officialQQMemberEventIdentity(event)
	return pa.enqueueOfficialQQGroupMemberEvent("GROUP_MEMBER_REMOVE", data.GroupOpenID, data.MemberOpenID, data.OpMemberOpenID, data.Timestamp, eventID, sequence)
}

func officialQQMemberEventIdentity(event *dto.WSPayload) (string, uint32) {
	if event == nil {
		return "", 0
	}
	return event.EventID, event.Seq
}

func (pa *PlatformAdapterOfficialQQ) enqueueOfficialQQGroupMemberEvent(eventType, groupOpenID, memberOpenID, operatorOpenID string, timestamp int64, eventID string, sequence uint32) error {
	memberEvent := officialQQGroupMemberEvent{
		Type:           eventType,
		GroupOpenID:    groupOpenID,
		MemberOpenID:   memberOpenID,
		OperatorOpenID: operatorOpenID,
		Timestamp:      timestamp,
		EventID:        eventID,
		Sequence:       sequence,
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
	if memberEvent.Type != "GROUP_MEMBER_ADD" || pa.EndPoint == nil || pa.EndPoint.Session == nil ||
		pa.EndPoint.Session.Parent == nil {
		return
	}
	endpoint := pa.EndPoint
	session := endpoint.Session
	d := session.Parent
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
	canonical, err := json.Marshal(memberEvent)
	if err != nil {
		if d.Logger != nil {
			d.Logger.Errorf("编码QQ官方成员事件失败: %v", err)
		}
		return
	}
	providerIdentity := memberEvent.EventID
	if providerIdentity == "" {
		digest := sha256.Sum256(canonical)
		providerIdentity = fmt.Sprintf("%d:%x", memberEvent.Sequence, digest)
	}
	invocation := fmt.Sprintf("%s:%s", endpoint.ID, providerIdentity)
	err = d.WithDomainExecution(
		context.Background(),
		d.DomainExecutionIdentity("official-qq-group-member", invocation),
		canonical,
		func(transaction *DurableCallbackTransaction) error {
			carrier := &MsgContext{
				MessageType: "group",
				EndPoint:    endpoint, Session: session, Dice: d,
				callbackTransaction: transaction, callbackMetadata: transaction.metadata,
				executionContext: transaction.executionContext,
			}
			defer carrier.releaseExecutionState()
			session.OnGroupMemberJoined(carrier, message)
			if executionErr := carrier.getExecutionError(); executionErr != nil {
				return executionErr
			}
			if executionErr := carrier.stopJSExecution(); executionErr != nil {
				return executionErr
			}
			return transaction.Domain().Err()
		},
	)
	if err != nil && d.Logger != nil {
		d.Logger.Errorf("处理QQ官方成员事件失败: %v", err)
	}
}
