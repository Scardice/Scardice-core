package dice

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	milky "github.com/Szzrain/Milky-go-sdk"
	"go.uber.org/zap"

	"Scardice-core/logger"
	"Scardice-core/message"
)

var _ forwardMsgSender = (*PlatformAdapterMilky)(nil)

type milkyOutgoingForwardedMessage struct {
	UserID     int64                   `json:"user_id"`
	SenderName string                  `json:"sender_name"`
	Segments   []milky.IMessageElement `json:"segments"`
}

type milkyForwardElement struct {
	Messages []milkyOutgoingForwardedMessage
}

type milkyForwardDelivery struct {
	MessageType string
	TargetID    string
	Nodes       []forwardNode
	MessageSeq  int64
}

func (element *milkyForwardElement) Type() milky.MessageElementType {
	return milky.Forward
}

func (element *milkyForwardElement) MarshalJSON() ([]byte, error) {
	payload := struct {
		Type milky.MessageElementType `json:"type"`
		Data struct {
			Messages []milkyOutgoingForwardedMessage `json:"messages"`
		} `json:"data"`
	}{
		Type: element.Type(),
	}
	payload.Data.Messages = element.Messages

	data, err := json.Marshal(&payload)
	if err != nil {
		return nil, fmt.Errorf("marshal Milky forward element: %w", err)
	}
	return data, nil
}

func buildMilkyForwardElement(nodes []forwardNode) (*milkyForwardElement, error) {
	if len(nodes) == 0 {
		return nil, errors.New("forward message has no nodes")
	}

	messages := make([]milkyOutgoingForwardedMessage, 0, len(nodes))
	for index, node := range nodes {
		userID, err := strconv.ParseInt(strings.TrimSpace(node.Data.Uin), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("forward node %d has invalid user ID %q: %w", index, node.Data.Uin, err)
		}
		if userID <= 0 {
			return nil, fmt.Errorf("forward node %d has invalid user ID %q", index, node.Data.Uin)
		}
		if strings.TrimSpace(node.Data.Content) == "" {
			return nil, fmt.Errorf("forward node %d has empty content", index)
		}

		segments := ParseMessageToMilky(message.ConvertStringMessage(node.Data.Content))
		if len(segments) == 0 {
			return nil, fmt.Errorf("forward node %d has no supported message segments", index)
		}
		messages = append(messages, milkyOutgoingForwardedMessage{
			UserID:     userID,
			SenderName: node.Data.Name,
			Segments:   segments,
		})
	}

	return &milkyForwardElement{Messages: messages}, nil
}

func (pa *PlatformAdapterMilky) recordForwardMessageSent(ctx *MsgContext, delivery milkyForwardDelivery) {
	if ctx == nil || pa == nil || pa.EndPoint == nil || pa.EndPoint.Session == nil {
		return
	}

	msg := &Message{
		Platform:    "QQ",
		MessageType: delivery.MessageType,
		Message:     forwardNodesToText(delivery.Nodes),
		Sender: SenderBase{
			UserID:   pa.EndPoint.UserID,
			Nickname: pa.EndPoint.Nickname,
		},
		RawID: delivery.MessageSeq,
	}
	if delivery.MessageType == "group" {
		msg.GroupID = delivery.TargetID
	}
	pa.EndPoint.Session.OnMessageSend(ctx, msg, "")
}

func (pa *PlatformAdapterMilky) SendGroupForwardMsg(ctx *MsgContext, groupID string, nodes []forwardNode) bool {
	log := zap.S().Named(logger.LogKeyAdapter)
	if pa == nil || pa.IntentSession == nil {
		log.Error("Failed to send Milky group forward message: session unavailable")
		return false
	}

	id, err := strconv.ParseInt(strings.TrimSpace(ExtractQQGroupID(groupID)), 10, 64)
	if err != nil || id <= 0 {
		log.Errorf("Invalid group ID %s for Milky forward message", groupID)
		return false
	}
	forward, err := buildMilkyForwardElement(nodes)
	if err != nil {
		log.Errorf("Failed to build Milky group forward message: %v", err)
		return false
	}

	if ctx != nil && ctx.EndPoint != nil && ctx.EndPoint.Platform == "QQ" {
		doSleepQQ(ctx)
	}
	elements := []milky.IMessageElement{forward}
	ret, err := pa.IntentSession.SendGroupMessage(id, &elements)
	if err != nil {
		log.Errorf("Failed to send group forward message to %s: %v", groupID, err)
		return false
	}

	pa.recordForwardMessageSent(ctx, milkyForwardDelivery{
		MessageType: "group",
		TargetID:    groupID,
		Nodes:       nodes,
		MessageSeq:  ret.MessageSeq,
	})
	return true
}

func (pa *PlatformAdapterMilky) SendPrivateForwardMsg(ctx *MsgContext, userID string, nodes []forwardNode) bool {
	log := zap.S().Named(logger.LogKeyAdapter)
	if pa == nil || pa.IntentSession == nil {
		log.Error("Failed to send Milky private forward message: session unavailable")
		return false
	}

	id, err := strconv.ParseInt(strings.TrimSpace(ExtractQQUserID(userID)), 10, 64)
	if err != nil || id <= 0 {
		log.Errorf("Invalid user ID %s for Milky forward message", userID)
		return false
	}
	forward, err := buildMilkyForwardElement(nodes)
	if err != nil {
		log.Errorf("Failed to build Milky private forward message: %v", err)
		return false
	}

	if ctx != nil && ctx.EndPoint != nil && ctx.EndPoint.Platform == "QQ" {
		doSleepQQ(ctx)
	}
	elements := []milky.IMessageElement{forward}
	ret, err := pa.IntentSession.SendPrivateMessage(id, &elements)
	if err != nil {
		log.Errorf("Failed to send private forward message to %s: %v", userID, err)
		return false
	}

	pa.recordForwardMessageSent(ctx, milkyForwardDelivery{
		MessageType: "private",
		TargetID:    userID,
		Nodes:       nodes,
		MessageSeq:  ret.MessageSeq,
	})
	return true
}
