package dice

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"Scardice-core/adapterapi"
	"Scardice-core/message"
)

func durableForwardPayloadNodes(nodes []message.ForwardNode) []adapterapi.ForwardMessageNode {
	payloadNodes := make([]adapterapi.ForwardMessageNode, 0, len(nodes))
	for _, node := range nodes {
		content := message.ConvertMessageElementsToString(node.Elements)
		if strings.TrimSpace(content) == "" {
			continue
		}
		payloadNodes = append(payloadNodes, adapterapi.ForwardMessageNode{
			SenderID:   adapterapi.PrincipalID(strings.TrimSpace(node.SenderID)),
			SenderName: node.SenderName,
			Content:    content,
		})
	}
	return payloadNodes
}

func onebotForwardRequestJSON(payload adapterapi.EffectPayload) ([]byte, error) {
	request, err := buildOnebotForwardRequestJSON(payload)
	if err != nil {
		return nil, err
	}
	if err := validateOnebotForwardRequestSize(request); err != nil {
		return nil, err
	}
	return request, nil
}

// RawJSON replaces the null echo with a UUID before dispatch. The placeholder
// has the same encoded size, so admission applies the exact protocol bound.
func validateOnebotForwardRequestSize(request []byte) error {
	const echoPlaceholderJSON = `"00000000-0000-0000-0000-000000000000"`
	const echoNullJSON = "null"
	const echoSizeDelta = len(echoPlaceholderJSON) - len(echoNullJSON)
	if len(request) > adapterapi.MaxProtocolJSONBytes-echoSizeDelta {
		return fmt.Errorf("%w: OneBot forward request exceeds protocol JSON bounds", adapterapi.ErrInvalidContract)
	}
	return nil
}

func buildOnebotForwardRequestJSON(payload adapterapi.EffectPayload) ([]byte, error) {
	if err := payload.Validate(); err != nil {
		return nil, err
	}
	group := payload.Target.Kind == adapterapi.TargetGroup
	targetID, err := onebotTargetID(payload.Target, group)
	if err != nil {
		return nil, errors.New("onebot: invalid forward target")
	}
	wireNodes := make([]gocqForwardNode, 0, len(payload.ForwardNodes))
	for _, node := range payload.ForwardNodes {
		userID, err := strconv.ParseInt(string(node.SenderID), 10, 64)
		if err != nil || userID <= 0 {
			return nil, errors.New("onebot: invalid forward sender")
		}
		content := OneBot11CqMessageToArrayMessage(node.Content)
		if len(content) == 0 {
			return nil, errors.New("onebot: empty forward content")
		}
		id := strconv.FormatInt(userID, 10)
		wireNode := gocqForwardNode{Type: "node"}
		wireNode.Data.UserID = id
		wireNode.Data.Nickname = node.SenderName
		wireNode.Data.Uin = id
		wireNode.Data.Name = node.SenderName
		wireNode.Data.Content = content
		wireNodes = append(wireNodes, wireNode)
	}

	if group {
		type params struct {
			GroupID  int64             `json:"group_id"`
			Messages []gocqForwardNode `json:"messages"`
		}
		return json.Marshal(oneBotCommand{
			Action: "send_group_forward_msg",
			Params: params{GroupID: targetID, Messages: wireNodes},
		})
	}
	type params struct {
		UserID   int64             `json:"user_id"`
		Messages []gocqForwardNode `json:"messages"`
	}
	return json.Marshal(oneBotCommand{
		Action: "send_private_forward_msg",
		Params: params{UserID: targetID, Messages: wireNodes},
	})
}
