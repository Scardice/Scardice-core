package dice

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"Scardice-core/adapterapi"
)

// errOnebotSelfUnplaceable marks an own message that cannot be tied to a
// conversation or a message id, so Core cannot record or de-duplicate it.
var errOnebotSelfUnplaceable = errors.New("onebot: own message cannot be placed")

// onebotIsSelfMessage reports whether the event is a message sent by the
// endpoint's own account: the protocol end's message_sent report, or a plain
// message whose sender is the reporting account (self_id).
func onebotIsSelfMessage(envelope *onebotInboundEnvelope) bool {
	switch envelope.PostType {
	case "message_sent":
		return true
	case "message":
		self, hasSelf := onebotInboundID(envelope.SelfID)
		user, hasUser := onebotInboundID(envelope.UserID)
		return hasSelf && hasUser && self != "0" && self == user
	}
	return false
}

// handleSelfMessage delivers the account's own message as an
// InboundKindSelfMessage, so nothing in Core can mistake it for a command.
// Whether Core issued the send is decided here, where every send action passes;
// a report that may still be racing its send's response is held briefly.
func (r *onebotRuntime) handleSelfMessage(ctx context.Context, raw []byte, event adapterapi.AdapterEvent, envelope *onebotInboundEnvelope) error {
	message := newOnebotInbound(envelope)
	key, err := fillOnebotSelfMessage(&message, envelope)
	if errors.Is(err, errOnebotSelfUnplaceable) {
		// Plugins still see the event, scoped to the recipient when it is known
		// and conversation-free otherwise; Core records nothing.
		return r.deliverOpaqueOnebotEvent(ctx, raw, event, envelope, true)
	}
	if err != nil {
		return err
	}
	eventCopy := event
	message.AdapterEvent = &eventCopy
	origin, held := r.sentLedger().classify(ctx, string(message.MessageID), key, message)
	if held {
		return nil
	}
	message.SelfOrigin = origin
	return r.deliverOnebotInbound(ctx, message)
}

// fillOnebotSelfMessage translates an own message into the inbound contract
// and returns the conversation key its send action would have carried. A group
// message is in its group; a private one is in the conversation with its
// recipient (target_id), not with the account itself.
func fillOnebotSelfMessage(message *adapterapi.InboundMessage, envelope *onebotInboundEnvelope) (string, error) {
	if _, ok := onebotInboundID(envelope.MessageID); !ok && envelope.PostType == "message_sent" {
		return "", errOnebotSelfUnplaceable
	}
	if err := fillOnebotMessage(message, envelope); err != nil {
		return "", err
	}
	message.Kind = adapterapi.InboundKindSelfMessage
	providerEventID, err := adapterapi.NewProviderEventID("onebot-self-message-" + string(message.MessageID))
	if err != nil {
		return "", fmt.Errorf("%w: invalid message_id", ErrOnebotUnsupportedInboundEvent)
	}
	message.ProviderEventID = providerEventID
	if message.ConversationKind == adapterapi.ConversationKindDirect {
		peer, err := onebotEventPrincipal(envelope.TargetID, "target_id")
		if err != nil {
			return "", err
		}
		if peer == "" {
			return "", errOnebotSelfUnplaceable
		}
		message.Conversation, err = adapterapi.NewConversationID(string(peer))
		if err != nil || !message.Conversation.Valid() {
			return "", onebotEventRejected("invalid target_id")
		}
	}
	return onebotSelfConversationKey(message.ConversationKind, message.Conversation), nil
}

// onebotSelfConversationKey is onebotConversationKey for a normalized conversation.
func onebotSelfConversationKey(kind adapterapi.ConversationKind, conversation adapterapi.ConversationID) string {
	id := string(conversation)
	switch {
	case kind == adapterapi.ConversationKindDirect:
		return onebotConversationKey("", "", "", strings.TrimPrefix(id, "QQ:"))
	case strings.HasPrefix(id, "QQ-Group:"):
		return onebotConversationKey(strings.TrimPrefix(id, "QQ-Group:"), "", "", "")
	case strings.HasPrefix(id, "QQ-CH-Group:"):
		return "c:" + strings.TrimPrefix(id, "QQ-CH-Group:")
	}
	return ""
}
