package dice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"Scardice-core/adapterapi"
)

const (
	onebotAdapterEventProtocol = "onebot11"
	maxOnebotGlobalEventQueue  = 32
)

// handleProtocolInbound preserves the exact protocol event while retaining the
// existing normalized handlers for facts Core already understands. A known but
// malformed event is never downgraded to an opaque event.
func (r *onebotRuntime) handleProtocolInbound(ctx context.Context, raw []byte) error {
	if len(raw) > maxOnebotInboundBytes || len(raw) > adapterapi.MaxProtocolJSONBytes {
		r.inboundRejected.Add(1)
		return ErrOnebotInboundPayloadTooLarge
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' || !utf8.Valid(raw) {
		return fmt.Errorf("%w: malformed JSON inbound payload", ErrOnebotUnsupportedInboundEvent)
	}
	var envelope onebotInboundEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return fmt.Errorf("%w: malformed JSON inbound payload", ErrOnebotUnsupportedInboundEvent)
	}
	if _, err := adapterapi.NewProviderEventID(envelope.PostType); err != nil {
		return fmt.Errorf("%w: invalid protocol event envelope", ErrOnebotUnsupportedInboundEvent)
	}
	event := adapterapi.AdapterEvent{Protocol: onebotAdapterEventProtocol, Type: envelope.PostType, RawJSON: string(raw)}

	message := newOnebotInbound(&envelope)
	switch envelope.PostType {
	case "message":
		if err := fillOnebotMessage(&message, &envelope); err != nil {
			return err
		}
	case "notice":
		if envelope.NoticeType == "group_recall" {
			if err := fillOnebotRecall(&message, &envelope); err != nil {
				return err
			}
			break
		}
		if !onebotEventHasNormalizedHandler(&envelope) {
			return r.deliverOpaqueOnebotEvent(ctx, raw, event, &envelope, true)
		}
		deliver, err := r.fillOnebotEvent(&message, &envelope)
		if err != nil {
			return err
		}
		if !deliver {
			return r.deliverOpaqueOnebotEvent(ctx, raw, event, &envelope, false)
		}
	case "request":
		if !onebotEventHasNormalizedHandler(&envelope) {
			return r.deliverOpaqueOnebotEvent(ctx, raw, event, &envelope, true)
		}
		deliver, err := r.fillOnebotEvent(&message, &envelope)
		if err != nil {
			return err
		}
		if !deliver {
			return r.deliverOpaqueOnebotEvent(ctx, raw, event, &envelope, false)
		}
	default:
		return r.deliverOpaqueOnebotEvent(ctx, raw, event, &envelope, true)
	}

	eventCopy := event
	message.AdapterEvent = &eventCopy
	r.enrichOnebotEvent(ctx, &message)
	return r.deliverOnebotInbound(ctx, message)
}

func onebotEventHasNormalizedHandler(event *onebotInboundEnvelope) bool {
	if event == nil {
		return false
	}
	switch event.PostType {
	case "notice":
		switch event.NoticeType {
		case "group_increase", "group_decrease", "group_dismiss", "group_ban", "friend_add":
			return true
		case "notify":
			return event.SubType == "poke"
		}
	case "request":
		return event.RequestType == "friend" || event.RequestType == "group"
	}
	return false
}

func fillOnebotRecall(message *adapterapi.InboundMessage, envelope *onebotInboundEnvelope) error {
	groupID, hasGroupID := onebotInboundID(envelope.GroupID)
	messageID, hasMessageID := onebotInboundID(envelope.MessageID)
	if !hasGroupID || !hasMessageID {
		return fmt.Errorf("%w: incomplete group_recall identity", ErrOnebotUnsupportedInboundEvent)
	}
	messageIDValue, err := adapterapi.NewMessageID(messageID)
	if err != nil {
		return fmt.Errorf("%w: invalid group_recall message_id", ErrOnebotUnsupportedInboundEvent)
	}
	providerEventID, err := adapterapi.NewProviderEventID("onebot-group-recall-" + messageID)
	if err != nil {
		return fmt.Errorf("%w: invalid group_recall message_id", ErrOnebotUnsupportedInboundEvent)
	}
	conversation, err := adapterapi.NewConversationID("QQ-Group:" + groupID)
	if err != nil {
		return fmt.Errorf("%w: invalid group_recall group_id", ErrOnebotUnsupportedInboundEvent)
	}
	message.Kind = adapterapi.InboundKindMessageDeleted
	message.MessageID = messageIDValue
	message.ProviderEventID = providerEventID
	message.ConversationKind = adapterapi.ConversationKindGroup
	message.Conversation = conversation
	if id, ok := onebotInboundID(envelope.UserID); ok {
		sender, err := adapterapi.NewPrincipalID("QQ:" + id)
		if err != nil {
			return fmt.Errorf("%w: invalid group_recall user_id", ErrOnebotUnsupportedInboundEvent)
		}
		message.Sender = sender
	} else if onebotRawFieldPresent(envelope.UserID) {
		return fmt.Errorf("%w: invalid group_recall user_id", ErrOnebotUnsupportedInboundEvent)
	}
	return nil
}

func (r *onebotRuntime) deliverOpaqueOnebotEvent(
	ctx context.Context,
	raw []byte,
	event adapterapi.AdapterEvent,
	envelope *onebotInboundEnvelope,
	allowGlobal bool,
) error {
	message, scoped, err := opaqueOnebotInbound(raw, event, envelope)
	if err != nil {
		if !allowGlobal {
			// Events which the normalized handler deliberately ignored keep
			// their historical non-failing behavior when no safe scope can be
			// recovered from the provider payload.
			return nil
		}
		return err
	}
	if scoped {
		return r.deliverOnebotInbound(ctx, message)
	}
	if !allowGlobal {
		return nil
	}
	return r.deliverGlobalOnebotEvent(ctx, event)
}

func opaqueOnebotInbound(raw []byte, event adapterapi.AdapterEvent, envelope *onebotInboundEnvelope) (adapterapi.InboundMessage, bool, error) {
	message := newOnebotInbound(envelope)
	message.Kind = adapterapi.InboundKindAdapterEvent
	eventCopy := event
	message.AdapterEvent = &eventCopy

	user, err := onebotEventPrincipal(envelope.UserID, "user_id")
	if err != nil {
		return adapterapi.InboundMessage{}, false, err
	}
	message.Sender = user

	guildPresent := onebotRawFieldPresent(envelope.GuildID)
	channelPresent := onebotRawFieldPresent(envelope.ChannelID)
	groupPresent := onebotRawFieldPresent(envelope.GroupID)
	switch {
	case guildPresent || channelPresent:
		guildID, hasGuildID := onebotInboundID(envelope.GuildID)
		channelID, hasChannelID := onebotInboundID(envelope.ChannelID)
		if !hasGuildID || !hasChannelID {
			return adapterapi.InboundMessage{}, false, onebotEventRejected("incomplete guild conversation")
		}
		conversation, err := adapterapi.NewConversationID(fmt.Sprintf("QQ-CH-Group:%s-%s", guildID, channelID))
		if err != nil {
			return adapterapi.InboundMessage{}, false, onebotEventRejected("invalid guild conversation")
		}
		message.ConversationKind, message.Conversation = adapterapi.ConversationKindGroup, conversation
	case groupPresent:
		groupID, ok := onebotInboundID(envelope.GroupID)
		if !ok {
			return adapterapi.InboundMessage{}, false, onebotEventRejected("invalid group_id")
		}
		conversation, err := adapterapi.NewConversationID("QQ-Group:" + groupID)
		if err != nil {
			return adapterapi.InboundMessage{}, false, onebotEventRejected("invalid group_id")
		}
		message.ConversationKind, message.Conversation = adapterapi.ConversationKindGroup, conversation
	case user != "" && envelope.PostType != "meta_event" && !onebotEventRequiresGroup(envelope):
		conversation, err := adapterapi.NewConversationID(string(user))
		if err != nil {
			return adapterapi.InboundMessage{}, false, onebotEventRejected("invalid user_id")
		}
		message.ConversationKind, message.Conversation = adapterapi.ConversationKindDirect, conversation
	default:
		return adapterapi.InboundMessage{}, false, nil
	}

	digest := sha256.Sum256(raw)
	providerEventID, err := adapterapi.NewProviderEventID("onebot-adapter-" + hex.EncodeToString(digest[:]))
	if err != nil {
		return adapterapi.InboundMessage{}, false, onebotEventRejected("event identity is invalid")
	}
	message.ProviderEventID = providerEventID
	return message, true, nil
}

func onebotEventRequiresGroup(event *onebotInboundEnvelope) bool {
	if event == nil {
		return false
	}
	return event.MessageType == "group" || event.MessageType == "guild" ||
		strings.HasPrefix(event.NoticeType, "group_") || event.RequestType == "group"
}

func onebotRawFieldPresent(raw json.RawMessage) bool {
	return len(raw) != 0 && !bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func (r *onebotRuntime) deliverOnebotInbound(ctx context.Context, message adapterapi.InboundMessage) error {
	if err := sealOnebotInbound(&message); err != nil {
		return err
	}
	r.mu.Lock()
	core := r.core
	r.mu.Unlock()
	if core == nil {
		return nil
	}
	receipt, err := core.HandleInbound(ctx, message)
	if err != nil {
		return err
	}
	return receipt.Validate()
}

func (r *onebotRuntime) startGlobalOnebotEventDelivery(ctx context.Context, core adapterapi.CorePort) {
	if r == nil || core == nil {
		return
	}
	port, ok := core.(adapterapi.AdapterEventCorePort)
	if !ok || port == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	r.globalEventMu.Lock()
	if r.globalEventEvents != nil || r.fenced.Load() || ctx.Err() != nil {
		r.globalEventMu.Unlock()
		return
	}
	laneCtx, cancel := context.WithCancel(ctx)
	if laneCtx.Err() != nil {
		r.globalEventMu.Unlock()
		cancel()
		return
	}
	events := make(chan adapterapi.AdapterEvent, maxOnebotGlobalEventQueue)
	r.globalEventCtx = laneCtx
	r.globalEventCancel = cancel
	r.globalEventEvents = events
	r.globalEventWG.Add(1)
	r.globalEventMu.Unlock()

	go r.runGlobalOnebotEventDelivery(laneCtx, cancel, events, port)
}

func (r *onebotRuntime) runGlobalOnebotEventDelivery(
	ctx context.Context,
	cancel context.CancelFunc,
	events chan adapterapi.AdapterEvent,
	port adapterapi.AdapterEventCorePort,
) {
	defer r.globalEventWG.Done()
	defer cancel()
	defer func() {
		r.globalEventMu.Lock()
		if r.globalEventEvents == events {
			r.globalEventCtx = nil
			r.globalEventCancel = nil
			r.globalEventEvents = nil
		}
		r.globalEventMu.Unlock()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case event := <-events:
			if ctx.Err() != nil || r.fenced.Load() {
				return
			}
			receipt, err := port.HandleAdapterEvent(ctx, event)
			if err == nil {
				err = receipt.Validate()
			}
			if err != nil {
				if ctx.Err() != nil || r.fenced.Load() {
					return
				}
				r.globalEventFailed.Add(1)
				onebotRuntimeLogger().Errorf("OneBot global adapter event callback failed: %v", err)
				continue
			}
			switch receipt.Outcome {
			case adapterapi.IngressAccepted:
				r.globalEventAccepted.Add(1)
			case adapterapi.IngressDuplicate:
				r.globalEventDuplicate.Add(1)
			case adapterapi.IngressRejected:
				r.globalEventRejected.Add(1)
			}
		}
	}
}

func (r *onebotRuntime) stopGlobalOnebotEventDelivery() {
	if r == nil {
		return
	}
	r.globalEventMu.Lock()
	cancel := r.globalEventCancel
	r.globalEventCtx = nil
	r.globalEventCancel = nil
	r.globalEventEvents = nil
	r.globalEventMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (r *onebotRuntime) waitGlobalOnebotEventDelivery() {
	if r != nil {
		r.globalEventWG.Wait()
	}
}

func (r *onebotRuntime) deliverGlobalOnebotEvent(ctx context.Context, event adapterapi.AdapterEvent) error {
	if r == nil {
		return nil
	}
	if ctx != nil && ctx.Err() != nil {
		return nil
	}

	r.globalEventMu.Lock()
	defer r.globalEventMu.Unlock()
	laneCtx, events := r.globalEventCtx, r.globalEventEvents
	if laneCtx == nil || events == nil || laneCtx.Err() != nil || r.fenced.Load() {
		return nil
	}
	if len(events) == cap(events) {
		r.globalEventBackpressure.Add(1)
	} else {
		r.globalEventEnqueued.Add(1)
		events <- event
	}
	// Queue admission is deliberately non-blocking. The single owned worker
	// preserves order, while its eventual Core receipt is accounted separately
	// from queue admission and never retried.
	return nil
}
