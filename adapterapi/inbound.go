package adapterapi

import (
	"fmt"
	"time"
	"unicode/utf8"
)

const (
	MaxInboundTextBytes  = 256 * 1024
	MaxInboundSegments   = 256
	MaxInboundFieldBytes = 4 * 1024
)

// InboundKind is a closed classification of provider facts delivered to Core.
type InboundKind uint8

const (
	InboundKindInvalid InboundKind = iota
	InboundKindMessage
	InboundKindNotice
	InboundKindRequest
	InboundKindReaction
	InboundKindMessageUpdated
	InboundKindMessageDeleted
	InboundKindAdapterEvent
)

func (kind InboundKind) Valid() bool {
	return kind > InboundKindInvalid && kind <= InboundKindAdapterEvent
}

// ConversationKind distinguishes direct and group conversations independently
// from the provider-specific conversation identifier.
type ConversationKind uint8

const (
	ConversationKindInvalid ConversationKind = iota
	ConversationKindDirect
	ConversationKindGroup
)

func (kind ConversationKind) Valid() bool {
	return kind == ConversationKindDirect || kind == ConversationKindGroup
}

// InboundEventKind is the closed vocabulary of typed provider facts carried by
// Notice and Request inbounds. Providers translate their native events into
// these kinds; Core never inspects provider payloads.
type InboundEventKind uint8

const (
	InboundEventNone InboundEventKind = iota
	// InboundEventPoke: Sender poked Subject in the conversation.
	InboundEventPoke
	// InboundEventMemberJoined: Subject joined the group; Operator approved or invited them.
	InboundEventMemberJoined
	// InboundEventSelfJoined: the bot joined the group; Operator invited or approved it.
	InboundEventSelfJoined
	// InboundEventSelfRemoved: the bot was removed from the group by Operator.
	InboundEventSelfRemoved
	// InboundEventSelfLeft: the bot left, or the group was disbanded.
	InboundEventSelfLeft
	// InboundEventSelfMuted: the bot was muted in the group by Operator for DurationSeconds.
	InboundEventSelfMuted
	// InboundEventFriendAdded: Subject became a friend of the bot.
	InboundEventFriendAdded
	// InboundEventFriendRequest: Sender asks to become a friend; Text is the verification comment.
	InboundEventFriendRequest
	// InboundEventGroupInvite: Sender invites the bot into Conversation.
	InboundEventGroupInvite
)

func (kind InboundEventKind) Valid() bool {
	return kind > InboundEventNone && kind <= InboundEventGroupInvite
}

// Request reports whether the event asks Core for an answer.
func (kind InboundEventKind) Request() bool {
	return kind == InboundEventFriendRequest || kind == InboundEventGroupInvite
}

// InboundHistory says how Core treats a message it fetched from the provider's
// history instead of receiving live. Only Core sets it, through the endpoint
// supervisor; a provider's own deliveries are always live.
type InboundHistory uint8

const (
	// InboundHistoryNone is an ordinary live message.
	InboundHistoryNone InboundHistory = iota
	// InboundHistoryExecute is a message missed while offline that is processed
	// like a live one: it is logged and its command runs.
	InboundHistoryExecute
	// InboundHistoryRecordOnly is a message missed while offline that is only
	// recorded in the active log. Nothing reacts to it.
	InboundHistoryRecordOnly
)

func (history InboundHistory) Valid() bool { return history <= InboundHistoryRecordOnly }

// InboundSegment contains bounded, normalized message data. Provider-specific
// payloads remain in the provider runtime and do not cross this seam.
type InboundSegment struct {
	Kind       string `json:"kind"`
	Text       string `json:"text,omitempty"`
	ProviderID string `json:"providerId,omitempty"`
	URL        string `json:"url,omitempty"`
}

// InboundMessage contains provider facts only. It intentionally has no
// endpoint, generation, or desired-version field; Supervisor's CorePort wrapper
// supplies those fences out of band.
type InboundMessage struct {
	ProviderEventID  ProviderEventID  `json:"providerEventId,omitempty"`
	MessageID        MessageID        `json:"messageId,omitempty"`
	Platform         string           `json:"platform,omitempty"`
	Sender           PrincipalID      `json:"sender,omitempty"`
	SenderRole       string           `json:"senderRole,omitempty"`
	Conversation     ConversationID   `json:"conversation,omitempty"`
	ConversationKind ConversationKind `json:"conversationKind"`
	Target           string           `json:"target,omitempty"`
	Kind             InboundKind      `json:"kind"`
	Text             string           `json:"text,omitempty"`
	Segments         []InboundSegment `json:"segments,omitempty"`
	OccurredAt       time.Time        `json:"occurredAt"`
	CausationID      CausationID      `json:"causationId,omitempty"`
	// Sequence is the provider's number for the message within its conversation
	// (OneBot message_seq), zero when the provider has none. It orders a log and
	// reveals messages missed while offline.
	Sequence int64 `json:"sequence,omitempty"`
	// History is set only on messages Core fetched from provider history.
	History InboundHistory `json:"history,omitempty"`
	// Event, Subject, Operator, DurationSeconds and RequestID are set only for
	// Notice and Request inbounds. RequestID is the provider token Core echoes
	// back when it answers a request.
	Event           InboundEventKind `json:"event,omitempty"`
	Subject         PrincipalID      `json:"subject,omitempty"`
	Operator        PrincipalID      `json:"operator,omitempty"`
	DurationSeconds uint32           `json:"durationSeconds,omitempty"`
	RequestID       string           `json:"requestId,omitempty"`
	// RequestPolicy is the endpoint's configured stance on friend requests
	// (accept, ignore, manual, deny). It is set only on friend requests; an
	// empty value means accept. Core owns the decision, the provider only
	// reports what the operator configured.
	RequestPolicy string `json:"requestPolicy,omitempty"`
	// SenderName, SubjectName and ConversationName are display names the
	// provider already knew or looked up when it delivered the event: a member's
	// group card or nickname, and the group's name. They are untrusted display
	// text, never identifiers, and are empty when the provider could not tell.
	SenderName       string `json:"senderName,omitempty"`
	SubjectName      string `json:"subjectName,omitempty"`
	ConversationName string `json:"conversationName,omitempty"`
	// AdapterEvent preserves the exact provider event alongside its normalized
	// fields. It is required for InboundKindAdapterEvent and optional for kinds
	// with an existing Core handler.
	AdapterEvent *AdapterEvent `json:"adapterEvent,omitempty"`
}

// Validate checks size and closed-enum bounds before an ingress is handed to
// Core. The method does not inspect provider payloads beyond bounded fields.
func (message InboundMessage) Validate() error {
	if !validOptionalIdentifier(string(message.ProviderEventID)) || !message.Kind.Valid() || !message.ConversationKind.Valid() {
		return fmt.Errorf("%w: inbound identity, kind, or conversation kind", ErrInvalidContract)
	}
	if !validOptionalIdentifier(message.Platform) ||
		!validOptionalIdentifier(string(message.MessageID)) ||
		!validOptionalIdentifier(string(message.Sender)) ||
		!validOptionalIdentifier(string(message.Conversation)) ||
		!validOptionalIdentifier(message.Target) ||
		!message.CausationID.Valid() {
		return fmt.Errorf("%w: invalid optional inbound identifier", ErrInvalidContract)
	}
	switch message.SenderRole {
	case "", "member", "admin", "owner":
	default:
		return fmt.Errorf("%w: invalid sender role", ErrInvalidContract)
	}
	if len(message.Platform) > MaxInboundFieldBytes || len(message.Target) > MaxInboundFieldBytes {
		return fmt.Errorf("%w: inbound identity exceeds bounds", ErrInvalidContract)
	}
	if !message.OccurredAt.IsZero() {
		if _, err := message.OccurredAt.MarshalJSON(); err != nil {
			return fmt.Errorf("%w: invalid inbound timestamp", ErrInvalidContract)
		}
	}
	if len(message.Text) > MaxInboundTextBytes || len(message.Segments) > MaxInboundSegments {
		return fmt.Errorf("%w: inbound payload exceeds bounds", ErrInvalidContract)
	}
	if message.Sequence < 0 {
		return fmt.Errorf("%w: negative inbound sequence", ErrInvalidContract)
	}
	if !message.History.Valid() {
		return fmt.Errorf("%w: unknown inbound history mode", ErrInvalidContract)
	}
	if message.History != InboundHistoryNone && (message.Kind != InboundKindMessage || message.ConversationKind != ConversationKindGroup) {
		return fmt.Errorf("%w: history applies to group messages only", ErrInvalidContract)
	}
	for _, segment := range message.Segments {
		if len(segment.Kind) == 0 || len(segment.Kind) > MaxInboundFieldBytes ||
			!validOptionalIdentifier(segment.ProviderID) ||
			len(segment.Text) > MaxInboundTextBytes || len(segment.ProviderID) > MaxInboundFieldBytes || len(segment.URL) > MaxInboundFieldBytes {
			return fmt.Errorf("%w: inbound segment exceeds bounds", ErrInvalidContract)
		}
	}
	if message.AdapterEvent != nil {
		if err := message.AdapterEvent.Validate(); err != nil {
			return err
		}
	}
	if message.Kind == InboundKindAdapterEvent {
		if message.AdapterEvent == nil || message.Platform == "" || message.Conversation == "" || message.Target != string(message.Conversation) {
			return fmt.Errorf("%w: adapter event requires a consistent conversation identity", ErrInvalidContract)
		}
	}
	typed := message.Kind == InboundKindNotice || message.Kind == InboundKindRequest
	if typed {
		if !message.Event.Valid() || message.Event.Request() != (message.Kind == InboundKindRequest) {
			return fmt.Errorf("%w: inbound kind does not match its typed event", ErrInvalidContract)
		}
		if message.Kind == InboundKindRequest && message.RequestID == "" {
			return fmt.Errorf("%w: request inbound requires a request id", ErrInvalidContract)
		}
	} else if message.Event != InboundEventNone || message.Subject != "" || message.Operator != "" || message.DurationSeconds != 0 || message.RequestID != "" {
		return fmt.Errorf("%w: typed event fields on a non-event inbound", ErrInvalidContract)
	}
	switch message.RequestPolicy {
	case "":
	case "accept", "ignore", "manual", "deny":
		if message.Event != InboundEventFriendRequest {
			return fmt.Errorf("%w: request policy outside a friend request", ErrInvalidContract)
		}
	default:
		return fmt.Errorf("%w: invalid request policy", ErrInvalidContract)
	}
	if !validOptionalIdentifier(string(message.Subject)) || !validOptionalIdentifier(string(message.Operator)) || !validOptionalIdentifier(message.RequestID) ||
		len(message.RequestID) > MaxInboundFieldBytes {
		return fmt.Errorf("%w: invalid inbound event identifier", ErrInvalidContract)
	}
	for _, name := range []string{message.SenderName, message.SubjectName, message.ConversationName} {
		if len(name) > MaxInboundFieldBytes || !utf8.ValidString(name) {
			return fmt.Errorf("%w: inbound display name", ErrInvalidContract)
		}
	}
	return nil
}

// IngressOutcome is the durable handoff result from CorePort.HandleInbound.
type IngressOutcome uint8

const (
	IngressOutcomeInvalid IngressOutcome = iota
	IngressAccepted
	IngressDuplicate
	IngressRejected
)

func (outcome IngressOutcome) Valid() bool {
	return outcome >= IngressAccepted && outcome <= IngressRejected
}

// IngressReceipt is metadata only; it never contains the inbound body.
type IngressReceipt struct {
	Outcome IngressOutcome `json:"outcome"`
	InboxID string         `json:"inboxId,omitempty"`
}

func (receipt IngressReceipt) Validate() error {
	if !receipt.Outcome.Valid() {
		return fmt.Errorf("%w: ingress outcome", ErrInvalidContract)
	}
	if len(receipt.InboxID) > MaxInboundFieldBytes || !validOptionalIdentifier(receipt.InboxID) {
		return fmt.Errorf("%w: ingress receipt id is invalid or exceeds bounds", ErrInvalidContract)
	}
	return nil
}
