package adapterapi

import (
	"fmt"
	"time"
)

const (
	MaxInboundTextBytes    = 256 * 1024
	MaxInboundSegments     = 256
	MaxInboundFieldBytes   = 4 * 1024
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
)

func (kind InboundKind) Valid() bool { return kind > InboundKindInvalid && kind <= InboundKindMessageDeleted }

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
	ProviderEventID ProviderEventID  `json:"providerEventId,omitempty"`
	MessageID       MessageID        `json:"messageId,omitempty"`
	Platform        string           `json:"platform,omitempty"`
	Sender          PrincipalID      `json:"sender,omitempty"`
	Conversation    ConversationID   `json:"conversation,omitempty"`
	Target          string           `json:"target,omitempty"`
	Kind            InboundKind      `json:"kind"`
	Text            string           `json:"text,omitempty"`
	Segments        []InboundSegment `json:"segments,omitempty"`
	OccurredAt      time.Time        `json:"occurredAt"`
	CausationID     CausationID      `json:"causationId,omitempty"`
}

// Validate checks size and closed-enum bounds before an ingress is handed to
// Core. The method does not inspect provider payloads beyond bounded fields.
func (message InboundMessage) Validate() error {
	if !validOptionalIdentifier(string(message.ProviderEventID)) || !message.Kind.Valid() {
		return fmt.Errorf("%w: inbound identity or kind", ErrInvalidContract)
	}
	if !validOptionalIdentifier(message.Platform) ||
		!validOptionalIdentifier(string(message.MessageID)) ||
		!validOptionalIdentifier(string(message.Sender)) ||
		!validOptionalIdentifier(string(message.Conversation)) ||
		!validOptionalIdentifier(message.Target) ||
		!message.CausationID.Valid() {
		return fmt.Errorf("%w: invalid optional inbound identifier", ErrInvalidContract)
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
	for _, segment := range message.Segments {
		if len(segment.Kind) == 0 || len(segment.Kind) > MaxInboundFieldBytes ||
			!validOptionalIdentifier(segment.ProviderID) ||
			len(segment.Text) > MaxInboundTextBytes || len(segment.ProviderID) > MaxInboundFieldBytes || len(segment.URL) > MaxInboundFieldBytes {
			return fmt.Errorf("%w: inbound segment exceeds bounds", ErrInvalidContract)
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
	InboxID  string        `json:"inboxId,omitempty"`
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
