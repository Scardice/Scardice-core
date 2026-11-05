package messageflow

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync/atomic"
	"unicode/utf8"

	"Scardice-core/adapterapi"
	"Scardice-core/endpoint"
	"Scardice-core/eventstore"
)

const defaultIngressCapacity = 32

var (
	ErrIngressBackpressure = errors.New("messageflow: inbound admission is full")
	ErrIngressUnavailable  = errors.New("messageflow: inbound service unavailable")
	ErrIngressPayload      = errors.New("messageflow: inbound payload exceeds bound")
)

type IngressCollision struct {
	EndpointID       string
	ProviderEventKey string
}

type IngressOption func(*InboundService)

func WithIngressCapacity(capacity int) IngressOption {
	return func(s *InboundService) {
		if capacity > 0 {
			s.capacity = capacity
		}
	}
}

func WithIngressClock(clock eventstore.Clock) IngressOption {
	return func(s *InboundService) {
		if clock != nil {
			s.clock = clock
		}
	}
}

func WithIngressCollisionObserver(observer func(IngressCollision)) IngressOption {
	return func(s *InboundService) { s.collisionObserver = observer }
}

type InboundService struct {
	repo              eventstore.InboxRepository
	clock             eventstore.Clock
	capacity          int
	admission         chan struct{}
	inFlight          atomic.Int64
	collisions        atomic.Uint64
	collisionObserver func(IngressCollision)
}

func NewInboundService(repo eventstore.InboxRepository, options ...IngressOption) (*InboundService, error) {
	if repo == nil {
		return nil, ErrIngressUnavailable
	}
	s := &InboundService{repo: repo, clock: eventstore.SystemClock{}}
	for _, option := range options {
		if option != nil {
			option(s)
		}
	}
	if s.capacity <= 0 {
		s.capacity = defaultIngressCapacity
	}
	s.admission = make(chan struct{}, s.capacity)
	return s, nil
}
func (s *InboundService) InFlight() int          { return int(s.inFlight.Load()) }
func (s *InboundService) CollisionCount() uint64 { return s.collisions.Load() }

func inboundJSONEscapedLen(value string) int {
	total := 0
	for i := 0; i < len(value); {
		r, size := utf8.DecodeRuneInString(value[i:])
		if r == utf8.RuneError && size == 1 {
			total += 6
			i++
			continue
		}
		switch r {
		case '"', '\\', '\b', '\f', '\n', '\r', '\t':
			total += 2
		case '<', '>', '&', '\u2028', '\u2029':
			total += 6
		default:
			if r < 0x20 {
				total += 6
			} else {
				total += size
			}
		}
		i += size
	}
	return total
}

func inboundJSONUpperBound(message adapterapi.InboundMessage) int {
	total := inboundJSONEscapedLen(string(message.ProviderEventID)) + inboundJSONEscapedLen(string(message.MessageID)) + inboundJSONEscapedLen(message.Platform) +
		inboundJSONEscapedLen(string(message.Sender)) + inboundJSONEscapedLen(message.SenderRole) + inboundJSONEscapedLen(string(message.Conversation)) + inboundJSONEscapedLen(message.Target) +
		inboundJSONEscapedLen(string(message.Kind)) + inboundJSONEscapedLen(message.Text) + inboundJSONEscapedLen(string(message.CausationID)) +
		inboundJSONEscapedLen(string(message.Subject)) + inboundJSONEscapedLen(string(message.Operator)) + inboundJSONEscapedLen(message.RequestID) +
		inboundJSONEscapedLen(message.RequestPolicy) + inboundJSONEscapedLen(message.SenderName) + inboundJSONEscapedLen(message.SubjectName) + inboundJSONEscapedLen(message.ConversationName)
	if message.AdapterEvent != nil {
		total += inboundJSONEscapedLen(message.AdapterEvent.Protocol) + inboundJSONEscapedLen(message.AdapterEvent.Type) + inboundJSONEscapedLen(message.AdapterEvent.RawJSON)
	}
	for _, segment := range message.Segments {
		total += inboundJSONEscapedLen(segment.Kind) + inboundJSONEscapedLen(segment.Text) + inboundJSONEscapedLen(segment.ProviderID) + inboundJSONEscapedLen(segment.URL)
	}
	const fixedJSONOverhead = 512
	const segmentJSONOverhead = 64
	fixed := fixedJSONOverhead + segmentJSONOverhead*len(message.Segments)
	if fixed > eventstore.MaxEventPayloadBytes || total > eventstore.MaxEventPayloadBytes-fixed {
		return eventstore.MaxEventPayloadBytes + 1
	}
	return fixed + total
}

func ingressPayloadJSONUpperBound(endpointID adapterapi.EndpointID, messageBound, contentDigestBytes int) int {
	const fixedJSONOverhead = 512
	const jsonEscapeUpperBound = 6
	const numericAndDigestOverhead = 128
	rawEnvelope := len(endpointID) + len(eventstore.InboxStatusPending)
	envelopeBound := fixedJSONOverhead + numericAndDigestOverhead + rawEnvelope*jsonEscapeUpperBound + contentDigestBytes*2
	if envelopeBound > eventstore.MaxEventPayloadBytes || messageBound > eventstore.MaxEventPayloadBytes-envelopeBound {
		return eventstore.MaxEventPayloadBytes + 1
	}
	return envelopeBound + messageBound
}

// inboundContentDigestJSON excludes the exact provider representation from
// normalized facts while retaining it for opaque adapter events. Every
// normalized field, including Core's history mode, remains part of the digest.
func inboundContentDigestJSON(message adapterapi.InboundMessage) ([]byte, error) {
	projection := message
	if projection.Kind != adapterapi.InboundKindAdapterEvent {
		projection.AdapterEvent = nil
	}
	return json.Marshal(projection)
}

// HandleInbound durably accepts one normalized provider fact. It never invokes
// IMSession, Core, plugins, or callbacks; consumers claim the plaintext inbox
// row in a later workflow.
func (s *InboundService) HandleInbound(ctx context.Context, fenced endpoint.FencedInbound) (adapterapi.IngressReceipt, error) {
	if s == nil || s.repo == nil {
		return adapterapi.IngressReceipt{}, ErrIngressUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := fenced.Message.Validate(); err != nil {
		return adapterapi.IngressReceipt{}, err
	}
	if !fenced.EndpointID.Valid() || fenced.Generation == 0 || fenced.DesiredVersion == 0 {
		return adapterapi.IngressReceipt{}, fmt.Errorf("%w: invalid fence", adapterapi.ErrInvalidContract)
	}
	select {
	case s.admission <- struct{}{}:
		s.inFlight.Add(1)
		defer func() { <-s.admission; s.inFlight.Add(-1) }()
	default:
		return adapterapi.IngressReceipt{}, ErrIngressBackpressure
	}

	message := fenced.Message
	if inboundJSONUpperBound(message) > eventstore.MaxEventPayloadBytes {
		return adapterapi.IngressReceipt{}, ErrIngressPayload
	}
	contentBytes, err := inboundContentDigestJSON(message)
	if err != nil {
		return adapterapi.IngressReceipt{}, err
	}
	if len(contentBytes) > adapterapi.MaxInboundTextBytes+adapterapi.MaxInboundSegments*adapterapi.MaxInboundFieldBytes {
		return adapterapi.IngressReceipt{}, ErrIngressPayload
	}
	contentDigest := eventstore.Digest("content-digest/v1", string(contentBytes))
	conversation := string(message.Conversation)
	if conversation == "" {
		conversation = message.Target
	}
	// Recovered messages that are only recorded can be hundreds; behind the
	// group's live lane they would hold its live messages back, so they queue
	// in a lane of their own. The conversation, and with it the privacy subject
	// below, is the same.
	conversationKind := "person"
	if message.ConversationKind == adapterapi.ConversationKindGroup {
		conversationKind = "group"
	}
	laneKind := "live"
	if message.History == adapterapi.InboundHistoryRecordOnly {
		laneKind = "recorded-history"
	}
	lane, err := json.Marshal([4]string{string(fenced.EndpointID), conversationKind, conversation, laneKind})
	if err != nil {
		return adapterapi.IngressReceipt{}, err
	}
	subject := conversation
	providerKey := ingressProviderKey(fenced.EndpointID, message, contentDigest)
	inboxDigest := eventstore.Digest("inbox-id/v1", string(fenced.EndpointID), providerKey)
	inboxID := "inbox-" + hex.EncodeToString(inboxDigest)
	payload := ingressPayload{EndpointID: fenced.EndpointID, Generation: fenced.Generation, DesiredVersion: fenced.DesiredVersion, Message: message, ContentDigest: contentDigest, Status: eventstore.InboxStatusPending}
	if ingressPayloadJSONUpperBound(fenced.EndpointID, inboundJSONUpperBound(message), len(contentDigest)) > eventstore.MaxEventPayloadBytes {
		return adapterapi.IngressReceipt{}, ErrIngressPayload
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return adapterapi.IngressReceipt{}, err
	}
	if len(plaintext) > eventstore.MaxEventPayloadBytes {
		return adapterapi.IngressReceipt{}, ErrIngressPayload
	}
	result, err := s.repo.AcceptInbox(ctx, eventstore.InboxUpdate{
		InboxID: inboxID, EndpointID: string(fenced.EndpointID), ProviderEventKey: providerKey,
		Lane: string(lane), Subject: subject, Status: eventstore.InboxStatusPending,
		Payload: plaintext, ContentDigest: contentDigest,
	})
	if err != nil {
		if errors.Is(err, eventstore.ErrConflict) {
			s.recordCollision(IngressCollision{EndpointID: string(fenced.EndpointID), ProviderEventKey: providerKey})
		}
		return adapterapi.IngressReceipt{}, err
	}
	if len(result.InboxIDs) == 0 {
		return adapterapi.IngressReceipt{}, eventstore.ErrParticipantFailure
	}
	outcome := adapterapi.IngressAccepted
	if result.Deduplicated {
		outcome = adapterapi.IngressDuplicate
	}
	return adapterapi.IngressReceipt{Outcome: outcome, InboxID: result.InboxIDs[0]}, nil
}

type ingressPayload struct {
	EndpointID     adapterapi.EndpointID     `json:"endpointId"`
	Generation     uint64                    `json:"generation"`
	DesiredVersion uint64                    `json:"desiredVersion"`
	Message        adapterapi.InboundMessage `json:"message"`
	ContentDigest  []byte                    `json:"contentDigest"`
	Status         string                    `json:"status"`
}

func ingressProviderKey(endpointID adapterapi.EndpointID, message adapterapi.InboundMessage, contentDigest []byte) string {
	if message.ProviderEventID != "" {
		return string(message.ProviderEventID)
	}
	target := message.Target
	if target == "" {
		target = string(message.Conversation)
	}
	occurred := "0"
	if !message.OccurredAt.IsZero() {
		occurred = strconv.FormatInt(message.OccurredAt.UTC().UnixNano(), 10)
	}
	identityParts := []string{string(endpointID), message.Platform, string(message.Sender), target, occurred}
	if message.OccurredAt.IsZero() || message.Kind == adapterapi.InboundKindAdapterEvent {
		identityParts = append(identityParts, hex.EncodeToString(contentDigest))
	}
	identityDigest := eventstore.Digest("fallback-provider-key/v1", canonicalIngressTuple(identityParts...))
	return "fallback:" + hex.EncodeToString(identityDigest)
}

func canonicalIngressTuple(parts ...string) string {
	var encoded bytes.Buffer
	encoded.WriteString("inbound-tuple/v1")
	var length [8]byte
	for _, part := range parts {
		binary.BigEndian.PutUint64(length[:], uint64(len(part)))
		_, _ = encoded.Write(length[:])
		_, _ = encoded.WriteString(part)
	}
	return encoded.String()
}

func (s *InboundService) recordCollision(collision IngressCollision) {
	s.collisions.Add(1)
	if s.collisionObserver != nil {
		s.collisionObserver(collision)
	}
}
