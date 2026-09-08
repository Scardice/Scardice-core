package messageflow

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"Scardice-core/adapterapi"
	"Scardice-core/endpoint"
	"Scardice-core/eventstore"
)

const IngressPayloadTTL = 7 * 24 * time.Hour
const defaultIngressCapacity = 32

var (
	ErrIngressBackpressure = errors.New("messageflow: inbound admission is full")
	ErrIngressUnavailable  = errors.New("messageflow: inbound service unavailable")
	ErrIngressPayload      = errors.New("messageflow: inbound payload exceeds bound")
)

type IngressSecurity interface {
	EncryptBound(context.Context, string, string, string, uint64, []byte) ([]byte, []byte, string, error)
	KeyedDigest(context.Context, string, ...string) ([]byte, string, error)
}

type IngressCollision struct {
	EndpointID      string
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
	security          IngressSecurity
	clock             eventstore.Clock
	capacity          int
	admission         chan struct{}
	inFlight          atomic.Int64
	collisions        atomic.Uint64
	collisionObserver func(IngressCollision)
}

func NewInboundService(repo eventstore.InboxRepository, security IngressSecurity, options ...IngressOption) (*InboundService, error) {
	if repo == nil || security == nil {
		return nil, ErrIngressUnavailable
	}
	s := &InboundService{repo: repo, security: security, clock: eventstore.SystemClock{}}
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

func (s *InboundService) InFlight() int { return int(s.inFlight.Load()) }
func (s *InboundService) CollisionCount() uint64 { return s.collisions.Load() }

// HandleInbound durably accepts one normalized provider fact. It never invokes
// IMSession, Core, plugins, or callbacks; consumers claim the encrypted inbox

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
		inboundJSONEscapedLen(string(message.Sender)) + inboundJSONEscapedLen(string(message.Conversation)) + inboundJSONEscapedLen(message.Target) +
		inboundJSONEscapedLen(string(message.Kind)) + inboundJSONEscapedLen(message.Text) + inboundJSONEscapedLen(string(message.CausationID))
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

func ingressPayloadJSONUpperBound(endpointID adapterapi.EndpointID, digestKeyID string, messageBound, contentDigestBytes int) int {
	const fixedJSONOverhead = 512
	const jsonEscapeUpperBound = 6
	const numericAndDigestOverhead = 128
	rawEnvelope := len(endpointID) + len(digestKeyID) + len(eventstore.InboxStatusPending)
	envelopeBound := fixedJSONOverhead + numericAndDigestOverhead + rawEnvelope*jsonEscapeUpperBound + contentDigestBytes*2
	if envelopeBound > eventstore.MaxEventPayloadBytes || messageBound > eventstore.MaxEventPayloadBytes-envelopeBound {
		return eventstore.MaxEventPayloadBytes + 1
	}
	return envelopeBound + messageBound
}

// row in a later workflow.
func (s *InboundService) HandleInbound(ctx context.Context, fenced endpoint.FencedInbound) (adapterapi.IngressReceipt, error) {
	if s == nil || s.repo == nil || s.security == nil {
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
	contentBytes, err := json.Marshal(message)
	if err != nil {
		return adapterapi.IngressReceipt{}, err
	}
	if len(contentBytes) > adapterapi.MaxInboundTextBytes+adapterapi.MaxInboundSegments*adapterapi.MaxInboundFieldBytes {
		return adapterapi.IngressReceipt{}, ErrIngressPayload
	}
	contentDigest, digestKeyID, err := s.security.KeyedDigest(ctx, "content-digest/v1", string(contentBytes))
	if err != nil {
		return adapterapi.IngressReceipt{}, err
	}
	conversation := string(message.Conversation)
	if conversation == "" {
		conversation = message.Target
	}
	laneDigest, _, err := s.security.KeyedDigest(ctx, "inbound-lane/v1", canonicalIngressTuple(string(fenced.EndpointID), conversation))
	if err != nil {
		return adapterapi.IngressReceipt{}, err
	}
	providerKey, err := s.providerKey(ctx, fenced.EndpointID, message, contentDigest)
	if err != nil {
		return adapterapi.IngressReceipt{}, err
	}
	inboxDigest, _, err := s.security.KeyedDigest(ctx, "inbox-id/v1", string(fenced.EndpointID), providerKey)
	if err != nil {
		return adapterapi.IngressReceipt{}, err
	}
	inboxID := "inbox-" + hex.EncodeToString(inboxDigest)
	payload := ingressPayload{EndpointID: fenced.EndpointID, Generation: fenced.Generation, DesiredVersion: fenced.DesiredVersion, Message: message, ContentDigest: contentDigest, ContentDigestKeyID: digestKeyID, Status: eventstore.InboxStatusPending}
	if ingressPayloadJSONUpperBound(fenced.EndpointID, digestKeyID, inboundJSONUpperBound(message), len(contentDigest)) > eventstore.MaxEventPayloadBytes {
		return adapterapi.IngressReceipt{}, ErrIngressPayload
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return adapterapi.IngressReceipt{}, err
	}
	if len(plaintext) > eventstore.MaxEventPayloadBytes {
		return adapterapi.IngressReceipt{}, ErrIngressPayload
	}
	ciphertext, nonce, encryptionKeyID, err := s.security.EncryptBound(ctx, "inbox/v1", inboxID, string(fenced.EndpointID), 1, plaintext)
	if err != nil {
		return adapterapi.IngressReceipt{}, err
	}
	now := s.clock.Now().UTC()
	result, err := s.repo.AcceptInbox(ctx, eventstore.InboxUpdate{
		InboxID: inboxID, EndpointID: string(fenced.EndpointID), ProviderEventKey: providerKey,
		LaneHMAC: laneDigest, Status: eventstore.InboxStatusPending,
		PayloadCiphertext: ciphertext, PayloadNonce: nonce,
		ContentDigest: contentDigest, ContentDigestKeyID: digestKeyID,
		PayloadEncryptionKeyID: encryptionKeyID, PayloadExpiresAt: now.Add(IngressPayloadTTL), AllowExpiredDedupe: true,
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
	EndpointID        adapterapi.EndpointID    `json:"endpointId"`
	Generation        uint64                   `json:"generation"`
	DesiredVersion    uint64                   `json:"desiredVersion"`
	Message           adapterapi.InboundMessage `json:"message"`
	ContentDigest     []byte                   `json:"contentDigest"`
	ContentDigestKeyID string                  `json:"contentDigestKeyId"`
	Status            string                   `json:"status"`
}

func (s *InboundService) providerKey(ctx context.Context, endpointID adapterapi.EndpointID, message adapterapi.InboundMessage, contentDigest []byte) (string, error) {
	if message.ProviderEventID != "" {
		return string(message.ProviderEventID), nil
	}
	target := message.Target
	if target == "" {
		target = string(message.Conversation)
	}
	occurred := "0"
	if !message.OccurredAt.IsZero() {
		occurred = fmt.Sprintf("%d", message.OccurredAt.UTC().UnixNano())
	}
	identityParts := []string{string(endpointID), message.Platform, string(message.Sender), target, occurred}
	if message.OccurredAt.IsZero() {
		identityParts = append(identityParts, hex.EncodeToString(contentDigest))
	}
	identityDigest, _, err := s.security.KeyedDigest(ctx, "fallback-provider-key/v1", canonicalIngressTuple(identityParts...))
	if err != nil {
		return "", err
	}
	return "fallback:" + hex.EncodeToString(identityDigest), nil
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

