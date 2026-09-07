package messageflow

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

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
	target := message.Target
	if target == "" {
		target = string(message.Conversation)
	}
	laneDigest, _, err := s.security.KeyedDigest(ctx, "inbound-lane/v1", string(fenced.EndpointID), target)
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
		PayloadEncryptionKeyID: encryptionKeyID, PayloadExpiresAt: now.Add(IngressPayloadTTL),
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
	identityDigest, _, err := s.security.KeyedDigest(ctx, "fallback-provider-key/v1", string(endpointID), message.Platform, string(message.Sender), target, occurred)
	if err != nil {
		return "", err
	}
	// The body digest is persisted separately and is intentionally not folded
	// into the identity key, so a same-identity/different-body collision is
	// detected by the durable repository rather than silently admitted.
	_ = contentDigest
	return "fallback:" + hex.EncodeToString(identityDigest), nil
}

func (s *InboundService) recordCollision(collision IngressCollision) {
	s.collisions.Add(1)
	if s.collisionObserver != nil {
		s.collisionObserver(collision)
	}
}

