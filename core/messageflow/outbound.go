package messageflow

import (
	"context"
	"crypto/hmac"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/eventstore"
)

var (
	ErrEndpointUnavailable    = errors.New("messageflow: endpoint unavailable")
	ErrCapabilityDenied       = errors.New("messageflow: capability denied")
	ErrCommandConflict        = errors.New("messageflow: command conflicts with existing request")
	ErrMissingOperationLookup = errors.New("messageflow: durable operation lookup unavailable")
)

func endpointUnavailable(reason string, cause error) error {
	if cause != nil {
		return fmt.Errorf("%w: %s: %w", ErrEndpointUnavailable, reason, cause)
	}
	return fmt.Errorf("%w: %s", ErrEndpointUnavailable, reason)
}

func observedStateLabel(state adapterapi.ObservedState) string {
	switch state {
	case adapterapi.ObservedStateStopped:
		return "stopped"
	case adapterapi.ObservedStateStarting:
		return "starting"
	case adapterapi.ObservedStateConnected:
		return "connected"
	case adapterapi.ObservedStateStopping:
		return "stopping"
	case adapterapi.ObservedStateFailed:
		return "failed"
	case adapterapi.ObservedStateAmbiguous:
		return "ambiguous"
	default:
		return "invalid"
	}
}

type EndpointSnapshot struct {
	EndpointID    adapterapi.EndpointID
	AdapterKey    adapterapi.AdapterKey
	DesiredState  string
	ObservedState adapterapi.ObservedState
	Capabilities  adapterapi.CapabilitySet
	Actions       adapterapi.ActionSet
	IndexRootID   string
	IndexSigner   IndexSigner
}

type EndpointResolver interface {
	Resolve(ctx context.Context, endpointID adapterapi.EndpointID) (EndpointSnapshot, error)
}
type IndexSigner interface {
	KeyedDigest(ctx context.Context, domain string, parts ...string) ([]byte, string, error)
}
type OperationLookup interface {
	GetOperationByIdempotency(ctx context.Context, principal, scope, key string) (eventstore.OperationView, error)
}
type IDGenerator interface{ NewID() (string, error) }
type BoundEncryptor interface {
	EncryptBound(ctx context.Context, domain, identity, owner string, version uint64, plaintext []byte) ([]byte, []byte, string, error)
}

type SubmitRequest struct {
	Effect        adapterapi.OutboundEffect
	CommandID     string
	PrincipalID   adapterapi.PrincipalID
	CorrelationID adapterapi.CorrelationID
	CausationID   adapterapi.CausationID
}
type SubmitResult struct {
	OperationID  string
	EffectID     string
	Digest       []byte
	Deduplicated bool
}

// PreparedOutbound is a validated, encrypted outbound request that has not
// been committed. Callers may atomically combine Work with other participants.
type PreparedOutbound struct {
	Work   eventstore.UnitOfWork
	Result SubmitResult
}

type preparedStore struct {
	eventstore.Store
	lookup OperationLookup
	work   eventstore.UnitOfWork
}

func (s *preparedStore) Commit(_ context.Context, work eventstore.UnitOfWork) (eventstore.CommitResult, error) {
	s.work = work
	return eventstore.CommitResult{}, nil
}

func (s *preparedStore) GetOperationByIdempotency(ctx context.Context, principal, scope, key string) (eventstore.OperationView, error) {
	return s.lookup.GetOperationByIdempotency(ctx, principal, scope, key)
}

// Prepare validates and encrypts an outbound request without committing it.
func (s *OutboundService) Prepare(ctx context.Context, req SubmitRequest) (PreparedOutbound, error) {
	if s == nil {
		return PreparedOutbound{}, errors.New("messageflow: outbound service unavailable")
	}
	lookup, ok := s.store.(OperationLookup)
	if !ok {
		return PreparedOutbound{}, ErrMissingOperationLookup
	}
	capture := &preparedStore{Store: s.store, lookup: lookup}
	s.serial.Lock()
	defer s.serial.Unlock()
	result, err := s.submit(ctx, req, capture)
	if err != nil {
		return PreparedOutbound{}, err
	}
	return PreparedOutbound{Work: capture.work, Result: result}, nil
}

type effectWire struct {
	Effect    adapterapi.OutboundEffect `json:"effect"`
	RawTarget string                    `json:"rawTarget,omitempty"`
}
type effectDigestProjection struct {
	Version              adapterapi.EffectVersion    `json:"version,omitempty"`
	EndpointID           adapterapi.EndpointID       `json:"endpointId,omitempty"`
	Risk                 adapterapi.EffectRisk       `json:"risk,omitempty"`
	RetryClass           adapterapi.EffectRetryClass `json:"retryClass,omitempty"`
	RequiredCapabilities adapterapi.CapabilitySet    `json:"requiredCapabilities,omitempty"`
	RequiredAction       adapterapi.ActionKind       `json:"requiredAction,omitempty"`
	Kind                 adapterapi.EffectKind       `json:"kind"`
	Action               adapterapi.ActionKind       `json:"action,omitempty"`
	Payload              adapterapi.EffectPayload    `json:"payload,omitempty"`
}

func logicalDigestBytes(e adapterapi.OutboundEffect) ([]byte, error) {
	projection := effectDigestProjection{
		Version:              e.Version,
		EndpointID:           e.EndpointID,
		Risk:                 e.Risk,
		RetryClass:           e.RetryClass,
		RequiredCapabilities: e.RequiredCapabilities,
		RequiredAction:       e.RequiredAction,
		Kind:                 e.Kind,
		Action:               e.Action,
		Payload:              e.Payload,
	}
	raw := ""
	if e.Payload.Target.Kind == adapterapi.TargetRaw {
		raw = e.Payload.Target.Raw
	}
	return json.Marshal(struct {
		Effect    effectDigestProjection `json:"effect"`
		RawTarget string                 `json:"rawTarget,omitempty"`
	}{Effect: projection, RawTarget: raw})
}

func effectBytes(e adapterapi.OutboundEffect) ([]byte, error) {
	raw := ""
	if e.Payload.Target.Kind == adapterapi.TargetRaw {
		raw = e.Payload.Target.Raw
	}
	return json.Marshal(effectWire{Effect: e, RawTarget: raw})
}

func snapshotLaneSigner(ctx context.Context, snapshot EndpointSnapshot) adapterapi.LaneSigner {
	return func(label string, payload []byte) ([]byte, error) {
		digest, keyID, err := snapshot.IndexSigner.KeyedDigest(ctx, label, string(payload))
		if err != nil || keyID != snapshot.IndexRootID {
			return nil, errors.New("messageflow: index signer unavailable")
		}
		return digest, nil
	}
}
func laneMAC(e adapterapi.OutboundEffect) ([]byte, error) {
	if e.Lane.MAC == "" {
		return nil, errors.New("messageflow: missing lane mac")
	}
	value, err := hex.DecodeString(e.Lane.MAC)
	if err != nil {
		return nil, errors.New("messageflow: invalid lane mac")
	}
	return value, nil
}
func riskClass(r adapterapi.EffectRisk, retry adapterapi.EffectRetryClass) string {
	switch retry {
	case adapterapi.EffectRetryPreDispatch:
		return eventstore.RiskPreDispatchRetryable
	case adapterapi.EffectRetryNonIdempotent:
		return eventstore.RiskNonIdempotentAfterDispatch
	default:
		return eventstore.RiskProviderIdempotent
	}
}
func effectType(k adapterapi.EffectKind) string {
	if k == adapterapi.EffectKindMessage {
		return "message"
	}
	return "action"
}

type OutboundOption func(*OutboundService)
type OutboundService struct {
	store     eventstore.Store
	resolver  EndpointResolver
	encryptor BoundEncryptor
	ids       IDGenerator
	clock     eventstore.Clock
	serial    sync.Mutex
}

func NewOutboundService(store eventstore.Store, resolver EndpointResolver, encryptor BoundEncryptor, ids IDGenerator, options ...OutboundOption) (*OutboundService, error) {
	if store == nil || resolver == nil || encryptor == nil || ids == nil {
		return nil, errors.New("messageflow: dependencies required")
	}
	if _, ok := store.(OperationLookup); !ok {
		return nil, ErrMissingOperationLookup
	}
	s := &OutboundService{store: store, resolver: resolver, encryptor: encryptor, ids: ids, clock: eventstore.SystemClock{}}
	for _, option := range options {
		if option != nil {
			option(s)
		}
	}
	return s, nil
}
func (s *OutboundService) Submit(ctx context.Context, req SubmitRequest) (SubmitResult, error) {
	if s == nil {
		return SubmitResult{}, errors.New("messageflow: outbound service unavailable")
	}
	s.serial.Lock()
	defer s.serial.Unlock()
	return s.submit(ctx, req, s.store)
}

func (s *OutboundService) submit(ctx context.Context, req SubmitRequest, store eventstore.Store) (SubmitResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	e := req.Effect
	if !req.PrincipalID.Valid() {
		return SubmitResult{}, adapterapi.ErrInvalidContract
	}
	if req.CommandID == "" {
		return SubmitResult{}, errors.New("messageflow: command id required")
	}
	if req.CorrelationID != "" {
		e.CorrelationID = req.CorrelationID
	}
	if req.CausationID != "" {
		e.CausationID = req.CausationID
	}
	if e.CorrelationID == "" || !e.CorrelationID.Valid() || (e.CausationID != "" && !e.CausationID.Valid()) {
		return SubmitResult{}, adapterapi.ErrInvalidContract
	}
	if e.ID == "" {
		id, allocErr := s.ids.NewID()
		if allocErr != nil {
			return SubmitResult{}, allocErr
		}
		e.ID = adapterapi.EffectID(id)
	}
	if e.OperationID == "" {
		id, allocErr := s.ids.NewID()
		if allocErr != nil {
			return SubmitResult{}, allocErr
		}
		e.OperationID = adapterapi.OperationID(id)
	}
	if e.Version != adapterapi.EffectVersionOne || e.EndpointID == "" {
		return SubmitResult{}, adapterapi.ErrInvalidContract
	}
	if err := e.Validate(); err != nil {
		return SubmitResult{}, err
	}
	snap, laneErr := s.resolver.Resolve(ctx, e.EndpointID)
	if laneErr != nil {
		return SubmitResult{}, endpointUnavailable("endpoint resolver failed", laneErr)
	}
	if snap.EndpointID != e.EndpointID {
		return SubmitResult{}, endpointUnavailable(fmt.Sprintf("resolved endpoint %q does not match request %q", snap.EndpointID, e.EndpointID), nil)
	}
	if snap.IndexRootID == "" || snap.IndexSigner == nil {
		return SubmitResult{}, endpointUnavailable("endpoint index signer unavailable", nil)
	}
	if err := e.Lane.VerifyWithSigner(snapshotLaneSigner(ctx, snap), e.EndpointID, e.Payload.Target); err != nil {
		return SubmitResult{}, endpointUnavailable("outbound lane verification failed", err)
	}
	plain, laneErr := effectBytes(e)
	if laneErr != nil {
		return SubmitResult{}, laneErr
	}
	digestPlain, laneErr := logicalDigestBytes(e)
	if laneErr != nil {
		return SubmitResult{}, laneErr
	}
	digest, digestKeyID, laneErr := snap.IndexSigner.KeyedDigest(ctx, "outbound-request/v1", string(digestPlain))
	if laneErr != nil {
		return SubmitResult{}, endpointUnavailable("outbound request digest failed", laneErr)
	}
	if digestKeyID != snap.IndexRootID {
		return SubmitResult{}, endpointUnavailable("outbound request digest key changed", nil)
	}
	if len(digest) == 0 {
		return SubmitResult{}, endpointUnavailable("outbound request digest is empty", nil)
	}
	lookup := store.(OperationLookup)
	if view, lookupErr := lookup.GetOperationByIdempotency(ctx, string(req.PrincipalID), "outbound", req.CommandID); lookupErr == nil {
		if !hmac.Equal(view.RequestDigest, digest) {
			return SubmitResult{}, ErrCommandConflict
		}
		return SubmitResult{OperationID: view.OperationID, EffectID: view.ResourceID, Digest: append([]byte(nil), digest...), Deduplicated: true}, nil
	} else if !errors.Is(lookupErr, eventstore.ErrNotFound) {
		return SubmitResult{}, lookupErr
	}
	now := s.clock.Now().UTC()
	if snap.DesiredState != "enabled" || snap.ObservedState != adapterapi.ObservedStateConnected {
		return SubmitResult{}, endpointUnavailable(fmt.Sprintf("endpoint %q has desired state %q and observed state %q", e.EndpointID, snap.DesiredState, observedStateLabel(snap.ObservedState)), nil)
	}
	if !e.Deadline.After(now) {
		return SubmitResult{}, endpointUnavailable(fmt.Sprintf("outbound deadline expired at %s", e.Deadline.UTC().Format(time.RFC3339Nano)), nil)
	}
	if err := e.ValidateForCapabilities(snap.Capabilities, snap.Actions); err != nil {
		return SubmitResult{}, ErrCapabilityDenied
	}
	effectID := e.ID
	opID := e.OperationID
	cipher, nonce, keyID, laneErr := s.encryptor.EncryptBound(ctx, "outbox/v1", string(effectID), string(e.EndpointID), 1, plain)
	if laneErr != nil {
		return SubmitResult{}, laneErr
	}
	lane, laneErr := laneMAC(e)
	if laneErr != nil {
		return SubmitResult{}, laneErr
	}
	expiry := time.Time{}
	if e.Deadline.After(now) && !e.Deadline.After(now.Add(eventstore.InboxPayloadTTL)) {
		expiry = e.Deadline
	}
	eventID, allocErr := s.ids.NewID()
	if allocErr != nil {
		return SubmitResult{}, allocErr
	}
	effectEventID := eventID
	segmentKinds := make([]string, 0, len(e.Payload.Segments))
	for _, segment := range e.Payload.Segments {
		segmentKinds = append(segmentKinds, segment.Kind)
	}
	eventPayload, marshalErr := json.Marshal(struct {
		Version       uint64                       `json:"version"`
		EffectID      string                       `json:"effectId"`
		OperationID   string                       `json:"operationId"`
		EndpointID    string                       `json:"endpointId"`
		RequestDigest string                       `json:"requestDigest"`
		DigestKeyID   string                       `json:"digestKeyId"`
		PayloadKind   adapterapi.EffectPayloadKind `json:"payloadKind"`
		SegmentKinds  []string                     `json:"segmentKinds,omitempty"`
		SegmentCount  int                          `json:"segmentCount"`
		TargetDigest  string                       `json:"targetDigest"`
		LaneKey       string                       `json:"laneKey"`
		LaneMAC       string                       `json:"laneMac"`
		Risk          adapterapi.EffectRisk        `json:"risk"`
	}{1, string(effectID), string(opID), string(e.EndpointID), hex.EncodeToString(digest), snap.IndexRootID, e.Payload.Kind, segmentKinds, len(e.Payload.Segments), e.Lane.TargetDigest, e.Lane.Key, e.Lane.MAC, e.Risk})
	if marshalErr != nil {
		return SubmitResult{}, errors.New("messageflow: shape event encoding failed")
	}
	work := eventstore.UnitOfWork{Streams: []eventstore.StreamAppend{{Stream: eventstore.StreamID{AggregateType: "outbound-effect", AggregateID: string(effectID)}, Events: []eventstore.NewEvent{{EventType: "OutboundEffectRequestedV1", SchemaVersion: 1, Payload: eventPayload, Metadata: eventstore.Metadata{EventID: effectEventID, CommandID: req.CommandID, CorrelationID: string(e.CorrelationID), CausationID: string(e.CausationID), PrincipalID: string(req.PrincipalID), Producer: "core/messageflow", OccurredAt: now}}}}}, Operations: []eventstore.OperationUpdate{{OperationID: string(opID), Kind: "outbound-effect", Status: "pending", PrincipalID: string(req.PrincipalID), ResourceID: string(effectID), RequestID: req.CommandID, CorrelationID: string(e.CorrelationID), IdempotencyScope: "outbound", IdempotencyKey: req.CommandID, RequestDigest: digest, CreatedAt: now, UpdatedAt: now}}, Effects: []eventstore.NewEffect{{EffectID: string(effectID), EndpointID: string(e.EndpointID), LaneHMAC: lane, EffectType: effectType(e.Kind), RiskClass: riskClass(e.Risk, e.RetryClass), Status: eventstore.OutboxStatusPending, DeadlineAt: e.Deadline, NextAttemptAt: e.NotBefore, PayloadCiphertext: cipher, PayloadNonce: nonce, ContentDigest: digest, DigestKeyID: "", PayloadEncryptionKeyID: keyID, ContentDigestKeyID: snap.IndexRootID, PayloadExpiresAt: expiry}}}
	subject := string(e.Payload.Target.Conversation)
	if subject == "" {
		subject = string(e.Payload.Target.Member)
	}
	subjectKey, subjectKeyID, subjectErr := snap.IndexSigner.KeyedDigest(ctx, "privacy-subject/v1", subject)
	if subjectErr != nil {
		return SubmitResult{}, endpointUnavailable("privacy subject digest failed", subjectErr)
	}
	if subjectKeyID != snap.IndexRootID {
		return SubmitResult{}, endpointUnavailable("privacy subject digest key changed", nil)
	}
	if len(subjectKey) == 0 {
		return SubmitResult{}, endpointUnavailable("privacy subject digest is empty", nil)
	}
	work.Streams[0].Events[0].Metadata.SubjectKey = subjectKey
	work.Effects[0].SubjectKey = subjectKey
	result, laneErr := store.Commit(ctx, work)
	if laneErr != nil {
		if view, lookupErr := store.(OperationLookup).GetOperationByIdempotency(ctx, string(req.PrincipalID), "outbound", req.CommandID); lookupErr == nil {
			if !hmac.Equal(view.RequestDigest, digest) {
				return SubmitResult{}, ErrCommandConflict
			}
			return SubmitResult{OperationID: view.OperationID, EffectID: view.ResourceID, Digest: append([]byte(nil), digest...), Deduplicated: true}, nil
		}
		return SubmitResult{}, laneErr
	}
	accepted := SubmitResult{OperationID: string(opID), EffectID: string(effectID), Digest: digest, Deduplicated: result.Deduplicated}
	return accepted, nil
}
