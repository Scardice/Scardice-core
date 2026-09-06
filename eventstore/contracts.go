// Package eventstore contains domain-neutral contracts for durable event storage.
package eventstore

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

const (
	MaxEventPayloadBytes = 256 * 1024
	MaxUnitOfWorkStreams = 128
	MaxUnitOfWorkEvents  = 2048
	MaxUnitOfWorkBytes   = 16 * 1024 * 1024
	MaxArtifactBytes     = 32 * 1024 * 1024
	DefaultArtifactTTL   = 10 * time.Minute
	MaxArtifactTTL       = 60 * time.Minute
	InboxPayloadTTL      = 30 * 24 * time.Hour
)

const (
	InboxStatusPending           = "pending"
	InboxStatusLeased            = "leased"
	InboxStatusCallbackStarted   = "callback-started"
	InboxStatusAmbiguous         = "ambiguous"
	InboxStatusConfirmedConsumed = "confirmed-consumed"
	InboxStatusFailed            = "failed"
	InboxStatusSkipped           = "skip"

	OutboxStatusPending    = "pending"
	OutboxStatusLeased     = "leased"
	OutboxStatusDispatched = "dispatched"
	OutboxStatusSucceeded  = "succeeded"
	OutboxStatusFailed     = "failed"
	OutboxStatusAmbiguous  = "ambiguous"

	RiskPreDispatchRetryable       = "pre-dispatch-retryable"
	RiskProviderIdempotent         = "provider-idempotent"
	RiskNonIdempotentAfterDispatch = "non-idempotent-after-dispatch"

	InboxResolutionConfirmedConsumed = "confirmed-consumed"
	InboxResolutionRetry             = "retry"
	InboxResolutionSkip              = "skip"
	OutboxResolutionRetry            = "retry"
	OutboxResolutionSucceeded        = "succeeded"
	OutboxResolutionFailed           = "failed"
)

var (
	ErrInvalidEvent      = errors.New("eventstore: invalid event")
	ErrInvalidMetadata   = errors.New("eventstore: invalid metadata")
	ErrUnsupportedSchema = errors.New("eventstore: unsupported schema")
	ErrConflict          = errors.New("eventstore: conflict")
	ErrEmptyUnitOfWork   = errors.New("eventstore: empty unit of work")
	ErrDuplicateStream   = errors.New("eventstore: duplicate stream")
	ErrDuplicateParticipant = errors.New("eventstore: duplicate participant")
	ErrOversizeInput     = errors.New("eventstore: input exceeds configured bound")
	ErrStaleLease        = errors.New("eventstore: stale lease")
	ErrNotFound           = errors.New("eventstore: not found")
	ErrInvalidTransition  = errors.New("eventstore: invalid state transition")
	ErrInvalidRiskClass   = errors.New("eventstore: invalid risk class")
	ErrPayloadExpired     = errors.New("eventstore: encrypted payload expired")
	ErrArtifactGone       = errors.New("eventstore: artifact gone")
	ErrEncryptionUnavailable = errors.New("eventstore: encryption unavailable")
	ErrAuthenticationFailed = errors.New("eventstore: encrypted data authentication failed")
	ErrInvalidTTL          = errors.New("eventstore: invalid ttl")
	ErrDeduplicated        = errors.New("eventstore: deduplicated")
	ErrReadinessInvalid    = errors.New("eventstore: invalid readiness")
	ErrReadinessQuarantined = errors.New("eventstore: readiness quarantine")
	ErrKeySourceUnavailable = errors.New("eventstore: key source unavailable")
	ErrKeyUnavailable      = errors.New("eventstore: encryption key unavailable")
	ErrPluginKVNotFound    = errors.New("eventstore: plugin key not found")
)

// Clock is injected anywhere a contract allocates a timestamp.
type Clock interface {
	Now() time.Time
}

// IDGenerator is injected anywhere a public identifier is allocated.
type IDGenerator interface {
	NewID() (string, error)
}

// SystemClock is the production UTC clock. Tests should provide a fixed Clock.
type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now().UTC() }

// UUIDGenerator allocates identifiers using UUIDv4 and returns entropy errors.
type UUIDGenerator struct{}

func (UUIDGenerator) NewID() (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("eventstore: allocate ID: %w", err)
	}
	return id.String(), nil
}

// Metadata is the canonical, non-payload event metadata. OccurredAtUnixNanoUTC
// is retained as the canonical storage scalar; OccurredAt is a convenience for
// callers constructing events in Go.
type Metadata struct {
	EventID                string
	CommandID              string
	CorrelationID          string
	CausationID            string
	PrincipalID            string
	Producer               string
	OccurredAt             time.Time
	OccurredAtUnixNanoUTC  int64
	OccurredAtUnixNanoSet  bool
}

// StreamID identifies one aggregate stream without importing an aggregate type.
type StreamID struct {
	AggregateType string
	AggregateID   string
}

// NewEvent is an already-decided event. Payload is kept as exact JSON bytes.
type NewEvent struct {
	EventType     string
	SchemaVersion uint16
	Payload       json.RawMessage
	Metadata      Metadata
}

// EventChecksum is the stable SHA-256 integrity contract for one envelope.
type EventChecksum [sha256.Size]byte

func (c EventChecksum) String() string { return hex.EncodeToString(c[:]) }

// Envelope is a persisted event with its allocated stream/global positions.
type Envelope struct {
	Stream         StreamID
	StreamVersion  uint64
	GlobalPosition uint64
	EventID        string
	EventType      string
	SchemaVersion  uint16
	Payload        json.RawMessage
	Metadata       Metadata
	Checksum       EventChecksum
}

// EventFactory supplies injected identity and time dependencies for events.
type EventFactory struct {
	Clock Clock
	IDs   IDGenerator
}

func (f EventFactory) NewEvent(eventType string, schemaVersion uint16, payload json.RawMessage, metadata Metadata) (NewEvent, error) {
	if eventType == "" || schemaVersion == 0 || len(payload) > MaxEventPayloadBytes {
		if len(payload) > MaxEventPayloadBytes {
			return NewEvent{}, &OversizeError{Bound: "event payload", Limit: MaxEventPayloadBytes, Actual: len(payload)}
		}
		return NewEvent{}, ErrInvalidEvent
	}
	if metadataTimestampConflict(metadata) {
		return NewEvent{}, ErrInvalidMetadata
	}
	if metadata.EventID == "" || metadata.CommandID == "" || metadata.CorrelationID == "" {
		if f.IDs == nil {
			return NewEvent{}, ErrInvalidMetadata
		}
	}
	var err error
	if metadata.EventID == "" {
		metadata.EventID, err = f.IDs.NewID()
		if err != nil {
			return NewEvent{}, err
		}
	}
	if metadata.CommandID == "" {
		metadata.CommandID, err = f.IDs.NewID()
		if err != nil {
			return NewEvent{}, err
		}
	}
	if metadata.CorrelationID == "" {
		metadata.CorrelationID, err = f.IDs.NewID()
		if err != nil {
			return NewEvent{}, err
		}
	}
	if metadata.OccurredAt.IsZero() && metadata.OccurredAtUnixNanoUTC == 0 && !metadata.OccurredAtUnixNanoSet {
		if f.Clock == nil {
			return NewEvent{}, ErrInvalidMetadata
		}
		metadata.OccurredAt = f.Clock.Now()
	}
	if !metadata.OccurredAt.IsZero() {
		metadata.OccurredAt = metadata.OccurredAt.UTC()
		metadata.OccurredAtUnixNanoUTC = metadata.OccurredAt.UnixNano()
		metadata.OccurredAtUnixNanoSet = true
	}
	if metadata.OccurredAt.IsZero() && (metadata.OccurredAtUnixNanoUTC != 0 || metadata.OccurredAtUnixNanoSet) {
		metadata.OccurredAtUnixNanoSet = true
	}
	if metadata.OccurredAt.IsZero() && !metadata.OccurredAtUnixNanoSet {
		return NewEvent{}, ErrInvalidMetadata
	}
	return NewEvent{EventType: eventType, SchemaVersion: schemaVersion, Payload: payload, Metadata: metadata}, nil
}
func metadataHasTimestamp(metadata Metadata) bool {
	return !metadata.OccurredAt.IsZero() || metadata.OccurredAtUnixNanoSet || metadata.OccurredAtUnixNanoUTC != 0
}

func metadataTimestampConflict(metadata Metadata) bool {
	if metadata.OccurredAt.IsZero() || (!metadata.OccurredAtUnixNanoSet && metadata.OccurredAtUnixNanoUTC == 0) {
		return false
	}
	return metadata.OccurredAt.UTC().UnixNano() != metadata.OccurredAtUnixNanoUTC
}

func metadataUnixNano(metadata Metadata) int64 {
	if !metadata.OccurredAt.IsZero() {
		return metadata.OccurredAt.UTC().UnixNano()
	}
	return metadata.OccurredAtUnixNanoUTC
}

// Envelope assigns storage positions and computes the stable event checksum.
func (f EventFactory) Envelope(stream StreamID, streamVersion, globalPosition uint64, event NewEvent) (Envelope, error) {
	if stream.AggregateType == "" || stream.AggregateID == "" || streamVersion == 0 || globalPosition == 0 {
		return Envelope{}, ErrInvalidEvent
	}
	if event.EventType == "" || event.SchemaVersion == 0 || len(event.Payload) > MaxEventPayloadBytes {
		if len(event.Payload) > MaxEventPayloadBytes {
			return Envelope{}, &OversizeError{Bound: "event payload", Limit: MaxEventPayloadBytes, Actual: len(event.Payload)}
		}
		return Envelope{}, ErrInvalidEvent
	}
	if metadataTimestampConflict(event.Metadata) || event.Metadata.EventID == "" || event.Metadata.CommandID == "" || event.Metadata.CorrelationID == "" || !metadataHasTimestamp(event.Metadata) {
		return Envelope{}, ErrInvalidMetadata
	}
	envelope := Envelope{
		Stream:         stream,
		StreamVersion:  streamVersion,
		GlobalPosition: globalPosition,
		EventID:        event.Metadata.EventID,
		EventType:      event.EventType,
		SchemaVersion:  event.SchemaVersion,
		Payload:        event.Payload,
		Metadata:       event.Metadata,
	}
	envelope.Checksum = ComputeEventChecksum(envelope)
	return envelope, nil
}

// ComputeEventChecksum implements A1's domain-separated canonical checksum.
// Every scalar has an explicit type and null marker followed by a length-prefixed
// value. The payload bytes are included verbatim and are never decoded.
func ComputeEventChecksum(event Envelope) EventChecksum {
	h := sha256.New()
	writeCanonicalString(h, "SCARDICE-EVENT-V1")
	writeCanonicalString(h, event.Stream.AggregateType)
	writeCanonicalString(h, event.Stream.AggregateID)
	writeCanonicalUint64(h, event.StreamVersion)
	writeCanonicalUint64(h, event.GlobalPosition)
	writeCanonicalString(h, event.EventType)
	writeCanonicalUint16(h, event.SchemaVersion)
	writeCanonicalString(h, event.Metadata.EventID)
	writeCanonicalString(h, event.Metadata.CommandID)
	writeCanonicalString(h, event.Metadata.CorrelationID)
	writeCanonicalOptionalString(h, event.Metadata.CausationID)
	writeCanonicalOptionalString(h, event.Metadata.PrincipalID)
	writeCanonicalOptionalString(h, event.Metadata.Producer)
	writeCanonicalInt64(h, metadataUnixNano(event.Metadata))
	writeCanonicalBytes(h, event.Payload, event.Payload == nil)
	var checksum EventChecksum
	copy(checksum[:], h.Sum(nil))
	return checksum
}

// writeCanonicalField is the one scalar encoding used by checksums. A marker
// value of zero is null; one is non-null. Non-null values, including empty
// strings/byte slices, retain a zero length rather than becoming null.
func writeCanonicalField(h interface{ Write([]byte) (int, error) }, typeTag byte, isNull bool, value []byte) {
	marker := byte(1)
	if isNull {
		marker = 0
		value = nil
	}
	_, _ = h.Write([]byte{typeTag, marker})
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = h.Write(length[:])
	_, _ = h.Write(value)
}

func writeCanonicalString(h interface{ Write([]byte) (int, error) }, value string) {
	writeCanonicalField(h, 's', false, []byte(value))
}

func writeCanonicalOptionalString(h interface{ Write([]byte) (int, error) }, value string) {
	writeCanonicalField(h, 's', value == "", []byte(value))
}

func writeCanonicalBytes(h interface{ Write([]byte) (int, error) }, value []byte, isNull bool) {
	writeCanonicalField(h, 'b', isNull, value)
}

func writeCanonicalUint16(h interface{ Write([]byte) (int, error) }, value uint16) {
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], value)
	writeCanonicalField(h, 'h', false, encoded[:])
}

func writeCanonicalUint64(h interface{ Write([]byte) (int, error) }, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	writeCanonicalField(h, 'u', false, encoded[:])
}

func writeCanonicalInt64(h interface{ Write([]byte) (int, error) }, value int64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(value))
	writeCanonicalField(h, 'i', false, encoded[:])
}

// StreamAppend is one already-decided optimistic append.
type StreamAppend struct {
	Stream          StreamID
	ExpectedVersion uint64
	Events          []NewEvent
}

// UnitOfWork is the complete storage input for one atomic commit. It may contain
// zero streams when one of the non-stream update lists is non-empty.
type UnitOfWork struct {
	Streams         []StreamAppend
	Operations      []OperationUpdate
	InboxUpdates    []InboxUpdate
	Effects         []NewEffect
	ArtifactUpdates []ArtifactUpdate
	SecretUpdates   []SecretUpdate
	PluginKVUpdates []PluginKVUpdate
	FenceUpdates    []SubjectFenceUpdate
}

// CommitResult reports allocated event positions and participant versions.
type CommitResult struct {
	Events          []Envelope
	StreamVersions  map[StreamID]uint64
	OperationIDs    []string
	InboxIDs        []string
	EffectIDs       []string
	ArtifactIDs     []string
	SecretRefs      []string
	PluginKVIndexes [][]byte
	FenceKeys       [][]byte
	Deduplicated    bool
	Idempotent      bool
	OrderingSequence uint64
	Version         uint64
}

// Store is intentionally limited to aggregate event operations.
type Store interface {
	Commit(context.Context, UnitOfWork) (CommitResult, error)
	Load(context.Context, StreamID, uint64) ([]Envelope, error)
	Close() error
}

// OperationUpdate contains opaque/encrypted private context, never plaintext
// credentials or message bodies.
type OperationUpdate struct {
	OperationID             string
	ExpectedVersion         uint64
	Version                 uint64
	Kind                    string
	Status                  string
	PrincipalID             string
	ResourceID              string
	RequestID               string
	CorrelationID           string
	IdempotencyScope        string
	IdempotencyKey          string
	RequestDigest           []byte
	ResultCode              string
	ErrorCode               string
	ArtifactID              string
	PrivateContextCiphertext []byte
	PrivateContextNonce     []byte
	EncryptionKeyID         string
	CreatedAt               time.Time
	UpdatedAt               time.Time
	ExpiresAt               time.Time
}

// InboxUpdate contains encrypted ingress data and durable state transitions.
type InboxUpdate struct {
	InboxID                string
	ExpectedVersion        uint64
	Version                uint64
	EndpointID             string
	ProviderEventKey       string
	LaneHMAC               []byte
	OrderingSequence       uint64
	Status                 string
	LeaseOwner             string
	LeaseEpoch             uint64
	LeaseExpiresAt         time.Time
	AttemptID              string
	PayloadCiphertext      []byte
	PayloadNonce           []byte
	ContentDigest          []byte
	DigestKeyID            string
	WorkflowID             string
	CallbackStartedAt      time.Time
	CompletedAt            time.Time
	PayloadExpiresAt       time.Time
	Resolution             string
	PrincipalID             string
	Reason                 string
	ResolutionAt           time.Time
}

// NewEffect is an outbound intent; its payload must be encrypted by persistence.
type NewEffect struct {
	EffectID               string
	ExpectedVersion        uint64
	Version                uint64
	EndpointID             string
	LaneHMAC               []byte
	OrderingSequence       uint64
	EffectType             string
	RiskClass              string
	Status                 string
	AttemptID              string
	LeaseOwner             string
	LeaseEpoch             uint64
	LeaseExpiresAt         time.Time
	DeadlineAt             time.Time
	NextAttemptAt          time.Time
	DispatchedAt           time.Time
	PayloadCiphertext      []byte
	PayloadNonce           []byte
	ContentDigest          []byte
	DigestKeyID             string
	ProviderMessageID      string
	ResultCode             string
	ErrorCode              string
	CompletedAt            time.Time
	PayloadExpiresAt       time.Time
	RetryCount             uint32
	Resolution             string
	PrincipalID             string
	Reason                 string
	ResolutionAt           time.Time
}

// ArtifactUpdate represents encrypted, bounded operation output.
type ArtifactUpdate struct {
	ArtifactID             string
	ExpectedVersion        uint64
	Version                uint64
	OperationID            string
	OwnerPrincipalID       string
	MediaType              string
	SafeFilename            string
	Size                   int64
	Status                 string
	Ciphertext             []byte
	Nonce                  []byte
	EncryptionKeyID        string
	ExpiresAt               time.Time
	ConsumedAt             time.Time
}

// SecretUpdate references encrypted operational secret material.
type SecretUpdate struct {
	SecretRef              string
	ExpectedVersion        uint64
	Version                uint64
	EndpointID             string
	AdapterID              string
	SecretVersion          uint64
	Ciphertext             []byte
	Nonce                  []byte
	EncryptionKeyID        string
	UpdatedAt              time.Time
}

// PluginKVUpdate is encrypted mutable plugin state indexed by a keyed digest.
type PluginKVUpdate struct {
	ExtensionID            string
	KeyHMAC                []byte
	ExpectedVersion        uint64
	Version                uint64
	KeyCiphertext          []byte
	KeyNonce               []byte
	ValueCiphertext        []byte
	ValueNonce             []byte
	EncryptionKeyID        string
	ValueSize               int64
	Deleted                 bool
	UpdatedAt              time.Time
}

// SubjectFenceUpdate is a privacy-purge ingress fence keyed by HMAC identity.
type SubjectFenceUpdate struct {
	SubjectKey             []byte
	Scope                  string
	ExpectedVersion        uint64
	Version                uint64
	PurgeOperationID       string
	CreatedAt              time.Time
	ExpiresAt              time.Time
	Deleted                 bool
}

// ValidateUnitOfWork performs pre-transaction validation and never includes
// payload content in errors.
func ValidateUnitOfWork(work UnitOfWork) error {
	if len(work.Streams) == 0 && len(work.Operations) == 0 && len(work.InboxUpdates) == 0 && len(work.Effects) == 0 && len(work.ArtifactUpdates) == 0 && len(work.SecretUpdates) == 0 && len(work.PluginKVUpdates) == 0 && len(work.FenceUpdates) == 0 {
		return ErrEmptyUnitOfWork
	}
	if len(work.Streams) > MaxUnitOfWorkStreams {
		return &OversizeError{Bound: "unit of work streams", Limit: MaxUnitOfWorkStreams, Actual: len(work.Streams)}
	}
	seen := make(map[StreamID]struct{}, len(work.Streams))
	eventCount := 0
	var encodedBytes uint64
	addBytes := func(n int) {
		if n <= 0 || encodedBytes > MaxUnitOfWorkBytes { return }
		if uint64(n) > uint64(MaxUnitOfWorkBytes)-encodedBytes {
			encodedBytes = uint64(MaxUnitOfWorkBytes) + 1
			return
		}
		encodedBytes += uint64(n)
	}
	addFields := func(parts ...int) { for _, part := range parts { addBytes(part) } }
	for _, append := range work.Streams {
		if append.Stream.AggregateType == "" || append.Stream.AggregateID == "" {
			return ErrInvalidEvent
		}
		if _, exists := seen[append.Stream]; exists {
			return ErrDuplicateStream
		}
		seen[append.Stream] = struct{}{}
		addFields(len(append.Stream.AggregateType), len(append.Stream.AggregateID))
		eventCount += len(append.Events)
		for _, event := range append.Events {
			if event.EventType == "" || event.SchemaVersion == 0 {
				return ErrInvalidEvent
			}
			if metadataTimestampConflict(event.Metadata) || !metadataHasTimestamp(event.Metadata) || event.Metadata.EventID == "" || event.Metadata.CommandID == "" || event.Metadata.CorrelationID == "" {
				return ErrInvalidMetadata
			}
			if len(event.Payload) > MaxEventPayloadBytes {
				return &OversizeError{Bound: "event payload", Limit: MaxEventPayloadBytes, Actual: len(event.Payload)}
			}
			addFields(len(event.EventType), len(event.Metadata.EventID), len(event.Metadata.CommandID), len(event.Metadata.CorrelationID), len(event.Metadata.CausationID), len(event.Metadata.PrincipalID), len(event.Metadata.Producer))
			addBytes(len(event.Payload))
		}
	}
	if eventCount > MaxUnitOfWorkEvents {
		return &OversizeError{Bound: "unit of work events", Limit: MaxUnitOfWorkEvents, Actual: eventCount}
	}
	for _, update := range work.Operations {
		addFields(len(update.OperationID), len(update.Kind), len(update.Status), len(update.PrincipalID), len(update.ResourceID), len(update.IdempotencyScope), len(update.IdempotencyKey), len(update.RequestID), len(update.RequestDigest), len(update.CorrelationID), len(update.ResultCode), len(update.ErrorCode), len(update.ArtifactID), len(update.PrivateContextCiphertext), len(update.PrivateContextNonce), len(update.EncryptionKeyID))
	}
	for _, update := range work.InboxUpdates {
		addFields(len(update.InboxID), len(update.EndpointID), len(update.ProviderEventKey), len(update.LaneHMAC), len(update.Status), len(update.LeaseOwner), len(update.AttemptID), len(update.PayloadCiphertext), len(update.PayloadNonce), len(update.ContentDigest), len(update.DigestKeyID), len(update.WorkflowID))
	}
	for _, update := range work.Effects {
		addFields(len(update.EffectID), len(update.EndpointID), len(update.LaneHMAC), len(update.EffectType), len(update.RiskClass), len(update.Status), len(update.AttemptID), len(update.LeaseOwner), len(update.PayloadCiphertext), len(update.PayloadNonce), len(update.ContentDigest), len(update.DigestKeyID), len(update.ProviderMessageID), len(update.ResultCode), len(update.ErrorCode))
	}
	for _, update := range work.ArtifactUpdates {
		addFields(len(update.ArtifactID), len(update.OperationID), len(update.OwnerPrincipalID), len(update.MediaType), len(update.SafeFilename), len(update.Ciphertext), len(update.Nonce), len(update.EncryptionKeyID))
	}
	for _, update := range work.SecretUpdates {
		addFields(len(update.SecretRef), len(update.EndpointID), len(update.AdapterID), len(update.Ciphertext), len(update.Nonce), len(update.EncryptionKeyID))
	}
	for _, update := range work.PluginKVUpdates {
		addFields(len(update.ExtensionID), len(update.KeyHMAC), len(update.KeyCiphertext), len(update.KeyNonce), len(update.ValueCiphertext), len(update.ValueNonce), len(update.EncryptionKeyID))
	}
	for _, update := range work.FenceUpdates {
		addFields(len(update.SubjectKey), len(update.Scope), len(update.PurgeOperationID))
	}
	if encodedBytes > MaxUnitOfWorkBytes {
		actual := int(encodedBytes)
		return &OversizeError{Bound: "unit of work encoded bytes", Limit: MaxUnitOfWorkBytes, Actual: actual}
	}
	if err := validateParticipantKeys(work); err != nil { return err }
	return nil
}

func validateParticipantKeys(work UnitOfWork) error {
	seen := func() map[string]struct{} { return make(map[string]struct{}) }
	check := func(m map[string]struct{}, key string) error { if _, ok := m[key]; ok { return ErrDuplicateParticipant }; m[key] = struct{}{}; return nil }
	type pair struct{ first, second string }
	checkPair := func(m map[pair]struct{}, key pair) error { if _, ok := m[key]; ok { return ErrDuplicateParticipant }; m[key] = struct{}{}; return nil }
	ops, arts, secrets, inbox, effects := seen(), seen(), seen(), seen(), seen()
	plugins, fences := make(map[pair]struct{}), make(map[pair]struct{})
	for _, v := range work.Operations { if v.OperationID != "" { if err:=check(ops,v.OperationID);err!=nil{return err} } }
	for _, v := range work.ArtifactUpdates { if v.ArtifactID != "" { if err:=check(arts,v.ArtifactID);err!=nil{return err} } }
	for _, v := range work.SecretUpdates { if v.SecretRef != "" { if err:=check(secrets,v.SecretRef);err!=nil{return err} } }
	for _, v := range work.InboxUpdates { if v.InboxID != "" { if err:=check(inbox,v.InboxID);err!=nil{return err} } }
	for _, v := range work.Effects { if v.EffectID != "" { if err:=check(effects,v.EffectID);err!=nil{return err} } }
	for _, v := range work.PluginKVUpdates { if v.ExtensionID != "" && len(v.KeyHMAC)>0 { if err:=checkPair(plugins,pair{v.ExtensionID,string(v.KeyHMAC)});err!=nil{return err} } }
	for _, v := range work.FenceUpdates { if len(v.SubjectKey)>0 && v.Scope != "" { if err:=checkPair(fences,pair{string(v.SubjectKey),v.Scope});err!=nil{return err} } }
	return nil
}

// OversizeError identifies only the bound that was exceeded.
type OversizeError struct {
	Bound  string
	Limit  int
	Actual int
}

func (e *OversizeError) Error() string {
	return fmt.Sprintf("%s: %s (limit %d)", ErrOversizeInput, e.Bound, e.Limit)
}
func (e *OversizeError) Unwrap() error { return ErrOversizeInput }

// StreamConflict is a complete expected/current stream version conflict.
type StreamConflict struct {
	Stream          StreamID
	ExpectedVersion uint64
	CurrentVersion  uint64
}

type InboxResolutionRequest struct {
	InboxID string
	ExpectedVersion uint64
	Resolution string
	PrincipalID string
	Reason string
}
type OutboxRenewRequest struct {
	EffectID string
	WorkerID string
	LeaseEpoch uint64
	AttemptID string
	LeaseDuration time.Duration
}
type OutboxDispatchRequest struct {
	EffectID string
	WorkerID string
	LeaseEpoch uint64
	AttemptID string
}
type OutboxCompletionRequest struct {
	EffectID string
	WorkerID string
	LeaseEpoch uint64
	AttemptID string
	Status string
	ResultCode string
	ErrorCode string
	ProviderMessageID string
}
type OutboxResolutionRequest struct {
	EffectID string
	ExpectedVersion uint64
	Resolution string
	PrincipalID string
	Reason string
}
type ArtifactPutRequest struct {
	ArtifactID string
	OperationID string
	OwnerPrincipalID string
	MediaType string
	SafeFilename string
	Plaintext []byte
	TTL time.Duration
}
type ArtifactPutResult struct {
	ArtifactID string
	Version uint64
	Size int64
	ExpiresAt time.Time
}
type ArtifactConsumeRequest struct { ArtifactID string }
type ArtifactResult struct {
	ArtifactID string
	OperationID string
	OwnerPrincipalID string
	MediaType string
	SafeFilename string
	Size int64
	Plaintext []byte
	ExpiresAt time.Time
	ConsumedAt time.Time
}
type PayloadCodec interface {
	Encrypt(context.Context, []byte) ([]byte, []byte, string, error)
	Decrypt(context.Context, []byte, []byte, string) ([]byte, error)
}
type ArtifactCodec = PayloadCodec

// ConflictError carries only stream identities and versions, never event data.
type ConflictError struct { Conflicts []StreamConflict }

func (e *ConflictError) Error() string { return ErrConflict.Error() }
func (e *ConflictError) Unwrap() error { return ErrConflict }

// InboxClaimRequest and InboxLease are domain-neutral lease contracts.
type InboxClaimRequest struct { WorkerID string; LeaseDuration time.Duration }
type InboxLease struct { Update InboxUpdate }

type OutboxClaimRequest struct { WorkerID string; LeaseDuration time.Duration }
type OutboxLease struct { Effect NewEffect }

// OperationView excludes private encrypted context.
type OperationView struct {
	OperationID string
	Version     uint64
	Kind        string
	Status      string
	ResultCode  string
	ErrorCode   string
	ArtifactID string
	CreatedAt time.Time
	UpdatedAt time.Time
	ExpiresAt time.Time
}
type Readiness struct {
	Mode                  string
	SchemaVersion         uint32
	DatabaseIdentity      string
	IndexRootID           string
	EncryptionRootIDs     []string
	SourceManifestDigest  []byte
	TargetManifestDigest  []byte
	TerminalGlobalPosition uint64
	TerminalProjectionPosition uint64
	CompletedAt            time.Time
}

type EncryptionRoot struct {
	ID       string
	Material []byte
}

// KeySource supplies a stable index root and versioned encryption roots.
// It is intentionally an opaque interface so deployments can wrap KMS/HSM
// implementations without importing their types into eventstore.
type KeySource interface{}

type SecretPutRequest struct {
	SecretRef       string
	EndpointID      string
	AdapterID       string
	SecretVersion   uint64
	ExpectedVersion uint64
	Plaintext       []byte
}

type PluginKVPutRequest struct {
	ExtensionID     string
	Key             string
	Value           []byte
	ExpectedVersion uint64
}

type PluginKVItem struct {
	ExtensionID string
	Key         string
	Value       []byte
	Version     uint64
}

type PluginKVListRequest struct {
	ExtensionID string
	Prefix      string
	Limit       int
}

type EncryptionRotationResult struct {
	Updated int
	Skipped int
	CurrentRootID string
}

type RebuildRequest struct { ProjectorVersion string }
type RebuildResult struct { GenerationID string; TerminalPosition uint64; Digest EventChecksum }
type PrivacyPurgeRequest struct { OperationID string; Scope string; AllowActive bool }
type PrivacyPurgeResult struct { OperationID string; Deleted int64 }
type SecretResolution struct { SecretRef string; SecretVersion uint64; Plaintext []byte }

// Separate narrow repository contracts deliberately keep Store aggregate-only.
type InboxRepository interface {
	AcceptInbox(context.Context, InboxUpdate) (CommitResult, error)
	ClaimInbox(context.Context, InboxClaimRequest) (InboxLease, error)
	UpdateInbox(context.Context, InboxUpdate) (CommitResult, error)
	ResolveInbox(context.Context, InboxResolutionRequest) (CommitResult, error)
}
type OutboxRepository interface {
	AcceptOutbox(context.Context, NewEffect) (CommitResult, error)
	ClaimOutbox(context.Context, OutboxClaimRequest) (OutboxLease, error)
	UpdateOutbox(context.Context, NewEffect) (CommitResult, error)
	RenewOutbox(context.Context, OutboxRenewRequest) (OutboxLease, error)
	MarkOutboxDispatched(context.Context, OutboxDispatchRequest) (OutboxLease, error)
	CompleteOutbox(context.Context, OutboxCompletionRequest) (CommitResult, error)
	ResolveOutbox(context.Context, OutboxResolutionRequest) (CommitResult, error)
}
type ArtifactRepository interface {
	PutArtifact(context.Context, ArtifactPutRequest) (ArtifactPutResult, error)
	ConsumeArtifact(context.Context, ArtifactConsumeRequest) (ArtifactResult, error)
}
type OperationRepository interface {
	GetOperation(context.Context, string) (OperationView, error)
}
type ReadinessRepository interface {
	GetReadiness(context.Context) (Readiness, error)
	SetReadiness(context.Context, Readiness) error
}
type ProjectionRebuilder interface {
	Rebuild(context.Context, RebuildRequest) (RebuildResult, error)
}
type PrivacyPurger interface {
	Purge(context.Context, PrivacyPurgeRequest) (PrivacyPurgeResult, error)
}
type SecretResolver interface {
	ResolveSecret(context.Context, string, uint64) (SecretResolution, error)
}
type SecretRepository interface {
	PutSecret(context.Context, SecretPutRequest) (SecretResolution, error)
	ResolveSecret(context.Context, string, uint64) (SecretResolution, error)
}
type PluginKVRepository interface {
	GetPluginKV(context.Context, string, string) (PluginKVItem, error)
	SetPluginKV(context.Context, PluginKVPutRequest) (PluginKVItem, error)
	DeletePluginKV(context.Context, string, string, uint64) error
	ListPluginKV(context.Context, PluginKVListRequest) ([]PluginKVItem, error)
}
type EncryptionRotator interface {
	RotateEncryptionRoots(context.Context) (EncryptionRotationResult, error)
}
