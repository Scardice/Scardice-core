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
)

var (
	ErrInvalidEvent      = errors.New("eventstore: invalid event")
	ErrInvalidMetadata   = errors.New("eventstore: invalid metadata")
	ErrUnsupportedSchema = errors.New("eventstore: unsupported schema")
	ErrConflict          = errors.New("eventstore: conflict")
	ErrEmptyUnitOfWork   = errors.New("eventstore: empty unit of work")
	ErrDuplicateStream   = errors.New("eventstore: duplicate stream")
	ErrOversizeInput     = errors.New("eventstore: input exceeds configured bound")
	ErrStaleLease        = errors.New("eventstore: stale lease")
	ErrNotFound          = errors.New("eventstore: not found")
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
	if metadata.OccurredAt.IsZero() && metadata.OccurredAtUnixNanoUTC == 0 {
		if f.Clock == nil {
			return NewEvent{}, ErrInvalidMetadata
		}
		metadata.OccurredAt = f.Clock.Now()
	}
	if !metadata.OccurredAt.IsZero() {
		metadata.OccurredAt = metadata.OccurredAt.UTC()
		metadata.OccurredAtUnixNanoUTC = metadata.OccurredAt.UnixNano()
	}
	if metadata.OccurredAtUnixNanoUTC == 0 {
		return NewEvent{}, ErrInvalidMetadata
	}
	return NewEvent{EventType: eventType, SchemaVersion: schemaVersion, Payload: payload, Metadata: metadata}, nil
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
	if event.Metadata.EventID == "" || event.Metadata.CommandID == "" || event.Metadata.CorrelationID == "" || event.Metadata.OccurredAtUnixNanoUTC == 0 {
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
// Every scalar is length-prefixed, and the payload bytes are included verbatim.
func ComputeEventChecksum(event Envelope) EventChecksum {
	h := sha256.New()
	writeChecksumString(h, "SCARDICE-EVENT-V1")
	writeChecksumString(h, event.Stream.AggregateType)
	writeChecksumString(h, event.Stream.AggregateID)
	writeChecksumUint64(h, event.StreamVersion)
	writeChecksumUint64(h, event.GlobalPosition)
	writeChecksumString(h, event.EventID)
	writeChecksumString(h, event.EventType)
	writeChecksumUint16(h, event.SchemaVersion)
	writeChecksumString(h, event.Metadata.EventID)
	writeChecksumString(h, event.Metadata.CommandID)
	writeChecksumString(h, event.Metadata.CorrelationID)
	writeChecksumString(h, event.Metadata.CausationID)
	writeChecksumString(h, event.Metadata.PrincipalID)
	writeChecksumString(h, event.Metadata.Producer)
	writeChecksumInt64(h, event.Metadata.OccurredAtUnixNanoUTC)
	writeChecksumBytes(h, event.Payload)
	var checksum EventChecksum
	copy(checksum[:], h.Sum(nil))
	return checksum
}

func writeChecksumBytes(h interface{ Write([]byte) (int, error) }, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = h.Write(length[:])
	_, _ = h.Write(value)
}

func writeChecksumString(h interface{ Write([]byte) (int, error) }, value string) {
	writeChecksumBytes(h, []byte(value))
}

func writeChecksumUint16(h interface{ Write([]byte) (int, error) }, value uint16) {
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], value)
	_, _ = h.Write(encoded[:])
}

func writeChecksumUint64(h interface{ Write([]byte) (int, error) }, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = h.Write(encoded[:])
}

func writeChecksumInt64(h interface{ Write([]byte) (int, error) }, value int64) {
	writeChecksumUint64(h, uint64(value))
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
	PayloadNonce            []byte
	ContentDigest          []byte
	DigestKeyID            string
	ProviderMessageID      string
	ResultCode             string
	ErrorCode              string
	CompletedAt            time.Time
	PayloadExpiresAt        time.Time
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
	encodedBytes := 0
	for _, append := range work.Streams {
		if append.Stream.AggregateType == "" || append.Stream.AggregateID == "" {
			return ErrInvalidEvent
		}
		if _, exists := seen[append.Stream]; exists {
			return ErrDuplicateStream
		}
		seen[append.Stream] = struct{}{}
		eventCount += len(append.Events)
		for _, event := range append.Events {
			if event.EventType == "" || event.SchemaVersion == 0 {
				return ErrInvalidEvent
			}
			if len(event.Payload) > MaxEventPayloadBytes {
				return &OversizeError{Bound: "event payload", Limit: MaxEventPayloadBytes, Actual: len(event.Payload)}
			}
			encodedBytes += len(event.Payload)
		}
	}
	if eventCount > MaxUnitOfWorkEvents {
		return &OversizeError{Bound: "unit of work events", Limit: MaxUnitOfWorkEvents, Actual: eventCount}
	}
	if encodedBytes > MaxUnitOfWorkBytes {
		return &OversizeError{Bound: "unit of work encoded bytes", Limit: MaxUnitOfWorkBytes, Actual: encodedBytes}
	}
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
	ArtifactID  string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	ExpiresAt   time.Time
}

type Readiness struct {
	Mode                  string
	SchemaVersion         uint32
	DatabaseIdentity      string
	IndexRootID           string
	TerminalGlobalPosition uint64
	TerminalProjectionPosition uint64
	CompletedAt            time.Time
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
}
type OutboxRepository interface {
	ClaimOutbox(context.Context, OutboxClaimRequest) (OutboxLease, error)
	UpdateOutbox(context.Context, NewEffect) (CommitResult, error)
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
