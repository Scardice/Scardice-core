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
	ErrInvalidEvent         = errors.New("eventstore: invalid event")
	ErrInvalidMetadata      = errors.New("eventstore: invalid metadata")
	ErrUnsupportedSchema    = errors.New("eventstore: unsupported schema")
	ErrConflict             = errors.New("eventstore: conflict")
	ErrEmptyUnitOfWork      = errors.New("eventstore: empty unit of work")
	ErrDuplicateStream      = errors.New("eventstore: duplicate stream")
	ErrDuplicateParticipant = errors.New("eventstore: duplicate participant")
	ErrOversizeInput        = errors.New("eventstore: input exceeds configured bound")
	ErrStaleLease           = errors.New("eventstore: stale lease")
	ErrNotFound             = errors.New("eventstore: not found")
	ErrInvalidTransition    = errors.New("eventstore: invalid state transition")
	ErrInvalidRiskClass     = errors.New("eventstore: invalid risk class")
	ErrArtifactGone         = errors.New("eventstore: artifact gone")
	ErrArtifactOwner        = errors.New("eventstore: artifact owner mismatch")
	ErrInvalidTTL           = errors.New("eventstore: invalid ttl")
	ErrDeduplicated         = errors.New("eventstore: deduplicated")
	ErrReadinessInvalid     = errors.New("eventstore: invalid readiness")
	ErrReadinessQuarantined = errors.New("eventstore: readiness quarantine")
	ErrPluginKVNotFound     = errors.New("eventstore: plugin key not found")
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
	EventID               string
	CommandID             string
	CorrelationID         string
	CausationID           string
	PrincipalID           string
	Producer              string
	OccurredAt            time.Time
	OccurredAtUnixNanoUTC int64
	OccurredAtUnixNanoSet bool
}

// StreamID identifies one aggregate stream without importing an aggregate type.
type StreamID struct {
	AggregateType string
	AggregateID   string
}

// StreamHead is the current version of one aggregate stream.
type StreamHead struct {
	Stream  StreamID
	Version uint64
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

// verifyEnvelopeChecksum preserves the checksum's nil-versus-empty payload
// marker when a SQL driver reports a zero-length BLOB as nil.
func verifyEnvelopeChecksum(event Envelope) (Envelope, error) {
	if ComputeEventChecksum(event) == event.Checksum {
		return event, nil
	}
	if event.Payload == nil {
		event.Payload = []byte{}
		if ComputeEventChecksum(event) == event.Checksum {
			return event, nil
		}
	}
	return Envelope{}, ErrChecksumMismatch
}

// writeCanonicalField is the one scalar encoding used by checksums. A marker
// value of zero is null; one is non-null. Non-null values, including empty
// strings/byte slices, retain a zero length rather than becoming null.
func writeCanonicalField(h interface {
	Write(data []byte) (int, error)
}, typeTag byte, isNull bool, value []byte) {
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

func writeCanonicalString(h interface {
	Write(data []byte) (int, error)
}, value string) {
	writeCanonicalField(h, 's', false, []byte(value))
}

func writeCanonicalOptionalString(h interface {
	Write(data []byte) (int, error)
}, value string) {
	writeCanonicalField(h, 's', value == "", []byte(value))
}

func writeCanonicalBytes(h interface {
	Write(data []byte) (int, error)
}, value []byte, isNull bool) {
	writeCanonicalField(h, 'b', isNull, value)
}

func writeCanonicalUint16(h interface {
	Write(data []byte) (int, error)
}, value uint16) {
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], value)
	writeCanonicalField(h, 'h', false, encoded[:])
}

func writeCanonicalUint64(h interface {
	Write(data []byte) (int, error)
}, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	writeCanonicalField(h, 'u', false, encoded[:])
}

func writeCanonicalInt64(h interface {
	Write(data []byte) (int, error)
}, value int64) {
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

// UnitOfWork is the complete storage input for one atomic commit. Read
// expectations are validated and held with the writes they protect; they do
// not count toward MaxUnitOfWorkStreams, which remains a write-stream bound.
// It may contain zero streams when one of the non-stream update lists or the
// execution terminal participant is non-empty.
type UnitOfWork struct {
	StreamReads            []StreamReadExpectation
	ProjectionReads        []ProjectionReadExpectation
	PluginKVReads          []PluginKVReadExpectation
	PluginKVNamespaceReads []PluginKVNamespaceReadExpectation
	CatalogReads           []CatalogReadExpectation
	CatalogUpdates         []CatalogRevisionUpdate
	Streams                []StreamAppend
	Operations             []OperationUpdate
	InboxUpdates           []InboxUpdate
	Effects                []NewEffect
	ArtifactUpdates        []ArtifactUpdate
	SecretUpdates          []SecretUpdate
	PluginKVUpdates        []PluginKVUpdate
	LogUpdates             []LogUpdate
	LogImports             []StoryLogImportRecord
	Execution              *ExecutionAttemptCommit
}

// CommitResult reports allocated event positions and participant versions.
type CommitResult struct {
	Events           []Envelope
	StreamVersions   map[StreamID]uint64
	OperationIDs     []string
	InboxIDs         []string
	EffectIDs        []string
	ArtifactIDs      []string
	SecretRefs       []string
	PluginKVIndexes  [][]byte
	Deduplicated     bool
	OrderingSequence uint64
	Idempotent       bool
	Version          uint64
}

// Store is intentionally limited to aggregate event operations.
type Store interface {
	Commit(ctx context.Context, work UnitOfWork) (CommitResult, error)
	Load(ctx context.Context, stream StreamID, afterVersion uint64) ([]Envelope, error)
	Close() error
}

// OperationUpdate carries command metadata and private context as raw bytes.
type OperationUpdate struct {
	OperationID      string
	ExpectedVersion  uint64
	Version          uint64
	Kind             string
	Status           string
	PrincipalID      string
	ResourceID       string
	RequestID        string
	CorrelationID    string
	IdempotencyScope string
	IdempotencyKey   string
	RequestDigest    []byte
	ResultCode       string
	ErrorCode        string
	ArtifactID       string
	PrivateContext   []byte
	CreatedAt        time.Time
	UpdatedAt        time.Time
	ExpiresAt        time.Time
}

type InboxUpdate struct {
	InboxID           string
	ExpectedVersion   uint64
	Version           uint64
	EndpointID        string
	ProviderEventKey  string
	Lane              string
	Subject           string
	OrderingSequence  uint64
	Status            string
	LeaseOwner        string
	LeaseEpoch        uint64
	LeaseExpiresAt    time.Time
	AttemptID         string
	Payload           []byte
	ContentDigest     []byte
	WorkflowID        string
	CallbackStartedAt time.Time
	CompletedAt       time.Time
	Resolution        string
	PrincipalID       string
	Reason            string
	ResolutionAt      time.Time
}

type NewEffect struct {
	EffectID          string
	ExpectedVersion   uint64
	Version           uint64
	EndpointID        string
	Lane              string
	Subject           string
	OrderingSequence  uint64
	EffectType        string
	RiskClass         string
	Status            string
	AttemptID         string
	LeaseOwner        string
	LeaseEpoch        uint64
	LeaseExpiresAt    time.Time
	DeadlineAt        time.Time
	NextAttemptAt     time.Time
	DispatchedAt      time.Time
	Payload           []byte
	ContentDigest     []byte
	ProviderMessageID string
	ResultCode        string
	ErrorCode         string
	CompletedAt       time.Time
	RetryCount        uint32
	Resolution        string
	PrincipalID       string
	Reason            string
	ResolutionAt      time.Time
}

type ArtifactUpdate struct {
	ArtifactID       string
	ExpectedVersion  uint64
	Version          uint64
	OperationID      string
	OwnerPrincipalID string
	MediaType        string
	SafeFilename     string
	Size             int64
	Status           string
	Data             []byte
	ExpiresAt        time.Time
	ConsumedAt       time.Time
}

type SecretUpdate struct {
	SecretRef       string
	ExpectedVersion uint64
	Version         uint64
	EndpointID      string
	AdapterID       string
	SecretVersion   uint64
	Value           []byte
	ValueSet        bool
	UpdatedAt       time.Time
}

type PluginKVUpdate struct {
	ExtensionID     string
	Key             string
	ExpectedVersion uint64
	Version         uint64
	Value           []byte
	Deleted         bool
	UpdatedAt       time.Time
}

// ValidateUnitOfWork performs pre-transaction validation and never includes
// payload content in errors.
func ValidateUnitOfWork(work UnitOfWork) error {
	if len(work.Streams) == 0 && len(work.Operations) == 0 && len(work.InboxUpdates) == 0 && len(work.Effects) == 0 && len(work.ArtifactUpdates) == 0 && len(work.SecretUpdates) == 0 && len(work.PluginKVUpdates) == 0 && len(work.LogUpdates) == 0 && len(work.LogImports) == 0 && len(work.CatalogUpdates) == 0 && work.Execution == nil {
		return ErrEmptyUnitOfWork
	}
	if len(work.Streams) > MaxUnitOfWorkStreams {
		return &OversizeError{Bound: "unit of work streams", Limit: MaxUnitOfWorkStreams, Actual: len(work.Streams)}
	}
	seen := make(map[StreamID]struct{}, len(work.Streams))
	streamExpectations := make(map[StreamID]uint64, len(work.StreamReads)+len(work.Streams))
	eventCount := 0
	var encodedBytes uint64
	addBytes := func(n int) {
		if n <= 0 || encodedBytes > MaxUnitOfWorkBytes {
			return
		}
		if uint64(n) > uint64(MaxUnitOfWorkBytes)-encodedBytes {
			encodedBytes = uint64(MaxUnitOfWorkBytes) + 1
			return
		}
		encodedBytes += uint64(n)
	}
	addFields := func(parts ...int) {
		for _, part := range parts {
			addBytes(part)
		}
	}
	for _, streamAppend := range work.Streams {
		if streamAppend.Stream.AggregateType == "" || streamAppend.Stream.AggregateID == "" {
			return ErrInvalidEvent
		}
		if _, exists := seen[streamAppend.Stream]; exists {
			return ErrDuplicateStream
		}
		seen[streamAppend.Stream] = struct{}{}
		addFields(len(streamAppend.Stream.AggregateType), len(streamAppend.Stream.AggregateID))
		eventCount += len(streamAppend.Events)
		for _, event := range streamAppend.Events {
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
	for _, read := range work.StreamReads {
		if read.Stream.AggregateType == "" || read.Stream.AggregateID == "" {
			return ErrInvalidEvent
		}
		if expected, exists := streamExpectations[read.Stream]; exists && expected != read.ExpectedVersion {
			return ErrConflict
		}
		streamExpectations[read.Stream] = read.ExpectedVersion
		addFields(len(read.Stream.AggregateType), len(read.Stream.AggregateID), 8)
	}
	for _, appendStream := range work.Streams {
		if expected, exists := streamExpectations[appendStream.Stream]; exists && expected != appendStream.ExpectedVersion {
			return ErrConflict
		}
		streamExpectations[appendStream.Stream] = appendStream.ExpectedVersion
	}
	for _, read := range work.ProjectionReads {
		if read.Generation == "" {
			return ErrInvalidMetadata
		}
		addFields(len(read.Generation), 8)
	}
	for _, read := range work.PluginKVReads {
		if read.Namespace == "" || len(read.Key) > MaxPluginKeyBytes {
			return ErrInvalidMetadata
		}
		addFields(len(read.Namespace), len(read.Key), 9)
	}
	for _, read := range work.PluginKVNamespaceReads {
		if read.Namespace == "" {
			return ErrInvalidMetadata
		}
		addFields(len(read.Namespace), 8)
	}
	for _, read := range work.CatalogReads {
		if read.Catalog == "" || read.Owner == "" {
			return ErrInvalidMetadata
		}
		addFields(len(read.Catalog), len(read.Owner), 8)
	}
	for _, update := range work.CatalogUpdates {
		if update.Catalog == "" || update.Owner == "" {
			return ErrInvalidMetadata
		}
		addFields(len(update.Catalog), len(update.Owner), 8)
	}
	if eventCount > MaxUnitOfWorkEvents {
		return &OversizeError{Bound: "unit of work events", Limit: MaxUnitOfWorkEvents, Actual: eventCount}
	}
	for _, update := range work.Operations {
		addFields(len(update.OperationID), len(update.Kind), len(update.Status), len(update.PrincipalID), len(update.ResourceID), len(update.IdempotencyScope), len(update.IdempotencyKey), len(update.RequestID), len(update.RequestDigest), len(update.CorrelationID), len(update.ResultCode), len(update.ErrorCode), len(update.ArtifactID), len(update.PrivateContext))
	}
	for _, update := range work.InboxUpdates {
		addFields(len(update.InboxID), len(update.EndpointID), len(update.ProviderEventKey), len(update.Lane), len(update.Subject), len(update.Status), len(update.LeaseOwner), len(update.AttemptID), len(update.Payload), len(update.WorkflowID))
	}
	for _, update := range work.Effects {
		addFields(len(update.EffectID), len(update.EndpointID), len(update.Lane), len(update.Subject), len(update.EffectType), len(update.RiskClass), len(update.Status), len(update.LeaseOwner), len(update.AttemptID), len(update.Payload), len(update.ContentDigest), len(update.ProviderMessageID), len(update.ResultCode), len(update.ErrorCode))
	}
	for _, update := range work.ArtifactUpdates {
		addFields(len(update.ArtifactID), len(update.OperationID), len(update.OwnerPrincipalID), len(update.MediaType), len(update.SafeFilename), len(update.Data))
	}
	for _, update := range work.SecretUpdates {
		addFields(len(update.SecretRef), len(update.EndpointID), len(update.AdapterID), len(update.Value))
	}
	for _, update := range work.PluginKVUpdates {
		addFields(len(update.ExtensionID), len(update.Key), len(update.Value))
	}
	if work.Execution != nil {
		if err := validateExecutionAttemptCommit(*work.Execution); err != nil {
			return err
		}
		addFields(len(work.Execution.Identity), len(work.Execution.RequestDigest), len(work.Execution.AttemptID), len(work.Execution.LeaseOwner), 16)
	}
	if err := validateStoryLogUpdates(work.LogUpdates); err != nil {
		return err
	}
	for _, update := range work.LogUpdates {
		addFields(len(update.Kind), len(update.DiceID), len(update.GroupID), len(update.Name), len(update.RawMsgID), len(update.EffectID), len(update.UploadURL),
			len(update.Entry.Message), len(update.Entry.Nickname), len(update.Entry.IMUserID), len(update.Entry.RawMsgID),
			len(update.Entry.UniformID), len(update.Entry.CommandInfo), len(update.Intent.EffectID), len(update.Intent.Entry.Message),
			len(update.Intent.Entry.Nickname), len(update.Intent.Entry.IMUserID), len(update.Intent.Entry.RawMsgID), len(update.Intent.Entry.CommandInfo))
	}
	if err := validateStoryLogImports(work.LogImports); err != nil {
		return err
	}
	for _, record := range work.LogImports {
		addFields(len(record.SourceID), len(record.Kind), len(record.DiceID), len(record.GroupID), len(record.SessionSourceID))
		if record.Session != nil {
			addFields(len(record.Session.Name), len(record.Session.UploadURL))
			if record.Session.Extra != nil {
				addBytes(len(*record.Session.Extra))
			}
		}
		if record.Entry != nil {
			addFields(len(record.Entry.LogName), len(record.Entry.Nickname), len(record.Entry.IMUserID), len(record.Entry.Message),
				len(record.Entry.CommandInfo), len(record.Entry.RawMsgID), len(record.Entry.UniformID))
		}
		if record.State != nil {
			addFields(len(record.State.Name))
		}
	}
	if encodedBytes > MaxUnitOfWorkBytes {
		actual := int(encodedBytes)
		return &OversizeError{Bound: "unit of work encoded bytes", Limit: MaxUnitOfWorkBytes, Actual: actual}
	}
	if err := validateParticipantKeys(work); err != nil {
		return err
	}
	return nil
}

func validateParticipantKeys(work UnitOfWork) error {
	seen := func() map[string]struct{} { return make(map[string]struct{}) }
	check := func(m map[string]struct{}, key string) error {
		if _, ok := m[key]; ok {
			return ErrDuplicateParticipant
		}
		m[key] = struct{}{}
		return nil
	}
	type pair struct{ first, second string }
	checkPair := func(m map[pair]struct{}, key pair) error {
		if _, ok := m[key]; ok {
			return ErrDuplicateParticipant
		}
		m[key] = struct{}{}
		return nil
	}
	ops, arts, secrets, inbox, effects := seen(), seen(), seen(), seen(), seen()
	plugins, catalogs := make(map[pair]struct{}), make(map[pair]struct{})
	for _, v := range work.Operations {
		if v.OperationID != "" {
			if err := check(ops, v.OperationID); err != nil {
				return err
			}
		}
	}
	for _, v := range work.ArtifactUpdates {
		if v.ArtifactID != "" {
			if err := check(arts, v.ArtifactID); err != nil {
				return err
			}
		}
	}
	for _, v := range work.SecretUpdates {
		if v.SecretRef != "" {
			if err := check(secrets, v.SecretRef); err != nil {
				return err
			}
		}
	}
	for _, v := range work.InboxUpdates {
		if v.InboxID != "" {
			if err := check(inbox, v.InboxID); err != nil {
				return err
			}
		}
	}
	for _, v := range work.Effects {
		if v.EffectID != "" {
			if err := check(effects, v.EffectID); err != nil {
				return err
			}
		}
	}
	for _, v := range work.PluginKVUpdates {
		if v.ExtensionID != "" && v.Key != "" {
			if err := checkPair(plugins, pair{v.ExtensionID, v.Key}); err != nil {
				return err
			}
		}
	}
	for _, v := range work.CatalogUpdates {
		if v.Catalog != "" && v.Owner != "" {
			if err := checkPair(catalogs, pair{v.Catalog, v.Owner}); err != nil {
				return err
			}
		}
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

type InboxResolutionRequest struct {
	InboxID         string
	ExpectedVersion uint64
	Resolution      string
	PrincipalID     string
	Reason          string
}
type OutboxRenewRequest struct {
	EffectID      string
	WorkerID      string
	LeaseEpoch    uint64
	AttemptID     string
	LeaseDuration time.Duration
}
type OutboxDispatchRequest struct {
	EffectID   string
	WorkerID   string
	LeaseEpoch uint64
	AttemptID  string
}
type OutboxPreDispatchRequeueRequest struct {
	EffectID      string
	WorkerID      string
	LeaseEpoch    uint64
	AttemptID     string
	RetryCount    uint32
	NextAttemptAt time.Time
}
type OutboxCompletionRequest struct {
	EffectID          string
	WorkerID          string
	LeaseEpoch        uint64
	AttemptID         string
	Status            string
	ResultCode        string
	ErrorCode         string
	ProviderMessageID string
}
type OutboxResolutionRequest struct {
	EffectID        string
	ExpectedVersion uint64
	Resolution      string
	PrincipalID     string
	Reason          string
}

// OutboxQuarantineRequest settles a dispatcher-owned lease after a durable
// validation or persistence failure. Implementations must CAS all lease fields.
type OutboxQuarantineRequest struct {
	EffectID        string
	ExpectedVersion uint64
	WorkerID        string
	LeaseEpoch      uint64
	AttemptID       string
	ErrorCode       string
	Reason          string
}
type ArtifactPutRequest struct {
	ArtifactID       string
	OperationID      string
	OwnerPrincipalID string
	MediaType        string
	SafeFilename     string
	Plaintext        []byte
	TTL              time.Duration
}
type ArtifactPutResult struct {
	ArtifactID string
	Version    uint64
	Size       int64
	ExpiresAt  time.Time
}
type ArtifactConsumeRequest struct {
	ArtifactID       string
	OwnerPrincipalID string
}
type ArtifactResult struct {
	ArtifactID       string
	OperationID      string
	OwnerPrincipalID string
	MediaType        string
	SafeFilename     string
	Size             int64
	Plaintext        []byte
	ExpiresAt        time.Time
	ConsumedAt       time.Time
}

// ConflictError carries only stream identities and versions, never event data.
type ConflictError struct{ Conflicts []StreamConflict }

func (e *ConflictError) Error() string { return ErrConflict.Error() }
func (e *ConflictError) Unwrap() error { return ErrConflict }

// InboxClaimRequest configures one inbox lease acquisition.
type InboxClaimRequest struct {
	WorkerID      string
	LeaseDuration time.Duration
}
type InboxRenewRequest struct {
	InboxID       string
	WorkerID      string
	LeaseEpoch    uint64
	AttemptID     string
	LeaseDuration time.Duration
}

type InboxLease struct{ Update InboxUpdate }

type OutboxClaimRequest struct {
	WorkerID      string
	LeaseDuration time.Duration
}
type OutboxLease struct{ Effect NewEffect }

// OperationView excludes private context.
type OperationView struct {
	OperationID      string
	Version          uint64
	Kind             string
	Status           string
	ResultCode       string
	ErrorCode        string
	ArtifactID       string
	PrincipalID      string
	ResourceID       string
	IdempotencyScope string
	IdempotencyKey   string
	RequestID        string
	RequestDigest    []byte
	CorrelationID    string
	CreatedAt        time.Time
	UpdatedAt        time.Time
	ExpiresAt        time.Time
}
type Readiness struct {
	Mode             string
	SchemaVersion    uint32
	DatabaseIdentity string
	CompletedAt      time.Time
}

type SecretPutRequest struct {
	SecretRef       string
	EndpointID      string
	AdapterID       string
	SecretVersion   uint64
	ExpectedVersion uint64
	Value           []byte
}

type SecretLookup struct {
	SecretRef     string
	SecretVersion uint64
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

type RebuildRequest struct{ ProjectorVersion string }
type RebuildResult struct {
	GenerationID     string
	TerminalPosition uint64
	Digest           EventChecksum
}

// PrivacyCounts are exact counts of durable event-store records selected by a
// controlled group purge. Counts are intentionally split by scope.
type PrivacyCounts struct {
	GroupRecord int64 `json:"groupRecord"`
	Players     int64 `json:"players"`
	Attrs       int64 `json:"attrs"`
	LogSessions int64 `json:"logSessions"`
	LogStates   int64 `json:"logStates"`
	LogEntries  int64 `json:"logEntries"`
	LogIntents  int64 `json:"logIntents"`
	LogImports  int64 `json:"logImports"`
	Inbox       int64 `json:"inbox"`
	Outbox      int64 `json:"outbox"`
	Secrets     int64 `json:"secrets"`
	Projections int64 `json:"projections"`
}

type PrivacyDryRunRequest struct {
	GroupID       string
	ActiveDiceIDs []string
	DiceIDs       []string
	Scopes        []string
}

type PrivacyDryRunResult struct {
	Version         uint64
	Digest          []byte
	Counts          PrivacyCounts
	ActiveDiceIDs   []string
	ExistingDiceIDs []string
	Uncovered       []string
}

type PrivacyDeleteRequest struct {
	PrivacyDryRunRequest
	AllowActive         bool
	ConfirmationDigest  []byte
	ConfirmationVersion uint64
}

type PrivacyDeleteResult struct {
	Scan    PrivacyDryRunResult
	Deleted PrivacyCounts
}

type SecretResolution struct {
	SecretRef     string
	SecretVersion uint64
	Value         []byte
}

// Separate narrow repository contracts deliberately keep Store aggregate-only.
type InboxRepository interface {
	AcceptInbox(ctx context.Context, update InboxUpdate) (CommitResult, error)
	ClaimInbox(ctx context.Context, request InboxClaimRequest) (InboxLease, error)
	RenewInbox(ctx context.Context, request InboxRenewRequest) (InboxLease, error)
	UpdateInbox(ctx context.Context, update InboxUpdate) (CommitResult, error)
	ResolveInbox(ctx context.Context, request InboxResolutionRequest) (CommitResult, error)
}
type OutboxRepository interface {
	AcceptOutbox(ctx context.Context, effect NewEffect) (CommitResult, error)
	ClaimOutbox(ctx context.Context, request OutboxClaimRequest) (OutboxLease, error)
	UpdateOutbox(ctx context.Context, effect NewEffect) (CommitResult, error)
	RequeuePreDispatch(ctx context.Context, request OutboxPreDispatchRequeueRequest) (CommitResult, error)
	RenewOutbox(ctx context.Context, request OutboxRenewRequest) (OutboxLease, error)
	MarkOutboxDispatched(ctx context.Context, request OutboxDispatchRequest) (OutboxLease, error)
	CompleteOutbox(ctx context.Context, request OutboxCompletionRequest) (CommitResult, error)
	ResolveOutbox(ctx context.Context, request OutboxResolutionRequest) (CommitResult, error)
}
type OutboxQuarantineRepository interface {
	QuarantineOutbox(ctx context.Context, request OutboxQuarantineRequest) (CommitResult, error)
}
type ArtifactRepository interface {
	PutArtifact(ctx context.Context, request ArtifactPutRequest) (ArtifactPutResult, error)
	ConsumeArtifact(ctx context.Context, request ArtifactConsumeRequest) (ArtifactResult, error)
}
type OperationRepository interface {
	GetOperation(ctx context.Context, operationID string) (OperationView, error)
}
type ReadinessRepository interface {
	GetReadiness(ctx context.Context) (Readiness, error)
	SetReadiness(ctx context.Context, readiness Readiness) error
}

// GroupPrivacyRepository atomically checks confirmation and deletes selected group data.
type GroupPrivacyRepository interface {
	PrivacyDryRun(ctx context.Context, request PrivacyDryRunRequest) (PrivacyDryRunResult, error)
	PrivacyDeleteGroup(ctx context.Context, request PrivacyDeleteRequest) (PrivacyDeleteResult, error)
}

type ProjectionRebuilder interface {
	Rebuild(ctx context.Context, request RebuildRequest) (RebuildResult, error)
}
type SecretResolver interface {
	ResolveSecret(ctx context.Context, secretRef string, version uint64) (SecretResolution, error)
}

type SecretBatchResolver interface {
	ResolveSecrets(ctx context.Context, lookups []SecretLookup) ([]SecretResolution, error)
}

// SecretOwnerResolver resolves endpoint secrets only after filtering by owner.
type SecretOwnerResolver interface {
	ResolveSecretForOwner(ctx context.Context, endpointID, adapterID, secretRef string, version uint64) (SecretResolution, error)
}
type SecretRepository interface {
	PutSecret(ctx context.Context, request SecretPutRequest) (SecretResolution, error)
	ResolveSecret(ctx context.Context, secretRef string, version uint64) (SecretResolution, error)
}
type PluginKVRepository interface {
	GetPluginKV(ctx context.Context, extension, key string) (PluginKVItem, error)
	SetPluginKV(ctx context.Context, request PluginKVPutRequest) (PluginKVItem, error)
	DeletePluginKV(ctx context.Context, extension, key string, expectedVersion uint64) error
	ListPluginKV(ctx context.Context, request PluginKVListRequest) ([]PluginKVItem, error)
}
