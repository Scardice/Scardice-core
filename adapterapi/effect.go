package adapterapi

import (
	"fmt"
	"time"
)

const (
	MaxEffectTextBytes     = 256 * 1024
	MaxEffectParameters    = 64
	MaxEffectFieldBytes    = 4 * 1024
	MaxArtifactResultBytes = 16 * 1024 * 1024
)

// EffectKind is the closed top-level union of outbound operations.
type EffectKind uint8

const (
	EffectKindInvalid EffectKind = iota
	EffectKindMessage
	EffectKindAction
)

func (kind EffectKind) Valid() bool { return kind == EffectKindMessage || kind == EffectKindAction }

// EffectParameter is a bounded, non-secret action parameter. Provider
// runtimes translate it to SDK input; raw SDK requests do not cross the seam.
type EffectParameter struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// ArtifactInput refers to an already durable artifact. It carries metadata and
// an ID only; outbound effects never carry local paths or secret bytes.
type ArtifactInput struct {
	ID          ArtifactID `json:"id"`
	ContentType string     `json:"contentType,omitempty"`
	Filename    string     `json:"filename,omitempty"`
}

// OutboundEffect is a closed DTO consumed by AdapterRuntime.Execute. Its
// payload is intentionally limited to normalized fields and typed parameters.
type OutboundEffect struct {
	Version    EffectVersion     `json:"version,omitempty"`
	ID         EffectID           `json:"id"`
	EndpointID EndpointID         `json:"endpointId,omitempty"`
	OperationID OperationID       `json:"operationId,omitempty"`
	CorrelationID CorrelationID   `json:"correlationId,omitempty"`
	CausationID  CausationID      `json:"causationId,omitempty"`
	Lane       LaneMetadata       `json:"lane,omitempty"`
	Deadline   time.Time          `json:"deadline,omitempty"`
	Risk       EffectRisk         `json:"risk,omitempty"`
	RetryClass EffectRetryClass   `json:"retryClass,omitempty"`
	RequiredCapabilities CapabilitySet `json:"requiredCapabilities,omitempty"`
	RequiredAction ActionKind     `json:"requiredAction,omitempty"`
	Kind       EffectKind         `json:"kind"`
	Action     ActionKind         `json:"action,omitempty"`
	Target     ConversationID     `json:"target,omitempty"`
	Text       string             `json:"text,omitempty"`
	ReplyTo    MessageID          `json:"replyTo,omitempty"`
	Parameters []EffectParameter  `json:"parameters,omitempty"`
	Artifact   *ArtifactInput     `json:"artifact,omitempty"`
	Payload    EffectPayload      `json:"payload,omitempty"`
}

func (effect OutboundEffect) Validate() error {
	if !effect.ID.Valid() || !effect.Kind.Valid() {
		return fmt.Errorf("%w: effect identity or kind", ErrInvalidContract)
	}
	if effect.Version != 0 {
		if effect.Version != EffectVersionOne || !effect.EndpointID.Valid() || !effect.OperationID.Valid() || effect.CorrelationID == "" || effect.CausationID == "" || !effect.CorrelationID.Valid() || !effect.CausationID.Valid() || !effect.Risk.Valid() || effect.Deadline.IsZero() || func() bool { _, err := effect.Deadline.MarshalJSON(); return err != nil }() || effect.Action != 0 || effect.Target != "" || effect.Text != "" || effect.ReplyTo != "" || len(effect.Parameters) != 0 || effect.Artifact != nil {
			return fmt.Errorf("%w: invalid versioned effect metadata", ErrInvalidContract)
		}
		expectedKind, expectedCaps, expectedAction, expectedRetry, expectedRisk, ok := payloadContract(effect.Payload.Kind)
		if effect.Payload.Kind == EffectPayloadSegments {
			for _, segment := range effect.Payload.Segments { if segment.Artifact != nil { expectedCaps |= CapabilityArtifacts; break } }
		}
		if !ok || effect.Kind != expectedKind || effect.RequiredCapabilities != expectedCaps || effect.RequiredAction != expectedAction || effect.RetryClass != expectedRetry || effect.Risk != expectedRisk {
			return fmt.Errorf("%w: versioned effect metadata does not match payload", ErrInvalidContract)
		}
		if err := effect.Lane.Validate(); err != nil || effect.Lane.EndpointID != effect.EndpointID { return fmt.Errorf("%w: lane does not bind effect target", ErrInvalidContract) }
		if err := effect.Payload.Validate(); err != nil { return err }
		return nil
	}
	if effect.EndpointID != "" || effect.OperationID != "" || effect.CorrelationID != "" || effect.CausationID != "" || effect.Lane != (LaneMetadata{}) || !effect.Deadline.IsZero() || effect.Risk != 0 || effect.RetryClass != 0 || effect.RequiredCapabilities != 0 || effect.RequiredAction != 0 || effect.Payload.Kind != 0 || effect.Payload.Target != (EffectTarget{}) || effect.Payload.Text != "" || len(effect.Payload.Segments) != 0 || effect.Payload.File != (ArtifactInput{}) || effect.Payload.MessageID != "" || effect.Payload.Card != "" || effect.Payload.DurationSeconds != 0 || effect.Payload.Reason != "" {
		return fmt.Errorf("%w: versioned fields require effect version", ErrInvalidContract)
	}
	if effect.Kind == EffectKindAction && !effect.Action.Valid() {
		return fmt.Errorf("%w: action effect missing closed action", ErrInvalidContract)
	}
	if effect.Kind == EffectKindMessage && effect.Action != 0 {
		return fmt.Errorf("%w: message effect cannot carry action", ErrInvalidContract)
	}
	if (effect.Target != "" && !effect.Target.Valid()) || (effect.ReplyTo != "" && !effect.ReplyTo.Valid()) {
		return fmt.Errorf("%w: invalid optional effect identifier", ErrInvalidContract)
	}
	if len(effect.Text) > MaxEffectTextBytes || len(effect.Parameters) > MaxEffectParameters {
		return fmt.Errorf("%w: effect payload exceeds bounds", ErrInvalidContract)
	}
	for _, parameter := range effect.Parameters {
		if len(parameter.Key) == 0 || len(parameter.Key) > MaxEffectFieldBytes || len(parameter.Value) > MaxEffectTextBytes {
			return fmt.Errorf("%w: effect parameter exceeds bounds", ErrInvalidContract)
		}
	}
	if effect.Artifact != nil {
		if err := effect.Artifact.Validate(); err != nil { return err }
	}
	return nil
}

func (effect OutboundEffect) ValidateForCapabilities(capabilities CapabilitySet, actions ActionSet) error {
	if err := effect.Validate(); err != nil { return err }
	if !capabilities.Valid() || !actions.Valid() || !capabilities.Has(effect.RequiredCapabilities) { return ErrUnsupportedAction }
	if effect.RequiredAction != 0 && !actions.Has(effect.RequiredAction) { return ErrUnsupportedAction }
	return nil
}

// EffectOutcome distinguishes unsupported capability, retryable provider
// failure, terminal provider failure, and post-dispatch ambiguity.
type EffectOutcome uint8

const (
	EffectOutcomeInvalid EffectOutcome = iota
	EffectSucceeded
	EffectUnsupported
	EffectRetryable
	EffectTerminal
	EffectAmbiguous
)

func (outcome EffectOutcome) Valid() bool {
	switch outcome { case EffectSucceeded, EffectUnsupported, EffectRetryable, EffectTerminal, EffectAmbiguous: return true }
	return false
}

// EffectResult is always tagged with a non-zero outcome. Provider IDs and
// bounded messages are metadata; ArtifactResult is the only place bytes may
// temporarily exist and is explicitly sensitive/ephemeral.
type EffectResult struct {
	Outcome    EffectOutcome  `json:"outcome"`
	Code       string         `json:"code,omitempty"`
	Message    string         `json:"message,omitempty"`
	ProviderID string         `json:"providerId,omitempty"`
	Artifact   *ArtifactResult `json:"artifact,omitempty"`
}

func (result EffectResult) Validate() error {
	if !result.Outcome.Valid() {
		return fmt.Errorf("%w: effect result has no classified outcome", ErrInvalidContract)
	}
	if result.ProviderID != "" && !validOptionalIdentifier(result.ProviderID) {
		return fmt.Errorf("%w: invalid optional effect provider id", ErrInvalidContract)
	}
	if len(result.Code) > MaxEffectFieldBytes || len(result.Message) > MaxEffectTextBytes || len(result.ProviderID) > MaxEffectFieldBytes {
		return fmt.Errorf("%w: effect result exceeds bounds", ErrInvalidContract)
	}
	if result.Artifact != nil {
		return result.Artifact.Validate()
	}
	return nil
}

func SucceededResult(providerID string) EffectResult {
	return EffectResult{Outcome: EffectSucceeded, ProviderID: providerID}
}
func UnsupportedResult(code string) EffectResult {
	return EffectResult{Outcome: EffectUnsupported, Code: code}
}
func RetryableResult(code, message string) EffectResult {
	return EffectResult{Outcome: EffectRetryable, Code: code, Message: message}
}
func TerminalResult(code, message string) EffectResult {
	return EffectResult{Outcome: EffectTerminal, Code: code, Message: message}
}
func AmbiguousResult(code, message string) EffectResult {
	return EffectResult{Outcome: EffectAmbiguous, Code: code, Message: message}
}

// ArtifactResult is an in-memory handoff only. Bytes are deliberately omitted
// from JSON and must be consumed immediately by the dispatcher, which encrypts
// them into artifact storage and retains metadata in events.
type ArtifactResult struct {
	ID          ArtifactID `json:"id,omitempty"`
	ContentType string     `json:"contentType,omitempty"`
	Filename    string     `json:"filename,omitempty"`
	Bytes       []byte     `json:"-"`
	Sensitive   bool         `json:"sensitive"`
	Ephemeral   bool         `json:"ephemeral"`
}

func NewArtifactResult(contentType, filename string, bytes []byte) ArtifactResult {
	return ArtifactResult{
		ContentType: contentType,
		Filename:    filename,
		Bytes:       append([]byte(nil), bytes...),
		Sensitive:   true,
		Ephemeral:   true,
	}
}

func (artifact ArtifactResult) Validate() error {
	if !artifact.Sensitive || !artifact.Ephemeral {
		return fmt.Errorf("%w: artifact result must be sensitive and ephemeral", ErrInvalidContract)
	}
	if artifact.ID != "" && !artifact.ID.Valid() {
		return fmt.Errorf("%w: invalid artifact result id", ErrInvalidContract)
	}
	if len(artifact.Bytes) > MaxArtifactResultBytes {
		return fmt.Errorf("%w: artifact result exceeds bounds", ErrInvalidContract)
	}
	if len(artifact.ContentType) > MaxEffectFieldBytes || !safeArtifactFilename(artifact.Filename) {
		return fmt.Errorf("%w: artifact metadata exceeds bounds", ErrInvalidContract)
	}
	return nil
}
