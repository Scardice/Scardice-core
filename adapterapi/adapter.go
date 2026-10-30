// Package adapterapi defines the dependency-leaf contract between Core and
// endpoint-owned adapter runtimes. It intentionally imports only the standard
// library; provider SDKs and Core objects stay on their respective sides.
package adapterapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	ErrInvalidID         = errors.New("adapterapi: invalid id")
	ErrInvalidConfig     = errors.New("adapterapi: invalid config")
	ErrInvalidContract   = errors.New("adapterapi: invalid contract value")
	ErrUnsupportedAction = errors.New("adapterapi: unsupported action")
)

const (
	MaxIdentifierBytes = 4 * 1024
	MaxConfigBytes     = 256 * 1024
	MaxSecretRefs      = 64
)

// String-backed identifiers are normalized at construction and are safe to
// carry across the Core/runtime boundary. Empty and whitespace-bearing values
// are not valid identifiers.
type EndpointID string
type AdapterKey string
type ProviderEventID string
type MessageID string
type PrincipalID string
type ConversationID string
type EffectID string
type OperationID string
type CorrelationID string
type CausationID string
type ArtifactID string

func normalizeID(value string, lower bool) (string, error) {
	if value == "" || len(value) > MaxIdentifierBytes || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return "", ErrInvalidID
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return "", ErrInvalidID
		}
	}
	if lower {
		value = strings.ToLower(value)
	}
	return value, nil
}

func validOptionalIdentifier(value string) bool {
	if value == "" {
		return true
	}
	_, err := normalizeID(value, false)
	return err == nil
}

func newID[T ~string](value string, lower bool) (T, error) {
	value, err := normalizeID(value, lower)
	return T(value), err
}

func NewEndpointID(value string) (EndpointID, error) { return newID[EndpointID](value, false) }
func NewAdapterKey(value string) (AdapterKey, error) { return newID[AdapterKey](value, true) }
func NewProviderEventID(value string) (ProviderEventID, error) {
	return newID[ProviderEventID](value, false)
}
func NewMessageID(value string) (MessageID, error)     { return newID[MessageID](value, false) }
func NewPrincipalID(value string) (PrincipalID, error) { return newID[PrincipalID](value, false) }
func NewConversationID(value string) (ConversationID, error) {
	return newID[ConversationID](value, false)
}
func NewEffectID(value string) (EffectID, error)           { return newID[EffectID](value, false) }
func NewOperationID(value string) (OperationID, error)     { return newID[OperationID](value, false) }
func NewCorrelationID(value string) (CorrelationID, error) { return newID[CorrelationID](value, false) }
func NewCausationID(value string) (CausationID, error)     { return newID[CausationID](value, false) }
func NewArtifactID(value string) (ArtifactID, error)       { return newID[ArtifactID](value, false) }

func (v EndpointID) Valid() bool { _, err := normalizeID(string(v), false); return err == nil }
func (v AdapterKey) Valid() bool {
	canonical, err := normalizeID(string(v), true)
	return err == nil && canonical == string(v)
}
func (v ProviderEventID) Valid() bool { _, err := normalizeID(string(v), false); return err == nil }
func (v MessageID) Valid() bool       { _, err := normalizeID(string(v), false); return err == nil }
func (v PrincipalID) Valid() bool     { _, err := normalizeID(string(v), false); return err == nil }
func (v ConversationID) Valid() bool  { _, err := normalizeID(string(v), false); return err == nil }
func (v EffectID) Valid() bool        { _, err := normalizeID(string(v), false); return err == nil }
func (v OperationID) Valid() bool     { _, err := normalizeID(string(v), false); return err == nil }
func (v CorrelationID) Valid() bool   { return validOptionalIdentifier(string(v)) }
func (v CausationID) Valid() bool     { return validOptionalIdentifier(string(v)) }
func (v ArtifactID) Valid() bool      { _, err := normalizeID(string(v), false); return err == nil }

func (v EndpointID) String() string      { return string(v) }
func (v AdapterKey) String() string      { return string(v) }
func (v ProviderEventID) String() string { return string(v) }
func (v MessageID) String() string       { return string(v) }
func (v PrincipalID) String() string     { return string(v) }
func (v ConversationID) String() string  { return string(v) }
func (v EffectID) String() string        { return string(v) }
func (v OperationID) String() string     { return string(v) }
func (v CorrelationID) String() string   { return string(v) }
func (v CausationID) String() string     { return string(v) }
func (v ArtifactID) String() string      { return string(v) }

// SecretRef identifies a versioned secret without carrying its value.
type SecretRef struct {
	Ref     string `json:"ref"`
	Version uint64 `json:"version"`
}

// ValidatedConfig is canonical, non-secret configuration. Canonical contains
// exact JSON bytes suitable for durable storage; SecretRefs contain references
// only, never credential bytes.
type ValidatedConfig struct {
	Version    uint16          `json:"version"`
	Canonical  json.RawMessage `json:"canonical"`
	SecretRefs []SecretRef     `json:"secretRefs"`
}

// SecretValue is an ephemeral sensitive value. It must be consumed by a
// runtime and must never be persisted, logged, or included in a DTO/event.
type SecretValue struct {
	Bytes   []byte `json:"-"`
	Version uint64 `json:"version"`
}

// SecretResolver is the only runtime input that can resolve secret material.
type SecretResolver interface {
	Resolve(ctx context.Context, ref SecretRef) (SecretValue, error)
}

func (s SecretRef) Validate() error {
	if len(s.Ref) == 0 || len(s.Ref) > 256 {
		return fmt.Errorf("%w: secret reference", ErrInvalidContract)
	}
	if _, err := normalizeID(s.Ref, false); err != nil {
		return fmt.Errorf("%w: secret reference", ErrInvalidContract)
	}
	return nil
}

func (c ValidatedConfig) Validate() error {
	if c.Version == 0 || len(c.Canonical) == 0 || len(c.Canonical) > MaxConfigBytes || len(c.SecretRefs) > MaxSecretRefs {
		return fmt.Errorf("%w: missing or oversized validated config", ErrInvalidConfig)
	}
	canonical, err := CanonicalizeJSON(c.Canonical)
	if err != nil || !bytes.Equal(canonical, c.Canonical) {
		return fmt.Errorf("%w: canonical JSON is not canonical", ErrInvalidConfig)
	}
	for _, ref := range c.SecretRefs {
		if err := ref.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// RuntimeInit contains immutable, already-validated construction inputs. A
// descriptor must not acquire resources while constructing a runtime; Run owns
// resource acquisition and Stop owns its release.
type RuntimeInit struct {
	EndpointID     EndpointID
	Generation     uint64
	DesiredVersion uint64
	Config         ValidatedConfig
	Secrets        SecretResolver
	ResourceRoot   string
	// ResourceAccessToken authenticates provider access to shared resources.
	// It is process-local and must never be persisted in adapter configuration.
	ResourceAccessToken string
	// ResourceServeAddress is the core HTTP listen address used to derive a
	// provider-reachable resource URL when the adapter has no explicit base URL.
	ResourceServeAddress string
}

// AdapterRuntime is owned by Supervisor for one endpoint generation.
type AdapterRuntime interface {
	Run(ctx context.Context, core CorePort) error
	Stop(context.Context) error
	Capabilities() CapabilitySet
	Execute(ctx context.Context, effect OutboundEffect) EffectResult
	Diagnostics(context.Context) DiagnosticReport
}

// CorePort is a generation-bound port supplied by Supervisor. DTOs deliberately
// do not carry endpoint, generation, or desired-version fields: an adapter
// cannot forge the fence selected by its owner.
type CorePort interface {
	HandleInbound(ctx context.Context, message InboundMessage) (IngressReceipt, error)
	ReportObservation(ctx context.Context, observation LifecycleObservation) error
}

// Descriptor validates pure config and creates an inert runtime. ValidateConfig
// and NewRuntime must not open sockets, processes, files, SDK sessions, or
// otherwise perform external I/O.
type Descriptor interface {
	Key() AdapterKey
	ConfigVersion() uint16
	ValidateConfig(ctx context.Context, raw json.RawMessage) (ValidatedConfig, error)
	Capabilities(ValidatedConfig) CapabilitySet
	SupportedActions(ValidatedConfig) ActionSet
	NewRuntime(RuntimeInit) (AdapterRuntime, error)
}

// CanonicalizeJSON validates JSON and emits deterministic compact bytes. It
// rejects trailing values and preserves number spelling through UseNumber.
func CanonicalizeJSON(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) > MaxConfigBytes {
		return nil, fmt.Errorf("%w: JSON exceeds %d bytes", ErrInvalidConfig, MaxConfigBytes)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, fmt.Errorf("%w: empty JSON", ErrInvalidConfig)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("%w: multiple JSON values", ErrInvalidConfig)
		}
		return nil, fmt.Errorf("%w: trailing JSON: %w", ErrInvalidConfig, err)
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	return canonical, nil
}

// Clone returns independent config storage so callers cannot mutate the
// descriptor's validated input through a shared JSON or reference slice.
func (c ValidatedConfig) Clone() ValidatedConfig {
	clone := c
	clone.Canonical = append(json.RawMessage(nil), c.Canonical...)
	clone.SecretRefs = append([]SecretRef(nil), c.SecretRefs...)
	return clone
}
