package adapterapi

import (
	"context"
	"fmt"
)

// ActionKind is a closed set of provider actions exposed to Core. Providers
// must return Unsupported for actions absent from their descriptor's ActionSet;
// they must not silently no-op.
type ActionKind uint8

const (
	ActionKindInvalid ActionKind = iota
	ActionKindRequestQRCode
	ActionKindSubmitSMS
	ActionKindSubmitCaptcha
	ActionKindValidateCredentials
	ActionKindGenerateConfigArtifact
	ActionKindSendMessage
	ActionKindSendFile
	ActionKindRecallMessage
	ActionKindEditMessage
	ActionKindSetGroupCard
	ActionKindQuit
	ActionKindBan
	ActionKindKick
	ActionKindGroupInfoRefresh
)
const maxActionKind = ActionKindGroupInfoRefresh

func (kind ActionKind) Valid() bool {
	switch kind {
	case ActionKindRequestQRCode, ActionKindSubmitSMS, ActionKindSubmitCaptcha, ActionKindValidateCredentials, ActionKindGenerateConfigArtifact, ActionKindSendMessage, ActionKindSendFile, ActionKindRecallMessage, ActionKindEditMessage, ActionKindSetGroupCard, ActionKindQuit, ActionKindBan, ActionKindKick, ActionKindGroupInfoRefresh:
		return true
	}
	return false
}

// Short aliases are the canonical vocabulary used by effect callers.
const (
	ActionRequestQRCode          = ActionKindRequestQRCode
	ActionSubmitSMS              = ActionKindSubmitSMS
	ActionSubmitCaptcha          = ActionKindSubmitCaptcha
	ActionValidateCredentials    = ActionKindValidateCredentials
	ActionGenerateConfigArtifact = ActionKindGenerateConfigArtifact
)

// ActionSet is the closed set of actions supported by a validated config.
type ActionSet uint16

const actionKnownBits ActionSet = (1 << maxActionKind) - 1

func ActionBit(kind ActionKind) ActionSet {
	if !kind.Valid() {
		return 0
	}
	return ActionSet(1) << (kind - 1)
}

func (set ActionSet) Valid() bool {
	return set&^actionKnownBits == 0
}
func (set ActionSet) Has(kind ActionKind) bool {
	return kind.Valid() && set.Valid() && set&ActionBit(kind) != 0
}
func (set ActionSet) With(kinds ...ActionKind) ActionSet {
	for _, kind := range kinds {
		set |= ActionBit(kind)
	}
	return set
}
func (set ActionSet) Kinds() []ActionKind {
	if !set.Valid() {
		return nil
	}
	result := make([]ActionKind, 0, maxActionKind)
	for kind := ActionKind(1); kind <= maxActionKind; kind++ {
		if set.Has(kind) {
			result = append(result, kind)
		}
	}
	return result
}

type ActionPayload struct {
	SMSCode string `json:"-"`
	Captcha string `json:"-"`
	Confirm bool   `json:"confirm,omitempty"`
}

// ActionRequest is the typed, provider-neutral input for an interactive
// action. Secret-bearing fields are intentionally excluded from JSON.
type ActionRequest struct {
	EndpointID EndpointID
	Generation uint64
	Kind       ActionKind
	Payload    ActionPayload
}

// ActionArtifact is ephemeral action output. Callers must encrypt and persist
// it through eventstore before returning it to an administrator.
type ActionArtifact struct {
	MediaType    string
	SafeFilename string
	Plaintext    []byte
}

// ActionResult is a bounded, secret-free result except for the transient
// artifact bytes, which must never be serialized or logged.
type ActionResult struct {
	ResultCode string
	Diagnostic DiagnosticReport
	Artifact   *ActionArtifact
}

func (result ActionResult) Validate() error {
	if result.Artifact != nil && len(result.Artifact.Plaintext) > 32*1024*1024 {
		return fmt.Errorf("%w: action artifact exceeds 32 MiB", ErrInvalidContract)
	}
	return result.Diagnostic.Validate()
}

// ActionRuntime is optional so existing runtimes can migrate incrementally.
// Implementations must keep ActionRequest.Payload secret fields in memory only.
type ActionRuntime interface {
	ExecuteAction(context.Context, ActionRequest) (ActionResult, error)
}
