package dice

import (
	"errors"
	"strings"

	"Scardice-core/eventstore"
)

var ErrJSEffect = errors.New("dice: invalid JS effect")

// JSEffectRequest contains only the opaque fields accepted from JS. Plaintext
// payloads and provider/runtime pointers have no representation in this DTO.
type JSEffectRequest struct {
	EffectID               string
	ExpectedVersion        uint64
	EndpointID             string
	LaneHMAC               []byte
	SubjectKey             []byte
	EffectType             string
	RiskClass              string
	Status                 string
	PayloadCiphertext      []byte
	PayloadNonce           []byte
	PayloadVersion         uint64
	PayloadEncryptionKeyID string
	ContentDigest          []byte
	ContentDigestKeyID     string
	PrincipalID            string
}

func BuildJSEffect(request JSEffectRequest) (eventstore.NewEffect, error) {
	if request.ExpectedVersion != 0 || len(request.SubjectKey) != 0 || request.PrincipalID != "" {
		return eventstore.NewEffect{}, ErrJSEffect
	}
	if strings.Contains(request.EffectID, "$t") || strings.Contains(request.EndpointID, "$t") || strings.Contains(request.EffectType, "$t") || strings.Contains(request.RiskClass, "$t") || strings.Contains(request.Status, "$t") || strings.Contains(request.PayloadEncryptionKeyID, "$t") || strings.Contains(request.ContentDigestKeyID, "$t") {
		return eventstore.NewEffect{}, ErrJSEffect
	}
	if strings.TrimSpace(request.EffectID) == "" || strings.TrimSpace(request.EndpointID) == "" || strings.TrimSpace(request.EffectType) == "" {
		return eventstore.NewEffect{}, ErrJSEffect
	}
	if request.EffectType != "send" && request.EffectType != "reply" && request.EffectType != "notice" {
		return eventstore.NewEffect{}, ErrJSEffect
	}
	if len(request.LaneHMAC) == 0 || request.Status != eventstore.OutboxStatusPending || !jsEffectRiskValid(request.RiskClass) || len(request.PayloadCiphertext) == 0 || len(request.PayloadNonce) == 0 || strings.TrimSpace(request.PayloadEncryptionKeyID) == "" {
		return eventstore.NewEffect{}, ErrJSEffect
	}
	effect := eventstore.NewEffect{EffectID: request.EffectID, EndpointID: request.EndpointID, LaneHMAC: append([]byte(nil), request.LaneHMAC...), EffectType: request.EffectType, RiskClass: request.RiskClass, Status: request.Status, PayloadCiphertext: append([]byte(nil), request.PayloadCiphertext...), PayloadNonce: append([]byte(nil), request.PayloadNonce...), PayloadVersion: request.PayloadVersion, PayloadEncryptionKeyID: request.PayloadEncryptionKeyID, ContentDigest: append([]byte(nil), request.ContentDigest...), ContentDigestKeyID: request.ContentDigestKeyID}
	return effect, nil
}
func BuildJSReplyEffect(request JSEffectRequest) (eventstore.NewEffect, error) { request.EffectType = "reply"; return BuildJSEffect(request) }
func BuildJSNoticeEffect(request JSEffectRequest) (eventstore.NewEffect, error) { request.EffectType = "notice"; return BuildJSEffect(request) }
func jsEffectRiskValid(value string) bool { return value == eventstore.RiskPreDispatchRetryable || value == eventstore.RiskProviderIdempotent || value == eventstore.RiskNonIdempotentAfterDispatch }
