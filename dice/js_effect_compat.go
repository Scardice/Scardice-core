package dice

import (
	"errors"
	"strings"

	"Scardice-core/eventstore"
)

var ErrJSEffect = errors.New("dice: invalid JS effect")

// JSEffectRequest contains JS effect inputs. ExpectedVersion, Subject and
// PrincipalID are Core-owned and must remain zero-valued.
type JSEffectRequest struct {
	EffectID        string
	ExpectedVersion uint64
	EndpointID      string
	Lane            string
	Subject         string
	EffectType      string
	RiskClass       string
	Status          string
	Payload         []byte
	ContentDigest   []byte
	PrincipalID     string
}

func BuildJSEffect(request JSEffectRequest) (eventstore.NewEffect, error) {
	if request.ExpectedVersion != 0 || request.Subject != "" || request.PrincipalID != "" {
		return eventstore.NewEffect{}, ErrJSEffect
	}
	if strings.Contains(request.EffectID, "$t") || strings.Contains(request.EndpointID, "$t") || strings.Contains(request.EffectType, "$t") || strings.Contains(request.RiskClass, "$t") || strings.Contains(request.Status, "$t") || strings.Contains(request.Lane, "$t") {
		return eventstore.NewEffect{}, ErrJSEffect
	}
	if strings.TrimSpace(request.EffectID) == "" || strings.TrimSpace(request.EndpointID) == "" || strings.TrimSpace(request.EffectType) == "" {
		return eventstore.NewEffect{}, ErrJSEffect
	}
	if request.EffectType != "send" && request.EffectType != "reply" && request.EffectType != "notice" {
		return eventstore.NewEffect{}, ErrJSEffect
	}
	if request.Lane == "" || request.Status != eventstore.OutboxStatusPending || !jsEffectRiskValid(request.RiskClass) || len(request.Payload) == 0 {
		return eventstore.NewEffect{}, ErrJSEffect
	}
	return eventstore.NewEffect{EffectID: request.EffectID, EndpointID: request.EndpointID, Lane: request.Lane, EffectType: request.EffectType, RiskClass: request.RiskClass, Status: request.Status, Payload: append([]byte(nil), request.Payload...), ContentDigest: append([]byte(nil), request.ContentDigest...)}, nil
}

func BuildJSReplyEffect(request JSEffectRequest) (eventstore.NewEffect, error) {
	request.EffectType = "reply"
	return BuildJSEffect(request)
}
func BuildJSNoticeEffect(request JSEffectRequest) (eventstore.NewEffect, error) {
	request.EffectType = "notice"
	return BuildJSEffect(request)
}
func jsEffectRiskValid(value string) bool {
	return value == eventstore.RiskPreDispatchRetryable || value == eventstore.RiskProviderIdempotent || value == eventstore.RiskNonIdempotentAfterDispatch
}
