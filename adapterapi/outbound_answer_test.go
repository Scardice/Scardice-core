package adapterapi

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func answerEffect(t *testing.T, target EffectTarget, mutate func(*OutboundEffect)) OutboundEffect {
	t.Helper()
	effect := OutboundEffect{
		Version: EffectVersionOne, ID: "effect-answer", EndpointID: "endpoint-1", OperationID: "operation-1",
		CorrelationID: "correlation-1", CausationID: "causation-1", Lane: testLane(t, target),
		Deadline: time.Now().Add(time.Minute), Risk: EffectRiskNormal, RetryClass: EffectRetryNonIdempotent,
		RequiredCapabilities: CapabilityOutbound | CapabilityActions, RequiredAction: ActionKindAnswerRequest,
		Kind:    EffectKindAction,
		Payload: EffectPayload{Kind: EffectPayloadAnswerRequest, Target: target, RequestID: "flag-1", Approve: true},
	}
	if mutate != nil {
		mutate(&effect)
	}
	return effect
}

func TestAnswerRequestPayloadContract(t *testing.T) {
	person := EffectTarget{Kind: TargetPerson, Conversation: "QQ:1001"}
	group := EffectTarget{Kind: TargetGroup, Conversation: "QQ-Group:2002"}
	for name, target := range map[string]EffectTarget{"friend request": person, "group invite": group} {
		if err := answerEffect(t, target, nil).Validate(); err != nil {
			t.Errorf("%s rejected: %v", name, err)
		}
	}
	rejection := answerEffect(t, person, func(e *OutboundEffect) { e.Payload.Approve = false; e.Payload.Reason = "blacklisted" })
	if err := rejection.Validate(); err != nil {
		t.Errorf("rejection with reason rejected: %v", err)
	}

	invalid := map[string]OutboundEffect{
		"missing request id": answerEffect(t, person, func(e *OutboundEffect) { e.Payload.RequestID = "" }),
		"padded request id":  answerEffect(t, person, func(e *OutboundEffect) { e.Payload.RequestID = " flag" }),
		"oversized reason":   answerEffect(t, person, func(e *OutboundEffect) { e.Payload.Reason = strings.Repeat("r", MaxEffectFieldBytes+1) }),
		"carries text":       answerEffect(t, person, func(e *OutboundEffect) { e.Payload.Text = "hello" }),
		"carries member":     answerEffect(t, group, func(e *OutboundEffect) { e.Payload.Target.Member = "QQ:1" }),
		"carries duration":   answerEffect(t, person, func(e *OutboundEffect) { e.Payload.DurationSeconds = 5 }),
		"wrong action":       answerEffect(t, person, func(e *OutboundEffect) { e.RequiredAction = ActionKindSendMessage }),
		"wrong retry class":  answerEffect(t, person, func(e *OutboundEffect) { e.RetryClass = EffectRetryProviderIdempotent }),
		"raw target":         answerEffect(t, EffectTarget{Kind: TargetRaw, Raw: "raw"}, nil),
	}
	for name, effect := range invalid {
		if err := effect.Validate(); !errors.Is(err, ErrInvalidContract) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}

	// Other payload kinds must not smuggle the new fields.
	text := OutboundEffect{
		Version: EffectVersionOne, ID: "effect-text", EndpointID: "endpoint-1", OperationID: "operation-1",
		CorrelationID: "correlation-1", CausationID: "causation-1", Lane: testLane(t, person),
		Deadline: time.Now().Add(time.Minute), Risk: EffectRiskNormal, RetryClass: EffectRetryNonIdempotent,
		RequiredCapabilities: CapabilityOutbound, RequiredAction: ActionKindSendMessage, Kind: EffectKindMessage,
		Payload: EffectPayload{Kind: EffectPayloadPersonText, Target: person, Text: "hello", RequestID: "flag-1"},
	}
	if err := text.Validate(); !errors.Is(err, ErrInvalidContract) {
		t.Errorf("text payload carrying a request id accepted: %v", err)
	}
	text.Payload.RequestID, text.Payload.Approve = "", true
	if err := text.Validate(); !errors.Is(err, ErrInvalidContract) {
		t.Errorf("text payload carrying an approval accepted: %v", err)
	}
}

func TestAnswerRequestActionIsAKnownActionBit(t *testing.T) {
	if !ActionKindAnswerRequest.Valid() {
		t.Fatal("answer-request action is not a valid action kind")
	}
	set := ActionSet(0).With(ActionKindSendMessage, ActionKindAnswerRequest)
	if !set.Valid() || !set.Has(ActionKindAnswerRequest) || set.Has(ActionKindKick) {
		t.Fatalf("action set = %b", set)
	}
	effect := answerEffect(t, EffectTarget{Kind: TargetPerson, Conversation: "QQ:1001"}, nil)
	if err := effect.ValidateForCapabilities(CapabilityOutbound|CapabilityActions, ActionSet(0).With(ActionKindSendMessage)); !errors.Is(err, ErrUnsupportedAction) {
		t.Fatalf("provider without the action accepted the effect: %v", err)
	}
	if err := effect.ValidateForCapabilities(CapabilityOutbound|CapabilityActions, set); err != nil {
		t.Fatalf("provider with the action rejected the effect: %v", err)
	}
}

func TestEffectNotBeforeBoundsAndSerialization(t *testing.T) {
	target := EffectTarget{Kind: TargetGroup, Conversation: "QQ-Group:2002"}
	delayed := func(offset time.Duration) OutboundEffect {
		effect := answerEffect(t, target, nil)
		effect.Deadline = time.Now().Add(time.Minute)
		effect.NotBefore = effect.Deadline.Add(offset)
		return effect
	}
	if err := delayed(-30 * time.Second).Validate(); err != nil {
		t.Errorf("not-before inside the deadline rejected: %v", err)
	}
	for name, offset := range map[string]time.Duration{"at the deadline": 0, "after the deadline": time.Second} {
		if err := delayed(offset).Validate(); !errors.Is(err, ErrInvalidContract) {
			t.Errorf("not-before %s accepted: %v", name, err)
		}
	}
	unversioned := OutboundEffect{ID: "effect-legacy", Kind: EffectKindMessage, NotBefore: time.Now()}
	if err := unversioned.Validate(); !errors.Is(err, ErrInvalidContract) {
		t.Errorf("unversioned effect with not-before accepted: %v", err)
	}

	raw, err := json.Marshal(answerEffect(t, target, nil))
	if err != nil || strings.Contains(string(raw), "notBefore") {
		t.Fatalf("an effect without a delay must not serialize notBefore: %s err=%v", raw, err)
	}
}
