package dice

import (
	"context"
	"testing"

	"Scardice-core/adapterapi"
	emitter "Scardice-core/dice/imsdk/onebot"
	emitterTypes "Scardice-core/dice/imsdk/onebot/types"
)

func answerEffect(t *testing.T, payload adapterapi.EffectPayload) adapterapi.OutboundEffect {
	t.Helper()
	effect := outboundEffectForTest(t, payload, adapterapi.CapabilityOutbound|adapterapi.CapabilityActions, adapterapi.ActionKindAnswerRequest)
	if err := effect.Validate(); err != nil {
		t.Fatalf("fixture invalid: %v", err)
	}
	return effect
}

func TestOnebotRuntimeAnswersFriendRequestsWithTheEchoedFlag(t *testing.T) {
	for _, approve := range []bool{true, false} {
		fake := &onebotOutboundFake{rawResponse: []byte(`{"status":"ok","retcode":0}`)}
		runtime := &onebotRuntime{outbound: fake}
		result := runtime.Execute(context.Background(), answerEffect(t, adapterapi.EffectPayload{
			Kind:      adapterapi.EffectPayloadAnswerRequest,
			Target:    adapterapi.EffectTarget{Kind: adapterapi.TargetPerson, Conversation: "QQ:1001"},
			RequestID: "friend-flag-1", Approve: approve,
		}))
		if result.Outcome != adapterapi.EffectSucceeded {
			t.Fatalf("approve=%v result = %#v", approve, result)
		}
		params, ok := fake.rawParams.(emitterTypes.FriendAddReq)
		if fake.rawAction != emitter.ACTION_SET_FRIEND_ADD_REQUEST || !ok || params.Flag != "friend-flag-1" || params.Approve != approve {
			t.Fatalf("approve=%v provider call = %q %#v", approve, fake.rawAction, fake.rawParams)
		}
	}
}

func TestOnebotRuntimeAnswersGroupInvitesAsInviteSubtypeWithReason(t *testing.T) {
	fake := &onebotOutboundFake{rawResponse: []byte(`{"status":"ok","retcode":0}`)}
	runtime := &onebotRuntime{outbound: fake}
	result := runtime.Execute(context.Background(), answerEffect(t, adapterapi.EffectPayload{
		Kind:      adapterapi.EffectPayloadAnswerRequest,
		Target:    adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"},
		RequestID: "group-flag-1", Approve: false, Reason: "拉黑群",
	}))
	if result.Outcome != adapterapi.EffectSucceeded {
		t.Fatalf("result = %#v", result)
	}
	params, ok := fake.rawParams.(emitterTypes.GroupAddReq)
	if fake.rawAction != emitter.ACTION_SET_GROUP_ADD_REQUEST || !ok ||
		params.Flag != "group-flag-1" || params.SubType != "invite" || params.Approve || params.Reason != "拉黑群" {
		t.Fatalf("provider call = %q %#v", fake.rawAction, fake.rawParams)
	}
}

func TestOnebotRuntimeReportsRejectedAnswerAsTerminalNotRetryable(t *testing.T) {
	fake := &onebotOutboundFake{rawResponse: []byte(`{"status":"failed","retcode":1200,"message":"flag expired"}`)}
	runtime := &onebotRuntime{outbound: fake}
	result := runtime.Execute(context.Background(), answerEffect(t, adapterapi.EffectPayload{
		Kind:      adapterapi.EffectPayloadAnswerRequest,
		Target:    adapterapi.EffectTarget{Kind: adapterapi.TargetPerson, Conversation: "QQ:1001"},
		RequestID: "stale-flag", Approve: true,
	}))
	if result.Outcome != adapterapi.EffectTerminal {
		t.Fatalf("a provider that rejected the flag must not be retried: %#v", result)
	}
}

func TestOnebotAdvertisesTheAnswerRequestAction(t *testing.T) {
	if !onebotSupportedActions().Has(adapterapi.ActionKindAnswerRequest) {
		t.Fatal("pure OneBot does not advertise answer-request")
	}
}
