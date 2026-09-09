package dice

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"



	"Scardice-core/adapterapi"
	emitter "Scardice-core/dice/imsdk/onebot"
	"Scardice-core/dice/imsdk/onebot/schema"
	emitterTypes "Scardice-core/dice/imsdk/onebot/types"
)

type onebotOutboundFake struct {
	personID int64
	groupID int64
	personMessage schema.MessageChain
	groupMessage schema.MessageChain
	deleted int64
	cardGroup, cardMember int64
	card string
	quitGroup int64
	groupInfo int64
	rawAction emitter.Action
	rawParams any
	rawResponse []byte
	rawErr error
	calls int
}

func (f *onebotOutboundFake) SendPvtMsg(_ context.Context, id int64, msg schema.MessageChain) (*emitterTypes.SendMsgRes, error) { f.calls++; f.personID, f.personMessage = id, msg; return &emitterTypes.SendMsgRes{MessageId: 123}, nil }
func (f *onebotOutboundFake) SendGrMsg(_ context.Context, id int64, msg schema.MessageChain) (*emitterTypes.SendMsgRes, error) { f.calls++; f.groupID, f.groupMessage = id, msg; return &emitterTypes.SendMsgRes{MessageId: 456}, nil }
func (f *onebotOutboundFake) DelMsg(_ context.Context, id int64) error { f.calls++; f.deleted = id; return nil }
func (f *onebotOutboundFake) SetGroupCard(_ context.Context, group, member int64, card string) error { f.calls++; f.cardGroup, f.cardMember, f.card = group, member, card; return nil }
func (f *onebotOutboundFake) QuitGroup(_ context.Context, group int64) error { f.calls++; f.quitGroup = group; return nil }
func (f *onebotOutboundFake) GetGroupInfo(_ context.Context, group int64, _ bool) (*emitterTypes.GroupInfo, error) { f.calls++; f.groupInfo = group; return &emitterTypes.GroupInfo{GroupId: group}, nil }
func (f *onebotOutboundFake) Raw(_ context.Context, action emitter.Action, params any) ([]byte, error) { f.calls++; f.rawAction, f.rawParams = action, params; return f.rawResponse, f.rawErr }
type onebotTemporaryError struct{}

func (onebotTemporaryError) Error() string   { return "temporary provider failure" }
func (onebotTemporaryError) Timeout() bool   { return false }
func (onebotTemporaryError) Temporary() bool { return true }


func outboundEffectForTest(t *testing.T, payload adapterapi.EffectPayload, caps adapterapi.CapabilitySet, action adapterapi.ActionKind) adapterapi.OutboundEffect {
	t.Helper()
	lane, err := adapterapi.NewLaneMetadata("endpoint-1", payload.Target, []byte("index-root"), 1)
	if err != nil { t.Fatal(err) }
	kind := adapterapi.EffectKindAction
	risk := adapterapi.EffectRiskNormal
	retry := adapterapi.EffectRetryProviderIdempotent
	switch payload.Kind {
	case adapterapi.EffectPayloadPersonText, adapterapi.EffectPayloadGroupText, adapterapi.EffectPayloadSegments, adapterapi.EffectPayloadFile:
		kind, retry = adapterapi.EffectKindMessage, adapterapi.EffectRetryNonIdempotent
	case adapterapi.EffectPayloadSetGroupCard, adapterapi.EffectPayloadQuit, adapterapi.EffectPayloadBan, adapterapi.EffectPayloadKick:
		risk, retry = adapterapi.EffectRiskHigh, adapterapi.EffectRetryNonIdempotent
	}
	return adapterapi.OutboundEffect{
		Version: adapterapi.EffectVersionOne, ID: "effect-1", EndpointID: "endpoint-1", OperationID: "operation-1",
		CorrelationID: "correlation-1", CausationID: "causation-1", Lane: lane, Deadline: time.Now().Add(time.Minute),
		Risk: risk, RetryClass: retry, RequiredCapabilities: caps,
		RequiredAction: action, Kind: kind, Payload: payload,
	}
}

func outboundMessageEffectForTest(t *testing.T, payload adapterapi.EffectPayload, caps adapterapi.CapabilitySet) adapterapi.OutboundEffect {
	effect := outboundEffectForTest(t, payload, caps, adapterapi.ActionKindSendMessage)
	effect.Kind = adapterapi.EffectKindMessage
	effect.RetryClass = adapterapi.EffectRetryNonIdempotent
	return effect
}

func TestOnebotRuntimeExecuteSendsPersonSegmentsAndReturnsProviderID(t *testing.T) {
	fake := &onebotOutboundFake{}
	runtime := &onebotRuntime{outbound: fake}
	effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadSegments, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetPerson, Conversation: "QQ:42"}, Segments: []adapterapi.MessageSegment{{Kind: adapterapi.SegmentKindText, Text: "hello"}, {Kind: adapterapi.SegmentKindMention, Text: "QQ:7"}}}, adapterapi.CapabilityOutbound|adapterapi.CapabilityRichMessages)
	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectSucceeded || result.ProviderID != "123" { t.Fatalf("result = %#v", result) }
	if fake.personID != 42 || len(fake.personMessage) != 2 { t.Fatalf("person send = %#v", fake) }
}
func TestOnebotRuntimeExecuteSendsGroupText(t *testing.T) {
	fake := &onebotOutboundFake{}
	runtime := &onebotRuntime{outbound: fake}
	effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadGroupText, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"}, Text: "hello"}, adapterapi.CapabilityOutbound)
	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectSucceeded || result.ProviderID != "456" {
		t.Fatalf("result = %#v", result)
	}
	if fake.groupID != 9 || len(fake.groupMessage) != 1 {
		t.Fatalf("group send = %#v", fake)
	}
}
func TestOnebotRuntimeExecuteAcceptsInboundGroupConversationID(t *testing.T) {
	fake := &onebotOutboundFake{}
	runtime := &onebotRuntime{outbound: fake}
	effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadGroupText, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ:group:9"}, Text: "hello"}, adapterapi.CapabilityOutbound)
	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectSucceeded || fake.groupID != 9 {
		t.Fatalf("result=%#v fake=%#v", result, fake)
	}
}

func TestOnebotRuntimeExecuteRejectsBareGroupConversationIDBeforeIO(t *testing.T) {
	fake := &onebotOutboundFake{}
	runtime := &onebotRuntime{outbound: fake}
	effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadGroupText, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "9"}, Text: "hello"}, adapterapi.CapabilityOutbound)
	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectUnsupported || fake.calls != 0 {
		t.Fatalf("result=%#v calls=%d", result, fake.calls)
	}
}
func TestOnebotRuntimeExecuteRejectsBarePersonAndMemberIDsBeforeIO(t *testing.T) {
	t.Run("person", func(t *testing.T) {
		fake := &onebotOutboundFake{}
		effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadPersonText, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetPerson, Conversation: "42"}, Text: "hello"}, adapterapi.CapabilityOutbound)
		result := (&onebotRuntime{outbound: fake}).Execute(context.Background(), effect)
		if result.Outcome != adapterapi.EffectUnsupported || fake.calls != 0 {
			t.Fatalf("result=%#v calls=%d", result, fake.calls)
		}
	})
	t.Run("member", func(t *testing.T) {
		fake := &onebotOutboundFake{}
		effect := outboundEffectForTest(t, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadKick, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ:group:9", Member: "8"}}, adapterapi.CapabilityOutbound|adapterapi.CapabilityActions, adapterapi.ActionKindKick)
		result := (&onebotRuntime{outbound: fake}).Execute(context.Background(), effect)
		if result.Outcome != adapterapi.EffectUnsupported || fake.calls != 0 {
			t.Fatalf("result=%#v calls=%d", result, fake.calls)
		}
	})
}

func TestOnebotRuntimeExecuteRejectsInvalidMentionsBeforeIO(t *testing.T) {
	for _, mention := range []string{"7", " QQ:7 "} {
		t.Run(mention, func(t *testing.T) {
			fake := &onebotOutboundFake{}
			effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadSegments, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetPerson, Conversation: "QQ:42"}, Segments: []adapterapi.MessageSegment{{Kind: adapterapi.SegmentKindMention, Text: mention}}}, adapterapi.CapabilityOutbound|adapterapi.CapabilityRichMessages)
			result := (&onebotRuntime{outbound: fake}).Execute(context.Background(), effect)
			if result.Outcome != adapterapi.EffectUnsupported || fake.calls != 0 {
				t.Fatalf("result=%#v calls=%d", result, fake.calls)
			}
		})
	}
}

func TestOnebotRuntimeExecuteSendsGroupSegments(t *testing.T) {
	fake := &onebotOutboundFake{}
	runtime := &onebotRuntime{outbound: fake}
	effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadSegments, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"}, Segments: []adapterapi.MessageSegment{{Kind: adapterapi.SegmentKindText, Text: "hello"}}}, adapterapi.CapabilityOutbound|adapterapi.CapabilityRichMessages)
	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectSucceeded || result.ProviderID != "456" || fake.groupID != 9 || len(fake.groupMessage) != 1 {
		t.Fatalf("result=%#v fake=%#v", result, fake)
	}
}

func TestOnebotRuntimeExecuteMapsActionsToTypedAndRawEmitterCalls(t *testing.T) {
	tests := []struct {
		name string
		payload adapterapi.EffectPayload

		action adapterapi.ActionKind
		caps adapterapi.CapabilitySet
		check func(*testing.T, *onebotOutboundFake)
	}{
		{"recall", adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadRecall, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"}, MessageID: "77"}, adapterapi.ActionKindRecallMessage, adapterapi.CapabilityOutbound|adapterapi.CapabilityActions, func(t *testing.T, f *onebotOutboundFake) { if f.deleted != 77 { t.Fatalf("deleted = %d", f.deleted) } }},
		{"card", adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadSetGroupCard, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9", Member: "QQ:8"}, Card: "new"}, adapterapi.ActionKindSetGroupCard, adapterapi.CapabilityOutbound|adapterapi.CapabilityActions, func(t *testing.T, f *onebotOutboundFake) { if f.cardGroup != 9 || f.cardMember != 8 || f.card != "new" { t.Fatalf("card = %#v", f) } }},
		{"quit", adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadQuit, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"}}, adapterapi.ActionKindQuit, adapterapi.CapabilityOutbound|adapterapi.CapabilityActions, func(t *testing.T, f *onebotOutboundFake) { if f.quitGroup != 9 { t.Fatalf("quit = %d", f.quitGroup) } }},
		{"edit", adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadEdit, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"}, MessageID: "77", Text: "edited"}, adapterapi.ActionKindEditMessage, adapterapi.CapabilityOutbound|adapterapi.CapabilityActions, func(t *testing.T, f *onebotOutboundFake) { if f.rawAction != "set_msg" { t.Fatalf("raw action = %q", f.rawAction) } }},
		{"ban", adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadBan, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9", Member: "QQ:8"}, DurationSeconds: 30, Reason: "rule"}, adapterapi.ActionKindBan, adapterapi.CapabilityOutbound|adapterapi.CapabilityActions, func(t *testing.T, f *onebotOutboundFake) { if f.rawAction != "set_group_ban" { t.Fatalf("raw action = %q", f.rawAction) } }},
		{"kick", adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadKick, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9", Member: "QQ:8"}, Reason: "rule"}, adapterapi.ActionKindKick, adapterapi.CapabilityOutbound|adapterapi.CapabilityActions, func(t *testing.T, f *onebotOutboundFake) { if f.rawAction != "set_group_kick" { t.Fatalf("raw action = %q", f.rawAction) } }},
		{"group info", adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadGroupInfoRefresh, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"}}, adapterapi.ActionKindGroupInfoRefresh, adapterapi.CapabilityOutbound|adapterapi.CapabilityActions, func(t *testing.T, f *onebotOutboundFake) { if f.groupInfo != 9 { t.Fatalf("group info = %d", f.groupInfo) } }},
	}
	for _, tt := range tests { t.Run(tt.name, func(t *testing.T) { fake := &onebotOutboundFake{rawResponse: []byte(`{"status":"ok","retcode":0}`)}; runtime := &onebotRuntime{outbound: fake}; effect := outboundEffectForTest(t, tt.payload, tt.caps, tt.action); if err := effect.Validate(); err != nil { t.Fatalf("fixture invalid: %v", err) }; result := runtime.Execute(context.Background(), effect); if result.Outcome != adapterapi.EffectSucceeded { t.Fatalf("result = %#v", result) }; tt.check(t, fake) }) }
}

func TestOnebotRuntimeExecuteRejectsFileAndArtifactBeforeProviderIO(t *testing.T) {
	fake := &onebotOutboundFake{}
	runtime := &onebotRuntime{outbound: fake}
	effect := outboundEffectForTest(t, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadFile, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"}, File: adapterapi.ArtifactInput{ID: "artifact-1", Filename: "safe.txt"}}, adapterapi.CapabilityOutbound|adapterapi.CapabilityArtifacts, adapterapi.ActionKindSendFile)
	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectUnsupported || fake.calls != 0 || !strings.Contains(result.Code, "artifact") { t.Fatalf("result=%#v calls=%d", result, fake.calls) }
}

func TestOnebotRuntimeExecuteRedactsProviderErrors(t *testing.T) {
	fake := &onebotOutboundFake{rawResponse: []byte(`{"status":"failed","retcode":1403,"token":"secret-token","body":"raw-provider-body"}`), rawErr: errors.New("Authorization: Bearer secret-token raw-provider-body")}
	runtime := &onebotRuntime{outbound: fake}
	effect := outboundEffectForTest(t, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadEdit, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"}, MessageID: "77", Text: "edited"}, adapterapi.CapabilityOutbound|adapterapi.CapabilityActions, adapterapi.ActionKindEditMessage)
	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectTerminal || strings.Contains(result.Message, "secret-token") || strings.Contains(result.Message, "raw-provider-body") || strings.Contains(result.Message, "Authorization") { t.Fatalf("result leaked provider details: %#v", result) }
}
func TestOnebotRuntimeExecuteClassifiesExplicitTemporaryProviderErrorsAsRetryable(t *testing.T) {
	fake := &onebotOutboundFake{rawErr: onebotTemporaryError{}}
	effect := outboundEffectForTest(t, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadEdit, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"}, MessageID: "77", Text: "edited"}, adapterapi.CapabilityOutbound|adapterapi.CapabilityActions, adapterapi.ActionKindEditMessage)
	result := (&onebotRuntime{outbound: fake}).Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectRetryable || result.Code != "onebot_provider_transient" {
		t.Fatalf("result=%#v", result)
	}
}

func TestOnebotRuntimeExecuteValidatesBeforeProviderIO(t *testing.T) {
	fake := &onebotOutboundFake{}
	runtime := &onebotRuntime{outbound: fake}
	effect := adapterapi.OutboundEffect{Version: adapterapi.EffectVersionOne, ID: "effect-1", Payload: adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadGroupText}}
	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectUnsupported || fake.calls != 0 { t.Fatalf("result=%#v calls=%d", result, fake.calls) }
}

func TestOnebotDescriptorAdvertisesImplementedActionsOnly(t *testing.T) {
	validated, err := (OnebotDescriptor{}).ValidateConfig(context.Background(), []byte(`{"mode":"client","url":"ws://bot.example"}`))
	if err != nil { t.Fatal(err) }
	actions := (OnebotDescriptor{}).SupportedActions(validated)
	for _, action := range []adapterapi.ActionKind{adapterapi.ActionKindSendMessage, adapterapi.ActionKindRecallMessage, adapterapi.ActionKindEditMessage, adapterapi.ActionKindSetGroupCard, adapterapi.ActionKindQuit, adapterapi.ActionKindBan, adapterapi.ActionKindKick, adapterapi.ActionKindGroupInfoRefresh} { if !actions.Has(action) { t.Fatalf("missing advertised action %v", action) } }
	if actions.Has(adapterapi.ActionKindSendFile) { t.Fatal("file action must remain unsupported without artifact reader") }
}
