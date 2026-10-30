package messageflow

import (
	"context"
	"strings"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/eventstore"
)

func delayedOutboundService(t *testing.T, effect adapterapi.OutboundEffect, root []byte) *OutboundService {
	t.Helper()
	service, err := NewOutboundService(&testStore{}, testResolver{snap: EndpointSnapshot{
		EndpointID: effect.EndpointID, DesiredState: "enabled", ObservedState: adapterapi.ObservedStateConnected,
		Capabilities: adapterapi.CapabilityOutbound, Actions: adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage),
		IndexRootID: "index-root-1", IndexSigner: testIndexSigner{root: root, id: "index-root-1"},
	}}, &testEncryptor{}, &testIDs{})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func TestOutboundNotBeforeBecomesTheOutboxDueTime(t *testing.T) {
	root := []byte(strings.Repeat("r", 32))
	effect := testEffect()
	effect.Deadline = time.Now().Add(time.Hour).UTC()
	effect.NotBefore = time.Now().Add(5 * time.Second).UTC()
	lane, err := adapterapi.NewLaneMetadata(effect.EndpointID, effect.Payload.Target, root, 1)
	if err != nil {
		t.Fatal(err)
	}
	effect.Lane = lane
	service := delayedOutboundService(t, effect, root)

	prepared, err := service.Prepare(context.Background(), SubmitRequest{Effect: effect, CommandID: "cmd-delayed", PrincipalID: "principal-a"})
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.Work.Effects) != 1 || !prepared.Work.Effects[0].NextAttemptAt.Equal(effect.NotBefore) {
		t.Fatalf("outbox due time = %#v, want %v", prepared.Work.Effects, effect.NotBefore)
	}

	immediate := effect
	immediate.NotBefore = time.Time{}
	prepared, err = service.Prepare(context.Background(), SubmitRequest{Effect: immediate, CommandID: "cmd-immediate", PrincipalID: "principal-a"})
	if err != nil {
		t.Fatal(err)
	}
	if !prepared.Work.Effects[0].NextAttemptAt.IsZero() {
		t.Fatalf("an undelayed effect became due at %v", prepared.Work.Effects[0].NextAttemptAt)
	}
}

func TestOutboundReplayDeduplicatesWhenTheRecomputedDelayDiffers(t *testing.T) {
	root := []byte(strings.Repeat("r", 32))
	effect := testEffect()
	effect.Deadline = time.Now().Add(time.Hour).UTC()
	effect.NotBefore = time.Now().Add(5 * time.Second).UTC()
	lane, err := adapterapi.NewLaneMetadata(effect.EndpointID, effect.Payload.Target, root, 1)
	if err != nil {
		t.Fatal(err)
	}
	effect.Lane = lane
	store := &testStore{}
	service, err := NewOutboundService(store, testResolver{snap: EndpointSnapshot{
		EndpointID: effect.EndpointID, DesiredState: "enabled", ObservedState: adapterapi.ObservedStateConnected,
		Capabilities: adapterapi.CapabilityOutbound, Actions: adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage),
		IndexRootID: "index-root-1", IndexSigner: testIndexSigner{root: root, id: "index-root-1"},
	}}, &testEncryptor{}, &testIDs{})
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.Submit(context.Background(), SubmitRequest{Effect: effect, CommandID: "cmd-replay-delay", PrincipalID: "principal-a"})
	if err != nil {
		t.Fatal(err)
	}
	replay := effect
	replay.ID, replay.OperationID = "effect-replay", "operation-replay"
	replay.NotBefore = effect.NotBefore.Add(3 * time.Second)
	if replay.Lane, err = adapterapi.NewLaneMetadata(replay.EndpointID, replay.Payload.Target, root, 2); err != nil {
		t.Fatal(err)
	}
	second, err := service.Submit(context.Background(), SubmitRequest{Effect: replay, CommandID: "cmd-replay-delay", PrincipalID: "principal-a"})
	if err != nil || !second.Deduplicated || second.EffectID != first.EffectID || store.calls != 1 {
		t.Fatalf("replay = %#v err=%v commits=%d", second, err, store.calls)
	}
}

func TestInboundBoundCoversTypedEventIdentifiers(t *testing.T) {
	base := adapterapi.InboundMessage{Kind: adapterapi.InboundKindNotice, Event: adapterapi.InboundEventPoke}
	small := inboundJSONUpperBound(base)
	large := base
	large.Subject = adapterapi.PrincipalID("QQ:" + strings.Repeat("9", 2000))
	large.Operator = adapterapi.PrincipalID("QQ:" + strings.Repeat("8", 2000))
	large.RequestID = strings.Repeat("f", 2000)
	if got := inboundJSONUpperBound(large); got < small+6000 {
		t.Fatalf("bound grew by %d for 6000 bytes of event identifiers", got-small)
	}
	huge := base
	huge.RequestID = strings.Repeat("f", eventstore.MaxEventPayloadBytes)
	if got := inboundJSONUpperBound(huge); got <= eventstore.MaxEventPayloadBytes {
		t.Fatalf("an oversized request id was not detected: %d", got)
	}
}

func TestInboundBoundCoversDisplayNamesAndRequestPolicy(t *testing.T) {
	base := adapterapi.InboundMessage{Kind: adapterapi.InboundKindNotice, Event: adapterapi.InboundEventPoke}
	small := inboundJSONUpperBound(base)
	named := base
	named.SenderName = strings.Repeat("a", 2000)
	named.SubjectName = strings.Repeat("b", 2000)
	named.ConversationName = strings.Repeat("c", 2000)
	if got := inboundJSONUpperBound(named); got < small+6000 {
		t.Fatalf("bound grew by %d for 6000 bytes of display names", got-small)
	}
	// A control or quote character expands when JSON-escaped; the bound must allow for it.
	escaped := base
	escaped.SenderName = strings.Repeat("\"", 2000)
	if got := inboundJSONUpperBound(escaped); got < small+4000 {
		t.Fatalf("bound grew by %d for 2000 quotes that escape to 4000 bytes", got-small)
	}
}
