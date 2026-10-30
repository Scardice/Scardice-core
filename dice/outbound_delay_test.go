package dice

import (
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/messageflow"
)

func TestOutboundDelayDefersTheEffectInsteadOfBlockingTheCaller(t *testing.T) {
	submitter := &bridgeTestSubmitter{}
	ctx, msg, _ := bridgeTestContext(submitter)
	ctx.setOutboundDelay(4 * time.Second)

	started := time.Now()
	ReplyToSender(ctx, msg, "delayed hello")
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("submission blocked for %s", elapsed)
	}

	submitter.mu.Lock()
	effect := submitter.request.Effect
	submitter.mu.Unlock()
	if effect.Payload.Text != "delayed hello" {
		t.Fatalf("effect = %#v", effect)
	}
	wait := time.Until(effect.NotBefore)
	if effect.NotBefore.IsZero() || wait < 3*time.Second || wait > 5*time.Second {
		t.Fatalf("NotBefore = %v (in %s), want about 4s from now", effect.NotBefore, wait)
	}
	if !effect.NotBefore.Before(effect.Deadline) {
		t.Fatalf("NotBefore %v must precede Deadline %v", effect.NotBefore, effect.Deadline)
	}
}

func TestOutboundWithoutDelayIsImmediateAndZeroDelayClearsIt(t *testing.T) {
	submitter := &bridgeTestSubmitter{}
	ctx, msg, _ := bridgeTestContext(submitter)

	ReplyToSender(ctx, msg, "now")
	submitter.mu.Lock()
	immediate := submitter.request.Effect.NotBefore
	submitter.mu.Unlock()
	if !immediate.IsZero() {
		t.Fatalf("undelayed effect carries NotBefore %v", immediate)
	}

	ctx.setOutboundDelay(3 * time.Second)
	ctx.setOutboundDelay(0)
	ReplyToSender(ctx, msg, "cleared")
	submitter.mu.Lock()
	cleared := submitter.request.Effect.NotBefore
	submitter.mu.Unlock()
	if !cleared.IsZero() {
		t.Fatalf("cleared delay still carries NotBefore %v", cleared)
	}
}

func TestOutboundDelayIsCappedBelowTheDeadline(t *testing.T) {
	submitter := &bridgeTestSubmitter{}
	ctx, msg, _ := bridgeTestContext(submitter)
	ctx.setOutboundDelay(24 * time.Hour)
	ReplyToSender(ctx, msg, "capped")

	submitter.mu.Lock()
	effect := submitter.request.Effect
	submitter.mu.Unlock()
	if effect.NotBefore.IsZero() || !effect.NotBefore.Before(effect.Deadline) {
		t.Fatalf("NotBefore %v must stay before Deadline %v", effect.NotBefore, effect.Deadline)
	}
}

func configureBridgeForAnswerRequest(ctx *MsgContext) {
	bridge := ctx.Dice.OutboundBridge.(*DurableOutboundBridge)
	bridge.resolver = bridgeTestResolver{snapshot: messageflow.EndpointSnapshot{
		EndpointID: "endpoint-1", AdapterKey: "pureonebot", DesiredState: "enabled",
		ObservedState: adapterapi.ObservedStateConnected,
		Capabilities:  adapterapi.CapabilityOutbound | adapterapi.CapabilityActions,
		Actions:       adapterapi.ActionSet(0).With(adapterapi.ActionKindAnswerRequest),
		IndexRootID:   "root-1",
		IndexSigner:   bridgeTestIndexSigner{root: []byte("01234567890123456789012345678901"), id: "root-1"},
	}}
}

func TestAnswerRequestActionIsSubmittedAsAnIdempotentProviderAction(t *testing.T) {
	submitter := &bridgeTestSubmitter{}
	ctx, _, legacy := bridgeTestContext(submitter)
	configureBridgeForAnswerRequest(ctx)

	payload := adapterapi.EffectPayload{
		Kind:      adapterapi.EffectPayloadAnswerRequest,
		Target:    adapterapi.EffectTarget{Kind: adapterapi.TargetPerson, Conversation: "QQ:1001"},
		RequestID: "flag-7", Approve: false, Reason: "blacklisted",
	}
	if err := ctx.Dice.OutboundBridge.(durableOutboundActionPort).SubmitAction(ctx, payload); err != nil {
		t.Fatalf("SubmitAction: %v", err)
	}
	if len(legacy.bans)+len(legacy.kicks)+len(legacy.quitGroups) != 0 {
		t.Fatalf("legacy adapter was called: %#v", legacy)
	}

	submitter.mu.Lock()
	effect := submitter.request.Effect
	submitter.mu.Unlock()
	if effect.Kind != adapterapi.EffectKindAction || effect.RequiredAction != adapterapi.ActionKindAnswerRequest {
		t.Fatalf("effect = %#v", effect)
	}
	if effect.Payload.RequestID != "flag-7" || effect.Payload.Approve || effect.Payload.Reason != "blacklisted" {
		t.Fatalf("payload = %#v", effect.Payload)
	}
	// A consumed request flag makes a second answer indistinguishable from a
	// lost first one, so an uncertain result must never be retried blindly.
	if effect.RetryClass != adapterapi.EffectRetryNonIdempotent {
		t.Fatalf("RetryClass = %v", effect.RetryClass)
	}
}
