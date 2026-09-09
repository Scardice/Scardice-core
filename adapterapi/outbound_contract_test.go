package adapterapi

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func testLane(t *testing.T, target EffectTarget) LaneMetadata {
	t.Helper()
	lane, err := NewLaneMetadata("endpoint-1", target, []byte("index-root"), 1)
	if err != nil { t.Fatal(err) }
	return lane
}

func TestVersionedOutboundPayloadsValidateAndBuildLaneMetadata(t *testing.T) {
	target := EffectTarget{Kind: TargetPerson, Conversation: "person-1"}
	effect := OutboundEffect{
		Version: EffectVersionOne,
		ID: "effect-1", EndpointID: "endpoint-1", OperationID: "operation-1", CorrelationID: "correlation-1", CausationID: "causation-1",
		Lane: testLane(t, target), Deadline: time.Now().Add(time.Minute), Risk: EffectRiskNormal, RetryClass: EffectRetryNonIdempotent,
		RequiredCapabilities: CapabilityOutbound, RequiredAction: ActionKindSendMessage, Kind: EffectKindMessage,
		Payload: EffectPayload{Kind: EffectPayloadPersonText, Target: target, Text: "hello"},
	}
	if err := effect.Validate(); err != nil { t.Fatal(err) }
	if effect.Payload.Kind != EffectPayloadPersonText || effect.Payload.Target.Conversation != "person-1" { t.Fatalf("payload = %#v", effect.Payload) }
}
func TestLaneMetadataIdentityUsesEndpointAndTargetNotSequence(t *testing.T) {
	root := []byte("index-root")
	target := EffectTarget{Kind: TargetGroup, Conversation: "group-1"}
	sameLane, err := NewLaneMetadata("endpoint-1", target, root, 7)
	if err != nil {
		t.Fatal(err)
	}
	retriedLane, err := NewLaneMetadata("endpoint-1", target, root, 8)
	if err != nil {
		t.Fatal(err)
	}
	otherTargetLane, err := NewLaneMetadata("endpoint-1", EffectTarget{Kind: TargetGroup, Conversation: "group-2"}, root, 7)
	if err != nil {
		t.Fatal(err)
	}
	otherEndpointLane, err := NewLaneMetadata("endpoint-2", target, root, 7)
	if err != nil {
		t.Fatal(err)
	}

	if sameLane.TargetDigest != retriedLane.TargetDigest || sameLane.Key != retriedLane.Key || sameLane.MAC != retriedLane.MAC {
		t.Fatalf("sequence changed lane identity: first=%+v retry=%+v", sameLane, retriedLane)
	}
	if sameLane.Sequence == retriedLane.Sequence {
		t.Fatal("sequence did not remain transport metadata")
	}
	for _, lane := range []LaneMetadata{sameLane, retriedLane} {
		if err := lane.Verify(root, "endpoint-1", target); err != nil {
			t.Fatalf("lane verification failed: %+v: %v", lane, err)
		}
	}
	if sameLane.TargetDigest == otherTargetLane.TargetDigest || sameLane.Key == otherTargetLane.Key || sameLane.MAC == otherTargetLane.MAC {
		t.Fatalf("target collision: same=%+v other=%+v", sameLane, otherTargetLane)
	}
	if sameLane.TargetDigest == otherEndpointLane.TargetDigest || sameLane.Key == otherEndpointLane.Key || sameLane.MAC == otherEndpointLane.MAC {
		t.Fatalf("endpoint collision: same=%+v other=%+v", sameLane, otherEndpointLane)
	}
	if err := sameLane.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestOutboundPayloadUnionRejectsSecretsPathsAndUnboundedTargets(t *testing.T) {
	cases := []OutboundEffect{
		{Version: EffectVersionOne, ID: "effect-path", EndpointID: "endpoint-1", OperationID: "operation-1", CorrelationID: "correlation-1", CausationID: "causation-1", Lane: testLane(t, EffectTarget{Kind: TargetGroup, Conversation: "group-1"}), Deadline: time.Now().Add(time.Minute), Risk: EffectRiskNormal, RetryClass: EffectRetryNonIdempotent, Kind: EffectKindMessage, Payload: EffectPayload{Kind: EffectPayloadFile, Target: EffectTarget{Kind: TargetGroup, Conversation: "group-1"}, File: ArtifactInput{ID: "artifact-1", Filename: "/etc/passwd"}}},
		{Version: EffectVersionOne, ID: "effect-target", EndpointID: "endpoint-1", OperationID: "operation-1", CorrelationID: "correlation-1", CausationID: "causation-1", Lane: testLane(t, EffectTarget{Kind: TargetRaw, Raw: "target"}), Deadline: time.Now().Add(time.Minute), Risk: EffectRiskNormal, RetryClass: EffectRetryNonIdempotent, Kind: EffectKindMessage, Payload: EffectPayload{Kind: EffectPayloadGroupText, Target: EffectTarget{Kind: TargetRaw, Raw: strings.Repeat("x", MaxEffectFieldBytes+1)}, Text: "hello"}},
	}
	for _, effect := range cases {
		if !errors.Is(effect.Validate(), ErrInvalidContract) { t.Fatalf("invalid payload accepted: %#v", effect) }
	}
}

func TestOutboundCapabilityAndRetryClassification(t *testing.T) {
	effect := OutboundEffect{Version: EffectVersionOne, ID: "effect-1", EndpointID: "endpoint-1", OperationID: "operation-1", CorrelationID: "correlation-1", CausationID: "causation-1", Lane: testLane(t, EffectTarget{Kind: TargetGroup, Conversation: "group-1", Member: "member-1"}), Deadline: time.Now().Add(time.Minute), Risk: EffectRiskHigh, RetryClass: EffectRetryNonIdempotent, RequiredCapabilities: CapabilityOutbound | CapabilityActions, Kind: EffectKindAction, RequiredAction: ActionKindKick, Payload: EffectPayload{Kind: EffectPayloadKick, Target: EffectTarget{Kind: TargetGroup, Conversation: "group-1", Member: "member-1"}}}
	if err := effect.ValidateForCapabilities(CapabilityOutbound, ActionSet(0)); !errors.Is(err, ErrUnsupportedAction) { t.Fatalf("unsupported capability result = %v", err) }
	if effect.RetryClass == EffectRetryInvalid { t.Fatal("retry classification missing") }
}

func TestArtifactResultMetadataNeverCarriesBytesInImmutableView(t *testing.T) {
	artifact := NewArtifactResult("image/png", "qr.png", []byte("secret"))
	if err := artifact.Validate(); err != nil { t.Fatal(err) }
	if artifact.ImmutableMetadata().Filename != "qr.png" { t.Fatal("immutable artifact metadata was not preserved") }
}
func TestEffectResultArtifactJSONRedactsBytesAndRejectsUnsafeFilename(t *testing.T) {
	artifact := NewArtifactResult("image/png", "qr.png", []byte("secret-bytes"))
	result := EffectResult{Outcome: EffectSucceeded, Artifact: &artifact}
	encoded, err := json.Marshal(result)
	if err != nil || strings.Contains(string(encoded), "secret-bytes") { t.Fatalf("artifact bytes leaked: %s err=%v", encoded, err) }
	unsafe := artifact
	unsafe.Filename = "../qr.png"
	if unsafe.Validate() == nil { t.Fatal("unsafe artifact filename accepted") }
}
func TestVersionedEffectRejectsLegacyCrossFieldsAndRawJSON(t *testing.T) {
	target := EffectTarget{Kind: TargetPerson, Conversation: "person-1"}
	effect := OutboundEffect{Version: EffectVersionOne, ID: "effect-1", EndpointID: "endpoint-1", OperationID: "operation-1", CorrelationID: "correlation-1", CausationID: "causation-1", Lane: testLane(t, target), Deadline: time.Now().Add(time.Minute), Risk: EffectRiskNormal, RetryClass: EffectRetryNonIdempotent, RequiredCapabilities: CapabilityOutbound, RequiredAction: ActionKindSendMessage, Kind: EffectKindMessage, Text: "legacy", Payload: EffectPayload{Kind: EffectPayloadPersonText, Target: target, Text: "hello"}}
	if !errors.Is(effect.Validate(), ErrInvalidContract) { t.Fatal("v1 legacy fields accepted") }
	raw := EffectTarget{Kind: TargetRaw, Raw: "provider-target"}
	if encoded, err := json.Marshal(raw); err != nil || strings.Contains(string(encoded), "provider-target") { t.Fatalf("raw target leaked: %s err=%v", encoded, err) }
}

func TestPayloadVariantsRequireSafeTargetAndRetryMatrix(t *testing.T) {
	cases := []struct{ kind EffectPayloadKind; target EffectTarget; retry EffectRetryClass; action ActionKind }{
		{EffectPayloadPersonText, EffectTarget{Kind: TargetPerson, Conversation: "person"}, EffectRetryNonIdempotent, ActionKindSendMessage},
		{EffectPayloadGroupText, EffectTarget{Kind: TargetGroup, Conversation: "group"}, EffectRetryNonIdempotent, ActionKindSendMessage},
		{EffectPayloadEdit, EffectTarget{Kind: TargetPerson, Conversation: "person"}, EffectRetryProviderIdempotent, ActionKindEditMessage},
		{EffectPayloadBan, EffectTarget{Kind: TargetGroup, Conversation: "group", Member: "member"}, EffectRetryNonIdempotent, ActionKindBan},
		{EffectPayloadKick, EffectTarget{Kind: TargetGroup, Conversation: "group", Member: "member"}, EffectRetryNonIdempotent, ActionKindKick},
	}
	for _, tc := range cases { if _, _, action, retry, _, ok := payloadContract(tc.kind); !ok || action != tc.action || retry != tc.retry || tc.target.Validate() != nil { t.Fatalf("matrix mismatch %#v", tc) } }
}
func TestVersionZeroRejectsVersionedFieldsAndEnumerationsAreClosed(t *testing.T) {
	legacy := OutboundEffect{ID: "effect-1", Kind: EffectKindMessage, EndpointID: "endpoint-1", Text: "legacy"}
	if !errors.Is(legacy.Validate(), ErrInvalidContract) { t.Fatal("versioned fields mixed into v0 effect") }
	for _, outcome := range []EffectOutcome{0, 99} { if outcome.Valid() { t.Fatalf("unknown outcome accepted: %d", outcome) } }
}
func TestLegacyEffectRejectsUnsafeArtifactFilename(t *testing.T) {
	effect := OutboundEffect{ID: "effect-legacy-artifact", Kind: EffectKindMessage, Artifact: &ArtifactInput{ID: "artifact-1", Filename: "../evil"}}
	if effect.Validate() == nil { t.Fatal("legacy unsafe artifact accepted") }
}
func TestVersionedDeadlineEncodingAndSegmentArtifactCapability(t *testing.T) {
	target := EffectTarget{Kind: TargetPerson, Conversation: "person"}
	segment := MessageSegment{Kind: SegmentKindImage, Artifact: &ArtifactInput{ID: "artifact-1", Filename: "image.png"}}
	effect := OutboundEffect{Version: EffectVersionOne, ID: "effect-segment", EndpointID: "endpoint-1", OperationID: "operation-1", CorrelationID: "correlation-1", CausationID: "causation-1", Lane: testLane(t, target), Deadline: time.Now().Add(time.Minute), Risk: EffectRiskNormal, RetryClass: EffectRetryNonIdempotent, RequiredCapabilities: CapabilityOutbound | CapabilityRichMessages | CapabilityArtifacts, RequiredAction: ActionKindSendMessage, Kind: EffectKindMessage, Payload: EffectPayload{Kind: EffectPayloadSegments, Target: target, Segments: []MessageSegment{segment}}}
	if err := effect.ValidateForCapabilities(CapabilityOutbound|CapabilityRichMessages, ActionSet(0)); !errors.Is(err, ErrUnsupportedAction) { t.Fatalf("artifact segment without artifact capability accepted: %v", err) }
	effect.Deadline = time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC)
	if effect.Validate() == nil { t.Fatal("unencodable deadline accepted") }
}
func TestVersionedPayloadMetadataMismatchIsRejected(t *testing.T) {
	target := EffectTarget{Kind: TargetGroup, Conversation: "group", Member: "member"}
	base := OutboundEffect{Version: EffectVersionOne, ID: "effect-kick", EndpointID: "endpoint-1", OperationID: "operation-1", CorrelationID: "correlation-1", CausationID: "causation-1", Lane: testLane(t, target), Deadline: time.Now().Add(time.Minute), Risk: EffectRiskHigh, RetryClass: EffectRetryNonIdempotent, RequiredCapabilities: CapabilityOutbound | CapabilityActions, RequiredAction: ActionKindKick, Kind: EffectKindAction, Payload: EffectPayload{Kind: EffectPayloadKick, Target: target}}
	if err := base.Validate(); err != nil { t.Fatal(err) }
	cases := []func(*OutboundEffect){func(e *OutboundEffect) { e.Kind = EffectKindMessage }, func(e *OutboundEffect) { e.RequiredCapabilities = CapabilityOutbound }, func(e *OutboundEffect) { e.RequiredAction = ActionKindBan }, func(e *OutboundEffect) { e.RetryClass = EffectRetryProviderIdempotent }, func(e *OutboundEffect) { e.Risk = EffectRiskNormal }}
	for _, mutate := range cases { candidate := base; mutate(&candidate); if candidate.Validate() == nil { t.Fatalf("metadata mismatch accepted: %+v", candidate) } }
}
func TestEditAndRecallPayloadsRequireAndAcceptMessageIDs(t *testing.T) {
	target := EffectTarget{Kind: TargetPerson, Conversation: "person"}
	edit := EffectPayload{Kind: EffectPayloadEdit, Target: target, MessageID: "42", Text: "updated"}
	recall := EffectPayload{Kind: EffectPayloadRecall, Target: target, MessageID: "42"}
	if err := edit.Validate(); err != nil {
		t.Fatalf("valid edit rejected: %v", err)
	}
	if err := recall.Validate(); err != nil {
		t.Fatalf("valid recall rejected: %v", err)
	}
	edit.MessageID = ""
	recall.MessageID = ""
	if edit.Validate() == nil || recall.Validate() == nil {
		t.Fatal("edit or recall without message ID accepted")
	}
}
