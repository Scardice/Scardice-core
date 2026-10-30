package adapterapi

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestForwardEffectRoundTripsAndBindsToConversation(t *testing.T) {
	const raw = `{"kind":14,"target":{"kind":2,"conversation":"QQ-Group:2002"},"forwardNodes":[{"senderId":"9001","senderName":"Dice","content":"first"},{"senderId":"9001","senderName":"Dice","content":"second"}]}`
	var payload EffectPayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatal(err)
	}
	if err := payload.Validate(); err != nil {
		t.Fatalf("forward payload rejected: %v", err)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Kind   int `json:"kind"`
		Target struct {
			Kind         TargetKind     `json:"kind"`
			Conversation ConversationID `json:"conversation"`
		} `json:"target"`
		ForwardNodes []struct {
			SenderID   string `json:"senderId"`
			SenderName string `json:"senderName"`
			Content    string `json:"content"`
		} `json:"forwardNodes"`
	}
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	if wire.Kind != 14 || wire.Target.Kind != TargetGroup || wire.Target.Conversation != "QQ-Group:2002" || len(wire.ForwardNodes) != 2 {
		t.Fatalf("forward payload wire value = %+v", wire)
	}
	if wire.ForwardNodes[0].SenderID != "9001" || wire.ForwardNodes[0].SenderName != "Dice" || wire.ForwardNodes[0].Content != "first" || wire.ForwardNodes[1].Content != "second" {
		t.Fatalf("forward node order or content changed: %+v", wire.ForwardNodes)
	}

	lane, laneErr := NewLaneMetadata("endpoint-1", payload.Target, []byte("index-root"), 1)
	if laneErr != nil {
		t.Fatal(laneErr)
	}
	effect := OutboundEffect{
		Version: EffectVersionOne, ID: "effect-forward", EndpointID: "endpoint-1", OperationID: "operation-forward",
		CorrelationID: "correlation-forward", CausationID: "causation-forward", Lane: lane,
		Deadline: time.Now().Add(time.Minute), Risk: EffectRiskNormal, RetryClass: EffectRetryNonIdempotent,
		RequiredCapabilities: CapabilityOutbound | CapabilityRichMessages, RequiredAction: ActionKindSendMessage,
		Kind: EffectKindMessage, Payload: payload,
	}
	if err := effect.ValidateForCapabilities(CapabilityOutbound|CapabilityRichMessages, ActionSet(0).With(ActionKindSendMessage)); err != nil {
		t.Fatalf("forward effect rejected for a rich-message endpoint: %v", err)
	}
	if err := effect.ValidateForCapabilities(CapabilityOutbound, ActionSet(0).With(ActionKindSendMessage)); err == nil {
		t.Fatal("forward effect accepted without rich-message capability")
	}
	if err := effect.ValidateForCapabilities(CapabilityOutbound|CapabilityRichMessages, ActionSet(0)); !errors.Is(err, ErrUnsupportedAction) {
		t.Fatalf("forward effect without send-message action error = %v", err)
	}
}

func TestForwardPayloadRejectsIncompleteNodes(t *testing.T) {
	for name, raw := range map[string]string{
		"empty nodes":    `{"kind":14,"target":{"kind":2,"conversation":"QQ-Group:2002"},"forwardNodes":[]}`,
		"missing sender": `{"kind":14,"target":{"kind":2,"conversation":"QQ-Group:2002"},"forwardNodes":[{"senderName":"Dice","content":"first"}]}`,
		"empty content":  `{"kind":14,"target":{"kind":2,"conversation":"QQ-Group:2002"},"forwardNodes":[{"senderId":"9001","senderName":"Dice","content":"  "}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			var payload EffectPayload
			if err := json.Unmarshal([]byte(raw), &payload); err != nil {
				t.Fatal(err)
			}
			if err := payload.Validate(); !errors.Is(err, ErrInvalidContract) {
				t.Fatalf("invalid forward payload error = %v", err)
			}
		})
	}
}
