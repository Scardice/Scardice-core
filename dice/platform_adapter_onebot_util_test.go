package dice

import (
	"testing"

	"github.com/bytedance/sonic"

	"Scardice-core/dice/imsdk/onebot/schema"
	"Scardice-core/message"
)

func TestConvertSealMsgToMessageChain_AtElement(t *testing.T) {
	input := []message.IMessageElement{
		&message.AtElement{Target: "2930699167"},
	}

	chain, cq := convertSealMsgToMessageChain(input)
	if cq != "[CQ:at,qq=2930699167]" {
		t.Fatalf("unexpected cq output: %q", cq)
	}
	if len(chain) != 1 {
		t.Fatalf("expected 1 chain element, got %d", len(chain))
	}
	if chain[0].Type != "at" {
		t.Fatalf("expected type=at, got %s", chain[0].Type)
	}

	var at schema.At
	if err := sonic.Unmarshal(chain[0].Data, &at); err != nil {
		t.Fatalf("unmarshal at data failed: %v", err)
	}
	if at.QQ != "2930699167" {
		t.Fatalf("expected qq=2930699167, got %s", at.QQ)
	}
}

func TestFormatAndParseOnebotMessageID(t *testing.T) {
	formatted := formatOnebotMessageID(123456789)
	if formatted != "123456789" {
		t.Fatalf("unexpected formatted message id: %q", formatted)
	}

	parsed, err := parseOnebotMessageID(formatted)
	if err != nil {
		t.Fatalf("parseOnebotMessageID returned error: %v", err)
	}
	if parsed != 123456789 {
		t.Fatalf("unexpected parsed message id: %d", parsed)
	}
}

func TestMessageOBQQToStdMessageUsesStringRawID(t *testing.T) {
	msg := (&MessageOBQQ{
		MessageQQOBBase: MessageQQOBBase{
			MessageID:   778899,
			MessageType: "private",
		},
	}).toStdMessage()

	rawID, ok := msg.RawID.(string)
	if !ok {
		t.Fatalf("expected RawID to be string, got %T", msg.RawID)
	}
	if rawID != "778899" {
		t.Fatalf("unexpected RawID: %q", rawID)
	}
}
