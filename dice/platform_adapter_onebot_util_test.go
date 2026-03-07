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
