package message

import "testing"

func TestConvertStringMessage_ParseRecall(t *testing.T) {
	elems := ConvertStringMessage("[CQ:recall,id=123456]")
	if len(elems) != 1 {
		t.Fatalf("expected 1 element, got %d", len(elems))
	}

	recall, ok := elems[0].(*RecallElement)
	if !ok {
		t.Fatalf("expected RecallElement, got %T", elems[0])
	}
	if recall.MessageID != "123456" {
		t.Fatalf("unexpected MessageID: %q", recall.MessageID)
	}
	if recall.DelayMS != 0 {
		t.Fatalf("unexpected DelayMS: %d", recall.DelayMS)
	}
}

func TestConvertStringMessage_ParseRecallWithDelay(t *testing.T) {
	elems := ConvertStringMessage("[CQ:recall,id=654321,delay=250]")
	if len(elems) != 1 {
		t.Fatalf("expected 1 element, got %d", len(elems))
	}

	recall, ok := elems[0].(*RecallElement)
	if !ok {
		t.Fatalf("expected RecallElement, got %T", elems[0])
	}
	if recall.MessageID != "654321" {
		t.Fatalf("unexpected MessageID: %q", recall.MessageID)
	}
	if recall.DelayMS != 250 {
		t.Fatalf("unexpected DelayMS: %d", recall.DelayMS)
	}
}

func TestConvertStringMessage_ParseRecallWithoutID(t *testing.T) {
	elems := ConvertStringMessage("[CQ:recall,delay=15]")
	if len(elems) != 1 {
		t.Fatalf("expected 1 element, got %d", len(elems))
	}

	recall, ok := elems[0].(*RecallElement)
	if !ok {
		t.Fatalf("expected RecallElement, got %T", elems[0])
	}
	if recall.MessageID != "" {
		t.Fatalf("unexpected MessageID: %q", recall.MessageID)
	}
	if recall.DelayMS != 15 {
		t.Fatalf("unexpected DelayMS: %d", recall.DelayMS)
	}
}
