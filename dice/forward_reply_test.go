package dice

import (
	"strings"
	"testing"

	ds "github.com/sealdice/dicescript"
	"go.uber.org/zap"

	"Scardice-core/message"
)

func TestForwardReplyPlanMixedAndSplit(t *testing.T) {
	ctx := &MsgContext{}
	ctx.InitSplitKey()
	wrapped := ctx.wrapForward("first" + ctx.getSplitKey() + "second")
	plan := ctx.compileReplyPlan("before" + wrapped + "after")
	if len(plan) != 3 {
		t.Fatalf("plan length = %d, want 3", len(plan))
	}
	if plan[0].Forward || plan[0].Text != "before" || !plan[1].Forward || plan[2].Forward || plan[2].Text != "after" {
		t.Fatalf("unexpected mixed reply plan: %#v", plan)
	}
	parts := ctx.SplitText(plan[1].Text)
	if len(parts) != 2 || parts[0] != "first" || parts[1] != "second" {
		t.Fatalf("forward node parts = %#v", parts)
	}
}

func TestExpandedForwardContentIsExcludedFromCommandText(t *testing.T) {
	msg := &Message{Segment: []message.IMessageElement{
		&message.ForwardElement{Kind: "forward", Loaded: true, Nodes: []message.ForwardNode{{
			SenderID: "10001", SenderName: "sender", Elements: message.ConvertStringMessage(".r 100d100"),
		}}},
	}}
	ensureMessageTextFromSegments(msg)
	if strings.Contains(msg.Message, ".r") || strings.Contains(extractResultFromSegments(msg.Segment), ".r") {
		t.Fatalf("expanded forward leaked into command text: message=%q args=%q", msg.Message, extractResultFromSegments(msg.Segment))
	}
}

func TestOnebotInlineForwardExpandsOnlyIntoSegmentTree(t *testing.T) {
	raw := []byte(`{"message_type":"private","user_id":10001,"message":[{"type":"forward","data":{"id":"forward-1","content":[{"type":"node","data":{"user_id":10002,"nickname":"nested","content":[{"type":"text","data":{"text":".help"}}]}}]}}]}`)
	msg, err := arrayByte2ScardiceMessage(zap.NewNop().Sugar(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(msg.Segment) != 1 {
		t.Fatalf("segments = %d", len(msg.Segment))
	}
	forward, ok := msg.Segment[0].(*message.ForwardElement)
	if !ok || !forward.Loaded || len(forward.Nodes) != 1 {
		t.Fatalf("forward was not expanded structurally: %#v", msg.Segment[0])
	}
	if strings.Contains(msg.Message, ".help") {
		t.Fatalf("forward command leaked into top-level text: %q", msg.Message)
	}
}

func TestDiceScriptForwardAcceptsMultilineFString(t *testing.T) {
	ctx := &MsgContext{}
	vm := ds.NewVM()
	vm.Attrs.Store("forward", ds.NewNativeFunctionVal(&ds.NativeFunctionData{
		Name: "forward", Params: []string{"text"},
		NativeFunc: func(_ *ds.Context, _ *ds.VMValue, params []*ds.VMValue) *ds.VMValue {
			return ds.NewStrVal(ctx.wrapForward(params[0].ToString()))
		},
	}))
	value, err := vm.RunExpr("\x1e{forward(`first line\nsecond line`)}\x1e", true)
	if err != nil {
		t.Fatalf("multiline forward failed to parse: %v", err)
	}
	plan := ctx.compileReplyPlan(value.ToString())
	if len(plan) != 1 || !plan[0].Forward || plan[0].Text != "first line\nsecond line" {
		t.Fatalf("unexpected multiline forward result: %#v", plan)
	}
}
