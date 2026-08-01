package dice

import (
	"testing"
	"time"

	ds "github.com/sealdice/dicescript"

	"Scardice-core/message"
)

type aliasTargetCapture struct {
	message  string
	segments []message.IMessageElement
}

func TestAliasExecutionRebuildsSegmentsForGroupAndPersonalTargetsWithCQCode(t *testing.T) {
	// Given
	d, ep, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()

	captures := make(chan aliasTargetCapture, 2)
	d.CmdMap["capture"] = &CmdItemInfo{
		Name: "capture",
		Solve: func(_ *MsgContext, msg *Message, _ *CmdArgs) CmdExecuteResult {
			captures <- aliasTargetCapture{
				message:  msg.Message,
				segments: append([]message.IMessageElement(nil), msg.Segment...),
			}
			return CmdExecuteResult{Matched: true, Solved: true}
		},
	}

	tests := []struct {
		name     string
		attrID   string
		attrKey  string
		incoming *Message
		target   string
		atTarget string
	}{
		{
			name:     "group alias",
			attrID:   "QQ-Group:alias-segment",
			attrKey:  "$g:alias:cq",
			incoming: newGroupMsg("QQ-Group:alias-segment", "QQ:200001", ".&cq"),
			target:   ".capture [CQ:at,qq=200002] group",
			atTarget: "200002",
		},
		{
			name:     "personal alias",
			attrID:   "QQ:300001",
			attrKey:  "$m:alias:cq",
			incoming: newPrivateMsg("QQ:300001", ".&cq"),
			target:   ".capture [CQ:at,qq=300002] personal",
			atTarget: "300002",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			attrs, err := d.AttrsManager.LoadById(test.attrID)
			if err != nil {
				t.Fatalf("load alias attributes: %v", err)
			}
			attrs.Store(test.attrKey, ds.NewStrVal(test.target))

			// When
			d.ImSession.ExecuteNew(ep, test.incoming)

			// Then
			var capture aliasTargetCapture
			select {
			case capture = <-captures:
			case <-time.After(2 * time.Second):
				t.Fatal("timeout waiting for alias target command")
			}
			if capture.message != test.target {
				t.Fatalf("alias target message = %q, want %q", capture.message, test.target)
			}
			var gotAtTarget string
			for _, segment := range capture.segments {
				if at, ok := segment.(*message.AtElement); ok {
					gotAtTarget = at.Target
					break
				}
			}
			if gotAtTarget != test.atTarget {
				t.Fatalf("alias target CQ-at = %q from %#v, want %q", gotAtTarget, capture.segments, test.atTarget)
			}
		})
	}
}
