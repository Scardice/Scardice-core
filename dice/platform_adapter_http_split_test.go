package dice

import (
	"fmt"
	"strings"
	"testing"

	"Scardice-core/utils"
)

func TestPlatformAdapterHTTPSplitsTestOutputByRequestLimit(t *testing.T) {
	const text = "long output that must retain every character "
	input := strings.Repeat(text, 60)

	for _, test := range []struct {
		name      string
		limit     int
		wantParts int
	}{
		{name: "short", limit: 300, wantParts: 9},
		{name: "qq", limit: 2000, wantParts: 2},
		{name: "unlimited", limit: 0, wantParts: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			adapter := &PlatformAdapterHTTP{}
			cursor := adapter.RecentMessagesSince("").Cursor
			ctx := &MsgContext{uiTestSplitLength: test.limit, uiTestSplitLengthSet: true}
			adapter.appendRecentMessages(ctx, "UI:1001", input, "private")

			messages := adapter.RecentMessagesSince(cursor).Messages
			if len(messages) != test.wantParts {
				t.Fatalf("message count = %d, want %d", len(messages), test.wantParts)
			}
			var joined strings.Builder
			for i, message := range messages {
				if message.UID != "UI:1001" || message.MessageType != "private" {
					t.Fatalf("message metadata = %#v", message)
				}
				content := message.Message
				if len(messages) > 1 {
					hint := fmt.Sprintf(utils.DefaultSplitPaginationHint, i+1, len(messages))
					var ok bool
					content, ok = strings.CutPrefix(content, hint)
					if !ok {
						t.Fatalf("message %d is missing pagination hint %q", i+1, hint)
					}
				}
				if test.limit > 0 && len(content) > test.limit {
					t.Fatalf("chunk body length = %d, exceeds requested limit %d", len(content), test.limit)
				}
				joined.WriteString(content)
			}
			if got := joined.String(); got != input {
				t.Fatalf("joined output length = %d, want exact input length %d", len(got), len(input))
			}
		})
	}
}

func TestCreateTempCtxPreservesUITestOutputSplitRequest(t *testing.T) {
	d, _, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()

	uiEndpoint := &EndPointInfo{
		EndPointInfoBase: EndPointInfoBase{
			ID: "1", UserID: "UI:1000", Nickname: "UI", Platform: "UI", Enable: true, State: StateConnected,
		},
		Adapter: &PlatformAdapterHTTP{},
	}
	uiEndpoint.bindCompatibilityRuntime(d.ImSession)
	msg := newGroupMsg("UI-Group:2101", "UI:1101", ".r 1")
	msg.TestUIOutputSplitLength = 2000
	msg.TestUIOutputSplitLengthSet = true

	ctx := CreateTempCtx(uiEndpoint, msg)
	if !ctx.uiTestSplitLengthSet || ctx.uiTestSplitLength != 2000 {
		t.Fatalf("context split request = (%d, %t), want (2000, true)", ctx.uiTestSplitLength, ctx.uiTestSplitLengthSet)
	}
}
