package dice

import (
	"testing"
	"time"
)

func TestWaitForCommandReply(t *testing.T) {
	t.Run("reply arrives within grace window", func(t *testing.T) {
		ctx := &MsgContext{}
		go func() {
			time.Sleep(20 * time.Millisecond)
			ctx.SetCommandReplied(true)
		}()

		if !waitForCommandReply(ctx, 80*time.Millisecond) {
			t.Fatal("expected grace window to observe late reply")
		}
	})

	t.Run("reply does not arrive within grace window", func(t *testing.T) {
		ctx := &MsgContext{}
		if waitForCommandReply(ctx, 30*time.Millisecond) {
			t.Fatal("expected grace window to expire without reply")
		}
	})
}
