//go:build cgo

package native

import (
	"context"
	"errors"
	"testing"
	"time"

	"Scardice-core/utils/jsengine"
)

type invocationTestContext struct {
	context.Context
	id int
}

func (c *invocationTestContext) ContextKey() any                   { return c.id }
func (c *invocationTestContext) ExecutionContext() context.Context { return c.Context }

func TestNativeExpiredInvocationCannotBecomeUnbound(t *testing.T) {
	loop := newContextLoop()
	ctx, cancel := context.WithCancel(context.Background())
	token := loop.registerContext(&invocationTestContext{Context: ctx, id: 1})
	cancel()
	deadline := time.Now().Add(100 * time.Millisecond)
	for time.Now().Before(deadline) {
		loop.contextMu.RLock()
		size := len(loop.contexts)
		loop.contextMu.RUnlock()
		if size == 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	loop.contextMu.Lock()
	retained := len(loop.contexts) + len(loop.contextTokens)
	loop.currentToken = token
	loop.contextMu.Unlock()
	if retained != 0 {
		t.Errorf("expired invocation retains %d context entries", retained)
	}
	if err := jsengine.ContextForExecution(loop.CurrentContext()).Err(); !errors.Is(err, context.Canceled) {
		t.Fatalf("expired token lost revocation: %v", err)
	}
	fresh := loop.registerContext(&invocationTestContext{Context: context.Background(), id: 1})
	if fresh == token {
		t.Fatal("new invocation revived expired callbacks")
	}
}
