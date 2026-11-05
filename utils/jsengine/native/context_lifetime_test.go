//go:build cgo

package native

import (
	"context"
	"errors"
	"sync"
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

type persistentInvocationTestContext struct {
	mu                  sync.RWMutex
	context             context.Context
	id                  int
	replacement         bool
	observedReplacement chan struct{}
	observeOnce         sync.Once
}

func (c *persistentInvocationTestContext) ContextKey() any { return c.id }

func (c *persistentInvocationTestContext) ExecutionContext() context.Context {
	c.mu.RLock()
	execution := c.context
	replacement := c.replacement
	c.mu.RUnlock()
	if replacement && c.observedReplacement != nil {
		c.observeOnce.Do(func() { close(c.observedReplacement) })
	}
	return execution
}
func (c *persistentInvocationTestContext) PromotePersistentAsync(run func() (jsengine.Value, error)) error {
	_, err := run()
	return err
}

func (c *persistentInvocationTestContext) replaceExecutionContext(replacement context.Context) {
	c.mu.Lock()
	c.context = replacement
	c.replacement = true
	c.mu.Unlock()
}

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

func TestNativePersistentInvocationTokenFollowsReplacementContext(t *testing.T) {
	loop := newContextLoop()
	loadContext, cancelLoad := context.WithCancel(context.Background())
	schedulerContext, cancelScheduler := context.WithCancel(context.Background())
	scope := &persistentInvocationTestContext{
		context:             loadContext,
		id:                  2,
		observedReplacement: make(chan struct{}),
	}
	token := loop.registerContext(scope)
	scope.replaceExecutionContext(schedulerContext)
	cancelLoad()
	select {
	case <-scope.observedReplacement:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("native context retirement did not inspect the replacement")
	}
	loop.contextMu.RLock()
	retained := loop.contexts[token] == scope
	loop.contextMu.RUnlock()
	if !retained {
		t.Fatal("persistent invocation token retired with its replaced load context")
	}

	cancelScheduler()
	deadline := time.Now().Add(100 * time.Millisecond)
	for time.Now().Before(deadline) {
		loop.contextMu.RLock()
		_, retained = loop.contexts[token]
		loop.contextMu.RUnlock()
		if !retained {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if retained {
		t.Fatal("persistent invocation token survived its scheduler context")
	}
}
