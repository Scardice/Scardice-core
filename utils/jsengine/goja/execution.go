package goja

import (
	"context"
	"reflect"
	"sync"
	"sync/atomic"

	"github.com/dop251/goja"

	"Scardice-core/utils/jsengine"
)

// Register interruption only once this invocation owns the VM. Stop and join
// the notifier before clearing: a late interrupt must not poison the next job.
func runWithExecutionContext(ctx context.Context, vm *goja.Runtime, run func() error) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if ctx.Done() == nil {
		return run()
	}
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		vm.Interrupt(ctx.Err())
		close(interrupted)
	})
	defer func() {
		if !stop() {
			<-interrupted
		}
		vm.ClearInterrupt()
		if contextErr := ctx.Err(); contextErr != nil {
			err = contextErr
		}
	}()
	return run()
}

// asyncContextToken is retained by Goja Promise reactions. Its payload exists
// only while the originating execution scope is live; cancellation turns it
// into a context-free tombstone.
type asyncContextToken struct {
	tracker *asyncContextTracker
	origin  any
	key     any
	stop    func() bool
	revoked bool
}

// asyncContextTracker is Goja's owner-thread bridge between Promise reactions
// and the host invocation that registered them. Comparable opaque contexts
// reuse one token, so a Promise graph does not allocate per reaction.
//
// Goja does not guarantee Exited after an interrupt. In particular, an
// InterruptedError raised by an async-function continuation escapes the
// reaction's vm.try and aborts the current Promise drain. Realm entry
// boundaries therefore call finish even when Goja cannot.
type asyncContextTracker struct {
	state *contextState
	vm    *goja.Runtime

	mu        sync.Mutex
	tokens    map[any]*asyncContextToken
	allTokens map[*asyncContextToken]struct{}
	closed    atomic.Bool

	boundaryDepth int
	resumed       bool
	previous      any
	leave         func()
	stop          func() bool
	interruptDone <-chan struct{}
	interrupted   bool
}

func (t *asyncContextTracker) enterBoundary() bool {
	root := t.boundaryDepth == 0
	t.boundaryDepth++
	return root
}

func (t *asyncContextTracker) exitBoundary(root bool) {
	t.boundaryDepth--
	if root {
		// contextState.with has already restored the boundary's context. Only
		// release reaction resources left behind by an abrupt Goja unwind.
		t.finish(false)
	}
}

func (t *asyncContextTracker) Grab() interface{} {
	origin := t.state.currentContext()
	if t.closed.Load() {
		return jsengine.RevokedExecutionScope{}
	}
	execution := jsengine.ContextForExecution(origin)
	if execution.Done() == nil {
		return origin
	}
	if execution.Err() != nil {
		return jsengine.RevokedExecutionScope{}
	}
	return t.tokenFor(origin, execution)
}

func asyncContextComparableKey(origin any) (any, bool) {
	if origin == nil {
		return nil, false
	}
	value := reflect.ValueOf(origin)
	return origin, value.IsValid() && value.Comparable()
}

func (t *asyncContextTracker) tokenFor(origin any, execution context.Context) interface{} {
	key, comparable := asyncContextComparableKey(origin)
	t.mu.Lock()
	if t.closed.Load() {
		t.mu.Unlock()
		return jsengine.RevokedExecutionScope{}
	}
	if comparable {
		if token := t.tokens[key]; token != nil && !token.revoked {
			t.mu.Unlock()
			return token
		}
	}
	token := &asyncContextToken{tracker: t, origin: origin}
	if comparable {
		token.key = key
		if t.tokens == nil {
			t.tokens = make(map[any]*asyncContextToken)
		}
		t.tokens[key] = token
	}
	if t.allTokens == nil {
		t.allTokens = make(map[*asyncContextToken]struct{})
	}
	t.allTokens[token] = struct{}{}
	t.mu.Unlock()

	stop := context.AfterFunc(execution, func() { t.revokeToken(token) })
	t.mu.Lock()
	retired := token.revoked || t.closed.Load()
	if !retired {
		token.stop = stop
	}
	t.mu.Unlock()
	if retired {
		stop()
	}
	if execution.Err() != nil {
		t.revokeToken(token)
	}
	return token
}

func (t *asyncContextTracker) resolveTrackingObject(trackingObject any) any {
	if t.closed.Load() {
		return jsengine.RevokedExecutionScope{}
	}
	token, ok := trackingObject.(*asyncContextToken)
	if !ok {
		return trackingObject
	}
	if token == nil || token.tracker != t {
		return jsengine.RevokedExecutionScope{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if token.revoked || token.origin == nil {
		return jsengine.RevokedExecutionScope{}
	}
	return token.origin
}

func (t *asyncContextTracker) revokeToken(token *asyncContextToken) {
	if token == nil || token.tracker != t {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if token.revoked {
		return
	}
	token.revoked = true
	if token.key != nil {
		if t.tokens[token.key] == token {
			delete(t.tokens, token.key)
		}
	}
	delete(t.allTokens, token)
	token.origin = nil
	token.key = nil
	token.stop = nil
}

func (t *asyncContextTracker) close() {
	if t == nil || t.closed.Swap(true) {
		return
	}
	t.mu.Lock()
	stops := make([]func() bool, 0, len(t.allTokens))
	for token := range t.allTokens {
		token.revoked = true
		token.origin = nil
		token.key = nil
		if token.stop != nil {
			stops = append(stops, token.stop)
			token.stop = nil
		}
	}
	t.tokens = nil
	t.allTokens = nil
	t.mu.Unlock()
	for _, stop := range stops {
		stop()
	}
}

func (t *asyncContextTracker) Resumed(trackingObject interface{}) {
	// Resumed/Exited are documented as non-nesting. Be defensive about an
	// earlier abrupt unwind so a missed Exited can never retain an admission
	// gate into later work.
	if t.resumed {
		t.finish(false)
	}
	trackingObject = t.resolveTrackingObject(trackingObject)

	previous := t.state.currentContext()
	leave, err := jsengine.EnterExecution(trackingObject, previous)
	t.resumed = true
	t.previous = previous
	t.leave = leave
	t.state.replaceContext(trackingObject)
	if err != nil {
		// AsyncContextTracker cannot selectively decline a reaction. Interrupt
		// is the only fail-closed option: Goja aborts this Promise drain rather
		// than running stale JavaScript under the resolver's authority.
		t.interrupted = true
		t.vm.Interrupt(err)
		return
	}

	execution := jsengine.ContextForExecution(trackingObject)
	if previous != nil && jsengine.ContextForExecution(previous) == execution {
		// The surrounding invocation already owns this gate and its
		// cancellation notifier.
		return
	}
	if execution.Done() == nil {
		return
	}

	interruptDone := make(chan struct{})
	t.interruptDone = interruptDone
	t.stop = context.AfterFunc(execution, func() {
		t.vm.Interrupt(execution.Err())
		close(interruptDone)
	})
	// Close the small registration race synchronously so stale JavaScript
	// cannot execute before context.AfterFunc gets scheduled.
	if err := execution.Err(); err != nil {
		t.interrupted = true
		t.vm.Interrupt(err)
	}
}

func (t *asyncContextTracker) Exited() {
	t.finish(true)
}

func (t *asyncContextTracker) finish(restore bool) {
	if !t.resumed {
		return
	}

	previous := t.previous
	leave := t.leave
	stop := t.stop
	interruptDone := t.interruptDone
	interrupted := t.interrupted

	t.resumed = false
	t.previous = nil
	t.leave = nil
	t.stop = nil
	t.interruptDone = nil
	t.interrupted = false

	if stop != nil && !stop() {
		<-interruptDone
		interrupted = true
	}
	if restore {
		t.state.replaceContext(previous)
	}
	if leave != nil {
		leave()
	}
	if interrupted {
		// A late notifier must not poison the next reaction. When Exited ran
		// normally, preserve cancellation of the surrounding resolver scope.
		t.vm.ClearInterrupt()
		if restore {
			if err := jsengine.ContextForExecution(previous).Err(); err != nil {
				t.vm.Interrupt(err)
			}
		}
	}
}

var _ goja.AsyncContextTracker = (*asyncContextTracker)(nil)
