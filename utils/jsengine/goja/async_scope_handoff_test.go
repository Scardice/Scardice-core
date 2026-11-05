package goja

import (
	"context"
	"testing"
	"time"

	g "github.com/dop251/goja"

	"Scardice-core/utils/jsengine"
)

// handoffScope is a promoted persistent root: once its own root ends it hands
// pending continuations to the longer-lived replacement scope.
type handoffScope struct {
	root              context.Context
	rootCancel        context.CancelFunc
	replacement       context.Context
	replacementCancel context.CancelFunc
	handedOver        chan struct{}
}

func newHandoffScope(t *testing.T) *handoffScope {
	t.Helper()
	root, rootCancel := context.WithCancel(context.Background())
	replacement, replacementCancel := context.WithCancel(context.Background())
	t.Cleanup(rootCancel)
	t.Cleanup(replacementCancel)
	return &handoffScope{
		root: root, rootCancel: rootCancel,
		replacement: replacement, replacementCancel: replacementCancel,
		handedOver: make(chan struct{}, 1),
	}
}

func (s *handoffScope) ExecutionContext() context.Context {
	if s.root.Err() == nil {
		return s.root
	}
	select {
	case s.handedOver <- struct{}{}:
	default:
	}
	return s.replacement
}

func (s *handoffScope) PromotePersistentAsync(func() (jsengine.Value, error)) error { return nil }

func TestAsyncContextTokenFollowsHandoffScopeAfterRootEnds(t *testing.T) {
	origin := newHandoffScope(t)
	state := &contextState{}
	state.replaceContext(origin)
	tracker := &asyncContextTracker{state: state, vm: g.New()}

	token, ok := tracker.Grab().(*asyncContextToken)
	if !ok {
		t.Fatal("Grab() did not return a cancellable token")
	}
	origin.rootCancel()
	select {
	case <-origin.handedOver:
	case <-time.After(2 * time.Second):
		t.Fatal("root end never consulted the scope for its replacement lifetime")
	}
	if resolved := tracker.resolveTrackingObject(token); resolved != origin {
		t.Fatalf("token resolved as %v after the root ended, want the handoff scope", resolved)
	}

	origin.replacementCancel()
	awaitAsyncTokenRevocation(t, tracker, token)
}
