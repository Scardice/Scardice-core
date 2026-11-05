package api

import (
	"context"
	"sync"
	"testing"
)

type apiTestOutboundNotificationOwner struct {
	ctx     context.Context
	mu      sync.Mutex
	closed  bool
	workers sync.WaitGroup
}

func newAPITestOutboundNotificationOwner(t *testing.T) *apiTestOutboundNotificationOwner {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	owner := &apiTestOutboundNotificationOwner{ctx: ctx}
	t.Cleanup(func() {
		owner.mu.Lock()
		owner.closed = true
		cancel()
		owner.mu.Unlock()
		owner.workers.Wait()
	})
	return owner
}

func (owner *apiTestOutboundNotificationOwner) Go(run func(context.Context)) bool {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closed || run == nil {
		return false
	}
	owner.workers.Add(1)
	go func() {
		defer owner.workers.Done()
		run(owner.ctx)
	}()
	return true
}
