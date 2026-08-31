package sealhttp

import (
	"context"
	"testing"
)

func TestFetchLifecycleCancelsTrackedRequestsOnClose(t *testing.T) {
	lifecycle := NewFetchLifecycle()
	ctx, cancel := context.WithCancel(context.Background())
	request := &fetchRequestData{ctx: ctx, cancel: cancel}
	if err := lifecycle.Start(request); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := lifecycle.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("Close() did not cancel the tracked request")
	}
	lifecycle.Done(request)
	if err := lifecycle.Start(request); err == nil {
		t.Fatal("Start() after Close error = nil")
	}
}
