package jsengine

import (
	"context"
	"testing"
)

type asyncWorkTestScope struct {
	execution context.Context
	work      context.Context
	released  int
}

func (s *asyncWorkTestScope) ExecutionContext() context.Context { return s.execution }

func (s *asyncWorkTestScope) AsyncWorkContext() (context.Context, context.CancelFunc) {
	return s.work, func() { s.released++ }
}

func TestContextForAsyncWorkPrefersAsyncWorkScope(t *testing.T) {
	execution, cancelExecution := context.WithCancel(context.Background())
	cancelExecution()
	scope := &asyncWorkTestScope{execution: execution, work: context.Background()}

	ctx, release := ContextForAsyncWork(scope)
	if ctx != scope.work {
		t.Fatalf("ContextForAsyncWork() = %v, want the scope's async work context", ctx)
	}
	release()
	if scope.released != 1 {
		t.Fatalf("release called %d times, want 1", scope.released)
	}
}

func TestContextForAsyncWorkFallsBackToExecutionLifetime(t *testing.T) {
	execution, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx, release := ContextForAsyncWork(executionOnlyScope{execution})
	release()
	if ctx != execution {
		t.Fatalf("ContextForAsyncWork() = %v, want the execution lifetime", ctx)
	}
	if ctx, release := ContextForAsyncWork(nil); ctx == nil || release == nil {
		t.Fatal("ContextForAsyncWork(nil) must return a usable background lifetime")
	}
}

type executionOnlyScope struct{ ctx context.Context }

func (s executionOnlyScope) ExecutionContext() context.Context { return s.ctx }
