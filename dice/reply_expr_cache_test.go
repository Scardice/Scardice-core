package dice

import (
	"fmt"
	"sync"
	"testing"

	ds "github.com/sealdice/dicescript"
	"go.uber.org/zap"
)

func newReplyExprCacheTestContext(value int64) *MsgContext {
	ctx := &MsgContext{
		Dice:   &Dice{Logger: zap.NewNop().Sugar(), AttrsManager: &AttrsManager{}},
		Group:  &GroupInfo{},
		Player: &GroupPlayerInfo{ValueMapTemp: &ds.ValueMap{}},
	}
	ctx.SetSplitKey("###reply-expr-cache###")
	ctx.CreateVmIfNotExists()
	ctx.vm.Attrs.Store("value", ds.NewIntVal(ds.IntType(value)))
	return ctx
}

func TestReplyExprProgramCacheReusesBytecodeWithoutCachingResult(t *testing.T) {
	cache := newReplyExprProgramCache(4)
	flags := replyVMFlags(ReplyVMVersionV2)

	first, _, err := cache.eval(newReplyExprCacheTestContext(1), "value == 1", flags)
	if err != nil || first == nil || !first.AsBool() {
		t.Fatalf("first evaluation=%#v err=%v", first, err)
	}
	second, _, err := cache.eval(newReplyExprCacheTestContext(0), "value == 1", flags)
	if err != nil || second == nil || second.AsBool() {
		t.Fatalf("second evaluation=%#v err=%v", second, err)
	}
	if got := cache.size(); got != 1 {
		t.Fatalf("cache size=%d want=1", got)
	}
}

func TestReplyExprProgramCachePreservesTrailingInput(t *testing.T) {
	cache := newReplyExprProgramCache(4)
	result, _, err := cache.eval(newReplyExprCacheTestContext(1), "1 trailing", replyVMFlags(ReplyVMVersionV2))
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.GetRestInput() == "" {
		t.Fatalf("trailing input was accepted: %#v", result)
	}
}

func TestReplyExprProgramCacheIsBounded(t *testing.T) {
	cache := newReplyExprProgramCache(2)
	ctx := newReplyExprCacheTestContext(1)
	for _, expression := range []string{"1", "2", "3"} {
		if _, _, err := cache.eval(ctx, expression, replyVMFlags(ReplyVMVersionV2)); err != nil {
			t.Fatalf("eval %q: %v", expression, err)
		}
	}
	if got := cache.size(); got != 2 {
		t.Fatalf("cache size=%d want=2", got)
	}
}

func TestReplyExprProgramCacheConcurrentFirstUse(t *testing.T) {
	cache := newReplyExprProgramCache(4)
	flags := replyVMFlags(ReplyVMVersionV2)
	const workers = 32
	var wait sync.WaitGroup
	errs := make(chan error, workers)
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, _, err := cache.eval(newReplyExprCacheTestContext(1), "value == 1", flags)
			if err != nil {
				errs <- err
				return
			}
			if result == nil || !result.AsBool() {
				errs <- fmt.Errorf("cached expression returned %#v", result)
			}
		}()
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
