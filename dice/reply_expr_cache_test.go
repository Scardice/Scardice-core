package dice

import (
	"fmt"
	"sync"
	"testing"

	ds "github.com/sealdice/dicescript"
)

func newReplyExprCacheTestContext(t *testing.T, d *Dice, label string, value int64) *MsgContext {
	t.Helper()
	ctx := newCanonicalTestMessageContext(
		t,
		d,
		newCanonicalTestEndpoint(d, "QQ:reply-cache-bot"),
		newGroupMsg("QQ-Group:reply-cache", "QQ:reply-cache-user", ""),
		label,
	)
	ctx.SetSplitKey("###reply-expr-cache###")
	ctx.CreateVmIfNotExists()
	ctx.vm.Attrs.Store("value", ds.NewIntVal(ds.IntType(value)))
	return ctx
}

func TestReplyExprProgramCacheReusesBytecodeWithoutCachingResult(t *testing.T) {
	d, _ := newCanonicalTestDice(t)
	cache := newReplyExprProgramCache(4)
	flags := replyVMFlags(ReplyVMVersionV2)

	first, _, err := cache.eval(newReplyExprCacheTestContext(t, d, "first-value", 1), "value == 1", flags)
	if err != nil || first == nil || !first.AsBool() {
		t.Fatalf("first evaluation=%#v err=%v", first, err)
	}
	second, _, err := cache.eval(newReplyExprCacheTestContext(t, d, "second-value", 0), "value == 1", flags)
	if err != nil || second == nil || second.AsBool() {
		t.Fatalf("second evaluation=%#v err=%v", second, err)
	}
	if got := cache.size(); got != 1 {
		t.Fatalf("cache size=%d want=1", got)
	}
}

func TestReplyExprProgramCachePreservesTrailingInput(t *testing.T) {
	d, _ := newCanonicalTestDice(t)
	cache := newReplyExprProgramCache(4)
	result, _, err := cache.eval(newReplyExprCacheTestContext(t, d, "trailing-input", 1), "1 trailing", replyVMFlags(ReplyVMVersionV2))
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.GetRestInput() == "" {
		t.Fatalf("trailing input was accepted: %#v", result)
	}
}

func TestReplyExprProgramCacheIsBounded(t *testing.T) {
	d, _ := newCanonicalTestDice(t)
	cache := newReplyExprProgramCache(2)
	ctx := newReplyExprCacheTestContext(t, d, "bounded-cache", 1)
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
	d, _ := newCanonicalTestDice(t)
	cache := newReplyExprProgramCache(4)
	flags := replyVMFlags(ReplyVMVersionV2)
	const workers = 32
	contexts := make([]*MsgContext, workers)
	for index := range contexts {
		contexts[index] = newReplyExprCacheTestContext(t, d, fmt.Sprintf("concurrent-%d", index), 1)
	}

	var wait sync.WaitGroup
	errs := make(chan error, workers)
	for index := range workers {
		wait.Add(1)
		go func(ctx *MsgContext) {
			defer wait.Done()
			result, _, err := cache.eval(ctx, "value == 1", flags)
			if err != nil {
				errs <- err
				return
			}
			if result == nil || !result.AsBool() {
				errs <- fmt.Errorf("cached expression returned %#v", result)
			}
		}(contexts[index])
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
