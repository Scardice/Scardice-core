package dice

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"testing"
)

func TestCanonicalFacadeResolutionIsSingleIdentityPerRoot(t *testing.T) {
	d, _ := newCanonicalTestDice(t)
	endpoint := newCanonicalTestEndpoint(d, "QQ:facade-race-bot")
	ctx := newCanonicalTestMessageContext(t, d, endpoint, newGroupMsg("QQ-Group:facade-race", "QQ:owner", ""), "facade-resolution-race")

	const workers = 100
	results := make(chan *GroupInfo, workers)
	errs := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			group, err := ctx.ResolveGroup(context.Background(), ctx.Group.GroupID())
			if err != nil {
				errs <- err
				return
			}
			results <- group
		}()
	}
	wait.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	for group := range results {
		if group != ctx.Group {
			t.Fatalf("same root returned distinct facades: got %p want %p", group, ctx.Group)
		}
	}
}

func TestCanonicalExtensionStateAndRuntimeCacheRemainConsistentUnderConcurrency(t *testing.T) {
	extension1 := &ExtInfo{Name: "ext1"}
	extension2 := &ExtInfo{Name: "ext2"}
	d, _ := newCanonicalTestDice(t)
	installCanonicalTestExtensions(d, extension1, extension2)
	endpoint := newCanonicalTestEndpoint(d, "QQ:extension-race-bot")
	ctx := newCanonicalTestMessageContext(t, d, endpoint, newGroupMsg("QQ-Group:extension-race", "QQ:owner", ""), "extension-state-race")
	if err := ctx.Group.SetExtension(extension1.Name, true); err != nil {
		t.Fatal(err)
	}

	const workers = 50
	errs := make(chan error, workers*2)
	var wait sync.WaitGroup
	for index := range workers {
		wait.Add(2)
		go func() {
			defer wait.Done()
			for _, extension := range ctx.Group.GetActivatedExtList(d) {
				if extension == nil || extension.Name == "" {
					errs <- fmt.Errorf("invalid derived extension: %#v", extension)
				}
			}
		}()
		go func(enabled bool) {
			defer wait.Done()
			if err := ctx.Group.SetExtension(extension2.Name, enabled); err != nil {
				errs <- err
			}
		}(index%2 == 0)
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	if err := ctx.Group.SetExtension(extension2.Name, true); err != nil {
		t.Fatal(err)
	}
	want := ctx.Group.ActivatedExtensionIDs()
	got := extListToNames(ctx.Group.GetActivatedExtList(d))
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("runtime extension cache = %v, canonical IDs = %v", got, want)
	}
}
