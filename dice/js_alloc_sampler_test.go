package dice

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"Scardice-core/utils/jsengine"
)

var jsAllocSink [][]byte

const jsAllocMB = 1 << 20

// jsAllocNoise bounds what the rest of the test process may add to a window.
// Tests are not parallel, so this is runtime and testing-framework noise only.
const jsAllocNoise = 64 << 10

func newSampleEverythingSampler() *JSAllocSampler {
	sampler := NewJSAllocSampler()
	sampler.SetConfig(JSAllocSamplerConfig{Warmup: 1 << 40, Every: 1, MaxPerSecond: 1 << 40})
	return sampler
}

func allocatingRun(size int) func() error {
	return func() error {
		jsAllocSink = append(jsAllocSink[:0], make([]byte, size))
		return nil
	}
}

func allocPluginContext(file, name string) *jsExecutionContext {
	return &jsExecutionContext{Script: &JsScriptInfo{Name: name, Filename: file}}
}

func allocStat(t *testing.T, sampler *JSAllocSampler, file string, phase JSAllocPhase) JSAllocStat {
	t.Helper()
	for _, stat := range sampler.Snapshot() {
		if stat.Script == file && stat.Phase == phase {
			return stat
		}
	}
	t.Fatalf("no statistics for %q in phase %q: %+v", file, phase, sampler.Snapshot())
	return JSAllocStat{}
}

// sampledAllocStat waits for a measured invocation to be recorded. A window
// closes after the callback returns, so a test that was released from inside
// the callback can look before its own sample has landed.
func sampledAllocStat(t *testing.T, sampler *JSAllocSampler, file string, phase JSAllocPhase) JSAllocStat {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, stat := range sampler.Snapshot() {
			if stat.Script == file && stat.Phase == phase && stat.Samples > 0 {
				return stat
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no sample recorded for %q in phase %q: %+v", file, phase, sampler.Snapshot())
		}
		time.Sleep(time.Millisecond)
	}
}

func TestJSAllocSamplerChargesBytesToThePluginAndPhase(t *testing.T) {
	sampler := newSampleEverythingSampler()
	a, b := allocPluginContext("/a.js", "A"), allocPluginContext("/b.js", "B")

	for range 3 {
		_ = sampler.ObserveInvocation(a, jsengine.InvocationRun, allocatingRun(jsAllocMB))
	}
	_ = sampler.ObserveInvocation(a, jsengine.InvocationLoad, allocatingRun(2*jsAllocMB))
	_ = sampler.ObserveInvocation(b, jsengine.InvocationReaction, allocatingRun(jsAllocMB))
	_ = sampler.ObserveInvocation(jsCompletionContext(b), jsengine.InvocationSchedule, allocatingRun(jsAllocMB))
	_ = sampler.ObserveInvocation(b, jsengine.InvocationSchedule, allocatingRun(jsAllocMB))

	for _, want := range []struct {
		file   string
		phase  JSAllocPhase
		calls  uint64
		bytes  uint64
		plugin string
	}{
		{"/a.js", JSAllocPhaseRun, 3, 3 * jsAllocMB, "A"},
		{"/a.js", JSAllocPhaseLoad, 1, 2 * jsAllocMB, "A"},
		// A reaction and a host completion are both asynchronous; a callback the
		// host merely queued is a run.
		{"/b.js", JSAllocPhaseAsync, 2, 2 * jsAllocMB, "B"},
		{"/b.js", JSAllocPhaseRun, 1, jsAllocMB, "B"},
	} {
		stat := allocStat(t, sampler, want.file, want.phase)
		if stat.Plugin != want.plugin || stat.Calls != want.calls || stat.ExclusiveSamples != want.calls {
			t.Fatalf("%s/%s = %+v, want %d calls all exclusive for plugin %s", want.file, want.phase, stat, want.calls, want.plugin)
		}
		if stat.ExclusiveBytes < want.bytes || stat.ExclusiveBytes > want.bytes+jsAllocNoise*want.calls {
			t.Fatalf("%s/%s charged %d bytes, want about %d", want.file, want.phase, stat.ExclusiveBytes, want.bytes)
		}
		if stat.MaxExclusiveBytes < want.bytes/want.calls {
			t.Fatalf("%s/%s largest sample %d is below one call's share", want.file, want.phase, stat.MaxExclusiveBytes)
		}
	}
}

func TestJSAllocSamplerAddsNothingToTheWindowItMeasures(t *testing.T) {
	sampler := newSampleEverythingSampler()
	ctx := allocPluginContext("/idle.js", "idle")
	empty := func() error { return nil }
	for range 300 {
		_ = sampler.ObserveInvocation(ctx, jsengine.InvocationRun, empty)
	}
	stat := allocStat(t, sampler, "/idle.js", JSAllocPhaseRun)
	if stat.ExclusiveSamples == 0 {
		t.Fatal("no exclusive samples were taken")
	}
	if perWindow := stat.ExclusiveBytes / stat.ExclusiveSamples; perWindow > 64 {
		t.Fatalf("an empty invocation was charged %d bytes on average: the sampler is allocating inside its own window", perWindow)
	}
}

func TestJSAllocSamplerMeasuresWarmupThenOneInEvery(t *testing.T) {
	sampler := NewJSAllocSampler()
	sampler.SetConfig(JSAllocSamplerConfig{Warmup: 2, Every: 4, MaxPerSecond: 1 << 40})
	ctx := allocPluginContext("/p.js", "P")
	for range 20 {
		_ = sampler.ObserveInvocation(ctx, jsengine.InvocationRun, func() error { return nil })
	}
	stat := allocStat(t, sampler, "/p.js", JSAllocPhaseRun)
	// Calls 1 and 2 are warmup; afterwards calls 4, 8, 12, 16 and 20.
	if stat.Calls != 20 || stat.Samples != 7 {
		t.Fatalf("calls=%d samples=%d, want 20 calls and 7 samples", stat.Calls, stat.Samples)
	}
}

func TestJSAllocSamplerRateLimitSparesLoading(t *testing.T) {
	sampler := NewJSAllocSampler()
	sampler.SetConfig(JSAllocSamplerConfig{Warmup: 1 << 40, Every: 1, MaxPerSecond: 3})
	clock := time.Unix(1_700_000_000, 0)
	sampler.now = func() time.Time { return clock }
	ctx := allocPluginContext("/p.js", "P")
	noop := func() error { return nil }

	for range 10 {
		_ = sampler.ObserveInvocation(ctx, jsengine.InvocationRun, noop)
	}
	for range 10 {
		_ = sampler.ObserveInvocation(ctx, jsengine.InvocationLoad, noop)
	}
	if got := allocStat(t, sampler, "/p.js", JSAllocPhaseRun).Samples; got != 3 {
		t.Fatalf("samples within one second = %d, want the cap of 3", got)
	}
	if got := allocStat(t, sampler, "/p.js", JSAllocPhaseLoad).Samples; got != 10 {
		t.Fatalf("loading samples = %d, want all 10: the cap must not hide a plugin's load cost", got)
	}

	clock = clock.Add(time.Second)
	for range 10 {
		_ = sampler.ObserveInvocation(ctx, jsengine.InvocationRun, noop)
	}
	if got := allocStat(t, sampler, "/p.js", JSAllocPhaseRun).Samples; got != 6 {
		t.Fatalf("samples after the next second = %d, want 6", got)
	}
}

func TestJSAllocSamplerFlagsWindowsThatOverlapAnotherInvocation(t *testing.T) {
	sampler := newSampleEverythingSampler()
	a, b := allocPluginContext("/a.js", "A"), allocPluginContext("/b.js", "B")

	inside := make(chan struct{})
	release := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		_ = sampler.ObserveInvocation(a, jsengine.InvocationRun, func() error {
			close(inside)
			<-release
			return nil
		})
	})
	<-inside
	_ = sampler.ObserveInvocation(b, jsengine.InvocationRun, allocatingRun(jsAllocMB))
	close(release)
	wg.Wait()

	for _, file := range []string{"/a.js", "/b.js"} {
		stat := allocStat(t, sampler, file, JSAllocPhaseRun)
		if stat.Samples != 1 || stat.ExclusiveSamples != 0 || stat.ExclusiveBytes != 0 {
			t.Fatalf("%s overlapped another invocation but was trusted: %+v", file, stat)
		}
	}

	_ = sampler.ObserveInvocation(b, jsengine.InvocationRun, allocatingRun(jsAllocMB))
	if stat := allocStat(t, sampler, "/b.js", JSAllocPhaseRun); stat.ExclusiveSamples != 1 {
		t.Fatalf("a later, isolated invocation was not exclusive: %+v", stat)
	}
}

func TestJSAllocSamplerSurvivesAPanickingInvocation(t *testing.T) {
	sampler := newSampleEverythingSampler()
	ctx := allocPluginContext("/p.js", "P")
	func() {
		defer func() { _ = recover() }()
		_ = sampler.ObserveInvocation(ctx, jsengine.InvocationRun, func() error { panic("plugin failure") })
	}()
	if stat := allocStat(t, sampler, "/p.js", JSAllocPhaseRun); stat.Samples != 1 {
		t.Fatalf("the panicking invocation was not recorded: %+v", stat)
	}
	_ = sampler.ObserveInvocation(ctx, jsengine.InvocationRun, func() error { return nil })
	if stat := allocStat(t, sampler, "/p.js", JSAllocPhaseRun); stat.ExclusiveSamples != 2 {
		t.Fatalf("a panic left the process looking busy: %+v", stat)
	}
}

func TestJSAllocSamplerReturnsTheCallbackErrorUnchangedAndCanBeDisabled(t *testing.T) {
	failure := errors.New("callback failed")
	ctx := allocPluginContext("/p.js", "P")

	var nilSampler *JSAllocSampler
	if err := nilSampler.ObserveInvocation(ctx, jsengine.InvocationRun, func() error { return failure }); !errors.Is(err, failure) {
		t.Fatalf("nil sampler err = %v", err)
	}

	sampler := newSampleEverythingSampler()
	if err := sampler.ObserveInvocation(ctx, jsengine.InvocationRun, func() error { return failure }); !errors.Is(err, failure) {
		t.Fatalf("sampler err = %v", err)
	}
	sampler.SetEnabled(false)
	called := false
	if err := sampler.ObserveInvocation(ctx, jsengine.InvocationRun, func() error { called = true; return nil }); err != nil || !called {
		t.Fatalf("a disabled sampler must still run the callback: err=%v called=%v", err, called)
	}
	if stat := allocStat(t, sampler, "/p.js", JSAllocPhaseRun); stat.Calls != 1 {
		t.Fatalf("a disabled sampler recorded an invocation: %+v", stat)
	}
	sampler.Reset()
	if got := sampler.Snapshot(); len(got) != 0 {
		t.Fatalf("Reset kept %+v", got)
	}
}

func TestJSAllocSamplerNamesPluginsWithoutAScriptAndGroupsTheRest(t *testing.T) {
	sampler := newSampleEverythingSampler()
	noop := func() error { return nil }
	_ = sampler.ObserveInvocation(&jsExecutionContext{Plugin: &ExtInfo{Name: "builtin-ext"}}, jsengine.InvocationRun, noop)
	_ = sampler.ObserveInvocation(nil, jsengine.InvocationRun, noop)
	_ = sampler.ObserveInvocation("not a dice context", jsengine.InvocationRun, noop)

	byName := map[string]uint64{}
	for _, stat := range sampler.Snapshot() {
		if stat.Script != "" {
			t.Fatalf("unexpected script %q", stat.Script)
		}
		byName[stat.Plugin] += stat.Calls
	}
	if byName["builtin-ext"] != 1 || byName[""] != 2 {
		t.Fatalf("calls by name = %v, want the extension named and the other two unattributed", byName)
	}
}

func TestJSCompletionContextKeepsIdentityAndLeavesTheOriginalAlone(t *testing.T) {
	original := allocPluginContext("/p.js", "P")
	original.Message = &MsgContext{}
	derived, ok := jsCompletionContext(original).(*jsExecutionContext)
	if !ok || derived == original || !derived.Completion || original.Completion {
		t.Fatalf("derived=%+v original=%+v", derived, original)
	}
	if !sameJSRealm(original, derived) || derived.ContextKey() != original.ContextKey() {
		t.Fatal("a completion must stay the same plugin and message as its origin")
	}
	if again := jsCompletionContext(derived); again != any(derived) {
		t.Fatal("marking an already marked context must not copy it again")
	}
	var typedNil *jsExecutionContext
	if got := jsCompletionContext(typedNil); got != any(typedNil) {
		t.Fatalf("nil context changed: %v", got)
	}
	if got := jsCompletionContext("opaque"); got != "opaque" {
		t.Fatalf("foreign context changed: %v", got)
	}
}

// The provider must attach the sampler to the loops it opens, or none of the
// above ever sees a real plugin.
func TestJSAllocSamplerSeesLoadRunAndAsyncWorkOfARealLoop(t *testing.T) {
	d := &Dice{Logger: zap.NewNop().Sugar()}
	d.JSAllocSampler().SetConfig(JSAllocSamplerConfig{Warmup: 1 << 40, Every: 1, MaxPerSecond: 1 << 40})
	loop, err := (&diceGojaProvider{dice: d}).Open(t.Context(), jsengine.RuntimeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer loop.Close()

	const churn = `var keep = []; for (var i = 0; i < 20000; i++) keep.push({ index: i, label: "item-" + i });`
	ctx := allocPluginContext("/real.js", "real")
	if err := jsengine.LoadEntryWithContext(loop, ctx, jsengine.Entry{Filename: "/real.js", Source: churn, Kind: jsengine.EntryExtension}); err != nil {
		t.Fatal(err)
	}
	if err := jsengine.RunWithContext(loop, ctx, func(rt jsengine.Runtime) error {
		_, err := rt.RunString("callback.js", churn)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	if err := jsengine.RunWithContext(loop, ctx, func(rt jsengine.Runtime) error {
		if err := rt.Set("finished", func() { close(done) }); err != nil {
			return err
		}
		_, err := rt.RunString("timer.js", `setTimeout(function () { `+churn+` finished(); }, 1)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timer never fired")
	}

	for _, phase := range []JSAllocPhase{JSAllocPhaseLoad, JSAllocPhaseRun, JSAllocPhaseAsync} {
		stat := sampledAllocStat(t, d.JSAllocSampler(), "/real.js", phase)
		if stat.Plugin != "real" || stat.MaxExclusiveBytes < 256<<10 {
			t.Fatalf("phase %s = %+v, want the plugin's allocation attributed to it", phase, stat)
		}
	}
}

// A host service resumes script on the loop's queue, the same way the host
// queues its own callbacks. Only the completion marker tells them apart, so a
// finished fetch must be charged as asynchronous work and never as a callback.
func TestJSAllocSamplerCountsAFinishedFetchAsAsyncNotAsACallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("hello")) }))
	defer server.Close()

	d := &Dice{Logger: zap.NewNop().Sugar()}
	d.JSAllocSampler().SetConfig(JSAllocSamplerConfig{Warmup: 1 << 40, Every: 1, MaxPerSecond: 1 << 40})
	loop, err := (&diceGojaProvider{dice: d}).Open(t.Context(), jsengine.RuntimeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer loop.Close()

	ctx := allocPluginContext("/fetcher.js", "fetcher")
	bodies := make(chan string, 1)
	if err := jsengine.RunWithContext(loop, ctx, func(rt jsengine.Runtime) error {
		return rt.Set("fetched", func(body string) { bodies <- body })
	}); err != nil {
		t.Fatal(err)
	}
	source := `fetch(` + "`" + server.URL + "`" + `).then(function (r) { return r.text(); }).then(function (body) { fetched(body); });`
	if err := jsengine.LoadEntryWithContext(loop, ctx, jsengine.Entry{Filename: "/fetcher.js", Source: source, Kind: jsengine.EntryExtension}); err != nil {
		t.Fatal(err)
	}
	select {
	case body := <-bodies:
		if body != "hello" {
			t.Fatalf("fetched %q", body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fetch never completed")
	}

	if got := allocStat(t, d.JSAllocSampler(), "/fetcher.js", JSAllocPhaseAsync); got.Calls == 0 {
		t.Fatalf("the fetch completion was not counted as asynchronous work: %+v", got)
	}
	// The only run is the explicit RunWithContext that installed the callback.
	if got := allocStat(t, d.JSAllocSampler(), "/fetcher.js", JSAllocPhaseRun); got.Calls != 1 {
		t.Fatalf("run calls = %d, want 1: a finished fetch was charged as a delivered callback", got.Calls)
	}
}
