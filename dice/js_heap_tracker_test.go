package dice

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/dop251/goja"
	"go.uber.org/zap"

	"Scardice-core/utils/jsengine"
)

func openHeapTrackedLoop(t *testing.T, config JSHeapTrackerConfig) (*Dice, jsengine.Loop) {
	t.Helper()
	d := &Dice{Logger: zap.NewNop().Sugar()}
	d.JSHeapTracker().SetConfig(config)
	loop, err := (&diceGojaProvider{dice: d}).Open(t.Context(), jsengine.RuntimeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = loop.Close() })
	return d, loop
}

func runAs(t *testing.T, loop jsengine.Loop, ctx *jsExecutionContext, source string) {
	t.Helper()
	if err := jsengine.RunWithContext(loop, ctx, func(rt jsengine.Runtime) error {
		_, err := rt.RunString("test.js", source)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func sweptHeapStats(t *testing.T, d *Dice) map[string]JSHeapStat {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if err := d.JSHeapTracker().Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	stats, sweptAt := d.JSHeapTracker().Snapshot()
	if sweptAt.IsZero() {
		t.Fatal("a sweep completed but the snapshot reports none")
	}
	byScript := make(map[string]JSHeapStat, len(stats))
	for _, stat := range stats {
		byScript[stat.Script] = stat
	}
	return byScript
}

func collectGarbage() {
	runtime.GC()
	runtime.GC()
}

func within(got, want uint64, tolerance float64) bool {
	return float64(got) >= float64(want)*(1-tolerance) && float64(got) <= float64(want)*(1+tolerance)
}

func TestJSHeapTrackerChargesLiveObjectsToThePluginThatAllocatedThem(t *testing.T) {
	d, loop := openHeapTrackedLoop(t, JSHeapTrackerConfig{SampleEvery: 8, LargeBytes: 64 << 10, Interval: time.Hour})
	a, b := allocPluginContext("/a.js", "A"), allocPluginContext("/b.js", "B")

	if err := jsengine.LoadEntryWithContext(loop, a, jsengine.Entry{Filename: "/a.js", Kind: jsengine.EntryExtension, Source: `
		globalThis.aBuffer = new ArrayBuffer(4 << 20);
		globalThis.aObjects = [];
		for (let i = 0; i < 40000; i++) aObjects.push({ index: i, label: "item-" + i });
	`}); err != nil {
		t.Fatal(err)
	}
	runAs(t, loop, b, `globalThis.bNumbers = Array.from({ length: 100000 }, (_, i) => i + 0.5);`)
	// Work outside any plugin is nobody's.
	if err := loop.Run(func(rt jsengine.Runtime) error {
		_, err := rt.RunString("host.js", `globalThis.hostObjects = []; for (let i = 0; i < 20000; i++) hostObjects.push({ i });`)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	stats := sweptHeapStats(t, d)
	if len(stats) != 2 {
		t.Fatalf("stats for %d scripts, want A and B only: %+v", len(stats), stats)
	}
	sa, sb := stats["/a.js"], stats["/b.js"]
	if sa.Plugin != "A" || sb.Plugin != "B" {
		t.Fatalf("plugin names %q %q", sa.Plugin, sb.Plugin)
	}
	if sa.ArrayBuffer.Objects != 1 || sa.ArrayBuffer.Bytes < 4<<20 || sa.ArrayBuffer.Bytes > 4<<20+4096 {
		t.Fatalf("A's 4 MiB buffer counted as %+v", sa.ArrayBuffer)
	}
	if !within(sa.Object.Objects, 40000, 0.15) {
		t.Fatalf("A's 40000 small objects estimated at %d", sa.Object.Objects)
	}
	// Each holds two properties and a short string.
	if perObject := sa.Object.Bytes / max(sa.Object.Objects, 1); perObject < 100 || perObject > 1000 {
		t.Fatalf("A's objects estimated at %d bytes each", perObject)
	}
	// The array holding them grew large and is tracked on its own.
	if sa.Array.Bytes < 40000*16 || sa.Large.Objects < 2 {
		t.Fatalf("A's large array missing: array %+v large %+v", sa.Array, sa.Large)
	}
	if sb.Array.Bytes < 100000*(16+8) || sb.Object.Objects > 100 {
		t.Fatalf("B's number array counted as %+v (objects %+v)", sb.Array, sb.Object)
	}
	if sa.Total.Bytes != sa.Object.Bytes+sa.Array.Bytes+sa.ArrayBuffer.Bytes {
		t.Fatalf("A's total %d does not add up", sa.Total.Bytes)
	}
}

func TestJSHeapTrackerForgetsWhatThePluginReleased(t *testing.T) {
	d, loop := openHeapTrackedLoop(t, JSHeapTrackerConfig{SampleEvery: 4, LargeBytes: 64 << 10, Interval: time.Hour})
	a := allocPluginContext("/a.js", "A")
	runAs(t, loop, a, `
		globalThis.keep = [];
		for (let i = 0; i < 20000; i++) keep.push({ index: i, label: "item-" + i });
		globalThis.buffer = new Uint8Array(2 << 20);
	`)
	if before := sweptHeapStats(t, d)["/a.js"]; before.Total.Bytes < 2<<20 {
		t.Fatalf("before release: %+v", before.Total)
	}
	runAs(t, loop, a, `keep = null; buffer = null;`)
	collectGarbage()
	if after := sweptHeapStats(t, d)["/a.js"]; after.Total.Bytes > 64<<10 {
		t.Fatalf("after release and GC the plugin still holds %+v", after.Total)
	}
}

func TestJSHeapTrackerDropsAClosedRuntime(t *testing.T) {
	d, loop := openHeapTrackedLoop(t, DefaultJSHeapTrackerConfig)
	runAs(t, loop, allocPluginContext("/a.js", "A"), `globalThis.buffer = new ArrayBuffer(1 << 20);`)
	if stats := sweptHeapStats(t, d); stats["/a.js"].ArrayBuffer.Objects != 1 {
		t.Fatalf("before close: %+v", stats)
	}
	if err := loop.Close(); err != nil {
		t.Fatal(err)
	}
	if stats, sweptAt := d.JSHeapTracker().Snapshot(); len(stats) != 0 || !sweptAt.IsZero() {
		t.Fatalf("a closed runtime still reports %+v at %v", stats, sweptAt)
	}
	d.JSHeapTracker().mu.Lock()
	running := d.JSHeapTracker().stop != nil
	d.JSHeapTracker().mu.Unlock()
	if running {
		t.Fatal("the sweep timer outlived the last runtime")
	}
}

func TestJSHeapTrackerSweepsPeriodically(t *testing.T) {
	d, loop := openHeapTrackedLoop(t, JSHeapTrackerConfig{SampleEvery: 1, LargeBytes: 64 << 10, Interval: 20 * time.Millisecond})
	runAs(t, loop, allocPluginContext("/a.js", "A"), `globalThis.kept = { value: 1 };`)
	deadline := time.Now().Add(5 * time.Second)
	for {
		stats, sweptAt := d.JSHeapTracker().Snapshot()
		if !sweptAt.IsZero() && len(stats) == 1 && stats[0].Object.Objects >= 1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no periodic sweep published: %+v at %v", stats, sweptAt)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// heapWorkload keeps a plugin-sized mix alive: many small objects and arrays,
// a few large arrays, and buffers both small and large.
const heapWorkload = `
	globalThis.records = [];
	for (let i = 0; i < 200000; i++) records.push({ id: i, name: "user-" + i, tags: [i % 7, i % 11] });
	globalThis.index = {};
	for (let i = 0; i < 50000; i++) index["k" + i] = i;
	globalThis.buffers = [];
	for (let i = 0; i < 2000; i++) buffers.push(new Uint8Array(1024));
	for (let i = 0; i < 16; i++) buffers.push(new Uint8Array(256 << 10));
`

func retainedHeap(t *testing.T, enabled bool) (retained uint64, estimate JSHeapStat) {
	t.Helper()
	d, loop := openHeapTrackedLoop(t, JSHeapTrackerConfig{SampleEvery: DefaultJSHeapTrackerConfig.SampleEvery, LargeBytes: DefaultJSHeapTrackerConfig.LargeBytes, Interval: time.Hour})
	d.JSHeapTracker().SetEnabled(enabled)
	var stats runtime.MemStats
	collectGarbage()
	runtime.ReadMemStats(&stats)
	before := stats.HeapAlloc
	runAs(t, loop, allocPluginContext("/w.js", "W"), heapWorkload)
	estimate = sweptHeapStats(t, d)["/w.js"]
	collectGarbage()
	runtime.ReadMemStats(&stats)
	retained = stats.HeapAlloc - before
	_ = loop.Close()
	collectGarbage()
	return retained, estimate
}

// The tracker must not noticeably raise the memory of the heap it measures.
func TestJSHeapTrackerPressureAddsLittleRetainedMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("pressure test")
	}
	baseline, _ := retainedHeap(t, false)
	tracked, estimate := retainedHeap(t, true)
	overhead := float64(tracked) - float64(baseline)
	t.Logf("retained without tracker %.1f MiB, with tracker %.1f MiB (%+.2f%%); estimate %.1f MiB from %d samples and %d large objects",
		float64(baseline)/(1<<20), float64(tracked)/(1<<20), 100*overhead/float64(baseline),
		float64(estimate.Total.Bytes)/(1<<20), estimate.Samples, estimate.Large.Objects)
	if overhead > 0.03*float64(baseline) {
		t.Fatalf("tracking added %.0f bytes to a %d byte heap", overhead, baseline)
	}
	// The estimate covers what the tracked kinds own, which is nearly all of
	// this workload; it must stay close to what the heap actually retains.
	if ratio := float64(estimate.Total.Bytes) / float64(baseline); ratio < 0.7 || ratio > 1.3 {
		t.Fatalf("estimate %d bytes is %.2f of the %d bytes retained", estimate.Total.Bytes, ratio, baseline)
	}
}

// Short-lived garbage must not pile up records between two sweeps.
func TestJSHeapTrackerPressureStaysSmallUnderChurn(t *testing.T) {
	if testing.Short() {
		t.Skip("pressure test")
	}
	d, loop := openHeapTrackedLoop(t, JSHeapTrackerConfig{SampleEvery: DefaultJSHeapTrackerConfig.SampleEvery, LargeBytes: DefaultJSHeapTrackerConfig.LargeBytes, Interval: time.Hour})
	a := allocPluginContext("/churn.js", "churn")
	for range 10 {
		runAs(t, loop, a, `for (let i = 0; i < 200000; i++) { const o = { i, s: "x" + i }; const arr = [o, i]; }`)
	}
	realm := onlyRealm(t, d)
	counts := make(chan int, 1)
	if !realm.schedule(func(*goja.Runtime) { counts <- len(realm.records) }) {
		t.Fatal("loop stopped")
	}
	// 4 million short-lived allocations sample about 62500 records; pruning
	// while allocating must keep only a small multiple of what is alive.
	if records := <-counts; records > 4*jsHeapMinPrune {
		t.Fatalf("%d records accumulated without a sweep", records)
	}
}

func onlyRealm(t *testing.T, d *Dice) *jsHeapRealm {
	t.Helper()
	tracker := d.JSHeapTracker()
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if len(tracker.realms) != 1 {
		t.Fatalf("%d realms attached, want 1", len(tracker.realms))
	}
	for realm := range tracker.realms {
		return realm
	}
	return nil
}

// A past peak of live objects must not pin the tracker's own storage.
func TestJSHeapTrackerReleasesItsStorageAfterAPeak(t *testing.T) {
	d, loop := openHeapTrackedLoop(t, JSHeapTrackerConfig{SampleEvery: 1, LargeBytes: 1024, Interval: time.Hour})
	a := allocPluginContext("/peak.js", "peak")
	runAs(t, loop, a, `
		globalThis.small = Array.from({ length: 100000 }, (_, i) => ({ i }));
		globalThis.large = Array.from({ length: 20000 }, () => new Uint8Array(2048));
	`)
	if stats := sweptHeapStats(t, d)["/peak.js"]; stats.Large.Objects < 20000 {
		t.Fatalf("peak not tracked: %+v", stats)
	}
	runAs(t, loop, a, `small = null; large = null;`)
	collectGarbage()
	sweptHeapStats(t, d)

	realm := onlyRealm(t, d)
	type sizes struct{ records, capacity, large, peak int }
	got := make(chan sizes, 1)
	if !realm.schedule(func(*goja.Runtime) {
		got <- sizes{len(realm.records), cap(realm.records), len(realm.large), realm.largePeak}
	}) {
		t.Fatal("loop stopped")
	}
	if s := <-got; s.capacity > 4*jsHeapMinPrune || s.peak > 4*jsHeapMinPrune {
		t.Fatalf("after release the tracker still holds %+v", s)
	}
}
