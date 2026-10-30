package dice

import (
	"cmp"
	"context"
	"maps"
	"math"
	"math/rand/v2"
	"slices"
	"sync"
	"sync/atomic"
	"time"
	"weak"

	"github.com/dop251/goja"

	"Scardice-core/utils/jsengine"
)

// TODO(插件内存/覆盖面): 目前只跟踪普通对象、数组与 ArrayBuffer。Map/Set、闭包与函数、
// 正则、Promise 以及插件持有的 Go 侧宿主对象都不计入；字符串只按持有者计入其直接引用的部分。
// TODO(插件内存/QuickJS): QuickJS 运行时与隔离 Goja realm 没有分配钩子，其插件的占用显示为“不支持”。

// JSHeapTrackerConfig bounds what tracking costs.
type JSHeapTrackerConfig struct {
	// SampleEvery is the mean number of small allocations per tracked one.
	// Each small allocation is tracked independently with probability
	// 1/SampleEvery and then stands for SampleEvery allocations.
	SampleEvery int
	// LargeBytes is the size at which an object is tracked individually: when
	// it is allocated that large (array buffers) or grows that large later.
	LargeBytes int
	// Interval is the time between two sweeps of the live objects.
	Interval time.Duration
}

// DefaultJSHeapTrackerConfig keeps the tracker's own memory around one
// percent of the small objects it estimates; see the pressure test.
var DefaultJSHeapTrackerConfig = JSHeapTrackerConfig{SampleEvery: 64, LargeBytes: 64 << 10, Interval: 15 * time.Second}

// jsHeapMinPrune is the record count below which dead records are left for
// the next sweep instead of being pruned while allocating.
const jsHeapMinPrune = 4096

// JSHeapAmount is an estimated number of live objects and the bytes they own.
type JSHeapAmount struct {
	Objects uint64
	Bytes   uint64
}

func (a *JSHeapAmount) add(objects, bytes uint64) {
	a.Objects += objects
	a.Bytes += bytes
}

// JSHeapStat estimates the live JS heap one plugin allocated, as of a sweep.
//
// Small objects are sampled, so their part is a statistical estimate whose
// precision grows with Samples. Large objects are tracked one by one and are
// exact up to the size approximation. Bytes count what each object owns
// directly (property table, elements, buffer data and the strings and numbers
// it holds), not what it references. An object is charged to the plugin
// whose code allocated it, or made it large; objects become dead only once a
// garbage collection has run.
type JSHeapStat struct {
	// Script is the plugin file; empty for plugins without one.
	Script string
	Plugin string
	// Total is the sum of the three kinds.
	Total       JSHeapAmount
	Object      JSHeapAmount
	Array       JSHeapAmount
	ArrayBuffer JSHeapAmount
	// Large is the part of Total tracked individually.
	Large JSHeapAmount
	// Samples counts the live sampled small objects behind the estimate.
	Samples uint64
}

func (s *JSHeapStat) add(kind goja.AllocationKind, objects, bytes uint64) {
	s.Total.add(objects, bytes)
	switch kind {
	case goja.AllocationObject:
		s.Object.add(objects, bytes)
	case goja.AllocationArray:
		s.Array.add(objects, bytes)
	case goja.AllocationArrayBuffer:
		s.ArrayBuffer.add(objects, bytes)
	}
}

func (s *JSHeapStat) merge(other JSHeapStat) {
	s.Total.add(other.Total.Objects, other.Total.Bytes)
	s.Object.add(other.Object.Objects, other.Object.Bytes)
	s.Array.add(other.Array.Objects, other.Array.Bytes)
	s.ArrayBuffer.add(other.ArrayBuffer.Objects, other.ArrayBuffer.Bytes)
	s.Large.add(other.Large.Objects, other.Large.Bytes)
	s.Samples += other.Samples
}

// JSHeapTracker estimates how much of the JS heap each plugin keeps alive. It
// holds weak pointers to a sample of the objects plugins allocate in every
// Goja runtime of a Dice, and periodically sums the size of the survivors.
type JSHeapTracker struct {
	enabled atomic.Bool
	config  atomic.Pointer[JSHeapTrackerConfig]

	mu     sync.Mutex
	realms map[*jsHeapRealm]*jsHeapPublished
	stop   chan struct{}
}

type jsHeapPublished struct {
	stats   []JSHeapStat
	sweptAt time.Time
}

// NewJSHeapTracker returns an enabled tracker using the default configuration.
func NewJSHeapTracker() *JSHeapTracker {
	t := &JSHeapTracker{realms: make(map[*jsHeapRealm]*jsHeapPublished)}
	t.SetConfig(DefaultJSHeapTrackerConfig)
	t.enabled.Store(true)
	return t
}

// SetEnabled turns tracking of new allocations on or off. Objects tracked
// before are still swept until they die.
func (t *JSHeapTracker) SetEnabled(enabled bool) { t.enabled.Store(enabled) }

// SetConfig replaces the policy. Sampling follows it from the next plugin
// invocation; a new Interval applies once the sweep timer restarts.
func (t *JSHeapTracker) SetConfig(config JSHeapTrackerConfig) {
	config.SampleEvery = max(config.SampleEvery, 1)
	if config.LargeBytes <= 0 {
		config.LargeBytes = DefaultJSHeapTrackerConfig.LargeBytes
	}
	if config.Interval <= 0 {
		config.Interval = DefaultJSHeapTrackerConfig.Interval
	}
	t.config.Store(&config)
}

// Snapshot returns the latest sweep of every runtime, merged per plugin and
// ordered by plugin file and name. sweptAt is the oldest of those sweeps, and
// zero while there is no runtime or one has not been swept yet.
func (t *JSHeapTracker) Snapshot() (stats []JSHeapStat, sweptAt time.Time) {
	t.mu.Lock()
	merged := make(map[jsAllocKey]*JSHeapStat)
	pending := len(t.realms) == 0
	for _, published := range t.realms {
		if published.sweptAt.IsZero() {
			pending = true
		} else if sweptAt.IsZero() || published.sweptAt.Before(sweptAt) {
			sweptAt = published.sweptAt
		}
		for _, stat := range published.stats {
			key := jsAllocKey{script: stat.Script, name: stat.Plugin}
			if existing := merged[key]; existing != nil {
				existing.merge(stat)
			} else {
				copied := stat
				merged[key] = &copied
			}
		}
	}
	t.mu.Unlock()
	if pending {
		sweptAt = time.Time{}
	}
	stats = make([]JSHeapStat, 0, len(merged))
	for _, stat := range merged {
		stats = append(stats, *stat)
	}
	slices.SortFunc(stats, func(a, b JSHeapStat) int {
		return cmp.Or(cmp.Compare(a.Script, b.Script), cmp.Compare(a.Plugin, b.Plugin))
	})
	return stats, sweptAt
}

// Sweep sweeps every runtime now and waits until all have published.
func (t *JSHeapTracker) Sweep(ctx context.Context) error {
	t.mu.Lock()
	realms := make([]*jsHeapRealm, 0, len(t.realms))
	for realm := range t.realms {
		realms = append(realms, realm)
	}
	t.mu.Unlock()
	done := make(chan struct{}, len(realms))
	waiting := 0
	for _, realm := range realms {
		if realm.schedule(func(*goja.Runtime) { realm.sweepAndPublish(); done <- struct{}{} }) {
			waiting++
		} else {
			t.detach(realm)
		}
	}
	for ; waiting > 0; waiting-- {
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// attach starts tracking a runtime. schedule queues work on the runtime's
// loop without going through the invocation observer and reports false once
// the loop has stopped. The returned realm must be installed both as the
// runtime's allocation tracker and as its loop's invocation observer, with
// next as the observer it wraps; detach it when the runtime closes.
func (t *JSHeapTracker) attach(schedule func(func(*goja.Runtime)) bool, next jsengine.InvocationObserver) *jsHeapRealm {
	realm := &jsHeapRealm{
		tracker:  t,
		next:     next,
		schedule: schedule,
		owners:   make(map[jsAllocKey]*jsHeapOwner),
		large:    make(map[weak.Pointer[goja.Object]]struct{}),
		pruneAt:  jsHeapMinPrune,
	}
	realm.applyConfig()
	realm.countdown = realm.nextStride()
	t.mu.Lock()
	t.realms[realm] = &jsHeapPublished{}
	if t.stop == nil {
		t.stop = make(chan struct{})
		go t.sweepPeriodically(t.stop, t.config.Load().Interval)
	}
	t.mu.Unlock()
	return realm
}

// detach forgets a runtime and its published statistics.
func (t *JSHeapTracker) detach(realm *jsHeapRealm) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.realms[realm]; !ok {
		return
	}
	delete(t.realms, realm)
	if len(t.realms) == 0 && t.stop != nil {
		close(t.stop)
		t.stop = nil
	}
}

func (t *JSHeapTracker) publish(realm *jsHeapRealm, stats []JSHeapStat, at time.Time) {
	t.mu.Lock()
	if published := t.realms[realm]; published != nil {
		published.stats, published.sweptAt = stats, at
	}
	t.mu.Unlock()
}

func (t *JSHeapTracker) sweepPeriodically(stop <-chan struct{}, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
		}
		t.mu.Lock()
		realms := make([]*jsHeapRealm, 0, len(t.realms))
		for realm := range t.realms {
			realms = append(realms, realm)
		}
		t.mu.Unlock()
		for _, realm := range realms {
			// A loop busy with a long callback must not pile up sweeps.
			if !realm.queued.CompareAndSwap(false, true) {
				continue
			}
			if !realm.schedule(func(*goja.Runtime) { realm.sweepAndPublish(); realm.queued.Store(false) }) {
				t.detach(realm)
			}
		}
	}
}

type jsHeapOwner struct {
	script string
	name   string
}

type jsHeapRecord struct {
	ptr    weak.Pointer[goja.Object]
	owner  *jsHeapOwner
	weight uint32
	kind   goja.AllocationKind
	large  bool
}

// jsHeapRealm tracks one Goja runtime. Apart from queued, its state belongs to
// the runtime's loop goroutine: allocations, invocations and sweeps all run
// there, so none of it needs a lock.
type jsHeapRealm struct {
	tracker  *JSHeapTracker
	next     jsengine.InvocationObserver
	schedule func(func(*goja.Runtime)) bool
	queued   atomic.Bool

	current     *jsHeapOwner
	owners      map[jsAllocKey]*jsHeapOwner
	sampleEvery int
	largeBytes  int
	countdown   int
	records     []jsHeapRecord
	// large holds the objects tracked individually, so that growth reported
	// again does not track them twice and their sampled record, if any, is
	// not counted on top.
	large     map[weak.Pointer[goja.Object]]struct{}
	largePeak int
	pruneAt   int
}

var (
	_ goja.AllocationTracker      = (*jsHeapRealm)(nil)
	_ jsengine.InvocationObserver = (*jsHeapRealm)(nil)
)

// ObserveInvocation implements jsengine.InvocationObserver: allocations made
// during the invocation are charged to the plugin that owns it.
func (r *jsHeapRealm) ObserveInvocation(context any, phase jsengine.InvocationPhase, run func() error) error {
	previous := r.current
	r.current = nil
	if r.tracker.enabled.Load() {
		r.applyConfig()
		r.current = r.ownerFor(context)
	}
	defer func() { r.current = previous }()
	if r.next == nil {
		return run()
	}
	return r.next.ObserveInvocation(context, phase, run)
}

func (r *jsHeapRealm) ownerFor(context any) *jsHeapOwner {
	script, name, _ := jsAllocIdentity(context)
	if script == "" && name == "" {
		return nil
	}
	key := jsAllocKey{script: script, name: name}
	owner := r.owners[key]
	if owner == nil {
		owner = &jsHeapOwner{script: script, name: name}
		r.owners[key] = owner
	}
	return owner
}

func (r *jsHeapRealm) applyConfig() {
	config := r.tracker.config.Load()
	if r.sampleEvery != config.SampleEvery {
		r.sampleEvery = config.SampleEvery
		r.countdown = min(r.countdown, r.sampleEvery)
	}
	r.largeBytes = config.LargeBytes
}

// nextStride draws the distance to the next sampled allocation. Sampling every
// allocation independently with probability 1/sampleEvery gives geometric
// distances, so no regular allocation pattern can line up with the sampler.
func (r *jsHeapRealm) nextStride() int {
	if r.sampleEvery <= 1 {
		return 1
	}
	return 1 + int(math.Log1p(-rand.Float64())/math.Log1p(-1/float64(r.sampleEvery)))
}

// Allocated implements goja.AllocationTracker.
func (r *jsHeapRealm) Allocated(o *goja.Object, kind goja.AllocationKind, bytes int) {
	owner := r.current
	if owner == nil {
		return
	}
	if bytes >= r.largeBytes {
		r.trackLarge(o, kind, owner)
		return
	}
	if r.countdown--; r.countdown > 0 {
		return
	}
	r.countdown = r.nextStride()
	r.append(jsHeapRecord{ptr: weak.Make(o), owner: owner, weight: uint32(r.sampleEvery), kind: kind})
}

// Grown implements goja.AllocationTracker.
func (r *jsHeapRealm) Grown(o *goja.Object, kind goja.AllocationKind, bytes int) {
	if owner := r.current; owner != nil && bytes >= r.largeBytes {
		r.trackLarge(o, kind, owner)
	}
}

func (r *jsHeapRealm) trackLarge(o *goja.Object, kind goja.AllocationKind, owner *jsHeapOwner) {
	ptr := weak.Make(o)
	if _, tracked := r.large[ptr]; tracked {
		return
	}
	r.large[ptr] = struct{}{}
	r.largePeak = max(r.largePeak, len(r.large))
	r.append(jsHeapRecord{ptr: ptr, owner: owner, weight: 1, kind: kind, large: true})
}

// append adds a record and, when the records have doubled since the last
// cleanup, drops those whose object has been collected. Under heavy churn this
// keeps the tracker's memory proportional to what is alive, not to what was
// ever allocated between two sweeps.
func (r *jsHeapRealm) append(record jsHeapRecord) {
	r.records = append(r.records, record)
	if len(r.records) >= r.pruneAt {
		r.compact(nil)
	}
}

// compact drops the records of collected objects and hands every surviving
// one to visit. Storage left over from a past peak is released, with enough
// slack that appending stays cheap.
func (r *jsHeapRealm) compact(visit func(record jsHeapRecord, o *goja.Object)) {
	kept := r.records[:0]
	for _, record := range r.records {
		o := record.ptr.Value()
		if o == nil {
			if record.large {
				delete(r.large, record.ptr)
			}
			continue
		}
		kept = append(kept, record)
		if visit != nil {
			visit(record, o)
		}
	}
	clear(r.records[len(kept):])
	if cap(kept) > 4*max(len(kept), jsHeapMinPrune) {
		kept = append(make([]jsHeapRecord, 0, 2*len(kept)), kept...)
	}
	r.records = kept
	r.pruneAt = max(2*len(kept), jsHeapMinPrune)
	// Go maps never shrink; rebuild the set once most of it has died.
	if r.largePeak > 4*max(len(r.large), jsHeapMinPrune) {
		r.large = maps.Clone(r.large)
		r.largePeak = len(r.large)
	}
}

// sweep estimates the live heap of every plugin. It must run on the loop.
//
// A sampled object stands for SampleEvery objects whatever its size: objects
// that grow large are tracked individually as they grow, so a sampled object
// that is large without that is one of a population that is large too.
func (r *jsHeapRealm) sweep() []JSHeapStat {
	totals := make(map[*jsHeapOwner]*JSHeapStat)
	r.compact(func(record jsHeapRecord, o *goja.Object) {
		if !record.large {
			if _, counted := r.large[record.ptr]; counted {
				return
			}
		}
		stat := totals[record.owner]
		if stat == nil {
			stat = &JSHeapStat{Script: record.owner.script, Plugin: record.owner.name}
			totals[record.owner] = stat
		}
		weight := uint64(record.weight)
		bytes := weight * uint64(o.ApproximateSize())
		stat.add(record.kind, weight, bytes)
		if record.large {
			stat.Large.add(1, bytes)
		} else {
			stat.Samples++
		}
	})
	stats := make([]JSHeapStat, 0, len(totals))
	for _, stat := range totals {
		stats = append(stats, *stat)
	}
	return stats
}

func (r *jsHeapRealm) sweepAndPublish() {
	r.tracker.publish(r, r.sweep(), time.Now())
}

// JSHeapTracker returns this Dice's heap tracker, creating it on first use.
// Every Goja runtime opened for this Dice reports to it.
func (d *Dice) JSHeapTracker() *JSHeapTracker {
	d.jsHeapTrackerOnce.Do(func() { d.jsHeapTracker = NewJSHeapTracker() })
	return d.jsHeapTracker
}
