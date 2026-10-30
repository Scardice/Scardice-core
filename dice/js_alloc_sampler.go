package dice

import (
	"cmp"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"Scardice-core/utils/jsengine"
)

// JSAllocPhase says what a plugin invocation was doing, for allocation accounting.
type JSAllocPhase string

const (
	// JSAllocPhaseLoad is evaluating the plugin's entry script.
	JSAllocPhaseLoad JSAllocPhase = "load"
	// JSAllocPhaseRun is a callback the host delivered: commands, message
	// hooks, scheduled tasks, activation and so on.
	JSAllocPhaseRun JSAllocPhase = "run"
	// JSAllocPhaseAsync is work the plugin started earlier and that resumes
	// on its own: timers, Promise reactions and host service completions.
	JSAllocPhaseAsync JSAllocPhase = "async"
)

// JSAllocSamplerConfig bounds the cost of measuring. Every sample reads the
// runtime allocation counter twice, and ReadMemStats stops the world, so the
// sampler measures a subset of invocations and never more than MaxPerSecond.
type JSAllocSamplerConfig struct {
	// Warmup measures the first Warmup invocations of each plugin and phase.
	Warmup uint64
	// Every measures one in Every invocations after the warmup.
	Every uint64
	// MaxPerSecond caps measured invocations across all plugins. Loading is
	// exempt: it happens once per plugin and is the most useful to see.
	MaxPerSecond int64
}

// DefaultJSAllocSamplerConfig keeps the stop-the-world cost well under one
// percent of a core in the worst case (measured ReadMemStats p50 is about 10µs).
var DefaultJSAllocSamplerConfig = JSAllocSamplerConfig{Warmup: 16, Every: 16, MaxPerSecond: 100}

// The heap counter is process-wide, so exclusivity is too: a window that
// overlaps any other observed JS invocation, on any Dice, is not exclusive.
var (
	jsAllocInflight atomic.Int64
	jsAllocStarted  atomic.Uint64
)

type jsAllocKey struct {
	script string
	name   string
	phase  JSAllocPhase
}

type jsAllocTotals struct {
	samples           uint64
	exclusiveSamples  uint64
	bytes             uint64
	exclusiveBytes    uint64
	maxExclusiveBytes uint64
}

type jsAllocEntry struct {
	calls atomic.Uint64
	mu    sync.Mutex
	total jsAllocTotals
}

// jsAllocWindow holds the two counters of one measurement. They are pooled so
// that taking a sample allocates nothing between the two reads.
type jsAllocWindow struct {
	before runtime.MemStats
	after  runtime.MemStats
}

// JSAllocStat is the allocation accounting of one plugin in one phase.
//
// Bytes come from the process-wide TotalAlloc counter, which cannot be split by
// goroutine, so a sample also contains whatever other goroutines allocated
// meanwhile. Exclusive samples are those that overlapped no other observed JS
// invocation; they are the trustworthy ones, though non-JS goroutines (message
// handling, storage) can still add noise. Scale a per-call average by Calls to
// estimate the total, since only a subset of invocations is measured.
type JSAllocStat struct {
	// Script is the plugin file; empty for invocations without a plugin.
	Script string
	// Plugin is the plugin's display name.
	Plugin string
	Phase  JSAllocPhase
	// Calls counts every observed invocation, measured or not.
	Calls            uint64
	Samples          uint64
	ExclusiveSamples uint64
	// SampledBytes sums the allocation of all samples.
	SampledBytes uint64
	// ExclusiveBytes sums the allocation of exclusive samples only.
	ExclusiveBytes uint64
	// MaxExclusiveBytes is the largest single exclusive sample.
	MaxExclusiveBytes uint64
}

// JSAllocSampler implements jsengine.InvocationObserver. It attributes the
// heap allocated during each plugin invocation to the plugin that owns it.
type JSAllocSampler struct {
	enabled atomic.Bool
	config  atomic.Pointer[JSAllocSamplerConfig]
	now     func() time.Time

	mu      sync.RWMutex
	entries map[jsAllocKey]*jsAllocEntry

	second atomic.Int64
	taken  atomic.Int64

	windows sync.Pool
}

var _ jsengine.InvocationObserver = (*JSAllocSampler)(nil)

// NewJSAllocSampler returns an enabled sampler using the default configuration.
func NewJSAllocSampler() *JSAllocSampler {
	s := &JSAllocSampler{now: time.Now, entries: make(map[jsAllocKey]*jsAllocEntry)}
	s.windows.New = func() any { return new(jsAllocWindow) }
	s.SetConfig(DefaultJSAllocSamplerConfig)
	s.enabled.Store(true)
	return s
}

// SetEnabled turns measuring on or off. While it is off nothing is recorded and
// observing an invocation costs one atomic load.
func (s *JSAllocSampler) SetEnabled(enabled bool) { s.enabled.Store(enabled) }

// SetConfig replaces the sampling policy. A zero Every measures every
// invocation after the warmup.
func (s *JSAllocSampler) SetConfig(config JSAllocSamplerConfig) {
	if config.Every == 0 {
		config.Every = 1
	}
	s.config.Store(&config)
}

// Reset discards all accumulated statistics.
func (s *JSAllocSampler) Reset() {
	s.mu.Lock()
	s.entries = make(map[jsAllocKey]*jsAllocEntry)
	s.mu.Unlock()
}

// Snapshot returns the statistics ordered by plugin file, name and phase.
func (s *JSAllocSampler) Snapshot() []JSAllocStat {
	s.mu.RLock()
	stats := make([]JSAllocStat, 0, len(s.entries))
	for key, entry := range s.entries {
		entry.mu.Lock()
		total := entry.total
		entry.mu.Unlock()
		stats = append(stats, JSAllocStat{
			Script: key.script, Plugin: key.name, Phase: key.phase,
			Calls: entry.calls.Load(), Samples: total.samples, ExclusiveSamples: total.exclusiveSamples,
			SampledBytes: total.bytes, ExclusiveBytes: total.exclusiveBytes, MaxExclusiveBytes: total.maxExclusiveBytes,
		})
	}
	s.mu.RUnlock()
	slices.SortFunc(stats, func(a, b JSAllocStat) int {
		return cmp.Or(cmp.Compare(a.Script, b.Script), cmp.Compare(a.Plugin, b.Plugin), cmp.Compare(a.Phase, b.Phase))
	})
	return stats
}

// ObserveInvocation implements jsengine.InvocationObserver.
func (s *JSAllocSampler) ObserveInvocation(context any, enginePhase jsengine.InvocationPhase, run func() error) error {
	if s == nil || !s.enabled.Load() {
		return run()
	}
	script, name, completion := jsAllocIdentity(context)
	phase := jsAllocPhaseFor(enginePhase, completion)
	entry := s.entry(jsAllocKey{script: script, name: name, phase: phase})
	calls := entry.calls.Add(1)

	running := jsAllocInflight.Add(1)
	started := jsAllocStarted.Add(1)
	defer jsAllocInflight.Add(-1)
	if !s.shouldSample(phase, calls) {
		return run()
	}
	return s.measure(entry, running, started, run)
}

// jsAllocPhaseFor refines the engine's entry mechanism. The host queues its own
// callbacks with Schedule, so only a completion context makes a scheduled task
// asynchronous; engine timers and Promise reactions always are.
func jsAllocPhaseFor(phase jsengine.InvocationPhase, completion bool) JSAllocPhase {
	switch phase {
	case jsengine.InvocationLoad:
		return JSAllocPhaseLoad
	case jsengine.InvocationReaction:
		return JSAllocPhaseAsync
	case jsengine.InvocationSchedule:
		if completion {
			return JSAllocPhaseAsync
		}
	case jsengine.InvocationRun:
		// A callback the host waited for is a run, like the default below.
	}
	return JSAllocPhaseRun
}

// jsAllocIdentity names the plugin that owns an invocation. The script file is
// the stable identity: it exists while the plugin is still loading, before the
// extension is registered, and survives reloads.
func jsAllocIdentity(context any) (script, name string, completion bool) {
	execution, _ := context.(*jsExecutionContext)
	if execution == nil {
		return "", "", false
	}
	if source := jsContextSource(execution); source != nil {
		return source.Filename, source.Name, execution.Completion
	}
	if plugin := jsContextPlugin(execution); plugin != nil {
		return "", plugin.Name, execution.Completion
	}
	return "", "", execution.Completion
}

func (s *JSAllocSampler) entry(key jsAllocKey) *jsAllocEntry {
	s.mu.RLock()
	entry := s.entries[key]
	s.mu.RUnlock()
	if entry != nil {
		return entry
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry = s.entries[key]; entry == nil {
		entry = new(jsAllocEntry)
		s.entries[key] = entry
	}
	return entry
}

func (s *JSAllocSampler) shouldSample(phase JSAllocPhase, calls uint64) bool {
	if phase == JSAllocPhaseLoad {
		return true
	}
	config := s.config.Load()
	if calls > config.Warmup && calls%config.Every != 0 {
		return false
	}
	second := s.now().Unix()
	if s.second.Load() != second {
		s.second.Store(second)
		s.taken.Store(0)
	}
	return s.taken.Add(1) <= config.MaxPerSecond
}

// measure brackets run with two allocation reads. Nothing between the reads may
// allocate except run itself, which is why the window comes from a pool and the
// bookkeeping happens after the second read.
func (s *JSAllocSampler) measure(entry *jsAllocEntry, running int64, started uint64, run func() error) error {
	window := s.windows.Get().(*jsAllocWindow)
	runtime.ReadMemStats(&window.before)
	defer s.finish(entry, window, running, started)
	return run()
}

func (s *JSAllocSampler) finish(entry *jsAllocEntry, window *jsAllocWindow, running int64, started uint64) {
	runtime.ReadMemStats(&window.after)
	bytes := window.after.TotalAlloc - window.before.TotalAlloc
	exclusive := running == 1 && jsAllocStarted.Load() == started
	s.windows.Put(window)

	entry.mu.Lock()
	entry.total.samples++
	entry.total.bytes += bytes
	if exclusive {
		entry.total.exclusiveSamples++
		entry.total.exclusiveBytes += bytes
		entry.total.maxExclusiveBytes = max(entry.total.maxExclusiveBytes, bytes)
	}
	entry.mu.Unlock()
}

// JSAllocSampler returns this Dice's sampler, creating it on first use. Every
// JS runtime opened for this Dice reports its invocations to it.
func (d *Dice) JSAllocSampler() *JSAllocSampler {
	d.jsAllocSamplerOnce.Do(func() { d.jsAllocSampler = NewJSAllocSampler() })
	return d.jsAllocSampler
}
