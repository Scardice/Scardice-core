package endpoint

import (
	"Scardice-core/adapterapi"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrSupervisorInvalidEffect   = errors.New("endpoint supervisor: invalid lifecycle effect")
	ErrSupervisorNoDescriptor    = errors.New("endpoint supervisor: descriptor not found")
	ErrSupervisorNoLifecycleSink = errors.New("endpoint supervisor: lifecycle sink is required")
	ErrSupervisorNoInboundSink   = errors.New("endpoint supervisor: inbound sink is required")
	ErrSupervisorStopTimeout     = errors.New("endpoint supervisor: stop timeout")
	ErrSupervisorAmbiguous       = errors.New("endpoint supervisor: lifecycle is ambiguous")
	ErrSupervisorShuttingDown    = errors.New("endpoint supervisor: shutting down")
	ErrSupervisorClosed          = ErrSupervisorShuttingDown
)

type LifecycleUpdate struct {
	EndpointID     adapterapi.EndpointID
	Generation     uint64
	DesiredVersion uint64
	ObservedState  adapterapi.ObservedState
	EffectKind     EffectKind
	Ambiguous      bool
	Deleted        bool
}
type LifecycleSink interface {
	RecordLifecycle(context.Context, LifecycleUpdate) error
}
type LifecycleSinkFunc func(context.Context, LifecycleUpdate) error

func (f LifecycleSinkFunc) RecordLifecycle(c context.Context, u LifecycleUpdate) error {
	return f(c, u)
}

type FencedInbound struct {
	EndpointID     adapterapi.EndpointID
	Generation     uint64
	DesiredVersion uint64
	Message        adapterapi.InboundMessage
}
type InboundSink interface {
	HandleInbound(context.Context, FencedInbound) (adapterapi.IngressReceipt, error)
}
type InboundSinkFunc func(context.Context, FencedInbound) (adapterapi.IngressReceipt, error)

func (f InboundSinkFunc) HandleInbound(c context.Context, i FencedInbound) (adapterapi.IngressReceipt, error) {
	return f(c, i)
}

type SupervisorOption func(*Supervisor)

func WithStopTimeout(d time.Duration) SupervisorOption {
	return func(s *Supervisor) {
		if d > 0 {
			s.stopTimeout = d
		}
	}
}
func WithWaitTimeout(d time.Duration) SupervisorOption { return WithStopTimeout(d) }
func WithLifecycleSink(v any) SupervisorOption {
	return func(s *Supervisor) { s.lifecycle = lifecycleSink(v) }
}
func WithInboundSink(v any) SupervisorOption {
	return func(s *Supervisor) { s.inbound = inboundSink(v) }
}
func WithDescriptorRegistry(v any) SupervisorOption { return func(s *Supervisor) { s.registry = v } }
func WithSecretResolver(v adapterapi.SecretResolver) SupervisorOption {
	return func(s *Supervisor) { s.secrets = v }
}

type Supervisor struct {
	registry          any
	service           *Service
	lifecycle         LifecycleSink
	inbound           InboundSink
	secrets           adapterapi.SecretResolver
	stopTimeout       time.Duration
	rootCtx           context.Context
	cancel            context.CancelFunc
	mu                sync.Mutex
	shutdownMu        sync.Mutex
	active            map[adapterapi.EndpointID]*supervisorWorker
	lanes             map[adapterapi.EndpointID]chan struct{}
	nextGeneration    map[adapterapi.EndpointID]uint64
	lastError         error
	completed         map[adapterapi.EndpointID]map[string]uint64
	terminal          map[adapterapi.EndpointID]terminalFence
	shuttingDown      bool
	shutdownAmbiguous bool
	reconcileInFlight int
	reconcileDone     chan struct{}
}
type terminalFence struct {
	generation uint64
	version    uint64
	kind       EffectKind
}
type pendingTerminal struct {
	effect  LifecycleEffect
	deleted bool
}
type supervisorWorker struct {
	endpointID        adapterapi.EndpointID
	generation        uint64
	desiredVersion    uint64
	effectKind        EffectKind
	runtime           adapterapi.AdapterRuntime
	cancel            context.CancelFunc
	done              chan struct{}
	launched          chan struct{}
	launchOnce        sync.Once
	mu                sync.Mutex
	exited            bool
	stopping          bool
	cleanup           bool
	terminalizing     bool
	terminalPublished bool
	ambiguous         bool
	pending           *pendingTerminal
	inflight          int
	callbacksDone     chan struct{}
}

func NewSupervisor(args ...any) *Supervisor {
	root, cancel := context.WithCancel(context.Background())
	s := &Supervisor{stopTimeout: 5 * time.Second, rootCtx: root, cancel: cancel, active: make(map[adapterapi.EndpointID]*supervisorWorker), lanes: make(map[adapterapi.EndpointID]chan struct{}), nextGeneration: make(map[adapterapi.EndpointID]uint64), completed: make(map[adapterapi.EndpointID]map[string]uint64), reconcileDone: make(chan struct{})}
	close(s.reconcileDone)
	for _, arg := range args {
		switch v := arg.(type) {
		case SupervisorOption:
			v(s)
		case *Service:
			s.service = v
			if s.registry == nil && v != nil {
				s.registry = v.Registry
			}
		default:
			if s.registry == nil {
				s.registry = v
			}
		}
	}
	if s.registry == nil && s.service != nil {
		s.registry = s.service.Registry
	}
	return s
}
func NewEndpointSupervisor(args ...any) *Supervisor { return NewSupervisor(args...) }
func (s *Supervisor) Cancel() {
	if s != nil && s.cancel != nil {
		s.cancel()
	}
}
func (s *Supervisor) BeginShutdown() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.shuttingDown = true
	s.mu.Unlock()
}
func (s *Supervisor) Shutdown(c context.Context) error {
	if s == nil {
		return ErrSupervisorClosed
	}
	s.shutdownMu.Lock()
	defer s.shutdownMu.Unlock()
	s.BeginShutdown()
	if c == nil {
		c = context.Background()
	}
	if err := s.waitReconciles(c); err != nil {
		s.Cancel()
		s.markShutdownAmbiguous(c)
		return err
	}
	if err := c.Err(); err != nil {
		s.Cancel()
		s.markShutdownAmbiguous(c)
		return err
	}
	s.Cancel()
	var first error
	for {
		s.mu.Lock()
		workers := make([]*supervisorWorker, 0, len(s.active))
		for _, w := range s.active {
			workers = append(workers, w)
		}
		s.mu.Unlock()
		if len(workers) == 0 {
			if err := c.Err(); err != nil {
				return err
			}
			return first
		}
		for _, w := range workers {
			w.mu.Lock()
			generation, version := w.generation, w.desiredVersion
			w.mu.Unlock()
			err := s.shutdownStopWorker(c, w, LifecycleEffect{Kind: EffectStop, EndpointID: w.endpointID, Generation: generation, DesiredVersion: version, DesiredState: DesiredStateDisabled, EffectID: "shutdown:" + string(w.endpointID)})
			if err != nil {
				s.markShutdownAmbiguous(c)
				return err
			}
			if err := c.Err(); err != nil {
				s.markShutdownAmbiguous(c)
				if first != nil {
					return errors.Join(first, err)
				}
				return err
			}
		}
	}
}
func (s *Supervisor) shutdownStopWorker(c context.Context, w *supervisorWorker, e LifecycleEffect) error {
	if c == nil {
		c = context.Background()
	}
	lane := s.lane(w.endpointID)
	select {
	case <-lane:
	case <-c.Done():
		return c.Err()
	}
	defer func() { lane <- struct{}{} }()
	return s.stopWorker(c, w, e, false)
}
func (s *Supervisor) markShutdownAmbiguous(c context.Context) {
	s.mu.Lock()
	s.shutdownAmbiguous = true
	workers := make([]*supervisorWorker, 0, len(s.active))
	for _, w := range s.active {
		workers = append(workers, w)
	}
	s.mu.Unlock()
	for _, w := range workers {
		w.mu.Lock()
		w.stopping = true
		w.ambiguous = true
		callbacks := w.callbacksDone
		generation, version := w.generation, w.desiredVersion
		kind := w.effectKind
		w.mu.Unlock()
		w.cancel()
		if err := s.waitCallbacks(callbacks); err != nil {
			s.remember(err)
		}
		if err := s.publishAmbiguous(c, LifecycleUpdate{EndpointID: w.endpointID, Generation: generation, DesiredVersion: version, ObservedState: adapterapi.ObservedStateAmbiguous, EffectKind: kind, Ambiguous: true}); err != nil {
			s.remember(err)
		}
	}
}
func (s *Supervisor) removeWorkerIfCleanLocked(w *supervisorWorker) {
	w.mu.Lock()
	retain := w.pending != nil || w.ambiguous || (w.stopping && !w.terminalPublished)
	w.mu.Unlock()
	if !retain && s.active[w.endpointID] == w {
		delete(s.active, w.endpointID)
	}
}
func (s *Supervisor) rejectStartingWorker(c context.Context, w *supervisorWorker) error {
	w.mu.Lock()
	w.stopping = true
	w.ambiguous = true
	generation, version := w.generation, w.desiredVersion
	kind := w.effectKind
	w.mu.Unlock()
	w.cancel()
	if err := s.publishAmbiguous(c, LifecycleUpdate{EndpointID: w.endpointID, Generation: generation, DesiredVersion: version, ObservedState: adapterapi.ObservedStateAmbiguous, EffectKind: kind, Ambiguous: true}); err != nil {
		s.remember(err)
	}
	return ErrSupervisorClosed
}
func (s *Supervisor) startPublicationFailure(c context.Context, w *supervisorWorker, cause error) error {
	s.mu.Lock()
	closing := s.shuttingDown
	s.mu.Unlock()
	w.mu.Lock()
	uncertain := w.ambiguous || w.stopping
	generation, version, kind := w.generation, w.desiredVersion, w.effectKind
	w.mu.Unlock()
	if !closing && !uncertain && !errors.Is(cause, context.Canceled) && !errors.Is(cause, context.DeadlineExceeded) {
		s.mu.Lock()
		closingNow := s.shuttingDown
		active := s.active[w.endpointID] == w
		if !closingNow && active {
			delete(s.active, w.endpointID)
			s.mu.Unlock()
			w.cancel()
			return cause
		}
		s.mu.Unlock()
	}
	w.mu.Lock()
	w.stopping = true
	w.ambiguous = true
	w.mu.Unlock()
	w.cancel()
	if pubErr := s.publishAmbiguous(c, LifecycleUpdate{EndpointID: w.endpointID, Generation: generation, DesiredVersion: version, ObservedState: adapterapi.ObservedStateAmbiguous, EffectKind: kind, Ambiguous: true}); pubErr != nil {
		s.remember(pubErr)
		return errors.Join(cause, pubErr)
	}
	if closing {
		return errors.Join(cause, ErrSupervisorClosed)
	}
	return errors.Join(cause, ErrSupervisorAmbiguous)
}
func (s *Supervisor) publishAmbiguous(parent context.Context, u LifecycleUpdate) error {
	if parent == nil || parent.Err() != nil {
		parent = context.Background()
	}
	return s.publish(parent, u)
}
func (s *Supervisor) Close() error { s.BeginShutdown(); s.Cancel(); return nil }
func (s *Supervisor) lane(id adapterapi.EndpointID) chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	lane := s.lanes[id]
	if lane == nil {
		lane = make(chan struct{}, 1)
		lane <- struct{}{}
		s.lanes[id] = lane
	}
	return lane
}
func (s *Supervisor) enter(c context.Context, id adapterapi.EndpointID) error {
	lane := s.lane(id)
	select {
	case <-lane:
	case <-c.Done():
		return c.Err()
	}
	s.mu.Lock()
	if s.shuttingDown {
		s.mu.Unlock()
		s.lane(id) <- struct{}{}
		return ErrSupervisorClosed
	}
	if s.reconcileInFlight == 0 {
		s.reconcileDone = make(chan struct{})
	}
	s.reconcileInFlight++
	s.mu.Unlock()
	return nil
}
func (s *Supervisor) leave(id adapterapi.EndpointID) {
	s.mu.Lock()
	s.reconcileInFlight--
	if s.reconcileInFlight == 0 {
		close(s.reconcileDone)
	}
	s.mu.Unlock()
	s.lane(id) <- struct{}{}
}
func (s *Supervisor) waitReconciles(c context.Context) error {
	s.mu.Lock()
	done := s.reconcileDone
	s.mu.Unlock()
	select {
	case <-done:
		return nil
	case <-c.Done():
		return c.Err()
	}
}
func (s *Supervisor) Reconcile(c context.Context, state State, e LifecycleEffect) error {
	if c == nil {
		c = context.Background()
	}
	if s == nil || !e.Kind.Valid() || !e.EndpointID.Valid() || e.EndpointID != state.EndpointID || e.DesiredVersion == 0 {
		return ErrSupervisorInvalidEffect
	}
	if err := c.Err(); err != nil {
		return err
	}
	if err := s.enter(c, e.EndpointID); err != nil {
		return err
	}
	defer s.leave(e.EndpointID)
	switch e.Kind {
	case EffectStart, EffectRelogin, EffectReplace:
		return s.reconcileStart(c, state, e)
	case EffectStop, EffectDelete:
		return s.reconcileStop(c, state, e)
	default:
		return ErrSupervisorInvalidEffect
	}
}
func (s *Supervisor) HandleEffect(c context.Context, state State, e LifecycleEffect) error {
	return s.Reconcile(c, state, e)
}
func (s *Supervisor) ApplyEffect(c context.Context, state State, e LifecycleEffect) error {
	return s.Reconcile(c, state, e)
}
func (s *Supervisor) ReconcileEffect(c context.Context, e LifecycleEffect, state State) error {
	return s.Reconcile(c, state, e)
}
func (s *Supervisor) reconcileStart(c context.Context, state State, e LifecycleEffect) error {
	if state.DesiredState != DesiredStateEnabled || e.DesiredState != DesiredStateEnabled {
		return ErrSupervisorInvalidEffect
	}
	if w := s.current(e.EndpointID); w != nil {
		w.mu.Lock()
		a, v, g := w.ambiguous, w.desiredVersion, w.generation
		w.mu.Unlock()
		if a {
			return ErrSupervisorAmbiguous
		}
		if e.Generation != 0 && e.Generation <= g {
			return nil
		}
		if e.DesiredVersion < v {
			return nil
		}
		if e.Generation == 0 && e.DesiredVersion == v {
			return nil
		}
		if err := s.stopWorker(c, w, e, false); err != nil {
			return err
		}
	}
	generation := e.Generation
	last := s.generationFloor(e.EndpointID)
	if generation == 0 {
		generation = last + 1
	}
	if generation <= last || s.startTerminalStale(e) {
		return nil
	}
	s.mu.Lock()
	closing := s.shuttingDown
	s.mu.Unlock()
	if closing {
		return ErrSupervisorClosed
	}
	descriptor, lookupErr := lookupDescriptor(c, s.registry, state.AdapterKey)
	if lookupErr != nil {
		return lookupErr
	}
	s.mu.Lock()
	closing = s.shuttingDown
	s.mu.Unlock()
	if closing {
		return ErrSupervisorClosed
	}
	runtime, err := descriptor.NewRuntime(adapterapi.RuntimeInit{EndpointID: e.EndpointID, Generation: generation, DesiredVersion: e.DesiredVersion, Config: state.Config.Clone(), Secrets: s.secrets})
	if err != nil {
		return err
	}
	runCtx, cancel := context.WithCancel(s.rootCtx)
	w := &supervisorWorker{endpointID: e.EndpointID, generation: generation, desiredVersion: e.DesiredVersion, effectKind: e.Kind, runtime: runtime, cancel: cancel, done: make(chan struct{}), launched: make(chan struct{}), callbacksDone: make(chan struct{})}
	close(w.callbacksDone)
	s.mu.Lock()
	if s.shuttingDown {
		s.mu.Unlock()
		cancel()
		return ErrSupervisorClosed
	}
	if s.active[e.EndpointID] != nil {
		s.mu.Unlock()
		cancel()
		return nil
	}
	if generation <= s.nextGeneration[e.EndpointID] || generation <= s.terminal[e.EndpointID].generation {
		s.mu.Unlock()
		cancel()
		return nil
	}
	s.active[e.EndpointID] = w
	s.mu.Unlock()
	if err := s.publish(c, LifecycleUpdate{EndpointID: e.EndpointID, Generation: generation, DesiredVersion: e.DesiredVersion, ObservedState: adapterapi.ObservedStateStarting, EffectKind: e.Kind}); err != nil {
		return s.startPublicationFailure(c, w, err)
	}
	s.mu.Lock()
	closing = s.shuttingDown
	s.mu.Unlock()
	if closing {
		return s.rejectStartingWorker(c, w)
	}
	s.mu.Lock()
	if generation > s.nextGeneration[e.EndpointID] {
		s.nextGeneration[e.EndpointID] = generation
	}
	s.mu.Unlock()
	go s.runWorker(runCtx, w, &generationCorePort{supervisor: s, worker: w})
	<-w.launched
	return nil
}
func (s *Supervisor) admitWorkerRun(w *supervisorWorker) bool {
	s.mu.Lock()
	w.mu.Lock()
	closing := s.shuttingDown
	blocked := w.ambiguous || w.stopping
	w.launchOnce.Do(func() { close(w.launched) })
	if closing || blocked {
		w.exited = true
		w.mu.Unlock()
		s.mu.Unlock()
		close(w.done)
		return false
	}
	w.mu.Unlock()
	s.mu.Unlock()
	return true
}
func (s *Supervisor) runWorker(c context.Context, w *supervisorWorker, p adapterapi.CorePort) {
	if !s.admitWorkerRun(w) {
		return
	}
	runErr := safeRun(w.runtime, c, p)
	close(w.done)
	w.mu.Lock()
	w.exited = true
	stopping, ambiguous, callbacks := w.stopping, w.ambiguous, w.callbacksDone
	w.mu.Unlock()
	if stopping || ambiguous {
		return
	}
	if err := s.waitCallbacks(callbacks); err != nil {
		_ = s.stopAfterRun(w)
		w.mu.Lock()
		w.ambiguous = true
		w.mu.Unlock()
		s.remember(err)
		_ = s.publish(context.Background(), LifecycleUpdate{EndpointID: w.endpointID, Generation: w.generation, DesiredVersion: w.desiredVersion, ObservedState: adapterapi.ObservedStateAmbiguous, Ambiguous: true})
		return
	}
	w.mu.Lock()
	stopping, ambiguous = w.stopping, w.ambiguous
	w.mu.Unlock()
	if stopping || ambiguous {
		return
	}
	stopErr := s.stopAfterRun(w)
	if stopErr != nil {
		w.mu.Lock()
		w.ambiguous = true
		w.mu.Unlock()
		s.remember(stopErr)
		_ = s.publish(context.Background(), LifecycleUpdate{EndpointID: w.endpointID, Generation: w.generation, DesiredVersion: w.desiredVersion, ObservedState: adapterapi.ObservedStateAmbiguous, Ambiguous: true})
		return
	}
	w.mu.Lock()
	stopping, ambiguous = w.stopping, w.ambiguous
	w.mu.Unlock()
	if stopping || ambiguous {
		return
	}
	observed := adapterapi.ObservedStateStopped
	if runErr != nil && !errors.Is(runErr, context.Canceled) && !errors.Is(runErr, context.DeadlineExceeded) {
		observed = adapterapi.ObservedStateFailed
	}
	if observed == adapterapi.ObservedStateFailed {
		if !beginFailureCallback(w) {
			return
		}
		pubErr := s.publish(context.Background(), LifecycleUpdate{EndpointID: w.endpointID, Generation: w.generation, DesiredVersion: w.desiredVersion, ObservedState: observed})
		endWorkerCallback(w)
		if pubErr != nil {
			s.remember(pubErr)
			w.mu.Lock()
			w.ambiguous = true
			w.mu.Unlock()
			_ = s.publish(context.Background(), LifecycleUpdate{EndpointID: w.endpointID, Generation: w.generation, DesiredVersion: w.desiredVersion, ObservedState: adapterapi.ObservedStateAmbiguous, Ambiguous: true})
			return
		}
	} else if err := s.publish(context.Background(), LifecycleUpdate{EndpointID: w.endpointID, Generation: w.generation, DesiredVersion: w.desiredVersion, ObservedState: observed}); err != nil {
		w.mu.Lock()
		w.ambiguous = true
		w.mu.Unlock()
		s.remember(err)
		_ = s.publish(context.Background(), LifecycleUpdate{EndpointID: w.endpointID, Generation: w.generation, DesiredVersion: w.desiredVersion, ObservedState: adapterapi.ObservedStateAmbiguous, Ambiguous: true})
		return
	}
	s.mu.Lock()
	s.removeWorkerIfCleanLocked(w)
	s.mu.Unlock()
}
func (s *Supervisor) stopAfterRun(w *supervisorWorker) error {
	w.mu.Lock()
	if w.stopping || w.cleanup {
		w.mu.Unlock()
		return nil
	}
	w.stopping = true
	w.cleanup = true
	w.mu.Unlock()
	d := s.stopTimeout
	if d <= 0 {
		d = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- safeStop(w.runtime, ctx) }()
	select {
	case err := <-done:
		if err == nil {
			w.mu.Lock()
			w.stopping = false
			w.mu.Unlock()
		}
		return err
	case <-ctx.Done():
		return fmt.Errorf("%w: runtime Stop timeout", ErrSupervisorStopTimeout)
	}
}
func (s *Supervisor) waitCallbacks(ch <-chan struct{}) error {
	d := s.stopTimeout
	if d <= 0 {
		d = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("%w: callback drain timeout", ErrSupervisorStopTimeout)
	}
}
func (s *Supervisor) waitCleanup(parent context.Context, w *supervisorWorker) error {
	if parent == nil {
		parent = context.Background()
	}
	d := s.stopTimeout
	if d <= 0 {
		d = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, d)
	defer cancel()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		w.mu.Lock()
		done, ambiguous, exited := w.terminalPublished, w.ambiguous, w.exited
		pending := w.pending
		w.mu.Unlock()
		if pending != nil && !pending.deleted && done && pending.effect.Generation == w.generation && pending.effect.DesiredVersion == w.desiredVersion {
			w.mu.Lock()
			if w.pending == pending {
				w.pending = nil
			}
			w.mu.Unlock()
			pending = nil
		}
		if pending != nil && (done || (ambiguous && exited && !done)) {
			u := LifecycleUpdate{EndpointID: w.endpointID, Generation: pending.effect.Generation, DesiredVersion: pending.effect.DesiredVersion, ObservedState: adapterapi.ObservedStateStopped, EffectKind: pending.effect.Kind, Deleted: pending.deleted}
			if err := s.publish(parent, u); err != nil {
				w.mu.Lock()
				w.ambiguous = true
				w.mu.Unlock()
				return fmt.Errorf("%w: pending terminal publication: %v", ErrSupervisorAmbiguous, err)
			}
			s.mu.Lock()
			shutdownAmbiguous := s.shutdownAmbiguous
			w.mu.Lock()
			if w.pending == pending {
				w.pending = nil
				if shutdownAmbiguous {
					w.ambiguous = true
				} else {
					w.ambiguous = false
				}
			}
			w.mu.Unlock()
			s.mu.Unlock()
			s.markCompletedEffect(w.endpointID, pending.effect)
			s.mu.Lock()
			s.removeWorkerIfCleanLocked(w)
			s.mu.Unlock()
			return nil
		}
		if done {
			s.mu.Lock()
			s.removeWorkerIfCleanLocked(w)
			s.mu.Unlock()
			return nil
		}
		if ambiguous {
			return ErrSupervisorAmbiguous
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.Canceled) {
				return context.Canceled
			}
			return fmt.Errorf("%w: cleanup wait timeout", ErrSupervisorAmbiguous)
		}
	}
}
func queuePendingTerminal(w *supervisorWorker, e LifecycleEffect, deleted bool) {
	if e.Generation == 0 {
		e.Generation = w.generation
	}
	if e.DesiredVersion == 0 {
		return
	}
	deleted = deleted || e.Kind == EffectDelete
	if !deleted && w.terminalPublished && e.Generation == w.generation && e.DesiredVersion == w.desiredVersion {
		return
	}
	p := &pendingTerminal{effect: e, deleted: deleted}
	if w.pending == nil || e.Generation > w.pending.effect.Generation || (e.Generation == w.pending.effect.Generation && e.DesiredVersion > w.pending.effect.DesiredVersion) || (e.Generation == w.pending.effect.Generation && e.DesiredVersion == w.pending.effect.DesiredVersion && deleted && !w.pending.deleted) {
		w.pending = p
	}
}
func safeRun(r adapterapi.AdapterRuntime, c context.Context, p adapterapi.CorePort) (err error) {
	defer func() {
		if v := recover(); v != nil {
			err = fmt.Errorf("runtime Run panic: %v", v)
		}
	}()
	return r.Run(c, p)
}
func safeStop(r adapterapi.AdapterRuntime, c context.Context) (err error) {
	defer func() {
		if v := recover(); v != nil {
			err = fmt.Errorf("runtime Stop panic: %v", v)
		}
	}()
	return r.Stop(c)
}
func (s *Supervisor) reconcileStop(c context.Context, state State, e LifecycleEffect) error {
	if e.Kind == EffectStop {
		if (state.DesiredState != DesiredStateDisabled && state.DesiredState != DesiredStateRemoving) || (e.DesiredState != DesiredStateDisabled && e.DesiredState != DesiredStateRemoving) {
			return ErrSupervisorInvalidEffect
		}
	} else if state.DesiredState != DesiredStateRemoving && state.DesiredState != DesiredStateDeleted || e.DesiredState != DesiredStateRemoving && e.DesiredState != DesiredStateDeleted {
		return ErrSupervisorInvalidEffect
	}
	if s.completedEffect(e.EndpointID, e) {
		return nil
	}
	w := s.current(e.EndpointID)
	if w == nil {
		if s.terminalStale(e) {
			return nil
		}
		err := s.publish(c, LifecycleUpdate{EndpointID: e.EndpointID, Generation: e.Generation, DesiredVersion: e.DesiredVersion, ObservedState: adapterapi.ObservedStateStopped, EffectKind: e.Kind, Deleted: e.Kind == EffectDelete})
		if err == nil {
			s.markCompletedEffect(e.EndpointID, e)
		}
		return err
	}
	w.mu.Lock()
	v, g, a, hasPending, retryBase := w.desiredVersion, w.generation, w.ambiguous, w.pending != nil, w.cleanup && w.exited && !w.terminalPublished
	w.mu.Unlock()
	if a && !hasPending && !retryBase {
		return ErrSupervisorAmbiguous
	}
	if (e.Generation != 0 && e.Generation < g) || (e.Generation == g && e.DesiredVersion < v) {
		return nil
	}
	return s.stopWorker(c, w, e, e.Kind == EffectDelete || state.DesiredState == DesiredStateRemoving)
}
func (s *Supervisor) stopWorker(parent context.Context, w *supervisorWorker, e LifecycleEffect, deleteAfter bool) error {
	w.mu.Lock()
	if w.cleanup && w.terminalPublished && !w.ambiguous {
		if e.Kind == EffectStart || e.Kind == EffectRelogin || e.Kind == EffectReplace {
			w.mu.Unlock()
			s.mu.Lock()
			s.removeWorkerIfCleanLocked(w)
			s.mu.Unlock()
			return nil
		}
		if e.DesiredVersion < w.desiredVersion || (e.DesiredVersion == w.desiredVersion && e.Generation <= w.generation) {
			w.mu.Unlock()
			s.mu.Lock()
			s.removeWorkerIfCleanLocked(w)
			s.mu.Unlock()
			return nil
		}
		w.mu.Unlock()
		return s.terminalizeExited(parent, w, e, deleteAfter || e.Kind == EffectDelete)
	}
	if w.stopping || w.cleanup {
		if w.cleanup && (!w.ambiguous || w.pending != nil || (w.exited && !w.terminalPublished)) {
			queuePendingTerminal(w, e, deleteAfter || e.Kind == EffectDelete)
			w.mu.Unlock()
			return s.waitCleanup(parent, w)
		}
		w.mu.Unlock()
		return ErrSupervisorAmbiguous
	}
	w.stopping = true
	callbacksDone := w.callbacksDone
	w.mu.Unlock()
	w.cancel()
	timeout := s.stopTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	stopCtx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	select {
	case <-callbacksDone:
	case <-stopCtx.Done():
		w.mu.Lock()
		w.ambiguous = true
		w.mu.Unlock()
		ambErr := fmt.Errorf("%w: %v", ErrSupervisorAmbiguous, ErrSupervisorStopTimeout)
		if pubErr := s.publishAmbiguous(parent, LifecycleUpdate{EndpointID: w.endpointID, Generation: w.generation, DesiredVersion: w.desiredVersion, ObservedState: adapterapi.ObservedStateAmbiguous, EffectKind: e.Kind, Ambiguous: true}); pubErr != nil {
			return errors.Join(ambErr, pubErr)
		}
		return ambErr
	}
	if true {
		stopDone := make(chan error, 1)
		go func() { stopDone <- safeStop(w.runtime, stopCtx) }()
		var stopErr error
		select {
		case stopErr = <-stopDone:
		case <-stopCtx.Done():
			stopErr = ErrSupervisorStopTimeout
		}
		if stopErr == nil {
			select {
			case <-w.done:
			case <-stopCtx.Done():
				stopErr = ErrSupervisorStopTimeout
			}
		}
		if stopErr != nil {
			w.mu.Lock()
			w.ambiguous = true
			w.mu.Unlock()
			ambErr := fmt.Errorf("%w: %v", ErrSupervisorAmbiguous, stopErr)
			if pubErr := s.publishAmbiguous(parent, LifecycleUpdate{EndpointID: w.endpointID, Generation: w.generation, DesiredVersion: w.desiredVersion, ObservedState: adapterapi.ObservedStateAmbiguous, EffectKind: e.Kind, Ambiguous: true}); pubErr != nil {
				return errors.Join(ambErr, pubErr)
			}
			return ambErr
		}
	}
	update := LifecycleUpdate{EndpointID: w.endpointID, Generation: w.generation, DesiredVersion: w.desiredVersion, ObservedState: adapterapi.ObservedStateStopped, EffectKind: e.Kind, Deleted: deleteAfter || e.Kind == EffectDelete}
	if err := s.publish(parent, update); err != nil {
		w.mu.Lock()
		w.ambiguous = true
		w.mu.Unlock()
		ambErr := fmt.Errorf("publish stopped: %w", err)
		if pubErr := s.publishAmbiguous(parent, LifecycleUpdate{EndpointID: w.endpointID, Generation: w.generation, DesiredVersion: w.desiredVersion, ObservedState: adapterapi.ObservedStateAmbiguous, EffectKind: e.Kind, Ambiguous: true}); pubErr != nil {
			return errors.Join(ambErr, pubErr)
		}
		return ambErr
	}
	s.markCompletedEffect(w.endpointID, e)
	s.mu.Lock()
	s.removeWorkerIfCleanLocked(w)
	s.mu.Unlock()
	return nil
}
func (s *Supervisor) terminalizeExited(parent context.Context, w *supervisorWorker, e LifecycleEffect, deleted bool) error {
	w.mu.Lock()
	w.terminalizing = true
	w.mu.Unlock()
	generation := e.Generation
	if generation == 0 {
		generation = w.generation
	}
	e.Generation = generation
	u := LifecycleUpdate{EndpointID: w.endpointID, Generation: generation, DesiredVersion: e.DesiredVersion, ObservedState: adapterapi.ObservedStateStopped, EffectKind: e.Kind, Deleted: deleted}
	if err := s.publish(parent, u); err != nil {
		w.mu.Lock()
		queuePendingTerminal(w, e, deleted)
		w.ambiguous = true
		w.mu.Unlock()
		amb := fmt.Errorf("%w: terminal replay publication: %v", ErrSupervisorAmbiguous, err)
		if pubErr := s.publishAmbiguous(parent, LifecycleUpdate{EndpointID: w.endpointID, Generation: generation, DesiredVersion: e.DesiredVersion, ObservedState: adapterapi.ObservedStateAmbiguous, EffectKind: e.Kind, Ambiguous: true}); pubErr != nil {
			return errors.Join(amb, pubErr)
		}
		return amb
	}
	s.markCompletedEffect(w.endpointID, e)
	s.mu.Lock()
	s.removeWorkerIfCleanLocked(w)
	s.mu.Unlock()
	return nil
}
func (s *Supervisor) current(id adapterapi.EndpointID) *supervisorWorker {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active[id]
}
func (s *Supervisor) generationFloor(id adapterapi.EndpointID) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	floor := s.nextGeneration[id]
	if t := s.terminal[id]; t.generation > floor {
		floor = t.generation
	}
	return floor
}
func (s *Supervisor) startTerminalStale(e LifecycleEffect) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.terminal[e.EndpointID]
	if !ok {
		return false
	}
	return (e.Generation != 0 && e.Generation < t.generation) || e.DesiredVersion < t.version
}
func effectKey(e LifecycleEffect) string {
	if e.EffectID != "" {
		return e.EffectID
	}
	return fmt.Sprintf("%s:%d:%d", e.Kind, e.Generation, e.DesiredVersion)
}
func (s *Supervisor) completedEffect(id adapterapi.EndpointID, e LifecycleEffect) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	versions := s.completed[id]
	if versions == nil {
		return false
	}
	v, ok := versions[effectKey(e)]
	return ok && v == e.DesiredVersion
}
func (s *Supervisor) terminalStale(e LifecycleEffect) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.terminal[e.EndpointID]
	if !ok {
		return false
	}
	if e.Generation < t.generation {
		return true
	}
	if e.Generation > t.generation {
		return false
	}
	return e.DesiredVersion <= t.version
}
func (s *Supervisor) markCompletedEffect(id adapterapi.EndpointID, e LifecycleEffect) {
	if e.Kind == EffectRelogin || e.Kind == EffectReplace {
		return
	}
	key := effectKey(e)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.completed[id] == nil {
		s.completed[id] = make(map[string]uint64)
	}
	s.completed[id][key] = e.DesiredVersion
	t := s.terminal[id]
	if e.Generation > t.generation || (e.Generation == t.generation && e.DesiredVersion >= t.version) {
		if s.terminal == nil {
			s.terminal = make(map[adapterapi.EndpointID]terminalFence)
		}
		s.terminal[id] = terminalFence{generation: e.Generation, version: e.DesiredVersion, kind: e.Kind}
	}
}
func beginWorkerCallback(w *supervisorWorker) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.exited || w.stopping || w.ambiguous {
		return false
	}
	if w.inflight == 0 {
		w.callbacksDone = make(chan struct{})
	}
	w.inflight++
	return true
}
func endWorkerCallback(w *supervisorWorker) {
	w.mu.Lock()
	w.inflight--
	if w.inflight == 0 {
		close(w.callbacksDone)
	}
	w.mu.Unlock()
}
func beginFailureCallback(w *supervisorWorker) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopping || w.ambiguous {
		return false
	}
	if w.inflight == 0 {
		w.callbacksDone = make(chan struct{})
	}
	w.inflight++
	return true
}
func (s *Supervisor) reportObservation(c context.Context, w *supervisorWorker, o adapterapi.LifecycleObservation) error {
	if err := o.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	valid := s.active[w.endpointID] == w
	s.mu.Unlock()
	if !valid || !beginWorkerCallback(w) {
		return nil
	}
	defer endWorkerCallback(w)
	return s.publish(c, LifecycleUpdate{EndpointID: w.endpointID, Generation: w.generation, DesiredVersion: w.desiredVersion, ObservedState: o.State})
}
func (s *Supervisor) handleInbound(c context.Context, w *supervisorWorker, m adapterapi.InboundMessage) (adapterapi.IngressReceipt, error) {
	if c == nil {
		c = context.Background()
	}
	if err := m.Validate(); err != nil {
		return adapterapi.IngressReceipt{}, err
	}
	s.mu.Lock()
	valid := s.active[w.endpointID] == w
	inbound := s.inbound
	s.mu.Unlock()
	if !valid || !beginWorkerCallback(w) {
		return adapterapi.IngressReceipt{}, ErrSupervisorClosed
	}
	defer endWorkerCallback(w)
	if inbound == nil {
		return adapterapi.IngressReceipt{}, ErrSupervisorNoInboundSink
	}
	receipt, err := inbound.HandleInbound(c, FencedInbound{EndpointID: w.endpointID, Generation: w.generation, DesiredVersion: w.desiredVersion, Message: m})
	if err != nil {
		return adapterapi.IngressReceipt{}, err
	}
	if err := receipt.Validate(); err != nil {
		return adapterapi.IngressReceipt{}, err
	}
	return receipt, nil
}
func (s *Supervisor) publish(parent context.Context, u LifecycleUpdate) error {
	if s.lifecycle == nil {
		return ErrSupervisorNoLifecycleSink
	}
	if u.EffectKind == "" {
		s.mu.Lock()
		if w := s.active[u.EndpointID]; w != nil {
			u.EffectKind = w.effectKind
		}
		s.mu.Unlock()
	}
	if parent == nil {
		parent = context.Background()
	}
	d := s.stopTimeout
	if d <= 0 {
		d = 5 * time.Second
	}
	c, cancel := context.WithTimeout(parent, d)
	defer cancel()
	if err := c.Err(); err != nil {
		return err
	}
	err := safeRecord(s.lifecycle, c, u)
	if err != nil {
		return err
	}
	if err := c.Err(); err != nil {
		return err
	}
	s.markTerminalPublished(u)
	return nil
}
func (s *Supervisor) markTerminalPublished(u LifecycleUpdate) {
	if u.ObservedState != adapterapi.ObservedStateStopped && u.ObservedState != adapterapi.ObservedStateFailed {
		return
	}
	s.mu.Lock()
	w := s.active[u.EndpointID]
	s.mu.Unlock()
	if w != nil {
		w.mu.Lock()
		matches := w.generation == u.Generation && u.DesiredVersion > 0 && u.DesiredVersion >= w.desiredVersion && (w.exited || w.stopping || w.cleanup)
		if matches {
			w.terminalPublished = true
		}
		kind := w.effectKind
		w.mu.Unlock()
		if matches {
			s.markCompletedEffect(u.EndpointID, LifecycleEffect{Kind: kind, EndpointID: u.EndpointID, Generation: u.Generation, DesiredVersion: u.DesiredVersion})
		}
	}
}
func safeRecord(sink LifecycleSink, c context.Context, u LifecycleUpdate) (err error) {
	defer func() {
		if v := recover(); v != nil {
			err = fmt.Errorf("lifecycle sink panic: %v", v)
		}
	}()
	return sink.RecordLifecycle(c, u)
}
func (s *Supervisor) remember(err error) {
	if err == nil {
		return
	}
	s.mu.Lock()
	if s.lastError == nil {
		s.lastError = err
	}
	s.mu.Unlock()
}
func (s *Supervisor) LastError() error { s.mu.Lock(); defer s.mu.Unlock(); return s.lastError }

type WorkerInspection struct {
	EndpointID     adapterapi.EndpointID
	Generation     uint64
	DesiredVersion uint64
	Exited         bool
	Ambiguous      bool
}

func (s *Supervisor) WorkerCount() int       { s.mu.Lock(); defer s.mu.Unlock(); return len(s.active) }
func (s *Supervisor) ActiveWorkerCount() int { return s.WorkerCount() }
func (s *Supervisor) ForgetWorker(id adapterapi.EndpointID) bool {
	s.mu.Lock()
	w := s.active[id]
	s.mu.Unlock()
	if w == nil {
		return false
	}
	w.mu.Lock()
	safe := w.exited && !w.ambiguous && !w.cleanup && !w.terminalizing && w.terminalPublished && w.inflight == 0
	w.mu.Unlock()
	if !safe {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active[id] == w {
		delete(s.active, id)
		return true
	}
	return false
}
func (s *Supervisor) Worker(id adapterapi.EndpointID) (WorkerInspection, bool) {
	s.mu.Lock()
	w := s.active[id]
	s.mu.Unlock()
	if w == nil {
		return WorkerInspection{}, false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return WorkerInspection{EndpointID: w.endpointID, Generation: w.generation, DesiredVersion: w.desiredVersion, Exited: w.exited, Ambiguous: w.ambiguous}, true
}
func (s *Supervisor) InspectWorker(id adapterapi.EndpointID) (WorkerInspection, bool) {
	return s.Worker(id)
}
func (s *Supervisor) Stop(c context.Context, id adapterapi.EndpointID) error {
	w := s.current(id)
	gen, version := uint64(1), uint64(1)
	if w != nil {
		gen, version = w.generation, w.desiredVersion
	}
	return s.Reconcile(c, State{EndpointID: id, DesiredState: DesiredStateDisabled}, LifecycleEffect{Kind: EffectStop, EndpointID: id, Generation: gen, DesiredVersion: version, DesiredState: DesiredStateDisabled})
}

// EffectExecutor is the generation-fenced outbound execution surface used by the dispatcher.
type EffectExecutor interface {
	ExecutePinned(context.Context, adapterapi.EndpointID, uint64, adapterapi.OutboundEffect) (adapterapi.EffectResult, error)
}

func (s *Supervisor) ExecutePinned(ctx context.Context, id adapterapi.EndpointID, generation uint64, effect adapterapi.OutboundEffect) (result adapterapi.EffectResult, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err = effect.Validate(); err != nil {
		return adapterapi.EffectResult{}, err
	}
	if s == nil {
		return adapterapi.EffectResult{}, ErrSupervisorClosed
	}
	s.mu.Lock()
	w := s.active[id]
	s.mu.Unlock()
	if w == nil {
		return adapterapi.EffectResult{}, ErrSupervisorClosed
	}
	w.mu.Lock()
	if generation == 0 {
		generation = w.generation
	}
	valid := w.generation == generation && !w.exited && !w.stopping && !w.ambiguous
	runtime := w.runtime
	w.mu.Unlock()
	if !valid || runtime == nil {
		return adapterapi.EffectResult{}, ErrSupervisorAmbiguous
	}
	if !beginWorkerCallback(w) {
		return adapterapi.EffectResult{}, ErrSupervisorAmbiguous
	}
	defer endWorkerCallback(w)
	return safeExecute(runtime, ctx, effect)
}

// ActionExecutor is the application-facing interactive action seam.
type ActionExecutor interface {
	ExecuteAction(context.Context, adapterapi.ActionRequest) (adapterapi.ActionResult, error)
}

// ExecuteAction invokes an optional interactive action on the currently
// active generation. The Supervisor, not the API, owns runtime access and
// generation fencing.
func (s *Supervisor) ExecuteAction(ctx context.Context, request adapterapi.ActionRequest) (result adapterapi.ActionResult, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s == nil {
		return adapterapi.ActionResult{}, ErrSupervisorClosed
	}
	if !request.EndpointID.Valid() || !request.Kind.Valid() {
		return adapterapi.ActionResult{}, adapterapi.ErrInvalidContract
	}
	s.mu.Lock()
	worker := s.active[request.EndpointID]
	s.mu.Unlock()
	if worker == nil {
		return adapterapi.ActionResult{}, ErrSupervisorClosed
	}
	worker.mu.Lock()
	if request.Generation == 0 {
		request.Generation = worker.generation
	}
	valid := worker.generation == request.Generation && !worker.exited && !worker.stopping && !worker.ambiguous
	runtime := worker.runtime
	worker.mu.Unlock()
	if !valid || runtime == nil {
		return adapterapi.ActionResult{}, ErrSupervisorAmbiguous
	}
	actionRuntime, ok := runtime.(adapterapi.ActionRuntime)
	if !ok {
		return adapterapi.ActionResult{}, adapterapi.ErrUnsupportedAction
	}
	if !beginWorkerCallback(worker) {
		return adapterapi.ActionResult{}, ErrSupervisorAmbiguous
	}
	defer endWorkerCallback(worker)
	defer func() {
		request.Payload.SMSCode = ""
		request.Payload.Captcha = ""
	}()
	return safeAction(actionRuntime, ctx, request)
}

func safeAction(runtime adapterapi.ActionRuntime, ctx context.Context, request adapterapi.ActionRequest) (result adapterapi.ActionResult, err error) {
	defer func() {
		if err != nil && result.Artifact != nil {
			clear(result.Artifact.Plaintext)
			result.Artifact.Plaintext = nil
		}
		if recovered := recover(); recovered != nil {
			if result.Artifact != nil {
				clear(result.Artifact.Plaintext)
				result.Artifact.Plaintext = nil
			}
			err = fmt.Errorf("endpoint supervisor: action panic: %v", recovered)
		}
	}()
	result, err = runtime.ExecuteAction(ctx, request)
	if err != nil {
		return adapterapi.ActionResult{}, err
	}
	if err = result.Validate(); err != nil {
		return adapterapi.ActionResult{}, err
	}
	return result, nil
}
func safeExecute(runtime adapterapi.AdapterRuntime, ctx context.Context, effect adapterapi.OutboundEffect) (result adapterapi.EffectResult, err error) {
	var artifact *adapterapi.ArtifactResult
	defer func() {
		if err != nil && artifact != nil {
			for i := range artifact.Bytes {
				artifact.Bytes[i] = 0
			}
			artifact.Bytes = nil
		}
		if v := recover(); v != nil {
			if artifact != nil {
				for i := range artifact.Bytes {
					artifact.Bytes[i] = 0
				}
				artifact.Bytes = nil
			}
			err = fmt.Errorf("endpoint supervisor: execute panic: %v", v)
		}
	}()
	result = runtime.Execute(ctx, effect)
	artifact = result.Artifact
	if err = result.Validate(); err != nil {
		return adapterapi.EffectResult{}, err
	}
	return result, nil
}
func lifecycleSink(v any) LifecycleSink {
	switch x := v.(type) {
	case LifecycleSink:
		return x
	case func(context.Context, LifecycleUpdate) error:
		return LifecycleSinkFunc(x)
	default:
		return nil
	}
}
func inboundSink(v any) InboundSink {
	switch x := v.(type) {
	case InboundSink:
		return x
	case func(context.Context, FencedInbound) (adapterapi.IngressReceipt, error):
		return InboundSinkFunc(x)
	default:
		return nil
	}
}
func lookupDescriptor(c context.Context, r any, k adapterapi.AdapterKey) (adapterapi.Descriptor, error) {
	if err := c.Err(); err != nil {
		return nil, err
	}
	accept := func(d adapterapi.Descriptor) (adapterapi.Descriptor, error) {
		if d == nil || d.Key() != k {
			return nil, ErrSupervisorNoDescriptor
		}
		return d, nil
	}
	switch x := r.(type) {
	case DescriptorRegistry:
		d, ok := x.Lookup(c, k)
		if err := c.Err(); err != nil {
			return nil, err
		}
		if !ok {
			return nil, ErrSupervisorNoDescriptor
		}
		return accept(d)
	case DescriptorLookup:
		d, e := x(c, k)
		if err := c.Err(); err != nil {
			return nil, err
		}
		if e != nil {
			return nil, e
		}
		return accept(d)
	case func(context.Context, adapterapi.AdapterKey) (adapterapi.Descriptor, error):
		d, e := x(c, k)
		if err := c.Err(); err != nil {
			return nil, err
		}
		if e != nil {
			return nil, e
		}
		return accept(d)
	case func(adapterapi.AdapterKey) (adapterapi.Descriptor, bool):
		d, ok := x(k)
		if !ok {
			return nil, ErrSupervisorNoDescriptor
		}
		return accept(d)
	case map[adapterapi.AdapterKey]adapterapi.Descriptor:
		d, ok := x[k]
		if !ok {
			return nil, ErrSupervisorNoDescriptor
		}
		return accept(d)
	case map[string]adapterapi.Descriptor:
		d, ok := x[string(k)]
		if !ok {
			return nil, ErrSupervisorNoDescriptor
		}
		return accept(d)
	case adapterapi.Descriptor:
		return accept(x)
	}
	return nil, ErrSupervisorNoDescriptor
}

type generationCorePort struct {
	supervisor *Supervisor
	worker     *supervisorWorker
}

func (p *generationCorePort) HandleInbound(c context.Context, m adapterapi.InboundMessage) (adapterapi.IngressReceipt, error) {
	return p.supervisor.handleInbound(c, p.worker, m)
}
func (p *generationCorePort) ReportObservation(c context.Context, o adapterapi.LifecycleObservation) error {
	return p.supervisor.reportObservation(c, p.worker, o)
}

var _ adapterapi.CorePort = (*generationCorePort)(nil)
