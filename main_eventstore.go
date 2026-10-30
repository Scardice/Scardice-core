package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/messageflow"
	"Scardice-core/endpoint"
	"Scardice-core/eventstore"
	"Scardice-core/logger"
)

const (
	eventCallbackWorkerCount    = 4
	eventEffectWorkerCount      = 4
	eventCallbackIdleDelay      = 50 * time.Millisecond
	eventEffectIdleDelay        = 100 * time.Millisecond
	eventWorkerMaximumIdleDelay = 500 * time.Millisecond
	eventWorkSignalDrainLimit   = 64
)

var errEventWorkerGroupClosed = errors.New("event worker group is shutting down")

// inboundReplay is Core's port for recovered messages: the supervisor submits
// them under the active generation's fence, the store reports their inbox rows.
type inboundReplay struct {
	*endpoint.Supervisor
	*eventstore.GORMStore
}

// legacyStatePresent only inspects legacy file presence. It never opens a
// legacy database or invokes a legacy loader; eventsourcing owns that read.
func legacyStatePresent() bool {
	for _, path := range []string{
		filepath.Join("data", "dice.yaml"),
		filepath.Join("data", "default", "serve.yaml"),
		filepath.Join("data", "default", "advanced.yaml"),
		filepath.Join("data", "default", "data.db"),
	} {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	entries, err := os.ReadDir("data")
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join("data", entry.Name(), "data.db")); err == nil {
			return true
		}
	}
	return false
}

type eventWorkerGroup struct {
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	accepting bool
	wg        sync.WaitGroup
	done      chan struct{}
	once      sync.Once
}

func newEventWorkerGroup(parent context.Context) *eventWorkerGroup {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	return &eventWorkerGroup{
		ctx:       ctx,
		cancel:    cancel,
		accepting: true,
		done:      make(chan struct{}),
	}
}

func (g *eventWorkerGroup) Go(run func(context.Context)) bool {
	if g == nil || run == nil {
		return false
	}
	g.mu.Lock()
	if !g.accepting {
		g.mu.Unlock()
		return false
	}
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		run(g.ctx)
	}()
	g.mu.Unlock()
	return true
}

func startEventWorkerPool(group *eventWorkerGroup, count int, factory func(int) (func(context.Context), error)) error {
	if group == nil || count <= 0 || factory == nil {
		return errors.New("event worker pool: invalid configuration")
	}
	for index := range count {
		group.mu.Lock()
		if !group.accepting {
			group.mu.Unlock()
			return errEventWorkerGroupClosed
		}
		run, err := factory(index)
		if err != nil {
			group.mu.Unlock()
			return err
		}
		if run == nil {
			group.mu.Unlock()
			return errors.New("event worker pool: nil worker")
		}
		group.wg.Add(1)
		go func() {
			defer group.wg.Done()
			run(group.ctx)
		}()
		group.mu.Unlock()
	}
	return nil
}

func (g *eventWorkerGroup) beginShutdown() {
	if g == nil {
		return
	}
	g.once.Do(func() {
		g.mu.Lock()
		g.accepting = false
		g.cancel()
		g.mu.Unlock()
		go func() {
			g.wg.Wait()
			close(g.done)
		}()
	})
}

func (g *eventWorkerGroup) Shutdown(ctx context.Context) error {
	if g == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	g.beginShutdown()
	select {
	case <-g.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func shutdownEventRuntime(ctx context.Context, phases ...func(context.Context) error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	var errs []error
	for _, phase := range phases {
		if phase == nil {
			continue
		}
		if err := phase(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

type eventEndpointResolver struct {
	service  *endpoint.Service
	registry *endpoint.Registry
	store    *eventstore.GORMStore
}

func newEventEndpointResolver(service *endpoint.Service, registry *endpoint.Registry, store *eventstore.GORMStore) *eventEndpointResolver {
	return &eventEndpointResolver{service: service, registry: registry, store: store}
}

func (r *eventEndpointResolver) Resolve(ctx context.Context, id adapterapi.EndpointID) (messageflow.EndpointSnapshot, error) {
	if r == nil || r.service == nil || r.registry == nil || r.store == nil || !id.Valid() {
		return messageflow.EndpointSnapshot{}, endpoint.ErrNotFound
	}
	view, err := r.service.Get(ctx, id)
	if err != nil {
		return messageflow.EndpointSnapshot{}, err
	}
	descriptor, ok := r.registry.Lookup(ctx, view.AdapterKey)
	if !ok || descriptor == nil {
		return messageflow.EndpointSnapshot{}, endpoint.ErrUnknownAdapter
	}
	_, rootID, err := r.store.KeyedDigest(ctx, "endpoint-snapshot/v1", string(id))
	if err != nil {
		return messageflow.EndpointSnapshot{}, err
	}
	capabilities := descriptor.Capabilities(view.Config)
	actions := descriptor.SupportedActions(view.Config)
	return messageflow.EndpointSnapshot{
		EndpointID:    view.EndpointID,
		AdapterKey:    view.AdapterKey,
		DesiredState:  string(view.DesiredState),
		ObservedState: view.ObservedState,
		Capabilities:  capabilities,
		Actions:       actions,
		IndexRootID:   rootID,
		IndexSigner:   r.store,
	}, nil
}

// eventQueueCoordinator owns the only idle probe for a queue. It never runs a
// callback or send, so one slow worker cannot prevent other lanes from waking.
type eventQueueCoordinator struct {
	mu   sync.Mutex
	wake chan struct{}
}

func newEventQueueCoordinator(group *eventWorkerGroup, initial time.Duration, work <-chan struct{}, probe func(context.Context) (bool, error)) *eventQueueCoordinator {
	queue := &eventQueueCoordinator{wake: make(chan struct{})}
	if group == nil {
		return queue
	}
	group.Go(func(ctx context.Context) {
		delay := initial
		timer := time.NewTimer(0)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case _, ok := <-work:
				if !ok {
					return
				}
				// Store notifications are buffered fan-out hints. Drain only a
				// bounded batch so cancellation and a continuously active
				// producer cannot starve the coordinator.
			drain:
				for range eventWorkSignalDrainLimit {
					select {
					case <-ctx.Done():
						return
					case _, ok = <-work:
						if !ok {
							queue.broadcast()
							return
						}
					default:
						break drain
					}
				}
				queue.broadcast()
				delay = initial
			case <-timer.C:
				if probe == nil {
					delay = nextEventWorkerIdleDelay(delay, initial)
					break
				}
				available, err := probe(ctx)
				if ctx.Err() != nil {
					return
				}
				switch {
				case err != nil:
					logger.QueueFailures().Warnw("durable queue availability probe failed", "error", err)
					delay = nextEventWorkerIdleDelay(delay, initial)
				case available:
					queue.broadcast()
					delay = initial
				default:
					delay = nextEventWorkerIdleDelay(delay, initial)
				}
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(delay)
		}
	})
	return queue
}

func (q *eventQueueCoordinator) signal() <-chan struct{} {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.wake
}

func (q *eventQueueCoordinator) broadcast() {
	q.mu.Lock()
	defer q.mu.Unlock()
	close(q.wake)
	q.wake = make(chan struct{})
}

func waitEventQueue(ctx context.Context, wake <-chan struct{}) bool {
	if wake == nil {
		return waitEventWorker(ctx, eventWorkerMaximumIdleDelay, nil)
	}
	select {
	case <-ctx.Done():
		return false
	case <-wake:
		return true
	}
}

func runEventEffectDispatcher(ctx context.Context, dispatcher *endpoint.EffectDispatcher, workSignal func() <-chan struct{}) {
	if dispatcher == nil {
		return
	}
	for {
		var wake <-chan struct{}
		if workSignal != nil {
			wake = workSignal()
		}
		_, err := dispatcher.DispatchOnce(ctx)
		switch {
		case err == nil, errors.Is(err, eventstore.ErrPayloadExpired):
			continue
		case errors.Is(err, eventstore.ErrNotFound):
			if !waitEventQueue(ctx, wake) {
				return
			}
		default:
			if ctx.Err() != nil {
				return
			}
			logger.QueueFailures().Warnw("durable outbound dispatch failed", "queue", "outbox", "error", err)
			if !waitEventQueue(ctx, wake) {
				return
			}
		}
	}
}

func runEventCallbackProcessor(ctx context.Context, callback *messageflow.CallbackService, workSignal func() <-chan struct{}) {
	if callback == nil {
		return
	}
	for {
		var wake <-chan struct{}
		if workSignal != nil {
			wake = workSignal()
		}
		summary, err := callback.ProcessOne(ctx)
		switch {
		case err == nil, errors.Is(err, eventstore.ErrPayloadExpired):
			continue
		case errors.Is(err, eventstore.ErrNotFound):
			if !waitEventQueue(ctx, wake) {
				return
			}
		default:
			if ctx.Err() != nil {
				return
			}
			logger.QueueFailures().Warnw("durable inbound callback failed", "queue", "inbox", "inbox_id", summary.InboxID, "status", summary.Status, "error", err)
			if !waitEventQueue(ctx, wake) {
				return
			}
		}
	}
}

func nextEventWorkerIdleDelay(current, initial time.Duration) time.Duration {
	if current < initial {
		return initial
	}
	if current >= eventWorkerMaximumIdleDelay/2 {
		return eventWorkerMaximumIdleDelay
	}
	return current * 2
}

func waitEventWorker(ctx context.Context, delay time.Duration, work <-chan struct{}) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-work:
		return true
	case <-timer.C:
		return true
	}
}
