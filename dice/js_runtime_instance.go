package dice

import (
	"errors"
	"sync"

	"Scardice-core/utils/jsengine"
	"Scardice-core/utils/jsengine/services"
)

// jsRuntimeInstance owns one live runtime together with every host-service
// registry attached to it. Callers transfer ownership by registering the
// instance with JsLoopManager; closing the instance is idempotent.
type jsRuntimeInstance struct {
	loop       jsengine.Loop
	generation int64
	registries []*services.Registry
	closeOnce  sync.Once
	closeErr   error
}

func newJSRuntimeInstance(loop jsengine.Loop, registries ...*services.Registry) *jsRuntimeInstance {
	if carrier, ok := loop.(jsRuntimeResourceCarrier); ok {
		registries = append(registries, carrier.takeJSRuntimeResources()...)
	}
	return &jsRuntimeInstance{
		loop:       loop,
		registries: uniqueJSServiceRegistries(registries),
	}
}

func (i *jsRuntimeInstance) Close() error {
	if i == nil {
		return nil
	}
	i.closeOnce.Do(func() {
		var errs []error
		for index := len(i.registries) - 1; index >= 0; index-- {
			if registry := i.registries[index]; registry != nil {
				if err := registry.Close(); err != nil {
					errs = append(errs, err)
				}
			}
		}
		if i.loop != nil {
			if err := i.loop.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		i.closeErr = errors.Join(errs...)
	})
	return i.closeErr
}

func uniqueJSServiceRegistries(registries []*services.Registry) []*services.Registry {
	if len(registries) == 0 {
		return nil
	}
	seen := make(map[*services.Registry]struct{}, len(registries))
	unique := make([]*services.Registry, 0, len(registries))
	for _, registry := range registries {
		if registry == nil {
			continue
		}
		if _, exists := seen[registry]; exists {
			continue
		}
		seen[registry] = struct{}{}
		unique = append(unique, registry)
	}
	return unique
}

// jsRuntimeResourceCarrier lets a provider transfer resources created while
// opening a loop to the Dice-level runtime instance. Until transferred, the
// loop remains independently safe to close for direct manager users.
type jsRuntimeResourceCarrier interface {
	takeJSRuntimeResources() []*services.Registry
}

// ownedJSLoop preserves optional loop interfaces while making provider-created
// service registries part of the loop's fallback ownership boundary.
type ownedJSLoop struct {
	loop      jsengine.Loop
	resourceM sync.Mutex
	resources []*services.Registry
	closeOnce sync.Once
	closeErr  error
}

func (l *ownedJSLoop) Engine() jsengine.EngineID                 { return l.loop.Engine() }
func (l *ownedJSLoop) Descriptor() jsengine.Descriptor           { return l.loop.Descriptor() }
func (l *ownedJSLoop) Run(fn func(jsengine.Runtime) error) error { return l.loop.Run(fn) }
func (l *ownedJSLoop) LoadEntry(entry jsengine.Entry) error      { return l.loop.LoadEntry(entry) }

func (l *ownedJSLoop) takeJSRuntimeResources() []*services.Registry {
	l.resourceM.Lock()
	defer l.resourceM.Unlock()
	resources := l.resources
	l.resources = nil
	return resources
}

func (l *ownedJSLoop) Close() error {
	if l == nil {
		return nil
	}
	l.closeOnce.Do(func() {
		resources := l.takeJSRuntimeResources()
		var errs []error
		for index := len(resources) - 1; index >= 0; index-- {
			if registry := resources[index]; registry != nil {
				if err := registry.Close(); err != nil {
					errs = append(errs, err)
				}
			}
		}
		if l.loop != nil {
			if err := l.loop.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		l.closeErr = errors.Join(errs...)
	})
	return l.closeErr
}

type ownedSchedulableJSLoop struct {
	*ownedJSLoop
	schedulable jsengine.SchedulableLoop
}

func (l *ownedSchedulableJSLoop) Schedule(run func(jsengine.Runtime) error) error {
	return l.schedulable.Schedule(run)
}

type ownedContextAwareJSLoop struct {
	*ownedJSLoop
	contextAware jsengine.ContextAwareLoop
}

func (l *ownedContextAwareJSLoop) RunWithContext(context any, run func(jsengine.Runtime) error) error {
	return l.contextAware.RunWithContext(context, run)
}

func (l *ownedContextAwareJSLoop) Schedule(run func(jsengine.Runtime) error) error {
	return l.contextAware.Schedule(run)
}

func (l *ownedContextAwareJSLoop) ScheduleWithContext(context any, run func(jsengine.Runtime) error) error {
	return l.contextAware.ScheduleWithContext(context, run)
}

func (l *ownedContextAwareJSLoop) CurrentContext() any {
	return l.contextAware.CurrentContext()
}

func (l *ownedContextAwareJSLoop) LoadEntryWithContext(context any, entry jsengine.Entry) error {
	return l.contextAware.LoadEntryWithContext(context, entry)
}

func ownJSRuntimeLoop(loop jsengine.Loop, registries ...*services.Registry) jsengine.Loop {
	owned := &ownedJSLoop{loop: loop, resources: uniqueJSServiceRegistries(registries)}
	if contextAware, ok := loop.(jsengine.ContextAwareLoop); ok {
		return &ownedContextAwareJSLoop{ownedJSLoop: owned, contextAware: contextAware}
	}
	if schedulable, ok := loop.(jsengine.SchedulableLoop); ok {
		return &ownedSchedulableJSLoop{ownedJSLoop: owned, schedulable: schedulable}
	}
	return owned
}

var _ jsengine.Loop = (*ownedJSLoop)(nil)
var _ jsengine.SchedulableLoop = (*ownedSchedulableJSLoop)(nil)
var _ jsengine.ContextAwareLoop = (*ownedContextAwareJSLoop)(nil)
