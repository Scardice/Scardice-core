package endpoint

import (
	"Scardice-core/adapterapi"
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"
)

func fakeEffect(id adapterapi.EndpointID, kind EffectKind, generation, desiredVersion uint64, desired DesiredState) LifecycleEffect {
	suffix := string(kind) + "-" + strconv.FormatUint(generation, 10) + "-" + strconv.FormatUint(desiredVersion, 10)
	return LifecycleEffect{ID: id.String() + "-" + suffix, EffectID: id.String() + "-effect-" + suffix, Kind: kind, EndpointID: id, Generation: generation, DesiredVersion: desiredVersion, DesiredState: desired, OperationID: "op", CorrelationID: "corr", CommandID: "cmd"}
}
func TestSupervisorStartsExactlyOneWorkerAndFencesObservation(t *testing.T) {
	id := adapterapi.EndpointID("sup-one")
	key := adapterapi.AdapterKey("fake")
	descriptor := &fakeDescriptor{key: key}
	sink := &fakeLifecycleSink{}
	sup := NewSupervisor(fakeDescriptorRegistry{key: descriptor}, WithLifecycleSink(sink))
	state := validFakeState(t, id, key, DesiredStateEnabled, 1, 2)
	effect := fakeEffect(id, EffectStart, 1, 2, DesiredStateEnabled)
	if err := sup.Reconcile(context.Background(), state, effect); err != nil {
		t.Fatal(err)
	}
	if got := sup.WorkerCount(); got != 1 {
		t.Fatalf("worker count=%d", got)
	}
	if err := sup.Reconcile(context.Background(), state, effect); err != nil {
		t.Fatal(err)
	}
	if got := descriptor.RuntimeCount(); got != 1 {
		t.Fatalf("duplicate runtime count=%d", got)
	}
	runtime := descriptor.Runtime(0)
	runtime.allowStart()
	select {
	case <-runtime.runStarted:
	case <-time.After(time.Second):
		t.Fatal("runtime did not launch")
	}
	if got := sink.Count(adapterapi.ObservedStateStarting); got != 1 {
		t.Fatalf("starting updates=%d", got)
	}
}
func TestSupervisorIgnoresStaleGenerationReport(t *testing.T) {
	id := adapterapi.EndpointID("sup-stale")
	key := adapterapi.AdapterKey("fake")
	descriptor := &fakeDescriptor{key: key}
	sink := &fakeLifecycleSink{}
	sup := NewSupervisor(fakeDescriptorRegistry{key: descriptor}, WithLifecycleSink(sink), WithStopTimeout(100*time.Millisecond))
	first := validFakeState(t, id, key, DesiredStateEnabled, 1, 2)
	if err := sup.Reconcile(context.Background(), first, fakeEffect(id, EffectStart, 1, 2, DesiredStateEnabled)); err != nil {
		t.Fatal(err)
	}
	old := descriptor.Runtime(0)
	old.allowStart()
	select {
	case <-old.runStarted:
	case <-time.After(time.Second):
		t.Fatal("old runtime did not launch")
	}
	connectedBeforeRelogin := sink.Count(adapterapi.ObservedStateConnected)
	relogin := validFakeState(t, id, key, DesiredStateEnabled, 2, 3)
	done := make(chan error, 1)
	go func() {
		done <- sup.Reconcile(context.Background(), relogin, fakeEffect(id, EffectRelogin, 2, 3, DesiredStateEnabled))
	}()
	select {
	case <-old.stopCalled:
	case <-time.After(time.Second):
		t.Fatal("relogin did not stop old runtime")
	}
	old.allowStopNow()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	current := descriptor.Runtime(1)
	current.allowStart()
	select {
	case <-current.runStarted:
	case <-time.After(time.Second):
		t.Fatal("current runtime did not launch")
	}
	deadline := time.Now().Add(time.Second)
	for sink.Count(adapterapi.ObservedStateConnected) <= connectedBeforeRelogin {
		if time.Now().After(deadline) {
			t.Fatal("current runtime did not publish connected")
		}
		time.Sleep(time.Millisecond)
	}
	before := sink.Count(adapterapi.ObservedStateConnected)
	if err := old.port().ReportObservation(context.Background(), adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateConnected}); err != nil {
		t.Fatal(err)
	}
	if got := sink.Count(adapterapi.ObservedStateConnected); got != before {
		t.Fatalf("stale connected changed durable observations: before=%d after=%d", before, got)
	}
}
func TestSupervisorStopTimeoutRetainsAmbiguousOwner(t *testing.T) {
	id := adapterapi.EndpointID("sup-timeout")
	key := adapterapi.AdapterKey("fake")
	descriptor := &fakeDescriptor{key: key}
	sink := &fakeLifecycleSink{}
	sup := NewSupervisor(fakeDescriptorRegistry{key: descriptor}, WithLifecycleSink(sink), WithStopTimeout(10*time.Millisecond))
	state := validFakeState(t, id, key, DesiredStateEnabled, 1, 2)
	if err := sup.Reconcile(context.Background(), state, fakeEffect(id, EffectStart, 1, 2, DesiredStateEnabled)); err != nil {
		t.Fatal(err)
	}
	descriptor.Runtime(0).allowStart()
	err := sup.Reconcile(context.Background(), validFakeState(t, id, key, DesiredStateDisabled, 1, 3), fakeEffect(id, EffectStop, 1, 3, DesiredStateDisabled))
	if err == nil || !errors.Is(err, ErrSupervisorAmbiguous) {
		t.Fatalf("stop timeout err=%v", err)
	}
	if got := sup.WorkerCount(); got != 1 {
		t.Fatalf("timeout dropped ownership, workers=%d", got)
	}
	if got := sink.Count(adapterapi.ObservedStateAmbiguous); got != 1 {
		t.Fatalf("ambiguous updates=%d", got)
	}
}
func TestSupervisorConcurrentDuplicateEffectsHaveOneWorker(t *testing.T) {
	id := adapterapi.EndpointID("sup-race")
	key := adapterapi.AdapterKey("fake")
	descriptor := &fakeDescriptor{key: key}
	sup := NewSupervisor(fakeDescriptorRegistry{key: descriptor}, WithLifecycleSink(&fakeLifecycleSink{}))
	state := validFakeState(t, id, key, DesiredStateEnabled, 1, 2)
	effect := fakeEffect(id, EffectStart, 1, 2, DesiredStateEnabled)
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := sup.Reconcile(context.Background(), state, effect); err != nil {
				t.Errorf("reconcile: %v", err)
			}
		}()
	}
	wg.Wait()
	if got := sup.WorkerCount(); got != 1 {
		t.Fatalf("worker count=%d", got)
	}
	if got := descriptor.RuntimeCount(); got != 1 {
		t.Fatalf("runtime count=%d", got)
	}
}
func TestSupervisorCallerCancellationDoesNotKillWorker(t *testing.T) {
	id := adapterapi.EndpointID("sup-context")
	key := adapterapi.AdapterKey("fake")
	descriptor := &fakeDescriptor{key: key}
	sup := NewSupervisor(fakeDescriptorRegistry{key: descriptor}, WithLifecycleSink(&fakeLifecycleSink{}))
	ctx, cancel := context.WithCancel(context.Background())
	state := validFakeState(t, id, key, DesiredStateEnabled, 1, 2)
	if err := sup.Reconcile(ctx, state, fakeEffect(id, EffectStart, 1, 2, DesiredStateEnabled)); err != nil {
		t.Fatal(err)
	}
	cancel()
	descriptor.Runtime(0).allowStart()
	select {
	case <-descriptor.Runtime(0).runStarted:
	case <-time.After(time.Second):
		t.Fatal("runtime did not launch")
	}
	if got := sup.WorkerCount(); got != 1 {
		t.Fatalf("caller cancellation killed worker, count=%d", got)
	}
}

type failingLifecycleSink struct{}

func (failingLifecycleSink) RecordLifecycle(context.Context, LifecycleUpdate) error {
	return errors.New("durable write failed")
}
func TestSupervisorRequiresDurableStarting(t *testing.T) {
	id := adapterapi.EndpointID("sup-start-error")
	key := adapterapi.AdapterKey("fake")
	descriptor := &fakeDescriptor{key: key}
	sup := NewSupervisor(fakeDescriptorRegistry{key: descriptor}, WithLifecycleSink(failingLifecycleSink{}))
	state := validFakeState(t, id, key, DesiredStateEnabled, 1, 2)
	if err := sup.Reconcile(context.Background(), state, fakeEffect(id, EffectStart, 1, 2, DesiredStateEnabled)); err == nil {
		t.Fatal("starting publication error was ignored")
	}
	if got := sup.WorkerCount(); got != 0 {
		t.Fatalf("worker retained after failed starting publication: %d", got)
	}
}
func TestSupervisorStopUsesCurrentWorkerFence(t *testing.T) {
	id := adapterapi.EndpointID("sup-stop-fence")
	key := adapterapi.AdapterKey("fake")
	descriptor := &fakeDescriptor{key: key}
	sup := NewSupervisor(fakeDescriptorRegistry{key: descriptor}, WithLifecycleSink(&fakeLifecycleSink{}))
	state := validFakeState(t, id, key, DesiredStateEnabled, 7, 11)
	if err := sup.Reconcile(context.Background(), state, fakeEffect(id, EffectStart, 7, 11, DesiredStateEnabled)); err != nil {
		t.Fatal(err)
	}
	runtime := descriptor.Runtime(0)
	runtime.allowStart()
	done := make(chan error, 1)
	go func() { done <- sup.Stop(context.Background(), id) }()
	select {
	case <-runtime.stopCalled:
	case <-time.After(time.Second):
		t.Fatal("Stop did not call current runtime")
	}
	runtime.allowStopNow()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := sup.WorkerCount(); got != 0 {
		t.Fatalf("worker retained after stop: %d", got)
	}
}
func TestSupervisorRejectsInvalidEffect(t *testing.T) {
	if err := NewSupervisor(nil).Reconcile(context.Background(), State{}, LifecycleEffect{}); !errors.Is(err, ErrSupervisorInvalidEffect) {
		t.Fatalf("err=%v", err)
	}
}
func TestSupervisorDuplicateReloginAndReplaceKeepWorker(t *testing.T) {
	id := adapterapi.EndpointID("sup-duplicate-relogin")
	key := adapterapi.AdapterKey("fake")
	descriptor := &fakeDescriptor{key: key}
	sup := NewSupervisor(fakeDescriptorRegistry{key: descriptor}, WithLifecycleSink(&fakeLifecycleSink{}), WithStopTimeout(100*time.Millisecond))
	state := validFakeState(t, id, key, DesiredStateEnabled, 2, 3)
	effect := fakeEffect(id, EffectStart, 2, 3, DesiredStateEnabled)
	if err := sup.Reconcile(context.Background(), state, effect); err != nil {
		t.Fatal(err)
	}
	if err := sup.Reconcile(context.Background(), state, fakeEffect(id, EffectRelogin, 2, 3, DesiredStateEnabled)); err != nil {
		t.Fatal(err)
	}
	if err := sup.Reconcile(context.Background(), state, fakeEffect(id, EffectReplace, 2, 3, DesiredStateEnabled)); err != nil {
		t.Fatal(err)
	}
	if got := descriptor.RuntimeCount(); got != 1 {
		t.Fatalf("duplicate relogin/replace constructed %d runtimes", got)
	}
	if got := sup.WorkerCount(); got != 1 {
		t.Fatalf("duplicate effects removed worker, count=%d", got)
	}
}
func TestSupervisorFailsClosedWithoutLifecycleSink(t *testing.T) {
	id := adapterapi.EndpointID("sup-no-sink")
	key := adapterapi.AdapterKey("fake")
	descriptor := &fakeDescriptor{key: key}
	sup := NewSupervisor(map[adapterapi.AdapterKey]adapterapi.Descriptor{key: descriptor})
	state := validFakeState(t, id, key, DesiredStateEnabled, 1, 2)
	if err := sup.Reconcile(context.Background(), state, fakeEffect(id, EffectStart, 1, 2, DesiredStateEnabled)); !errors.Is(err, ErrSupervisorNoLifecycleSink) {
		t.Fatalf("nil sink err=%v", err)
	}
	if got := descriptor.RuntimeCount(); got != 1 {
		t.Fatalf("descriptor should construct inert runtime once, got=%d", got)
	}
	if got := sup.WorkerCount(); got != 0 {
		t.Fatalf("nil sink started worker, count=%d", got)
	}
}
func TestSupervisorDeduplicatesCompletedNoWorkerStop(t *testing.T) {
	id := adapterapi.EndpointID("sup-terminal-dedupe")
	key := adapterapi.AdapterKey("fake")
	sink := &fakeLifecycleSink{}
	sup := NewSupervisor(fakeDescriptorRegistry{key: &fakeDescriptor{key: key}}, WithLifecycleSink(sink))
	state := validFakeState(t, id, key, DesiredStateDisabled, 1, 3)
	effect := fakeEffect(id, EffectStop, 1, 3, DesiredStateDisabled)
	if err := sup.Reconcile(context.Background(), state, effect); err != nil {
		t.Fatal(err)
	}
	if err := sup.Reconcile(context.Background(), state, effect); err != nil {
		t.Fatal(err)
	}
	if got := sink.Count(adapterapi.ObservedStateStopped); got != 1 {
		t.Fatalf("terminal effect replay published %d stops", got)
	}
}

type blockingLifecycleSink struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	mu      sync.Mutex
	updates []LifecycleUpdate
}

func (s *blockingLifecycleSink) RecordLifecycle(_ context.Context, u LifecycleUpdate) error {
	s.mu.Lock()
	s.updates = append(s.updates, u)
	s.mu.Unlock()
	if u.ObservedState == adapterapi.ObservedStateConnected {
		s.once.Do(func() { close(s.entered) })
		<-s.release
	}
	return nil
}
func (s *blockingLifecycleSink) Last() LifecycleUpdate {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.updates) == 0 {
		return LifecycleUpdate{}
	}
	return s.updates[len(s.updates)-1]
}
func TestSupervisorStopWaitsForInflightObservation(t *testing.T) {
	id := adapterapi.EndpointID("sup-inflight")
	key := adapterapi.AdapterKey("fake")
	sink := &blockingLifecycleSink{entered: make(chan struct{}), release: make(chan struct{})}
	descriptor := &fakeDescriptor{key: key}
	sup := NewSupervisor(fakeDescriptorRegistry{key: descriptor}, WithLifecycleSink(sink), WithStopTimeout(time.Second))
	state := validFakeState(t, id, key, DesiredStateEnabled, 1, 2)
	if err := sup.Reconcile(context.Background(), state, fakeEffect(id, EffectStart, 1, 2, DesiredStateEnabled)); err != nil {
		t.Fatal(err)
	}
	runtime := descriptor.Runtime(0)
	runtime.allowStart()
	select {
	case <-sink.entered:
	case <-time.After(time.Second):
		t.Fatal("observation did not enter sink")
	}
	done := make(chan error, 1)
	go func() {
		done <- sup.Reconcile(context.Background(), validFakeState(t, id, key, DesiredStateDisabled, 1, 3), fakeEffect(id, EffectStop, 1, 3, DesiredStateDisabled))
	}()
	select {
	case <-runtime.stopCalled:
		t.Fatal("Stop ran before inflight observation drained")
	case <-time.After(20 * time.Millisecond):
	}
	close(sink.release)
	select {
	case <-runtime.stopCalled:
	case <-time.After(time.Second):
		t.Fatal("Stop was not called after observation drained")
	}
	runtime.allowStopNow()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
func TestSupervisorNaturalRunExitStopsAndPublishes(t *testing.T) {
	id := adapterapi.EndpointID("sup-natural-exit")
	key := adapterapi.AdapterKey("fake")
	sink := &fakeLifecycleSink{}
	descriptor := &fakeDescriptor{key: key}
	sup := NewSupervisor(fakeDescriptorRegistry{key: descriptor}, WithLifecycleSink(sink), WithStopTimeout(time.Second))
	state := validFakeState(t, id, key, DesiredStateEnabled, 1, 2)
	if err := sup.Reconcile(context.Background(), state, fakeEffect(id, EffectStart, 1, 2, DesiredStateEnabled)); err != nil {
		t.Fatal(err)
	}
	runtime := descriptor.Runtime(0)
	runtime.allowStart()
	close(runtime.exit)
	select {
	case <-runtime.stopCalled:
	case <-time.After(time.Second):
		t.Fatal("natural exit did not invoke Stop")
	}
	runtime.allowStopNow()
	deadline := time.Now().Add(time.Second)
	for sink.Count(adapterapi.ObservedStateStopped) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if sink.Count(adapterapi.ObservedStateStopped) != 1 {
		t.Fatalf("natural exit stopped count=%d", sink.Count(adapterapi.ObservedStateStopped))
	}
	if got := sup.WorkerCount(); got != 0 {
		t.Fatalf("natural exit retained live worker: %d", got)
	}
}
func TestSupervisorShutdownAfterNaturalRunExitRemovesWorker(t *testing.T) {
	id := adapterapi.EndpointID("sup-natural-shutdown")
	key := adapterapi.AdapterKey("fake")
	descriptor := &fakeDescriptor{key: key}
	sup := NewSupervisor(fakeDescriptorRegistry{key: descriptor}, WithLifecycleSink(&fakeLifecycleSink{}), WithStopTimeout(time.Second))
	state := validFakeState(t, id, key, DesiredStateEnabled, 1, 2)
	if err := sup.Reconcile(context.Background(), state, fakeEffect(id, EffectStart, 1, 2, DesiredStateEnabled)); err != nil {
		t.Fatal(err)
	}
	runtime := descriptor.Runtime(0)
	runtime.allowStart()
	select {
	case <-runtime.runStarted:
	case <-time.After(time.Second):
		t.Fatal("runtime did not launch")
	}
	close(runtime.exit)
	select {
	case <-runtime.stopCalled:
	case <-time.After(time.Second):
		t.Fatal("natural exit did not invoke Stop")
	}
	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- sup.Shutdown(context.Background()) }()
	runtime.allowStopNow()
	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown did not drain natural exit")
	}
	if got := sup.WorkerCount(); got != 0 {
		t.Fatalf("natural-exit worker retained after shutdown: %d", got)
	}
}
func TestSupervisorEqualTerminalStopRemovesOwner(t *testing.T) {
	id := adapterapi.EndpointID("sup-terminal-owner")
	key := adapterapi.AdapterKey("fake")
	descriptor := &fakeDescriptor{key: key}
	sup := NewSupervisor(fakeDescriptorRegistry{key: descriptor}, WithLifecycleSink(&fakeLifecycleSink{}))
	state := validFakeState(t, id, key, DesiredStateEnabled, 4, 7)
	if err := sup.Reconcile(context.Background(), state, fakeEffect(id, EffectStart, 4, 7, DesiredStateEnabled)); err != nil {
		t.Fatal(err)
	}
	w := sup.current(id)
	if w == nil {
		t.Fatal("worker missing")
	}
	w.mu.Lock()
	w.cleanup = true
	w.exited = true
	w.terminalPublished = true
	w.mu.Unlock()
	stopState := validFakeState(t, id, key, DesiredStateDisabled, 4, 7)
	if err := sup.Reconcile(context.Background(), stopState, fakeEffect(id, EffectStop, 4, 7, DesiredStateDisabled)); err != nil {
		t.Fatal(err)
	}
	if got := sup.WorkerCount(); got != 0 {
		t.Fatalf("equal terminal stop retained owner: %d", got)
	}
}

func TestSupervisorInboundNilContextUsesBackground(t *testing.T) {
	id := adapterapi.EndpointID("sup-inbound-context")
	key := adapterapi.AdapterKey("fake")
	descriptor := &fakeDescriptor{key: key}
	called := make(chan struct{})
	sup := NewSupervisor(fakeDescriptorRegistry{key: descriptor}, WithLifecycleSink(&fakeLifecycleSink{}), WithInboundSink(func(c context.Context, _ FencedInbound) (adapterapi.IngressReceipt, error) {
		if c == nil {
			return adapterapi.IngressReceipt{}, errors.New("nil context")
		}
		close(called)
		return adapterapi.IngressReceipt{Outcome: adapterapi.IngressAccepted}, nil
	}))
	state := validFakeState(t, id, key, DesiredStateEnabled, 1, 2)
	if err := sup.Reconcile(context.Background(), state, fakeEffect(id, EffectStart, 1, 2, DesiredStateEnabled)); err != nil {
		t.Fatal(err)
	}
	runtime := descriptor.Runtime(0)
	runtime.allowStart()
	select {
	case <-runtime.runStarted:
	case <-time.After(time.Second):
		t.Fatal("runtime did not launch")
	}
	receipt, err := runtime.port().HandleInbound(nil, adapterapi.InboundMessage{ProviderEventID: "evt-1", Kind: adapterapi.InboundKindMessage})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Outcome != adapterapi.IngressAccepted {
		t.Fatalf("outcome=%v", receipt.Outcome)
	}
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("inbound sink not called")
	}
}
func TestSupervisorShutdownCancellationMarksAllOwnersAmbiguous(t *testing.T) {
	key := adapterapi.AdapterKey("fake")
	descriptor := &fakeDescriptor{key: key}
	sink := &fakeLifecycleSink{}
	sup := NewSupervisor(fakeDescriptorRegistry{key: descriptor}, WithLifecycleSink(sink), WithStopTimeout(20*time.Millisecond))
	ids := []adapterapi.EndpointID{"sup-shutdown-a", "sup-shutdown-b"}
	for i, id := range ids {
		state := validFakeState(t, id, key, DesiredStateEnabled, 1, uint64(i+2))
		if err := sup.Reconcile(context.Background(), state, fakeEffect(id, EffectStart, 1, uint64(i+2), DesiredStateEnabled)); err != nil {
			t.Fatal(err)
		}
	}
	for i := range ids {
		descriptor.Runtime(i).allowStart()
		select {
		case <-descriptor.Runtime(i).runStarted:
		case <-time.After(time.Second):
			t.Fatal("runtime did not launch")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sup.Shutdown(ctx); err == nil {
		t.Fatal("canceled shutdown returned nil")
	}
	for _, id := range ids {
		inspection, ok := sup.Worker(id)
		if !ok {
			t.Fatalf("worker %s was deleted after canceled shutdown", id)
		}
		if !inspection.Ambiguous {
			t.Fatalf("worker %s was not marked ambiguous", id)
		}
	}
	if got := sink.Count(adapterapi.ObservedStateAmbiguous); got < 2 {
		t.Fatalf("ambiguous updates=%d", got)
	}
}
func TestSupervisorShutdownDuringRuntimeConstructionFencesStart(t *testing.T) {
	id := adapterapi.EndpointID("sup-shutdown-construction")
	key := adapterapi.AdapterKey("fake")
	descriptor := &fakeDescriptor{key: key, newRuntimeEntered: make(chan struct{}), allowNewRuntime: make(chan struct{})}
	sup := NewSupervisor(fakeDescriptorRegistry{key: descriptor}, WithLifecycleSink(&fakeLifecycleSink{}))
	state := validFakeState(t, id, key, DesiredStateEnabled, 1, 2)
	reconcileDone := make(chan error, 1)
	go func() {
		reconcileDone <- sup.Reconcile(context.Background(), state, fakeEffect(id, EffectStart, 1, 2, DesiredStateEnabled))
	}()
	select {
	case <-descriptor.newRuntimeEntered:
	case <-time.After(time.Second):
		t.Fatal("NewRuntime did not block")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sup.Shutdown(ctx); err == nil {
		t.Fatal("canceled shutdown returned nil")
	}
	close(descriptor.allowNewRuntime)
	select {
	case err := <-reconcileDone:
		if !errors.Is(err, ErrSupervisorClosed) {
			t.Fatalf("reconcile error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("reconcile remained blocked")
	}
	if got := sup.WorkerCount(); got != 0 {
		t.Fatalf("worker inserted after shutdown: %d", got)
	}
}
func TestSupervisorStopHigherDesiredVersionRemovesWorker(t *testing.T) {
	id := adapterapi.EndpointID("sup-stop-version")
	key := adapterapi.AdapterKey("fake")
	descriptor := &fakeDescriptor{key: key}
	sup := NewSupervisor(fakeDescriptorRegistry{key: descriptor}, WithLifecycleSink(&fakeLifecycleSink{}))
	enabled := validFakeState(t, id, key, DesiredStateEnabled, 1, 2)
	if err := sup.Reconcile(context.Background(), enabled, fakeEffect(id, EffectStart, 1, 2, DesiredStateEnabled)); err != nil {
		t.Fatal(err)
	}
	runtime := descriptor.Runtime(0)
	runtime.allowStart()
	select {
	case <-runtime.runStarted:
	case <-time.After(time.Second):
		t.Fatal("runtime did not launch")
	}
	disabled := validFakeState(t, id, key, DesiredStateDisabled, 1, 3)
	done := make(chan error, 1)
	go func() {
		done <- sup.Reconcile(context.Background(), disabled, fakeEffect(id, EffectStop, 1, 3, DesiredStateDisabled))
	}()
	select {
	case <-runtime.stopCalled:
	case <-time.After(time.Second):
		t.Fatal("Stop was not called")
	}
	runtime.allowStopNow()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := sup.WorkerCount(); got != 0 {
		t.Fatalf("worker retained after higher-version stop: %d", got)
	}
}

type blockingStartingSink struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	err     error
}

func (s *blockingStartingSink) RecordLifecycle(c context.Context, u LifecycleUpdate) error {
	if u.ObservedState == adapterapi.ObservedStateStarting {
		s.once.Do(func() { close(s.entered) })
		select {
		case <-s.release:
		case <-c.Done():
			return c.Err()
		}
	}
	return s.err
}

func TestSupervisorShutdownDuringStartingPublicationFencesLaunch(t *testing.T) {
	id := adapterapi.EndpointID("sup-shutdown-starting")
	key := adapterapi.AdapterKey("fake")
	descriptor := &fakeDescriptor{key: key}
	sink := &blockingStartingSink{entered: make(chan struct{}), release: make(chan struct{})}
	sup := NewSupervisor(fakeDescriptorRegistry{key: descriptor}, WithLifecycleSink(sink))
	state := validFakeState(t, id, key, DesiredStateEnabled, 1, 2)
	reconcileDone := make(chan error, 1)
	go func() {
		reconcileDone <- sup.Reconcile(context.Background(), state, fakeEffect(id, EffectStart, 1, 2, DesiredStateEnabled))
	}()
	select {
	case <-sink.entered:
	case <-time.After(time.Second):
		t.Fatal("starting publication did not block")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := sup.Shutdown(ctx); err == nil {
		t.Fatal("shutdown timeout returned nil")
	}
	close(sink.release)
	select {
	case err := <-reconcileDone:
		if !errors.Is(err, ErrSupervisorClosed) {
			t.Fatalf("reconcile error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("reconcile remained blocked")
	}
	runtime := descriptor.Runtime(0)
	select {
	case <-runtime.runStarted:
		t.Fatal("runtime launched after shutdown")
	case <-time.After(30 * time.Millisecond):
	}
	inspection, ok := sup.Worker(id)
	if !ok || !inspection.Ambiguous {
		t.Fatalf("worker owner not retained ambiguous: ok=%v inspection=%+v", ok, inspection)
	}
}
func TestSupervisorShutdownStartingPublicationErrorRetainsOwner(t *testing.T) {
	id := adapterapi.EndpointID("sup-shutdown-starting-error")
	key := adapterapi.AdapterKey("fake")
	descriptor := &fakeDescriptor{key: key}
	sink := &blockingStartingSink{entered: make(chan struct{}), release: make(chan struct{}), err: errors.New("starting uncertain")}
	sup := NewSupervisor(fakeDescriptorRegistry{key: descriptor}, WithLifecycleSink(sink))
	state := validFakeState(t, id, key, DesiredStateEnabled, 1, 2)
	reconcileDone := make(chan error, 1)
	go func() {
		reconcileDone <- sup.Reconcile(context.Background(), state, fakeEffect(id, EffectStart, 1, 2, DesiredStateEnabled))
	}()
	select {
	case <-sink.entered:
	case <-time.After(time.Second):
		t.Fatal("starting publication did not block")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := sup.Shutdown(ctx); err == nil {
		t.Fatal("shutdown timeout returned nil")
	}
	close(sink.release)
	select {
	case err := <-reconcileDone:
		if err == nil {
			t.Fatal("reconcile unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("reconcile remained blocked")
	}
	inspection, ok := sup.Worker(id)
	if !ok || !inspection.Ambiguous {
		t.Fatalf("uncertain starting owner not retained: ok=%v inspection=%+v", ok, inspection)
	}
}
func TestSupervisorShutdownDrainsObservationBeforeAmbiguous(t *testing.T) {
	id := adapterapi.EndpointID("sup-shutdown-observation")
	key := adapterapi.AdapterKey("fake")
	descriptor := &fakeDescriptor{key: key}
	sink := &blockingLifecycleSink{entered: make(chan struct{}), release: make(chan struct{})}
	sup := NewSupervisor(fakeDescriptorRegistry{key: descriptor}, WithLifecycleSink(sink), WithStopTimeout(100*time.Millisecond))
	state := validFakeState(t, id, key, DesiredStateEnabled, 1, 2)
	if err := sup.Reconcile(context.Background(), state, fakeEffect(id, EffectStart, 1, 2, DesiredStateEnabled)); err != nil {
		t.Fatal(err)
	}
	runtime := descriptor.Runtime(0)
	runtime.allowStart()
	select {
	case <-sink.entered:
	case <-time.After(time.Second):
		t.Fatal("observation did not block")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() { done <- sup.Shutdown(ctx) }()
	close(sink.release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not drain observation")
	}
	if got := sink.Last().ObservedState; got != adapterapi.ObservedStateAmbiguous {
		t.Fatalf("last lifecycle state=%v", got)
	}
	inspection, ok := sup.Worker(id)
	if !ok || !inspection.Ambiguous {
		t.Fatalf("owner not retained ambiguous: ok=%v inspection=%+v", ok, inspection)
	}
}

type blockingStoppedSink struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	mu      sync.Mutex
	updates []LifecycleUpdate
}

func (s *blockingStoppedSink) RecordLifecycle(_ context.Context, u LifecycleUpdate) error {
	s.mu.Lock()
	s.updates = append(s.updates, u)
	s.mu.Unlock()
	if u.ObservedState == adapterapi.ObservedStateStopped {
		s.once.Do(func() { close(s.entered); <-s.release })
	}
	return nil
}
func (s *blockingStoppedSink) Last() LifecycleUpdate {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.updates) == 0 {
		return LifecycleUpdate{}
	}
	return s.updates[len(s.updates)-1]
}
func TestSupervisorSkipsDuplicateSameFencePendingStop(t *testing.T) {
	id := adapterapi.EndpointID("sup-duplicate-pending-stop")
	key := adapterapi.AdapterKey("fake")
	descriptor := &fakeDescriptor{key: key}
	sup := NewSupervisor(fakeDescriptorRegistry{key: descriptor}, WithLifecycleSink(&fakeLifecycleSink{}))
	state := validFakeState(t, id, key, DesiredStateEnabled, 4, 2)
	if err := sup.Reconcile(context.Background(), state, fakeEffect(id, EffectStart, 4, 2, DesiredStateEnabled)); err != nil {
		t.Fatal(err)
	}
	w := sup.current(id)
	w.mu.Lock()
	w.cleanup = true
	w.exited = true
	w.terminalPublished = true
	queuePendingTerminal(w, LifecycleEffect{Kind: EffectStop, EndpointID: id, Generation: 4, DesiredVersion: 2, DesiredState: DesiredStateDisabled}, false)
	pending := w.pending
	w.mu.Unlock()
	if pending != nil {
		t.Fatalf("duplicate same-fence Stop queued destructive terminal: %+v", pending)
	}
}
func TestSupervisorStickyShutdownAmbiguityRetainsCleanupOwner(t *testing.T) {
	id := adapterapi.EndpointID("sup-sticky-shutdown-owner")
	key := adapterapi.AdapterKey("fake")
	descriptor := &fakeDescriptor{key: key}
	sup := NewSupervisor(fakeDescriptorRegistry{key: descriptor}, WithLifecycleSink(&fakeLifecycleSink{}))
	state := validFakeState(t, id, key, DesiredStateEnabled, 4, 7)
	if err := sup.Reconcile(context.Background(), state, fakeEffect(id, EffectStart, 4, 7, DesiredStateEnabled)); err != nil {
		t.Fatal(err)
	}
	w := sup.current(id)
	w.mu.Lock()
	w.cleanup = true
	w.exited = true
	w.terminalPublished = true
	w.ambiguous = true
	w.pending = &pendingTerminal{effect: LifecycleEffect{Kind: EffectDelete, EndpointID: id, Generation: 4, DesiredVersion: 8, DesiredState: DesiredStateRemoving}, deleted: true}
	w.mu.Unlock()
	sup.mu.Lock()
	sup.shutdownAmbiguous = true
	sup.mu.Unlock()
	if err := sup.waitCleanup(context.Background(), w); err != nil {
		t.Fatal(err)
	}
	inspection, ok := sup.Worker(id)
	if !ok || !inspection.Ambiguous {
		t.Fatalf("sticky shutdown owner was removed or cleared: ok=%v inspection=%+v", ok, inspection)
	}
}

type replayFailureSink struct {
	mu      sync.Mutex
	reject  bool
	updates []LifecycleUpdate
}

func (s *replayFailureSink) RecordLifecycle(_ context.Context, u LifecycleUpdate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updates = append(s.updates, u)
	if s.reject && u.DesiredVersion == 3 {
		return errors.New("replay terminal rejected")
	}
	return nil
}
func (s *replayFailureSink) Last() LifecycleUpdate {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.updates) == 0 {
		return LifecycleUpdate{}
	}
	return s.updates[len(s.updates)-1]
}
func (s *replayFailureSink) setReject(reject bool) { s.mu.Lock(); s.reject = reject; s.mu.Unlock() }

func TestSupervisorRetriesFailedHigherTerminalReplay(t *testing.T) {
	id := adapterapi.EndpointID("sup-replay-retry")
	key := adapterapi.AdapterKey("fake")
	descriptor := &fakeDescriptor{key: key}
	sink := &replayFailureSink{}
	sup := NewSupervisor(fakeDescriptorRegistry{key: descriptor}, WithLifecycleSink(sink))
	state := validFakeState(t, id, key, DesiredStateEnabled, 4, 2)
	if err := sup.Reconcile(context.Background(), state, fakeEffect(id, EffectStart, 4, 2, DesiredStateEnabled)); err != nil {
		t.Fatal(err)
	}
	w := sup.current(id)
	w.mu.Lock()
	w.cleanup = true
	w.exited = true
	w.terminalPublished = true
	w.mu.Unlock()
	sink.setReject(true)
	replay := LifecycleEffect{Kind: EffectStop, EndpointID: id, Generation: 4, DesiredVersion: 3, DesiredState: DesiredStateDisabled, EffectID: "replay-stop"}
	if err := sup.stopWorker(context.Background(), w, replay, false); err == nil {
		t.Fatal("failed terminal replay was swallowed")
	}
	inspection, ok := sup.Worker(id)
	if !ok || !inspection.Ambiguous {
		t.Fatalf("failed replay did not retain ambiguous owner: ok=%v inspection=%+v", ok, inspection)
	}
	w.mu.Lock()
	pending := w.pending
	w.mu.Unlock()
	if pending == nil || pending.effect.DesiredVersion != 3 {
		t.Fatalf("failed replay effect was not retained: %+v", pending)
	}
	sink.setReject(false)
	if err := sup.Reconcile(context.Background(), validFakeState(t, id, key, DesiredStateDisabled, 4, 3), replay); err != nil {
		t.Fatal(err)
	}
	if got := sup.WorkerCount(); got != 0 {
		t.Fatalf("owner retained after replay retry: %d", got)
	}
	last := sink.Last()
	if last.DesiredVersion != 3 || last.ObservedState != adapterapi.ObservedStateStopped {
		t.Fatalf("replay retry update=%+v", last)
	}
}

type failStoppedOnceSink struct {
	mu      sync.Mutex
	failed  bool
	updates []LifecycleUpdate
}

func (s *failStoppedOnceSink) RecordLifecycle(_ context.Context, u LifecycleUpdate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updates = append(s.updates, u)
	if u.ObservedState == adapterapi.ObservedStateStopped && !s.failed {
		s.failed = true
		return errors.New("natural terminal rejected")
	}
	return nil
}
func (s *failStoppedOnceSink) Last() LifecycleUpdate {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.updates) == 0 {
		return LifecycleUpdate{}
	}
	return s.updates[len(s.updates)-1]
}

func TestSupervisorRetriesFailedNaturalTerminal(t *testing.T) {
	id := adapterapi.EndpointID("sup-natural-terminal-retry")
	key := adapterapi.AdapterKey("fake")
	descriptor := &fakeDescriptor{key: key}
	sink := &failStoppedOnceSink{}
	sup := NewSupervisor(fakeDescriptorRegistry{key: descriptor}, WithLifecycleSink(sink), WithStopTimeout(time.Second))
	enabled := validFakeState(t, id, key, DesiredStateEnabled, 1, 2)
	if err := sup.Reconcile(context.Background(), enabled, fakeEffect(id, EffectStart, 1, 2, DesiredStateEnabled)); err != nil {
		t.Fatal(err)
	}
	runtime := descriptor.Runtime(0)
	runtime.allowStart()
	select {
	case <-runtime.runStarted:
	case <-time.After(time.Second):
		t.Fatal("runtime did not launch")
	}
	close(runtime.exit)
	select {
	case <-runtime.stopCalled:
	case <-time.After(time.Second):
		t.Fatal("natural cleanup Stop not called")
	}
	runtime.allowStopNow()
	deadline := time.Now().Add(time.Second)
	for {
		inspection, ok := sup.Worker(id)
		if ok && inspection.Ambiguous {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("failed natural terminal did not retain ambiguous owner")
		}
		time.Sleep(time.Millisecond)
	}
	if err := sup.Reconcile(context.Background(), validFakeState(t, id, key, DesiredStateDisabled, 1, 3), fakeEffect(id, EffectStop, 1, 3, DesiredStateDisabled)); err != nil {
		t.Fatal(err)
	}
	if got := sup.WorkerCount(); got != 0 {
		t.Fatalf("owner retained after natural terminal retry: %d", got)
	}
	last := sink.Last()
	if last.DesiredVersion != 3 || last.ObservedState != adapterapi.ObservedStateStopped {
		t.Fatalf("retry terminal update=%+v", last)
	}
}

type retryPendingSink struct {
	entered       chan struct{}
	release       chan struct{}
	once          sync.Once
	mu            sync.Mutex
	updates       []LifecycleUpdate
	rejectPending bool
}

func (s *retryPendingSink) RecordLifecycle(_ context.Context, u LifecycleUpdate) error {
	s.mu.Lock()
	s.updates = append(s.updates, u)
	reject := s.rejectPending && u.DesiredVersion == 8
	s.mu.Unlock()
	if u.ObservedState == adapterapi.ObservedStateStopped {
		s.once.Do(func() { close(s.entered); <-s.release })
	}
	if reject {
		return errors.New("pending terminal rejected")
	}
	return nil
}
func (s *retryPendingSink) setRejectPending(reject bool) {
	s.mu.Lock()
	s.rejectPending = reject
	s.mu.Unlock()
}
func (s *retryPendingSink) Last() LifecycleUpdate {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.updates) == 0 {
		return LifecycleUpdate{}
	}
	return s.updates[len(s.updates)-1]
}

func TestSupervisorPendingDeleteRetainedAndRetriedAfterPublishFailure(t *testing.T) {
	id := adapterapi.EndpointID("sup-pending-retry")
	key := adapterapi.AdapterKey("fake")
	descriptor := &fakeDescriptor{key: key}
	sink := &retryPendingSink{entered: make(chan struct{}), release: make(chan struct{})}
	sup := NewSupervisor(fakeDescriptorRegistry{key: descriptor}, WithLifecycleSink(sink), WithStopTimeout(time.Second))
	enabled := validFakeState(t, id, key, DesiredStateEnabled, 4, 7)
	if err := sup.Reconcile(context.Background(), enabled, fakeEffect(id, EffectStart, 4, 7, DesiredStateEnabled)); err != nil {
		t.Fatal(err)
	}
	runtime := descriptor.Runtime(0)
	runtime.allowStart()
	select {
	case <-runtime.runStarted:
	case <-time.After(time.Second):
		t.Fatal("runtime did not launch")
	}
	close(runtime.exit)
	select {
	case <-runtime.stopCalled:
	case <-time.After(time.Second):
		t.Fatal("natural cleanup Stop not called")
	}
	runtime.allowStopNow()
	select {
	case <-sink.entered:
	case <-time.After(time.Second):
		t.Fatal("natural terminal publication did not block")
	}
	w := sup.current(id)
	if w == nil {
		t.Fatal("owner missing during cleanup window")
	}
	stopDone := make(chan error, 1)
	go func() {
		stopDone <- sup.stopWorker(context.Background(), w, LifecycleEffect{Kind: EffectStop, EndpointID: id, DesiredVersion: 8, DesiredState: DesiredStateDisabled, EffectID: "pending-stop"}, false)
	}()
	deadline := time.Now().Add(time.Second)
	for {
		w.mu.Lock()
		queued := w.pending != nil
		w.mu.Unlock()
		if queued {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("pending stop was not queued")
		}
		time.Sleep(time.Millisecond)
	}
	w.mu.Lock()
	queuePendingTerminal(w, LifecycleEffect{Kind: EffectDelete, EndpointID: id, Generation: 4, DesiredVersion: 8, DesiredState: DesiredStateRemoving, EffectID: "pending-delete"}, true)
	w.mu.Unlock()
	w.mu.Lock()
	pending := w.pending
	w.mu.Unlock()
	if pending == nil || !pending.deleted || pending.effect.Generation != 4 {
		t.Fatalf("pending delete was not normalized/prioritized: %+v", pending)
	}
	sink.setRejectPending(true)
	close(sink.release)
	if err := <-stopDone; err == nil {
		t.Fatal("pending stop publication failure was swallowed")
	}
	inspection, ok := sup.Worker(id)
	if !ok || !inspection.Ambiguous {
		t.Fatalf("failed pending terminal did not retain ambiguous owner: ok=%v inspection=%+v", ok, inspection)
	}
	w.mu.Lock()
	pending = w.pending
	terminal := w.terminalPublished
	w.mu.Unlock()
	if !terminal {
		t.Fatal("natural terminal publication was not fenced")
	}
	if pending == nil || !pending.deleted || pending.effect.DesiredVersion != 8 {
		t.Fatalf("pending delete was lost: %+v", pending)
	}
	sink.setRejectPending(false)
	if err := sup.Reconcile(context.Background(), validFakeState(t, id, key, DesiredStateRemoving, 4, 8), LifecycleEffect{Kind: EffectDelete, EndpointID: id, Generation: 4, DesiredVersion: 8, DesiredState: DesiredStateRemoving, EffectID: "pending-delete-retry"}); err != nil {
		t.Fatal(err)
	}
	if got := sup.WorkerCount(); got != 0 {
		t.Fatalf("owner retained after successful pending retry: %d", got)
	}
	last := sink.Last()
	if last.DesiredVersion != 8 || !last.Deleted {
		t.Fatalf("retry lost delete terminal: %+v", last)
	}
}
func TestSupervisorNaturalCleanupConsumesPendingDelete(t *testing.T) {
	id := adapterapi.EndpointID("sup-pending-delete")
	key := adapterapi.AdapterKey("fake")
	descriptor := &fakeDescriptor{key: key}
	sink := &blockingStoppedSink{entered: make(chan struct{}), release: make(chan struct{})}
	sup := NewSupervisor(fakeDescriptorRegistry{key: descriptor}, WithLifecycleSink(sink), WithStopTimeout(time.Second))
	enabled := validFakeState(t, id, key, DesiredStateEnabled, 1, 2)
	if err := sup.Reconcile(context.Background(), enabled, fakeEffect(id, EffectStart, 1, 2, DesiredStateEnabled)); err != nil {
		t.Fatal(err)
	}
	runtime := descriptor.Runtime(0)
	runtime.allowStart()
	select {
	case <-runtime.runStarted:
	case <-time.After(time.Second):
		t.Fatal("runtime did not launch")
	}
	close(runtime.exit)
	select {
	case <-runtime.stopCalled:
	case <-time.After(time.Second):
		t.Fatal("natural cleanup Stop not called")
	}
	runtime.allowStopNow()
	select {
	case <-sink.entered:
	case <-time.After(time.Second):
		t.Fatal("natural terminal publication did not block")
	}
	done := make(chan error, 1)
	go func() {
		done <- sup.Reconcile(context.Background(), validFakeState(t, id, key, DesiredStateRemoving, 1, 3), LifecycleEffect{Kind: EffectDelete, EndpointID: id, Generation: 1, DesiredVersion: 3, DesiredState: DesiredStateRemoving, EffectID: "pending-delete"})
	}()
	time.Sleep(10 * time.Millisecond)
	close(sink.release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("pending delete did not converge")
	}
	last := sink.Last()
	if last.DesiredVersion != 3 || !last.Deleted {
		t.Fatalf("last terminal update=%+v", last)
	}
	if got := sup.WorkerCount(); got != 0 {
		t.Fatalf("worker retained after pending delete: %d", got)
	}
}
