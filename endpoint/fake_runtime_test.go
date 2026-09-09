package endpoint

import (
    "context"
    "encoding/json"
    "errors"
    "sync"
    "testing"

    "Scardice-core/adapterapi"
)

type fakeDescriptor struct {
    key adapterapi.AdapterKey
    mu sync.Mutex
    inits []adapterapi.RuntimeInit
    runtimes []*fakeRuntime
    newRuntimeEntered chan struct{}
    allowNewRuntime chan struct{}
}
func (d *fakeDescriptor) Key() adapterapi.AdapterKey { return d.key }
func (d *fakeDescriptor) ConfigVersion() uint16 { return 1 }
func (d *fakeDescriptor) ValidateConfig(_ context.Context, raw json.RawMessage) (adapterapi.ValidatedConfig, error) { canonical, err := adapterapi.CanonicalizeJSON(raw); if err != nil { return adapterapi.ValidatedConfig{}, err }; return adapterapi.ValidatedConfig{Version:1,Canonical:canonical}, nil }
func (d *fakeDescriptor) SupportedActions(adapterapi.ValidatedConfig) adapterapi.ActionSet { return 0 }
func (d *fakeDescriptor) NewRuntime(init adapterapi.RuntimeInit) (adapterapi.AdapterRuntime,error) { if d.newRuntimeEntered!=nil { closeOnce(d.newRuntimeEntered); <-d.allowNewRuntime }; if init.Generation==0 || init.DesiredVersion==0{return nil,errors.New("missing runtime fence")}; r:=newFakeRuntime(init); d.mu.Lock(); d.inits=append(d.inits,init); d.runtimes=append(d.runtimes,r); d.mu.Unlock(); return r,nil }
func (d *fakeDescriptor) Runtime(i int) *fakeRuntime { d.mu.Lock(); defer d.mu.Unlock(); if i<0||i>=len(d.runtimes){return nil}; return d.runtimes[i] }
func (d *fakeDescriptor) RuntimeCount() int { d.mu.Lock(); defer d.mu.Unlock(); return len(d.runtimes) }

type fakeRuntime struct {
    init adapterapi.RuntimeInit
    core adapterapi.CorePort
    runStarted chan struct{}
    allowRun chan struct{}
    stopCalled chan struct{}
    allowStop chan struct{}
    exit chan struct{}
    runOnce sync.Once
    stopOnce sync.Once
    coreMu sync.Mutex
}
func newFakeRuntime(init adapterapi.RuntimeInit) *fakeRuntime { return &fakeRuntime{init:init,runStarted:make(chan struct{}),allowRun:make(chan struct{}),stopCalled:make(chan struct{}),allowStop:make(chan struct{}),exit:make(chan struct{})} }
func (r *fakeRuntime) Run(ctx context.Context, core adapterapi.CorePort) error { r.coreMu.Lock(); r.core=core; r.coreMu.Unlock(); r.runOnce.Do(func(){close(r.runStarted)}); select{case <-r.allowRun:case <-ctx.Done():return ctx.Err()}; _=core.ReportObservation(ctx,adapterapi.LifecycleObservation{Kind:adapterapi.LifecycleObservationState,State:adapterapi.ObservedStateConnected}); select{case <-r.exit:return nil;case <-ctx.Done():return ctx.Err()} }
func (r *fakeRuntime) Stop(ctx context.Context) error { r.stopOnce.Do(func(){close(r.stopCalled)}); select{case <-r.allowStop:closeOnce(r.exit);return nil;case <-ctx.Done():return ctx.Err()} }
func (r *fakeRuntime) Capabilities() adapterapi.CapabilitySet{return 0}
func (r *fakeRuntime) Execute(context.Context,adapterapi.OutboundEffect) adapterapi.EffectResult{return adapterapi.UnsupportedResult("fake")}
func (r *fakeRuntime) Diagnostics(context.Context) adapterapi.DiagnosticReport{return adapterapi.DiagnosticReport{}}
func (r *fakeRuntime) allowStart(){closeOnce(r.allowRun)}
func (r *fakeRuntime) allowStopNow(){closeOnce(r.allowStop)}
func (r *fakeRuntime) port() adapterapi.CorePort{r.coreMu.Lock();defer r.coreMu.Unlock();return r.core}
func closeOnce(ch chan struct{}){select{case <-ch:default:close(ch)}}

type fakeLifecycleSink struct{mu sync.Mutex;updates []LifecycleUpdate}
func(s *fakeLifecycleSink)RecordLifecycle(_ context.Context,u LifecycleUpdate)error{s.mu.Lock();s.updates=append(s.updates,u);s.mu.Unlock();return nil}
func(s *fakeLifecycleSink)Last()LifecycleUpdate{s.mu.Lock();defer s.mu.Unlock();if len(s.updates)==0{return LifecycleUpdate{}};return s.updates[len(s.updates)-1]}
func(s *fakeLifecycleSink)Count(state adapterapi.ObservedState)int{s.mu.Lock();defer s.mu.Unlock();n:=0;for _,u:=range s.updates{if u.ObservedState==state{n++}};return n}

type fakeDescriptorRegistry map[adapterapi.AdapterKey]adapterapi.Descriptor
func(r fakeDescriptorRegistry)Lookup(_ context.Context,k adapterapi.AdapterKey)(adapterapi.Descriptor,bool){d,ok:=r[k];return d,ok}
func validFakeState(t *testing.T,id adapterapi.EndpointID,key adapterapi.AdapterKey,desired DesiredState,generation,desiredVersion uint64)State{t.Helper();return State{EndpointID:id,AdapterKey:key,Config:adapterapi.ValidatedConfig{Version:1,Canonical:json.RawMessage(`{"x":1}`)},DesiredState:desired,ObservedState:adapterapi.ObservedStateStopped,OperationState:OperationStatePending,Generation:generation,DesiredVersion:desiredVersion,Version:desiredVersion,OperationID:"op",CorrelationID:"corr",ProcessedCommands:map[string]CommandRecord{},AppliedEffects:map[string]struct{}{}}}
