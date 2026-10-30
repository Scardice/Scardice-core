package dice

import (
	"context"
	"errors"
	"testing"

	"Scardice-core/dice/sealpack"
	"Scardice-core/eventstore"
	"Scardice-core/utils/jsengine"
)

type revokedOwnerLoop struct{}

func (revokedOwnerLoop) Engine() jsengine.EngineID { return jsengine.EngineGoja }
func (revokedOwnerLoop) Descriptor() jsengine.Descriptor {
	return jsengine.Descriptor{ID: jsengine.EngineGoja}
}
func (revokedOwnerLoop) Run(func(jsengine.Runtime) error) error      { return nil }
func (revokedOwnerLoop) LoadEntry(jsengine.Entry) error              { return nil }
func (revokedOwnerLoop) Close() error                                { return nil }
func (revokedOwnerLoop) Schedule(func(jsengine.Runtime) error) error { return nil }
func (revokedOwnerLoop) RunWithContext(any, func(jsengine.Runtime) error) error {
	return nil
}
func (revokedOwnerLoop) ScheduleWithContext(any, func(jsengine.Runtime) error) error {
	return nil
}
func (revokedOwnerLoop) CurrentContext() any { return jsengine.RevokedExecutionScope{} }
func (revokedOwnerLoop) LoadEntryWithContext(any, jsengine.Entry) error {
	return nil
}
func (revokedOwnerLoop) InOwner() bool { return true }

func TestRevokedExecutionScopeResolvesToExpiredMessageContext(t *testing.T) {
	execution := jsOpaqueExecutionContext(jsengine.RevokedExecutionScope{})
	if execution == nil || execution.Message == nil {
		t.Fatal("revoked provider context became an unbound standalone context")
	}
	if err := execution.Message.checkExecution(); !errors.Is(err, context.Canceled) {
		t.Fatalf("revoked message context error = %v, want context cancellation", err)
	}
}
func TestRevokedNativeCallbackCannotFallbackToStandaloneStorage(t *testing.T) {
	store, _ := repairTestStore(t)
	loop := revokedOwnerLoop{}
	manager := NewJsLoopManager()
	manager.instances[1] = &jsRuntimeInstance{loop: loop, generation: 1}
	d := &Dice{DurableStore: store, ExtLoopManager: manager}
	ext := &ExtInfo{Name: "revoked-native-callback", dice: d}

	if err := ext.StorageSet("escaped", "value"); !errors.Is(err, context.Canceled) {
		t.Fatalf("revoked storage write error = %v, want context cancellation", err)
	}
	if _, err := store.GetPluginKV(context.Background(), ext.Name, "escaped"); !errors.Is(err, eventstore.ErrPluginKVNotFound) {
		t.Fatalf("revoked callback wrote through standalone fallback: %v", err)
	}
}

func TestJSCompatibilityReplayDecisionSuppressesCallbacksSchedulingAndEffects(t *testing.T) {
	decision := DecideJSCompatibility(JSCompatibilityReplay)
	if decision.AllowsLegacyCallback() || decision.AllowsCallbackScheduling() || decision.AllowsEffectCapture() {
		t.Fatalf("replay decision allows side effects: %#v", decision)
	}
	boundary := NewJSCompatibilityBoundary(JSCompatibilityReplay)
	if err := boundary.InvokeLegacyCallback(func() error { t.Fatal("replay callback ran"); return nil }); !errors.Is(err, ErrJSCompatibilityReplaySuppressed) {
		t.Fatalf("replay callback err=%v", err)
	}
	if err := boundary.ScheduleCallback(func() error { t.Fatal("replay schedule ran"); return nil }); !errors.Is(err, ErrJSCompatibilityReplaySuppressed) {
		t.Fatalf("replay schedule err=%v", err)
	}
	request := JSEffectRequest{
		EffectID: "effect", EndpointID: "endpoint", LaneHMAC: []byte("lane"),
		EffectType: "send", RiskClass: eventstore.RiskPreDispatchRetryable,
		Status: eventstore.OutboxStatusPending, PayloadCiphertext: []byte("cipher"),
		PayloadNonce: []byte("nonce"), PayloadEncryptionKeyID: "key",
	}
	if _, err := boundary.BuildEffect(request); !errors.Is(err, ErrJSCompatibilityReplaySuppressed) {
		t.Fatalf("replay effect build err=%v", err)
	}
	if err := boundary.CaptureEffect(func() error { t.Fatal("replay effect capture ran"); return nil }); !errors.Is(err, ErrJSCompatibilityReplaySuppressed) {
		t.Fatalf("replay effect capture err=%v", err)
	}
}

func TestJSCompatibilityLiveDecisionAllowsCallbacksAndEffects(t *testing.T) {
	decision := DecideJSCompatibility(JSCompatibilityLive)
	if !decision.AllowsLegacyCallback() || !decision.AllowsCallbackScheduling() || !decision.AllowsEffectCapture() {
		t.Fatalf("live decision suppresses work: %#v", decision)
	}
	boundary := NewJSCompatibilityBoundary(JSCompatibilityLive)
	called := false
	if err := boundary.InvokeLegacyCallback(func() error { called = true; return nil }); err != nil || !called {
		t.Fatalf("live callback err=%v called=%v", err, called)
	}
}

func TestJSCompatibilityExternalEffectTrackerClassifiesUncertainty(t *testing.T) {
	tracker := NewJSExternalEffectTracker()
	if tracker.PossiblyStarted() {
		t.Fatal("new tracker reports an external effect")
	}
	tracker.MarkPossible()
	if !tracker.PossiblyStarted() {
		t.Fatal("tracker lost external-effect marker")
	}
	if !errors.Is(ClassifyJSCompatibilityFailure(tracker, errors.New("process lost")), ErrJSExternalEffectAmbiguous) {
		t.Fatal("uncertain external effect was not classified ambiguous")
	}
	if !errors.Is(ClassifyJSCompatibilityFailure(NewJSExternalEffectTracker(), ErrJSValidation), ErrJSValidation) {
		t.Fatal("deterministic validation failure was not preserved")
	}
}

func TestJSCompatibilityExternalAccessIsSuppressedOnlyInReplay(t *testing.T) {
	replayTracker := NewJSExternalEffectTracker()
	replay := &jsExecutionContext{CompatibilityMode: JSCompatibilityReplay, ExternalEffects: replayTracker}
	if err := jsCompatibilityExternalAccess(replay); !errors.Is(err, ErrJSCompatibilityReplaySuppressed) {
		t.Fatalf("replay external access err=%v", err)
	}
	if replayTracker.PossiblyStarted() {
		t.Fatal("replay marked an external effect")
	}
	liveTracker := NewJSExternalEffectTracker()
	live := &jsExecutionContext{CompatibilityMode: JSCompatibilityLive, ExternalEffects: liveTracker}
	if err := jsCompatibilityExternalAccess(live); err != nil {
		t.Fatalf("live external access err=%v", err)
	}
	if !liveTracker.PossiblyStarted() {
		t.Fatal("live external access did not mark possible effect")
	}
}

func TestJSCompatibilityUncertainCallbackIsAmbiguousAndValidationRemainsDeterministic(t *testing.T) {
	boundary := NewJSCompatibilityBoundary(JSCompatibilityLive)
	tracker := NewJSExternalEffectTracker()
	err := boundary.InvokeLegacyCallbackWithTracker(tracker, func() error {
		tracker.MarkPossible()
		return errors.New("host lost")
	})
	if !errors.Is(err, ErrJSExternalEffectAmbiguous) {
		t.Fatalf("uncertain callback err=%v", err)
	}
	validation := boundary.InvokeLegacyCallbackWithTracker(NewJSExternalEffectTracker(), func() error {
		return ErrJSValidation
	})
	if !errors.Is(validation, ErrJSValidation) || errors.Is(validation, ErrJSExternalEffectAmbiguous) {
		t.Fatalf("validation callback err=%v", validation)
	}
}

func TestJSCompatibilityReplayDoesNotBypassPermissions(t *testing.T) {
	const packageID = "author/replay-permissions"
	d := newPermissionTestDice(t, packageID, sealpack.Permissions{})
	replay := &jsExecutionContext{CompatibilityMode: JSCompatibilityReplay, Plugin: &ExtInfo{Source: &JsScriptInfo{PackageID: packageID}}}
	if err := jsNetworkAuthorizeWithContext(d, replay, "https://example.test"); err == nil || errors.Is(err, ErrJSCompatibilityReplaySuppressed) {
		t.Fatalf("network permission result=%v, want permission denial before replay gate", err)
	}
	if err := jsFilesystemAuthorizeWithContext(d, replay, "data://blocked.txt", true); err == nil || errors.Is(err, ErrJSCompatibilityReplaySuppressed) {
		t.Fatalf("filesystem permission result=%v, want permission denial before replay gate", err)
	}
}
