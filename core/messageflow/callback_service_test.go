package messageflow

import (
	"context"
	"errors"
	"testing"
	"time"

	"Scardice-core/core/playerstate"
	"Scardice-core/eventstore"
)

func TestCallbackRejectsTypedNilDependencies(t *testing.T) {
	var inbox *callbackTestInbox
	if _, err := NewCallbackService(CallbackConfig{
		Inbox: inbox, Store: &callbackTestStore{}, Codec: callbackTestCodec{}, AllowUnboundCodec: true,
		Resolver: callbackTestResolver{}, Group: callbackTestGroupLoader{}, Player: callbackTestPlayerLoader{},
		Host: &callbackTestHost{}, WorkerID: "worker",
	}); !errors.Is(err, ErrCallbackUnavailable) {
		t.Fatalf("typed-nil callback dependency err=%v", err)
	}
	var clock *callbackFixedClock
	if collector := NewMutationCollector(eventstore.EventFactory{Clock: clock}); collector == nil {
		t.Fatal("typed-nil collector clock returned nil collector")
	}
}

func TestCallbackRejectsLeaseShorterThanHeartbeatSafetyWindow(t *testing.T) {
	_, err := NewCallbackService(CallbackConfig{
		Inbox: &callbackTestInbox{}, Store: &callbackTestStore{}, Codec: callbackTestCodec{}, AllowUnboundCodec: true,
		Resolver: callbackTestResolver{}, Group: callbackTestGroupLoader{}, Player: callbackTestPlayerLoader{},
		Host: &callbackTestHost{}, WorkerID: "worker", LeaseDuration: 29 * time.Millisecond,
	})
	if !errors.Is(err, ErrCallbackLease) {
		t.Fatalf("short callback lease err=%v", err)
	}
}

func TestCallbackProcessOneClaimsAndMarksBeforeHost(t *testing.T) {
	inbox := newCallbackTestInbox()
	store := &callbackTestStore{}
	host := &callbackTestHost{inbox: inbox}
	service := newCallbackTestService(t, inbox, store, host, callbackTestCodec{})
	if _, err := service.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !host.called || !host.markerObserved {
		t.Fatalf("host called=%v marker=%v", host.called, host.markerObserved)
	}
	if len(store.commits) != 1 || store.commits[0].InboxUpdates[0].Status != eventstore.InboxStatusConfirmedConsumed {
		t.Fatalf("commits=%#v", store.commits)
	}
}
func TestCallbackRunsAfterCommitOnlyAfterTerminalCommit(t *testing.T) {
	inbox := newCallbackTestInbox()
	fence := &callbackTestFence{}
	afterCommitCalls := 0
	store := &callbackTestStore{onCommit: func() {
		if !fence.locked || afterCommitCalls != 0 {
			t.Fatalf("commit fence locked=%v after=%d", fence.locked, afterCommitCalls)
		}
	}}
	host := &callbackTestHost{inbox: inbox, fn: func(context.Context, CallbackRequest, *playerstate.LocalOverlay, *MutationCollector) (CallbackResult, error) {
		return CallbackResult{CommitFence: fence, AfterCommit: func() {
			if !fence.locked {
				t.Fatal("after-commit hook ran outside commit fence")
			}
			afterCommitCalls++
		}}, nil
	}}
	service := newCallbackTestService(t, inbox, store, host, callbackTestCodec{})

	if _, err := service.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	if afterCommitCalls != 1 || len(store.commits) != 1 || fence.lockCalls != 1 || fence.unlockCalls != 1 || fence.locked {
		t.Fatalf("after=%d commits=%d fence=%#v", afterCommitCalls, len(store.commits), fence)
	}
}

func TestCallbackLoadsBeforeMarkerAndHost(t *testing.T) {
	inbox := newCallbackTestInbox()
	store := &callbackTestStore{}
	host := &callbackTestHost{inbox: inbox}
	service := newCallbackTestService(t, inbox, store, host, callbackTestCodec{}, callbackTestGroupLoader{err: errors.New("load group")})
	if _, err := service.ProcessOne(context.Background()); err == nil {
		t.Fatal("load failure unexpectedly succeeded")
	}
	if host.called {
		t.Fatal("host called before load completed")
	}
	if len(inbox.updates) != 1 || inbox.updates[0].Status != eventstore.InboxStatusFailed {
		t.Fatalf("updates=%#v", inbox.updates)
	}
	if len(store.commits) != 0 {
		t.Fatal("load failure committed callback mutations")
	}
}

func TestCallbackMalformedPayloadNoHost(t *testing.T) {
	inbox := newCallbackTestInbox()
	store := &callbackTestStore{}
	host := &callbackTestHost{inbox: inbox}
	service := newCallbackTestService(t, inbox, store, host, callbackTestCodec{payload: []byte(`{"status":"pending","unknown":1}`)})
	if _, err := service.ProcessOne(context.Background()); !errors.Is(err, ErrCallbackPayload) {
		t.Fatalf("malformed err=%v", err)
	}
	if host.called || len(store.commits) != 0 {
		t.Fatal("malformed payload reached host or commit")
	}
	if len(inbox.updates) != 1 || inbox.updates[0].Status != eventstore.InboxStatusFailed {
		t.Fatalf("updates=%#v", inbox.updates)
	}
}

func TestCallbackPayloadMetadataMismatchNoHost(t *testing.T) {
	tests := []struct {
		name    string
		payload string
	}{
		{
			name:    "endpoint",
			payload: `{"endpointId":"other-endpoint","generation":1,"desiredVersion":1,"message":{"kind":1,"sender":"user","conversation":"group","platform":"test"},"contentDigest":"AQ==","contentDigestKeyId":"digest","status":"pending"}`,
		},
		{
			name:    "digest",
			payload: `{"endpointId":"endpoint","generation":1,"desiredVersion":1,"message":{"kind":1,"sender":"user","conversation":"group","platform":"test"},"contentDigest":"Ag==","contentDigestKeyId":"digest","status":"pending"}`,
		},
		{
			name:    "digest key",
			payload: `{"endpointId":"endpoint","generation":1,"desiredVersion":1,"message":{"kind":1,"sender":"user","conversation":"group","platform":"test"},"contentDigest":"AQ==","contentDigestKeyId":"other-digest","status":"pending"}`,
		},
		{
			name:    "duplicate envelope field",
			payload: `{"endpointId":"endpoint","generation":1,"desiredVersion":1,"message":{"kind":1,"sender":"user","conversation":"group","platform":"test"},"contentDigest":"AQ==","contentDigestKeyId":"digest","status":"pending","status":"pending"}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inbox := newCallbackTestInbox()
			host := &callbackTestHost{inbox: inbox}
			service := newCallbackTestService(t, inbox, &callbackTestStore{}, host, callbackTestCodec{payload: []byte(test.payload)})
			if _, err := service.ProcessOne(context.Background()); !errors.Is(err, ErrCallbackPayload) {
				t.Fatalf("metadata mismatch err=%v", err)
			}
			if host.called {
				t.Fatal("metadata mismatch reached host")
			}
		})
	}
}

func TestCallbackPreMarkerConflictRetriesAtMostThree(t *testing.T) {
	inbox := newCallbackTestInbox()
	inbox.markerConflicts = CallbackMaxPreMarkerAttempts
	host := &callbackTestHost{inbox: inbox}
	store := &callbackTestStore{}
	service := newCallbackTestService(t, inbox, store, host, callbackTestCodec{})
	if _, err := service.ProcessOne(context.Background()); !errors.Is(err, eventstore.ErrConflict) {
		t.Fatalf("conflict err=%v", err)
	}
	if inbox.claims != CallbackMaxPreMarkerAttempts || host.called {
		t.Fatalf("claims=%d host=%v", inbox.claims, host.called)
	}
}

func TestCallbackHostPanicBecomesAmbiguousAndNeverReruns(t *testing.T) {
	inbox := newCallbackTestInbox()
	host := &callbackTestHost{inbox: inbox, panic: true}
	service := newCallbackTestService(t, inbox, &callbackTestStore{}, host, callbackTestCodec{})
	if _, err := service.ProcessOne(context.Background()); err == nil {
		t.Fatal("panic unexpectedly succeeded")
	}
	if len(inbox.updates) != 2 || inbox.updates[0].Status != eventstore.InboxStatusCallbackStarted || inbox.updates[1].Status != eventstore.InboxStatusAmbiguous {
		t.Fatalf("updates=%#v", inbox.updates)
	}
	if _, err := service.ProcessOne(context.Background()); !errors.Is(err, eventstore.ErrNotFound) {
		t.Fatalf("ambiguous rerun err=%v", err)
	}
	if host.calls != 1 {
		t.Fatalf("host calls=%d", host.calls)
	}
}

func TestCallbackAtomicMultiStreamPluginEffectAndWorkflow(t *testing.T) {
	inbox := newCallbackTestInbox()
	store := &callbackTestStore{}
	host := &callbackTestHost{inbox: inbox, fn: func(_ context.Context, _ CallbackRequest, overlay *playerstate.LocalOverlay, collector *MutationCollector) (CallbackResult, error) {
		overlay.Set("$t临时", "local")
		if err := collector.AddStream(eventstore.StreamID{AggregateType: "player", AggregateID: "player-1"}, 2, []eventstore.NewEvent{callbackEvent("player.changed", `{"name":"new"}`)}); err != nil {
			return CallbackResult{}, err
		}
		if err := collector.AddPluginKV(eventstore.PluginKVUpdate{ExtensionID: "plugin", KeyHMAC: []byte("hmac"), KeyCiphertext: []byte("encrypted-key"), KeyNonce: []byte("nonce"), ValueCiphertext: []byte("encrypted-value"), ValueNonce: []byte("nonce"), EncryptionKeyID: "key", ValueSize: 2}); err != nil {
			return CallbackResult{}, err
		}
		if err := collector.AddEffect(eventstore.NewEffect{EffectID: "effect-1", EndpointID: "endpoint", LaneHMAC: []byte("lane"), EffectType: "send", RiskClass: eventstore.RiskPreDispatchRetryable, Status: eventstore.OutboxStatusPending, PayloadCiphertext: []byte("encrypted-effect"), PayloadNonce: []byte("nonce"), PayloadEncryptionKeyID: "key"}); err != nil {
			return CallbackResult{}, err
		}
		if err := collector.AddSecretUpdate(eventstore.SecretUpdate{SecretRef: "attributes-secret", EndpointID: "attrs-1", AdapterID: "attributes", SecretVersion: 1, Ciphertext: []byte("encrypted-attributes"), Nonce: []byte("nonce"), EncryptionKeyID: "key"}); err != nil {
			return CallbackResult{}, err
		}
		return CallbackResult{Workflow: &WorkflowResult{ID: "workflow-1", Event: callbackEvent(MessageWorkflowTerminatedEventType, `{"done":true}`)}}, nil
	}}
	service := newCallbackTestService(t, inbox, store, host, callbackTestCodec{})
	result, err := service.ProcessOne(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.WorkflowID != "workflow-1" || len(store.commits) != 1 {
		t.Fatalf("result=%#v commits=%d", result, len(store.commits))
	}
	work := store.commits[0]
	if len(work.Streams) != 2 || len(work.PluginKVUpdates) != 1 || len(work.SecretUpdates) != 1 || len(work.Effects) != 1 || len(work.InboxUpdates) != 1 {
		t.Fatalf("work=%#v", work)
	}
	if work.InboxUpdates[0].WorkflowID != "workflow-1" || work.InboxUpdates[0].Status != eventstore.InboxStatusConfirmedConsumed {
		t.Fatalf("terminal=%#v", work.InboxUpdates[0])
	}
}

func TestCallbackOrdinaryCallbackHasNoWorkflow(t *testing.T) {
	inbox := newCallbackTestInbox()
	store := &callbackTestStore{}
	service := newCallbackTestService(t, inbox, store, &callbackTestHost{inbox: inbox}, callbackTestCodec{})
	if _, err := service.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	work := store.commits[0]
	if len(work.Streams) != 0 || work.InboxUpdates[0].WorkflowID != "" {
		t.Fatalf("ordinary workflow mutation=%#v", work)
	}
}

func TestCallbackInvalidWorkflowIsAmbiguous(t *testing.T) {
	inbox := newCallbackTestInbox()
	host := &callbackTestHost{inbox: inbox, fn: func(context.Context, CallbackRequest, *playerstate.LocalOverlay, *MutationCollector) (CallbackResult, error) {
		return CallbackResult{Workflow: &WorkflowResult{ID: "bad/id", Event: callbackEvent(MessageWorkflowTerminatedEventType, `{}`)}}, nil
	}}
	service := newCallbackTestService(t, inbox, &callbackTestStore{}, host, callbackTestCodec{})
	if _, err := service.ProcessOne(context.Background()); !errors.Is(err, ErrCallbackWorkflow) {
		t.Fatalf("workflow err=%v", err)
	}
	if inbox.updates[len(inbox.updates)-1].Status != eventstore.InboxStatusAmbiguous {
		t.Fatalf("updates=%#v", inbox.updates)
	}
}

func TestCallbackCollectorRejectsOverlayIdentitiesAndMalformedEvents(t *testing.T) {
	collector := NewMutationCollector(eventstore.EventFactory{})
	stream := eventstore.StreamID{AggregateType: "group", AggregateID: "group-1"}
	if err := NewMutationCollector(eventstore.EventFactory{}).AddStream(eventstore.StreamID{AggregateType: "group", AggregateID: "duplicate-key"}, 0, []eventstore.NewEvent{callbackEvent("group.changed", `{"value":"$t","value":"ok"}`)}); !errors.Is(err, eventstore.ErrInvalidEvent) {
		t.Fatalf("duplicate-key event err=%v", err)
	}
	if err := NewMutationCollector(eventstore.EventFactory{}).AddStream(eventstore.StreamID{AggregateType: "group", AggregateID: "trailing-value"}, 0, []eventstore.NewEvent{callbackEvent("group.changed", `{"value":"ok"} {"value":"later"}`)}); !errors.Is(err, eventstore.ErrInvalidEvent) {
		t.Fatalf("trailing event err=%v", err)
	}
	for _, field := range []string{"EventID", "CommandID", "CorrelationID", "CausationID", "PrincipalID", "Producer"} {
		event := callbackEvent("group.metadata", `{}`)
		switch field {
		case "EventID":
			event.Metadata.EventID = "$t-event"
		case "CommandID":
			event.Metadata.CommandID = "$t-command"
		case "CorrelationID":
			event.Metadata.CorrelationID = "$t-correlation"
		case "CausationID":
			event.Metadata.CausationID = "$t-causation"
		case "PrincipalID":
			event.Metadata.PrincipalID = "$t-principal"
		case "Producer":
			event.Metadata.Producer = "$t-producer"
		}
		if err := NewMutationCollector(eventstore.EventFactory{}).AddStream(eventstore.StreamID{AggregateType: "group", AggregateID: "metadata-" + field}, 0, []eventstore.NewEvent{event}); !errors.Is(err, eventstore.ErrInvalidEvent) {
			t.Fatalf("overlay metadata %s err=%v", field, err)
		}
	}
	for _, stream := range []eventstore.StreamID{
		{AggregateType: "$t-type", AggregateID: "group"},
		{AggregateType: "group", AggregateID: "$t-id"},
	} {
		if err := NewMutationCollector(eventstore.EventFactory{}).AddStream(stream, 0, []eventstore.NewEvent{callbackEvent("group.changed", `{}`)}); !errors.Is(err, ErrCallbackWorkflow) {
			t.Fatalf("overlay stream %#v err=%v", stream, err)
		}
	}
	event := callbackEvent("group.changed", `{}`)
	event.EventType = "$t-event"
	if err := NewMutationCollector(eventstore.EventFactory{}).AddStream(eventstore.StreamID{AggregateType: "group", AggregateID: "event-type"}, 0, []eventstore.NewEvent{event}); !errors.Is(err, eventstore.ErrInvalidEvent) {
		t.Fatalf("overlay event type err=%v", err)
	}
	plugin := eventstore.PluginKVUpdate{
		ExtensionID: "plugin", KeyHMAC: []byte("key"), KeyCiphertext: []byte("ciphertext"), KeyNonce: []byte("nonce"),
		ValueCiphertext: []byte("value"), ValueNonce: []byte("nonce"), EncryptionKeyID: "key", ValueSize: 2,
	}
	for _, field := range []string{"ExtensionID", "EncryptionKeyID"} {
		update := plugin
		if field == "ExtensionID" {
			update.ExtensionID = "$t-plugin"
		} else {
			update.EncryptionKeyID = "$t-plugin-key"
		}
		if err := NewMutationCollector(eventstore.EventFactory{}).AddPluginKV(update); !errors.Is(err, eventstore.ErrInvalidMetadata) {
			t.Fatalf("overlay plugin %s err=%v", field, err)
		}
	}
	effect := eventstore.NewEffect{
		EffectID: "effect", EndpointID: "endpoint", LaneHMAC: []byte("lane"), EffectType: "send",
		RiskClass: eventstore.RiskPreDispatchRetryable, Status: eventstore.OutboxStatusPending,
		PayloadCiphertext: []byte("ciphertext"), PayloadNonce: []byte("nonce"), PayloadEncryptionKeyID: "key",
	}
	for _, field := range []string{"EffectID", "EndpointID", "EffectType", "RiskClass", "Status", "AttemptID", "LeaseOwner", "DigestKeyID", "PayloadEncryptionKeyID", "ContentDigestKeyID", "ProviderMessageID", "ResultCode", "ErrorCode", "Resolution", "PrincipalID", "Reason"} {
		update := effect
		switch field {
		case "EffectID":
			update.EffectID = "$t-effect"
		case "EndpointID":
			update.EndpointID = "$t-endpoint"
		case "EffectType":
			update.EffectType = "$t-effect-type"
		case "RiskClass":
			update.RiskClass = "$t-risk"
		case "Status":
			update.Status = "$t-status"
		case "AttemptID":
			update.AttemptID = "$t-attempt"
		case "LeaseOwner":
			update.LeaseOwner = "$t-owner"
		case "DigestKeyID":
			update.DigestKeyID = "$t-digest"
		case "PayloadEncryptionKeyID":
			update.PayloadEncryptionKeyID = "$t-payload-key"
		case "ContentDigestKeyID":
			update.ContentDigestKeyID = "$t-content-key"
		case "ProviderMessageID":
			update.ProviderMessageID = "$t-provider"
		case "ResultCode":
			update.ResultCode = "$t-result"
		case "ErrorCode":
			update.ErrorCode = "$t-error"
		case "Resolution":
			update.Resolution = "$t-resolution"
		case "PrincipalID":
			update.PrincipalID = "$t-principal"
		case "Reason":
			update.Reason = "$t-reason"
		}
		if err := NewMutationCollector(eventstore.EventFactory{}).AddEffect(update); !errors.Is(err, eventstore.ErrInvalidMetadata) {
			t.Fatalf("overlay effect %s err=%v", field, err)
		}
	}
	if err := validateWorkflowResult(&WorkflowResult{ID: "$t-workflow", Event: callbackEvent(MessageWorkflowTerminatedEventType, `{}`)}); !errors.Is(err, ErrCallbackWorkflow) {
		t.Fatalf("overlay workflow id err=%v", err)
	}
	opaqueCollector := NewMutationCollector(eventstore.EventFactory{})
	if err := opaqueCollector.AddPluginKV(eventstore.PluginKVUpdate{
		ExtensionID: "plugin", KeyHMAC: []byte("key"), KeyCiphertext: []byte("$t-ciphertext"),
		KeyNonce: []byte("nonce"), ValueCiphertext: []byte("$t-ciphertext"), ValueNonce: []byte("nonce"),
		EncryptionKeyID: "key", ValueSize: 2,
	}); err != nil {
		t.Fatalf("opaque ciphertext rejected: %v", err)
	}
	if err := collector.AddStream(stream, 0, []eventstore.NewEvent{callbackEvent("group.changed", `{}`)}); err != nil {
		t.Fatal(err)
	}
	if err := collector.AddStream(stream, 0, []eventstore.NewEvent{callbackEvent("group.changed", `{}`)}); !errors.Is(err, eventstore.ErrDuplicateStream) {
		t.Fatalf("duplicate stream err=%v", err)
	}
	if err := collector.AddStream(eventstore.StreamID{AggregateType: MessageWorkflowAggregateType, AggregateID: "workflow"}, 0, []eventstore.NewEvent{callbackEvent(MessageWorkflowTerminatedEventType, `{}`)}); err == nil {
		t.Fatal("ordinary collector accepted workflow stream")
	}
}

func TestCallbackRenewsLeaseWhileHostRuns(t *testing.T) {
	inbox := newCallbackTestInbox()
	inbox.renewed = make(chan struct{}, 1)
	store := &callbackTestStore{}
	host := &callbackTestHost{fn: func(ctx context.Context, _ CallbackRequest, _ *playerstate.LocalOverlay, _ *MutationCollector) (CallbackResult, error) {
		select {
		case <-inbox.renewed:
			return CallbackResult{}, nil
		case <-ctx.Done():
			return CallbackResult{}, ctx.Err()
		case <-time.After(time.Second):
			return CallbackResult{}, errors.New("lease was not renewed")
		}
	}}
	service, err := NewCallbackService(CallbackConfig{
		Inbox: inbox, Store: store, Codec: callbackTestCodec{}, AllowUnboundCodec: true,
		Resolver: callbackTestResolver{}, Group: callbackTestGroupLoader{}, Player: callbackTestPlayerLoader{},
		Host: host, WorkerID: "worker", LeaseDuration: 30 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	if inbox.renewals == 0 {
		t.Fatal("callback completed without renewing its lease")
	}
	if len(store.commits) != 1 || len(store.commits[0].InboxUpdates) != 1 || store.commits[0].InboxUpdates[0].ExpectedVersion != inbox.lease.Update.Version {
		t.Fatalf("terminal commit did not use renewed lease version: lease=%#v commits=%#v", inbox.lease, store.commits)
	}
}
func TestCallbackCommitFailureBecomesAmbiguousWithoutHostRetry(t *testing.T) {
	inbox := newCallbackTestInbox()
	fence := &callbackTestFence{}
	store := &callbackTestStore{commitErr: eventstore.ErrParticipantFailure, onCommit: func() {
		if !fence.locked {
			t.Fatal("failed terminal commit ran outside commit fence")
		}
	}}
	afterCommitCalls := 0
	host := &callbackTestHost{inbox: inbox, fn: func(context.Context, CallbackRequest, *playerstate.LocalOverlay, *MutationCollector) (CallbackResult, error) {
		return CallbackResult{CommitFence: fence, AfterCommit: func() { afterCommitCalls++ }}, nil
	}}
	service := newCallbackTestService(t, inbox, store, host, callbackTestCodec{})
	if _, err := service.ProcessOne(context.Background()); !errors.Is(err, eventstore.ErrParticipantFailure) {
		t.Fatalf("commit err=%v", err)
	}
	if host.calls != 1 || len(inbox.updates) != 2 || inbox.updates[1].Status != eventstore.InboxStatusAmbiguous {
		t.Fatalf("host calls=%d updates=%#v", host.calls, inbox.updates)
	}
	if afterCommitCalls != 0 || fence.lockCalls != 1 || fence.unlockCalls != 1 || fence.locked {
		t.Fatalf("failed commit after=%d fence=%#v", afterCommitCalls, fence)
	}
	if _, err := service.ProcessOne(context.Background()); !errors.Is(err, eventstore.ErrNotFound) {
		t.Fatalf("ambiguous retry err=%v", err)
	}
	if host.calls != 1 || afterCommitCalls != 0 || fence.lockCalls != 1 || fence.unlockCalls != 1 {
		t.Fatalf("retry reran host or hooks: host=%d after=%d fence=%#v", host.calls, afterCommitCalls, fence)
	}
}

func TestMutationCollectorBatchAndSubjectBindingAreAtomic(t *testing.T) {
	collector := NewMutationCollector(eventstore.EventFactory{})
	valid := eventstore.PluginKVUpdate{ExtensionID: "plugin", KeyHMAC: []byte("one"), KeyCiphertext: []byte("key"), KeyNonce: []byte("nonce"), ValueCiphertext: []byte("value"), ValueNonce: []byte("nonce"), EncryptionKeyID: "key", ValueSize: 5}
	invalid := valid
	invalid.ExtensionID = "$t-plugin"
	if err := collector.AddPluginKVBatch([]eventstore.PluginKVUpdate{valid, invalid}); !errors.Is(err, eventstore.ErrInvalidMetadata) {
		t.Fatalf("batch err=%v", err)
	}
	work, collectorErr := collector.UnitOfWork()
	if collectorErr != nil {
		t.Fatal(collectorErr)
	}
	if len(work.PluginKVUpdates) != 0 {
		t.Fatalf("failed batch staged %#v", work.PluginKVUpdates)
	}
	collector.subjectKey = []byte("subject")
	effect := eventstore.NewEffect{EffectID: "effect", EndpointID: "endpoint", LaneHMAC: []byte("lane"), EffectType: "send", RiskClass: eventstore.RiskPreDispatchRetryable, Status: eventstore.OutboxStatusPending, PayloadCiphertext: []byte("cipher"), PayloadNonce: []byte("nonce"), PayloadEncryptionKeyID: "key"}
	if err := collector.AddEffect(effect); err != nil {
		t.Fatal(err)
	}
	effect.SubjectKey = []byte("forged")
	if err := collector.AddEffect(effect); !errors.Is(err, eventstore.ErrDuplicateParticipant) {
		t.Fatalf("duplicate forged effect err=%v", err)
	}
	work, collectorErr = collector.UnitOfWork()
	if collectorErr != nil || len(work.Effects) != 1 || string(work.Effects[0].SubjectKey) != "subject" {
		t.Fatalf("bound effect=%#v err=%v", work.Effects, collectorErr)
	}
	work.Effects[0].SubjectKey[0] = 'x'
	again, collectorErr := collector.UnitOfWork()
	if collectorErr != nil || string(again.Effects[0].SubjectKey) != "subject" {
		t.Fatalf("effect snapshot aliases collector=%#v err=%v", again.Effects, collectorErr)
	}
}

func TestMutationCollectorClonesEventSubjectKey(t *testing.T) {
	collector := NewMutationCollector(eventstore.EventFactory{})
	key := []byte("subject")
	event := callbackEvent("group.changed", `{}`)
	event.Metadata.SubjectKey = key
	if err := collector.AddStream(eventstore.StreamID{AggregateType: "group", AggregateID: "group-1"}, 0, []eventstore.NewEvent{event}); err != nil {
		t.Fatal(err)
	}
	key[0] = 'x'
	work, err := collector.UnitOfWork()
	if err != nil || string(work.Streams[0].Events[0].Metadata.SubjectKey) != "subject" {
		t.Fatalf("event subject key=%#v err=%v", work.Streams, err)
	}
}
