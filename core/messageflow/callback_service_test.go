package messageflow

import (
	"context"
	"errors"
	"testing"
	"time"

	"Scardice-core/core/execution"
	"Scardice-core/core/playerstate"
	"Scardice-core/eventstore"
)

func TestCallbackRejectsTypedNilDependencies(t *testing.T) {
	var inbox *callbackTestInbox
	if _, err := NewCallbackService(CallbackConfig{
		Inbox: inbox, Store: &callbackTestStore{},
		Resolver: callbackTestResolver{},
		Host:     &callbackTestHost{}, WorkerID: "worker",
	}); !errors.Is(err, ErrCallbackUnavailable) {
		t.Fatalf("typed-nil callback dependency err=%v", err)
	}
	var clock *callbackFixedClock
	if collector := execution.NewMutationCollector(eventstore.EventFactory{Clock: clock}); collector == nil {
		t.Fatal("typed-nil collector clock returned nil collector")
	}
}

func TestCallbackRejectsLeaseShorterThanHeartbeatSafetyWindow(t *testing.T) {
	_, err := NewCallbackService(CallbackConfig{
		Inbox: &callbackTestInbox{}, Store: &callbackTestStore{},
		Resolver: callbackTestResolver{},
		Host:     &callbackTestHost{}, WorkerID: "worker", LeaseDuration: 29 * time.Millisecond,
	})
	if !errors.Is(err, ErrCallbackLease) {
		t.Fatalf("short callback lease err=%v", err)
	}
}

func TestCallbackProcessOneClaimsAndMarksBeforeHost(t *testing.T) {
	inbox := newCallbackTestInbox()
	store := &callbackTestStore{}
	host := &callbackTestHost{inbox: inbox}
	service := newCallbackTestService(t, inbox, store, host)
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
func TestCallbackPublishesBeforeReleasingCommitFenceAndNotifiesAfter(t *testing.T) {
	inbox := newCallbackTestInbox()
	fence := &callbackTestFence{}
	published := false
	afterCommitCalls := 0
	store := &callbackTestStore{onCommit: func() {
		if !fence.locked || published || afterCommitCalls != 0 {
			t.Fatalf("commit fence locked=%v published=%v after=%d", fence.locked, published, afterCommitCalls)
		}
	}}
	host := &callbackTestHost{inbox: inbox, fn: func(context.Context, CallbackRequest, *playerstate.LocalOverlay, *execution.MutationCollector) (CallbackResult, error) {
		return CallbackResult{
			CommitFence: fence,
			PublishCommitted: func() {
				if !fence.locked {
					t.Fatal("committed ownership published outside commit fence")
				}
				published = true
			},
			AfterCommit: func() {
				if fence.locked || !published {
					t.Fatalf("after-commit fence=%v published=%v", fence.locked, published)
				}
				afterCommitCalls++
			},
		}, nil
	}}
	service := newCallbackTestService(t, inbox, store, host)

	if _, err := service.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !published || afterCommitCalls != 1 || len(store.commits) != 1 || fence.lockCalls != 1 || fence.unlockCalls != 1 || fence.locked {
		t.Fatalf("published=%v after=%d commits=%d fence=%#v", published, afterCommitCalls, len(store.commits), fence)
	}
}

func TestCallbackMalformedPayloadNoHost(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{"empty", nil},
		{"truncated", []byte(`{"endpointId":`)},
		{"non-object", []byte(`[]`)},
		{"null", []byte(`null`)},
		{"empty envelope", []byte(`{}`)},
		{"unknown field", []byte(`{"unexpected":true}`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inbox := newCallbackTestInbox()
			inbox.lease.Update.Payload = test.payload
			store := &callbackTestStore{}
			host := &callbackTestHost{inbox: inbox}
			service := newCallbackTestService(t, inbox, store, host)
			summary, err := service.ProcessOne(context.Background())
			if !errors.Is(err, ErrCallbackPayload) || summary.Status != eventstore.InboxStatusFailed {
				t.Fatalf("malformed summary=%+v err=%v", summary, err)
			}
			if host.called || len(store.commits) != 0 {
				t.Fatal("malformed payload reached host or commit")
			}
			if len(inbox.updates) != 1 || inbox.updates[0].Status != eventstore.InboxStatusFailed {
				t.Fatalf("updates=%#v", inbox.updates)
			}
		})
	}
}

func TestCallbackPayloadMetadataMismatchNoHost(t *testing.T) {
	tests := []struct {
		name    string
		payload string
	}{
		{
			name:    "endpoint",
			payload: `{"endpointId":"other-endpoint","generation":1,"desiredVersion":1,"message":{"kind":1,"conversationKind":2,"sender":"user","conversation":"group","platform":"test"},"contentDigest":"AQ==","status":"pending"}`,
		},
		{
			name:    "digest",
			payload: `{"endpointId":"endpoint","generation":1,"desiredVersion":1,"message":{"kind":1,"conversationKind":2,"sender":"user","conversation":"group","platform":"test"},"contentDigest":"Ag==","status":"pending"}`,
		},
		{
			name:    "duplicate envelope field",
			payload: `{"endpointId":"endpoint","generation":1,"desiredVersion":1,"message":{"kind":1,"conversationKind":2,"sender":"user","conversation":"group","platform":"test"},"contentDigest":"AQ==","status":"pending","status":"pending"}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inbox := newCallbackTestInbox()
			host := &callbackTestHost{inbox: inbox}
			inbox.lease.Update.Payload = []byte(test.payload)
			service := newCallbackTestService(t, inbox, &callbackTestStore{}, host)
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
	service := newCallbackTestService(t, inbox, store, host)
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
	service := newCallbackTestService(t, inbox, &callbackTestStore{}, host)
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
	host := &callbackTestHost{inbox: inbox, fn: func(_ context.Context, _ CallbackRequest, overlay *playerstate.LocalOverlay, collector *execution.MutationCollector) (CallbackResult, error) {
		overlay.Set("$t临时", "local")
		if err := collector.AddStream(eventstore.StreamID{AggregateType: "player", AggregateID: "player-1"}, 2, []eventstore.NewEvent{callbackEvent("player.changed", `{"name":"new"}`)}); err != nil {
			return CallbackResult{}, err
		}
		if err := collector.AddPluginKV(eventstore.PluginKVUpdate{ExtensionID: "plugin", Key: "key", Value: []byte("value")}); err != nil {
			return CallbackResult{}, err
		}
		if err := collector.AddEffect(eventstore.NewEffect{EffectID: "effect-1", EndpointID: "endpoint", Lane: "lane", EffectType: "send", RiskClass: eventstore.RiskPreDispatchRetryable, Status: eventstore.OutboxStatusPending, Payload: []byte("effect-payload")}); err != nil {
			return CallbackResult{}, err
		}
		if err := collector.AddSecretUpdate(eventstore.SecretUpdate{SecretRef: "attributes-secret", EndpointID: "attrs-1", AdapterID: "attributes", SecretVersion: 1, Value: []byte("attributes"), ValueSet: true}); err != nil {
			return CallbackResult{}, err
		}
		return CallbackResult{Workflow: &WorkflowResult{ID: "workflow-1", Event: callbackEvent(MessageWorkflowTerminatedEventType, `{"done":true}`)}}, nil
	}}
	service := newCallbackTestService(t, inbox, store, host)
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
	service := newCallbackTestService(t, inbox, store, &callbackTestHost{inbox: inbox})
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
	host := &callbackTestHost{inbox: inbox, fn: func(context.Context, CallbackRequest, *playerstate.LocalOverlay, *execution.MutationCollector) (CallbackResult, error) {
		return CallbackResult{Workflow: &WorkflowResult{ID: "bad/id", Event: callbackEvent(MessageWorkflowTerminatedEventType, `{}`)}}, nil
	}}
	service := newCallbackTestService(t, inbox, &callbackTestStore{}, host)
	if _, err := service.ProcessOne(context.Background()); !errors.Is(err, ErrCallbackWorkflow) {
		t.Fatalf("workflow err=%v", err)
	}
	if inbox.updates[len(inbox.updates)-1].Status != eventstore.InboxStatusAmbiguous {
		t.Fatalf("updates=%#v", inbox.updates)
	}
}

func TestCallbackCollectorRejectsOverlayIdentitiesAndMalformedEvents(t *testing.T) {
	collector := execution.NewMutationCollector(eventstore.EventFactory{}, execution.WithReservedStreamTypes(MessageWorkflowAggregateType))
	stream := eventstore.StreamID{AggregateType: "group", AggregateID: "group-1"}
	if err := execution.NewMutationCollector(eventstore.EventFactory{}).AddStream(eventstore.StreamID{AggregateType: "group", AggregateID: "duplicate-key"}, 0, []eventstore.NewEvent{callbackEvent("group.changed", `{"value":"$t","value":"ok"}`)}); !errors.Is(err, eventstore.ErrInvalidEvent) {
		t.Fatalf("duplicate-key event err=%v", err)
	}
	if err := execution.NewMutationCollector(eventstore.EventFactory{}).AddStream(eventstore.StreamID{AggregateType: "group", AggregateID: "trailing-value"}, 0, []eventstore.NewEvent{callbackEvent("group.changed", `{"value":"ok"} {"value":"later"}`)}); !errors.Is(err, eventstore.ErrInvalidEvent) {
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
		if err := execution.NewMutationCollector(eventstore.EventFactory{}).AddStream(eventstore.StreamID{AggregateType: "group", AggregateID: "metadata-" + field}, 0, []eventstore.NewEvent{event}); !errors.Is(err, eventstore.ErrInvalidEvent) {
			t.Fatalf("overlay metadata %s err=%v", field, err)
		}
	}
	for _, stream := range []eventstore.StreamID{
		{AggregateType: "$t-type", AggregateID: "group"},
		{AggregateType: "group", AggregateID: "$t-id"},
	} {
		if err := execution.NewMutationCollector(eventstore.EventFactory{}).AddStream(stream, 0, []eventstore.NewEvent{callbackEvent("group.changed", `{}`)}); !errors.Is(err, execution.ErrInvalidMutation) {
			t.Fatalf("overlay stream %#v err=%v", stream, err)
		}
	}
	event := callbackEvent("group.changed", `{}`)
	event.EventType = "$t-event"
	if err := execution.NewMutationCollector(eventstore.EventFactory{}).AddStream(eventstore.StreamID{AggregateType: "group", AggregateID: "event-type"}, 0, []eventstore.NewEvent{event}); !errors.Is(err, eventstore.ErrInvalidEvent) {
		t.Fatalf("overlay event type err=%v", err)
	}
	for name, payload := range map[string]string{
		"identity-field":  `{"groupId":"$t-group"}`,
		"identity-array":  `{"members":["$t-user"]}`,
		"key-field":       `{"key":"$t-key"}`,
		"reference-field": `{"authSecretRef":"$t-secret"}`,
		"reference-array": `{"refs":["$t-secret"]}`,
		"transient-key":   `{"attrs":{"$t-key":"value"}}`,
	} {
		if err := execution.NewMutationCollector(eventstore.EventFactory{}).AddStream(
			eventstore.StreamID{AggregateType: "group", AggregateID: "payload-" + name},
			0,
			[]eventstore.NewEvent{callbackEvent("group.changed", payload)},
		); !errors.Is(err, eventstore.ErrInvalidEvent) {
			t.Fatalf("overlay payload %s err=%v", name, err)
		}
	}
	if err := execution.NewMutationCollector(eventstore.EventFactory{}).AddStream(
		eventstore.StreamID{AggregateType: "group", AggregateID: "ordinary-text"},
		0,
		[]eventstore.NewEvent{callbackEvent("group.changed", `{"template":"{$t玩家_RAW}","value":"$t is durable text"}`)},
	); err != nil {
		t.Fatalf("ordinary durable payload text err=%v", err)
	}
	plugin := eventstore.PluginKVUpdate{ExtensionID: "plugin", Key: "key", Value: []byte("value")}
	for _, field := range []string{"ExtensionID", "Key"} {
		update := plugin
		if field == "ExtensionID" {
			update.ExtensionID = "$t-plugin"
		} else {
			update.Key = "$t-plugin-key"
		}
		if err := execution.NewMutationCollector(eventstore.EventFactory{}).AddPluginKV(update); !errors.Is(err, eventstore.ErrInvalidMetadata) {
			t.Fatalf("overlay plugin %s err=%v", field, err)
		}
	}
	effect := eventstore.NewEffect{EffectID: "effect", EndpointID: "endpoint", Lane: "lane", EffectType: "send", RiskClass: eventstore.RiskPreDispatchRetryable, Status: eventstore.OutboxStatusPending, Payload: []byte("{}")}
	for _, field := range []string{"EffectID", "EndpointID", "EffectType", "RiskClass", "Status", "AttemptID", "LeaseOwner", "ProviderMessageID", "ResultCode", "ErrorCode", "Resolution", "PrincipalID", "Reason"} {
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
		if err := execution.NewMutationCollector(eventstore.EventFactory{}).AddEffect(update); !errors.Is(err, eventstore.ErrInvalidMetadata) {
			t.Fatalf("overlay effect %s err=%v", field, err)
		}
	}
	if err := validateWorkflowResult(&WorkflowResult{ID: "$t-workflow", Event: callbackEvent(MessageWorkflowTerminatedEventType, `{}`)}); !errors.Is(err, ErrCallbackWorkflow) {
		t.Fatalf("overlay workflow id err=%v", err)
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
	host := &callbackTestHost{fn: func(ctx context.Context, _ CallbackRequest, _ *playerstate.LocalOverlay, _ *execution.MutationCollector) (CallbackResult, error) {
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
		Inbox: inbox, Store: store,
		Resolver: callbackTestResolver{},
		Host:     host, WorkerID: "worker", LeaseDuration: 30 * time.Millisecond,
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
	publicationCalls, afterCommitCalls := 0, 0
	host := &callbackTestHost{inbox: inbox, fn: func(context.Context, CallbackRequest, *playerstate.LocalOverlay, *execution.MutationCollector) (CallbackResult, error) {
		return CallbackResult{
			CommitFence: fence, PublishCommitted: func() { publicationCalls++ },
			AfterCommit: func() { afterCommitCalls++ },
		}, nil
	}}
	service := newCallbackTestService(t, inbox, store, host)
	if _, err := service.ProcessOne(context.Background()); !errors.Is(err, eventstore.ErrParticipantFailure) {
		t.Fatalf("commit err=%v", err)
	}
	if host.calls != 1 || len(inbox.updates) != 2 || inbox.updates[1].Status != eventstore.InboxStatusAmbiguous {
		t.Fatalf("host calls=%d updates=%#v", host.calls, inbox.updates)
	}
	if publicationCalls != 0 || afterCommitCalls != 0 || fence.lockCalls != 1 || fence.unlockCalls != 1 || fence.locked {
		t.Fatalf("failed commit published=%d after=%d fence=%#v", publicationCalls, afterCommitCalls, fence)
	}
	if _, err := service.ProcessOne(context.Background()); !errors.Is(err, eventstore.ErrNotFound) {
		t.Fatalf("ambiguous retry err=%v", err)
	}
	if host.calls != 1 || publicationCalls != 0 || afterCommitCalls != 0 || fence.lockCalls != 1 || fence.unlockCalls != 1 {
		t.Fatalf("retry reran host or hooks: host=%d published=%d after=%d fence=%#v", host.calls, publicationCalls, afterCommitCalls, fence)
	}
}

func TestMutationCollectorBatchAtomicityPreservesExplicitEffectSubject(t *testing.T) {
	collector := execution.NewMutationCollector(eventstore.EventFactory{})
	valid := eventstore.PluginKVUpdate{ExtensionID: "plugin", Key: "one", Value: []byte("value")}
	invalid := valid
	invalid.ExtensionID = "$t-plugin"
	if err := collector.AddPluginKVBatch([]eventstore.PluginKVUpdate{valid, invalid}); !errors.Is(err, eventstore.ErrInvalidMetadata) {
		t.Fatalf("batch err=%v", err)
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(work.PluginKVUpdates) != 0 {
		t.Fatalf("failed batch staged %#v", work.PluginKVUpdates)
	}
	effect := eventstore.NewEffect{EffectID: "effect", EndpointID: "endpoint", Lane: "lane", Subject: "group", EffectType: "send", RiskClass: eventstore.RiskPreDispatchRetryable, Status: eventstore.OutboxStatusPending, Payload: []byte("{}")}
	if err := collector.AddEffect(effect); err != nil {
		t.Fatal(err)
	}
	work, err = collector.UnitOfWork()
	if err != nil || len(work.Effects) != 1 || work.Effects[0].Subject != "group" {
		t.Fatalf("explicit effect subject=%#v err=%v", work.Effects, err)
	}
}
