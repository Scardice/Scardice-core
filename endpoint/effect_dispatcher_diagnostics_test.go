package endpoint

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"Scardice-core/adapterapi"
	"Scardice-core/eventstore"
)

type dispatcherDiagnosticExecutor struct {
	result adapterapi.EffectResult
}

func (e dispatcherDiagnosticExecutor) ExecutePinned(context.Context, adapterapi.EndpointID, uint64, adapterapi.OutboundEffect) (adapterapi.EffectResult, error) {
	return e.result, nil
}

type dispatcherDiagnosticNotifier struct {
	received chan adapterapi.EffectResult
}

func (n dispatcherDiagnosticNotifier) NotifyOutboundEffectResult(_ context.Context, _ adapterapi.OutboundEffect, result adapterapi.EffectResult) {
	n.received <- result
}

func TestEffectDispatcherPersistsNotifiesAndLogsTerminalDiagnostics(t *testing.T) {
	target := adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9", Member: "QQ:8"}
	lane, err := adapterapi.NewLaneMetadata("endpoint-1", target, []byte("root"), 1)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Unix(3600, 0).UTC()
	effect := adapterapi.OutboundEffect{
		Version:              adapterapi.EffectVersionOne,
		ID:                   "effect-1",
		EndpointID:           "endpoint-1",
		OperationID:          "op-1",
		CorrelationID:        "corr-1",
		CausationID:          "cause-1",
		Lane:                 lane,
		Deadline:             deadline,
		Risk:                 adapterapi.EffectRiskHigh,
		RetryClass:           adapterapi.EffectRetryNonIdempotent,
		RequiredCapabilities: adapterapi.CapabilityOutbound | adapterapi.CapabilityActions,
		RequiredAction:       adapterapi.ActionKindSetGroupCard,
		Kind:                 adapterapi.EffectKindAction,
		Payload: adapterapi.EffectPayload{
			Kind:   adapterapi.EffectPayloadSetGroupCard,
			Target: target,
			Card:   "safe-card",
		},
	}
	plain, err := json.Marshal(effectWire{Effect: effect})
	if err != nil {
		t.Fatal(err)
	}
	store := &dispatcherTestStore{
		claimed: eventstore.OutboxLease{Effect: eventstore.NewEffect{
			EffectID:               "effect-1",
			Version:                1,
			EndpointID:             "endpoint-1",
			LeaseOwner:             "worker",
			LeaseEpoch:             1,
			AttemptID:              "attempt-1",
			PayloadCiphertext:      []byte("cipher"),
			PayloadNonce:           []byte("nonce"),
			PayloadEncryptionKeyID: "key",
			DeadlineAt:             deadline,
			RiskClass:              eventstore.RiskNonIdempotentAfterDispatch,
		}},
		marked: eventstore.OutboxLease{Effect: eventstore.NewEffect{
			EffectID:               "effect-1",
			Version:                2,
			EndpointID:             "endpoint-1",
			PayloadCiphertext:      []byte("cipher"),
			PayloadNonce:           []byte("nonce"),
			PayloadEncryptionKeyID: "key",
			RiskClass:              eventstore.RiskNonIdempotentAfterDispatch,
		}},
	}
	providerResult := adapterapi.TerminalResult(
		"onebot_provider_rejected",
		"action=set_group_card status=failed retcode=1200 category=provider rejected action",
	)
	notifier := dispatcherDiagnosticNotifier{received: make(chan adapterapi.EffectResult, 1)}
	logCore, observed := observer.New(zapcore.WarnLevel)
	restoreLogger := zap.ReplaceGlobals(zap.New(logCore))
	t.Cleanup(restoreLogger)

	dispatcher, err := NewEffectDispatcher(
		store,
		dispatcherTestDecrypt{plain: plain},
		dispatcherDiagnosticExecutor{result: providerResult},
		"worker",
		WithDispatcherIDGenerator(&dispatcherTestIDs{}),
		WithDispatcherClock(dispatcherTestClock{}),
		WithEffectResultNotifier(notifier),
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := dispatcher.DispatchOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Code != providerResult.Code || result.Message != providerResult.Message {
		t.Fatalf("returned terminal diagnostics = %#v, want %#v", result, providerResult)
	}

	select {
	case notified := <-notifier.received:
		if notified.Code != providerResult.Code || notified.Message != providerResult.Message {
			t.Fatalf("notified terminal diagnostics = %#v, want %#v", notified, providerResult)
		}
	case <-time.After(time.Second):
		t.Fatal("terminal result notifier was not called")
	}

	if len(store.work.Streams) != 1 || len(store.work.Streams[0].Events) != 1 {
		t.Fatalf("terminal stream work = %#v", store.work.Streams)
	}
	var terminalEvent struct {
		Status        string `json:"status"`
		ResultCode    string `json:"resultCode"`
		ResultMessage string `json:"resultMessage"`
	}
	if err := json.Unmarshal(store.work.Streams[0].Events[0].Payload, &terminalEvent); err != nil {
		t.Fatal(err)
	}
	if terminalEvent.Status != eventstore.OutboxStatusFailed || terminalEvent.ResultCode != providerResult.Code || terminalEvent.ResultMessage != providerResult.Message {
		t.Fatalf("terminal result event diagnostics = %#v, want code and message preserved", terminalEvent)
	}

	entries := observed.FilterMessageSnippet("outbound effect isolated").All()
	if len(entries) != 1 {
		t.Fatalf("failure log entries = %d, want 1: %#v", len(entries), observed.All())
	}
	fields := entries[0].ContextMap()
	if fields["result_code"] != providerResult.Code || fields["result_message"] != providerResult.Message {
		t.Fatalf("failure log diagnostics = %#v, want result_code=%q result_message=%q", fields, providerResult.Code, providerResult.Message)
	}
}
