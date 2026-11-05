package dice

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/execution"
	"Scardice-core/core/groupstate"
	"Scardice-core/core/messageflow"
	"Scardice-core/core/playerstate"
	"Scardice-core/eventstore"
)

type callbackProcessResult struct {
	summary messageflow.CallbackResultSummary
	err     error
}

func callbackCommandMessage(providerID, messageID, groupID, text string) adapterapi.InboundMessage {
	return adapterapi.InboundMessage{
		ProviderEventID:  adapterapi.ProviderEventID(providerID),
		MessageID:        adapterapi.MessageID(messageID),
		Kind:             adapterapi.InboundKindMessage,
		ConversationKind: adapterapi.ConversationKindGroup,
		Conversation:     adapterapi.ConversationID(groupID),
		Sender:           "QQ:1001",
		Text:             text,
	}
}

func awaitCallbackResult(t *testing.T, results <-chan callbackProcessResult) callbackProcessResult {
	t.Helper()
	select {
	case result := <-results:
		return result
	case <-time.After(5 * time.Second):
		t.Fatal("callback did not finish")
		return callbackProcessResult{}
	}
}

func TestDurableCallbacksForDifferentGroupsDoNotBlockEachOther(t *testing.T) {
	fixture := newEventFixture(t)
	const firstGroup = "QQ-Group:admission-one"
	const secondGroup = "QQ-Group:admission-two"
	firstEntered := make(chan struct{})
	secondEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(releaseFirst) })

	fixture.dice.CmdMap["increment"] = &CmdItemInfo{Name: "increment", Raw: true, Solve: func(ctx *MsgContext, _ *Message, _ *CmdArgs) CmdExecuteResult {
		switch ctx.Group.GroupID() {
		case firstGroup:
			close(firstEntered)
			<-releaseFirst
		case secondGroup:
			close(secondEntered)
		}
		if err := ctx.Group.SetDiceSideNum(ctx.Group.DiceSideNum() + 1); err != nil {
			ctx.setExecutionError(err)
		}
		return CmdExecuteResult{Matched: true, Solved: true}
	}}

	initialSides := make(map[string]int64, 2)
	for _, inbound := range []adapterapi.InboundMessage{
		callbackCommandMessage("admission-one", "admission-message-one", firstGroup, ".increment"),
		callbackCommandMessage("admission-two", "admission-message-two", secondGroup, ".increment"),
	} {
		receipt, err := fixture.enqueue(inbound, fixture.activeGroup())
		if err != nil || receipt.Outcome != adapterapi.IngressAccepted {
			t.Fatalf("enqueue %s = %#v, %v", inbound.Conversation, receipt, err)
		}
		state, err := groupstate.ReadProjected(context.Background(), fixture.store, fixture.dice.BaseConfig.Name, string(inbound.Conversation))
		if err != nil {
			t.Fatalf("read seeded group %s: %v", inbound.Conversation, err)
		}
		initialSides[string(inbound.Conversation)] = state.DiceSideNum
	}

	first := fixture.newCallbackService("admission-worker-one", fixture.host)
	second := fixture.newCallbackService("admission-worker-two", fixture.host)
	firstResults := make(chan callbackProcessResult, 1)
	secondResults := make(chan callbackProcessResult, 1)
	go func() {
		summary, err := first.ProcessOne(context.Background())
		firstResults <- callbackProcessResult{summary: summary, err: err}
	}()
	select {
	case <-firstEntered:
	case result := <-firstResults:
		t.Fatalf("first callback returned before entering command: %#v, %v", result.summary, result.err)
	case <-time.After(5 * time.Second):
		t.Fatal("first callback did not enter its command")
	}

	go func() {
		summary, err := second.ProcessOne(context.Background())
		secondResults <- callbackProcessResult{summary: summary, err: err}
	}()
	var secondResult callbackProcessResult
	select {
	case <-secondEntered:
		secondResult = awaitCallbackResult(t, secondResults)
	case secondResult = <-secondResults:
	case <-time.After(5 * time.Second):
		t.Fatal("second group was blocked by the first group's callback")
	}
	if secondResult.err != nil || secondResult.summary.Status != eventstore.InboxStatusConfirmedConsumed {
		t.Fatalf("second callback = %#v, %v", secondResult.summary, secondResult.err)
	}

	releaseOnce.Do(func() { close(releaseFirst) })
	firstResult := awaitCallbackResult(t, firstResults)
	if firstResult.err != nil || firstResult.summary.Status != eventstore.InboxStatusConfirmedConsumed {
		t.Fatalf("first callback = %#v, %v", firstResult.summary, firstResult.err)
	}
	for _, groupID := range []string{firstGroup, secondGroup} {
		state, err := groupstate.ReadProjected(context.Background(), fixture.store, fixture.dice.BaseConfig.Name, groupID)
		if err != nil || state.DiceSideNum != initialSides[groupID]+1 {
			t.Fatalf("group %s state = %#v, %v; want one committed increment from %d", groupID, state, err, initialSides[groupID])
		}
	}
}

type conflictAfterCallbackHost struct {
	delegate messageflow.CallbackHost
	store    *eventstore.GORMStore
	diceID   string
	groupID  string
	injected atomic.Bool
}

func (h *conflictAfterCallbackHost) HandleCallback(
	ctx context.Context,
	request messageflow.CallbackRequest,
	overlay *playerstate.LocalOverlay,
	collector *execution.MutationCollector,
) (messageflow.CallbackResult, error) {
	result, err := h.delegate.HandleCallback(ctx, request, overlay, collector)
	if err != nil || request.Scope.GroupID != h.groupID || !h.injected.CompareAndSwap(false, true) {
		return result, err
	}
	repository := groupstate.NewRepository(h.store)
	state, err := repository.Load(ctx, h.diceID, h.groupID)
	if err != nil {
		return messageflow.CallbackResult{}, err
	}
	_, err = repository.DecideAndAppend(ctx, state, state.Version, eventstore.Metadata{
		CommandID: "concurrent-group-write", CorrelationID: "concurrent-group-write",
		Producer: "dice/callback-admission-test", OccurredAt: time.Unix(2, 0).UTC(),
	}, groupstate.Command{Kind: groupstate.CommandName, GroupName: "concurrent-winner"})
	if err != nil {
		return messageflow.CallbackResult{}, err
	}
	return result, nil
}

func TestFailedCallbackCommitDoesNotLeakStateIntoAnotherGroup(t *testing.T) {
	fixture := newEventFixture(t)
	const conflictedGroup = "QQ-Group:failed-commit"
	const independentGroup = "QQ-Group:after-failed-commit"
	fixture.dice.CmdMap["setside"] = &CmdItemInfo{Name: "setside", Raw: true, Solve: func(ctx *MsgContext, _ *Message, _ *CmdArgs) CmdExecuteResult {
		if err := ctx.Group.SetDiceSideNum(77); err != nil {
			ctx.setExecutionError(err)
		}
		return CmdExecuteResult{Matched: true, Solved: true}
	}}

	failedInbound := callbackCommandMessage("failed-commit", "failed-commit-message", conflictedGroup, ".setside")
	receipt, err := fixture.enqueue(failedInbound, fixture.activeGroup())
	if err != nil || receipt.Outcome != adapterapi.IngressAccepted {
		t.Fatalf("enqueue conflicted callback = %#v, %v", receipt, err)
	}
	conflictingHost := &conflictAfterCallbackHost{
		delegate: fixture.host, store: fixture.store,
		diceID: fixture.dice.BaseConfig.Name, groupID: conflictedGroup,
	}
	failedService := fixture.newCallbackService("failed-commit-worker", conflictingHost)
	failedSummary, processErr := failedService.ProcessOne(context.Background())
	if processErr == nil || failedSummary.Status != eventstore.InboxStatusAmbiguous {
		t.Fatalf("conflicted callback = %#v, %v; want an ambiguous failed commit", failedSummary, processErr)
	}
	conflicted, err := groupstate.ReadProjected(context.Background(), fixture.store, fixture.dice.BaseConfig.Name, conflictedGroup)
	if err != nil {
		t.Fatalf("read conflicted group: %v", err)
	}
	if conflicted.DiceSideNum == 77 || conflicted.GroupName != "concurrent-winner" {
		t.Fatalf("failed callback leaked state: %#v", conflicted)
	}

	independentInbound := callbackCommandMessage("after-failed-commit", "after-failed-commit-message", independentGroup, ".setside")
	receipt, err = fixture.enqueue(independentInbound, fixture.activeGroup())
	if err != nil || receipt.Outcome != adapterapi.IngressAccepted {
		t.Fatalf("enqueue independent callback = %#v, %v", receipt, err)
	}
	independentService := fixture.newCallbackService("after-failed-commit-worker", fixture.host)
	independentSummary, err := independentService.ProcessOne(context.Background())
	if err != nil || independentSummary.Status != eventstore.InboxStatusConfirmedConsumed {
		t.Fatalf("independent callback = %#v, %v", independentSummary, err)
	}
	independent, err := groupstate.ReadProjected(context.Background(), fixture.store, fixture.dice.BaseConfig.Name, independentGroup)
	if err != nil || independent.DiceSideNum != 77 {
		t.Fatalf("independent state = %#v, %v; want committed side 77", independent, err)
	}
}

var _ messageflow.CallbackHost = (*conflictAfterCallbackHost)(nil)
