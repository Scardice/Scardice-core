package dice

import (
	"errors"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/groupstate"
	"Scardice-core/core/messageflow"
	"Scardice-core/core/playerstate"
	"Scardice-core/eventstore"
)

const durableQuitTargetGroupID = "QQ-Group:9302"

func enableDurableQuitForHarness(t *testing.T, harness *durableOBHarness) {
	t.Helper()
	resolver := groupCardSQLiteResolver{snapshot: messageflow.EndpointSnapshot{
		EndpointID: adapterapi.EndpointID(harness.endpoint.ID), AdapterKey: OnebotAdapterKey,
		DesiredState: "enabled", ObservedState: adapterapi.ObservedStateConnected,
		Capabilities: adapterapi.CapabilityOutbound | adapterapi.CapabilityActions,
		Actions: adapterapi.ActionSet(0).With(
			adapterapi.ActionKindSendMessage,
			adapterapi.ActionKindQuit,
		),
		IndexRootID: "card-index-v1", IndexSigner: groupCardSQLiteIndexSigner{},
	}}
	outbound, err := messageflow.NewOutboundService(harness.store, resolver, harness.store, eventstore.UUIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	harness.dice.OutboundBridge = NewDurableOutboundBridge(outbound, resolver, eventstore.UUIDGenerator{})
}

func seedDurableQuitTarget(t *testing.T, harness *durableOBHarness) (groupstate.State, *GroupInfo) {
	t.Helper()
	metadata := eventstore.Metadata{
		CommandID: "seed-durable-quit-target", CorrelationID: "seed-durable-quit-target",
		OccurredAt: time.Unix(20, 0).UTC(),
	}
	repository := groupstate.NewRepository(harness.store)
	if _, err := repository.AppendTyped(harness.ctx, harness.dice.BaseConfig.Name, durableQuitTargetGroupID, 0, metadata, []groupstate.TypedEvent{
		groupstate.NewGroupCreatedV1(harness.dice.BaseConfig.Name, durableQuitTargetGroupID, "Durable Quit Target", 20),
		groupstate.NewGroupActivationChangedV1(harness.endpoint.UserID, true, true),
	}); err != nil {
		t.Fatal(err)
	}
	state, err := repository.Load(harness.ctx, harness.dice.BaseConfig.Name, durableQuitTargetGroupID)
	if err != nil {
		t.Fatal(err)
	}
	group := compatibilityGroupFromState(harness.dice, state, playerstate.PlayerState{
		DiceID: harness.dice.BaseConfig.Name, GroupID: durableQuitTargetGroupID,
		UserID: obTestUserID, Name: "Quit Operator",
	}, messageflow.CallbackScope{
		DiceID: harness.dice.BaseConfig.Name, GroupID: durableQuitTargetGroupID, UserID: obTestUserID,
	})
	harness.dice.ImSession.ServiceAtNew.Store(durableQuitTargetGroupID, group)
	return state, group
}

func TestDurableDismissCommitConflictKeepsTargetMembership(t *testing.T) {
	harness := newDurableOBHarness(t)
	enableDurableQuitForHarness(t, harness)
	state, group := seedDurableQuitTarget(t, harness)
	collector := messageflow.NewMutationCollector(eventstore.EventFactory{})
	transaction, err := NewDurableCallbackTransaction(harness.store, collector)
	if err != nil {
		t.Fatal(err)
	}
	metadata := eventstore.Metadata{
		CommandID: "inbox-dismiss-conflict", CorrelationID: "inbox-dismiss-conflict",
		OccurredAt: time.Unix(21, 0).UTC(),
	}
	messageContext := &MsgContext{
		Dice: harness.dice, Session: harness.dice.ImSession, EndPoint: harness.endpoint,
		Group: group, MessageType: "group", IsCurGroupBotOn: true, PrivilegeLevel: 100,
		CommandID: 21, CurrentCommand: "dismiss", callbackTransaction: transaction, callbackMetadata: metadata,
	}
	message := newGroupMsg(durableQuitTargetGroupID, obTestUserID, ".dismiss")
	result := harness.dice.executeDismissOperation(messageContext, message, durableQuitTargetGroupID, group)
	if !result.Matched || !result.Solved {
		t.Fatalf("dismiss result = %#v", result)
	}
	if !group.DiceIDExistsMap.Exists(harness.endpoint.UserID) {
		t.Fatal("dismiss removed membership before callback commit")
	}
	if err = transaction.Finalize(harness.ctx); err != nil {
		t.Fatal(err)
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	conflictMetadata := eventstore.Metadata{
		CommandID: "conflict-durable-quit-target", CorrelationID: "conflict-durable-quit-target",
		OccurredAt: time.Unix(22, 0).UTC(),
	}
	if _, err = groupstate.NewRepository(harness.store).AppendTyped(harness.ctx, harness.dice.BaseConfig.Name, durableQuitTargetGroupID, state.Version, conflictMetadata, []groupstate.TypedEvent{
		groupstate.NewGroupNameChangedV1("Concurrent Target Name"),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = harness.store.Commit(harness.ctx, work); !errors.Is(err, eventstore.ErrConflict) {
		t.Fatalf("stale callback commit error = %v, want conflict", err)
	}
	if !group.DiceIDExistsMap.Exists(harness.endpoint.UserID) {
		t.Fatal("failed callback commit removed target membership")
	}
	if effects := harness.outboundEffects(); len(effects) != 0 {
		t.Fatalf("failed callback commit persisted effects: %#v", effects)
	}
}

func TestDurableMasterQuitPersistsCrossGroupMembershipRemoval(t *testing.T) {
	harness := newDurableOBHarness(t)
	enableDurableQuitForHarness(t, harness)
	_, targetGroup := seedDurableQuitTarget(t, harness)
	harness.dice.DiceMasters = []string{obTestUserID}

	groupRepository := groupstate.NewRepository(harness.store)
	sourceState, err := groupRepository.Load(harness.ctx, harness.dice.BaseConfig.Name, obTestGroupID)
	if err != nil {
		t.Fatal(err)
	}
	playerState, err := playerstate.NewRepository(harness.store).LoadPlayer(harness.ctx, harness.dice.BaseConfig.Name, obTestGroupID, obTestUserID)
	if err != nil {
		t.Fatal(err)
	}
	collector := messageflow.NewMutationCollector(eventstore.EventFactory{})
	request := messageflow.CallbackRequest{
		InboxID: "inbox-master-cross-group-quit", EndpointID: harness.endpoint.ID,
		Message: adapterapi.InboundMessage{
			ProviderEventID: "provider-master-cross-group-quit", MessageID: "message-master-cross-group-quit",
			Kind: adapterapi.InboundKindMessage, ConversationKind: adapterapi.ConversationKindGroup,
			Platform: "QQ", Sender: adapterapi.PrincipalID(obTestUserID), Conversation: adapterapi.ConversationID(obTestGroupID),
			Target: harness.endpoint.UserID, Text: ".master quitgroup " + durableQuitTargetGroupID,
			OccurredAt: time.Unix(23, 0).UTC(),
		},
		Scope: messageflow.CallbackScope{DiceID: harness.dice.BaseConfig.Name, GroupID: obTestGroupID, UserID: obTestUserID},
		Group: sourceState.CompatibilityView(), Player: playerState.CompatibilityView(),
	}
	callbackResult, err := NewDurableCallbackHost(harness.dice).HandleCallback(harness.ctx, request, playerstate.NewLocalOverlay(), collector)
	if err != nil {
		t.Fatal(err)
	}
	if callbackResult.Release != nil {
		defer callbackResult.Release()
	}
	if !targetGroup.DiceIDExistsMap.Exists(harness.endpoint.UserID) {
		t.Fatal("master quit removed cross-group membership before callback commit")
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	fenceLocked := false
	if callbackResult.CommitFence != nil {
		if !callbackResult.CommitFence.TryLock() {
			t.Fatal("callback commit fence was unexpectedly busy")
		}
		fenceLocked = true
		defer func() {
			if fenceLocked {
				callbackResult.CommitFence.Unlock()
			}
		}()
	}
	if _, err = harness.store.Commit(harness.ctx, work); err != nil {
		t.Fatal(err)
	}
	if callbackResult.AfterCommit != nil {
		callbackResult.AfterCommit()
	}
	if fenceLocked {
		callbackResult.CommitFence.Unlock()
		fenceLocked = false
	}
	if targetGroup.DiceIDExistsMap.Exists(harness.endpoint.UserID) {
		t.Fatal("committed master quit retained cross-group membership")
	}

	harness.reopen()
	restored, err := groupstate.NewRepository(harness.store).Load(harness.ctx, harness.dice.BaseConfig.Name, durableQuitTargetGroupID)
	if err != nil {
		t.Fatal(err)
	}
	if restored.DiceIDExists[harness.endpoint.UserID] {
		t.Fatalf("reopened target membership = %#v, want endpoint absent", restored.DiceIDExists)
	}
}
