package dice

import (
	"errors"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/groupstate"
	"Scardice-core/core/messageflow"
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
	}}
	ids := &canonicalFixtureIDs{prefix: canonicalFixtureLabel(t, "durable-quit-outbound")}
	outbound, err := messageflow.NewOutboundService(harness.store, resolver, ids)
	if err != nil {
		t.Fatal(err)
	}
	harness.dice.OutboundBridge = NewDurableOutboundBridge(outbound, resolver, ids, newBridgeTestNotificationOwner(t))
}

func seedDurableQuitTarget(t *testing.T, harness *durableOBHarness) groupstate.State {
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
	return state
}

func TestDurableDismissCommitConflictKeepsTargetMembership(t *testing.T) {
	harness := newDurableOBHarness(t)
	enableDurableQuitForHarness(t, harness)
	state := seedDurableQuitTarget(t, harness)
	root := newCanonicalTestRoot(t, harness.dice, "dismiss-conflict")
	message := newGroupMsg(durableQuitTargetGroupID, obTestUserID, ".dismiss")
	messageContext, err := NewDomainMsgContext(
		root.Transaction, harness.dice, harness.dice.ImSession, harness.endpoint, message,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer messageContext.releaseExecutionState()
	messageContext.IsCurGroupBotOn = true
	messageContext.PrivilegeLevel = 100
	messageContext.CommandID = 21
	messageContext.CurrentCommand = "dismiss"
	result := harness.dice.executeDismissOperation(messageContext, message, durableQuitTargetGroupID)
	if !result.Matched || !result.Solved {
		t.Fatalf("dismiss result = %#v", result)
	}
	if messageContext.Group.DiceIDExists(harness.endpoint.UserID) {
		t.Fatal("dismiss was not visible inside the active domain transaction")
	}
	if err = root.Transaction.Finalize(harness.ctx); err != nil {
		t.Fatal(err)
	}
	work, err := root.Collector.UnitOfWork()
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
	persisted, err := groupstate.NewRepository(harness.store).Load(harness.ctx, harness.dice.BaseConfig.Name, durableQuitTargetGroupID)
	if err != nil {
		t.Fatal(err)
	}
	if !persisted.DiceIDExists[harness.endpoint.UserID] {
		t.Fatal("failed callback commit removed durable target membership")
	}
	if effects := harness.outboundEffects(); len(effects) != 0 {
		t.Fatalf("failed callback commit persisted effects: %#v", effects)
	}
}

func TestDurableMasterQuitPersistsCrossGroupMembershipRemoval(t *testing.T) {
	harness := newDurableOBHarness(t)
	enableDurableQuitForHarness(t, harness)
	seedDurableQuitTarget(t, harness)
	updateCanonicalTestConfig(t, harness.dice, func(config *Config) {
		config.DiceMasters = []string{obTestUserID}
	})
	harness.process(".master quitgroup " + durableQuitTargetGroupID)
	removed, err := groupstate.NewRepository(harness.store).Load(harness.ctx, harness.dice.BaseConfig.Name, durableQuitTargetGroupID)
	if err != nil {
		t.Fatal(err)
	}
	if removed.DiceIDExists[harness.endpoint.UserID] {
		t.Fatalf("committed master quit retained membership: %#v", removed.DiceIDExists)
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
