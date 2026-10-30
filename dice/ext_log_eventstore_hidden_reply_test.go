package dice

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/groupstate"
	"Scardice-core/core/messageflow"
	"Scardice-core/core/playerstate"
	"Scardice-core/dice/service"
	"Scardice-core/eventstore"
)

func TestEventStoreHiddenRollArchivesGroupAndPrivateEffectsAtTerminalSuccess(t *testing.T) {
	ctx := context.Background()
	d, endpoint, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	endpoint.ProtocolType = "pureonebot"

	keys := groupCardSQLiteKeySource{}
	database, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{
		Type: "sqlite", DSN: filepath.Join(t.TempDir(), "hidden-roll.db"),
		KeySource: keys, DatabaseIdentity: "hidden-roll-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store := eventstore.NewStore(database, eventstore.WithKeySource(keys))
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "hidden-roll-test",
		IndexRootID: "card-index-v1", EncryptionRootIDs: []string{"card-root-v1"},
		SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	const groupID = "QQ-Group:90001"
	const sessionName = "hidden-roll-session"
	session, err := store.CreateStoryLog(ctx, d.BaseConfig.Name, groupID, sessionName)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetStoryLogState(ctx, eventstore.StoryLogState{
		DiceID: d.BaseConfig.Name, GroupID: groupID, SessionID: session.ID, Name: sessionName, On: true,
	}); err != nil {
		t.Fatal(err)
	}
	d.DurableStore = store
	d.LogRepository = service.NewEventStoreLogRepository(store, d.BaseConfig.Name)

	resolver := groupCardSQLiteResolver{snapshot: messageflow.EndpointSnapshot{
		EndpointID: adapterapi.EndpointID(endpoint.ID), AdapterKey: OnebotAdapterKey,
		DesiredState: "enabled", ObservedState: adapterapi.ObservedStateConnected,
		Capabilities: adapterapi.CapabilityOutbound,
		Actions:      adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage),
		IndexRootID:  "card-index-v1", IndexSigner: groupCardSQLiteIndexSigner{},
	}}
	outbound, err := messageflow.NewOutboundService(store, resolver, store, eventstore.UUIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	bridge := NewDurableOutboundBridge(outbound, resolver, eventstore.UUIDGenerator{})
	d.OutboundBridge = bridge
	sent := make(chan string, 4)
	d.ExtList = append(d.ExtList, &ExtInfo{Name: "hidden-roll-test-observer", OnMessageSend: func(_ *MsgContext, msg *Message, _ string) {
		sent <- msg.MessageType + ":" + msg.Message
	}})

	request := messageflow.CallbackRequest{
		InboxID: "inbox-hidden-roll", EndpointID: endpoint.ID,
		Message: adapterapi.InboundMessage{
			ProviderEventID: "provider-hidden-roll", MessageID: "incoming-hidden-roll",
			Kind: adapterapi.InboundKindMessage, ConversationKind: adapterapi.ConversationKindGroup,
			Platform: "QQ", Sender: "QQ:9001", Conversation: groupID, Target: endpoint.UserID, Text: ".rh 1d1",
		},
		Scope: messageflow.CallbackScope{DiceID: d.BaseConfig.Name, GroupID: groupID, UserID: "QQ:9001"},
		Group: groupstate.State{
			DiceID: d.BaseConfig.Name, GroupID: groupID, Active: true,
			DiceIDActive: map[string]bool{endpoint.UserID: true}, DiceIDExists: map[string]bool{endpoint.UserID: true},
			ActivatedExtensions: []string{"log"},
		}.CompatibilityView(),
		Player: playerstate.PlayerState{DiceID: d.BaseConfig.Name, GroupID: groupID, UserID: "QQ:9001", Name: "Tester"}.CompatibilityView(),
	}
	collector := messageflow.NewMutationCollector(eventstore.EventFactory{})
	callbackResult, err := NewDurableCallbackHost(d).HandleCallback(ctx, request, playerstate.NewLocalOverlay(), collector)
	if err != nil {
		t.Fatalf("DurableCallbackHost.HandleCallback(.rh): %v", err)
	}
	if callbackResult.Release != nil {
		defer callbackResult.Release()
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatalf("build hidden-roll callback UnitOfWork: %v", err)
	}
	if len(work.Effects) != 2 {
		t.Fatalf(".rh produced %d outbound effects, want real group acknowledgment and private roll", len(work.Effects))
	}
	intents := map[string]eventstore.StoryLogEntry{}
	for _, update := range work.LogUpdates {
		if update.Kind == "intent-put" {
			intents[update.Intent.EffectID] = update.Intent.Entry
		}
	}
	if len(intents) != 2 {
		t.Fatalf(".rh prepared %d archive intents for %d group/person effects, want one intent per successful effect", len(intents), len(work.Effects))
	}

	if callbackResult.CommitFence != nil && !callbackResult.CommitFence.TryLock() {
		t.Fatal("callback commit fence is busy")
	}
	if _, err := store.Commit(ctx, work); err != nil {
		if callbackResult.CommitFence != nil {
			callbackResult.CommitFence.Unlock()
		}
		t.Fatalf("commit hidden-roll callback: %v", err)
	}
	if callbackResult.AfterCommit != nil {
		callbackResult.AfterCommit()
	}
	if callbackResult.CommitFence != nil {
		callbackResult.CommitFence.Unlock()
	}

	outboundIDs := make(map[string]struct{}, len(work.Effects))
	for _, effect := range work.Effects {
		outboundIDs[effect.EffectID] = struct{}{}
	}
	bridge.mu.Lock()
	pending := make(map[string]outboundSuccessNotification, len(bridge.pending))
	for id, notification := range bridge.pending {
		pending[id] = notification
	}
	bridge.mu.Unlock()
	if len(pending) != 2 {
		t.Fatalf("prepared outbound notifications=%d, want two", len(pending))
	}
	type expectedOutbound struct {
		notification outboundSuccessNotification
		entry        eventstore.StoryLogEntry
		group        bool
		target       string
	}
	expected := make(map[string]expectedOutbound, len(pending))
	sawGroup, sawPerson := false, false
	for effectID, notification := range pending {
		entry, ok := intents[effectID]
		if !ok {
			t.Fatalf("outbound effect %q has no archive intent", effectID)
		}
		if _, ok := outboundIDs[effectID]; !ok {
			t.Fatalf("notification effect %q is absent from callback UnitOfWork", effectID)
		}
		if notification.callbackCtx == nil || notification.session != d.ImSession ||
			!notification.callbackCtx.skipLogArchive || notification.callbackCtx.CommandHideFlag != groupID ||
			notification.text == "" || notification.text != entry.Message {
			t.Fatalf("incomplete durable notification for %q: %#v", effectID, notification)
		}
		target := groupID
		if notification.group {
			sawGroup = true
			if notification.msg.GroupID != groupID {
				t.Fatalf("group effect %q target=%q, want %q", effectID, notification.msg.GroupID, groupID)
			}
		} else {
			sawPerson = true
			target = notification.msg.Sender.UserID
			if target != "QQ:9001" || notification.msg.GroupID != groupID {
				t.Fatalf("private effect %q target=%q source group=%q", effectID, target, notification.msg.GroupID)
			}
		}
		if entry.DiceID != d.BaseConfig.Name || entry.GroupID != groupID || entry.LogName != sessionName ||
			!entry.IsDice || entry.CommandID == 0 || entry.UniformID != endpoint.UserID {
			t.Fatalf("incomplete archive payload for %q: %#v", effectID, entry)
		}
		var commandInfo struct {
			Command string            `json:"cmd"`
			Hide    bool              `json:"hide"`
			Items   []json.RawMessage `json:"items"`
		}
		if err := json.Unmarshal(entry.CommandInfo, &commandInfo); err != nil ||
			commandInfo.Command != "roll" || !commandInfo.Hide || len(commandInfo.Items) == 0 {
			t.Fatalf("hidden-roll command info for %q = %s (decode error %v)", effectID, entry.CommandInfo, err)
		}
		expected[effectID] = expectedOutbound{notification: notification, entry: entry, group: notification.group, target: target}
	}
	if !sawGroup || !sawPerson || len(expected) != len(work.Effects) {
		t.Fatalf(".rh effects were not a complete group/person pair: group=%t person=%t expected=%d effects=%d", sawGroup, sawPerson, len(expected), len(work.Effects))
	}

	seen := make(map[string]struct{}, len(expected))
	for len(seen) < len(expected) {
		lease, err := store.ClaimOutbox(ctx, eventstore.OutboxClaimRequest{WorkerID: "hidden-roll-test", LeaseDuration: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		effectID := lease.Effect.EffectID
		outbound, ok := expected[effectID]
		if !ok {
			t.Fatalf("claimed unexpected outbound effect %q", effectID)
		}
		if _, duplicate := seen[effectID]; duplicate {
			t.Fatalf("claimed outbound effect %q more than once", effectID)
		}
		seen[effectID] = struct{}{}
		dispatched, err := store.MarkOutboxDispatched(ctx, eventstore.OutboxDispatchRequest{
			EffectID: effectID, WorkerID: lease.Effect.LeaseOwner, LeaseEpoch: lease.Effect.LeaseEpoch, AttemptID: lease.Effect.AttemptID,
		})
		if err != nil {
			t.Fatal(err)
		}
		providerID := "provider-" + effectID
		if _, err := store.CompleteOutbox(ctx, eventstore.OutboxCompletionRequest{
			EffectID: effectID, WorkerID: dispatched.Effect.LeaseOwner, LeaseEpoch: dispatched.Effect.LeaseEpoch,
			AttemptID: dispatched.Effect.AttemptID, Status: eventstore.OutboxStatusSucceeded,
			ResultCode: "success", ProviderMessageID: providerID,
		}); err != nil {
			t.Fatalf("terminal commit of %s: %v", effectID, err)
		}
		entries, err := store.GetStoryLogEntries(ctx, d.BaseConfig.Name, groupID, sessionName)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, entry := range entries {
			if entry.Message == outbound.entry.Message && entry.RawMsgID == providerID &&
				string(entry.CommandInfo) == string(outbound.entry.CommandInfo) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("successful terminal transaction %s did not archive its message and command info before async callback: entries=%#v", effectID, entries)
		}
		bridge.NotifyOutboundEffectResult(ctx, adapterapi.OutboundEffect{ID: adapterapi.EffectID(effectID)}, adapterapi.SucceededResult(providerID))
		wantType := "private"
		if outbound.group {
			wantType = "group"
		}
		select {
		case got := <-sent:
			if got != wantType+":"+outbound.notification.text {
				t.Fatalf("success callback for %s = %q, want %q target %q", effectID, got, wantType+":"+outbound.notification.text, outbound.target)
			}
		case <-time.After(time.Second):
			t.Fatalf("outbound success callback for %s was not delivered", effectID)
		}
	}
	entries, err := store.GetStoryLogEntries(ctx, d.BaseConfig.Name, groupID, sessionName)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range intents {
		found := false
		for _, stored := range entries {
			if stored.Message == entry.Message {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("hidden reply %q was not retained after asynchronous callback: %#v", entry.Message, entries)
		}
	}
}
