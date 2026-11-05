package dice

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/messageflow"
	"Scardice-core/dice/service"
	endpointcore "Scardice-core/endpoint"
	"Scardice-core/eventstore"
)

func TestEventStoreHiddenRollArchivesGroupAndPrivateEffectsAtTerminalSuccess(t *testing.T) {
	ctx := context.Background()
	d, runtimeEndpoint, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	runtimeEndpoint.ProtocolType = "pureonebot"
	store, ok := d.DurableStore.(*eventstore.GORMStore)
	if !ok {
		t.Fatal("hidden-roll fixture requires the canonical GORM EventStore")
	}
	projected := projectCallbackTestEndpoint(t, d, store, runtimeEndpoint)
	runtimeEndpoint = projected.info

	const groupID = "QQ-Group:90001"
	const userID = "QQ:9001"
	const sessionName = "hidden-roll-session"
	session, err := store.CreateStoryLog(ctx, d.BaseConfig.Name, groupID, sessionName)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.SetStoryLogState(ctx, eventstore.StoryLogState{
		DiceID: d.BaseConfig.Name, GroupID: groupID, SessionID: session.ID, Name: sessionName, On: true,
	}); err != nil {
		t.Fatal(err)
	}
	d.LogRepository = service.NewEventStoreLogRepository(store, d.BaseConfig.Name)

	resolver := groupCardSQLiteResolver{snapshot: messageflow.EndpointSnapshot{
		EndpointID: projected.state.EndpointID, AdapterKey: OnebotAdapterKey,
		DesiredState: "enabled", ObservedState: adapterapi.ObservedStateConnected,
		Capabilities: adapterapi.CapabilityOutbound,
		Actions:      adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage),
	}}
	ids := &canonicalFixtureIDs{prefix: canonicalFixtureLabel(t, "hidden-roll-outbound")}
	outbound, err := messageflow.NewOutboundService(store, resolver, ids)
	if err != nil {
		t.Fatal(err)
	}
	bridge := NewDurableOutboundBridge(outbound, resolver, ids, newBridgeTestNotificationOwner(t))
	d.OutboundBridge = bridge
	type hookObservation struct {
		messageType, text string
		groupID, playerID string
		hideFlag          string
		skipLogArchive    bool
	}
	sent := make(chan hookObservation, 4)
	d.RegisterExtension(&ExtInfo{Name: "hidden-roll-test-observer", OnMessageSend: func(hookCtx *MsgContext, msg *Message, _ string) {
		observation := hookObservation{
			messageType: msg.MessageType, text: msg.Message,
			hideFlag: hookCtx.CommandHideFlag, skipLogArchive: hookCtx.skipLogArchive,
		}
		if hookCtx.Group != nil {
			observation.groupID = hookCtx.Group.GroupID()
		}
		if hookCtx.Player != nil {
			observation.playerID = hookCtx.Player.UserID()
		}
		sent <- observation
	}})

	seedMessage := &Message{
		Platform: "QQ", MessageType: "group", GroupID: groupID, GroupName: "Hidden Roll Group",
		Sender: SenderBase{UserID: userID, Nickname: "Tester"},
	}
	withCanonicalTestMessageContext(t, d, runtimeEndpoint, seedMessage, "hidden-roll-seed", func(root *MsgContext) error {
		if err := root.Group.SetGroupName(seedMessage.GroupName); err != nil {
			return err
		}
		if err := root.Group.SetActivation(runtimeEndpoint.UserID, true, true); err != nil {
			return err
		}
		return root.Group.SetExtension("log", true)
	})

	inbound, err := messageflow.NewInboundService(store)
	if err != nil {
		t.Fatal(err)
	}
	callback, err := messageflow.NewCallbackService(messageflow.CallbackConfig{
		Inbox: store, Store: store,
		Resolver: NewDurableCallbackScopeResolver(d), Host: NewDurableCallbackHost(d),
		WorkerID: "hidden-roll-callback-worker",
	})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := inbound.HandleInbound(ctx, endpointcore.FencedInbound{
		EndpointID: projected.state.EndpointID, Generation: projected.state.Generation,
		DesiredVersion: projected.state.DesiredVersion,
		Message: adapterapi.InboundMessage{
			ProviderEventID: "provider-hidden-roll", MessageID: "incoming-hidden-roll",
			Kind: adapterapi.InboundKindMessage, ConversationKind: adapterapi.ConversationKindGroup,
			Platform: "QQ", Sender: userID, Conversation: groupID, Target: runtimeEndpoint.UserID,
			Text: ".rh 1d1", OccurredAt: time.Unix(3, 0).UTC(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Outcome != adapterapi.IngressAccepted || receipt.InboxID == "" {
		t.Fatalf("hidden-roll ingress receipt = %#v", receipt)
	}
	summary, err := callback.ProcessOne(ctx)
	if err != nil {
		t.Fatalf("process hidden roll: %v", err)
	}
	if summary.InboxID != receipt.InboxID || summary.Status != eventstore.InboxStatusConfirmedConsumed {
		t.Fatalf("hidden-roll callback summary = %#v", summary)
	}

	bridge.mu.Lock()
	pending := make(map[string]outboundSuccessNotification, len(bridge.pending))
	for id, notification := range bridge.pending {
		pending[id] = notification
	}
	bridge.mu.Unlock()
	if len(pending) != 2 {
		t.Fatalf(".rh prepared %d durable outbound notifications, want group acknowledgment and private roll", len(pending))
	}
	sawGroup, sawPerson := false, false
	for effectID, notification := range pending {
		if notification.dice != d || notification.session != d.ImSession ||
			notification.endpoint == nil || notification.endpoint.ID != runtimeEndpoint.ID ||
			notification.sourceGroupID != groupID || notification.sourcePlayerID != userID ||
			!notification.skipLogArchive || notification.commandHideFlag != groupID ||
			notification.text == "" {
			t.Fatalf("incomplete durable notification for %q: %#v", effectID, notification)
		}
		if notification.group {
			sawGroup = true
			if notification.msg.GroupID != groupID {
				t.Fatalf("group effect %q target=%q, want %q", effectID, notification.msg.GroupID, groupID)
			}
		} else {
			sawPerson = true
			if notification.msg.Sender.UserID != userID || notification.msg.GroupID != groupID {
				t.Fatalf("private effect %q target=%q source group=%q", effectID, notification.msg.Sender.UserID, notification.msg.GroupID)
			}
		}
	}
	if !sawGroup || !sawPerson {
		t.Fatalf(".rh effects were not a complete group/person pair: group=%t person=%t", sawGroup, sawPerson)
	}

	seen := make(map[string]struct{}, len(pending))
	for len(seen) < len(pending) {
		lease, claimErr := store.ClaimOutbox(ctx, eventstore.OutboxClaimRequest{
			WorkerID: "hidden-roll-test", LeaseDuration: time.Minute,
		})
		if claimErr != nil {
			t.Fatal(claimErr)
		}
		effectID := lease.Effect.EffectID
		notification, exists := pending[effectID]
		if !exists {
			t.Fatalf("claimed unexpected outbound effect %q", effectID)
		}
		if _, duplicate := seen[effectID]; duplicate {
			t.Fatalf("claimed outbound effect %q more than once", effectID)
		}
		seen[effectID] = struct{}{}
		dispatched, dispatchErr := store.MarkOutboxDispatched(ctx, eventstore.OutboxDispatchRequest{
			EffectID: effectID, WorkerID: lease.Effect.LeaseOwner, LeaseEpoch: lease.Effect.LeaseEpoch,
			AttemptID: lease.Effect.AttemptID,
		})
		if dispatchErr != nil {
			t.Fatal(dispatchErr)
		}
		providerID := "provider-" + effectID
		if _, completionErr := store.CompleteOutbox(ctx, eventstore.OutboxCompletionRequest{
			EffectID: effectID, WorkerID: dispatched.Effect.LeaseOwner, LeaseEpoch: dispatched.Effect.LeaseEpoch,
			AttemptID: dispatched.Effect.AttemptID, Status: eventstore.OutboxStatusSucceeded,
			ResultCode: "success", ProviderMessageID: providerID,
		}); completionErr != nil {
			t.Fatalf("terminal commit of %s: %v", effectID, completionErr)
		}
		entries, entriesErr := store.GetStoryLogEntries(ctx, d.BaseConfig.Name, groupID, sessionName)
		if entriesErr != nil {
			t.Fatal(entriesErr)
		}
		found := false
		for _, entry := range entries {
			if entry.Message != notification.text || entry.RawMsgID != providerID {
				continue
			}
			if entry.DiceID != d.BaseConfig.Name || entry.GroupID != groupID || entry.LogName != sessionName ||
				!entry.IsDice || entry.CommandID == 0 || entry.UniformID != runtimeEndpoint.UserID {
				t.Fatalf("incomplete archive payload for %q: %#v", effectID, entry)
			}
			var commandInfo struct {
				Command string            `json:"cmd"`
				Hide    bool              `json:"hide"`
				Items   []json.RawMessage `json:"items"`
			}
			if decodeErr := json.Unmarshal(entry.CommandInfo, &commandInfo); decodeErr != nil ||
				commandInfo.Command != "roll" || !commandInfo.Hide || len(commandInfo.Items) == 0 {
				t.Fatalf("hidden-roll command info for %q = %s (decode error %v)", effectID, entry.CommandInfo, decodeErr)
			}
			found = true
			break
		}
		if !found {
			t.Fatalf("successful terminal transaction %s did not archive %q: entries=%#v", effectID, notification.text, entries)
		}
		lane, laneErr := adapterapi.NewLaneMetadata(notification.expectedEndpoint, notification.expectedTarget, 1)
		if laneErr != nil {
			t.Fatal(laneErr)
		}
		completed := adapterapi.OutboundEffect{
			Version: adapterapi.EffectVersionOne, ID: adapterapi.EffectID(effectID), EndpointID: notification.expectedEndpoint,
			OperationID: "hidden-roll-operation", CorrelationID: "hidden-roll-correlation", CausationID: "hidden-roll-causation",
			Lane: lane, Deadline: time.Now().Add(time.Minute), Risk: adapterapi.EffectRiskNormal,
			RetryClass: adapterapi.EffectRetryNonIdempotent, RequiredCapabilities: adapterapi.CapabilityOutbound,
			RequiredAction: adapterapi.ActionKindSendMessage, Kind: adapterapi.EffectKindMessage,
			Payload: adapterapi.EffectPayload{Kind: notification.expectedKind, Target: notification.expectedTarget, Text: notification.text},
		}
		bridge.NotifyOutboundEffectResult(ctx, completed, adapterapi.SucceededResult(providerID))
		wantType := "private"
		if notification.group {
			wantType = "group"
		}
		select {
		case got := <-sent:
			if got.messageType != wantType || got.text != notification.text ||
				got.groupID != groupID || got.playerID != userID ||
				got.hideFlag != groupID || !got.skipLogArchive {
				t.Fatalf("success callback for %s = %#v, want %s:%q with fresh source %s/%s", effectID, got, wantType, notification.text, groupID, userID)
			}
		case <-time.After(time.Second):
			t.Fatalf("outbound success callback for %s was not delivered", effectID)
		}
	}
}
