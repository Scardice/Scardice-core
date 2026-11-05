package dice

import (
	"context"
	"fmt"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/groupstate"
	"Scardice-core/core/playerstate"
	"Scardice-core/dice/service"
	endpointcore "Scardice-core/endpoint"
	"Scardice-core/eventstore"
)

const selfEventRaw = `{"post_type":"message_sent","message_type":"group","group_id":2002}`

func selfMessageInbound(account, conversation string, kind adapterapi.ConversationKind, id string, seq int64, text string, origin adapterapi.SelfMessageOrigin) adapterapi.InboundMessage {
	return adapterapi.InboundMessage{
		ProviderEventID: adapterapi.ProviderEventID("onebot-self-message-" + id), MessageID: adapterapi.MessageID(id),
		Kind: adapterapi.InboundKindSelfMessage, ConversationKind: kind, Platform: "QQ",
		Sender: adapterapi.PrincipalID(account), Conversation: adapterapi.ConversationID(conversation), Target: conversation,
		Text: text, Sequence: seq, OccurredAt: time.Unix(1234567000+seq, 0).UTC(), SenderName: "Dice", SelfOrigin: origin,
		AdapterEvent: &adapterapi.AdapterEvent{Protocol: "onebot11", Type: "message_sent", RawJSON: selfEventRaw},
	}
}

func (h *durableOBHarness) selfGroupMessage(id string, seq int64, text string, origin adapterapi.SelfMessageOrigin) adapterapi.InboundMessage {
	return selfMessageInbound(h.endpoint.UserID, obTestGroupID, adapterapi.ConversationKindGroup, id, seq, text, origin)
}

// enableLog opens a log named name in the fixture group, measuring sequences
// from baseline.
func (h *durableOBHarness) enableLog(name string, on bool, baseline int64) {
	h.t.Helper()
	h.dice.LogRepository = service.NewEventStoreLogRepository(h.store, h.dice.BaseConfig.Name)
	log, err := h.store.CreateStoryLog(h.ctx, h.dice.BaseConfig.Name, obTestGroupID, name)
	if err != nil {
		h.t.Fatal(err)
	}
	if err := h.store.SetStoryLogState(h.ctx, eventstore.StoryLogState{
		DiceID: h.dice.BaseConfig.Name, GroupID: obTestGroupID, SessionID: log.ID, Name: name, On: on, BaselineSeq: baseline,
	}); err != nil {
		h.t.Fatal(err)
	}
}

// deliver submits one inbound and runs its callback to commit.
func (h *durableOBHarness) deliver(message adapterapi.InboundMessage) adapterapi.IngressReceipt {
	h.t.Helper()
	receipt, err := h.inbound.HandleInbound(h.ctx, endpointcore.FencedInbound{
		EndpointID: h.fence.EndpointID, Generation: h.fence.Generation, DesiredVersion: h.fence.DesiredVersion, Message: message,
	})
	if err != nil {
		h.t.Fatal(err)
	}
	if receipt.Outcome == adapterapi.IngressDuplicate {
		return receipt
	}
	summary, err := h.callback.ProcessOne(h.ctx)
	if err != nil {
		h.t.Fatalf("process %q: %v", message.Text, err)
	}
	if summary.InboxID != receipt.InboxID || summary.Status != eventstore.InboxStatusConfirmedConsumed {
		h.t.Fatalf("%q callback summary = %#v", message.Text, summary)
	}
	return receipt
}

func (h *durableOBHarness) logEntries(name string) []eventstore.StoryLogEntry {
	h.t.Helper()
	entries, err := h.store.GetStoryLogEntries(h.ctx, h.dice.BaseConfig.Name, obTestGroupID, name)
	if err != nil {
		h.t.Fatal(err)
	}
	return entries
}

// completeNextOutbound drives the oldest outbound effect to success, as the
// dispatcher does, answering with the provider message id.
func (h *durableOBHarness) completeNextOutbound(providerMessageID string) {
	h.t.Helper()
	lease, err := h.store.ClaimOutbox(h.ctx, eventstore.OutboxClaimRequest{WorkerID: "self-test", LeaseDuration: time.Minute})
	if err != nil {
		h.t.Fatal(err)
	}
	sent, err := h.store.MarkOutboxDispatched(h.ctx, eventstore.OutboxDispatchRequest{
		EffectID: lease.Effect.EffectID, WorkerID: lease.Effect.LeaseOwner, LeaseEpoch: lease.Effect.LeaseEpoch, AttemptID: lease.Effect.AttemptID,
	})
	if err != nil {
		h.t.Fatal(err)
	}
	if _, err := h.store.CompleteOutbox(h.ctx, eventstore.OutboxCompletionRequest{
		EffectID: sent.Effect.EffectID, WorkerID: sent.Effect.LeaseOwner, LeaseEpoch: sent.Effect.LeaseEpoch, AttemptID: sent.Effect.AttemptID,
		Status: eventstore.OutboxStatusSucceeded, ResultCode: "success", ProviderMessageID: providerMessageID,
	}); err != nil {
		h.t.Fatal(err)
	}
}

// A hand-typed message of the account is the dice's speech in the log: one
// entry under the provider's message id, at the provider's time and sequence,
// however often it is reported.
func TestManualSelfMessageIsArchivedOnceAsDiceSpeech(t *testing.T) {
	h := newDurableOBHarness(t)
	h.enableLog("manual", true, 100)

	typed := h.selfGroupMessage("m-105", 105, "我手动说的话", adapterapi.SelfMessageUnattributed)
	h.deliver(typed)
	entries := h.logEntries("manual")
	if len(entries) != 1 {
		t.Fatalf("entries = %#v, want one", entries)
	}
	e := entries[0]
	if !e.IsDice || e.Message != "我手动说的话" || e.RawMsgID != "m-105" || e.UniformID != h.endpoint.UserID ||
		e.Time != typed.OccurredAt.Unix() || e.Seq == nil || *e.Seq != 105 {
		t.Fatalf("entry = %#v, want the dice's own line with the provider's id, time and sequence", e)
	}

	// The same provider message arriving under another event identity (a history
	// copy) is still one entry.
	again := typed
	again.ProviderEventID = "history-copy-of-m-105"
	h.deliver(again)
	if got := h.logEntries("manual"); len(got) != 1 {
		t.Fatalf("a second report of m-105 left %d entries", len(got))
	}
	// A different message is its own entry.
	h.deliver(h.selfGroupMessage("m-106", 106, "又一句", adapterapi.SelfMessageUnattributed))
	if got := h.logEntries("manual"); len(got) != 2 {
		t.Fatalf("entries = %d, want 2", len(got))
	}
}

func TestSelfMessageIsNotArchivedWhenTheLogIsOffOrBeforeItsBaseline(t *testing.T) {
	h := newDurableOBHarness(t)
	h.enableLog("paused", false, 100)
	h.deliver(h.selfGroupMessage("p-1", 105, "paused", adapterapi.SelfMessageUnattributed))
	if got := h.logEntries("paused"); len(got) != 0 {
		t.Fatalf("a paused log recorded %#v", got)
	}

	h2 := newDurableOBHarness(t)
	h2.enableLog("running", true, 100)
	h2.deliver(h2.selfGroupMessage("b-1", 100, "before the log", adapterapi.SelfMessageUnattributed))
	h2.deliver(h2.selfGroupMessage("b-2", 90, "long before", adapterapi.SelfMessageUnattributed))
	if got := h2.logEntries("running"); len(got) != 0 {
		t.Fatalf("messages from before the log began were recorded: %#v", got)
	}
}

// A report of a message Core sent is only acknowledged: Core's own outbound
// state archives it.
func TestSelfMessageIssuedByCoreIsAcknowledgedNotArchived(t *testing.T) {
	h := newDurableOBHarness(t)
	h.enableLog("core", true, 100)
	h.deliver(h.selfGroupMessage("c-105", 105, "core reply", adapterapi.SelfMessageIssuedByCore))
	if got := h.logEntries("core"); len(got) != 0 {
		t.Fatalf("a Core-issued report was archived: %#v", got)
	}
}

// Whatever order the provider's report and Core's terminal commit land in, the
// log holds one entry for the reply, with Core's own content, time and position.
func TestCoreReplyAndItsReportLeaveOneIdenticalEntryInEitherOrder(t *testing.T) {
	type outcome struct {
		message string
		time    int64
		seq     int64
		isDice  bool
		raw     string
	}
	run := func(t *testing.T, reportFirst bool) []outcome {
		h := newDurableOBHarness(t)
		h.enableLog("reply", true, 100)
		h.processSelfTestCommand(t, 101)
		report := h.selfGroupMessage("reply-1", 102, "reported text of the reply", adapterapi.SelfMessageUnattributed)
		if reportFirst {
			h.deliver(report)
			h.completeNextOutbound("reply-1")
		} else {
			h.completeNextOutbound("reply-1")
			h.deliver(report)
		}
		var out []outcome
		for _, e := range h.logEntries("reply") {
			seq := int64(0)
			if e.Seq != nil {
				seq = *e.Seq
			}
			out = append(out, outcome{e.Message, e.Time, seq, e.IsDice, e.RawMsgID})
		}
		return out
	}
	first, second := run(t, true), run(t, false)
	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("entries: report first %#v, terminal first %#v, want the command and one reply each", first, second)
	}
	if first[1].message == "reported text of the reply" || !first[1].isDice || first[1].raw != "reply-1" {
		t.Fatalf("reply entry = %#v, want Core's own content under the provider id", first[1])
	}
	if first[0] != second[0] || first[1].message != second[1].message || first[1].seq != second[1].seq || first[1].raw != second[1].raw || first[1].isDice != second[1].isDice {
		t.Fatalf("order changed the log:\nreport first   %#v\nterminal first %#v", first, second)
	}
}

// processSelfTestCommand has a player run a command in the logged group.
func (h *durableOBHarness) processSelfTestCommand(t *testing.T, seq int64) {
	t.Helper()
	h.sequence++
	id := fmt.Sprintf("provider-self-cmd-%d", h.sequence)
	h.deliver(adapterapi.InboundMessage{
		ProviderEventID: adapterapi.ProviderEventID(id), MessageID: adapterapi.MessageID(id + "-message"),
		Kind: adapterapi.InboundKindMessage, ConversationKind: adapterapi.ConversationKindGroup, Platform: "QQ",
		Sender: adapterapi.PrincipalID(obTestUserID), Conversation: obTestGroupID, Target: h.endpoint.UserID,
		Text: ".r 1d1", Sequence: seq, OccurredAt: time.Unix(1234567890, 0).UTC(),
	})
}

// A command of the account's own is never run, and nothing replies to it.
func TestSelfMessageNeverRunsACommandOrCreatesAPlayer(t *testing.T) {
	for _, origin := range []adapterapi.SelfMessageOrigin{adapterapi.SelfMessageUnattributed, adapterapi.SelfMessageIssuedByCore} {
		t.Run(fmt.Sprint(origin), func(t *testing.T) {
			h := newDurableOBHarness(t)
			h.enableLog("quiet", true, 100)
			operations, effects := h.outboundRowsSinceSeed()
			h.deliver(h.selfGroupMessage("q-1", 101, ".r 1d1", origin))
			h.deliver(selfMessageInbound(h.endpoint.UserID, "QQ:1001", adapterapi.ConversationKindDirect, "q-2", 0, ".r 1d1", origin))
			afterOperations, afterEffects := h.outboundRowsSinceSeed()
			if afterOperations != operations || afterEffects != effects {
				t.Fatalf("a command of the account's own produced outbound work: operations %d→%d effects %d→%d", operations, afterOperations, effects, afterEffects)
			}
			repository := playerstate.NewRepository(h.store)
			for _, scope := range []struct{ group, user string }{
				{obTestGroupID, h.endpoint.UserID}, {"PG-QQ:1001", h.endpoint.UserID}, {"PG-QQ:1001", "QQ:1001"}, {"PG-" + h.endpoint.UserID, h.endpoint.UserID},
			} {
				player, err := repository.LoadPlayer(h.ctx, h.dice.BaseConfig.Name, scope.group, scope.user)
				if err != nil || player.Version != 0 {
					t.Fatalf("player %v = %#v err=%v, want none", scope, player, err)
				}
			}
			// No line was recorded for the command as if a user had said it.
			for _, e := range h.logEntries("quiet") {
				if !e.IsDice {
					t.Fatalf("a command of the account's own was logged as a user's: %#v", e)
				}
			}
		})
	}
}

// Message hooks and custom replies never see an own message; a plugin that
// subscribed to the raw adapter event still does, in the right conversation.
func TestSelfMessageReachesOnlyAdapterEventHooks(t *testing.T) {
	f := newEventFixture(t)
	counts := map[string]int{}
	var adapterCtx *MsgContext
	var adapterEvent *AdapterEventView
	f.dice.RegisterExtension(&ExtInfo{
		Name:               "self-probe",
		AdapterEventFilter: map[string]any{"events": "all"},
		CmdMap: CmdMapCls{"probe": &CmdItemInfo{Name: "probe", Solve: func(*MsgContext, *Message, *CmdArgs) CmdExecuteResult {
			counts["command"]++
			return CmdExecuteResult{Matched: true, Solved: true}
		}}},
		OnMessageReceived:    func(*MsgContext, *Message) { counts["received"]++ },
		OnNotCommandReceived: func(*MsgContext, *Message) { counts["not-command"]++ },
		OnCommandReceived:    func(*MsgContext, *Message, *CmdArgs) { counts["command-received"]++ },
		OnCommandOverride:    func(*MsgContext, *Message, *CmdArgs) bool { counts["override"]++; return false },
		OnMessageSend:        func(*MsgContext, *Message, string) { counts["send"]++ },
		OnAdapterEvent: func(ctx *MsgContext, event *AdapterEventView) {
			counts["adapter-event"]++
			adapterCtx, adapterEvent = ctx, event
		},
	})
	group := f.activeGroup("self-probe")
	const account = "QQ:3003"

	f.seedConversation(adapterapi.InboundMessage{ConversationKind: adapterapi.ConversationKindGroup, Conversation: "QQ-Group:2002", Sender: "QQ:1001"}, group, "seed-group")
	inbound := selfMessageInbound(account, "QQ-Group:2002", adapterapi.ConversationKindGroup, "e-1", 5, ".probe", adapterapi.SelfMessageUnattributed)
	if err := f.run(inbound, groupstate.State{}); err != nil {
		t.Fatal(err)
	}
	if counts["adapter-event"] != 1 || adapterCtx == nil || adapterCtx.Group == nil || adapterCtx.Group.GroupID() != "QQ-Group:2002" ||
		adapterCtx.Player != nil || adapterEvent == nil || adapterEvent.Type != "message_sent" || adapterEvent.RawJSON != selfEventRaw {
		t.Fatalf("group adapter hook: counts=%v ctx=%#v event=%#v", counts, adapterCtx, adapterEvent)
	}

	// A private message of the account runs hooks in the recipient's conversation.
	f.seedConversation(adapterapi.InboundMessage{ConversationKind: adapterapi.ConversationKindDirect, Sender: "QQ:1001"}, group, "seed-private")
	private := selfMessageInbound(account, "QQ:1001", adapterapi.ConversationKindDirect, "e-2", 0, ".probe", adapterapi.SelfMessageIssuedByCore)
	if err := f.run(private, groupstate.State{}); err != nil {
		t.Fatal(err)
	}
	if counts["adapter-event"] != 2 || adapterCtx == nil || adapterCtx.Group == nil || adapterCtx.Group.GroupID() != "PG-QQ:1001" ||
		adapterCtx.MessageType != "private" || !adapterCtx.IsPrivate {
		t.Fatalf("private adapter hook: counts=%v ctx=%#v", counts, adapterCtx)
	}
	delete(counts, "adapter-event")
	if len(counts) != 0 {
		t.Fatalf("an own message reached message hooks or commands: %v", counts)
	}
	if effects := f.prep.effects(); len(effects) != 0 {
		t.Fatalf("an own message caused %d outbound effects", len(effects))
	}
	for _, scope := range []struct{ group, user string }{{"QQ-Group:2002", account}, {"PG-QQ:1001", account}, {"PG-" + account, account}} {
		player, err := playerstate.NewRepository(f.store).LoadPlayer(context.Background(), f.dice.BaseConfig.Name, scope.group, scope.user)
		if err != nil || player.Version != 0 {
			t.Fatalf("player %v = %#v err=%v, want none", scope, player, err)
		}
	}
}

// Recovered history: an own message not yet archived is recorded, an archived
// one is skipped, a Core-issued one is skipped, and none is ever executed.
func TestSelfMessagesInRecoveredHistoryAreRecordedNeverExecuted(t *testing.T) {
	for _, mode := range []adapterapi.InboundHistory{adapterapi.InboundHistoryExecute, adapterapi.InboundHistoryRecordOnly} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			h := newDurableOBHarness(t)
			h.enableLog("history", true, 100)
			if err := h.store.AppendStoryLogEntry(h.ctx, eventstore.StoryLogEntry{
				DiceID: h.dice.BaseConfig.Name, GroupID: obTestGroupID, LogName: "history", Nickname: "Dice", IsDice: true,
				Message: "already archived", RawMsgID: "h-101", Time: 1234567101, Seq: new(int64(101)),
			}); err != nil {
				t.Fatal(err)
			}
			operations, effects := h.outboundRowsSinceSeed()
			for i, message := range []adapterapi.InboundMessage{
				h.selfGroupMessage("h-101", 101, ".r 1d1", adapterapi.SelfMessageUnattributed),
				h.selfGroupMessage("h-102", 102, ".r 1d1", adapterapi.SelfMessageUnattributed),
				h.selfGroupMessage("h-103", 103, "sent by Core", adapterapi.SelfMessageIssuedByCore),
			} {
				message.ProviderEventID = adapterapi.ProviderEventID(fmt.Sprintf("history-%d", i))
				message.History = mode
				h.deliver(message)
			}
			entries := h.logEntries("history")
			if len(entries) != 2 || entries[0].Message != "already archived" || entries[1].RawMsgID != "h-102" || !entries[1].IsDice || entries[1].Message != ".r 1d1" {
				t.Fatalf("entries = %#v, want the archived one kept and h-102 added once", entries)
			}
			afterOperations, afterEffects := h.outboundRowsSinceSeed()
			if afterOperations != operations || afterEffects != effects {
				t.Fatalf("recovered own message produced outbound work")
			}
		})
	}
}

// Gap recovery keeps the account's own messages (as own messages) instead of
// dropping them, and an ordinary message that merely names the account as its
// sender is still not replayed.
func TestLogGapReplayRecordsOwnMessagesAndSkipsArchivedOnes(t *testing.T) {
	h := newDurableOBHarness(t)
	h.dice.LogRepository = service.NewEventStoreLogRepository(h.store, h.dice.BaseConfig.Name)
	log, err := h.store.CreateStoryLog(h.ctx, h.dice.BaseConfig.Name, obTestGroupID, "gap-self")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.SetStoryLogState(h.ctx, eventstore.StoryLogState{DiceID: h.dice.BaseConfig.Name, GroupID: obTestGroupID, SessionID: log.ID, Name: "gap-self", On: true, BaselineSeq: 100}); err != nil {
		t.Fatal(err)
	}
	if err := h.store.AppendStoryLogEntry(h.ctx, eventstore.StoryLogEntry{
		DiceID: h.dice.BaseConfig.Name, GroupID: obTestGroupID, LogName: "gap-self", Nickname: "Dice", IsDice: true,
		Message: "archived reply", RawMsgID: "g-102", Time: 1234567102, Seq: new(int64(102)),
	}); err != nil {
		t.Fatal(err)
	}
	user := func(id string, seq int64) adapterapi.InboundMessage {
		return adapterapi.InboundMessage{
			ProviderEventID: adapterapi.ProviderEventID("onebot-message-" + id), MessageID: adapterapi.MessageID(id),
			Kind: adapterapi.InboundKindMessage, ConversationKind: adapterapi.ConversationKindGroup, Conversation: obTestGroupID,
			Platform: "QQ", Sender: obTestUserID, SenderName: "Tester", Target: h.endpoint.UserID, Text: "闲聊",
			Sequence: seq, OccurredAt: time.Unix(1234567890, 0).UTC(),
		}
	}
	port := &replayTestPort{h: h, messages: []adapterapi.InboundMessage{
		user("g-101", 101),
		h.selfGroupMessage("g-102", 102, "archived reply", adapterapi.SelfMessageIssuedByCore),
		h.selfGroupMessage("g-103", 103, "typed by hand", adapterapi.SelfMessageUnattributed),
		func() adapterapi.InboundMessage {
			stray := user("g-104", 104)
			stray.Sender = adapterapi.PrincipalID(h.endpoint.UserID)
			return stray
		}(),
	}}
	h.dice.ProviderQuery = port
	h.dice.InboundReplay = port
	task := logGapFillTask{
		dice: h.dice, endpoint: h.endpoint, groupID: obTestGroupID,
		runtime:      h.dice.ImSession.runtimeResources().Group(h.dice.BaseConfig.Name, obTestGroupID),
		invocationID: canonicalFixtureLabel(t, "self-replay-task"),
		logID:        log.ID, logName: "gap-self", fromSeq: 100, toSeq: 105, gap: 4,
	}
	task.run()
	entries := h.logEntries("gap-self")
	got := map[string]bool{}
	for _, e := range entries {
		got[e.RawMsgID] = true
	}
	if len(entries) != 3 || !got["g-101"] || !got["g-102"] || !got["g-103"] || got["g-104"] {
		t.Fatalf("entries = %#v, want g-101 (user), g-102 (kept once), g-103 (own, typed by hand); g-104 is not replayed", entries)
	}
	for _, e := range entries {
		if e.RawMsgID == "g-103" && (!e.IsDice || e.Message != "typed by hand") {
			t.Fatalf("recovered own message = %#v", e)
		}
	}
}
