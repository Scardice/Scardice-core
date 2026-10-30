package dice

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/groupstate"
	"Scardice-core/core/messageflow"
	"Scardice-core/core/playerstate"
	"Scardice-core/dice/service"
	endpointcore "Scardice-core/endpoint"
	"Scardice-core/eventstore"
)

// stored stands in for the highest sequence found in the log's stored entries.
// Reading it costs a pass over the whole encrypted log, so the tests also count
// how often it is asked for.
type storedSeq struct {
	value int64
	calls int
}

func (s *storedSeq) read() (int64, error) {
	s.calls++
	return s.value, nil
}

func seqMessage(seq int64) *Message { return &Message{Seq: seq, RawID: seq} }

func TestDetectLogGapAdoptsBaselineForLogsThatHaveNone(t *testing.T) {
	group := &GroupInfo{}
	state := GroupLogState{ID: 7, Name: "run", On: true}
	stored := &storedSeq{value: 5}

	span, adopt := detectLogGap(group, state, seqMessage(100), stored.read)
	if span.missing != 0 || adopt != 99 {
		t.Fatalf("first message: span=%+v adopt=%d, want no gap and baseline 99", span, adopt)
	}
	if stored.calls != 0 {
		t.Fatal("a log without a baseline must not trust stored sequences: they may predate a pause")
	}
	// Once persisted the baseline is passed back in, and measuring starts from it.
	state.BaselineSeq = adopt
	if span, _ := detectLogGap(group, state, seqMessage(101), stored.read); span.missing != 0 {
		t.Fatalf("consecutive message reported a gap: %+v", span)
	}
	span, adopt = detectLogGap(group, state, seqMessage(110), stored.read)
	if span.fromSeq != 101 || span.toSeq != 110 || span.missing != 8 || adopt != 0 {
		t.Fatalf("gap = %+v adopt=%d, want 101..110 missing 8", span, adopt)
	}
}

func TestDetectLogGapAfterRestartUsesPersistedBaselineOnce(t *testing.T) {
	group := &GroupInfo{} // a fresh process knows nothing in memory
	state := GroupLogState{ID: 7, Name: "run", On: true, BaselineSeq: 99}
	stored := &storedSeq{value: 105}

	span, adopt := detectLogGap(group, state, seqMessage(120), stored.read)
	if span.fromSeq != 105 || span.missing != 14 || adopt != 0 {
		t.Fatalf("gap after restart = %+v adopt=%d, want 105..120 missing 14", span, adopt)
	}
	if span, _ := detectLogGap(group, state, seqMessage(121), stored.read); span.missing != 0 {
		t.Fatalf("message after the gap reported another: %+v", span)
	}
	if stored.calls != 1 {
		t.Fatalf("stored sequence read %d times, want once per process", stored.calls)
	}
}

func TestDetectLogGapIgnoresMessagesBeforeTheLogResumed(t *testing.T) {
	group := &GroupInfo{}
	stored := &storedSeq{}
	state := GroupLogState{ID: 7, Name: "run", On: true, BaselineSeq: 90}
	detectLogGap(group, state, seqMessage(300), stored.read)

	// The log is paused for a long while, then switched on again by message 500.
	state.BaselineSeq = 500
	if span, _ := detectLogGap(group, state, seqMessage(501), stored.read); span.missing != 0 {
		t.Fatalf("messages from the paused period were treated as a gap: %+v", span)
	}
	span, _ := detectLogGap(group, state, seqMessage(505), stored.read)
	if span.fromSeq != 501 || span.missing != 3 {
		t.Fatalf("gap after resuming = %+v, want 501..505 missing 3", span)
	}
}

func TestDetectLogGapDoesNotReachIntoAnEarlierLog(t *testing.T) {
	group := &GroupInfo{}
	stored := &storedSeq{}
	detectLogGap(group, GroupLogState{ID: 7, Name: "old", On: true, BaselineSeq: 90}, seqMessage(300), stored.read)

	fresh := GroupLogState{ID: 8, Name: "new", On: true}
	if span, adopt := detectLogGap(group, fresh, seqMessage(900), stored.read); span.missing != 0 || adopt != 899 {
		t.Fatalf("a new log inherited the previous one's position: span=%+v adopt=%d", span, adopt)
	}
}

func TestDetectLogGapDiscountsTheBotsOwnMessages(t *testing.T) {
	group := &GroupInfo{}
	state := GroupLogState{ID: 7, Name: "run", On: true, BaselineSeq: 9}
	stored := &storedSeq{value: 10}
	detectLogGap(group, state, seqMessage(10), stored.read)

	group.noteLogSelfSent()
	group.noteLogSelfSent()
	// 11 and 12 were the bot's own replies, 13 is missing, 14 is this message.
	span, _ := detectLogGap(group, state, seqMessage(14), stored.read)
	if span.fromSeq != 10 || span.toSeq != 14 || span.missing != 1 {
		t.Fatalf("gap = %+v, want 10..14 missing 1", span)
	}
}

func TestDetectLogGapNeverMovesBackwards(t *testing.T) {
	group := &GroupInfo{}
	state := GroupLogState{ID: 7, Name: "run", On: true, BaselineSeq: 19}
	stored := &storedSeq{}
	detectLogGap(group, state, seqMessage(20), stored.read)

	// A late delivery or a recovered message is older than what is known.
	if span, _ := detectLogGap(group, state, seqMessage(18), stored.read); span.missing != 0 {
		t.Fatalf("an older message reported a gap: %+v", span)
	}
	span, _ := detectLogGap(group, state, seqMessage(22), stored.read)
	if span.fromSeq != 20 || span.missing != 1 {
		t.Fatalf("gap = %+v, want 20..22 missing 1", span)
	}
}

func TestDetectLogGapNeedsASequence(t *testing.T) {
	group := &GroupInfo{}
	stored := &storedSeq{}
	span, adopt := detectLogGap(group, GroupLogState{ID: 7, Name: "run", On: true}, &Message{}, stored.read)
	if span.missing != 0 || adopt != 0 || stored.calls != 0 {
		t.Fatalf("a message without a sequence changed state: span=%+v adopt=%d reads=%d", span, adopt, stored.calls)
	}
}

func TestLogSequenceSurvivesCallbackGroupReconstruction(t *testing.T) {
	d, _, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	scope := messageflow.CallbackScope{DiceID: d.BaseConfig.Name, GroupID: "QQ-Group:321", UserID: "QQ:123"}
	state := GroupLogState{ID: 7, Name: "run", On: true, BaselineSeq: 100}
	stored := &storedSeq{value: 100}
	first := compatibilityGroupFromState(d, groupstate.State{}, playerstate.PlayerState{}, scope)
	d.ImSession.ServiceAtNew.Store(scope.GroupID, first)
	detectLogGap(first, state, seqMessage(101), stored.read)
	first.noteLogSelfSent()
	second := compatibilityGroupFromState(d, groupstate.State{}, playerstate.PlayerState{}, scope)
	span, _ := detectLogGap(second, state, seqMessage(103), stored.read)
	if span.missing != 0 || stored.calls != 1 {
		t.Fatalf("callback rebuilt runtime baseline: gap=%+v repository reads=%d", span, stored.calls)
	}
	// A delayed send notification holding the prior view updates the same tracker.
	first.noteLogSelfSent()
	if span, _ := detectLogGap(second, state, seqMessage(105), stored.read); span.missing != 0 {
		t.Fatalf("old callback view lost self-message accounting: %+v", span)
	}
}

type replayTestPort struct {
	h            *durableOBHarness
	messages     []adapterapi.InboundMessage
	calls, reads int
	backpressure bool
	beforePoll   func()
}

func (p *replayTestPort) Query(_ context.Context, r adapterapi.QueryRequest) (adapterapi.QueryResult, error) {
	if r.Kind != adapterapi.QueryKindGroupHistory || r.Group != obTestGroupID || r.Limit > 1000 {
		return adapterapi.QueryResult{}, errors.New("wrong history request")
	}
	return adapterapi.QueryResult{History: slices.Clone(p.messages)}, nil
}
func (p *replayTestPort) SubmitInbound(ctx context.Context, id adapterapi.EndpointID, m adapterapi.InboundMessage) (adapterapi.IngressReceipt, error) {
	p.calls++
	if p.backpressure && p.calls == 1 {
		return adapterapi.IngressReceipt{}, messageflow.ErrIngressBackpressure
	}
	return p.h.inbound.HandleInbound(ctx, endpointcore.FencedInbound{EndpointID: id, Generation: 1, DesiredVersion: 1, Message: m})
}
func (p *replayTestPort) InboxStatuses(ctx context.Context, ids []string) (map[string]string, error) {
	p.reads++
	if p.beforePoll != nil {
		p.beforePoll()
	}
	// A real worker consumes one row per observation; the task must wait for all.
	if _, err := p.h.callback.ProcessOne(ctx); err != nil && !errors.Is(err, eventstore.ErrNotFound) {
		return nil, err
	}
	return p.h.store.InboxStatuses(ctx, ids)
}

func TestLogGapReplayUsesDurableInboxAndWaitsForCommit(t *testing.T) {
	for _, scenario := range []struct {
		count     int
		preloaded bool
	}{{5, false}, {6, false}, {6, true}} {
		count := scenario.count
		t.Run(fmt.Sprintf("%d/preloaded=%t", count, scenario.preloaded), func(t *testing.T) {
			h := newDurableOBHarness(t)
			h.dice.LogRepository = service.NewEventStoreLogRepository(h.store, h.dice.BaseConfig.Name)
			log, err := h.store.CreateStoryLog(h.ctx, h.dice.BaseConfig.Name, obTestGroupID, "gap")
			if err != nil {
				t.Fatal(err)
			}
			if err := h.store.SetStoryLogState(h.ctx, eventstore.StoryLogState{DiceID: h.dice.BaseConfig.Name, GroupID: obTestGroupID, SessionID: log.ID, Name: "gap", On: true, BaselineSeq: 100}); err != nil {
				t.Fatal(err)
			}
			port := &replayTestPort{h: h, backpressure: true}
			for i := range count + 1 {
				id := fmt.Sprintf("gap-%d-%d", count, i)
				sender := adapterapi.PrincipalID(obTestUserID)
				if i == count {
					sender = adapterapi.PrincipalID(h.endpoint.UserID)
				}
				port.messages = append(port.messages, adapterapi.InboundMessage{ProviderEventID: adapterapi.ProviderEventID(id), MessageID: adapterapi.MessageID(id), Kind: adapterapi.InboundKindMessage, ConversationKind: adapterapi.ConversationKindGroup, Conversation: obTestGroupID, Platform: "QQ", Sender: sender, SenderName: "Tester", Target: h.endpoint.UserID, Text: ".r 1d1", Sequence: int64(101 + i), OccurredAt: time.Unix(1234567890, 0).UTC()})
			}
			if scenario.preloaded {
				for _, m := range port.messages[:count] {
					m.History = adapterapi.InboundHistoryRecordOnly
					if _, err := h.inbound.HandleInbound(h.ctx, endpointcore.FencedInbound{EndpointID: adapterapi.EndpointID(h.endpoint.ID), Generation: 1, DesiredVersion: 1, Message: m}); err != nil {
						t.Fatal(err)
					}
				}
			}
			h.dice.ProviderQuery = port
			if count > 5 {
				port.beforePoll = func() {
					if len(h.outboundEffects()) != 0 {
						t.Fatal("completion report sent before all inbox rows reached terminal state")
					}
				}
			}
			h.dice.InboundReplay = port
			task := logGapFillTask{dice: h.dice, endpoint: h.endpoint, group: &GroupInfo{GroupID: obTestGroupID}, logID: log.ID, logName: "gap", fromSeq: 100, toSeq: int64(102 + count), gap: int64(count)}
			task.run()
			entries, err := h.store.GetStoryLogEntries(h.ctx, h.dice.BaseConfig.Name, obTestGroupID, "gap")
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != count {
				t.Fatalf("task returned before history committed: entries=%d want=%d submissions=%d polls=%d", len(entries), count, port.calls, port.reads)
			}
			for i, e := range entries {
				if e.Seq == nil || *e.Seq != int64(101+i) || e.UniformID == h.endpoint.UserID {
					t.Fatalf("wrong recovered order or self replay: %+v", entries)
				}
			}
			effects := h.outboundEffects()
			want := count
			if count > 5 {
				want = 1
			}
			if len(effects) != want {
				t.Fatalf("effects=%d want=%d (execute versus record-only)", len(effects), want)
			}
			if port.calls != count+1 || port.reads < count {
				t.Fatalf("did not retry backpressure or await commit: calls=%d reads=%d", port.calls, port.reads)
			}
			// Repeating the same fetched history cannot execute commands or append twice.
			port.beforePoll = nil
			task.run()
			again, err := h.store.GetStoryLogEntries(h.ctx, h.dice.BaseConfig.Name, obTestGroupID, "gap")
			if err != nil || len(again) != count {
				t.Fatalf("duplicate replay: entries=%d err=%v", len(again), err)
			}
			if count <= 5 && len(h.outboundEffects()) != want {
				t.Fatal("duplicate history executed again")
			}
		})
	}
}

func TestHistoryLaneDoesNotHoldLiveMessagesBehindBackfill(t *testing.T) {
	h := newDurableOBHarness(t)
	h.dice.LogRepository = service.NewEventStoreLogRepository(h.store, h.dice.BaseConfig.Name)
	log, err := h.store.CreateStoryLog(h.ctx, h.dice.BaseConfig.Name, obTestGroupID, "lane-history")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.SetStoryLogState(h.ctx, eventstore.StoryLogState{DiceID: h.dice.BaseConfig.Name, GroupID: obTestGroupID, SessionID: log.ID, Name: "lane-history", On: true, BaselineSeq: 90}); err != nil {
		t.Fatal(err)
	}
	submit := func(id string, mode adapterapi.InboundHistory, seq int64) string {
		t.Helper()
		msg := adapterapi.InboundMessage{ProviderEventID: adapterapi.ProviderEventID(id), MessageID: adapterapi.MessageID(id), Kind: adapterapi.InboundKindMessage, ConversationKind: adapterapi.ConversationKindGroup, Platform: "QQ", Sender: obTestUserID, Conversation: obTestGroupID, Target: h.endpoint.UserID, Text: ".r 1d1", OccurredAt: time.Unix(1234567890, 0).UTC(), Sequence: seq, History: mode}
		receipt, err := h.inbound.HandleInbound(h.ctx, endpointcore.FencedInbound{EndpointID: adapterapi.EndpointID(h.endpoint.ID), Generation: 1, DesiredVersion: 1, Message: msg})
		if err != nil {
			t.Fatal(err)
		}
		return receipt.InboxID
	}
	first := submit("history-lane-first", adapterapi.InboundHistoryRecordOnly, 101)
	live := submit("history-lane-live", adapterapi.InboundHistoryNone, 110)
	second := submit("history-lane-second", adapterapi.InboundHistoryRecordOnly, 102)
	for _, want := range []string{first, live, second} {
		result, err := h.callback.ProcessOne(h.ctx)
		if err != nil || result.InboxID != want || result.Status != eventstore.InboxStatusConfirmedConsumed {
			t.Fatalf("claim=%+v err=%v want=%s", result, err, want)
		}
	}
	if got := len(h.outboundEffects()); got != 1 {
		t.Fatalf("live command replies=%d want=1", got)
	}
}

type historyCommitProbe struct {
	store   *eventstore.GORMStore
	inboxID string
	done    chan error
}

func (p *historyCommitProbe) Query(ctx context.Context, request adapterapi.QueryRequest) (adapterapi.QueryResult, error) {
	statuses, err := p.store.InboxStatuses(ctx, []string{p.inboxID})
	if err == nil && statuses[p.inboxID] != eventstore.InboxStatusConfirmedConsumed {
		err = fmt.Errorf("history fetch began before trigger commit: %s", statuses[p.inboxID])
	}
	p.done <- err
	return adapterapi.QueryResult{}, err
}

func TestLogGapFetchStartsOnlyAfterTriggerCommits(t *testing.T) {
	h := newDurableOBHarness(t)
	h.dice.LogRepository = service.NewEventStoreLogRepository(h.store, h.dice.BaseConfig.Name)
	log, err := h.store.CreateStoryLog(h.ctx, h.dice.BaseConfig.Name, obTestGroupID, "after-commit")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.SetStoryLogState(h.ctx, eventstore.StoryLogState{DiceID: h.dice.BaseConfig.Name, GroupID: obTestGroupID, SessionID: log.ID, Name: "after-commit", On: true, BaselineSeq: 100}); err != nil {
		t.Fatal(err)
	}
	msg := adapterapi.InboundMessage{ProviderEventID: "gap-trigger", MessageID: "gap-trigger", Kind: adapterapi.InboundKindMessage, ConversationKind: adapterapi.ConversationKindGroup, Platform: "QQ", Sender: obTestUserID, Conversation: obTestGroupID, Target: h.endpoint.UserID, Text: "after gap", OccurredAt: time.Now().UTC(), Sequence: 103}
	receipt, err := h.inbound.HandleInbound(h.ctx, endpointcore.FencedInbound{EndpointID: adapterapi.EndpointID(h.endpoint.ID), Generation: 1, DesiredVersion: 1, Message: msg})
	if err != nil {
		t.Fatal(err)
	}
	probe := &historyCommitProbe{store: h.store, inboxID: receipt.InboxID, done: make(chan error, 1)}
	h.dice.ProviderQuery = probe
	h.dice.InboundReplay = &replayTestPort{h: h}
	if _, err := h.callback.ProcessOne(h.ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-probe.done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("committed sequence gap did not start recovery")
	}
}

func TestManualLogCheckSkipsArchivedMessagesBeforeChoosingMode(t *testing.T) {
	h := newDurableOBHarness(t)
	h.dice.LogRepository = service.NewEventStoreLogRepository(h.store, h.dice.BaseConfig.Name)
	log, err := h.store.CreateStoryLog(h.ctx, h.dice.BaseConfig.Name, obTestGroupID, "manual")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.SetStoryLogState(h.ctx, eventstore.StoryLogState{DiceID: h.dice.BaseConfig.Name, GroupID: obTestGroupID, SessionID: log.ID, Name: "manual", On: true, BaselineSeq: 100}); err != nil {
		t.Fatal(err)
	}
	port := &replayTestPort{h: h}
	for i := range 7 {
		id := fmt.Sprintf("manual-%d", i)
		m := adapterapi.InboundMessage{ProviderEventID: adapterapi.ProviderEventID(id), MessageID: adapterapi.MessageID(id), Kind: adapterapi.InboundKindMessage, ConversationKind: adapterapi.ConversationKindGroup, Platform: "QQ", Sender: obTestUserID, Conversation: obTestGroupID, Target: h.endpoint.UserID, Text: ".r 1d1", OccurredAt: time.Unix(1234567890, 0).UTC(), Sequence: int64(101 + i)}
		port.messages = append(port.messages, m)
		if i < 6 {
			if err := h.store.AppendStoryLogEntry(h.ctx, eventstore.StoryLogEntry{DiceID: h.dice.BaseConfig.Name, GroupID: obTestGroupID, LogName: "manual", RawMsgID: id, Time: 1234567890, Message: m.Text, Seq: new(int64(101 + i))}); err != nil {
				t.Fatal(err)
			}
		}
	}
	h.dice.ProviderQuery, h.dice.InboundReplay = port, port
	ctx := &MsgContext{Dice: h.dice, EndPoint: h.endpoint, Group: &GroupInfo{GroupID: obTestGroupID}, PrivilegeLevel: 100}
	task, err := newLogGapCheck(ctx, 100, 108)
	if err != nil {
		t.Fatal(err)
	}
	task.run()
	entries, err := h.store.GetStoryLogEntries(h.ctx, h.dice.BaseConfig.Name, obTestGroupID, "manual")
	if err != nil || len(entries) != 7 {
		t.Fatalf("archived entries=%d err=%v", len(entries), err)
	}
	if port.calls != 1 || len(h.outboundEffects()) != 2 {
		t.Fatalf("archived commands replayed or one missing command not executed: submissions=%d effects=%d", port.calls, len(h.outboundEffects()))
	}
}

func TestManualLogCheckRequiresMasterAndActiveBaseline(t *testing.T) {
	h := newDurableOBHarness(t)
	h.dice.LogRepository = service.NewEventStoreLogRepository(h.store, h.dice.BaseConfig.Name)
	log, err := h.store.CreateStoryLog(h.ctx, h.dice.BaseConfig.Name, obTestGroupID, "manual-guards")
	if err != nil {
		t.Fatal(err)
	}
	h.dice.ProviderQuery = &replayTestPort{h: h}
	h.dice.InboundReplay = &replayTestPort{h: h}
	for _, tc := range []struct {
		name          string
		privilege     int
		on            bool
		after, before int64
	}{
		{"not-master", 50, true, 100, 110},
		{"paused", 100, false, 100, 110},
		{"before-baseline", 100, true, 99, 110},
		{"reversed", 100, true, 110, 100},
		{"unbounded", 100, true, 100, 1102},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := h.store.SetStoryLogState(h.ctx, eventstore.StoryLogState{DiceID: h.dice.BaseConfig.Name, GroupID: obTestGroupID, SessionID: log.ID, Name: "manual-guards", On: tc.on, BaselineSeq: 100}); err != nil {
				t.Fatal(err)
			}
			ctx := &MsgContext{Dice: h.dice, EndPoint: h.endpoint, Group: &GroupInfo{GroupID: obTestGroupID}, PrivilegeLevel: tc.privilege}
			if _, err := newLogGapCheck(ctx, tc.after, tc.before); err == nil {
				t.Fatal("unsafe manual recovery accepted")
			}
		})
	}
}

func TestHistoryCallbackRecordOnlyDoesNotExecute(t *testing.T) {
	for _, on := range []bool{true, false} {
		t.Run(strconv.FormatBool(on), func(t *testing.T) {
			h := newDurableOBHarness(t)
			h.dice.LogRepository = service.NewEventStoreLogRepository(h.store, h.dice.BaseConfig.Name)
			log, err := h.store.CreateStoryLog(h.ctx, h.dice.BaseConfig.Name, obTestGroupID, "recovered")
			if err != nil {
				t.Fatal(err)
			}
			err = h.store.SetStoryLogState(h.ctx, eventstore.StoryLogState{DiceID: h.dice.BaseConfig.Name, GroupID: obTestGroupID, SessionID: log.ID, Name: "recovered", On: on, BaselineSeq: 90})
			if err != nil {
				t.Fatal(err)
			}
			// Every append would normally issue a size reminder. RecordOnly must not.
			h.dice.Config.LogSizeNoticeEnable = true
			h.dice.Config.LogSizeNoticeCount = 1
			msg := adapterapi.InboundMessage{ProviderEventID: adapterapi.ProviderEventID("history-" + strconv.FormatBool(on)), MessageID: adapterapi.MessageID("history-" + strconv.FormatBool(on)), Kind: adapterapi.InboundKindMessage, ConversationKind: adapterapi.ConversationKindGroup, Platform: "QQ", Sender: "QQ:987654321", SenderName: "Recovered player", Conversation: obTestGroupID, Target: h.endpoint.UserID, Text: ".r 1d1", OccurredAt: time.Unix(1234567890, 0).UTC(), Sequence: 101, History: adapterapi.InboundHistoryRecordOnly}
			receipt, err := h.inbound.HandleInbound(h.ctx, endpointcore.FencedInbound{EndpointID: adapterapi.EndpointID(h.endpoint.ID), Generation: 1, DesiredVersion: 1, Message: msg})
			if err != nil {
				t.Fatal(err)
			}
			result, err := h.callback.ProcessOne(h.ctx)
			if err != nil || result.InboxID != receipt.InboxID || result.Status != eventstore.InboxStatusConfirmedConsumed {
				t.Fatalf("callback=%+v err=%v", result, err)
			}
			if effects := h.outboundEffects(); len(effects) != 0 {
				t.Fatalf("record-only executed or sent a reminder: %+v", effects)
			}
			player, err := playerstate.NewRepository(h.store).LoadPlayer(h.ctx, h.dice.BaseConfig.Name, obTestGroupID, string(msg.Sender))
			if err != nil {
				t.Fatal(err)
			}
			if player.Version != 0 {
				t.Fatalf("record-only created a player: %+v", player)
			}
			entries, err := h.store.GetStoryLogEntries(context.Background(), h.dice.BaseConfig.Name, obTestGroupID, "recovered")
			if err != nil {
				t.Fatal(err)
			}
			want := 0
			if on {
				want = 1
			}
			if len(entries) != want {
				t.Fatalf("entries=%+v want=%d", entries, want)
			}
			if on {
				e := entries[0]
				if e.Message != ".r 1d1" || e.Time != 1234567890 || e.Seq == nil || *e.Seq != 101 || e.Nickname != "Recovered player" || e.IsDice {
					t.Fatalf("wrong recovered entry: %+v", e)
				}
			}
		})
	}
}

func TestHistoryCallbackExecuteArchivesReplyAtOriginalTime(t *testing.T) {
	h := newDurableOBHarness(t)
	h.dice.LogRepository = service.NewEventStoreLogRepository(h.store, h.dice.BaseConfig.Name)
	log, err := h.store.CreateStoryLog(h.ctx, h.dice.BaseConfig.Name, obTestGroupID, "execute-history")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.SetStoryLogState(h.ctx, eventstore.StoryLogState{DiceID: h.dice.BaseConfig.Name, GroupID: obTestGroupID, SessionID: log.ID, Name: "execute-history", On: true, BaselineSeq: 90}); err != nil {
		t.Fatal(err)
	}
	msg := adapterapi.InboundMessage{ProviderEventID: "history-execute", MessageID: "history-execute", Kind: adapterapi.InboundKindMessage, ConversationKind: adapterapi.ConversationKindGroup, Platform: "QQ", Sender: obTestUserID, Conversation: obTestGroupID, Target: h.endpoint.UserID, Text: ".r 1d1", OccurredAt: time.Unix(1234567890, 0).UTC(), Sequence: 101, History: adapterapi.InboundHistoryExecute}
	if _, err := h.inbound.HandleInbound(h.ctx, endpointcore.FencedInbound{EndpointID: adapterapi.EndpointID(h.endpoint.ID), Generation: 1, DesiredVersion: 1, Message: msg}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.callback.ProcessOne(h.ctx); err != nil {
		t.Fatal(err)
	}
	lease, err := h.store.ClaimOutbox(h.ctx, eventstore.OutboxClaimRequest{WorkerID: "history-test", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	sent, err := h.store.MarkOutboxDispatched(h.ctx, eventstore.OutboxDispatchRequest{EffectID: lease.Effect.EffectID, WorkerID: lease.Effect.LeaseOwner, LeaseEpoch: lease.Effect.LeaseEpoch, AttemptID: lease.Effect.AttemptID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.CompleteOutbox(h.ctx, eventstore.OutboxCompletionRequest{EffectID: sent.Effect.EffectID, WorkerID: sent.Effect.LeaseOwner, LeaseEpoch: sent.Effect.LeaseEpoch, AttemptID: sent.Effect.AttemptID, Status: eventstore.OutboxStatusSucceeded, ResultCode: "success", ProviderMessageID: "history-reply"}); err != nil {
		t.Fatal(err)
	}
	entries, err := h.store.GetStoryLogEntries(h.ctx, h.dice.BaseConfig.Name, obTestGroupID, "execute-history")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].IsDice || !entries[1].IsDice || entries[0].Seq == nil || *entries[0].Seq != 101 || entries[1].Seq == nil || *entries[1].Seq != 101 || entries[0].Time != 1234567890 || entries[1].Time != 1234567890 {
		t.Fatalf("recovered command/reply order: %+v", entries)
	}
}

func TestHistoryCallbackExecuteDoesNotRunAfterLogPaused(t *testing.T) {
	h := newDurableOBHarness(t)
	h.dice.LogRepository = service.NewEventStoreLogRepository(h.store, h.dice.BaseConfig.Name)
	log, err := h.store.CreateStoryLog(h.ctx, h.dice.BaseConfig.Name, obTestGroupID, "paused-history")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.SetStoryLogState(h.ctx, eventstore.StoryLogState{DiceID: h.dice.BaseConfig.Name, GroupID: obTestGroupID, SessionID: log.ID, Name: "paused-history", On: false, BaselineSeq: 90}); err != nil {
		t.Fatal(err)
	}
	msg := adapterapi.InboundMessage{ProviderEventID: "paused-execute", MessageID: "paused-execute", Kind: adapterapi.InboundKindMessage, ConversationKind: adapterapi.ConversationKindGroup, Platform: "QQ", Sender: obTestUserID, Conversation: obTestGroupID, Target: h.endpoint.UserID, Text: ".r 1d1", OccurredAt: time.Unix(1234567890, 0).UTC(), Sequence: 101, History: adapterapi.InboundHistoryExecute}
	if _, err := h.inbound.HandleInbound(h.ctx, endpointcore.FencedInbound{EndpointID: adapterapi.EndpointID(h.endpoint.ID), Generation: 1, DesiredVersion: 1, Message: msg}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.callback.ProcessOne(h.ctx); err != nil {
		t.Fatal(err)
	}
	if effects := h.outboundEffects(); len(effects) != 0 {
		t.Fatalf("historical command executed after pause: %d effects", len(effects))
	}
}
