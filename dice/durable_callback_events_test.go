package dice

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/groupstate"
	"Scardice-core/core/messageflow"
	"Scardice-core/core/playerstate"
	"Scardice-core/dice/events"
	"Scardice-core/endpoint"
	"Scardice-core/eventstore"
)

// recordingPreparer records every outbound effect a callback stages, so tests
// can assert on what Core decided to send without a provider.
type recordingPreparer struct {
	*bridgeTestSubmitter
	recMu    sync.Mutex
	prepared []adapterapi.OutboundEffect
}

func (p *recordingPreparer) Prepare(ctx context.Context, request messageflow.SubmitRequest) (messageflow.PreparedOutbound, error) {
	p.recMu.Lock()
	p.prepared = append(p.prepared, request.Effect)
	p.recMu.Unlock()
	return p.bridgeTestSubmitter.Prepare(ctx, request)
}

func (p *recordingPreparer) effects() []adapterapi.OutboundEffect {
	p.recMu.Lock()
	defer p.recMu.Unlock()
	return append([]adapterapi.OutboundEffect(nil), p.prepared...)
}

// answers returns the provider answers to requests, in staging order.
func (p *recordingPreparer) answers() []adapterapi.EffectPayload {
	var out []adapterapi.EffectPayload
	for _, effect := range p.effects() {
		if effect.Payload.Kind == adapterapi.EffectPayloadAnswerRequest {
			out = append(out, effect.Payload)
		}
	}
	return out
}

// texts returns the staged person/group messages, in staging order.
func (p *recordingPreparer) texts() []adapterapi.OutboundEffect {
	var out []adapterapi.OutboundEffect
	for _, effect := range p.effects() {
		if effect.Payload.Kind == adapterapi.EffectPayloadPersonText || effect.Payload.Kind == adapterapi.EffectPayloadGroupText {
			out = append(out, effect)
		}
	}
	return out
}

func (p *recordingPreparer) textContaining(fragment string) (adapterapi.OutboundEffect, bool) {
	for _, effect := range p.texts() {
		if strings.Contains(effect.Payload.Text, fragment) {
			return effect, true
		}
	}
	return adapterapi.OutboundEffect{}, false
}

type eventFixture struct {
	t        *testing.T
	dice     *Dice
	endpoint *EndPointInfo
	host     *DurableCallbackHost
	prep     *recordingPreparer
}

const (
	eventNoticeTarget = "QQ:9999"
	eventNoticeOption = ":only=invite,group,system"
)

func newEventFixture(t *testing.T) *eventFixture {
	t.Helper()
	instance, endpoint, _, cleanup := newExecuteNewTestDice(t)
	t.Cleanup(cleanup)
	instance.ExtList = nil
	instance.Config.MessageDelayRangeStart, instance.Config.MessageDelayRangeEnd = 0, 0
	endpoint.Platform, endpoint.ProtocolType, endpoint.Enable, endpoint.State = "QQ", "pureonebot", true, StateConnected

	database, err := eventstore.OpenDatabase(context.Background(), eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/events.db"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	store := eventstore.NewStore(database, eventstore.WithKeySource(compatKeySource{}))
	if err := store.SetReadiness(context.Background(), eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "event-callback-db", IndexRootID: "index-v1",
		EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32),
		TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	instance.DurableStore = store
	// The test Dice already runs a save loop for its non-durable manager; stop it
	// so the durable switch does not leak a second, uncancellable loop.
	instance.AttrsManager.Stop()
	if err := instance.AttrsManager.InitDurable(instance); err != nil {
		t.Fatalf("durable attributes: %v", err)
	}
	// Cleanups run last-in-first-out: the manager must flush before the store closes.
	t.Cleanup(instance.AttrsManager.Stop)

	prep := &recordingPreparer{bridgeTestSubmitter: &bridgeTestSubmitter{}}
	instance.OutboundBridge = NewDurableOutboundBridge(prep, bridgeTestResolver{snapshot: messageflow.EndpointSnapshot{
		EndpointID: adapterapi.EndpointID(endpoint.ID), AdapterKey: "pureonebot", DesiredState: "enabled",
		ObservedState: adapterapi.ObservedStateConnected,
		Capabilities:  adapterapi.CapabilityOutbound | adapterapi.CapabilityActions,
		Actions:       adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage, adapterapi.ActionKindAnswerRequest, adapterapi.ActionKindGroupInfoRefresh),
		IndexRootID:   "root-1",
		IndexSigner:   bridgeTestIndexSigner{root: []byte("01234567890123456789012345678901"), id: "root-1"},
	}}, eventstore.UUIDGenerator{})
	return &eventFixture{t: t, dice: instance, endpoint: endpoint, host: NewDurableCallbackHost(instance), prep: prep}
}

// notify routes notices of the given types to a private target.
func (f *eventFixture) notify() {
	f.dice.Config.NoticeIDs = []string{eventNoticeTarget + eventNoticeOption}
}

// run delivers one typed inbound through the real durable callback host.
func (f *eventFixture) run(inbound adapterapi.InboundMessage, group groupstate.State) error {
	f.t.Helper()
	inbound.Platform = "QQ"
	if inbound.OccurredAt.IsZero() {
		inbound.OccurredAt = time.Unix(1700000000, 0)
	}
	if inbound.ProviderEventID == "" {
		inbound.ProviderEventID = adapterapi.ProviderEventID("test-event")
	}
	// Without an endpoint projection the host derives the endpoint from Target,
	// which the real runtime sets to the conversation. Address the bot's account
	// so the fallback endpoint carries the bot's identity.
	inbound.Target = f.endpoint.UserID
	scope := messageflow.CallbackScope{DiceID: f.dice.BaseConfig.Name, UserID: string(inbound.Sender)}
	if inbound.ConversationKind == adapterapi.ConversationKindGroup {
		scope.GroupID = string(inbound.Conversation)
	} else {
		scope.GroupID = "PG-" + string(inbound.Sender)
	}
	group.DiceID, group.GroupID = f.dice.BaseConfig.Name, scope.GroupID
	request := messageflow.CallbackRequest{
		InboxID: "inbox-event", EndpointID: f.endpoint.ID, Message: inbound, Scope: scope,
		Group: group.CompatibilityView(),
	}
	result, err := f.host.HandleCallback(context.Background(), request, playerstate.NewLocalOverlay(), messageflow.NewMutationCollector(eventstore.EventFactory{}))
	if result.Release != nil {
		result.Release()
	}
	return err
}

func (f *eventFixture) activeGroup(extensions ...string) groupstate.State {
	return groupstate.State{
		Active:              true,
		DiceIDActive:        map[string]bool{f.endpoint.UserID: true},
		DiceIDExists:        map[string]bool{f.endpoint.UserID: true},
		ActivatedExtensions: extensions,
	}
}

func friendRequest(user, flag, comment, policy string) adapterapi.InboundMessage {
	return adapterapi.InboundMessage{
		Kind: adapterapi.InboundKindRequest, Event: adapterapi.InboundEventFriendRequest,
		ConversationKind: adapterapi.ConversationKindDirect, Sender: adapterapi.PrincipalID(user),
		Conversation: adapterapi.ConversationID(user), Text: comment, RequestID: flag, RequestPolicy: policy,
	}
}

func groupInvite(inviter, group, flag string) adapterapi.InboundMessage {
	return adapterapi.InboundMessage{
		Kind: adapterapi.InboundKindRequest, Event: adapterapi.InboundEventGroupInvite,
		ConversationKind: adapterapi.ConversationKindGroup, Sender: adapterapi.PrincipalID(inviter),
		Conversation: adapterapi.ConversationID(group), RequestID: flag,
	}
}

func groupNotice(event adapterapi.InboundEventKind, sender, subject, operator adapterapi.PrincipalID) adapterapi.InboundMessage {
	return adapterapi.InboundMessage{
		Kind: adapterapi.InboundKindNotice, Event: event,
		ConversationKind: adapterapi.ConversationKindGroup, Conversation: "QQ-Group:2002",
		Sender: sender, Subject: subject, Operator: operator,
	}
}

func TestFriendRequestIsAnsweredFromQuestionBlacklistAndPolicy(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(*Dice)
		comment     string
		policy      string
		wantAnswer  bool
		wantApprove bool
	}{
		{name: "no question accepts", wantAnswer: true, wantApprove: true},
		{name: "explicit accept policy accepts", policy: "accept", wantAnswer: true, wantApprove: true},
		{name: "right answer accepts", setup: func(d *Dice) { d.Config.FriendAddComment = "芝士" }, comment: "芝士", wantAnswer: true, wantApprove: true},
		{name: "wrong answer rejects", setup: func(d *Dice) { d.Config.FriendAddComment = "芝士" }, comment: "蛋糕", wantAnswer: true},
		{name: "multi-line answers are matched in order", setup: func(d *Dice) { d.Config.FriendAddComment = "甲 乙" }, comment: "问题\n回答:甲\n回答:乙", wantAnswer: true, wantApprove: true},
		{name: "wrong multi-line answer rejects", setup: func(d *Dice) { d.Config.FriendAddComment = "甲 乙" }, comment: "问题\n回答:乙\n回答:甲", wantAnswer: true},
		{
			name: "a banned user is rejected even with the right answer",
			setup: func(d *Dice) {
				d.Config.BanList.BanBehaviorRefuseInvite = true
				d.Config.BanList.Map.Store("QQ:1001", &BanListInfoItem{ID: "QQ:1001", Rank: BanRankBanned})
			},
			wantAnswer: true,
		},
		{name: "ignore policy only reports", policy: "ignore"},
		{name: "manual policy only reports", policy: "manual"},
		{name: "deny policy rejects an otherwise acceptable request", policy: "deny", wantAnswer: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newEventFixture(t)
			if tt.setup != nil {
				tt.setup(f.dice)
			}
			f.notify()
			if err := f.run(friendRequest("QQ:1001", "friend-flag", tt.comment, tt.policy), groupstate.State{}); err != nil {
				t.Fatal(err)
			}
			answers := f.prep.answers()
			if !tt.wantAnswer {
				if len(answers) != 0 {
					t.Fatalf("a report-only request was answered: %#v", answers)
				}
			} else {
				if len(answers) != 1 {
					t.Fatalf("answers = %#v, want exactly one", answers)
				}
				got := answers[0]
				if got.RequestID != "friend-flag" || got.Approve != tt.wantApprove ||
					got.Target.Kind != adapterapi.TargetPerson || got.Target.Conversation != "QQ:1001" {
					t.Fatalf("answer = %#v, want approve=%v for QQ:1001 flag friend-flag", got, tt.wantApprove)
				}
			}
			// The operator is told about every request, answered or not, and the
			// report is staged in the same transaction as the answer.
			report, ok := f.prep.textContaining("收到QQ好友邀请")
			if !ok || report.Payload.Target.Conversation != eventNoticeTarget || !strings.Contains(report.Payload.Text, "邀请人:1001") {
				t.Fatalf("operator report = %#v ok=%v", report.Payload, ok)
			}
			if tt.policy == "ignore" || tt.policy == "manual" {
				if !strings.Contains(report.Payload.Text, "仅为通报") {
					t.Fatalf("a report-only request must say so: %q", report.Payload.Text)
				}
			}
		})
	}
}

func TestGroupInviteIsAnsweredFromBlacklistAndTrustPolicy(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(*Dice)
		wantApprove bool
		wantReason  string
	}{
		{name: "an ordinary invite is accepted", wantApprove: true},
		{name: "refusing all invites rejects", setup: func(d *Dice) { d.Config.RefuseGroupInvite = true }, wantReason: "拒绝拉群邀请"},
		{name: "trust-only mode rejects a non-master inviter", setup: func(d *Dice) {
			d.Config.TrustOnlyMode = true
			d.DiceMasters = []string{"QQ:99999"}
		}, wantReason: "只允许信任的人拉群"},
		{name: "trust-only mode accepts a master inviter", setup: func(d *Dice) {
			d.Config.TrustOnlyMode = true
			d.DiceMasters = []string{"QQ:1001"}
		}, wantApprove: true},
		{name: "a banned inviter is rejected", setup: func(d *Dice) {
			d.Config.BanList.BanBehaviorRefuseInvite = true
			d.Config.BanList.Map.Store("QQ:1001", &BanListInfoItem{ID: "QQ:1001", Rank: BanRankBanned})
		}, wantReason: "邀请人在黑名单上"},
		{name: "a banned group is rejected", setup: func(d *Dice) {
			d.Config.BanList.Map.Store("QQ-Group:2002", &BanListInfoItem{ID: "QQ-Group:2002", Rank: BanRankBanned})
		}, wantReason: "群组在黑名单上"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newEventFixture(t)
			if tt.setup != nil {
				tt.setup(f.dice)
			}
			f.notify()
			if err := f.run(groupInvite("QQ:1001", "QQ-Group:2002", "group-flag"), groupstate.State{}); err != nil {
				t.Fatal(err)
			}
			answers := f.prep.answers()
			if len(answers) != 1 {
				t.Fatalf("answers = %#v, want exactly one", answers)
			}
			got := answers[0]
			if got.RequestID != "group-flag" || got.Approve != tt.wantApprove || got.Reason != tt.wantReason ||
				got.Target.Kind != adapterapi.TargetGroup || got.Target.Conversation != "QQ-Group:2002" {
				t.Fatalf("answer = %#v, want approve=%v reason=%q", got, tt.wantApprove, tt.wantReason)
			}
			if report, ok := f.prep.textContaining("收到QQ加群邀请"); !ok || !strings.Contains(report.Payload.Text, "QQ-Group:2002") {
				t.Fatalf("operator report = %#v ok=%v", report.Payload, ok)
			}
		})
	}
}

func TestRequestAnswerFailsSoftWhenTheBridgeIsUnavailable(t *testing.T) {
	f := newEventFixture(t)
	f.dice.OutboundBridge = nil
	if err := f.run(friendRequest("QQ:1001", "friend-flag", "", ""), groupstate.State{}); err != nil {
		t.Fatalf("a missing bridge must not fail the callback: %v", err)
	}
}

func TestPokeReachesTheActivatedExtensionWithItsFacts(t *testing.T) {
	for _, private := range []bool{false, true} {
		name := "group"
		if private {
			name = "private"
		}
		t.Run(name, func(t *testing.T) {
			f := newEventFixture(t)
			got := make(chan [4]any, 1)
			f.dice.RegisterExtension(&ExtInfo{Name: "poke-probe", OnPoke: func(_ *MsgContext, event *events.PokeEvent) {
				got <- [4]any{event.GroupID, event.SenderID, event.TargetID, event.IsPrivate}
			}})
			inbound := groupNotice(adapterapi.InboundEventPoke, "QQ:1001", "QQ:3003", "")
			group := f.activeGroup("poke-probe")
			if private {
				inbound.ConversationKind, inbound.Conversation = adapterapi.ConversationKindDirect, "QQ:1001"
			}
			if err := f.run(inbound, group); err != nil {
				t.Fatal(err)
			}
			select {
			case facts := <-got:
				wantGroup := "QQ-Group:2002"
				if private {
					wantGroup = ""
				}
				if facts != [4]any{wantGroup, "QQ:1001", "QQ:3003", private} {
					t.Fatalf("poke facts = %v", facts)
				}
			default:
				t.Fatal("the poke did not reach the extension")
			}
		})
	}
}

func TestPokeIsIgnoredWhileTheBotIsOffInThatGroup(t *testing.T) {
	f := newEventFixture(t)
	called := false
	f.dice.RegisterExtension(&ExtInfo{Name: "poke-probe", OnPoke: func(_ *MsgContext, _ *events.PokeEvent) { called = true }})
	group := f.activeGroup("poke-probe")
	group.Active, group.DiceIDActive = false, map[string]bool{}
	if err := f.run(groupNotice(adapterapi.InboundEventPoke, "QQ:1001", "QQ:3003", ""), group); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("a poke reached an extension in a group where the bot is off")
	}
}

func TestMemberJoinedIsWelcomedOnlyWhenEnabledAndOnlyOncePerEvent(t *testing.T) {
	enabled := func(f *eventFixture) groupstate.State {
		group := f.activeGroup()
		group.ShowGroupWelcome, group.GroupWelcomeMessage = true, "欢迎新人"
		return group
	}
	join := groupNotice(adapterapi.InboundEventMemberJoined, "QQ:4004", "QQ:4004", "QQ:1001")

	t.Run("enabled welcomes the new member in the group", func(t *testing.T) {
		f := newEventFixture(t)
		if err := f.run(join, enabled(f)); err != nil {
			t.Fatal(err)
		}
		welcome, ok := f.prep.textContaining("欢迎新人")
		if !ok || welcome.Payload.Kind != adapterapi.EffectPayloadGroupText || welcome.Payload.Target.Conversation != "QQ-Group:2002" {
			t.Fatalf("welcome = %#v ok=%v", welcome.Payload, ok)
		}
	})
	t.Run("disabled stays silent", func(t *testing.T) {
		f := newEventFixture(t)
		group := enabled(f)
		group.ShowGroupWelcome = false
		if err := f.run(join, group); err != nil {
			t.Fatal(err)
		}
		if texts := f.prep.texts(); len(texts) != 0 {
			t.Fatalf("a disabled welcome sent %#v", texts)
		}
	})
	t.Run("a redelivered join is welcomed once", func(t *testing.T) {
		f := newEventFixture(t)
		for range 2 {
			if err := f.run(join, enabled(f)); err != nil {
				t.Fatal(err)
			}
		}
		count := 0
		for _, effect := range f.prep.texts() {
			if strings.Contains(effect.Payload.Text, "欢迎新人") {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("welcome sent %d times, want once", count)
		}
	})
}

func TestBotJoiningAGroupRecordsTheInviterAndDefersTheWelcomeWithoutBlocking(t *testing.T) {
	f := newEventFixture(t)
	f.notify()
	joined := make(chan string, 1)
	f.dice.RegisterExtension(&ExtInfo{Name: "join-probe", OnGroupJoined: func(_ *MsgContext, msg *Message) { joined <- msg.Sender.UserID }})
	group := f.activeGroup("join-probe")

	started := time.Now()
	if err := f.run(groupNotice(adapterapi.InboundEventSelfJoined, "QQ:1001", adapterapi.PrincipalID(f.endpoint.UserID), "QQ:1001"), group); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("the callback slept for %s while holding its lease", elapsed)
	}

	stored, ok := f.dice.ImSession.ServiceAtNew.Load("QQ-Group:2002")
	if !ok || stored.InviteUserID != "QQ:1001" {
		t.Fatalf("group after join = %#v ok=%v, want inviter QQ:1001", stored, ok)
	}
	select {
	case inviter := <-joined:
		if inviter != "QQ:1001" {
			t.Fatalf("extension saw inviter %q", inviter)
		}
	default:
		t.Fatal("the join hook did not run")
	}

	var welcome adapterapi.OutboundEffect
	for _, effect := range f.prep.texts() {
		if effect.Payload.Kind == adapterapi.EffectPayloadGroupText && effect.Payload.Target.Conversation == "QQ-Group:2002" {
			welcome = effect
		}
	}
	if welcome.ID == "" {
		t.Fatalf("no welcome staged: %#v", f.prep.texts())
	}
	if wait := time.Until(welcome.NotBefore); welcome.NotBefore.IsZero() || wait < 2*time.Second || wait > 6*time.Second {
		t.Fatalf("welcome NotBefore = %v (in %s), want the legacy ~4s pause", welcome.NotBefore, wait)
	}
	if report, ok := f.prep.textContaining("加入群组"); !ok || !report.NotBefore.IsZero() && time.Until(report.NotBefore) > 2*time.Second {
		t.Fatalf("operator report = %#v ok=%v, want an undelayed notice", report.Payload, ok)
	}
}

func TestBecomingFriendsWelcomesAfterTheLegacyPauseAndFiresTheHook(t *testing.T) {
	f := newEventFixture(t)
	hooked := make(chan string, 1)
	f.dice.RegisterExtension(&ExtInfo{Name: "friend-probe", OnBecomeFriend: func(_ *MsgContext, msg *Message) { hooked <- msg.Sender.UserID }})
	inbound := adapterapi.InboundMessage{
		Kind: adapterapi.InboundKindNotice, Event: adapterapi.InboundEventFriendAdded,
		ConversationKind: adapterapi.ConversationKindDirect, Conversation: "QQ:1001", Sender: "QQ:1001", Subject: "QQ:1001",
	}
	group := f.activeGroup("friend-probe")
	if err := f.run(inbound, group); err != nil {
		t.Fatal(err)
	}
	texts := f.prep.texts()
	if len(texts) != 1 || texts[0].Payload.Kind != adapterapi.EffectPayloadPersonText || texts[0].Payload.Target.Conversation != "QQ:1001" {
		t.Fatalf("friend welcome = %#v", texts)
	}
	if wait := time.Until(texts[0].NotBefore); texts[0].NotBefore.IsZero() || wait < 3*time.Second || wait > 7*time.Second {
		t.Fatalf("friend welcome NotBefore = %v (in %s), want the legacy ~5s pause", texts[0].NotBefore, wait)
	}
	select {
	case user := <-hooked:
		if user != "QQ:1001" {
			t.Fatalf("hook sender = %q", user)
		}
	default:
		t.Fatal("the become-friend hook did not run")
	}
}

func TestBotLeavingARoomDropsItFromTheGroupRosterAndReports(t *testing.T) {
	for _, event := range []adapterapi.InboundEventKind{adapterapi.InboundEventSelfLeft} {
		f := newEventFixture(t)
		f.notify()
		inbound := groupNotice(event, "QQ:1001", "QQ:3003", "QQ:1001")
		if err := f.run(inbound, f.activeGroup()); err != nil {
			t.Fatal(err)
		}
		group, ok := f.dice.ImSession.ServiceAtNew.Load("QQ-Group:2002")
		if !ok {
			t.Fatal("group vanished entirely")
		}
		if _, exists := group.DiceIDExistsMap.Load(f.endpoint.UserID); exists {
			t.Fatal("the bot is still on the group roster after leaving")
		}
		if report, ok := f.prep.textContaining("离开群组或群解散"); !ok || !strings.Contains(report.Payload.Text, "QQ-Group:2002") {
			t.Fatalf("operator report = %#v ok=%v", report.Payload, ok)
		}
		// Leaving must not stage a provider refresh for a group the bot is gone from.
		for _, effect := range f.prep.effects() {
			if effect.Payload.Kind == adapterapi.EffectPayloadGroupInfoRefresh {
				t.Fatalf("staged a group info refresh for a departed group: %#v", effect.Payload)
			}
		}
	}
}

func TestBotRemovedFromAGroupFiresTheLeaveHookWithTheOperator(t *testing.T) {
	f := newEventFixture(t)
	got := make(chan [3]string, 1)
	f.dice.RegisterExtension(&ExtInfo{Name: "leave-probe", OnGroupLeave: func(_ *MsgContext, event *events.GroupLeaveEvent) {
		got <- [3]string{event.GroupID, event.UserID, event.OperatorID}
	}})
	if err := f.run(groupNotice(adapterapi.InboundEventSelfRemoved, "QQ:1001", "QQ:3003", "QQ:1001"), f.activeGroup("leave-probe")); err != nil {
		t.Fatal(err)
	}
	select {
	case facts := <-got:
		if facts != [3]string{"QQ-Group:2002", "QQ:3003", "QQ:1001"} {
			t.Fatalf("leave facts = %v", facts)
		}
	default:
		t.Fatal("the leave hook did not run")
	}
}

func TestBotMutedScoresTheOperatorAndReportsTheDurationInSeconds(t *testing.T) {
	f := newEventFixture(t)
	f.notify()
	f.dice.Config.BanList.ScoreGroupMuted = 100
	inbound := groupNotice(adapterapi.InboundEventSelfMuted, "QQ:1001", "QQ:3003", "QQ:1001")
	inbound.DurationSeconds = 600
	if err := f.run(inbound, f.activeGroup()); err != nil {
		t.Fatal(err)
	}
	item, ok := f.dice.Config.BanList.GetByID("QQ:1001")
	if !ok || item.Score < 100 {
		t.Fatalf("the muting operator was not scored: %#v ok=%v", item, ok)
	}
	report, ok := f.prep.textContaining("被禁言")
	if !ok || !strings.Contains(report.Payload.Text, "时长600秒") || !strings.Contains(report.Payload.Text, "QQ-Group:2002") {
		t.Fatalf("mute report = %q ok=%v", report.Payload.Text, ok)
	}
}

func TestNoticesInsideACallbackAreStaggeredInsteadOfSleeping(t *testing.T) {
	f := newEventFixture(t)
	f.dice.Config.NoticeIDs = []string{"QQ:9001:only=invite", "QQ:9002:only=invite", "QQ:9003:only=invite"}
	started := time.Now()
	if err := f.run(friendRequest("QQ:1001", "friend-flag", "", "manual"), groupstate.State{}); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("delivering three notices blocked for %s", elapsed)
	}
	var reports []adapterapi.OutboundEffect
	for _, effect := range f.prep.texts() {
		if strings.Contains(effect.Payload.Text, "收到QQ好友邀请") {
			reports = append(reports, effect)
		}
	}
	if len(reports) != 3 {
		t.Fatalf("reports = %d, want one per target", len(reports))
	}
	byTarget := map[string]time.Time{}
	for _, report := range reports {
		byTarget[string(report.Payload.Target.Conversation)] = report.NotBefore
	}
	if !byTarget["QQ:9001"].IsZero() {
		t.Fatalf("the first notice must not be delayed: %v", byTarget["QQ:9001"])
	}
	for _, target := range []string{"QQ:9002", "QQ:9003"} {
		if byTarget[target].IsZero() {
			t.Fatalf("notice to %s was not staggered", target)
		}
	}
	if !byTarget["QQ:9003"].After(byTarget["QQ:9002"]) {
		t.Fatalf("notices are not spaced: %v then %v", byTarget["QQ:9002"], byTarget["QQ:9003"])
	}
}

func TestBlackListChecksAreDecidedFromTheInviterAndGroup(t *testing.T) {
	d, _, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	ctx := &MsgContext{Dice: d}
	d.Config.TrustOnlyMode = true
	d.DiceMasters = []string{"QQ:55555"}
	d.Config.BanList.Map.Store("QQ-Group:66666", &BanListInfoItem{ID: "QQ-Group:66666", Rank: BanRankNormal})
	if ok, reason := checkPassBlackListGroup("QQ:55555", "QQ-Group:66666", ctx); !ok {
		t.Fatalf("a master inviter must pass trust-only mode, got %q", reason)
	}
	if ok, _ := checkPassBlackListGroup("QQ:11111", "QQ-Group:66666", ctx); ok {
		t.Fatal("a non-master inviter must not pass trust-only mode")
	}

	d.Config.BanList.Map.Store("QQ:55555", &BanListInfoItem{ID: "QQ:55555", Rank: BanRankBanned})
	d.Config.BanList.BanBehaviorRefuseInvite = true
	result := checkBlackList("QQ:55555", "user", "", ctx)
	if result.Passed || result.Reason != "邀请人在黑名单上" {
		t.Fatalf("a banned master must still be rejected as inviter, got %#v", result)
	}
}

func TestEventNamesReachCachesGroupsPlayersAndReports(t *testing.T) {
	f := newEventFixture(t)
	f.notify()
	inbound := groupNotice(adapterapi.InboundEventSelfJoined, "QQ:1001", adapterapi.PrincipalID(f.endpoint.UserID), "QQ:1001")
	inbound.SenderName, inbound.ConversationName = "爱丽丝", "测试群"
	if err := f.run(inbound, f.activeGroup()); err != nil {
		t.Fatal(err)
	}
	if got := f.dice.Parent.TryGetUserName("QQ:1001"); got != "爱丽丝" {
		t.Fatalf("cached user name = %q", got)
	}
	if got := f.dice.Parent.TryGetGroupName("QQ-Group:2002"); got != "测试群" {
		t.Fatalf("cached group name = %q", got)
	}
	report, ok := f.prep.textContaining("加入群组")
	if !ok || !strings.Contains(report.Payload.Text, "<测试群>(QQ-Group:2002)") {
		t.Fatalf("join report = %q ok=%v, want the group named", report.Payload.Text, ok)
	}
	if group, ok := f.dice.ImSession.ServiceAtNew.Load("QQ-Group:2002"); !ok || group.GroupName != "测试群" {
		t.Fatalf("group after join = %#v", group)
	}
}

func TestInviteReportNamesTheInviterAndTheGroup(t *testing.T) {
	f := newEventFixture(t)
	f.notify()
	inbound := groupInvite("QQ:1001", "QQ-Group:2002", "group-flag")
	inbound.SenderName, inbound.ConversationName = "爱丽丝", "测试群"
	if err := f.run(inbound, groupstate.State{}); err != nil {
		t.Fatal(err)
	}
	report, ok := f.prep.textContaining("收到QQ加群邀请")
	if !ok || !strings.Contains(report.Payload.Text, "<测试群>(QQ-Group:2002)") || !strings.Contains(report.Payload.Text, "<爱丽丝>(QQ:1001)") {
		t.Fatalf("invite report = %q ok=%v", report.Payload.Text, ok)
	}
}

func TestMissingNamesNeverEraseWhatIsAlreadyKnown(t *testing.T) {
	f := newEventFixture(t)
	f.dice.Parent.GroupNameCache.Store("QQ-Group:2002", &GroupNameCacheItem{Name: "旧群名", MemberCount: 42, MemberCountKnown: true})
	f.dice.Parent.UserNameCache.Store("QQ:1001", &GroupNameCacheItem{Name: "旧昵称"})

	// An event the provider could not name leaves both caches alone.
	if err := f.run(groupNotice(adapterapi.InboundEventPoke, "QQ:1001", "QQ:3003", ""), f.activeGroup()); err != nil {
		t.Fatal(err)
	}
	if got := f.dice.Parent.TryGetGroupName("QQ-Group:2002"); got != "旧群名" {
		t.Fatalf("an unnamed event erased the group name: %q", got)
	}
	if got := f.dice.Parent.TryGetUserName("QQ:1001"); got != "旧昵称" {
		t.Fatalf("an unnamed event erased the user name: %q", got)
	}

	// A named event renames them but keeps the rest of the cached group facts.
	named := groupNotice(adapterapi.InboundEventPoke, "QQ:1001", "QQ:3003", "")
	named.SenderName, named.ConversationName = "新昵称", "新群名"
	if err := f.run(named, f.activeGroup()); err != nil {
		t.Fatal(err)
	}
	item, _ := f.dice.Parent.GroupNameCache.Load("QQ-Group:2002")
	if item == nil || item.Name != "新群名" || !item.MemberCountKnown || item.MemberCount != 42 {
		t.Fatalf("group cache after rename = %#v, want the new name with its member count kept", item)
	}
	if got := f.dice.Parent.TryGetUserName("QQ:1001"); got != "新昵称" {
		t.Fatalf("user name = %q", got)
	}
}

func TestANewMemberIsNamedFromTheEventNotFromItsId(t *testing.T) {
	f := newEventFixture(t)
	inbound := groupNotice(adapterapi.InboundEventPoke, "QQ:1001", "QQ:3003", "")
	inbound.SenderName = "爱丽丝"
	if err := f.run(inbound, f.activeGroup()); err != nil {
		t.Fatal(err)
	}
	group, ok := f.dice.ImSession.ServiceAtNew.Load("QQ-Group:2002")
	if !ok {
		t.Fatal("group missing")
	}
	player, ok := group.Players.Load("QQ:1001")
	if !ok || player.Name != "爱丽丝" {
		t.Fatalf("player = %#v ok=%v, want the provider-supplied name instead of the id", player, ok)
	}
}

func TestMessagesAlsoRememberTheirSendersName(t *testing.T) {
	f := newEventFixture(t)
	inbound := adapterapi.InboundMessage{
		Kind: adapterapi.InboundKindMessage, ConversationKind: adapterapi.ConversationKindGroup,
		Conversation: "QQ-Group:2002", Sender: "QQ:1001", SenderName: "爱丽丝", Text: "闲聊一句",
	}
	if err := f.run(inbound, f.activeGroup()); err != nil {
		t.Fatal(err)
	}
	if got := f.dice.Parent.TryGetUserName("QQ:1001"); got != "爱丽丝" {
		t.Fatalf("message sender name not remembered: %q", got)
	}
}

func TestDurableCallbackRunsKnownPokeAndRawAdapterHookOnce(t *testing.T) {
	fixture := newEventFixture(t)
	pokeCalls, rawCalls := 0, 0
	extension := &ExtInfo{
		Name: "poke-and-raw-probe",
		OnPoke: func(_ *MsgContext, _ *events.PokeEvent) {
			pokeCalls++
		},
		OnAdapterEvent: func(ctx *MsgContext, event *AdapterEventView) {
			if ctx == nil || event == nil || event.RawJSON == "" {
				t.Fatal("scoped adapter callback did not receive its context and event")
			}
			rawCalls++
		},
	}
	fixture.dice.RegisterExtension(extension)
	group := fixture.activeGroup(extension.Name)
	inbound := groupNotice(adapterapi.InboundEventPoke, "QQ:1001", "QQ:3003", "")
	inbound.AdapterEvent = &adapterapi.AdapterEvent{
		Protocol: "onebot11",
		Type:     "notice",
		RawJSON:  `{"post_type":"notice","notice_type":"notify","sub_type":"poke","group_id":2002,"user_id":1001,"target_id":3003}`,
	}
	if err := fixture.run(inbound, group); err != nil {
		t.Fatal(err)
	}
	if pokeCalls != 1 || rawCalls != 1 {
		t.Fatalf("known/raw callback counts = %d/%d", pokeCalls, rawCalls)
	}
}

func TestDurableOpaqueAdapterEventUsesProjectedConversationScope(t *testing.T) {
	fixture := newEventFixture(t)
	called := 0
	extension := &ExtInfo{
		Name: "opaque-scope-probe",
		OnAdapterEvent: func(ctx *MsgContext, event *AdapterEventView) {
			called++
			if ctx == nil || ctx.Group == nil || ctx.Player == nil || ctx.EndPoint == nil || ctx.EndPoint.ID != fixture.endpoint.ID {
				t.Fatalf("opaque callback context = %#v", ctx)
			}
			if ctx.MessageType != "group" || ctx.IsPrivate || !ctx.IsCurGroupBotOn ||
				ctx.PrivilegeLevel != 50 || ctx.GroupRoleLevel != 50 {
				t.Fatalf("opaque callback compatibility flags = type=%q private=%t active=%t privilege=%d role=%d",
					ctx.MessageType, ctx.IsPrivate, ctx.IsCurGroupBotOn, ctx.PrivilegeLevel, ctx.GroupRoleLevel)
			}
			if ctx.callbackTransaction == nil || ctx.callbackMetadata.CommandID != "inbox-event" {
				t.Fatal("opaque callback escaped durable callback ownership")
			}
			ReplyToSender(ctx, &Message{
				MessageType: "group", GroupID: ctx.Group.GroupID, Platform: "QQ",
				Sender: SenderBase{UserID: ctx.Player.UserID},
			}, "opaque adapter reply")
			if event.RawJSON != `{"post_type":"notice","notice_type":"group_admin","group_id":2002,"user_id":1001}` {
				t.Fatalf("raw JSON = %q", event.RawJSON)
			}
		},
	}
	fixture.dice.RegisterExtension(extension)
	group := fixture.activeGroup(extension.Name)
	inbound := adapterapi.InboundMessage{
		ProviderEventID:  "opaque-scope-1",
		Kind:             adapterapi.InboundKindAdapterEvent,
		ConversationKind: adapterapi.ConversationKindGroup,
		Platform:         "QQ",
		Sender:           "QQ:1001",
		SenderRole:       "admin",
		Conversation:     "QQ-Group:2002",
		Target:           "QQ-Group:2002",
		AdapterEvent: &adapterapi.AdapterEvent{
			Protocol: "onebot11",
			Type:     "notice",
			RawJSON:  `{"post_type":"notice","notice_type":"group_admin","group_id":2002,"user_id":1001}`,
		},
	}
	if err := fixture.run(inbound, group); err != nil {
		t.Fatal(err)
	}
	if called != 1 {
		t.Fatalf("opaque callback count = %d", called)
	}
	if reply, ok := fixture.prep.textContaining("opaque adapter reply"); !ok || reply.Payload.Target.Conversation != "QQ-Group:2002" {
		t.Fatalf("scoped adapter reply = %#v, found=%v", reply.Payload, ok)
	}
}

func TestGlobalAdapterEventUsesNilCallbackContextWithoutConversationState(t *testing.T) {
	fixture := newEventFixture(t)
	called := 0
	extension := &ExtInfo{
		Name:               "global-adapter-probe",
		AdapterEventFilter: map[string]any{"events": "all"},
		OnAdapterEvent: func(ctx *MsgContext, event *AdapterEventView) {
			called++
			if ctx != nil {
				t.Fatalf("global callback context = %#v, want nil", ctx)
			}
			if event == nil || event.EndPoint == nil || event.EndPoint.ID != fixture.endpoint.ID {
				t.Fatalf("global endpoint = %#v", event)
			}
		},
	}
	fixture.dice.RegisterExtension(extension)
	receipt, err := fixture.host.HandleAdapterEvent(context.Background(), endpoint.FencedAdapterEvent{
		EndpointID: adapterapi.EndpointID(fixture.endpoint.ID), Generation: 1, DesiredVersion: 1,
		Event: adapterapi.AdapterEvent{Protocol: "onebot11", Type: "meta_event", RawJSON: `{"post_type":"meta_event","meta_event_type":"heartbeat"}`},
	})
	if err != nil || receipt.Outcome != adapterapi.IngressAccepted {
		t.Fatalf("HandleAdapterEvent() = %#v, %v", receipt, err)
	}
	if called != 1 {
		t.Fatalf("global callback count = %d", called)
	}
}

func TestGlobalAdapterPluginFailureIsContained(t *testing.T) {
	fixture := newEventFixture(t)
	fixture.dice.RegisterExtension(&ExtInfo{
		Name:               "invalid-global-adapter-filter",
		AdapterEventFilter: map[string]any{"events": 42},
		OnAdapterEvent:     func(*MsgContext, *AdapterEventView) {},
	})
	receipt, err := fixture.host.HandleAdapterEvent(context.Background(), endpoint.FencedAdapterEvent{
		EndpointID: adapterapi.EndpointID(fixture.endpoint.ID), Generation: 1, DesiredVersion: 1,
		Event: adapterapi.AdapterEvent{Protocol: "onebot11", Type: "notice", RawJSON: `{"post_type":"notice"}`},
	})
	if err != nil || receipt.Outcome != adapterapi.IngressRejected {
		t.Fatalf("contained plugin failure = %#v, %v", receipt, err)
	}
}

func TestGlobalAdapterPluginPanicIsContained(t *testing.T) {
	fixture := newEventFixture(t)
	fixture.dice.RegisterExtension(&ExtInfo{
		Name:           "panicking-global-adapter-hook",
		OnAdapterEvent: func(*MsgContext, *AdapterEventView) { panic("plugin boom") },
	})
	receipt, err := fixture.host.HandleAdapterEvent(context.Background(), endpoint.FencedAdapterEvent{
		EndpointID: adapterapi.EndpointID(fixture.endpoint.ID), Generation: 1, DesiredVersion: 1,
		Event: adapterapi.AdapterEvent{Protocol: "onebot11", Type: "notice", RawJSON: `{"post_type":"notice"}`},
	})
	if err != nil || receipt.Outcome != adapterapi.IngressRejected {
		t.Fatalf("contained plugin panic = %#v, %v", receipt, err)
	}
}
