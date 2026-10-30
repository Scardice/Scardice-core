package dice

import (
	"context"
	"errors"
	"math"
	"testing"

	"Scardice-core/adapterapi"
)

func onebotEventRuntime(policy string) (*onebotRuntime, *onebotRuntimeCore) {
	core := &onebotRuntimeCore{inboundCh: make(chan adapterapi.InboundMessage, 4)}
	return &onebotRuntime{core: core, config: OnebotConfig{FriendRequestPolicy: policy}}, core
}

func TestOnebotNoticesAndRequestsBecomeTypedInbounds(t *testing.T) {
	const self = `"self_id":3003`
	tests := []struct {
		name     string
		raw      string
		kind     adapterapi.InboundKind
		event    adapterapi.InboundEventKind
		conv     adapterapi.ConversationID
		convKind adapterapi.ConversationKind
		sender   adapterapi.PrincipalID
		subject  adapterapi.PrincipalID
		operator adapterapi.PrincipalID
		extra    func(*testing.T, adapterapi.InboundMessage)
	}{
		{
			name: "poke in a group", raw: `{"post_type":"notice","notice_type":"notify","sub_type":"poke","group_id":2002,"user_id":1001,"target_id":3003,"time":1700000000,` + self + `}`,
			kind: adapterapi.InboundKindNotice, event: adapterapi.InboundEventPoke,
			conv: "QQ-Group:2002", convKind: adapterapi.ConversationKindGroup, sender: "QQ:1001", subject: "QQ:3003",
		},
		{
			name: "poke in a private chat", raw: `{"post_type":"notice","notice_type":"notify","sub_type":"poke","user_id":1001,"target_id":3003,"time":1700000000,` + self + `}`,
			kind: adapterapi.InboundKindNotice, event: adapterapi.InboundEventPoke,
			conv: "QQ:1001", convKind: adapterapi.ConversationKindDirect, sender: "QQ:1001", subject: "QQ:3003",
		},
		{
			name: "another member joins", raw: `{"post_type":"notice","notice_type":"group_increase","sub_type":"approve","group_id":2002,"user_id":4004,"operator_id":1001,"time":1700000000,` + self + `}`,
			kind: adapterapi.InboundKindNotice, event: adapterapi.InboundEventMemberJoined,
			conv: "QQ-Group:2002", convKind: adapterapi.ConversationKindGroup, sender: "QQ:4004", subject: "QQ:4004", operator: "QQ:1001",
		},
		{
			name: "the bot is invited into a group", raw: `{"post_type":"notice","notice_type":"group_increase","sub_type":"invite","group_id":2002,"user_id":3003,"operator_id":1001,"time":1700000000,` + self + `}`,
			kind: adapterapi.InboundKindNotice, event: adapterapi.InboundEventSelfJoined,
			conv: "QQ-Group:2002", convKind: adapterapi.ConversationKindGroup, sender: "QQ:1001", subject: "QQ:3003", operator: "QQ:1001",
		},
		{
			name: "the bot joins without an operator", raw: `{"post_type":"notice","notice_type":"group_increase","group_id":2002,"user_id":3003,"operator_id":0,"time":1700000000,` + self + `}`,
			kind: adapterapi.InboundKindNotice, event: adapterapi.InboundEventSelfJoined,
			conv: "QQ-Group:2002", convKind: adapterapi.ConversationKindGroup, sender: "QQ:3003", subject: "QQ:3003",
		},
		{
			name: "the bot is kicked", raw: `{"post_type":"notice","notice_type":"group_decrease","sub_type":"kick_me","group_id":2002,"user_id":3003,"operator_id":1001,"time":1700000000,` + self + `}`,
			kind: adapterapi.InboundKindNotice, event: adapterapi.InboundEventSelfRemoved,
			conv: "QQ-Group:2002", convKind: adapterapi.ConversationKindGroup, sender: "QQ:1001", subject: "QQ:3003", operator: "QQ:1001",
		},
		{
			name: "the bot leaves", raw: `{"post_type":"notice","notice_type":"group_decrease","sub_type":"leave","group_id":2002,"user_id":3003,"operator_id":3003,"time":1700000000,` + self + `}`,
			kind: adapterapi.InboundKindNotice, event: adapterapi.InboundEventSelfLeft,
			conv: "QQ-Group:2002", convKind: adapterapi.ConversationKindGroup, sender: "QQ:3003", subject: "QQ:3003", operator: "QQ:3003",
		},
		{
			name: "the group is disbanded by its owner", raw: `{"post_type":"notice","notice_type":"group_decrease","sub_type":"disband","group_id":2002,"user_id":3003,"operator_id":1001,"time":1700000000,` + self + `}`,
			kind: adapterapi.InboundKindNotice, event: adapterapi.InboundEventSelfLeft,
			conv: "QQ-Group:2002", convKind: adapterapi.ConversationKindGroup, sender: "QQ:1001", subject: "QQ:3003", operator: "QQ:1001",
		},
		{
			name: "the bot is muted", raw: `{"post_type":"notice","notice_type":"group_ban","sub_type":"ban","group_id":2002,"user_id":3003,"operator_id":1001,"duration":600,"time":1700000000,` + self + `}`,
			kind: adapterapi.InboundKindNotice, event: adapterapi.InboundEventSelfMuted,
			conv: "QQ-Group:2002", convKind: adapterapi.ConversationKindGroup, sender: "QQ:1001", subject: "QQ:3003", operator: "QQ:1001",
			extra: func(t *testing.T, m adapterapi.InboundMessage) {
				if m.DurationSeconds != 600 {
					t.Fatalf("DurationSeconds = %d", m.DurationSeconds)
				}
			},
		},
		{
			name: "a friend is added", raw: `{"post_type":"notice","notice_type":"friend_add","user_id":1001,"time":1700000000,` + self + `}`,
			kind: adapterapi.InboundKindNotice, event: adapterapi.InboundEventFriendAdded,
			conv: "QQ:1001", convKind: adapterapi.ConversationKindDirect, sender: "QQ:1001", subject: "QQ:1001",
		},
		{
			name: "a friend request", raw: `{"post_type":"request","request_type":"friend","flag":"friend-flag-1","user_id":1001,"comment":"hello\n回答:骰子","time":1700000000,` + self + `}`,
			kind: adapterapi.InboundKindRequest, event: adapterapi.InboundEventFriendRequest,
			conv: "QQ:1001", convKind: adapterapi.ConversationKindDirect, sender: "QQ:1001",
			extra: func(t *testing.T, m adapterapi.InboundMessage) {
				if m.RequestID != "friend-flag-1" || m.Text != "hello\n回答:骰子" || m.RequestPolicy != "manual" {
					t.Fatalf("request facts = id %q text %q policy %q", m.RequestID, m.Text, m.RequestPolicy)
				}
			},
		},
		{
			name: "a group invitation", raw: `{"post_type":"request","request_type":"group","sub_type":"invite","flag":"group-flag-1","group_id":2002,"user_id":1001,"time":1700000000,` + self + `}`,
			kind: adapterapi.InboundKindRequest, event: adapterapi.InboundEventGroupInvite,
			conv: "QQ-Group:2002", convKind: adapterapi.ConversationKindGroup, sender: "QQ:1001",
			extra: func(t *testing.T, m adapterapi.InboundMessage) {
				if m.RequestID != "group-flag-1" || m.RequestPolicy != "" {
					t.Fatalf("invite facts = id %q policy %q", m.RequestID, m.RequestPolicy)
				}
			},
		},
		{
			name: "a group message is recalled", raw: `{"post_type":"notice","notice_type":"group_recall","time":1700000000,"user_id":"2001","group_id":"2002","message_id":"opaque-recalled-message"}`,
			kind: adapterapi.InboundKindMessageDeleted,
			conv: "QQ-Group:2002", convKind: adapterapi.ConversationKindGroup, sender: "QQ:2001",
			extra: func(t *testing.T, m adapterapi.InboundMessage) {
				if m.MessageID != "opaque-recalled-message" {
					t.Fatalf("recalled message ID = %q", m.MessageID)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runtime, core := onebotEventRuntime("manual")
			if err := runtime.handleInbound(context.Background(), []byte(tt.raw)); err != nil {
				t.Fatalf("handleInbound: %v", err)
			}
			var m adapterapi.InboundMessage
			select {
			case m = <-core.inboundCh:
			default:
				t.Fatal("event did not reach Core")
			}
			if m.Kind != tt.kind || m.Event != tt.event || m.Conversation != tt.conv || m.ConversationKind != tt.convKind ||
				m.Sender != tt.sender || m.Subject != tt.subject || m.Operator != tt.operator || m.Target != string(tt.conv) {
				t.Fatalf("inbound = %#v", m)
			}
			if m.ProviderEventID == "" || !m.CausationID.Valid() || m.Platform != "QQ" || m.OccurredAt.IsZero() {
				t.Fatalf("identity facts missing: %#v", m)
			}
			if tt.extra != nil {
				tt.extra(t, m)
			}
		})
	}
}

func TestOnebotEventIdentityIsStableSoRedeliveryDeduplicates(t *testing.T) {
	raws := map[string]string{
		"friend request": `{"post_type":"request","request_type":"friend","flag":"f-1","user_id":1001,"time":1700000000,"self_id":3003}`,
		"group invite":   `{"post_type":"request","request_type":"group","sub_type":"invite","flag":"g-1","group_id":2002,"user_id":1001,"time":1700000000,"self_id":3003}`,
		"member joined":  `{"post_type":"notice","notice_type":"group_increase","group_id":2002,"user_id":4004,"operator_id":1001,"time":1700000000,"self_id":3003}`,
		"poke":           `{"post_type":"notice","notice_type":"notify","sub_type":"poke","group_id":2002,"user_id":1001,"target_id":3003,"time":1700000000,"self_id":3003}`,
	}
	for name, raw := range raws {
		runtime, core := onebotEventRuntime("accept")
		for range 2 {
			if err := runtime.handleInbound(context.Background(), []byte(raw)); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
		first, second := <-core.inboundCh, <-core.inboundCh
		if first.ProviderEventID != second.ProviderEventID {
			t.Fatalf("%s: redelivery changed identity %q -> %q", name, first.ProviderEventID, second.ProviderEventID)
		}
	}

	// Two different events must never share an identity.
	runtime, core := onebotEventRuntime("accept")
	for _, raw := range []string{
		`{"post_type":"notice","notice_type":"notify","sub_type":"poke","group_id":2002,"user_id":1001,"target_id":3003,"time":1700000000,"self_id":3003}`,
		`{"post_type":"notice","notice_type":"notify","sub_type":"poke","group_id":2002,"user_id":1001,"target_id":3003,"time":1700000001,"self_id":3003}`,
		`{"post_type":"notice","notice_type":"notify","sub_type":"poke","group_id":2002,"user_id":1002,"target_id":3003,"time":1700000000,"self_id":3003}`,
	} {
		if err := runtime.handleInbound(context.Background(), []byte(raw)); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[adapterapi.ProviderEventID]bool{}
	for range 3 {
		id := (<-core.inboundCh).ProviderEventID
		if seen[id] {
			t.Fatalf("distinct pokes collapsed to one identity %q", id)
		}
		seen[id] = true
	}
}

func TestOnebotEventsWithoutCoreHandlersRemainAvailableAsOpaqueEvents(t *testing.T) {
	for name, raw := range map[string]string{
		"another member leaves":   `{"post_type":"notice","notice_type":"group_decrease","sub_type":"leave","group_id":2002,"user_id":4004,"operator_id":4004,"time":1700000000,"self_id":3003}`,
		"another member kicked":   `{"post_type":"notice","notice_type":"group_decrease","sub_type":"kick","group_id":2002,"user_id":4004,"operator_id":1001,"time":1700000000,"self_id":3003}`,
		"another member muted":    `{"post_type":"notice","notice_type":"group_ban","sub_type":"ban","group_id":2002,"user_id":4004,"operator_id":1001,"duration":60,"time":1700000000,"self_id":3003}`,
		"the bot is unmuted":      `{"post_type":"notice","notice_type":"group_ban","sub_type":"lift_ban","group_id":2002,"user_id":3003,"operator_id":1001,"time":1700000000,"self_id":3003}`,
		"a join request to admin": `{"post_type":"request","request_type":"group","sub_type":"add","flag":"g-2","group_id":2002,"user_id":1001,"time":1700000000,"self_id":3003}`,
	} {
		t.Run(name, func(t *testing.T) {
			runtime, core := onebotEventRuntime("accept")
			if err := runtime.handleInbound(context.Background(), []byte(raw)); err != nil {
				t.Fatalf("opaque event: %v", err)
			}
			message := <-core.inboundCh
			if message.Kind != adapterapi.InboundKindAdapterEvent || message.AdapterEvent == nil || message.AdapterEvent.RawJSON != raw {
				t.Fatalf("opaque event = %#v", message)
			}
			if got := runtime.inboundRejected.Load(); got != 0 {
				t.Fatalf("retained event was counted as rejected (%d)", got)
			}
		})
	}
}

func TestOnebotEventsWithoutStableIdentityAreRejected(t *testing.T) {
	for name, raw := range map[string]string{
		"friend request without a flag":       `{"post_type":"request","request_type":"friend","user_id":1001,"time":1700000000,"self_id":3003}`,
		"group invite without a flag":         `{"post_type":"request","request_type":"group","sub_type":"invite","group_id":2002,"user_id":1001,"time":1700000000,"self_id":3003}`,
		"group invite without a group":        `{"post_type":"request","request_type":"group","sub_type":"invite","flag":"g","user_id":1001,"time":1700000000,"self_id":3003}`,
		"poke without a sender":               `{"post_type":"notice","notice_type":"notify","sub_type":"poke","group_id":2002,"target_id":3003,"time":1700000000,"self_id":3003}`,
		"poke without a target":               `{"post_type":"notice","notice_type":"notify","sub_type":"poke","group_id":2002,"user_id":1001,"time":1700000000,"self_id":3003}`,
		"group_increase without a group":      `{"post_type":"notice","notice_type":"group_increase","user_id":4004,"time":1700000000,"self_id":3003}`,
		"self-directed event without self id": `{"post_type":"notice","notice_type":"group_ban","sub_type":"ban","group_id":2002,"user_id":3003,"operator_id":1001,"duration":60,"time":1700000000}`,
		"friend_add without a user":           `{"post_type":"notice","notice_type":"friend_add","time":1700000000,"self_id":3003}`,
	} {
		t.Run(name, func(t *testing.T) {
			runtime, core := onebotEventRuntime("accept")
			if err := runtime.handleInbound(context.Background(), []byte(raw)); !errors.Is(err, ErrOnebotUnsupportedInboundEvent) {
				t.Fatalf("error = %v, want unsupported", err)
			}
			select {
			case m := <-core.inboundCh:
				t.Fatalf("event reached Core: %#v", m)
			default:
			}
		})
	}
}

func TestOnebotFriendRequestReportsTheConfiguredPolicy(t *testing.T) {
	for _, policy := range []string{"accept", "ignore", "manual", "deny"} {
		runtime, core := onebotEventRuntime(policy)
		raw := `{"post_type":"request","request_type":"friend","flag":"f-1","user_id":1001,"time":1700000000,"self_id":3003}`
		if err := runtime.handleInbound(context.Background(), []byte(raw)); err != nil {
			t.Fatal(err)
		}
		if got := (<-core.inboundCh).RequestPolicy; got != policy {
			t.Fatalf("policy %q reported as %q", policy, got)
		}
	}
}

func TestOnebotUnknownNoticeAndRequestTypesReachCoreWithoutRejection(t *testing.T) {
	for name, raw := range map[string]string{
		"unknown notify sub type": `{"post_type":"notice","notice_type":"notify","sub_type":"honor","group_id":2002,"user_id":1001,"time":1700000000,"self_id":3003}`,
		"unknown notice type":     `{"post_type":"notice","notice_type":"group_upload","group_id":2002,"user_id":1001,"time":1700000000,"self_id":3003}`,
		"unknown request type":    `{"post_type":"request","request_type":"guild_invite","flag":"x","user_id":1001,"time":1700000000,"self_id":3003}`,
	} {
		t.Run(name, func(t *testing.T) {
			runtime, core := onebotEventRuntime("accept")
			if err := runtime.processRuntimeEvent(context.Background(), onebotRuntimeEvent{kind: "inbound", raw: []byte(raw)}); err != nil {
				t.Fatalf("opaque event stopped the worker: %v", err)
			}
			if got := runtime.inboundRejected.Load(); got != 0 {
				t.Fatalf("opaque event rejection count = %d", got)
			}
			message := <-core.inboundCh
			if message.Kind != adapterapi.InboundKindAdapterEvent || message.AdapterEvent == nil || message.AdapterEvent.RawJSON != raw {
				t.Fatalf("opaque event = %#v", message)
			}
		})
	}
}

// LuckyLillia (LLBot) reports a disbanded group as its own notice whose user_id
// is the owner, instead of a group_decrease with sub_type disband.
func TestOnebotGroupDismissMeansTheBotLostTheRoom(t *testing.T) {
	runtime, core := onebotEventRuntime("accept")
	raw := `{"post_type":"notice","notice_type":"group_dismiss","group_id":2002,"user_id":1001,"time":1700000000,"self_id":3003}`
	if err := runtime.handleInbound(context.Background(), []byte(raw)); err != nil {
		t.Fatalf("handleInbound: %v", err)
	}
	m := <-core.inboundCh
	if m.Kind != adapterapi.InboundKindNotice || m.Event != adapterapi.InboundEventSelfLeft || m.Conversation != "QQ-Group:2002" ||
		m.Sender != "QQ:1001" || m.Subject != "QQ:3003" || m.Operator != "QQ:1001" {
		t.Fatalf("group_dismiss inbound = %#v", m)
	}
	// Two dismiss notices for different groups must not share an identity.
	other := `{"post_type":"notice","notice_type":"group_dismiss","group_id":2003,"user_id":1001,"time":1700000000,"self_id":3003}`
	if err := runtime.handleInbound(context.Background(), []byte(other)); err != nil {
		t.Fatal(err)
	}
	if second := <-core.inboundCh; second.ProviderEventID == m.ProviderEventID {
		t.Fatalf("different groups collapsed to one identity %q", m.ProviderEventID)
	}
	if err := runtime.handleInbound(context.Background(), []byte(`{"post_type":"notice","notice_type":"group_dismiss","user_id":1001,"time":1700000000,"self_id":3003}`)); !errors.Is(err, ErrOnebotUnsupportedInboundEvent) {
		t.Fatalf("a dismiss without a group must be rejected, got %v", err)
	}
}

func TestOnebotMuteEventsFollowTheProtocolsWholeGroupAndPermanentForms(t *testing.T) {
	// A whole-group mute has no normalized Core handler, but remains available
	// to adapter-event subscribers.
	runtime, core := onebotEventRuntime("accept")
	whole := `{"post_type":"notice","notice_type":"group_ban","sub_type":"ban","group_id":2002,"user_id":0,"operator_id":1001,"duration":-1,"time":1700000000,"self_id":3003}`
	if err := runtime.handleInbound(context.Background(), []byte(whole)); err != nil {
		t.Fatalf("a whole-group mute must be retained: %v", err)
	}
	if message := <-core.inboundCh; message.Kind != adapterapi.InboundKindAdapterEvent || message.AdapterEvent == nil || message.AdapterEvent.RawJSON != whole {
		t.Fatalf("whole-group mute = %#v", message)
	}
	if got := runtime.inboundRejected.Load(); got != 0 {
		t.Fatalf("a whole-group mute was counted as rejected (%d)", got)
	}

	// duration -1 mutes the bot permanently.
	permanent := `{"post_type":"notice","notice_type":"group_ban","sub_type":"ban","group_id":2002,"user_id":3003,"operator_id":1001,"duration":-1,"time":1700000000,"self_id":3003}`
	if err := runtime.handleInbound(context.Background(), []byte(permanent)); err != nil {
		t.Fatal(err)
	}
	if m := <-core.inboundCh; m.Event != adapterapi.InboundEventSelfMuted || m.DurationSeconds != math.MaxUint32 {
		t.Fatalf("a permanent mute must report the maximum duration, got %#v", m)
	}

	// A zero-length ban is an unmute. It is not normalized as a mute, but its
	// exact protocol event remains available to adapter-event subscribers.
	zero := `{"post_type":"notice","notice_type":"group_ban","sub_type":"ban","group_id":2002,"user_id":3003,"operator_id":1001,"duration":0,"time":1700000000,"self_id":3003}`
	if err := runtime.handleInbound(context.Background(), []byte(zero)); err != nil {
		t.Fatal(err)
	}
	if message := <-core.inboundCh; message.Kind != adapterapi.InboundKindAdapterEvent || message.AdapterEvent == nil || message.AdapterEvent.RawJSON != zero {
		t.Fatalf("zero-length ban = %#v", message)
	}
}
