package dice

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	emitter "Scardice-core/dice/imsdk/onebot"
	emitterTypes "Scardice-core/dice/imsdk/onebot/types"
)

// onebotLookupFake answers provider lookups per action and records each call.
type onebotLookupFake struct {
	*onebotOutboundFake
	mu        sync.Mutex
	responses map[emitter.Action]string
	errs      map[emitter.Action]error
	block     bool
	calls     []onebotLookupCall
}

type onebotLookupCall struct {
	action emitter.Action
	params any
}

func (f *onebotLookupFake) Raw(ctx context.Context, action emitter.Action, params any) ([]byte, error) {
	f.mu.Lock()
	f.calls = append(f.calls, onebotLookupCall{action, params})
	response, hasResponse := f.responses[action]
	err := f.errs[action]
	block := f.block
	f.mu.Unlock()
	if block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	if !hasResponse {
		return nil, errors.New("no scripted response for " + action)
	}
	return []byte(response), nil
}

func (f *onebotLookupFake) actions() []emitter.Action {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]emitter.Action, 0, len(f.calls))
	for _, call := range f.calls {
		out = append(out, call.action)
	}
	return out
}

func (f *onebotLookupFake) paramsOf(action emitter.Action) any {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, call := range f.calls {
		if call.action == action {
			return call.params
		}
	}
	return nil
}

func newLookupFake() *onebotLookupFake {
	return &onebotLookupFake{
		onebotOutboundFake: &onebotOutboundFake{},
		responses: map[emitter.Action]string{
			emitter.ACTION_GET_GROUP_INFO:        `{"status":"ok","retcode":0,"data":{"group_id":2002,"group_name":"测试群","member_count":3,"max_member_count":500}}`,
			emitter.ACTION_GET_GROUP_MEMBER_INFO: `{"status":"ok","retcode":0,"data":{"group_id":2002,"user_id":1001,"nickname":"爱丽丝","card":"群里的爱丽丝","role":"admin"}}`,
			emitter.ACTION_GET_STRANGER_INFO:     `{"status":"ok","retcode":0,"data":{"user_id":1001,"nickname":"陌生的爱丽丝"}}`,
		},
		errs: map[emitter.Action]error{},
	}
}

func lookupRuntime(fake *onebotLookupFake) (*onebotRuntime, *onebotRuntimeCore) {
	core := &onebotRuntimeCore{inboundCh: make(chan adapterapi.InboundMessage, 4)}
	return &onebotRuntime{core: core, outbound: fake, config: OnebotConfig{FriendRequestPolicy: "accept"}}, core
}

func deliver(t *testing.T, runtime *onebotRuntime, core *onebotRuntimeCore, raw string) adapterapi.InboundMessage {
	t.Helper()
	if err := runtime.handleInbound(context.Background(), []byte(raw)); err != nil {
		t.Fatalf("handleInbound: %v", err)
	}
	select {
	case message := <-core.inboundCh:
		return message
	default:
		t.Fatal("event did not reach Core")
		return adapterapi.InboundMessage{}
	}
}

func TestOnebotEventsCarryTheNamesTheProviderCanTell(t *testing.T) {
	tests := []struct {
		name                    string
		raw                     string
		wantSender, wantSubject string
		wantGroup               string
		wantActions             []emitter.Action
	}{
		{
			name:       "a group poke names the poker's group card and the group",
			raw:        `{"post_type":"notice","notice_type":"notify","sub_type":"poke","group_id":2002,"user_id":1001,"target_id":3003,"time":1700000000,"self_id":3003}`,
			wantSender: "群里的爱丽丝", wantGroup: "测试群",
			wantActions: []emitter.Action{emitter.ACTION_GET_GROUP_INFO, emitter.ACTION_GET_GROUP_MEMBER_INFO},
		},
		{
			name:       "a new member is named once, as sender and subject",
			raw:        `{"post_type":"notice","notice_type":"group_increase","group_id":2002,"user_id":1001,"operator_id":4004,"time":1700000000,"self_id":3003}`,
			wantSender: "群里的爱丽丝", wantSubject: "群里的爱丽丝", wantGroup: "测试群",
			wantActions: []emitter.Action{emitter.ACTION_GET_GROUP_INFO, emitter.ACTION_GET_GROUP_MEMBER_INFO},
		},
		{
			name:       "the bot joining names the group and its inviter",
			raw:        `{"post_type":"notice","notice_type":"group_increase","sub_type":"invite","group_id":2002,"user_id":3003,"operator_id":1001,"time":1700000000,"self_id":3003}`,
			wantSender: "群里的爱丽丝", wantGroup: "测试群",
			wantActions: []emitter.Action{emitter.ACTION_GET_GROUP_INFO, emitter.ACTION_GET_GROUP_MEMBER_INFO},
		},
		{
			name:       "a friend request names the requester from their profile",
			raw:        `{"post_type":"request","request_type":"friend","flag":"f-1","user_id":1001,"time":1700000000,"self_id":3003}`,
			wantSender: "陌生的爱丽丝", wantActions: []emitter.Action{emitter.ACTION_GET_STRANGER_INFO},
		},
		{
			name:       "a new friend is named from their profile",
			raw:        `{"post_type":"notice","notice_type":"friend_add","user_id":1001,"time":1700000000,"self_id":3003}`,
			wantSender: "陌生的爱丽丝", wantSubject: "陌生的爱丽丝", wantActions: []emitter.Action{emitter.ACTION_GET_STRANGER_INFO},
		},
		{
			name:       "a group invitation names the group and the inviter",
			raw:        `{"post_type":"request","request_type":"group","sub_type":"invite","flag":"g-1","group_id":2002,"user_id":1001,"time":1700000000,"self_id":3003}`,
			wantSender: "陌生的爱丽丝", wantGroup: "测试群",
			wantActions: []emitter.Action{emitter.ACTION_GET_GROUP_INFO, emitter.ACTION_GET_STRANGER_INFO},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := newLookupFake()
			runtime, core := lookupRuntime(fake)
			got := deliver(t, runtime, core, tt.raw)
			if got.SenderName != tt.wantSender || got.SubjectName != tt.wantSubject || got.ConversationName != tt.wantGroup {
				t.Fatalf("names = sender %q subject %q group %q, want %q %q %q", got.SenderName, got.SubjectName, got.ConversationName, tt.wantSender, tt.wantSubject, tt.wantGroup)
			}
			if actions := fake.actions(); len(actions) != len(tt.wantActions) {
				t.Fatalf("lookups = %v, want %v", actions, tt.wantActions)
			} else {
				for i := range actions {
					if actions[i] != tt.wantActions[i] {
						t.Fatalf("lookups = %v, want %v", actions, tt.wantActions)
					}
				}
			}
		})
	}
}

func TestOnebotFallsBackToTheNicknameWhenTheGroupCardIsEmpty(t *testing.T) {
	fake := newLookupFake()
	fake.responses[emitter.ACTION_GET_GROUP_MEMBER_INFO] = `{"status":"ok","retcode":0,"data":{"user_id":1001,"nickname":"爱丽丝","card":""}}`
	runtime, core := lookupRuntime(fake)
	got := deliver(t, runtime, core, `{"post_type":"notice","notice_type":"notify","sub_type":"poke","group_id":2002,"user_id":1001,"target_id":3003,"time":1700000000,"self_id":3003}`)
	if got.SenderName != "爱丽丝" {
		t.Fatalf("SenderName = %q, want the nickname", got.SenderName)
	}
}

func TestOnebotLookupsAskForTheRightMembersAndGroups(t *testing.T) {
	fake := newLookupFake()
	runtime, core := lookupRuntime(fake)
	deliver(t, runtime, core, `{"post_type":"notice","notice_type":"notify","sub_type":"poke","group_id":2002,"user_id":1001,"target_id":3003,"time":1700000000,"self_id":3003}`)
	if params, ok := fake.paramsOf(emitter.ACTION_GET_GROUP_INFO).(emitterTypes.GetGroupInfoReq); !ok || params.GroupId != 2002 {
		t.Fatalf("group lookup = %#v", fake.paramsOf(emitter.ACTION_GET_GROUP_INFO))
	}
	if params, ok := fake.paramsOf(emitter.ACTION_GET_GROUP_MEMBER_INFO).(emitterTypes.GetGroupMemberInfoReq); !ok || params.GroupId != 2002 || params.UserId != 1001 {
		t.Fatalf("member lookup = %#v", fake.paramsOf(emitter.ACTION_GET_GROUP_MEMBER_INFO))
	}
}

func TestOnebotEventsAboutLeavingARoomNeverQueryTheProvider(t *testing.T) {
	for name, raw := range map[string]string{
		"left":    `{"post_type":"notice","notice_type":"group_decrease","sub_type":"leave","group_id":2002,"user_id":3003,"operator_id":3003,"time":1700000000,"self_id":3003}`,
		"kicked":  `{"post_type":"notice","notice_type":"group_decrease","sub_type":"kick_me","group_id":2002,"user_id":3003,"operator_id":1001,"time":1700000000,"self_id":3003}`,
		"message": `{"post_type":"message","message_type":"private","message_id":7,"user_id":1001,"message":[{"type":"text","data":{"text":"hi"}}],"sender":{"user_id":1001,"nickname":"爱丽丝"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			fake := newLookupFake()
			runtime, core := lookupRuntime(fake)
			deliver(t, runtime, core, raw)
			if actions := fake.actions(); len(actions) != 0 {
				t.Fatalf("queried %v although the answer is unavailable or already in the payload", actions)
			}
		})
	}
}

func TestOnebotEventStillReachesCoreWhenLookupsFailOrHang(t *testing.T) {
	raw := `{"post_type":"notice","notice_type":"notify","sub_type":"poke","group_id":2002,"user_id":1001,"target_id":3003,"time":1700000000,"self_id":3003}`

	failing := newLookupFake()
	failing.errs[emitter.ACTION_GET_GROUP_INFO] = errors.New("provider unavailable")
	failing.errs[emitter.ACTION_GET_GROUP_MEMBER_INFO] = errors.New("provider unavailable")
	runtime, core := lookupRuntime(failing)
	got := deliver(t, runtime, core, raw)
	if got.SenderName != "" || got.ConversationName != "" || got.Event != adapterapi.InboundEventPoke {
		t.Fatalf("a failed lookup must leave names empty and keep the event, got %#v", got)
	}

	rejected := newLookupFake()
	rejected.responses[emitter.ACTION_GET_GROUP_INFO] = `{"status":"failed","retcode":1404,"data":null}`
	rejected.responses[emitter.ACTION_GET_GROUP_MEMBER_INFO] = `not json`
	runtime, core = lookupRuntime(rejected)
	if got = deliver(t, runtime, core, raw); got.SenderName != "" || got.ConversationName != "" {
		t.Fatalf("a rejected or malformed answer must not name anything, got %#v", got)
	}

	hanging := newLookupFake()
	hanging.block = true
	runtime, core = lookupRuntime(hanging)
	runtime.lookupBudget = 80 * time.Millisecond
	started := time.Now()
	got = deliver(t, runtime, core, raw)
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("a hanging provider stalled the event worker for %s", elapsed)
	}
	if got.SenderName != "" || got.Event != adapterapi.InboundEventPoke {
		t.Fatalf("a timed-out lookup must still deliver the event, got %#v", got)
	}
}

func TestOnebotMessagesNameTheirSenderFromThePayload(t *testing.T) {
	tests := []struct {
		name, raw, want string
	}{
		{"group card wins", `{"post_type":"message","message_type":"group","message_id":8,"group_id":2002,"user_id":1001,"message":[{"type":"text","data":{"text":"hi"}}],"sender":{"user_id":1001,"nickname":"爱丽丝","card":"群里的爱丽丝","role":"member"}}`, "群里的爱丽丝"},
		{"nickname when the card is empty", `{"post_type":"message","message_type":"group","message_id":9,"group_id":2002,"user_id":1001,"message":[{"type":"text","data":{"text":"hi"}}],"sender":{"user_id":1001,"nickname":"爱丽丝","card":""}}`, "爱丽丝"},
		{"private nickname", `{"post_type":"message","message_type":"private","message_id":10,"user_id":1001,"message":[{"type":"text","data":{"text":"hi"}}],"sender":{"user_id":1001,"nickname":"爱丽丝"}}`, "爱丽丝"},
		{"no sender object", `{"post_type":"message","message_type":"private","message_id":11,"user_id":1001,"message":[{"type":"text","data":{"text":"hi"}}]}`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runtime, core := lookupRuntime(newLookupFake())
			if got := deliver(t, runtime, core, tt.raw); got.SenderName != tt.want {
				t.Fatalf("SenderName = %q, want %q", got.SenderName, tt.want)
			}
		})
	}
}

func TestOnebotQueriesTheBotsRoleInAGroup(t *testing.T) {
	request := adapterapi.QueryRequest{EndpointID: "endpoint-1", Kind: adapterapi.QueryKindMemberRole, Group: "QQ-Group:2002", Member: "QQ:3003", Fresh: true}
	for provider, want := range map[string]string{"owner": "owner", "admin": "admin", "member": "member", "administrator": "admin", "normal": "member"} {
		fake := newLookupFake()
		fake.responses[emitter.ACTION_GET_GROUP_MEMBER_INFO] = `{"status":"ok","retcode":0,"data":{"user_id":3003,"role":"` + provider + `"}}`
		runtime, _ := lookupRuntime(fake)
		result, err := runtime.Query(context.Background(), request)
		if err != nil || result.Role != want {
			t.Fatalf("provider role %q -> %#v, %v; want %q", provider, result, err, want)
		}
		params, ok := fake.paramsOf(emitter.ACTION_GET_GROUP_MEMBER_INFO).(emitterTypes.GetGroupMemberInfoReq)
		if !ok || params.GroupId != 2002 || params.UserId != 3003 || !params.NoCache {
			t.Fatalf("provider request = %#v; a fresh query must bypass the provider cache", fake.paramsOf(emitter.ACTION_GET_GROUP_MEMBER_INFO))
		}
	}
	fake := newLookupFake()
	runtime, _ := lookupRuntime(fake)
	cached := request
	cached.Fresh = false
	if _, err := runtime.Query(context.Background(), cached); err != nil {
		t.Fatal(err)
	}
	if params := fake.paramsOf(emitter.ACTION_GET_GROUP_MEMBER_INFO).(emitterTypes.GetGroupMemberInfoReq); params.NoCache {
		t.Fatal("a non-fresh query asked the provider to bypass its cache")
	}
}

func TestOnebotRoleQueryFailsClosedWithoutGuessing(t *testing.T) {
	request := adapterapi.QueryRequest{EndpointID: "endpoint-1", Kind: adapterapi.QueryKindMemberRole, Group: "QQ-Group:2002", Member: "QQ:3003"}
	cases := map[string]func(*onebotLookupFake){
		"provider error": func(f *onebotLookupFake) { f.errs[emitter.ACTION_GET_GROUP_MEMBER_INFO] = errors.New("down") },
		"provider rejection": func(f *onebotLookupFake) {
			f.responses[emitter.ACTION_GET_GROUP_MEMBER_INFO] = `{"status":"failed","retcode":1404}`
		},
		"malformed answer": func(f *onebotLookupFake) { f.responses[emitter.ACTION_GET_GROUP_MEMBER_INFO] = `{` },
		"missing role": func(f *onebotLookupFake) {
			f.responses[emitter.ACTION_GET_GROUP_MEMBER_INFO] = `{"status":"ok","retcode":0,"data":{"user_id":3003}}`
		},
		"unrecognized role": func(f *onebotLookupFake) {
			f.responses[emitter.ACTION_GET_GROUP_MEMBER_INFO] = `{"status":"ok","retcode":0,"data":{"role":"supreme"}}`
		},
		"empty provider reply": func(f *onebotLookupFake) { f.responses[emitter.ACTION_GET_GROUP_MEMBER_INFO] = `` },
	}
	for name, mutate := range cases {
		fake := newLookupFake()
		mutate(fake)
		runtime, _ := lookupRuntime(fake)
		if result, err := runtime.Query(context.Background(), request); err == nil {
			t.Errorf("%s: answered %#v instead of failing", name, result)
		}
	}

	if _, err := (&onebotRuntime{}).Query(context.Background(), request); err == nil {
		t.Error("a runtime without a provider connection answered a query")
	}
	runtime, _ := lookupRuntime(newLookupFake())
	for name, bad := range map[string]adapterapi.QueryRequest{
		"guild group":      {EndpointID: "endpoint-1", Kind: adapterapi.QueryKindMemberRole, Group: "QQ-CH-Group:1-2", Member: "QQ:3003"},
		"non-numeric user": {EndpointID: "endpoint-1", Kind: adapterapi.QueryKindMemberRole, Group: "QQ-Group:2002", Member: "QQ:bot"},
		"foreign platform": {EndpointID: "endpoint-1", Kind: adapterapi.QueryKindMemberRole, Group: "TG-Group:2002", Member: "QQ:3003"},
	} {
		if _, err := runtime.Query(context.Background(), bad); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
