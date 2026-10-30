package dice

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/groupstate"
	"Scardice-core/core/messageflow"
	"Scardice-core/core/playerstate"
	"Scardice-core/endpoint"
)

type observedCallbackAdmission struct {
	*DurableCallbackHost
	waiting chan struct{}
	entries atomic.Int32
}

func (h *observedCallbackAdmission) BeginCallback(ctx context.Context) (context.Context, func(), error) {
	if h.entries.Add(1) == 2 {
		close(h.waiting)
	}
	return any(h.DurableCallbackHost).(interface {
		BeginCallback(context.Context) (context.Context, func(), error)
	}).BeginCallback(ctx)
}

type observedCallbackLoader struct {
	messageflow.CallbackGroupLoader
	second chan struct{}
	loads  atomic.Int32
}

func (l *observedCallbackLoader) Load(ctx context.Context, diceID, groupID string) (groupstate.State, error) {
	state, err := l.CallbackGroupLoader.Load(ctx, diceID, groupID)
	if l.loads.Add(1) == 2 {
		close(l.second)
	}
	return state, err
}

func TestDurableCallbacksAcrossEndpointsLoadInsideAdmission(t *testing.T) {
	store, _ := repairTestStore(t)
	d, ep, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	d.DurableStore = store
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	var calls atomic.Int32
	d.CmdMap["increment"] = &CmdItemInfo{Name: "increment", Raw: true, Solve: func(ctx *MsgContext, _ *Message, _ *CmdArgs) CmdExecuteResult {
		if calls.Add(1) == 1 {
			close(started)
			<-release
		}
		ctx.Group.DiceSideNum++
		return CmdExecuteResult{Matched: true, Solved: true}
	}}
	inbound, err := messageflow.NewInboundService(store, store)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{ep.ID, "second-endpoint"} {
		_, err := inbound.HandleInbound(context.Background(), endpoint.FencedInbound{EndpointID: adapterapi.EndpointID(id), Generation: 1, DesiredVersion: 1, Message: adapterapi.InboundMessage{ProviderEventID: adapterapi.ProviderEventID(id), MessageID: adapterapi.MessageID(id), Kind: adapterapi.InboundKindMessage, ConversationKind: adapterapi.ConversationKindGroup, Platform: "QQ", Sender: "QQ:1001", Conversation: "QQ-Group:2002", Target: ep.UserID, Text: ".increment"}})
		if err != nil {
			t.Fatal(err)
		}
	}
	host := &observedCallbackAdmission{DurableCallbackHost: NewDurableCallbackHost(d), waiting: make(chan struct{})}
	loader := &observedCallbackLoader{CallbackGroupLoader: groupstate.NewRepository(store), second: make(chan struct{})}
	makeService := func(worker string) *messageflow.CallbackService {
		service, err := messageflow.NewCallbackService(messageflow.CallbackConfig{Inbox: store, Store: store, BoundCodec: store, Resolver: NewDurableCallbackScopeResolver(d), Group: loader, Player: playerstate.NewRepository(store), Host: host, WorkerID: worker})
		if err != nil {
			t.Fatal(err)
		}
		return service
	}
	first, second := makeService("one"), makeService("two")
	results := make(chan error, 2)
	go func() { _, err := first.ProcessOne(context.Background()); results <- err }()
	select {
	case <-started:
	case err := <-results:
		t.Fatalf("first callback: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("first callback did not execute")
	}
	go func() { _, err := second.ProcessOne(context.Background()); results <- err }()
	select {
	case <-host.waiting:
	case <-loader.second:
	case <-time.After(5 * time.Second):
		t.Fatal("second callback did not enter admission or loading")
	}
	once.Do(func() { close(release) })
	for range 2 {
		select {
		case err := <-results:
			if err != nil {
				t.Errorf("callback failed: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("callback stuck")
		}
	}
	state, err := groupstate.NewRepository(store).Load(context.Background(), d.BaseConfig.Name, "QQ-Group:2002")
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || state.DiceSideNum != 2 {
		t.Fatalf("callbacks=%d final dice sides=%d, want two committed increments", calls.Load(), state.DiceSideNum)
	}
}
