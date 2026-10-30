package dice

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	dingtalk "github.com/Szzrain/DingTalk-go"
	"github.com/open-dingtalk/dingtalk-stream-sdk-go/chatbot"

	"Scardice-core/adapterapi"
	"Scardice-core/adapterapi/contracttest"
)

func TestDingTalkDescriptorOwnsSessionLifecycleIngressAndOutbound(t *testing.T) {
	descriptor := NewDingTalkDescriptor()
	config, err := descriptor.ValidateConfig(context.Background(), json.RawMessage(`{"clientId":"client-1","robotCode":"robot-1","coolAppCode":"cool-1","stream":true,"token":{"secretRef":"dingtalk-token","version":1}}`))
	if err != nil {
		t.Fatalf("validate config: %v", err)
	}
	runtimeRaw, err := descriptor.NewRuntime(adapterapi.RuntimeInit{EndpointID: "dingtalk-smoke", Generation: 1, DesiredVersion: 1, Config: config, Secrets: &onebotRuntimeResolver{bytes: []byte("runtime-token")}})
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	runtime := runtimeRaw.(*dingTalkRuntime)
	fake := &fakeDingTalkSession{}
	runtime.newSession = func(string, string) dingTalkSession { return fake }
	core := &onebotRuntimeCore{ch: make(chan adapterapi.LifecycleObservation, 8), inboundCh: make(chan adapterapi.InboundMessage, 1)}
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(context.Background(), core) }()
	core.waitState(t, adapterapi.ObservedStateConnected)
	fake.emit(&chatbot.BotCallbackDataModel{MsgId: "message-1", ConversationId: "group-1", ConversationType: "2", SenderStaffId: "user-1", SenderNick: "alice", Text: chatbot.BotCallbackDataTextModel{Content: "hello inbound"}})
	select {
	case inbound := <-core.inboundCh:
		if inbound.ProviderEventID != "dingtalk-message:message-1" || inbound.Conversation != "DINGTALK-Group:group-1" || inbound.ConversationKind != adapterapi.ConversationKindGroup || inbound.Text != "hello inbound" {
			t.Fatalf("inbound = %#v", inbound)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for DingTalk inbound")
	}
	effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadGroupText, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "DINGTALK-Group:group-1"}, Text: "hello outbound"}, adapterapi.CapabilityOutbound)
	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectSucceeded || result.ProviderID != "query-1" {
		t.Fatalf("result = %#v", result)
	}
	if err := runtime.Stop(context.Background()); err != nil {
		t.Fatalf("stop runtime: %v", err)
	}
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("run exit: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("DingTalk runtime did not stop")
	}
	if !fake.closed {
		t.Fatal("DingTalk session was not closed")
	}
}

func TestDingTalkDescriptorStampsAdminSenderRole(t *testing.T) {
	for _, tc := range []struct {
		name    string
		isAdmin bool
		want    string
	}{
		{name: "admin", isAdmin: true, want: "admin"},
		{name: "ordinary", isAdmin: false, want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			descriptor := NewDingTalkDescriptor()
			config, err := descriptor.ValidateConfig(context.Background(), json.RawMessage(`{"clientId":"client-1","robotCode":"robot-1","coolAppCode":"cool-1","stream":true,"token":{"secretRef":"dingtalk-token","version":1}}`))
			if err != nil {
				t.Fatalf("validate config: %v", err)
			}
			runtimeRaw, err := descriptor.NewRuntime(adapterapi.RuntimeInit{EndpointID: "dingtalk-role", Generation: 1, DesiredVersion: 1, Config: config, Secrets: &onebotRuntimeResolver{bytes: []byte("runtime-token")}})
			if err != nil {
				t.Fatalf("new runtime: %v", err)
			}
			runtime := runtimeRaw.(*dingTalkRuntime)
			fake := &fakeDingTalkSession{}
			runtime.newSession = func(string, string) dingTalkSession { return fake }
			core := &onebotRuntimeCore{ch: make(chan adapterapi.LifecycleObservation, 8), inboundCh: make(chan adapterapi.InboundMessage, 1)}
			runDone := make(chan error, 1)
			go func() { runDone <- runtime.Run(context.Background(), core) }()
			core.waitState(t, adapterapi.ObservedStateConnected)
			fake.emit(&chatbot.BotCallbackDataModel{MsgId: "message-role", ConversationId: "group-1", ConversationType: "2", SenderStaffId: "user-1", SenderNick: "alice", IsAdmin: tc.isAdmin, Text: chatbot.BotCallbackDataTextModel{Content: "hi"}})
			select {
			case inbound := <-core.inboundCh:
				if inbound.SenderRole != tc.want {
					t.Fatalf("SenderRole = %q, want %q", inbound.SenderRole, tc.want)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("timed out waiting for DingTalk inbound")
			}
			if err := runtime.Stop(context.Background()); err != nil {
				t.Fatalf("stop runtime: %v", err)
			}
			if err := <-runDone; err != nil && !errors.Is(err, context.Canceled) {
				t.Fatalf("runtime exit: %v", err)
			}
		})
	}
}

func TestDingTalkDescriptorSatisfiesRuntimeContract(t *testing.T) {
	contracttest.Verify(t, contracttest.Case{
		NewDescriptor:                NewDingTalkDescriptor,
		Config:                       json.RawMessage(`{"clientId":"client-1","robotCode":"robot-1","coolAppCode":"cool-1","stream":true,"token":{"secretRef":"dingtalk-token","version":1}}`),
		Init:                         adapterapi.RuntimeInit{EndpointID: "dingtalk-contract", Generation: 1, DesiredVersion: 1},
		SecretValues:                 []string{"runtime-token"},
		RequireOwnedResourceManifest: true,
	})
}

type fakeDingTalkSession struct {
	mu      sync.Mutex
	handler func(*dingtalk.Session, *chatbot.BotCallbackDataModel)
	closed  bool
}

func (session *fakeDingTalkSession) AddEventHandler(handler interface{}) func() {
	session.handler = handler.(func(*dingtalk.Session, *chatbot.BotCallbackDataModel))
	return func() {}
}
func (*fakeDingTalkSession) Open() error { return nil }
func (session *fakeDingTalkSession) Close() error {
	session.closed = true
	return nil
}
func (*fakeDingTalkSession) MessagePrivateSend(string, string, dingtalk.Message) (string, error) {
	return "query-private", nil
}
func (*fakeDingTalkSession) MessageGroupSend(string, string, string, dingtalk.Message) (string, error) {
	return "query-1", nil
}
func (session *fakeDingTalkSession) emit(data *chatbot.BotCallbackDataModel) {
	session.mu.Lock()
	handler := session.handler
	session.mu.Unlock()
	handler(nil, data)
}
