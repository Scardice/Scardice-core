package dice

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/sealdice/botgo/dto"

	qqevent "github.com/sealdice/botgo/event"

	"Scardice-core/adapterapi"
	"Scardice-core/adapterapi/contracttest"
	"Scardice-core/endpoint"
)

func TestAdapterDescriptorRegistryHasStableKeys(t *testing.T) {
	descriptors := NewAdapterDescriptors()
	want := []adapterapi.AdapterKey{
		"gocq", "lagrange", "walleq", "red", "official_qq", "satori", "milky", "discord", "kook",
		"telegram", "slack", "dodo", "dingtalk", "minecraft", "sealchat", "http", "pureonebot",
	}
	if len(descriptors) != len(want) {
		t.Fatalf("descriptor count = %d, want %d", len(descriptors), len(want))
	}
	registry := endpoint.NewRegistry()
	for i, descriptor := range descriptors {
		if descriptor == nil {
			t.Fatalf("descriptor %d is nil", i)
		}
		if got := descriptor.Key(); got != want[i] {
			t.Fatalf("descriptor %d key = %q, want %q", i, got, want[i])
		}
		if err := registry.Register(descriptor); err != nil {
			t.Fatalf("register %q: %v", descriptor.Key(), err)
		}
	}
	if _, ok := registry.Lookup(context.Background(), "pureonebot"); !ok {
		t.Fatal("registry did not expose pureonebot")
	}
}

func TestAdapterDescriptorRegistryUsesLiveRedRuntime(t *testing.T) {
	descriptor := descriptorForAdapterKey(t, RedAdapterKey)
	if _, ok := descriptor.(RedDescriptor); !ok {
		t.Fatalf("Red descriptor type = %T, want RedDescriptor", descriptor)
	}
}

func TestAdapterDescriptorRegistryUsesLiveOfficialQQRuntime(t *testing.T) {
	descriptor := descriptorForAdapterKey(t, OfficialQQAdapterKey)
	if _, ok := descriptor.(OfficialQQDescriptor); !ok {
		t.Fatalf("official QQ descriptor type = %T, want OfficialQQDescriptor", descriptor)
	}
}

func TestAdapterDescriptorRegistryUsesLiveSatoriRuntime(t *testing.T) {
	descriptor := descriptorForAdapterKey(t, SatoriAdapterKey)
	if _, ok := descriptor.(SatoriDescriptor); !ok {
		t.Fatalf("Satori descriptor type = %T, want SatoriDescriptor", descriptor)
	}
}

func TestAdapterDescriptorRegistryUsesLiveMilkyRuntime(t *testing.T) {
	descriptor := descriptorForAdapterKey(t, MilkyAdapterKey)
	if _, ok := descriptor.(MilkyDescriptor); !ok {
		t.Fatalf("Milky descriptor type = %T, want MilkyDescriptor", descriptor)
	}
}

func TestAdapterDescriptorRegistryUsesLiveDiscordRuntime(t *testing.T) {
	descriptor := descriptorForAdapterKey(t, DiscordAdapterKey)
	if _, ok := descriptor.(DiscordDescriptor); !ok {
		t.Fatalf("Discord descriptor type = %T, want DiscordDescriptor", descriptor)
	}
}

func TestAdapterDescriptorRegistryUsesLiveKookRuntime(t *testing.T) {
	descriptor := descriptorForAdapterKey(t, KookAdapterKey)
	if _, ok := descriptor.(KookDescriptor); !ok {
		t.Fatalf("Kook descriptor type = %T, want KookDescriptor", descriptor)
	}
}

func TestAdapterDescriptorRegistryUsesLiveTelegramRuntime(t *testing.T) {
	descriptor := descriptorForAdapterKey(t, TelegramAdapterKey)
	if _, ok := descriptor.(TelegramDescriptor); !ok {
		t.Fatalf("Telegram descriptor type = %T, want TelegramDescriptor", descriptor)
	}
}

func TestAdapterDescriptorRegistryUsesLiveSlackRuntime(t *testing.T) {
	descriptor := descriptorForAdapterKey(t, SlackAdapterKey)
	if _, ok := descriptor.(SlackDescriptor); !ok {
		t.Fatalf("Slack descriptor type = %T, want SlackDescriptor", descriptor)
	}
}

func TestAdapterDescriptorRegistryUsesLiveDodoRuntime(t *testing.T) {
	descriptor := descriptorForAdapterKey(t, DodoAdapterKey)
	if _, ok := descriptor.(DodoDescriptor); !ok {
		t.Fatalf("Dodo descriptor type = %T, want DodoDescriptor", descriptor)
	}
}

func TestAdapterDescriptorRegistryUsesLiveDingTalkRuntime(t *testing.T) {
	descriptor := descriptorForAdapterKey(t, DingTalkAdapterKey)
	if _, ok := descriptor.(DingTalkDescriptor); !ok {
		t.Fatalf("DingTalk descriptor type = %T, want DingTalkDescriptor", descriptor)
	}
}

func TestAdapterDescriptorRegistryUsesLiveMinecraftRuntime(t *testing.T) {
	descriptor := descriptorForAdapterKey(t, MinecraftAdapterKey)
	if _, ok := descriptor.(MinecraftDescriptor); !ok {
		t.Fatalf("Minecraft descriptor type = %T, want MinecraftDescriptor", descriptor)
	}
}

func TestAdapterDescriptorRegistryUsesLiveSealChatRuntime(t *testing.T) {
	descriptor := descriptorForAdapterKey(t, SealChatAdapterKey)
	if _, ok := descriptor.(SealChatDescriptor); !ok {
		t.Fatalf("SealChat descriptor type = %T, want SealChatDescriptor", descriptor)
	}
}

func TestAdapterDescriptorRegistryUsesLiveHTTPRuntime(t *testing.T) {
	descriptor := descriptorForAdapterKey(t, HTTPAdapterKey)
	if _, ok := descriptor.(HTTPDescriptor); !ok {
		t.Fatalf("HTTP descriptor type = %T, want HTTPDescriptor", descriptor)
	}
}

func TestGoCQDescriptorUsesExternalOnebotRuntime(t *testing.T) {
	contracttest.Verify(t, contracttest.Case{
		NewDescriptor: NewGocqDescriptor,
		Config:        json.RawMessage(`{"connectUrl":"ws://127.0.0.1:1/ws","token":{"secretRef":"gocq-token","version":1}}`),
		Init: adapterapi.RuntimeInit{
			EndpointID:     "gocq-contract",
			Generation:     1,
			DesiredVersion: 1,
			ResourceRoot:   t.TempDir(),
		},
		RequireOwnedResourceManifest: true,
	})
}

func TestGoCQDescriptorMigratesReverseListenerMode(t *testing.T) {
	descriptor := NewGocqDescriptor()
	config, err := descriptor.ValidateConfig(context.Background(), json.RawMessage(`{"isReverse":true,"reverseAddr":"127.0.0.1:19000"}`))
	if err != nil {
		t.Fatalf("validate reverse config: %v", err)
	}
	runtime, err := descriptor.NewRuntime(adapterapi.RuntimeInit{
		EndpointID:     "gocq-reverse",
		Generation:     1,
		DesiredVersion: 1,
		Config:         config,
	})
	if err != nil {
		t.Fatalf("new reverse runtime: %v", err)
	}
	onebot, ok := runtime.(*onebotRuntime)
	if !ok {
		t.Fatalf("reverse runtime type = %T, want *onebotRuntime", runtime)
	}
	if onebot.config.Mode != "server" || onebot.config.ListenAddress != "127.0.0.1:19000" {
		t.Fatalf("reverse runtime config = %#v", onebot.config)
	}
}

func TestLagrangeDescriptorUsesExternalOnebotRuntime(t *testing.T) {
	contracttest.Verify(t, contracttest.Case{
		NewDescriptor: NewLagrangeDescriptor,
		Config:        json.RawMessage(`{"connectUrl":"ws://127.0.0.1:1/ws","token":{"secretRef":"lagrange-token","version":1}}`),
		Init: adapterapi.RuntimeInit{
			EndpointID:     "lagrange-contract",
			Generation:     1,
			DesiredVersion: 1,
			ResourceRoot:   t.TempDir(),
		},
		RequireOwnedResourceManifest: true,
	})
}

func TestLagrangeDescriptorAcceptsBuiltInMode(t *testing.T) {
	descriptor := NewLagrangeDescriptor()
	config, err := descriptor.ValidateConfig(context.Background(), json.RawMessage(`{"useInPackGoCqhttp":true,"builtinMode":"lagrange","accountHint":"QQ:12345","signServerVersion":"41857","signServerName":"RSign"}`))
	if err != nil {
		t.Fatalf("validate built-in Lagrange config: %v", err)
	}
	if actions := descriptor.SupportedActions(config); !actions.Has(adapterapi.ActionKindRequestQRCode) {
		t.Fatalf("built-in Lagrange actions = %#v", actions)
	}
	runtime, err := descriptor.NewRuntime(adapterapi.RuntimeInit{
		EndpointID:     "lagrange-builtin",
		Generation:     1,
		DesiredVersion: 1,
		Config:         config,
		ResourceRoot:   t.TempDir(),
	})
	if err != nil {
		t.Fatalf("new built-in Lagrange runtime: %v", err)
	}
	if _, ok := runtime.(*builtinProcessRuntime); !ok {
		t.Fatalf("built-in Lagrange runtime type = %T", runtime)
	}
}

func TestGoCQDescriptorAcceptsBuiltInMode(t *testing.T) {
	descriptor := NewGocqDescriptor()
	config, err := descriptor.ValidateConfig(context.Background(), json.RawMessage(`{"useInPackGoCqhttp":true,"builtinMode":"gocq","account":"12345"}`))
	if err != nil {
		t.Fatalf("validate built-in GoCQ config: %v", err)
	}
	if _, err := descriptor.NewRuntime(adapterapi.RuntimeInit{
		EndpointID:     "gocq-builtin",
		Generation:     1,
		DesiredVersion: 1,
		Config:         config,
		ResourceRoot:   t.TempDir(),
	}); err != nil {
		t.Fatalf("new built-in GoCQ runtime: %v", err)
	}
}

func TestMilkyDescriptorAcceptsBuiltInMode(t *testing.T) {
	descriptor := NewMilkyDescriptor()
	config, err := descriptor.ValidateConfig(context.Background(), json.RawMessage(`{"version":"1","built_in_mode":"yogurt","account":"QQ:12345"}`))
	if err != nil {
		t.Fatalf("validate built-in Milky config: %v", err)
	}
	if actions := descriptor.SupportedActions(config); !actions.Has(adapterapi.ActionKindRequestQRCode) {
		t.Fatalf("built-in Milky actions = %#v", actions)
	}
	runtime, err := descriptor.NewRuntime(adapterapi.RuntimeInit{
		EndpointID:     "milky-builtin",
		Generation:     1,
		DesiredVersion: 1,
		Config:         config,
		ResourceRoot:   t.TempDir(),
	})
	if err != nil {
		t.Fatalf("new built-in Milky runtime: %v", err)
	}
	if _, ok := runtime.(*builtinProcessRuntime); !ok {
		t.Fatalf("built-in Milky runtime type = %T", runtime)
	}
}

func TestGoCQDescriptorRejectsNullControlFields(t *testing.T) {
	descriptor := NewGocqDescriptor()
	if _, err := descriptor.ValidateConfig(context.Background(), json.RawMessage(`{"connectUrl":"ws://127.0.0.1:1/ws","useInPackGoCqhttp":null}`)); err == nil {
		t.Fatal("GoCQ descriptor accepted null built-in mode control")
	}
}

func TestAdapterRegistryUsesLiveGoCQDescriptor(t *testing.T) {
	if _, ok := descriptorForAdapterKey(t, GocqAdapterKey).(GocqDescriptor); !ok {
		t.Fatal("gocq registry entry is not the live external descriptor")
	}
}

func TestOfficialQQDescriptorCanonicalizesCredentialReferences(t *testing.T) {
	descriptor := NewOfficialQQDescriptor()
	validated, err := descriptor.ValidateConfig(context.Background(), json.RawMessage(`{"appId":12345,"appSecret":{"secretRef":"official-app-secret","version":2},"token":{"secretRef":"official-token","version":3},"onlyQQGuild":true}`))
	if err != nil {
		t.Fatalf("validate config: %v", err)
	}
	if err := validated.Validate(); err != nil {
		t.Fatalf("validated config: %v", err)
	}
	if string(validated.Canonical) != `{"appId":12345,"appSecret":{"secretRef":"official-app-secret","version":2},"onlyQQGuild":true,"token":{"secretRef":"official-token","version":3}}` {
		t.Fatalf("canonical config = %s", validated.Canonical)
	}
	if len(validated.SecretRefs) != 2 {
		t.Fatalf("secret refs = %#v", validated.SecretRefs)
	}
}

func TestOfficialQQDescriptorConstructsRuntimeWithoutResolvingSecrets(t *testing.T) {
	descriptor := NewOfficialQQDescriptor()
	config, err := descriptor.ValidateConfig(context.Background(), json.RawMessage(`{"appId":12345,"appSecret":{"secretRef":"official-app-secret","version":2},"token":{"secretRef":"official-token","version":3}}`))
	if err != nil {
		t.Fatalf("validate config: %v", err)
	}
	runtime, err := descriptor.NewRuntime(adapterapi.RuntimeInit{
		EndpointID:     "official-qq-contract",
		Generation:     1,
		DesiredVersion: 1,
		Config:         config,
		Secrets:        noCallSecretResolver{},
	})
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	if runtime == nil {
		t.Fatal("new runtime returned nil")
	}
	manifestRuntime, ok := runtime.(adapterapi.OwnedResourceManifestRuntime)
	if !ok {
		t.Fatal("official QQ runtime does not declare owned resources")
	}
	if err := manifestRuntime.OwnedResources().Validate(); err != nil {
		t.Fatalf("owned resources: %v", err)
	}
	if runtime.(*officialQQRuntime).appID != 12345 {
		t.Fatalf("runtime appId = %d", runtime.(*officialQQRuntime).appID)
	}
	if runtime.(*officialQQRuntime).appSecret.Ref != "official-app-secret" || runtime.(*officialQQRuntime).token.Ref != "official-token" {
		t.Fatalf("runtime secret refs = %#v %#v", runtime.(*officialQQRuntime).appSecret, runtime.(*officialQQRuntime).token)
	}
	if runtime.(*officialQQRuntime).onlyQQGuild {
		t.Fatal("runtime onlyQQGuild = true")
	}
	if got := runtime.Capabilities(); got != adapterapi.CapabilityLifecycle|adapterapi.CapabilityInbound|adapterapi.CapabilityOutbound|adapterapi.CapabilityActions|adapterapi.CapabilityArtifacts|adapterapi.CapabilityRichMessages {
		t.Fatalf("runtime capabilities = %#x", got)
	}
}

func TestOfficialQQRuntimeRejectsMissingAppSecretResolver(t *testing.T) {
	runtime := &officialQQRuntime{
		appSecret: adapterapi.SecretRef{Ref: "official-app-secret", Version: 2},
	}
	if _, err := runtime.resolveAppSecret(context.Background()); err == nil {
		t.Fatal("runtime accepted a missing secret resolver")
	}
}

func TestOfficialQQRuntimeRunFailsBeforeNetworkWithoutAppSecret(t *testing.T) {
	runtime := &officialQQRuntime{appID: 12345, appSecret: adapterapi.SecretRef{Ref: "official-app-secret", Version: 2}, queue: newOfficialQQEventQueue()}
	if err := runtime.Run(context.Background(), &officialQQIngressCore{}); err == nil {
		t.Fatal("runtime started without an app-secret resolver")
	}
}
func TestOfficialQQRuntimeStopClosesQueueAdmission(t *testing.T) {
	runtime := &officialQQRuntime{queue: newOfficialQQEventQueue()}
	if !runtime.enqueue(func() {}) {
		t.Fatal("runtime rejected event before stop")
	}
	if err := runtime.Stop(context.Background()); err != nil {
		t.Fatalf("stop runtime: %v", err)
	}
	executed := false
	if runtime.enqueue(func() { executed = true }) {
		t.Fatal("runtime accepted event after stop")
	}
	if executed {
		t.Fatal("runtime executed an event after stop")
	}
}

func TestOfficialQQRuntimeRunReportsSecretFreeFailure(t *testing.T) {
	runtime := &officialQQRuntime{appID: 12345, appSecret: adapterapi.SecretRef{Ref: "official-app-secret", Version: 2}, queue: newOfficialQQEventQueue()}
	core := &officialQQIngressCore{}
	if err := runtime.Run(context.Background(), core); err == nil {
		t.Fatal("runtime started without an app-secret resolver")
	}
	if core.observation.State != adapterapi.ObservedStateFailed || core.observation.Code != "runtime_failed" || core.observation.Detail != "Official QQ runtime failed" {
		t.Fatalf("failure observation = %#v", core.observation)
	}
}

func TestOfficialQQRuntimeRequestQRCodeReturnsEphemeralArtifact(t *testing.T) {
	runtime := &officialQQRuntime{
		qrClient:  officialQQQRClientFunc(func(context.Context, string) (string, error) { return "task-1", nil }),
		qrEncoder: func(string) ([]byte, error) { return []byte("qr-bytes"), nil },
	}
	result, err := runtime.ExecuteAction(context.Background(), adapterapi.ActionRequest{Kind: adapterapi.ActionRequestQRCode})
	if err != nil {
		t.Fatalf("request QR: %v", err)
	}
	if result.Artifact == nil || string(result.Artifact.Plaintext) != "qr-bytes" || result.Artifact.SafeFilename != "official-qq-qr.png" {
		t.Fatalf("QR result = %#v", result)
	}

	runtime.qrEncoder = nil
	result, err = runtime.ExecuteAction(context.Background(), adapterapi.ActionRequest{Kind: adapterapi.ActionRequestQRCode})
	if err != nil {
		t.Fatalf("request QR URL fallback: %v", err)
	}
	if result.Artifact == nil ||
		result.Artifact.MediaType != "text/plain" ||
		result.Artifact.SafeFilename != "official-qq-qr.txt" ||
		string(result.Artifact.Plaintext) != "https://q.qq.com/qqbot/connect.html?task_id=task-1&source=scardice&_wv=2" {
		t.Fatalf("QR URL fallback = %#v", result)
	}
}

func TestOfficialQQRuntimeReportsVerifiedIdentity(t *testing.T) {
	core := &officialQQIngressCore{}
	if err := reportOfficialQQVerifiedIdentity(context.Background(), core, &dto.User{ID: "verified-uin"}); err != nil {
		t.Fatalf("report verified identity: %v", err)
	}
	if core.observation.Kind != adapterapi.LifecycleObservationIdentity ||
		core.observation.State != adapterapi.ObservedStateConnected ||
		core.observation.ProviderID != adapterapi.PrincipalID("verified-uin") {
		t.Fatalf("identity observation = %#v", core.observation)
	}
}

func TestOfficialQQChannelInboundNormalizesProviderMessage(t *testing.T) {
	data := dto.WSATMessageData(dto.Message{
		ID:        "message-1",
		GuildID:   "guild-1",
		ChannelID: "channel-1",
		Content:   "hello",
		Timestamp: dto.Timestamp("2026-09-06T12:00:00Z"),
		Author:    &dto.User{ID: "user-1"},
	})
	inbound, err := officialQQChannelInbound(&data)
	if err != nil {
		t.Fatalf("convert inbound: %v", err)
	}
	if inbound.ProviderEventID != "message-1" || inbound.MessageID != "message-1" || inbound.Sender != "OpenQQCH:user-1" || inbound.Conversation != "OpenQQCH-Channel:guild-1-channel-1" || inbound.Text != "hello" {
		t.Fatalf("inbound = %#v", inbound)
	}
	if err := inbound.Validate(); err != nil {
		t.Fatalf("inbound validate: %v", err)
	}
}

func TestOfficialQQRuntimeHandsChannelIngressToCore(t *testing.T) {
	runtime := &officialQQRuntime{queue: newOfficialQQEventQueue()}
	core := &officialQQIngressCore{}
	data := dto.WSATMessageData(dto.Message{
		ID:        "message-1",
		GuildID:   "guild-1",
		ChannelID: "channel-1",
		Content:   "hello",
		Timestamp: dto.Timestamp("2026-09-06T12:00:00Z"),
		Author:    &dto.User{ID: "user-1"},
	})
	if err := runtime.handleChannelInbound(context.Background(), core, &data); err != nil {
		t.Fatalf("handle channel inbound: %v", err)
	}
	if core.inbound.Text != "hello" || core.inbound.Conversation != "OpenQQCH-Channel:guild-1-channel-1" {
		t.Fatalf("core inbound = %#v", core.inbound)
	}
}

func TestOfficialQQDirectInboundNormalizesProviderMessage(t *testing.T) {
	data := dto.WSDirectMessageData(dto.Message{
		ID:        "message-2",
		GuildID:   "guild-1",
		ChannelID: "direct-channel-1",
		Content:   "private hello",
		Timestamp: dto.Timestamp("2026-09-06T12:00:00Z"),
		Author:    &dto.User{ID: "user-2"},
	})
	inbound, err := officialQQDirectInbound(&data)
	if err != nil {
		t.Fatalf("convert inbound: %v", err)
	}
	if inbound.ProviderEventID != "message-2" || inbound.Sender != "OpenQQCH:user-2" || inbound.Conversation != "OpenQQCH-Channel:guild-1-direct-channel-1" || inbound.Text != "private hello" {
		t.Fatalf("inbound = %#v", inbound)
	}
	if err := inbound.Validate(); err != nil {
		t.Fatalf("inbound validate: %v", err)
	}
}

func TestOfficialQQGroupInboundUsesAccountNamespacedIdentity(t *testing.T) {
	data := dto.WSGroupATMessageData(dto.Message{
		ID: "message-3", GroupOpenID: "group-1", Content: "group hello",
		Timestamp: dto.Timestamp("2026-09-06T12:00:00Z"),
		Author:    &dto.User{MemberOpenID: "member-1"},
	})
	inbound, err := officialQQGroupInbound(12345, &data)
	if err != nil {
		t.Fatalf("convert inbound: %v", err)
	}
	if inbound.Platform != "OpenQQ" || inbound.Sender != "OpenQQ-Member-T:12345-group-1-member-1" || inbound.Conversation != "OpenQQ-Group-T:12345-group-1" || inbound.Text != "group hello" {
		t.Fatalf("inbound = %#v", inbound)
	}
}

func TestOfficialQQGroupInboundCarriesMemberRole(t *testing.T) {
	cases := []struct {
		role string
		want string
	}{
		{role: "owner", want: "owner"},
		{role: "admin", want: "admin"},
		{role: "member", want: "member"},
		{role: "custom-title", want: ""},
		{role: "", want: ""},
	}
	for _, test := range cases {
		t.Run(test.role, func(t *testing.T) {
			data := dto.WSGroupATMessageData(dto.Message{
				ID: "message-role", GroupOpenID: "group-1", Content: "group hello",
				Timestamp: dto.Timestamp("2026-09-06T12:00:00Z"),
				Author:    &dto.User{MemberOpenID: "member-1", MemberRole: test.role},
			})
			inbound, err := officialQQGroupInbound(12345, &data)
			if err != nil {
				t.Fatalf("convert inbound: %v", err)
			}
			if inbound.SenderRole != test.want {
				t.Fatalf("sender role = %q, want %q", inbound.SenderRole, test.want)
			}
		})
	}
}

func TestOfficialQQGroupInboundWithoutMemberRoleOmitsRole(t *testing.T) {
	data := dto.WSGroupATMessageData(dto.Message{
		ID: "message-role-absent", GroupOpenID: "group-1", Content: "group hello",
		Timestamp: dto.Timestamp("2026-09-06T12:00:00Z"),
		Author:    &dto.User{MemberOpenID: "member-1"},
	})
	inbound, err := officialQQGroupInbound(12345, &data)
	if err != nil {
		t.Fatalf("convert inbound: %v", err)
	}
	if inbound.SenderRole != "" {
		t.Fatalf("sender role = %q, want empty", inbound.SenderRole)
	}
}

func TestOfficialQQChannelInboundOmitsMemberRole(t *testing.T) {
	data := dto.WSATMessageData(dto.Message{
		ID: "message-channel", GuildID: "guild-1", ChannelID: "channel-1", Content: "hello",
		Timestamp: dto.Timestamp("2026-09-06T12:00:00Z"),
		Author:    &dto.User{ID: "user-1", MemberRole: "owner"},
	})
	inbound, err := officialQQChannelInbound(&data)
	if err != nil {
		t.Fatalf("convert inbound: %v", err)
	}
	if inbound.SenderRole != "" {
		t.Fatalf("channel message carried group role %q", inbound.SenderRole)
	}
}

func TestOfficialQQRuntimeHandsGroupIngressToCore(t *testing.T) {
	runtime := &officialQQRuntime{appID: 12345, queue: newOfficialQQEventQueue()}
	core := &officialQQIngressCore{}
	data := dto.WSGroupATMessageData(dto.Message{
		ID: "message-3", GroupOpenID: "group-1", Content: "group hello",
		Timestamp: dto.Timestamp("2026-09-06T12:00:00Z"), Author: &dto.User{MemberOpenID: "member-1"},
	})
	if err := runtime.handleGroupInbound(context.Background(), core, &data); err != nil {
		t.Fatalf("handle group inbound: %v", err)
	}
	if core.inbound.Conversation != "OpenQQ-Group-T:12345-group-1" {
		t.Fatalf("core inbound = %#v", core.inbound)
	}
}

func TestOfficialQQRuntimeBuildsSDKChannelHandler(t *testing.T) {
	runtime := &officialQQRuntime{appID: 12345, queue: newOfficialQQEventQueue()}
	core := &officialQQIngressCore{}
	handler := runtime.channelAtMessageHandler(context.Background(), core)
	data := dto.WSATMessageData(dto.Message{
		ID: "message-4", GuildID: "guild-1", ChannelID: "channel-1", Content: "hello",
		Timestamp: dto.Timestamp("2026-09-06T12:00:00Z"), Author: &dto.User{ID: "user-1"},
	})
	if err := handler(nil, &data); err != nil {
		t.Fatalf("SDK handler: %v", err)
	}
	if core.inbound.MessageID != "message-4" {
		t.Fatalf("core inbound = %#v", core.inbound)
	}
}

func TestOfficialQQRuntimeBuildsSDKDirectAndGroupHandlers(t *testing.T) {
	runtime := &officialQQRuntime{appID: 12345, queue: newOfficialQQEventQueue()}
	core := &officialQQIngressCore{}
	direct := dto.WSDirectMessageData(dto.Message{
		ID: "message-5", GuildID: "guild-1", ChannelID: "channel-1",
		Timestamp: dto.Timestamp("2026-09-06T12:00:00Z"), Author: &dto.User{ID: "user-1"},
	})

	if err := runtime.directMessageHandler(context.Background(), core)(nil, &direct); err != nil {
		t.Fatalf("direct SDK handler: %v", err)
	}
	group := dto.WSGroupATMessageData(dto.Message{
		ID: "message-6", GroupOpenID: "group-1",
		Timestamp: dto.Timestamp("2026-09-06T12:00:00Z"), Author: &dto.User{MemberOpenID: "member-1"},
	})
	if err := runtime.groupAtMessageHandler(context.Background(), core)(nil, &group); err != nil {
		t.Fatalf("group SDK handler: %v", err)
	}
	if core.inbound.MessageID != "message-6" {
		t.Fatalf("core inbound = %#v", core.inbound)
	}
}
func TestOfficialQQAppIDDispatchDropsStaleGenerationPayload(t *testing.T) {
	first := &officialQQIngressCore{}
	second := &officialQQIngressCore{}
	firstRuntime := &officialQQRuntime{appID: 1, queue: newOfficialQQEventQueue()}
	secondRuntime := &officialQQRuntime{appID: 1, queue: newOfficialQQEventQueue()}
	firstRouteID := officialQQHandlerRoutes.nextRouteID()
	firstSessionTokenSource := officialQQRoutingTokenSource{routeID: firstRouteID}
	firstIntent := registerOfficialQQHandlers(true)
	if firstIntent&dto.EventToIntent(dto.EventGroupAtMessageCreate) == 0 {
		t.Fatal("group-enabled handler intent omitted group messages")
	}
	firstRuntime.activateHandlerRoute(firstRouteID, context.Background(), first)
	defer func() {
		if err := firstRuntime.Stop(context.Background()); err != nil {
			t.Errorf("stop first runtime: %v", err)
		}
	}()

	makePayload := func(routeID, messageID string) *dto.WSPayload {
		t.Helper()
		raw, err := json.Marshal(struct {
			Data dto.Message `json:"d"`
		}{Data: dto.Message{
			ID: messageID, GuildID: "guild-1", ChannelID: "channel-1",
			Timestamp: dto.Timestamp("2026-09-06T12:00:00Z"), Author: &dto.User{ID: "user-1"},
		}})
		if err != nil {
			t.Fatalf("marshal dispatch payload: %v", err)
		}
		return &dto.WSPayload{
			WSPayloadBase: dto.WSPayloadBase{OPCode: dto.WSDispatchEvent, Type: dto.EventAtMessageCreate},
			RawMessage:    raw,
			Session: &dto.Session{
				AppID:       officialQQHandlerAppID,
				TokenSource: officialQQRoutingTokenSource{routeID: routeID},
			},
		}
	}
	oldPayload := makePayload(firstRouteID, "message-7")
	if err := qqevent.ParseAndHandle(oldPayload); err != nil {
		t.Fatalf("first generation dispatch: %v", err)
	}
	if first.inbound.MessageID != "message-7" {
		t.Fatalf("first generation inbound = %#v", first.inbound)
	}
	if err := firstRuntime.Stop(context.Background()); err != nil {
		t.Fatalf("stop first generation: %v", err)
	}

	secondRouteID := officialQQHandlerRoutes.nextRouteID()
	if secondRouteID == firstRouteID {
		t.Fatal("runtime generations received the same internal route ID")
	}
	secondSessionTokenSource := officialQQRoutingTokenSource{routeID: secondRouteID}
	if secondSessionTokenSource.GetAppID() != firstSessionTokenSource.GetAppID() {
		t.Fatal("BotGo handler key changed between runtime generations")
	}
	secondRuntime.onlyQQGuild = true
	secondIntent := registerOfficialQQHandlers(false)
	if secondIntent&dto.EventToIntent(dto.EventGroupAtMessageCreate) != 0 {
		t.Fatal("onlyQQGuild handler intent included group messages")
	}
	secondRuntime.activateHandlerRoute(secondRouteID, context.Background(), second)
	defer func() {
		if err := secondRuntime.Stop(context.Background()); err != nil {
			t.Errorf("stop second runtime: %v", err)
		}
	}()

	if err := qqevent.ParseAndHandle(oldPayload); err != nil {
		t.Fatalf("stale generation dispatch: %v", err)
	}
	if first.inbound.MessageID != "message-7" || second.inbound.MessageID != "" {
		t.Fatalf("stale generation reached a runtime: first=%#v second=%#v", first.inbound, second.inbound)
	}
	if err := qqevent.ParseAndHandle(makePayload(secondRouteID, "message-8")); err != nil {
		t.Fatalf("current generation dispatch: %v", err)
	}
	if second.inbound.MessageID != "message-8" {
		t.Fatalf("current generation inbound = %#v", second.inbound)
	}
}

type officialQQIngressCore struct {
	inbound     adapterapi.InboundMessage
	receipt     adapterapi.IngressReceipt
	observation adapterapi.LifecycleObservation
}

func (core *officialQQIngressCore) HandleInbound(_ context.Context, inbound adapterapi.InboundMessage) (adapterapi.IngressReceipt, error) {
	core.inbound = inbound
	if core.receipt.Outcome != adapterapi.IngressOutcomeInvalid {
		return core.receipt, nil
	}
	return adapterapi.IngressReceipt{Outcome: adapterapi.IngressAccepted}, nil
}

func (core *officialQQIngressCore) ReportObservation(_ context.Context, observation adapterapi.LifecycleObservation) error {
	core.observation = observation
	return nil
}

func TestOfficialQQRuntimeRejectsUndurableChannelIngress(t *testing.T) {
	runtime := &officialQQRuntime{queue: newOfficialQQEventQueue()}
	core := &officialQQIngressCore{receipt: adapterapi.IngressReceipt{Outcome: adapterapi.IngressRejected}}
	data := dto.WSATMessageData(dto.Message{
		ID: "message-1", GuildID: "guild-1", ChannelID: "channel-1",
		Timestamp: dto.Timestamp("2026-09-06T12:00:00Z"), Author: &dto.User{ID: "user-1"},
	})
	if err := runtime.handleChannelInbound(context.Background(), core, &data); err == nil {
		t.Fatal("runtime accepted rejected ingress")
	}
}

func TestAdapterRegistryUsesLiveLagrangeDescriptor(t *testing.T) {
	if _, ok := descriptorForAdapterKey(t, LagrangeAdapterKey).(LagrangeDescriptor); !ok {
		t.Fatal("lagrange registry entry is not the live external descriptor")
	}
}

func TestAdapterRegistryUsesLiveWalleQDescriptor(t *testing.T) {
	if _, ok := descriptorForAdapterKey(t, WalleQAdapterKey).(WalleQDescriptor); !ok {
		t.Fatal("walleq registry entry is not the live external descriptor")
	}
}

func TestAdapterDescriptorsDeclareCapabilitiesBeforeRuntimeConstruction(t *testing.T) {
	for _, descriptor := range NewAdapterDescriptors() {
		capabilityDescriptor, ok := descriptor.(interface {
			Capabilities(adapterapi.ValidatedConfig) adapterapi.CapabilitySet
		})
		if !ok {
			t.Fatalf("descriptor %q has no static capability contract", descriptor.Key())
		}
		capabilities := capabilityDescriptor.Capabilities(adapterapi.ValidatedConfig{})
		if !capabilities.Has(adapterapi.CapabilityLifecycle) {
			t.Fatalf("descriptor %q capabilities = %#x, want lifecycle", descriptor.Key(), capabilities)
		}
		if !capabilities.Valid() {
			t.Fatalf("descriptor %q capabilities = %#x, want known bits", descriptor.Key(), capabilities)
		}
	}
}

func descriptorForAdapterKey(t *testing.T, key adapterapi.AdapterKey) adapterapi.Descriptor {
	t.Helper()
	for _, descriptor := range NewAdapterDescriptors() {
		if descriptor.Key() == key {
			return descriptor
		}
	}
	t.Fatalf("descriptor %q not found", key)
	return nil
}

type noCallSecretResolver struct{}

func (noCallSecretResolver) Resolve(context.Context, adapterapi.SecretRef) (adapterapi.SecretValue, error) {
	panic("compat runtime constructor attempted to resolve a secret")
}
