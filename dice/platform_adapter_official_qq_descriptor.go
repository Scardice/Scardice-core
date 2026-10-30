package dice

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	qqbot "github.com/sealdice/botgo"
	"github.com/sealdice/botgo/dto"
	qqevent "github.com/sealdice/botgo/event"
	qqapi "github.com/sealdice/botgo/openapi"
	qqtoken "github.com/sealdice/botgo/token"
	"golang.org/x/oauth2"

	"Scardice-core/adapterapi"
)

const OfficialQQAdapterKey adapterapi.AdapterKey = "official_qq"
const officialQQHandlerAppID = "scardice:official-qq:dispatch"

type OfficialQQDescriptor struct{}

type officialQQConfigInput struct {
	AppID       uint64          `json:"appId"`
	AppIDLegacy uint64          `json:"appID"`
	AppSecret   json.RawMessage `json:"appSecret"`
	Token       json.RawMessage `json:"token"`
	AccountHint string          `json:"accountHint,omitempty"`
	OnlyQQGuild bool            `json:"onlyQQGuild"`
}

type officialQQCanonicalSecret struct {
	SecretRef string `json:"secretRef"`
	Version   uint64 `json:"version"`
}

type officialQQCanonicalConfig struct {
	AppID       uint64                    `json:"appId"`
	AppSecret   officialQQCanonicalSecret `json:"appSecret"`
	Token       officialQQCanonicalSecret `json:"token"`
	AccountHint string                    `json:"accountHint,omitempty"`
	OnlyQQGuild bool                      `json:"onlyQQGuild"`
}

func NewOfficialQQDescriptor() adapterapi.Descriptor    { return OfficialQQDescriptor{} }
func (OfficialQQDescriptor) Key() adapterapi.AdapterKey { return OfficialQQAdapterKey }
func (OfficialQQDescriptor) ConfigVersion() uint16      { return 1 }
func (OfficialQQDescriptor) SupportedActions(adapterapi.ValidatedConfig) adapterapi.ActionSet {
	return officialQQSupportedActions()
}

func (OfficialQQDescriptor) Capabilities(adapterapi.ValidatedConfig) adapterapi.CapabilitySet {
	return adapterapi.CapabilityLifecycle |
		adapterapi.CapabilityInbound |
		adapterapi.CapabilityOutbound |
		adapterapi.CapabilityActions |
		adapterapi.CapabilityArtifacts |
		adapterapi.CapabilityRichMessages
}

func (OfficialQQDescriptor) ValidateConfig(ctx context.Context, raw json.RawMessage) (adapterapi.ValidatedConfig, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var input officialQQConfigInput
	if err := decoder.Decode(&input); err != nil {
		return adapterapi.ValidatedConfig{}, fmt.Errorf("official QQ: invalid configuration: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return adapterapi.ValidatedConfig{}, fmt.Errorf("official QQ: invalid trailing JSON: %w", err)
	}
	if input.AppID != 0 && input.AppIDLegacy != 0 && input.AppID != input.AppIDLegacy {
		return adapterapi.ValidatedConfig{}, errors.New("official QQ: appId aliases conflict")
	}
	if input.AppID == 0 {
		input.AppID = input.AppIDLegacy
	}
	if input.AppID == 0 {
		return adapterapi.ValidatedConfig{}, errors.New("official QQ: appId is required")
	}
	if err := validateOnebotText(input.AccountHint, "account hint", 256); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	appSecret, err := officialQQSecretRef(input.AppSecret, "appSecret")
	if err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	token, err := officialQQSecretRef(input.Token, "token")
	if err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	canonicalRaw, err := json.Marshal(officialQQCanonicalConfig{
		AppID: input.AppID,
		AppSecret: officialQQCanonicalSecret{
			SecretRef: appSecret.Ref,
			Version:   appSecret.Version,
		},
		Token: officialQQCanonicalSecret{
			SecretRef: token.Ref,
			Version:   token.Version,
		},
		OnlyQQGuild: input.OnlyQQGuild,
		AccountHint: input.AccountHint,
	})
	if err != nil {
		return adapterapi.ValidatedConfig{}, fmt.Errorf("official QQ: canonical configuration: %w", err)
	}
	canonical, err := adapterapi.CanonicalizeJSON(canonicalRaw)
	if err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	validated := adapterapi.ValidatedConfig{Version: 1, Canonical: canonical, SecretRefs: []adapterapi.SecretRef{appSecret, token}}
	if err := validated.Validate(); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	return validated, nil
}

func (OfficialQQDescriptor) NewRuntime(init adapterapi.RuntimeInit) (adapterapi.AdapterRuntime, error) {
	if !init.EndpointID.Valid() || init.Generation == 0 || init.DesiredVersion == 0 {
		return nil, errors.New("official QQ: runtime identity is incomplete")
	}
	if err := init.Config.Validate(); err != nil || init.Config.Version != 1 {
		return nil, errors.New("official QQ: runtime configuration was not validated")
	}
	validated, err := (OfficialQQDescriptor{}).ValidateConfig(context.Background(), init.Config.Canonical)
	if err != nil || !bytes.Equal(validated.Canonical, init.Config.Canonical) || len(validated.SecretRefs) != len(init.Config.SecretRefs) {
		return nil, errors.New("official QQ: runtime configuration was not canonical")
	}
	for index := range validated.SecretRefs {
		if validated.SecretRefs[index] != init.Config.SecretRefs[index] {
			return nil, errors.New("official QQ: runtime secret references do not match")
		}
	}
	var config officialQQCanonicalConfig
	if err := json.Unmarshal(init.Config.Canonical, &config); err != nil || config.AppID == 0 {
		return nil, errors.New("official QQ: runtime canonical configuration is invalid")
	}
	return &officialQQRuntime{
		appID:       config.AppID,
		appSecret:   adapterapi.SecretRef{Ref: config.AppSecret.SecretRef, Version: config.AppSecret.Version},
		token:       adapterapi.SecretRef{Ref: config.Token.SecretRef, Version: config.Token.Version},
		onlyQQGuild: config.OnlyQQGuild,
		resolver:    init.Secrets,
		queue:       newOfficialQQEventQueue(),
	}, nil
}

type officialQQRuntime struct {
	appID          uint64
	appSecret      adapterapi.SecretRef
	token          adapterapi.SecretRef
	onlyQQGuild    bool
	resolver       adapterapi.SecretResolver
	queue          *officialQQEventQueue
	qrClient       officialQQQRClient
	qrEncoder      officialQQQREncoder
	mu             sync.Mutex
	cancel         context.CancelFunc
	api            qqapi.OpenAPI
	handlerRouteID string
}

type officialQQHandlerRoute struct {
	runtime      *officialQQRuntime
	ctx          context.Context
	core         adapterapi.CorePort
	groupEnabled bool
}

type officialQQHandlerRouter struct {
	mu     sync.RWMutex
	nextID atomic.Uint64
	routes map[string]*officialQQHandlerRoute
}

var officialQQHandlerRoutes = officialQQHandlerRouter{
	routes: make(map[string]*officialQQHandlerRoute),
}

type officialQQStaticHandlers struct{}

var officialQQHandlers officialQQStaticHandlers

var officialQQHandlerRegistration struct {
	once   sync.Once
	intent dto.Intent
}

// BotGo uses this GetAppID value only as dto.Session.AppID for event handler lookup.
// Keep the real credential AppID in OpenAPI and pass through its token source.
type officialQQRoutingTokenSource struct {
	source  oauth2.TokenSource
	routeID string
}

func (source officialQQRoutingTokenSource) Token() (*oauth2.Token, error) {
	return source.source.Token()
}

func (source officialQQRoutingTokenSource) GetAppID() string {
	return officialQQHandlerAppID
}

// A fresh process-local key scopes each BotGo session set to one Run invocation.
func (router *officialQQHandlerRouter) nextRouteID() string {
	return fmt.Sprintf("scardice:official-qq:run:%d", router.nextID.Add(1))
}

// Register the immutable dispatch functions once; each BotGo session carries its runtime route token.
func registerOfficialQQHandlers(groupEnabled bool) dto.Intent {
	officialQQHandlerRegistration.once.Do(func() {
		officialQQHandlerRegistration.intent = qqevent.RegisterHandlersByAppID(
			officialQQHandlerAppID,
			qqevent.ATMessageEventHandler(officialQQHandlers.channelAtMessageHandler),
			qqevent.DirectMessageEventHandler(officialQQHandlers.directMessageHandler),
			qqevent.GroupATMessageEventHandler(officialQQHandlers.groupAtMessageHandler),
		)
	})
	intent := officialQQHandlerRegistration.intent
	if !groupEnabled {
		intent &^= dto.EventToIntent(dto.EventGroupAtMessageCreate)
	}
	return intent
}

func (router *officialQQHandlerRouter) activate(routeID string, route *officialQQHandlerRoute) {
	router.mu.Lock()
	router.routes[routeID] = route
	router.mu.Unlock()
}

// BotGo has no synchronized unregister API; remove only runtime-bearing state.
func (router *officialQQHandlerRouter) deactivate(routeID string) {
	router.mu.Lock()
	delete(router.routes, routeID)
	router.mu.Unlock()
}

func (router *officialQQHandlerRouter) lookup(payload *dto.WSPayload) *officialQQHandlerRoute {
	if payload == nil || payload.Session == nil || payload.Session.AppID != officialQQHandlerAppID {
		return nil
	}
	tokenSource, ok := payload.Session.TokenSource.(officialQQRoutingTokenSource)
	if !ok || tokenSource.routeID == "" {
		return nil
	}
	router.mu.RLock()
	route := router.routes[tokenSource.routeID]
	router.mu.RUnlock()
	return route
}

func (runtime *officialQQRuntime) activateHandlerRoute(routeID string, ctx context.Context, core adapterapi.CorePort) {
	if ctx == nil {
		ctx = context.Background()
	}
	runtime.mu.Lock()
	runtime.handlerRouteID = routeID
	officialQQHandlerRoutes.activate(routeID, &officialQQHandlerRoute{
		runtime:      runtime,
		ctx:          ctx,
		core:         core,
		groupEnabled: !runtime.onlyQQGuild,
	})
	runtime.mu.Unlock()
}

func (officialQQStaticHandlers) channelAtMessageHandler(payload *dto.WSPayload, data *dto.WSATMessageData) error {
	route := officialQQHandlerRoutes.lookup(payload)
	if route == nil {
		return nil
	}
	return route.runtime.handleChannelInbound(route.ctx, route.core, data)
}

func (officialQQStaticHandlers) directMessageHandler(payload *dto.WSPayload, data *dto.WSDirectMessageData) error {
	route := officialQQHandlerRoutes.lookup(payload)
	if route == nil {
		return nil
	}
	inbound, err := officialQQDirectInbound(data)
	if err != nil {
		return err
	}
	return route.runtime.handleInbound(route.ctx, route.core, inbound, "direct")
}

func (officialQQStaticHandlers) groupAtMessageHandler(payload *dto.WSPayload, data *dto.WSGroupATMessageData) error {
	route := officialQQHandlerRoutes.lookup(payload)
	if route == nil || !route.groupEnabled {
		return nil
	}
	return route.runtime.handleGroupInbound(route.ctx, route.core, data)
}

func (runtime *officialQQRuntime) resolveAppSecret(ctx context.Context) (string, error) {
	if runtime == nil || runtime.resolver == nil {
		return "", errors.New("official QQ: appSecret resolver is unavailable")
	}
	value, err := runtime.resolver.Resolve(ctx, runtime.appSecret)
	if err != nil {
		return "", err
	}
	if value.Version != runtime.appSecret.Version || len(value.Bytes) == 0 {
		return "", errors.New("official QQ: appSecret resolution is invalid")
	}
	return string(value.Bytes), nil
}

type officialQQQRClientFunc func(context.Context, string) (string, error)

func (fn officialQQQRClientFunc) Create(ctx context.Context, key string) (string, error) {
	return fn(ctx, key)
}

func (runtime *officialQQRuntime) ExecuteAction(ctx context.Context, action adapterapi.ActionRequest) (adapterapi.ActionResult, error) {
	if runtime == nil || action.Kind != adapterapi.ActionRequestQRCode {
		return adapterapi.ActionResult{}, errors.New("official QQ: unsupported action")
	}
	client := runtime.qrClient
	if client == nil {
		client = newOfficialQQQRHTTPClient(http.DefaultClient, "https://q.qq.com")
	}
	key := make([]byte, 32)
	if _, err := crand.Read(key); err != nil {
		return adapterapi.ActionResult{}, err
	}
	taskID, err := client.Create(ctx, base64.StdEncoding.EncodeToString(key))
	if err != nil {
		return adapterapi.ActionResult{}, err
	}
	qrURL := "https://q.qq.com/qqbot/connect.html?task_id=" + url.QueryEscape(taskID) + "&source=scardice&_wv=2"
	if runtime.qrEncoder == nil {
		return adapterapi.ActionResult{
			ResultCode: "qr_ready",
			Artifact:   &adapterapi.ActionArtifact{MediaType: "text/plain", SafeFilename: "official-qq-qr.txt", Plaintext: []byte(qrURL)},
		}, nil
	}
	artifact := &adapterapi.ActionArtifact{MediaType: "image/png", SafeFilename: "official-qq-qr.png"}
	artifact.Plaintext, err = runtime.qrEncoder(qrURL)
	if err != nil {
		return adapterapi.ActionResult{}, err
	}
	return adapterapi.ActionResult{ResultCode: "qr_ready", Artifact: artifact}, nil
}

func (runtime *officialQQRuntime) Run(ctx context.Context, core adapterapi.CorePort) (runErr error) {
	if runtime == nil || core == nil {
		return errors.New("official QQ: runtime or core is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	defer func() {
		if runErr != nil {
			_ = core.ReportObservation(context.Background(), adapterapi.LifecycleObservation{
				Kind:       adapterapi.LifecycleObservationState,
				State:      adapterapi.ObservedStateFailed,
				Code:       "runtime_failed",
				Detail:     "Official QQ runtime failed",
				Retryable:  true,
				OccurredAt: time.Now().UTC(),
			})
		}
	}()
	appSecret, runErr := runtime.resolveAppSecret(ctx)
	if runErr != nil {
		return runErr
	}
	runCtx, cancel := context.WithCancel(ctx)
	runtime.mu.Lock()
	runtime.cancel = cancel
	runtime.mu.Unlock()
	defer func() {
		if stopErr := runtime.Stop(context.Background()); stopErr != nil && runErr == nil {
			runErr = stopErr
		}
	}()
	if err := core.ReportObservation(runCtx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateStarting, Code: "starting", Detail: "Official QQ runtime starting", OccurredAt: time.Now().UTC()}); err != nil {
		return err
	}
	appID := strconv.FormatUint(runtime.appID, 10)
	tokenSource := qqtoken.NewQQBotTokenSource(&qqtoken.QQBotCredentials{AppID: appID, AppSecret: appSecret})
	api := qqbot.NewOpenAPI(appID, tokenSource).WithTimeout(3 * time.Second)
	ws, err := api.WS(runCtx, nil, "")
	if err != nil {
		return err
	}
	if err := validateOfficialQQWebsocketAP(ws); err != nil {
		return err
	}
	runtime.mu.Lock()
	runtime.api = api
	runtime.mu.Unlock()
	if identity, err := api.Me(runCtx); err == nil {
		if err := reportOfficialQQVerifiedIdentity(runCtx, core, identity); err != nil {
			return err
		}
	}
	routeID := officialQQHandlerRoutes.nextRouteID()
	intent := registerOfficialQQHandlers(!runtime.onlyQQGuild)
	runtime.activateHandlerRoute(routeID, runCtx, core)
	sessionTokenSource := officialQQRoutingTokenSource{source: tokenSource, routeID: routeID}
	return runOfficialQQSession(runCtx, func(sessionCtx context.Context) error {
		return qqbot.NewSessionManager().Start(sessionCtx, ws, sessionTokenSource, &intent)
	})
}

func reportOfficialQQVerifiedIdentity(ctx context.Context, core adapterapi.CorePort, identity *dto.User) error {
	if core == nil || identity == nil || identity.ID == "" {
		return nil
	}
	return core.ReportObservation(ctx, adapterapi.LifecycleObservation{
		Kind:       adapterapi.LifecycleObservationIdentity,
		State:      adapterapi.ObservedStateConnected,
		ProviderID: adapterapi.PrincipalID(identity.ID),
		Code:       "verified_identity",
		OccurredAt: time.Now().UTC(),
	})
}

func (runtime *officialQQRuntime) Stop(context.Context) error {
	if runtime == nil {
		return nil
	}
	runtime.mu.Lock()
	cancel := runtime.cancel
	runtime.cancel = nil
	runtime.api = nil
	routeID := runtime.handlerRouteID
	runtime.handlerRouteID = ""
	if routeID != "" {
		officialQQHandlerRoutes.deactivate(routeID)
	}
	runtime.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if runtime.queue != nil {
		runtime.queue.closeAndWait()
	}
	return nil
}

func (runtime *officialQQRuntime) enqueue(event func()) bool {
	return runtime != nil && runtime.queue != nil && runtime.queue.Enqueue(event)
}

func (runtime *officialQQRuntime) handleChannelInbound(ctx context.Context, core adapterapi.CorePort, data *dto.WSATMessageData) error {
	inbound, err := officialQQChannelInbound(data)
	if err != nil {
		return err
	}
	return runtime.handleInbound(ctx, core, inbound, "channel")
}

func (runtime *officialQQRuntime) handleGroupInbound(ctx context.Context, core adapterapi.CorePort, data *dto.WSGroupATMessageData) error {
	if runtime == nil {
		return errors.New("official QQ: group ingress runtime is unavailable")
	}
	inbound, err := officialQQGroupInbound(runtime.appID, data)
	if err != nil {
		return err
	}
	return runtime.handleInbound(ctx, core, inbound, "group")
}

func (runtime *officialQQRuntime) handleInbound(ctx context.Context, core adapterapi.CorePort, inbound adapterapi.InboundMessage, kind string) error {
	if runtime == nil || core == nil {
		return fmt.Errorf("official QQ: %s ingress runtime or core is unavailable", kind)
	}
	done := make(chan struct{})
	var result error
	if !runtime.enqueue(func() {
		defer close(done)
		receipt, err := core.HandleInbound(ctx, inbound)
		if err != nil {
			result = err
			return
		}
		if err := receipt.Validate(); err != nil {
			result = err
			return
		}
		if receipt.Outcome == adapterapi.IngressRejected {
			result = fmt.Errorf("official QQ: %s ingress rejected", kind)
		}
	}) {
		return fmt.Errorf("official QQ: %s ingress queue is closed", kind)
	}
	<-done
	return result
}

func (runtime *officialQQRuntime) channelAtMessageHandler(ctx context.Context, core adapterapi.CorePort) qqevent.ATMessageEventHandler {
	return func(_ *dto.WSPayload, data *dto.WSATMessageData) error {
		return runtime.handleChannelInbound(ctx, core, data)
	}
}

func (runtime *officialQQRuntime) directMessageHandler(ctx context.Context, core adapterapi.CorePort) qqevent.DirectMessageEventHandler {
	return func(_ *dto.WSPayload, data *dto.WSDirectMessageData) error {
		inbound, err := officialQQDirectInbound(data)
		if err != nil {
			return err
		}
		return runtime.handleInbound(ctx, core, inbound, "direct")
	}
}

func (runtime *officialQQRuntime) groupAtMessageHandler(ctx context.Context, core adapterapi.CorePort) qqevent.GroupATMessageEventHandler {
	return func(_ *dto.WSPayload, data *dto.WSGroupATMessageData) error {
		return runtime.handleGroupInbound(ctx, core, data)
	}
}

func (*officialQQRuntime) OwnedResources() adapterapi.OwnedResourceManifest {
	return adapterapi.OwnedResourceManifest{}
}

func (*officialQQRuntime) Capabilities() adapterapi.CapabilitySet {
	return adapterapi.CapabilityLifecycle |
		adapterapi.CapabilityInbound |
		adapterapi.CapabilityOutbound |
		adapterapi.CapabilityActions |
		adapterapi.CapabilityArtifacts |
		adapterapi.CapabilityRichMessages
}

func officialQQSupportedActions() adapterapi.ActionSet {
	return adapterapi.ActionSet(0).With(
		adapterapi.ActionKindRequestQRCode,
		adapterapi.ActionKindSendMessage,
	)
}

type officialQQDeliveryKind uint8

const (
	officialQQDeliveryChannel officialQQDeliveryKind = iota + 1
	officialQQDeliveryDirect
	officialQQDeliveryC2C
	officialQQDeliveryGroup
)

type officialQQDelivery struct {
	kind      officialQQDeliveryKind
	userID    string
	groupID   string
	guildID   string
	channelID string
}

func officialQQDeliveryTarget(target adapterapi.EffectTarget) (officialQQDelivery, error) {
	value := target.Conversation.String()
	switch target.Kind {
	case adapterapi.TargetGroup:
		if rest, ok := strings.CutPrefix(value, "OpenQQ-Group-T:"); ok {
			_, groupID, found := strings.Cut(rest, "-")
			if found && groupID != "" {
				return officialQQDelivery{kind: officialQQDeliveryGroup, groupID: groupID}, nil
			}
		}
		if rest, ok := strings.CutPrefix(value, "OpenQQCH-Channel:"); ok {
			guildID, channelID, found := strings.Cut(rest, "-")
			if found && guildID != "" && channelID != "" {
				return officialQQDelivery{kind: officialQQDeliveryChannel, guildID: guildID, channelID: channelID}, nil
			}
		}
	case adapterapi.TargetPerson:
		if rest, ok := strings.CutPrefix(value, "OpenQQCH-Channel:"); ok {
			guildID, channelID, found := strings.Cut(rest, "-")
			if found && guildID != "" && channelID != "" {
				return officialQQDelivery{kind: officialQQDeliveryDirect, guildID: guildID, channelID: channelID}, nil
			}
		}
		if userID, ok := strings.CutPrefix(value, "OpenQQCH:"); ok && userID != "" {
			return officialQQDelivery{kind: officialQQDeliveryC2C, userID: userID}, nil
		}
		if userID, ok := strings.CutPrefix(value, "OpenQQ:"); ok && userID != "" {
			return officialQQDelivery{kind: officialQQDeliveryC2C, userID: userID}, nil
		}
	default:
		return officialQQDelivery{}, errors.New("official QQ: unsupported target kind")
	}
	return officialQQDelivery{}, errors.New("official QQ: unsupported target")
}

func officialQQMessageContent(payload adapterapi.EffectPayload, delivery officialQQDelivery) (string, error) {
	if payload.Kind == adapterapi.EffectPayloadPersonText || payload.Kind == adapterapi.EffectPayloadGroupText {
		content := payload.Text
		if delivery.kind == officialQQDeliveryChannel || delivery.kind == officialQQDeliveryGroup {
			content = officialQQTextLinkStrip(content)
		}
		return content, nil
	}
	var content strings.Builder
	for _, segment := range payload.Segments {
		switch segment.Kind {
		case adapterapi.SegmentKindText:
			content.WriteString(segment.Text)
		case adapterapi.SegmentKindMention:
			if delivery.kind != officialQQDeliveryChannel {
				continue
			}
			if segment.Text == "all" || segment.Text == "QQ:all" {
				content.WriteString("@everyone")
				continue
			}
			userID, ok := strings.CutPrefix(segment.Text, "OpenQQCH:")
			if !ok || userID == "" {
				userID, ok = strings.CutPrefix(segment.Text, "OpenQQ:")
			}
			if !ok || userID == "" {
				return "", errors.New("official QQ: invalid mention target")
			}
			content.WriteString("<@")
			content.WriteString(userID)
			content.WriteByte('>')
		case adapterapi.SegmentKindImage, adapterapi.SegmentKindFile:
			return "", errors.New("official QQ: artifact segment cannot be resolved")
		default:
			return "", errors.New("official QQ: unsupported message segment")
		}
	}
	if content.Len() == 0 {
		return "", errors.New("official QQ: message has no supported content")
	}
	result := content.String()
	if delivery.kind == officialQQDeliveryChannel || delivery.kind == officialQQDeliveryGroup {
		result = officialQQTextLinkStrip(result)
	}
	return result, nil
}

func (runtime *officialQQRuntime) Execute(ctx context.Context, effect adapterapi.OutboundEffect) adapterapi.EffectResult {
	if runtime == nil {
		return adapterapi.TerminalResult("official_qq_provider_unavailable", "provider unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if effect.Version != adapterapi.EffectVersionOne {
		return adapterapi.UnsupportedResult("official_qq_invalid_effect_version")
	}
	if err := effect.ValidateForCapabilities(runtime.Capabilities(), officialQQSupportedActions()); err != nil {
		return adapterapi.UnsupportedResult("official_qq_effect_not_supported")
	}
	for _, segment := range effect.Payload.Segments {
		if segment.Artifact != nil {
			return adapterapi.UnsupportedResult("official_qq_artifact_reader_unavailable")
		}
	}
	runtime.mu.Lock()
	api := runtime.api
	runtime.mu.Unlock()
	if api == nil {
		return adapterapi.TerminalResult("official_qq_provider_unavailable", "provider unavailable")
	}
	delivery, err := officialQQDeliveryTarget(effect.Payload.Target)
	if err != nil {
		return adapterapi.UnsupportedResult("official_qq_invalid_target")
	}
	content, err := officialQQMessageContent(effect.Payload, delivery)
	if err != nil {
		return adapterapi.UnsupportedResult("official_qq_unsupported_segment")
	}
	request := &dto.MessageToCreate{Content: content, MsgType: dto.TextMsg}
	var response *dto.Message
	switch delivery.kind {
	case officialQQDeliveryChannel:
		response, err = api.PostMessage(ctx, delivery.channelID, request)
	case officialQQDeliveryDirect:
		response, err = api.PostDirectMessage(ctx, &dto.DirectMessage{GuildID: delivery.guildID, ChannelID: delivery.channelID}, request)
	case officialQQDeliveryC2C:
		response, err = api.PostC2CMessage(ctx, delivery.userID, request)
	case officialQQDeliveryGroup:
		response, err = api.PostGroupMessage(ctx, delivery.groupID, request)
	default:
		return adapterapi.UnsupportedResult("official_qq_invalid_target")
	}
	if err != nil {
		return officialQQProviderErrorResult(err)
	}
	if response == nil || response.ID == "" {
		return adapterapi.TerminalResult("official_qq_invalid_response", "provider returned no message id")
	}
	return adapterapi.SucceededResult(response.ID)
}

func officialQQProviderErrorResult(err error) adapterapi.EffectResult {
	var networkErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &networkErr) && networkErr.Timeout()) {
		return adapterapi.RetryableResult("official_qq_provider_transient", "provider request timed out")
	}
	return adapterapi.AmbiguousResult("official_qq_provider_ambiguous", "provider dispatch outcome is unknown")
}

var officialQQURLExtract = regexp.MustCompile(`(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/|\/|\/\/)?[A-z0-9_-]*?[:]?[A-z0-9_-]*?[@]?[A-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?`)

func officialQQTextLinkStrip(text string) string {
	urls := officialQQURLExtract.FindAllString(text, -1)
	for _, value := range urls {
		replaced := strings.ReplaceAll(value, ".", "_")
		replaced = strings.ReplaceAll(replaced, "https://", "https_")
		replaced = strings.ReplaceAll(replaced, "http://", "http_")
		text = strings.ReplaceAll(text, value, replaced)
	}
	return text
}

func (*officialQQRuntime) Diagnostics(context.Context) adapterapi.DiagnosticReport {
	return adapterapi.DiagnosticReport{}
}

func officialQQSecretRef(raw json.RawMessage, name string) (adapterapi.SecretRef, error) {
	var input struct {
		SecretRef string `json:"secretRef"`
		Version   uint64 `json:"version"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return adapterapi.SecretRef{}, fmt.Errorf("official QQ: %s must be a secret reference", name)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return adapterapi.SecretRef{}, fmt.Errorf("official QQ: %s has trailing JSON", name)
	}
	ref := adapterapi.SecretRef{Ref: input.SecretRef, Version: input.Version}
	if err := ref.Validate(); err != nil || ref.Version == 0 {
		return adapterapi.SecretRef{}, fmt.Errorf("official QQ: invalid %s secret reference", name)
	}
	return ref, nil
}

func officialQQChannelInbound(data *dto.WSATMessageData) (adapterapi.InboundMessage, error) {
	if data == nil || data.Author == nil {
		return adapterapi.InboundMessage{}, errors.New("official QQ: channel message identity is incomplete")
	}
	occurredAt, err := data.Timestamp.Time()
	if err != nil {
		return adapterapi.InboundMessage{}, fmt.Errorf("official QQ: channel message timestamp: %w", err)
	}
	inbound := adapterapi.InboundMessage{
		ProviderEventID:  adapterapi.ProviderEventID(data.ID),
		MessageID:        adapterapi.MessageID(data.ID),
		Platform:         "OpenQQCH",
		Sender:           adapterapi.PrincipalID(formatDiceIDOfficialQQCh(data.Author.ID)),
		Conversation:     adapterapi.ConversationID(formatDiceIDOfficialQQChannel(data.GuildID, data.ChannelID)),
		ConversationKind: adapterapi.ConversationKindGroup,
		Kind:             adapterapi.InboundKindMessage,
		Text:             data.Content,
		OccurredAt:       occurredAt,
	}
	if err := inbound.Validate(); err != nil {
		return adapterapi.InboundMessage{}, fmt.Errorf("official QQ: invalid channel inbound: %w", err)
	}
	return inbound, nil
}

func officialQQDirectInbound(data *dto.WSDirectMessageData) (adapterapi.InboundMessage, error) {
	if data == nil || data.Author == nil {
		return adapterapi.InboundMessage{}, errors.New("official QQ: direct message identity is incomplete")
	}
	occurredAt, err := data.Timestamp.Time()
	if err != nil {
		return adapterapi.InboundMessage{}, fmt.Errorf("official QQ: direct message timestamp: %w", err)
	}
	inbound := adapterapi.InboundMessage{
		ProviderEventID:  adapterapi.ProviderEventID(data.ID),
		MessageID:        adapterapi.MessageID(data.ID),
		Platform:         "OpenQQCH",
		Sender:           adapterapi.PrincipalID(formatDiceIDOfficialQQCh(data.Author.ID)),
		Conversation:     adapterapi.ConversationID(formatDiceIDOfficialQQChannel(data.GuildID, data.ChannelID)),
		ConversationKind: adapterapi.ConversationKindDirect,
		Kind:             adapterapi.InboundKindMessage,
		Text:             data.Content,
		OccurredAt:       occurredAt,
	}
	if err := inbound.Validate(); err != nil {
		return adapterapi.InboundMessage{}, fmt.Errorf("official QQ: invalid direct inbound: %w", err)
	}
	return inbound, nil
}

func officialQQGroupInbound(appID uint64, data *dto.WSGroupATMessageData) (adapterapi.InboundMessage, error) {
	if appID == 0 || data == nil || data.Author == nil || data.GroupOpenID == "" || data.Author.MemberOpenID == "" {
		return adapterapi.InboundMessage{}, errors.New("official QQ: group message identity is incomplete")
	}
	occurredAt, err := data.Timestamp.Time()
	if err != nil {
		return adapterapi.InboundMessage{}, fmt.Errorf("official QQ: group message timestamp: %w", err)
	}
	account := strconv.FormatUint(appID, 10)
	inbound := adapterapi.InboundMessage{
		ProviderEventID:  adapterapi.ProviderEventID(data.ID),
		MessageID:        adapterapi.MessageID(data.ID),
		Platform:         "OpenQQ",
		Sender:           adapterapi.PrincipalID(formatDiceIDOfficialQQMemberOpenID(account, data.GroupOpenID, data.Author.MemberOpenID)),
		Conversation:     adapterapi.ConversationID(formatDiceIDOfficialQQGroupOpenID(account, data.GroupOpenID)),
		ConversationKind: adapterapi.ConversationKindGroup,
		Kind:             adapterapi.InboundKindMessage,
		Text:             data.Content,
		SenderRole:       normalizeGroupSenderRole(data.Author.MemberRole),
		OccurredAt:       occurredAt,
	}
	if err := inbound.Validate(); err != nil {
		return adapterapi.InboundMessage{}, fmt.Errorf("official QQ: invalid group inbound: %w", err)
	}
	return inbound, nil
}
