package dice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"

	"Scardice-core/adapterapi"
)

const (
	HTTPAdapterKey              adapterapi.AdapterKey = "http"
	httpAdapterMaxResponseBytes int64                 = 4 << 20
	httpAdapterDefaultTimeout                         = 15 * time.Second
	httpAdapterMaxRedirects                           = 3
)

var (
	errHTTPAdapterRedirectLimit     = errors.New("http adapter redirect limit exceeded")
	errHTTPAdapterRedirectTarget    = errors.New("http adapter redirect target is invalid")
	errHTTPAdapterRedirectDowngrade = errors.New("http adapter rejects HTTPS downgrade")
)

type HTTPDescriptor struct{}

type httpConfigInput struct {
	Version        string          `json:"version"`
	URL            string          `json:"url"`
	Method         string          `json:"method"`
	Path           string          `json:"path"`
	TimeoutSeconds int             `json:"timeoutSeconds"`
	Token          json.RawMessage `json:"token"`
}

type httpCanonicalConfig struct {
	Version        string                   `json:"version"`
	URL            string                   `json:"url"`
	Method         string                   `json:"method"`
	Path           string                   `json:"path"`
	TimeoutSeconds int                      `json:"timeoutSeconds"`
	Token          *providerCanonicalSecret `json:"token,omitempty"`
}

type httpAdapterRuntime struct {
	config    httpCanonicalConfig
	target    string
	tokenRef  *adapterapi.SecretRef
	resolver  adapterapi.SecretResolver
	client    *http.Client
	transport *http.Transport

	mu        sync.Mutex
	cancel    context.CancelFunc
	running   bool
	connected bool
}

func NewHTTPDescriptor() adapterapi.Descriptor { return HTTPDescriptor{} }

func (HTTPDescriptor) Key() adapterapi.AdapterKey { return HTTPAdapterKey }

func (HTTPDescriptor) ConfigVersion() uint16 { return 1 }

func (HTTPDescriptor) SupportedActions(adapterapi.ValidatedConfig) adapterapi.ActionSet {
	return adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage)
}

func (HTTPDescriptor) Capabilities(adapterapi.ValidatedConfig) adapterapi.CapabilitySet {
	return adapterapi.CapabilityLifecycle | adapterapi.CapabilityOutbound
}

func (HTTPDescriptor) ValidateConfig(ctx context.Context, raw json.RawMessage) (adapterapi.ValidatedConfig, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	var input httpConfigInput
	if err := decodeStrictProviderJSON(raw, &input); err != nil {
		return adapterapi.ValidatedConfig{}, fmt.Errorf("http: invalid config: %w", err)
	}
	if input.Version != "1" {
		return adapterapi.ValidatedConfig{}, errors.New("http: unsupported config version")
	}
	baseURL, err := normalizeHTTPAdapterURL(input.URL)
	if err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	method := strings.ToUpper(strings.TrimSpace(input.Method))
	if method == "" {
		method = http.MethodPost
	}
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
	default:
		return adapterapi.ValidatedConfig{}, errors.New("http: method must be POST, PUT, or PATCH")
	}
	requestPath, err := normalizeHTTPAdapterPath(input.Path)
	if err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	if _, resolveErr := resolveHTTPAdapterTarget(baseURL, requestPath); resolveErr != nil {
		return adapterapi.ValidatedConfig{}, resolveErr
	}
	timeoutSeconds := input.TimeoutSeconds
	if timeoutSeconds == 0 {
		timeoutSeconds = int(httpAdapterDefaultTimeout / time.Second)
	}
	if timeoutSeconds < 1 || timeoutSeconds > int(httpAdapterDefaultTimeout/time.Second) {
		return adapterapi.ValidatedConfig{}, errors.New("http: timeoutSeconds must be between 1 and 15")
	}
	var token *providerCanonicalSecret
	var refs []adapterapi.SecretRef
	trimmedToken := bytes.TrimSpace(input.Token)
	if len(trimmedToken) != 0 && !bytes.Equal(trimmedToken, []byte("null")) {
		var secret providerCanonicalSecret
		if decodeErr := decodeStrictProviderJSON(input.Token, &secret); decodeErr != nil || secret.Version == 0 {
			return adapterapi.ValidatedConfig{}, errors.New("http: invalid token reference")
		}
		ref := adapterapi.SecretRef{Ref: secret.SecretRef, Version: secret.Version}
		if validateErr := ref.Validate(); validateErr != nil {
			return adapterapi.ValidatedConfig{}, validateErr
		}
		token = &secret
		refs = []adapterapi.SecretRef{ref}
	}
	encoded, err := json.Marshal(httpCanonicalConfig{Version: input.Version, URL: baseURL, Method: method, Path: requestPath, TimeoutSeconds: timeoutSeconds, Token: token})
	if err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	canonical, err := adapterapi.CanonicalizeJSON(encoded)
	if err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	validated := adapterapi.ValidatedConfig{Version: 1, Canonical: canonical, SecretRefs: refs}
	if err := validated.Validate(); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	return validated, nil
}

func normalizeHTTPAdapterURL(raw string) (string, error) {
	if strings.IndexFunc(raw, unicode.IsControl) >= 0 {
		return "", errors.New("http: URL contains a control character")
	}
	normalized, err := normalizeProviderHTTPURL(raw, false)
	if err != nil {
		return "", fmt.Errorf("http: invalid URL: %w", err)
	}
	return normalized, nil
}

func normalizeHTTPAdapterPath(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if strings.IndexFunc(raw, unicode.IsControl) >= 0 || !strings.HasPrefix(raw, "/") {
		return "", errors.New("http: path must be an absolute URL path")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("http: path must not contain a scheme, authority, query, or fragment")
	}
	return parsed.EscapedPath(), nil
}

func resolveHTTPAdapterTarget(base, requestPath string) (string, error) {
	parsed, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	if requestPath != "" {
		reference, parseErr := url.Parse(requestPath)
		if parseErr != nil {
			return "", parseErr
		}
		parsed = parsed.ResolveReference(reference)
	}
	return normalizeHTTPAdapterURL(parsed.String())
}

func (descriptor HTTPDescriptor) NewRuntime(init adapterapi.RuntimeInit) (adapterapi.AdapterRuntime, error) {
	if !init.EndpointID.Valid() || init.Generation == 0 || init.DesiredVersion == 0 {
		return nil, errors.New("http: runtime identity is incomplete")
	}
	if err := init.Config.Validate(); err != nil {
		return nil, err
	}
	validated, err := descriptor.ValidateConfig(context.Background(), init.Config.Canonical)
	if err != nil || validated.Version != init.Config.Version || !bytes.Equal(validated.Canonical, init.Config.Canonical) || len(validated.SecretRefs) != len(init.Config.SecretRefs) {
		return nil, errors.New("http: runtime config was not validated by descriptor")
	}
	for index := range validated.SecretRefs {
		if validated.SecretRefs[index] != init.Config.SecretRefs[index] {
			return nil, errors.New("http: runtime secret references do not match")
		}
	}
	var config httpCanonicalConfig
	if decodeErr := json.Unmarshal(init.Config.Canonical, &config); decodeErr != nil {
		return nil, errors.New("http: invalid canonical runtime config")
	}
	target, err := resolveHTTPAdapterTarget(config.URL, config.Path)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	runtime := &httpAdapterRuntime{config: config, target: target, resolver: init.Secrets, transport: transport}
	if len(validated.SecretRefs) == 1 {
		ref := validated.SecretRefs[0]
		runtime.tokenRef = &ref
	}
	runtime.client = &http.Client{Transport: transport, Timeout: time.Duration(config.TimeoutSeconds) * time.Second, CheckRedirect: checkHTTPAdapterRedirect}
	return runtime, nil
}

func checkHTTPAdapterRedirect(request *http.Request, via []*http.Request) error {
	if len(via) > httpAdapterMaxRedirects {
		return errHTTPAdapterRedirectLimit
	}
	if _, err := normalizeHTTPAdapterURL(request.URL.String()); err != nil {
		return fmt.Errorf("%w: %w", errHTTPAdapterRedirectTarget, err)
	}
	if len(via) != 0 && via[len(via)-1].URL.Scheme == "https" && request.URL.Scheme != "https" {
		return errHTTPAdapterRedirectDowngrade
	}
	return nil
}

func (*httpAdapterRuntime) OwnedResources() adapterapi.OwnedResourceManifest {
	return adapterapi.OwnedResourceManifest{}
}

func (*httpAdapterRuntime) Capabilities() adapterapi.CapabilitySet {
	return adapterapi.CapabilityLifecycle | adapterapi.CapabilityOutbound
}

func (*httpAdapterRuntime) Diagnostics(context.Context) adapterapi.DiagnosticReport {
	return adapterapi.DiagnosticReport{}
}

func (runtime *httpAdapterRuntime) Execute(ctx context.Context, effect adapterapi.OutboundEffect) adapterapi.EffectResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return adapterapi.TerminalResult("http_context_canceled", "dispatch context canceled")
	}
	if effect.Version != adapterapi.EffectVersionOne {
		return adapterapi.UnsupportedResult("http_invalid_effect_version")
	}
	if err := effect.ValidateForCapabilities(runtime.Capabilities(), adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage)); err != nil {
		return adapterapi.UnsupportedResult("http_effect_not_supported")
	}
	messageType := ""
	switch effect.Payload.Kind {
	case adapterapi.EffectPayloadGroupText:
		if effect.Payload.Target.Kind == adapterapi.TargetGroup {
			messageType = "group"
		}
	case adapterapi.EffectPayloadPersonText:
		if effect.Payload.Target.Kind == adapterapi.TargetPerson {
			messageType = "private"
		}
	case adapterapi.EffectPayloadInvalid,
		adapterapi.EffectPayloadSegments,
		adapterapi.EffectPayloadFile,
		adapterapi.EffectPayloadEdit,
		adapterapi.EffectPayloadRecall,
		adapterapi.EffectPayloadSetGroupCard,
		adapterapi.EffectPayloadQuit,
		adapterapi.EffectPayloadBan,
		adapterapi.EffectPayloadKick,
		adapterapi.EffectPayloadGroupInfoRefresh,
		adapterapi.EffectPayloadAnswerRequest:
		return adapterapi.UnsupportedResult("http_effect_not_supported")
	}
	if messageType == "" {
		return adapterapi.UnsupportedResult("http_effect_not_supported")
	}
	runtime.mu.Lock()
	connected := runtime.running && runtime.connected
	runtime.mu.Unlock()
	if !connected {
		return adapterapi.TerminalResult("http_provider_unavailable", "provider unavailable")
	}
	body, err := json.Marshal(HTTPSimpleMessage{UID: effect.Payload.Target.Conversation.String(), Message: effect.Payload.Text, MessageType: messageType})
	if err != nil {
		return adapterapi.TerminalResult("http_invalid_request", "request payload is invalid")
	}
	request, err := http.NewRequestWithContext(ctx, runtime.config.Method, runtime.target, bytes.NewReader(body))
	if err != nil {
		return adapterapi.TerminalResult("http_invalid_request", "request is invalid")
	}
	request.Header.Set("Content-Type", "application/json")
	if runtime.tokenRef != nil {
		if runtime.resolver == nil {
			return adapterapi.TerminalResult("http_secret_unavailable", "token resolver is unavailable")
		}
		value, resolveErr := runtime.resolver.Resolve(ctx, *runtime.tokenRef)
		if resolveErr != nil || value.Version != runtime.tokenRef.Version || len(value.Bytes) == 0 {
			return adapterapi.TerminalResult("http_secret_unavailable", "token resolution failed")
		}
		request.Header.Set("Authorization", "Bearer "+string(value.Bytes))
	}
	response, err := runtime.client.Do(request)
	if err != nil {
		if errors.Is(err, errHTTPAdapterRedirectLimit) || errors.Is(err, errHTTPAdapterRedirectTarget) || errors.Is(err, errHTTPAdapterRedirectDowngrade) {
			return adapterapi.AmbiguousResult("http_redirect_policy", "provider redirect was rejected")
		}
		return adapterapi.AmbiguousResult("http_provider_ambiguous", "provider dispatch outcome is unknown")
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, httpAdapterMaxResponseBytes+1))
	if err != nil {
		return adapterapi.AmbiguousResult("http_provider_ambiguous", "provider response could not be read")
	}
	if int64(len(responseBody)) > httpAdapterMaxResponseBytes {
		return adapterapi.AmbiguousResult("http_response_too_large", "provider response exceeded the configured bound")
	}
	if response.StatusCode == http.StatusTooManyRequests {
		return adapterapi.RetryableResult("http_rate_limited", "provider rate limited the request")
	}
	if response.StatusCode >= http.StatusInternalServerError {
		return adapterapi.AmbiguousResult("http_provider_ambiguous", "provider dispatch outcome is unknown")
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return adapterapi.TerminalResult("http_provider_rejected", "provider rejected the request")
	}
	providerID := httpAdapterResponseID(responseBody)
	result := adapterapi.SucceededResult(providerID)
	if result.Validate() != nil {
		return adapterapi.SucceededResult("")
	}
	return result
}

func httpAdapterResponseID(body []byte) string {
	var response struct {
		ID        string `json:"id"`
		MessageID string `json:"messageId"`
		SnakeID   string `json:"message_id"`
	}
	if json.Unmarshal(body, &response) != nil {
		return ""
	}
	if response.ID != "" {
		return response.ID
	}
	if response.MessageID != "" {
		return response.MessageID
	}
	return response.SnakeID
}

func (runtime *httpAdapterRuntime) Run(ctx context.Context, core adapterapi.CorePort) (runErr error) {
	if runtime == nil || core == nil {
		return errors.New("http: runtime or core is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithCancel(ctx)
	runtime.mu.Lock()
	if runtime.cancel != nil {
		runtime.mu.Unlock()
		cancel()
		return errors.New("http: runtime already started")
	}
	runtime.cancel, runtime.running = cancel, true
	runtime.mu.Unlock()
	defer func() { _ = runtime.Stop(context.Background()) }()
	if err := core.ReportObservation(runCtx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateStarting, Code: "starting", Detail: "HTTP runtime starting", OccurredAt: time.Now().UTC()}); err != nil {
		return err
	}
	runtime.mu.Lock()
	if !runtime.running {
		runtime.mu.Unlock()
		return nil
	}
	runtime.connected = true
	runtime.mu.Unlock()
	if err := core.ReportObservation(runCtx, adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationState, State: adapterapi.ObservedStateConnected, Code: "connected", Detail: "HTTP request client ready", OccurredAt: time.Now().UTC()}); err != nil {
		return err
	}
	<-runCtx.Done()
	return nil
}

func (runtime *httpAdapterRuntime) Stop(context.Context) error {
	if runtime == nil {
		return nil
	}
	runtime.mu.Lock()
	cancel := runtime.cancel
	runtime.cancel = nil
	runtime.running = false
	runtime.connected = false
	runtime.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if runtime.transport != nil {
		runtime.transport.CloseIdleConnections()
	}
	return nil
}
