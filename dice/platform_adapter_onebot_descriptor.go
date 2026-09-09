package dice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"Scardice-core/adapterapi"
)

const (
	OnebotAdapterKey      adapterapi.AdapterKey = "pureonebot"
	PureOnebotAdapterKey                       = OnebotAdapterKey
	OnebotConfigVersion                        = uint16(1)
	onebotConfigVersion                        = OnebotConfigVersion
)

// OnebotConfig is the typed, non-secret pure OneBot endpoint configuration.
// Token identifies encrypted material in the event store; it never carries
// token bytes.
type OnebotConfig struct {
	Mode                string                 `json:"mode"`
	URL                 string                 `json:"url,omitempty"`
	ClientURL           string                 `json:"clientUrl,omitempty"`
	ConnectURL          string                 `json:"connectUrl,omitempty"`
	ListenAddress       string                 `json:"listenAddress,omitempty"`
	ReverseURL          string                 `json:"reverseUrl,omitempty"`
	ReverseSuffix       string                 `json:"reverseSuffix"`
	AccountHint         string                 `json:"accountHint,omitempty"`
	FriendRequestPolicy string                 `json:"friendRequestPolicy"`
	IgnoreFriendRequest bool                   `json:"ignoreFriendRequest,omitempty"`
	ImageAssetBaseURL   string                 `json:"imageAssetBaseUrl,omitempty"`
	InsecureSkipVerify  bool                   `json:"insecureSkipVerify"`
	Token               adapterapi.SecretRef   `json:"token"`

}

// PureOnebotConfig is retained as a descriptive spelling for callers that use
// the provider name rather than its historical Onebot casing.
type PureOnebotConfig = OnebotConfig

type OnebotDescriptor struct{ listenerFactory onebotListenerFactory }
type PureOnebotDescriptor = OnebotDescriptor

func NewOnebotDescriptor() adapterapi.Descriptor { return OnebotDescriptor{} }
func NewPureOnebotDescriptor() adapterapi.Descriptor { return OnebotDescriptor{} }
func newOnebotDescriptorWithListenerFactory(factory onebotListenerFactory) adapterapi.Descriptor {
	return OnebotDescriptor{listenerFactory: factory}
}

func (OnebotDescriptor) Key() adapterapi.AdapterKey { return OnebotAdapterKey }
func (OnebotDescriptor) ConfigVersion() uint16       { return onebotConfigVersion }
type onebotConfigInput struct {
	Mode                string           `json:"mode"`
	URL                 string           `json:"url"`
	ClientURL           string           `json:"clientUrl"`
	ConnectURL          string           `json:"connectUrl"`
	ListenAddress       string           `json:"listenAddress"`
	ReverseURL          string           `json:"reverseUrl"`
	ReverseSuffix       string           `json:"reverseSuffix"`
	AccountHint         string           `json:"accountHint"`
	FriendRequestPolicy string           `json:"friendRequestPolicy"`
	IgnoreFriendRequest *bool            `json:"ignoreFriendRequest"`
	IgnoreFriendRequestLegacy *bool      `json:"ignore_friend_request"`
	ImageAssetBaseURL   string           `json:"imageAssetBaseUrl"`
	InsecureSkipVerify  bool             `json:"insecureSkipVerify"`
	Token               json.RawMessage  `json:"token"`
	TokenSecretRef      string           `json:"tokenSecretRef"`
	TokenSecretVersion  *uint64          `json:"tokenSecretVersion"`
}

type onebotTokenInput struct {
	SecretRef string `json:"secretRef"`
	Ref       string `json:"ref"`
	Version   uint64 `json:"version"`
}

type onebotCanonicalConfig struct {
	Mode                string                  `json:"mode"`
	URL                 string                  `json:"url,omitempty"`
	ListenAddress       string                  `json:"listenAddress,omitempty"`
	ReverseSuffix       string                  `json:"reverseSuffix"`
	AccountHint         string                  `json:"accountHint,omitempty"`
	FriendRequestPolicy string                  `json:"friendRequestPolicy"`
	ImageAssetBaseURL   string                  `json:"imageAssetBaseUrl,omitempty"`
	InsecureSkipVerify  bool                    `json:"insecureSkipVerify"`
	Token               *onebotCanonicalToken   `json:"token,omitempty"`
}

type onebotCanonicalToken struct {
	SecretRef string `json:"secretRef"`
	Version   uint64 `json:"version"`
}

func (OnebotDescriptor) ValidateConfig(ctx context.Context, raw json.RawMessage) (adapterapi.ValidatedConfig, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	if hasControl(raw) {
		return adapterapi.ValidatedConfig{}, invalidOnebotConfig("control character")
	}
	var rawFields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rawFields); err == nil {
		for _, key := range []string{"ignoreFriendRequest", "ignore_friend_request", "tokenSecretVersion"} {
			if value, ok := rawFields[key]; ok && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return adapterapi.ValidatedConfig{}, invalidOnebotConfig("%s cannot be null", key)
			}
		}
	}
	var input onebotConfigInput
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return adapterapi.ValidatedConfig{}, invalidOnebotConfig("invalid JSON: %v", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return adapterapi.ValidatedConfig{}, invalidOnebotConfig("multiple JSON values")
	} else if !errors.Is(err, io.EOF) {
		return adapterapi.ValidatedConfig{}, invalidOnebotConfig("trailing JSON: %v", err)
	}
	mode := strings.ToLower(strings.TrimSpace(input.Mode))
	if mode != "client" && mode != "server" {
		return adapterapi.ValidatedConfig{}, invalidOnebotConfig("mode must be client or server")
	}
	if err := rejectOnebotAliasConflict("client URL", input.URL, input.ClientURL, input.ConnectURL); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	if err := rejectOnebotAliasConflict("reverse listen address", input.ListenAddress, input.ReverseURL); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	endpointURL := strings.TrimSpace(input.URL)
	if endpointURL == "" {
		endpointURL = strings.TrimSpace(input.ClientURL)
	}
	if endpointURL == "" {
		endpointURL = strings.TrimSpace(input.ConnectURL)
	}
	listenAddress := strings.TrimSpace(input.ListenAddress)
	if listenAddress == "" {
		listenAddress = strings.TrimSpace(input.ReverseURL)
	}
	if mode == "client" && endpointURL == "" {
		return adapterapi.ValidatedConfig{}, invalidOnebotConfig("client URL is required")
	}
	if mode == "server" && listenAddress == "" {
		return adapterapi.ValidatedConfig{}, invalidOnebotConfig("reverse listen address is required")
	}
	if endpointURL != "" && mode == "client" {
		if err := validateOnebotURL(endpointURL); err != nil {
			return adapterapi.ValidatedConfig{}, err
		}
	}
	if mode == "server" {
		if err := validateOnebotListenAddress(listenAddress); err != nil {
			return adapterapi.ValidatedConfig{}, err
		}
	}
	suffix := strings.TrimSpace(input.ReverseSuffix)
	if suffix == "" {
		suffix = "/ws"
	}
	if err := validateOnebotSuffix(suffix); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	if err := validateOnebotText(input.AccountHint, "account hint", 256); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	policy := strings.ToLower(strings.TrimSpace(input.FriendRequestPolicy))
	if input.IgnoreFriendRequest != nil && input.IgnoreFriendRequestLegacy != nil && *input.IgnoreFriendRequest != *input.IgnoreFriendRequestLegacy {
		return adapterapi.ValidatedConfig{}, invalidOnebotConfig("friend request ignore aliases conflict")
	}
	var boolPolicy string
	if input.IgnoreFriendRequest != nil || input.IgnoreFriendRequestLegacy != nil {
		ignore := false
		if input.IgnoreFriendRequest != nil {
			ignore = *input.IgnoreFriendRequest
		} else {
			ignore = *input.IgnoreFriendRequestLegacy
		}
		if ignore {
			boolPolicy = "ignore"
		} else {
			boolPolicy = "accept"
		}
	}
	if policy != "" && boolPolicy != "" && policy != boolPolicy {
		return adapterapi.ValidatedConfig{}, invalidOnebotConfig("friend request policy aliases conflict")
	}
	if policy == "" {
		policy = boolPolicy
		if policy == "" {
			policy = "accept"
		}
	}
	if policy != "accept" && policy != "ignore" && policy != "manual" && policy != "deny" {
		return adapterapi.ValidatedConfig{}, invalidOnebotConfig("friend request policy is invalid")
	}
	rawImageBase := strings.TrimSpace(input.ImageAssetBaseURL)
	imageBase := strings.TrimRight(rawImageBase, "/")
	if rawImageBase != "" {
		if imageBase == "" {
			return adapterapi.ValidatedConfig{}, invalidOnebotConfig("image asset base URL is invalid")
		}
		if err := validateOnebotHTTPURL(imageBase); err != nil {
			return adapterapi.ValidatedConfig{}, fmt.Errorf("onebot: invalid image asset base URL: %w", err)
		}
	}
	token, hasToken, err := parseOnebotToken(input)
	if err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	if mode == "server" && !hasToken {
		return adapterapi.ValidatedConfig{}, invalidOnebotConfig("reverse listener requires a token secret reference")
	}
	canonical := onebotCanonicalConfig{
		Mode: mode, URL: endpointURL, ListenAddress: listenAddress, ReverseSuffix: suffix,
		AccountHint: input.AccountHint, FriendRequestPolicy: policy, ImageAssetBaseURL: imageBase,
		InsecureSkipVerify: input.InsecureSkipVerify,
	}
	if hasToken {
		canonical.Token = &onebotCanonicalToken{SecretRef: token.Ref, Version: token.Version}
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return adapterapi.ValidatedConfig{}, invalidOnebotConfig("canonical config: %v", err)
	}
	canonicalJSON, err := adapterapi.CanonicalizeJSON(encoded)
	if err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	refs := []adapterapi.SecretRef(nil)
	if hasToken {
		refs = []adapterapi.SecretRef{token}
	}
	validated := adapterapi.ValidatedConfig{Version: onebotConfigVersion, Canonical: canonicalJSON, SecretRefs: refs}
	if err := validated.Validate(); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	return validated, nil
}

func (d OnebotDescriptor) SupportedActions(adapterapi.ValidatedConfig) adapterapi.ActionSet {
	return onebotSupportedActions()
}

func (d OnebotDescriptor) NewRuntime(init adapterapi.RuntimeInit) (adapterapi.AdapterRuntime, error) {
	if init.EndpointID == "" || !init.EndpointID.Valid() || init.Generation == 0 || init.DesiredVersion == 0 {
		return nil, errors.New("onebot: runtime identity is incomplete")
	}
	if err := init.Config.Validate(); err != nil {
		return nil, err
	}
	validated, err := d.ValidateConfig(context.Background(), init.Config.Canonical)
	if err != nil || validated.Version != init.Config.Version || !bytes.Equal(validated.Canonical, init.Config.Canonical) || len(validated.SecretRefs) != len(init.Config.SecretRefs) {
		return nil, invalidOnebotConfig("runtime config was not validated by the OneBot descriptor")
	}
	for index := range validated.SecretRefs {
		if validated.SecretRefs[index] != init.Config.SecretRefs[index] {
			return nil, invalidOnebotConfig("runtime secret references do not match canonical config")
		}
	}
	config, err := d.decodeValidatedConfig(init.Config)
	if err != nil {
		return nil, err
	}
	return newOnebotRuntime(config, init.Secrets, d.listenerFactory), nil
}

func (OnebotDescriptor) decodeValidatedConfig(config adapterapi.ValidatedConfig) (OnebotConfig, error) {
	var canonical onebotCanonicalConfig
	if err := json.Unmarshal(config.Canonical, &canonical); err != nil {
		return OnebotConfig{}, invalidOnebotConfig("canonical config: %v", err)
	}
	result := OnebotConfig{
		Mode: canonical.Mode, URL: canonical.URL, ClientURL: canonical.URL, ConnectURL: canonical.URL,
		ListenAddress: canonical.ListenAddress, ReverseURL: canonical.ListenAddress,
		ReverseSuffix: canonical.ReverseSuffix, AccountHint: canonical.AccountHint,
		FriendRequestPolicy: canonical.FriendRequestPolicy, IgnoreFriendRequest: canonical.FriendRequestPolicy == "ignore",
		ImageAssetBaseURL: canonical.ImageAssetBaseURL, InsecureSkipVerify: canonical.InsecureSkipVerify,
	}
	if canonical.Token != nil {
		result.Token = adapterapi.SecretRef{Ref: canonical.Token.SecretRef, Version: canonical.Token.Version}
	}
	return result, nil
}

func parseOnebotToken(input onebotConfigInput) (adapterapi.SecretRef, bool, error) {
	if len(input.Token) == 0 && input.TokenSecretRef == "" && input.TokenSecretVersion == nil {
		return adapterapi.SecretRef{}, false, nil
	}
	if len(input.Token) > 0 && string(input.Token) != "null" {
		var token onebotTokenInput
		tokenDecoder := json.NewDecoder(bytes.NewReader(input.Token))
		tokenDecoder.DisallowUnknownFields()
		if err := tokenDecoder.Decode(&token); err != nil {
			return adapterapi.SecretRef{}, false, invalidOnebotConfig("token must contain only secretRef and version")
		}
		var extra any
		if err := tokenDecoder.Decode(&extra); err != io.EOF {
			return adapterapi.SecretRef{}, false, invalidOnebotConfig("token must contain only secretRef and version")
		}
		if token.SecretRef != "" && token.Ref != "" && token.SecretRef != token.Ref {
			return adapterapi.SecretRef{}, false, invalidOnebotConfig("token secret references conflict")
		}
		if token.SecretRef == "" {
			token.SecretRef = token.Ref
		}
		if token.SecretRef == "" {
			return adapterapi.SecretRef{}, false, invalidOnebotConfig("token secretRef is required")
		}
		if input.TokenSecretRef != "" && input.TokenSecretRef != token.SecretRef {
			return adapterapi.SecretRef{}, false, invalidOnebotConfig("token secret references conflict")
		}
		if input.TokenSecretVersion != nil && *input.TokenSecretVersion != token.Version {
			return adapterapi.SecretRef{}, false, invalidOnebotConfig("token secret versions conflict")
		}
		input.TokenSecretRef = token.SecretRef
		if input.TokenSecretVersion == nil {
			input.TokenSecretVersion = &token.Version
		}
	}
	if input.TokenSecretRef == "" {
		return adapterapi.SecretRef{}, false, invalidOnebotConfig("token secretRef is required")
	}
	version := uint64(0)
	if input.TokenSecretVersion != nil {
		version = *input.TokenSecretVersion
	}
	ref := adapterapi.SecretRef{Ref: strings.TrimSpace(input.TokenSecretRef), Version: version}
	if ref.Version == 0 {
		return adapterapi.SecretRef{}, false, invalidOnebotConfig("token secret version is required")
	}
	if err := ref.Validate(); err != nil {
		return adapterapi.SecretRef{}, false, invalidOnebotConfig("invalid token secret reference: %v", err)
	}
	return ref, true, nil
}

func validateOnebotURL(raw string) error {
	if hasControl([]byte(raw)) {
		return invalidOnebotConfig("URL contains control character")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return invalidOnebotConfig("invalid URL: %v", err)
	}
	if u.Scheme != "ws" && u.Scheme != "wss" {
		return invalidOnebotConfig("URL scheme must be ws or wss")
	}
	if u.User != nil {
		return invalidOnebotConfig("URL userinfo is not allowed")
	}
	if u.Fragment != "" {
		return invalidOnebotConfig("URL fragment is not allowed")
	}
	if u.Host == "" || u.Hostname() == "" {
		return invalidOnebotConfig("URL host is required")
	}
	if err := validateOnebotURLAuthority(u.Host); err != nil {
		return err
	}
	if strings.ContainsAny(u.Host, "\r\n") {
		return invalidOnebotConfig("URL host contains control character")
	}
	return nil
}

func validOnebotPort(port string) bool {
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535
}

func validateOnebotURLAuthority(host string) error {
	if host == "" {
		return invalidOnebotConfig("URL host is required")
	}
	if strings.HasPrefix(host, "[") {
		end := strings.IndexByte(host, ']')
		if end <= 1 {
			return invalidOnebotConfig("URL host is malformed")
		}
		ip := host[1:end]
		if percent := strings.LastIndexByte(ip, '%'); percent >= 0 {
			ip = ip[:percent]
		}
		if net.ParseIP(ip) == nil {
			return invalidOnebotConfig("URL bracketed host must be IPv6")
		}
		rest := host[end+1:]
		if rest != "" && (!strings.HasPrefix(rest, ":") || !validOnebotPort(rest[1:])) {
			return invalidOnebotConfig("URL port is invalid")
		}
		return nil
	}
	if strings.ContainsAny(host, "[]") || strings.Count(host, ":") > 1 {
		return invalidOnebotConfig("URL host is malformed")
	}
	if colon := strings.IndexByte(host, ':'); colon >= 0 {
		if colon == 0 || !validOnebotPort(host[colon+1:]) {
			return invalidOnebotConfig("URL port is invalid")
		}
	}
	return nil
}

func validateOnebotHTTPURL(raw string) error {
	if hasControl([]byte(raw)) {
		return invalidOnebotConfig("HTTP URL contains control character")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" || u.Hostname() == "" {
		return invalidOnebotConfig("image asset base URL must be an http/https URL without userinfo or fragment")
	}
	if err := validateOnebotURLAuthority(u.Host); err != nil {
		return err
	}
	if hasControl([]byte(u.Host)) {
		return invalidOnebotConfig("HTTP URL host contains control character")
	}
	return nil
}

func validateOnebotListenAddress(raw string) error {
	if hasControl([]byte(raw)) {
		return invalidOnebotConfig("listen address contains control character")
	}
	host, port, err := net.SplitHostPort(raw)
	if err != nil || host == "" || port == "" {
		return invalidOnebotConfig("listen address must include host and port")
	}
	if !validOnebotPort(port) {
		return invalidOnebotConfig("listen address port is invalid")
	}
	if strings.ContainsAny(host, "[]") {
		return invalidOnebotConfig("listen address host is malformed")
	}
	if strings.HasPrefix(raw, "[") {
		ipHost := host
		if percent := strings.LastIndexByte(ipHost, '%'); percent >= 0 {
			ipHost = ipHost[:percent]
		}
		if net.ParseIP(ipHost) == nil {
			return invalidOnebotConfig("listen address bracketed host must be IPv6")
		}
	}
	return validateOnebotListenHost(host)
}

func validateOnebotListenHost(host string) error {
	if host == "" || hasControl([]byte(host)) || strings.ContainsAny(host, "/\\ \t") {
		return invalidOnebotConfig("listen address host is malformed")
	}
	if strings.Contains(host, ":") {
		ipHost := host
		if percent := strings.LastIndexByte(ipHost, '%'); percent >= 0 {
			if percent == len(ipHost)-1 {
				return invalidOnebotConfig("listen address host is malformed")
			}
			ipHost = ipHost[:percent]
		}
		if net.ParseIP(ipHost) == nil {
			return invalidOnebotConfig("listen address host is malformed")
		}
		return nil
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || label[0] == '-' || label[len(label)-1] == '-' {
			return invalidOnebotConfig("listen address host is malformed")
		}
		for _, r := range label {
			if !(r == '-' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
				return invalidOnebotConfig("listen address host is malformed")
			}
		}
	}
	return nil
}

func validateOnebotSuffix(suffix string) error {
	if suffix == "" || !strings.HasPrefix(suffix, "/") || strings.ContainsAny(suffix, "?#") || hasControl([]byte(suffix)) {
		return invalidOnebotConfig("reverse suffix must be an absolute path")
	}
	return nil
}

func validateOnebotText(value, name string, max int) error {
	if len(value) > max || hasControl([]byte(value)) {
		return invalidOnebotConfig("%s is invalid", name)
	}
	return nil
}
func rejectOnebotAliasConflict(name string, values ...string) error {
	expected := ""
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if expected == "" {
			expected = value
			continue
		}
		if expected != value {
			return invalidOnebotConfig("%s aliases conflict", name)
		}
	}
	return nil
}


func invalidOnebotConfig(format string, args ...any) error {
	return fmt.Errorf("onebot: %w: %s", adapterapi.ErrInvalidConfig, fmt.Sprintf(format, args...))
}

func hasControl(raw []byte) bool {
	for _, r := range string(raw) {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}
