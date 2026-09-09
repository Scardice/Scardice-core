package dice

import (
	"Scardice-core/adapterapi"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode"
)

const compatAdapterConfigVersion uint16 = 1

// ErrAdapterProviderUnavailable is returned by compatibility runtimes whose
// legacy provider has not yet been migrated to the endpoint seam.
var ErrAdapterProviderUnavailable = errors.New("adapter provider unavailable")

type compatFieldKind uint8

const (
	compatString compatFieldKind = iota + 1
	compatURL
	compatBool
	compatInteger
	compatScalar
	compatObject
)

type compatAdapterDescriptor struct {
	key    adapterapi.AdapterKey
	fields map[string]compatFieldKind
}

var compatCommonFields = map[string]compatFieldKind{
	"url": compatURL, "baseUrl": compatURL, "apiUrl": compatURL, "wsUrl": compatURL,
	"webhookUrl": compatURL, "endpoint": compatURL, "proxy": compatURL,
	"mode": compatString, "account": compatString, "accountHint": compatString,
	"accountType": compatInteger, "nickname": compatString, "appVersion": compatString,
	"friendRequestPolicy": compatString, "signServerName": compatString, "signServerVersion": compatString,
	"relWorkDir": compatString, "useSignServer": compatBool, "imageAssetBaseUrl": compatURL,
	"wsGateway": compatURL, "restGateway": compatURL,
	"insecureSkipVerify": compatBool, "timeoutSeconds": compatInteger,
}

var compatProviderFields = map[string]compatFieldKind{
	"connectUrl": compatURL, "proxyURL": compatURL, "reverseProxyUrl": compatURL, "reverseProxyCDNUrl": compatURL,
	"ws_gateway": compatURL, "rest_gateway": compatURL, "signServer": compatURL,
	"channel": compatString, "guild": compatString, "username": compatString, "region": compatString, "botId": compatString,
	"method": compatString, "path": compatString, "serverAddress": compatString, "clientId": compatString,
	"clientID": compatString, "robotCode": compatString, "coolAppCode": compatString, "stream": compatBool,
	"appId": compatScalar, "appID": compatScalar, "islandId": compatString, "tenant": compatString,
	"platform": compatString, "selfId": compatString, "eventPath": compatString, "chatId": compatString,
	"authMode": compatString, "device": compatString, "protocol": compatScalar, "host": compatString,
	"redVersion": compatString, "builtinMode": compatString, "built_in_mode": compatString,
	"implementation": compatString, "reverseAddr": compatString,
	"reconnect": compatBool, "autoReconnect": compatBool, "sandbox": compatBool, "isReverse": compatBool,
	"useInPackGoCqhttp": compatBool, "useInPackWalleQ": compatBool,
	"ignoreFriendRequest": compatBool, "ignore_friend_request": compatBool, "onlyQQGuild": compatBool,
	"port": compatInteger, "version": compatScalar, "signServerConfig": compatObject,
}

var compatSecretFields = map[string]struct{}{
	"token": {}, "secret": {}, "password": {}, "appToken": {}, "appSecret": {}, "signingSecret": {},
	"clientSecret": {}, "accessToken": {}, "botToken": {},
}

// NewAdapterDescriptors returns the built-in endpoint seam descriptors in a
// stable order. Non-pure-OneBot entries are intentionally inert until their
// provider implementation is migrated; they never claim a live connection.
func NewAdapterDescriptors() []adapterapi.Descriptor {
	return []adapterapi.Descriptor{
		newCompatAdapterDescriptor("gocq", "connectUrl", "device", "protocol", "signServer", "signServerConfig", "autoReconnect", "useInPackGoCqhttp", "builtinMode", "isReverse", "reverseAddr"),
		newCompatAdapterDescriptor("lagrange", "connectUrl", "device", "protocol", "signServer", "signServerConfig", "autoReconnect", "useInPackGoCqhttp", "builtinMode", "isReverse", "reverseAddr"),
		newCompatAdapterDescriptor("walleq", "connectUrl", "device", "protocol", "appId", "autoReconnect", "useInPackWalleQ"),
		newCompatAdapterDescriptor("red", "device", "protocol", "appId", "host", "port", "redVersion"),
		newCompatAdapterDescriptor("official_qq", "appId", "sandbox", "appID", "onlyQQGuild"),
		newCompatAdapterDescriptor("satori", "platform", "selfId", "eventPath", "version", "host", "port"),
		newCompatAdapterDescriptor("milky", "version", "ws_gateway", "rest_gateway", "built_in_mode", "ignore_friend_request"),
		newCompatAdapterDescriptor("discord", "guild", "channel", "version", "proxyURL", "reverseProxyUrl", "reverseProxyCDNUrl"),
		newCompatAdapterDescriptor("kook", "guild", "channel", "version"),
		newCompatAdapterDescriptor("telegram", "chatId", "webhookUrl", "proxyURL"),
		newCompatAdapterDescriptor("slack", "channel", "version"),
		newCompatAdapterDescriptor("dodo", "islandId", "botId", "clientID"),
		newCompatAdapterDescriptor("dingtalk", "clientId", "robotCode", "coolAppCode", "stream"),
		newCompatAdapterDescriptor("minecraft", "serverAddress", "username", "authMode", "connectUrl"),
		newCompatAdapterDescriptor("sealchat", "appId", "tenant", "connectUrl"),
		newCompatAdapterDescriptor("http", "method", "path"),
		NewOnebotDescriptor(),
	}
}

// AllAdapterDescriptors is a compatibility spelling for callers that used the
// registry before it was named NewAdapterDescriptors.
func AllAdapterDescriptors() []adapterapi.Descriptor { return NewAdapterDescriptors() }

func newCompatAdapterDescriptor(key string, extras ...string) adapterapi.Descriptor {
	fields := make(map[string]compatFieldKind, len(compatCommonFields)+len(extras))
	for name, kind := range compatCommonFields {
		fields[name] = kind
	}
	for _, name := range extras {
		if kind, ok := compatProviderFields[name]; ok {
			fields[name] = kind
		}
	}
	return &compatAdapterDescriptor{key: adapterapi.AdapterKey(key), fields: fields}
}
func (*compatAdapterDescriptor) Capabilities(adapterapi.ValidatedConfig) adapterapi.CapabilitySet {
	return adapterapi.CapabilityLifecycle
}

func (d *compatAdapterDescriptor) Key() adapterapi.AdapterKey { return d.key }
func (*compatAdapterDescriptor) ConfigVersion() uint16        { return compatAdapterConfigVersion }
func (*compatAdapterDescriptor) SupportedActions(adapterapi.ValidatedConfig) adapterapi.ActionSet {
	return adapterapi.ActionSet(0)
}

func (d *compatAdapterDescriptor) ValidateConfig(ctx context.Context, raw json.RawMessage) (adapterapi.ValidatedConfig, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	if hasCompatControl(raw) {
		return adapterapi.ValidatedConfig{}, compatInvalidConfig("control character")
	}
	fields, err := decodeCompatObject(raw)
	if err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	canonical := make(map[string]any, len(fields))
	refs := make([]adapterapi.SecretRef, 0, 2)
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		value := fields[name]
		if _, ok := d.fields[name]; !ok {
			if _, secret := compatSecretFields[name]; !secret && name != "secretRef" && name != "secretRefs" {
				return adapterapi.ValidatedConfig{}, compatInvalidConfig("unknown field %q", name)
			}
		}
		if name == "secretRef" {
			canonicalValue, ref, err := parseCompatSecretRef(value, "secretRef")
			if err != nil {
				return adapterapi.ValidatedConfig{}, err
			}
			canonical[name] = canonicalValue
			refs = appendCompatSecretRef(refs, ref)
			continue
		}
		if name == "secretRefs" {
			canonicalValue, extracted, err := parseCompatSecretRefs(value)
			if err != nil {
				return adapterapi.ValidatedConfig{}, err
			}
			canonical[name] = canonicalValue
			for _, ref := range extracted {
				refs = appendCompatSecretRef(refs, ref)
			}
			continue
		}
		if _, secret := compatSecretFields[name]; secret {
			canonicalValue, ref, err := parseCompatSecretValue(value, name)
			if err != nil {
				return adapterapi.ValidatedConfig{}, err
			}
			canonical[name] = canonicalValue
			refs = appendCompatSecretRef(refs, ref)
			continue
		}
		normalized, nestedRefs, err := normalizeCompatField(name, d.fields[name], value)
		if err != nil {
			return adapterapi.ValidatedConfig{}, err
		}
		canonical[name] = normalized
		for _, ref := range nestedRefs {
			refs = appendCompatSecretRef(refs, ref)
		}
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return adapterapi.ValidatedConfig{}, compatInvalidConfig("canonical config: %v", err)
	}
	canonicalJSON, err := adapterapi.CanonicalizeJSON(encoded)
	if err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	validated := adapterapi.ValidatedConfig{Version: compatAdapterConfigVersion, Canonical: canonicalJSON, SecretRefs: refs}
	if err := validated.Validate(); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	return validated, nil
}

func (d *compatAdapterDescriptor) NewRuntime(init adapterapi.RuntimeInit) (adapterapi.AdapterRuntime, error) {
	if init.EndpointID == "" || !init.EndpointID.Valid() || init.Generation == 0 || init.DesiredVersion == 0 {
		return nil, fmt.Errorf("%s: runtime identity is incomplete", d.key)
	}
	if err := init.Config.Validate(); err != nil {
		return nil, err
	}
	validated, err := d.ValidateConfig(context.Background(), init.Config.Canonical)
	if err != nil || validated.Version != init.Config.Version || !bytes.Equal(validated.Canonical, init.Config.Canonical) || !sameCompatSecretRefs(validated.SecretRefs, init.Config.SecretRefs) {
		return nil, fmt.Errorf("%s: runtime config was not validated by descriptor", d.key)
	}
	return &compatAdapterRuntime{key: d.key, stopCh: make(chan struct{})}, nil
}

type compatAdapterRuntime struct {
	key    adapterapi.AdapterKey
	stopCh chan struct{}
	once   sync.Once
}

func (r *compatAdapterRuntime) Run(ctx context.Context, _ adapterapi.CorePort) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return fmt.Errorf("%s: %w", r.key, ErrAdapterProviderUnavailable)
}

func (r *compatAdapterRuntime) Stop(context.Context) error {
	if r == nil {
		return nil
	}
	r.once.Do(func() { close(r.stopCh) })
	return nil
}

func (r *compatAdapterRuntime) Capabilities() adapterapi.CapabilitySet {
	return adapterapi.CapabilityLifecycle
}

func (r *compatAdapterRuntime) Execute(context.Context, adapterapi.OutboundEffect) adapterapi.EffectResult {
	return adapterapi.UnsupportedResult("provider_unavailable")
}
func (r *compatAdapterRuntime) Diagnostics(context.Context) adapterapi.DiagnosticReport {
	return adapterapi.DiagnosticReport{Entries: []adapterapi.DiagnosticEntry{{
		Severity: adapterapi.DiagnosticError,
		Code:     "provider_unavailable",
		Message:  "adapter provider is unavailable; legacy provider migration is required",
		Fields:   []adapterapi.DiagnosticField{adapterapi.RedactedDiagnosticField("adapter")},
	}}}
}

func decodeCompatObject(raw []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var fields map[string]json.RawMessage
	if err := decoder.Decode(&fields); err != nil || fields == nil {
		return nil, compatInvalidConfig("configuration must be a JSON object")
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return nil, compatInvalidConfig("multiple JSON values")
	} else if !errors.Is(err, io.EOF) {
		return nil, compatInvalidConfig("trailing JSON: %v", err)
	}
	return fields, nil
}
func normalizeCompatField(name string, kind compatFieldKind, raw json.RawMessage) (any, []adapterapi.SecretRef, error) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil, compatInvalidConfig("field %q cannot be null", name)
	}
	switch kind {
	case compatURL:
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, nil, compatInvalidConfig("field %q must be a URL string", name)
		}
		value = strings.TrimSpace(value)
		if err := validateCompatURL(value); err != nil {
			return nil, nil, fmt.Errorf("%w: field %q: %v", adapterapi.ErrInvalidConfig, name, err)
		}
		return value, nil, nil
	case compatString:
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, nil, compatInvalidConfig("field %q must be a string", name)
		}
		value = strings.TrimSpace(value)
		if value == "" || len(value) > 4096 || hasCompatControl([]byte(value)) {
			return nil, nil, compatInvalidConfig("field %q is empty or invalid", name)
		}
		return value, nil, nil
	case compatBool:
		var value bool
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, nil, compatInvalidConfig("field %q must be boolean", name)
		}
		if name == "insecureSkipVerify" && value {
			return nil, nil, compatInvalidConfig("TLS certificate verification cannot be disabled")
		}
		return value, nil, nil
	case compatInteger:
		var value json.Number
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			return nil, nil, compatInvalidConfig("field %q must be an integer", name)
		}
		integer, err := strconv.ParseInt(string(value), 10, 64)
		if err != nil || integer < 0 || integer > 86400 {
			return nil, nil, compatInvalidConfig("field %q is out of range", name)
		}
		return integer, nil, nil
	case compatScalar:
		var value any
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			return nil, nil, compatInvalidConfig("field %q is invalid", name)
		}
		switch typed := value.(type) {
		case string:
			if typed == "" || len(typed) > 4096 || hasCompatControl([]byte(typed)) {
				return nil, nil, compatInvalidConfig("field %q is empty or invalid", name)
			}
			return strings.TrimSpace(typed), nil, nil
		case bool, json.Number:
			return typed, nil, nil
		default:
			return nil, nil, compatInvalidConfig("field %q must be scalar", name)
		}
	case compatObject:
		object, refs, err := normalizeCompatObject(name, raw)
		return object, refs, err
	default:
		return nil, nil, compatInvalidConfig("field %q has unknown type", name)
	}
}

func normalizeCompatObject(name string, raw json.RawMessage) (map[string]any, []adapterapi.SecretRef, error) {
	if name != "signServerConfig" {
		return nil, nil, compatInvalidConfig("field %q has unknown object type", name)
	}
	fields, err := decodeCompatObject(raw)
	if err != nil {
		return nil, nil, err
	}
	canonical := make(map[string]any, len(fields))
	refs := make([]adapterapi.SecretRef, 0, 2)
	names := make([]string, 0, len(fields))
	for key := range fields {
		names = append(names, key)
	}
	sort.Strings(names)
	for _, key := range names {
		value := fields[key]
		switch key {
		case "signServers":
			var entries []json.RawMessage
			if err := json.Unmarshal(value, &entries); err != nil || entries == nil || len(entries) > adapterapi.MaxSecretRefs {
				return nil, nil, compatInvalidConfig("signServers must be a bounded array")
			}
			servers := make([]any, 0, len(entries))
			for index, entry := range entries {
				serverFields, decodeErr := decodeCompatObject(entry)
				if decodeErr != nil {
					return nil, nil, compatInvalidConfig("signServers[%d]: %v", index, decodeErr)
				}
				server := make(map[string]any, len(serverFields))
				serverNames := make([]string, 0, len(serverFields))
				for field := range serverFields {
					serverNames = append(serverNames, field)
				}
				sort.Strings(serverNames)
				for _, field := range serverNames {
					serverValue := serverFields[field]
					switch field {
					case "url":
						normalized, nestedRefs, normalizeErr := normalizeCompatField(fmt.Sprintf("signServers[%d].url", index), compatURL, serverValue)
						if normalizeErr != nil {
							return nil, nil, normalizeErr
						}
						server[field] = normalized
						for _, ref := range nestedRefs {
							refs = appendCompatSecretRef(refs, ref)
						}
					case "key", "authorization":
						normalized, ref, secretErr := parseCompatSecretValue(serverValue, fmt.Sprintf("signServers[%d].%s", index, field))
						if secretErr != nil {
							return nil, nil, secretErr
						}
						server[field] = normalized
						refs = appendCompatSecretRef(refs, ref)
					default:
						return nil, nil, compatInvalidConfig("signServers[%d] has unknown field %q", index, field)
					}
				}
				servers = append(servers, server)
			}
			canonical[key] = servers
		case "ruleChangeSignServer", "maxCheckCount", "signServerTimeout", "refreshInterval":
			normalized, nestedRefs, normalizeErr := normalizeCompatField(key, compatInteger, value)
			if normalizeErr != nil {
				return nil, nil, normalizeErr
			}
			canonical[key] = normalized
			for _, ref := range nestedRefs {
				refs = appendCompatSecretRef(refs, ref)
			}
		case "autoRegister", "autoRefreshToken":
			normalized, nestedRefs, normalizeErr := normalizeCompatField(key, compatBool, value)
			if normalizeErr != nil {
				return nil, nil, normalizeErr
			}
			canonical[key] = normalized
			for _, ref := range nestedRefs {
				refs = appendCompatSecretRef(refs, ref)
			}
		default:
			return nil, nil, compatInvalidConfig("signServerConfig has unknown field %q", key)
		}
	}
	return canonical, refs, nil
}

func parseCompatSecretValue(raw json.RawMessage, field string) (map[string]any, adapterapi.SecretRef, error) {
	var value map[string]json.RawMessage
	if err := json.Unmarshal(raw, &value); err != nil || value == nil {
		return nil, adapterapi.SecretRef{}, compatInvalidConfig("secret field %q requires secretRef and version", field)
	}
	for name := range value {
		if name != "secretRef" && name != "ref" && name != "version" {
			return nil, adapterapi.SecretRef{}, compatInvalidConfig("secret field %q has unknown field %q", field, name)
		}
	}
	ref, err := parseCompatSecretObject(value, field)
	if err != nil {
		return nil, adapterapi.SecretRef{}, err
	}
	return map[string]any{"secretRef": ref.Ref, "version": ref.Version}, ref, nil
}

func parseCompatSecretRef(raw json.RawMessage, field string) (any, adapterapi.SecretRef, error) {
	var stringRef string
	if json.Unmarshal(raw, &stringRef) == nil {
		ref := adapterapi.SecretRef{Ref: strings.TrimSpace(stringRef), Version: 1}
		if err := ref.Validate(); err != nil {
			return nil, adapterapi.SecretRef{}, compatInvalidConfig("%s: invalid secret reference", field)
		}
		return ref.Ref, ref, nil
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return nil, adapterapi.SecretRef{}, compatInvalidConfig("%s must be a secret reference", field)
	}
	ref, err := parseCompatSecretObject(object, field)
	if err != nil {
		return nil, adapterapi.SecretRef{}, err
	}
	return map[string]any{"secretRef": ref.Ref, "version": ref.Version}, ref, nil
}

func parseCompatSecretRefs(raw json.RawMessage) ([]any, []adapterapi.SecretRef, error) {
	var entries []json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil || entries == nil || len(entries) > adapterapi.MaxSecretRefs {
		return nil, nil, compatInvalidConfig("secretRefs must be a bounded array")
	}
	canonical := make([]any, 0, len(entries))
	refs := make([]adapterapi.SecretRef, 0, len(entries))
	for index, entry := range entries {
		value, ref, err := parseCompatSecretRef(entry, fmt.Sprintf("secretRefs[%d]", index))
		if err != nil {
			return nil, nil, err
		}
		canonical = append(canonical, value)
		refs = append(refs, ref)
	}
	return canonical, refs, nil
}

func parseCompatSecretObject(value map[string]json.RawMessage, field string) (adapterapi.SecretRef, error) {
	secretRefRaw, hasSecretRef := value["secretRef"]
	refRaw, hasRef := value["ref"]
	if hasSecretRef && hasRef {
		return adapterapi.SecretRef{}, compatInvalidConfig("%s cannot contain both secretRef and ref", field)
	}
	if !hasSecretRef {
		secretRefRaw = refRaw
	}
	if len(secretRefRaw) == 0 {
		return adapterapi.SecretRef{}, compatInvalidConfig("%s secretRef is required", field)
	}
	var ref string
	if err := json.Unmarshal(secretRefRaw, &ref); err != nil {
		return adapterapi.SecretRef{}, compatInvalidConfig("%s secretRef must be a string", field)
	}
	version := uint64(1)
	if versionRaw, ok := value["version"]; ok {
		if err := json.Unmarshal(versionRaw, &version); err != nil || version == 0 {
			return adapterapi.SecretRef{}, compatInvalidConfig("%s version must be positive", field)
		}
	}
	result := adapterapi.SecretRef{Ref: strings.TrimSpace(ref), Version: version}
	if err := result.Validate(); err != nil {
		return adapterapi.SecretRef{}, compatInvalidConfig("%s has invalid secret reference", field)
	}
	return result, nil
}

func appendCompatSecretRef(refs []adapterapi.SecretRef, ref adapterapi.SecretRef) []adapterapi.SecretRef {
	for _, existing := range refs {
		if existing == ref {
			return refs
		}
	}
	return append(refs, ref)
}

func sameCompatSecretRefs(left, right []adapterapi.SecretRef) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func validateCompatURL(raw string) error {
	if raw == "" || hasCompatControl([]byte(raw)) {
		return errors.New("invalid URL")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || parsed.Hostname() == "" {
		return errors.New("invalid URL")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https", "ws", "wss":
	default:
		return errors.New("URL scheme is not allowed")
	}
	return nil
}

func hasCompatControl(raw []byte) bool {
	for _, r := range string(raw) {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func compatInvalidConfig(format string, args ...any) error {
	return fmt.Errorf("%w: %s", adapterapi.ErrInvalidConfig, fmt.Sprintf(format, args...))
}
