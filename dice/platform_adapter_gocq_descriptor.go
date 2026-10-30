package dice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"Scardice-core/adapterapi"
)

const GocqAdapterKey adapterapi.AdapterKey = "gocq"

// GocqDescriptor owns legacy GoCQHTTP OneBot v11 client, reverse-listener,
// and process-owned built-in configurations.
type GocqDescriptor struct{}

func NewGocqDescriptor() adapterapi.Descriptor { return GocqDescriptor{} }

func (GocqDescriptor) Key() adapterapi.AdapterKey { return GocqAdapterKey }
func (GocqDescriptor) ConfigVersion() uint16      { return OnebotConfigVersion }

func (GocqDescriptor) ValidateConfig(ctx context.Context, raw json.RawMessage) (adapterapi.ValidatedConfig, error) {
	return validateLegacyOnebotDescriptorConfig(ctx, raw, builtinModeGoCQ)
}

func (GocqDescriptor) SupportedActions(config adapterapi.ValidatedConfig) adapterapi.ActionSet {
	actions := OnebotDescriptor{}.SupportedActions(config)
	if isBuiltinOnebotConfig(config) {
		actions = actions.With(adapterapi.ActionKindRequestQRCode)
	}
	return actions
}

func (GocqDescriptor) Capabilities(config adapterapi.ValidatedConfig) adapterapi.CapabilitySet {
	capabilities := OnebotDescriptor{}.Capabilities(config)
	if isBuiltinOnebotConfig(config) {
		capabilities |= adapterapi.CapabilityArtifacts
	}
	return capabilities
}

func (descriptor GocqDescriptor) NewRuntime(init adapterapi.RuntimeInit) (adapterapi.AdapterRuntime, error) {
	if init.EndpointID == "" || !init.EndpointID.Valid() || init.Generation == 0 || init.DesiredVersion == 0 {
		return nil, errors.New("gocq: runtime identity is incomplete")
	}
	if err := init.Config.Validate(); err != nil {
		return nil, err
	}
	builtin, builtinErr := decodeBuiltinOnebotCanonical(init.Config)
	var validated adapterapi.ValidatedConfig
	var err error
	if builtinErr == nil {
		validated, err = descriptor.ValidateConfig(context.Background(), init.Config.Canonical)
	} else {
		validated, err = (OnebotDescriptor{}).validateConfig(context.Background(), init.Config.Canonical, false)
	}
	if err != nil || validated.Version != init.Config.Version || !bytes.Equal(validated.Canonical, init.Config.Canonical) || len(validated.SecretRefs) != len(init.Config.SecretRefs) {
		return nil, errors.New("gocq: runtime config was not validated by the GoCQ descriptor")
	}
	for index := range validated.SecretRefs {
		if validated.SecretRefs[index] != init.Config.SecretRefs[index] {
			return nil, errors.New("gocq: runtime secret references do not match canonical config")
		}
	}
	if builtinErr == nil {
		if builtin.BuiltInMode == builtinModeLagrange {
			return newBuiltinLagrangeRuntime(init, builtin), nil
		}
		return newBuiltinGoCQRuntime(init, builtin), nil
	}
	config, err := (OnebotDescriptor{}).decodeValidatedConfig(init.Config)
	if err != nil {
		return nil, err
	}
	return newOnebotRuntimeWithResources(config, init.Secrets, init.ResourceRoot, init.ResourceAccessToken, init.ResourceServeAddress, nil), nil
}

func validateLegacyOnebotDescriptorConfig(ctx context.Context, raw json.RawMessage, builtinDefaultMode string) (adapterapi.ValidatedConfig, error) {
	requested, err := builtinOnebotRequested(raw)
	if err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	if requested {
		return validateBuiltinOnebotConfig(ctx, raw, builtinDefaultMode)
	}
	onebotConfig, err := gocqExternalOnebotConfig(raw)
	if err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	return OnebotDescriptor{}.validateConfig(ctx, onebotConfig, false)
}

func gocqExternalOnebotConfig(raw json.RawMessage) (json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var fields map[string]json.RawMessage
	if err := decoder.Decode(&fields); err != nil || fields == nil {
		return nil, errors.New("gocq: external configuration must be an object")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("gocq: external configuration has trailing JSON")
	}

	allowed := map[string]bool{
		"connectUrl": true, "url": true, "token": true, "accessToken": true,
		"insecureSkipVerify": true, "friendRequestPolicy": true, "ignoreFriendRequest": true,
		"ignore_friend_request": true, "accountHint": true, "imageAssetBaseUrl": true,
		"useInPackGoCqhttp": true, "builtinMode": true, "isReverse": true, "reverseAddr": true,
	}
	for name := range fields {
		if !allowed[name] {
			return nil, fmt.Errorf("gocq: unsupported external configuration field %q", name)
		}
	}
	reverse, err := gocqBoolean(fields["isReverse"])
	if err != nil {
		return nil, err
	}
	reverse = reverse || gocqHasText(fields["reverseAddr"])

	mapped := make(map[string]json.RawMessage, 8)
	if reverse {
		if err := gocqCopyAlias(mapped, "listenAddress", fields, "reverseAddr"); err != nil {
			return nil, err
		}
		if _, ok := mapped["listenAddress"]; !ok {
			return nil, errors.New("gocq: reverseAddr is required for reverse mode")
		}
		mapped["mode"] = json.RawMessage(`"server"`)
	} else {
		if err := gocqCopyAlias(mapped, "url", fields, "connectUrl", "url"); err != nil {
			return nil, err
		}
		if _, ok := mapped["url"]; !ok {
			return nil, errors.New("gocq: connectUrl is required for external mode")
		}
		mapped["mode"] = json.RawMessage(`"client"`)
	}
	if err := gocqCopyAlias(mapped, "token", fields, "token", "accessToken"); err != nil {
		return nil, err
	}
	for _, name := range []string{"insecureSkipVerify", "friendRequestPolicy", "ignoreFriendRequest", "ignore_friend_request", "accountHint", "imageAssetBaseUrl"} {
		if value, ok := fields[name]; ok {
			mapped[name] = append(json.RawMessage(nil), value...)
		}
	}
	encoded, err := json.Marshal(mapped)
	if err != nil {
		return nil, fmt.Errorf("gocq: canonical external configuration: %w", err)
	}
	return encoded, nil
}

func gocqCopyAlias(target map[string]json.RawMessage, destination string, fields map[string]json.RawMessage, aliases ...string) error {
	for _, alias := range aliases {
		value, ok := fields[alias]
		if !ok {
			continue
		}
		if previous, exists := target[destination]; exists && !bytes.Equal(bytes.TrimSpace(previous), bytes.TrimSpace(value)) {
			return fmt.Errorf("gocq: %s aliases conflict", destination)
		}
		target[destination] = append(json.RawMessage(nil), value...)
	}
	return nil
}

func gocqBoolean(raw json.RawMessage) (bool, error) {
	if len(raw) == 0 {
		return false, nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return false, errors.New("gocq: boolean field is invalid")
	}
	var value bool
	if err := json.Unmarshal(raw, &value); err != nil {
		return false, errors.New("gocq: boolean field is invalid")
	}
	return value, nil
}

func gocqHasText(raw json.RawMessage) bool {
	return strings.TrimSpace(gocqString(raw)) != ""
}

func gocqString(raw json.RawMessage) string {
	var value string
	_ = json.Unmarshal(raw, &value)
	return value
}
