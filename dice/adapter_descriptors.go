package dice

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strings"

	"Scardice-core/adapterapi"
)

type providerCanonicalSecret struct {
	SecretRef string `json:"secretRef"`
	Version   uint64 `json:"version"`
}

func decodeStrictProviderJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func normalizeProviderHTTPURL(raw string, optional bool) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" && optional {
		return "", nil
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" || parsed.ForceQuery {
		return "", errors.New("must be an absolute http or https URL without credentials, query, or fragment")
	}
	escapedPath := strings.TrimRight(parsed.EscapedPath(), "/")
	decodedPath, err := url.PathUnescape(escapedPath)
	if err != nil {
		return "", err
	}
	parsed.Path = decodedPath
	parsed.RawPath = escapedPath
	return strings.TrimRight(parsed.String(), "/"), nil
}

// NewAdapterDescriptors returns the built-in endpoint seam descriptors in a
// stable order.
func NewAdapterDescriptors() []adapterapi.Descriptor {
	return []adapterapi.Descriptor{
		NewGocqDescriptor(),
		NewLagrangeDescriptor(),
		NewWalleQDescriptor(),
		NewRedDescriptor(),
		NewOfficialQQDescriptor(),
		NewSatoriDescriptor(),
		NewMilkyDescriptor(),
		NewDiscordDescriptor(),
		NewKookDescriptor(),
		NewTelegramDescriptor(),
		NewSlackDescriptor(),
		NewDodoDescriptor(),
		NewDingTalkDescriptor(),
		NewMinecraftDescriptor(),
		NewSealChatDescriptor(),
		NewHTTPDescriptor(),
		NewOnebotDescriptor(),
	}
}
